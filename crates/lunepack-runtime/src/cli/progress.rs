//! The output of an app-facing command (C4 Output): progress while it runs and the one final
//! line, all written by a single thread so a slow or stuck reader never slows the operation.
//!
//! The facade's progress callback runs on the polling thread and only stores the newest event in a
//! slot (a phase change first queues the last event of the phase it ends, so every phase shows).
//! The writer thread takes the slot at most [`JSON_INTERVAL`] apart (10 a second) for JSON Lines
//! on stdout, or [`HUMAN_INTERVAL`] apart for one human line on stderr. The final line is written
//! only after everything queued before it, by the same thread.
//!
//! A failed write to stdout (a closed pipe, a closed descriptor) cancels the operation through its
//! token, so a download keeps its partial file for the next run, and is reported by
//! [`Finished::stdout_failed`]. A writer that is blocked on a pipe nobody reads is abandoned after
//! a deadline; the process then exits with the operation's own result.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use lunepack::{CancelToken, Progress};

use crate::events::{Event, phase_name, to_json_line};

/// The least time between two progress lines of JSON output.
pub const JSON_INTERVAL: Duration = Duration::from_millis(100);
/// The least time between two progress lines of human output.
pub const HUMAN_INTERVAL: Duration = Duration::from_secs(1);
/// Most phase-end events kept for a writer that is behind.
const PHASE_QUEUE_CAP: usize = 16;

/// The final line of a command.
pub struct FinalLine {
    /// The line, without the newline.
    pub text: String,
    /// An error line goes to stderr in human mode; a result goes to stdout.
    pub is_error: bool,
}

/// What became of the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finished {
    /// A write to stdout failed, or the writer did not finish before the deadline.
    pub stdout_failed: bool,
}

#[derive(Default)]
struct State {
    /// The newest progress event not yet written.
    latest: Option<Progress>,
    /// Events that ended a phase, oldest first, written before `latest`.
    ended: VecDeque<Progress>,
    final_line: Option<FinalLine>,
    stdout_failed: bool,
    done: bool,
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

fn lock(shared: &Shared) -> MutexGuard<'_, State> {
    shared.state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The output of one command.
pub struct Output {
    shared: Arc<Shared>,
    handle: JoinHandle<()>,
}

impl Output {
    /// Starts the writer thread over `stdout` and `stderr`.
    pub fn start(
        stdout: Box<dyn Write + Send>,
        stderr: Box<dyn Write + Send>,
        json: bool,
        cancel: CancelToken,
    ) -> Output {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
        });
        let writer = Arc::clone(&shared);
        let handle = std::thread::Builder::new()
            .name("lunepack-cli-output".to_owned())
            .spawn(move || write_loop(&writer, stdout, stderr, json, &cancel))
            .unwrap_or_else(|_| std::process::exit(70));
        Output { shared, handle }
    }

    /// The callback to give the facade. It never blocks on the writer.
    pub fn callback(&self) -> Box<dyn FnMut(&Progress) + Send> {
        let shared = Arc::clone(&self.shared);
        Box::new(move |p: &Progress| {
            let mut state = lock(&shared);
            if let Some(old) = state.latest.take()
                && old.phase != p.phase
            {
                if state.ended.len() >= PHASE_QUEUE_CAP {
                    state.ended.pop_front();
                }
                state.ended.push_back(old);
            }
            state.latest = Some(p.clone());
            drop(state);
            shared.wake.notify_all();
        })
    }

    /// Writes `last` after everything queued, and waits up to `deadline` for the writer.
    pub fn finish(self, last: FinalLine, deadline: Duration) -> Finished {
        {
            let mut state = lock(&self.shared);
            state.final_line = Some(last);
        }
        self.shared.wake.notify_all();
        let end = Instant::now() + deadline;
        while !self.handle.is_finished() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        let finished = self.handle.is_finished();
        let failed = lock(&self.shared).stdout_failed;
        Finished {
            stdout_failed: failed || !finished,
        }
    }
}

fn progress_text(p: &Progress, json: bool) -> String {
    if json {
        return to_json_line(&Event::Progress(p.clone()));
    }
    if p.total > 0 {
        format!("{}: {} of {} bytes", phase_name(p.phase), p.done, p.total)
    } else {
        format!("{}: {}", phase_name(p.phase), p.done)
    }
}

fn write_line(out: &mut dyn Write, text: &str) -> std::io::Result<()> {
    let mut line = String::with_capacity(text.len() + 1);
    line.push_str(text);
    line.push('\n');
    out.write_all(line.as_bytes())?;
    out.flush()
}

fn write_loop(
    shared: &Shared,
    mut stdout: Box<dyn Write + Send>,
    mut stderr: Box<dyn Write + Send>,
    json: bool,
    cancel: &CancelToken,
) {
    let interval = if json { JSON_INTERVAL } else { HUMAN_INTERVAL };
    let mut last_emit: Option<Instant> = None;
    loop {
        enum Step {
            Progress(Progress),
            Final(FinalLine),
            Wait(Duration),
        }
        let step = {
            let mut state = lock(shared);
            loop {
                let due = last_emit.is_none_or(|t| t.elapsed() >= interval);
                // JSON shows every phase; human output keeps to its rate.
                if json && let Some(p) = state.ended.pop_front() {
                    break Step::Progress(p);
                }
                if !json {
                    state.ended.clear();
                }
                if due && let Some(p) = state.latest.take() {
                    break Step::Progress(p);
                }
                if state.latest.is_none() && state.ended.is_empty() {
                    if let Some(last) = state.final_line.take() {
                        break Step::Final(last);
                    }
                    state = shared
                        .wake
                        .wait(state)
                        .unwrap_or_else(PoisonError::into_inner);
                    continue;
                }
                // Something is waiting for its slot.
                let wait = interval.saturating_sub(last_emit.map_or(interval, |t| t.elapsed()));
                break Step::Wait(wait.max(Duration::from_millis(1)));
            }
        };
        match step {
            Step::Wait(wait) => std::thread::sleep(wait),
            Step::Progress(p) => {
                last_emit = Some(Instant::now());
                let text = progress_text(&p, json);
                if json {
                    if write_line(&mut *stdout, &text).is_err() {
                        fail(shared, cancel);
                    }
                } else {
                    // Progress on stderr is a courtesy: a closed stderr changes nothing.
                    let _ = write_line(&mut *stderr, &text);
                }
            }
            Step::Final(last) => {
                let out: &mut dyn Write = if last.is_error && !json {
                    &mut *stderr
                } else {
                    &mut *stdout
                };
                if write_line(out, &last.text).is_err() && !(last.is_error && !json) {
                    fail(shared, cancel);
                }
                lock(shared).done = true;
                return;
            }
        }
    }
}

fn fail(shared: &Shared, cancel: &CancelToken) {
    lock(shared).stdout_failed = true;
    cancel.cancel();
}

#[cfg(test)]
mod tests {
    use super::*;
    use lunepack::Phase;

    /// A writer that records what it is given.
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Sink {
        fn text(&self) -> String {
            String::from_utf8(
                self.0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone(),
            )
            .expect("utf-8")
        }
    }

    /// A writer that fails every call.
    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }

    /// A writer that never returns, as a write to a full pipe nobody reads.
    struct Stuck;

    impl Write for Stuck {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn progress(phase: Phase, done: u64) -> Progress {
        Progress {
            phase,
            done,
            total: 100,
            file: None,
        }
    }

    fn last(text: &str) -> FinalLine {
        FinalLine {
            text: text.to_owned(),
            is_error: false,
        }
    }

    #[test]
    fn every_phase_shows_and_the_final_line_comes_last() {
        let out = Sink::default();
        let output = Output::start(
            Box::new(out.clone()),
            Box::new(Sink::default()),
            true,
            CancelToken::new(),
        );
        let mut cb = output.callback();
        for (phase, done) in [
            (Phase::Scan, 1),
            (Phase::Scan, 2),
            (Phase::Download, 5),
            (Phase::Stage, 7),
            (Phase::Stage, 9),
        ] {
            cb(&progress(phase, done));
        }
        let finished = output.finish(last("{\"final\":true}"), Duration::from_secs(5));
        assert!(!finished.stdout_failed);
        let text = out.text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.last().copied(), Some("{\"final\":true}"));
        for phase in ["scan", "download", "stage"] {
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains(&format!("\"phase\":\"{phase}\""))),
                "{phase} missing in {lines:?}"
            );
        }
        // The newest event of the last phase is not lost.
        assert!(
            lines
                .iter()
                .any(|l| l.contains("\"phase\":\"stage\",\"done\":9"))
        );
    }

    #[test]
    fn progress_is_rate_limited() {
        let out = Sink::default();
        let output = Output::start(
            Box::new(out.clone()),
            Box::new(Sink::default()),
            true,
            CancelToken::new(),
        );
        let mut cb = output.callback();
        for done in 0..10_000 {
            cb(&progress(Phase::Download, done));
        }
        output.finish(last("{}"), Duration::from_secs(5));
        let n = out.text().lines().count();
        assert!(
            (2..=20).contains(&n),
            "{n} lines for one phase of 10000 events"
        );
    }

    #[test]
    fn human_output_goes_to_stderr_and_the_result_to_stdout() {
        let (out, err) = (Sink::default(), Sink::default());
        let output = Output::start(
            Box::new(out.clone()),
            Box::new(err.clone()),
            false,
            CancelToken::new(),
        );
        output.callback()(&progress(Phase::Download, 5));
        output.finish(last("check: no update"), Duration::from_secs(5));
        assert_eq!(out.text(), "check: no update\n");
        assert!(
            err.text().contains("download: 5 of 100 bytes"),
            "{}",
            err.text()
        );
    }

    #[test]
    fn a_human_error_goes_to_stderr() {
        let (out, err) = (Sink::default(), Sink::default());
        let output = Output::start(
            Box::new(out.clone()),
            Box::new(err.clone()),
            false,
            CancelToken::new(),
        );
        output.finish(
            FinalLine {
                text: "error: usage (exit 2)".to_owned(),
                is_error: true,
            },
            Duration::from_secs(5),
        );
        assert_eq!(out.text(), "");
        assert_eq!(err.text(), "error: usage (exit 2)\n");
    }

    #[test]
    fn a_failed_write_cancels_the_operation() {
        let cancel = CancelToken::new();
        let output = Output::start(
            Box::new(Broken),
            Box::new(Sink::default()),
            true,
            cancel.clone(),
        );
        output.callback()(&progress(Phase::Download, 1));
        let finished = output.finish(last("{}"), Duration::from_secs(5));
        assert!(finished.stdout_failed);
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn a_reader_that_never_reads_stalls_nothing() {
        let output = Output::start(
            Box::new(Stuck),
            Box::new(Sink::default()),
            true,
            CancelToken::new(),
        );
        let mut cb = output.callback();
        let started = Instant::now();
        for done in 0..100_000 {
            cb(&progress(Phase::Download, done));
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the callback waited for the writer"
        );
        let finished = output.finish(last("{}"), Duration::from_millis(300));
        assert!(
            finished.stdout_failed,
            "an abandoned writer is a failed output"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
