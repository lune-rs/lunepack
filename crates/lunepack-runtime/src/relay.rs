//! The relay of an elevated child's progress to the unelevated setup that started it (M10 step 16,
//! M10-D15).
//!
//! A Windows setup that installs for all users starts an elevated copy of itself (the hidden
//! `machine-install` mode). The copy writes its progress, one short text line per event, into an
//! outbound named pipe it owns; the unelevated setup reads the lines and shows them in its UI. The
//! pipe carries progress only: the outcome is the child's exit code and the machine record, never
//! a line read here, so a reader that fails, lags or is killed changes nothing about the install.
//!
//! The lines are a closed grammar, ASCII, at most [`MAX_LINE`] bytes, at most [`MAX_STREAM`] bytes
//! in all; anything else ends the relay (and is never echoed anywhere):
//!
//! ```text
//! phase <name>
//! progress <name> <done> <total>
//! end <code>
//! ```
//!
//! where `<name>` is one of the closed phase names and the numbers are decimal. `end` is the last
//! line of a mode whose result no exit code reaches the reader (the machine uninstall, whose
//! copy runs after the process the reader started has exited); `<code>` is the mode's exit code.
//! It is advice for the failure the reader names, never proof of success: the reader decides
//! success from the machine record.

#![cfg_attr(not(windows), allow(dead_code))]

use std::io::{ErrorKind, Read, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use lunepack::{Phase, Progress};
use lunepack_core::service::Duplex;

use crate::events::{Event, Events, Sink, SinkFailed, phase_name};

/// The longest line the relay reads or writes, without its newline.
pub const MAX_LINE: usize = 96;
/// The most bytes the relay reads in all.
pub const MAX_STREAM: usize = 256 * 1024;
/// How long one attempt to open the child's pipe waits, and how long one read waits before the
/// relay looks whether the child has ended.
pub const SLICE: Duration = Duration::from_millis(200);
/// How long the relay keeps trying to open the pipe of a child that runs.
pub const CONNECT_LIMIT: Duration = Duration::from_secs(60);
/// The prefix of the elevation pipe's name; the 32-hex id follows.
pub const PIPE_PREFIX: &str = "lunepack-setup-";

/// The pipe name (the part after `\\.\pipe\`) of the child with id `id`.
pub fn pipe_name(id: &str) -> String {
    format!("{PIPE_PREFIX}{id}")
}

/// Every phase the relay carries, as the events name them.
const PHASES: [Phase; 12] = [
    Phase::Check,
    Phase::Scan,
    Phase::Download,
    Phase::Stage,
    Phase::Install,
    Phase::Wait,
    Phase::Apply,
    Phase::Launch,
    Phase::Confirm,
    Phase::Rollback,
    Phase::Uninstall,
    Phase::Adopt,
];

fn phase_of(name: &str) -> Option<Phase> {
    PHASES.into_iter().find(|p| phase_name(*p) == name)
}

/// The relay line of `event` (without its newline), `None` for an event the relay does not carry
/// (only phases and byte progress without a file travel).
pub fn encode(event: &Event) -> Option<String> {
    match event {
        Event::Phase {
            phase,
            reason: None,
            ..
        } if phase_of(phase_name(*phase)).is_some() => {
            Some(format!("phase {}", phase_name(*phase)))
        }
        Event::Progress(p) if p.file.is_none() && phase_of(phase_name(p.phase)).is_some() => Some(
            format!("progress {} {} {}", phase_name(p.phase), p.done, p.total),
        ),
        _ => None,
    }
}

/// A decimal number: ASCII digits only, no sign, no leading zero but `0` itself.
fn number(text: &str) -> Option<u64> {
    let plain = !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if plain { text.parse().ok() } else { None }
}

/// One line of the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// An event (`phase`, `progress`).
    Event(Event),
    /// `end <code>`: the exit code of the writer's mode.
    End(u8),
}

/// The relay line of the end of a mode that exited with `code`.
pub fn encode_end(code: u8) -> String {
    format!("end {code}")
}

/// One relay line, `None` for anything outside the grammar.
pub fn decode_line(line: &str) -> Option<Line> {
    if line.len() > MAX_LINE || !line.is_ascii() {
        return None;
    }
    if let Some(code) = line.strip_prefix("end ") {
        return number(code)
            .and_then(|n| u8::try_from(n).ok())
            .map(Line::End);
    }
    decode(line).map(Line::Event)
}

/// The event of one relay line, `None` for anything outside the grammar.
pub fn decode(line: &str) -> Option<Event> {
    if line.len() > MAX_LINE || !line.is_ascii() {
        return None;
    }
    let mut words = line.split(' ');
    let kind = words.next()?;
    let name = words.next()?;
    let phase = phase_of(name)?;
    let event = match kind {
        "phase" => Event::phase(phase, None),
        "progress" => {
            let done = number(words.next()?)?;
            let total = number(words.next()?)?;
            Event::Progress(Progress {
                phase,
                done,
                total,
                file: None,
            })
        }
        _ => return None,
    };
    words.next().is_none().then_some(event)
}

/// The child's end: its events as relay lines into `out`. An event the relay does not carry is
/// skipped; a write that fails drops the sink (the install goes on).
pub struct RelaySink {
    out: Box<dyn Write + Send>,
}

impl RelaySink {
    /// A sink writing to `out`.
    pub fn new(out: Box<dyn Write + Send>) -> RelaySink {
        RelaySink { out }
    }
}

/// Writes the `end` line of a mode that exits with `code` into `out`; best effort.
pub fn write_end(out: &mut dyn Write, code: u8) {
    let mut line = encode_end(code);
    line.push('\n');
    let _ = out.write_all(line.as_bytes()).and_then(|()| out.flush());
}

impl Sink for RelaySink {
    fn name(&self) -> &'static str {
        "relay"
    }

    fn deliver(&mut self, event: &Event) -> Result<(), SinkFailed> {
        let Some(mut line) = encode(event) else {
            return Ok(());
        };
        line.push('\n');
        self.out
            .write_all(line.as_bytes())
            .and_then(|()| self.out.flush())
            .map_err(|_| SinkFailed)
    }
}

/// Why one attempt to open the child's pipe did not give a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// The pipe is not there yet, or busy: try again.
    NotYet,
    /// The pipe is there but refused: not owned by Administrators, or not open to this user. No
    /// more attempts.
    Refused,
}

/// Opens the elevated child's pipe, checking its owner.
pub trait EventConnector: Send + Sync {
    /// One attempt for the pipe of child `id`, waiting at most `wait` for it to appear.
    fn connect(&self, id: &str, wait: Duration) -> Result<Box<dyn Duplex>, Attempt>;
}

/// How many chunks the pump of a [`StreamConnector`] queues before it waits for the reader.
const PUMP_QUEUE: usize = 8;

/// The elevated child's standard output as the relay's channel (Linux, M11-D9): the one stream
/// there is, taken by the first [`connect`](EventConnector::connect) and by no later one. There is
/// no pipe to name or check: the stream is the pipe pkexec was started with, which only the child
/// writes into. Its reads are bounded by a pump thread, so [`Duplex::set_read_deadline`] holds
/// over a stream that has none; the pump goes on reading (and drops what it reads) after the
/// relay has stopped, so a child that keeps writing is never stalled by a reader that gave up.
pub struct StreamConnector {
    stream: Mutex<Option<Box<dyn Read + Send>>>,
}

impl StreamConnector {
    /// A connector over `stream`.
    pub fn new(stream: Box<dyn Read + Send>) -> StreamConnector {
        StreamConnector {
            stream: Mutex::new(Some(stream)),
        }
    }
}

impl EventConnector for StreamConnector {
    fn connect(&self, _id: &str, _wait: Duration) -> Result<Box<dyn Duplex>, Attempt> {
        let stream = self
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or(Attempt::Refused)?;
        PumpedStream::start(stream)
            .map(|p| Box::new(p) as Box<dyn Duplex>)
            .ok_or(Attempt::Refused)
    }
}

/// A [`Read`] stream behind a pump thread: chunks arrive through a bounded queue.
struct PumpedStream {
    chunks: Receiver<Vec<u8>>,
    pending: Vec<u8>,
    deadline: Option<Duration>,
}

impl PumpedStream {
    fn start(mut stream: Box<dyn Read + Send>) -> Option<PumpedStream> {
        let (tx, chunks) = mpsc::sync_channel::<Vec<u8>>(PUMP_QUEUE);
        std::thread::Builder::new()
            .name("relay-pump".to_owned())
            .spawn(move || {
                let mut buf = [0u8; 512];
                let mut listening = true;
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if listening && tx.send(buf[..n].to_vec()).is_err() {
                                // The reader is gone: read on, so the writer never blocks.
                                listening = false;
                            }
                        }
                        Err(e) if e.kind() == ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
            })
            .ok()?;
        Some(PumpedStream {
            chunks,
            pending: Vec::new(),
            deadline: None,
        })
    }
}

impl Read for PumpedStream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pending.is_empty() {
            let next = match self.deadline {
                Some(wait) => self.chunks.recv_timeout(wait),
                None => self
                    .chunks
                    .recv()
                    .map_err(|_| RecvTimeoutError::Disconnected),
            };
            match next {
                Ok(chunk) => self.pending = chunk,
                Err(RecvTimeoutError::Timeout) => return Err(ErrorKind::TimedOut.into()),
                // The stream ended: what was queued before it has all been read.
                Err(RecvTimeoutError::Disconnected) => return Ok(0),
            }
        }
        let n = out.len().min(self.pending.len());
        out[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
}

impl Write for PumpedStream {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(ErrorKind::Unsupported.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Duplex for PumpedStream {
    fn set_read_deadline(&mut self, deadline: Option<Duration>) -> std::io::Result<()> {
        self.deadline = deadline;
        Ok(())
    }
}

/// Reads the child's lines into `events` until the pipe ends, `done` is set and nothing more
/// comes, or the stream breaks its caps. Returns the number of events relayed. Never reports a
/// failure: the relay is a view, not a result.
pub fn relay(
    connector: &dyn EventConnector,
    id: &str,
    events: &Events,
    done: &AtomicBool,
) -> usize {
    relay_ending(connector, id, events, done).0
}

/// [`relay`], and the code of the `end` line when the stream ended with one (advice only).
pub fn relay_ending(
    connector: &dyn EventConnector,
    id: &str,
    events: &Events,
    done: &AtomicBool,
) -> (usize, Option<u8>) {
    let start = Instant::now();
    let mut channel = loop {
        match connector.connect(id, SLICE) {
            Ok(channel) => break channel,
            Err(Attempt::Refused) => return (0, None),
            Err(Attempt::NotYet) => {
                if done.load(Ordering::Acquire) || start.elapsed() > CONNECT_LIMIT {
                    return (0, None);
                }
            }
        }
    };
    if channel.set_read_deadline(Some(SLICE)).is_err() {
        return (0, None);
    }
    let mut carry: Vec<u8> = Vec::new();
    let mut total = 0usize;
    let mut relayed = 0usize;
    let mut end: Option<u8> = None;
    let mut buf = [0u8; 512];
    loop {
        match channel.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total > MAX_STREAM {
                    break;
                }
                carry.extend_from_slice(&buf[..n]);
                while let Some(at) = carry.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = carry.drain(..=at).collect();
                    let Ok(line) = std::str::from_utf8(&line[..line.len() - 1]) else {
                        return (relayed, end);
                    };
                    // Nothing follows an `end`.
                    if end.is_some() {
                        return (relayed, end);
                    }
                    match decode_line(line) {
                        Some(Line::Event(event)) => {
                            events.emit(&event);
                            relayed += 1;
                        }
                        Some(Line::End(code)) => end = Some(code),
                        // Outside the grammar: the stream is not what it should be.
                        None => return (relayed, end),
                    }
                }
                if carry.len() > MAX_LINE {
                    break;
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                // Nothing came within a slice: the child may have ended.
                if done.load(Ordering::Acquire) {
                    break;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    (relayed, end)
}

/// [`relay_ending`] for a writer that may take a long time (a process that runs after the one the
/// reader started has exited): follows the pipe until it ends, or until `limit` has passed.
pub fn relay_to_the_end(
    connector: &dyn EventConnector,
    id: &str,
    events: &Events,
    limit: Duration,
) -> (usize, Option<u8>) {
    let done = AtomicBool::new(false);
    let finished = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let start = Instant::now();
            while !finished.load(Ordering::Acquire) && start.elapsed() < limit {
                std::thread::sleep(Duration::from_millis(50));
            }
            done.store(true, Ordering::Release);
        });
        let out = relay_ending(connector, id, events, &done);
        finished.store(true, Ordering::Release);
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Sink, SinkFailed};
    use std::sync::{Arc, Mutex};

    use lunepack_testkit::{MemDuplex, mem_duplex};

    #[derive(Clone, Default)]
    struct Collect(Arc<Mutex<Vec<Event>>>);

    impl Sink for Collect {
        fn name(&self) -> &'static str {
            "collect"
        }

        fn deliver(&mut self, event: &Event) -> Result<(), SinkFailed> {
            self.0.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    fn progress(phase: Phase, done: u64, total: u64) -> Event {
        Event::Progress(Progress {
            phase,
            done,
            total,
            file: None,
        })
    }

    #[test]
    fn events_round_trip_through_their_lines() {
        for event in [
            Event::phase(Phase::Install, None),
            Event::phase(Phase::Stage, None),
            progress(Phase::Install, 0, 0),
            progress(Phase::Install, 123, 4_000_000_000),
            progress(Phase::Stage, u64::MAX, u64::MAX),
        ] {
            let line = encode(&event).expect("a relayed event");
            assert!(line.len() <= MAX_LINE, "{line}");
            assert_eq!(decode(&line), Some(event));
        }
        assert_eq!(
            encode(&progress(Phase::Install, 5, 9)).as_deref(),
            Some("progress install 5 9")
        );
    }

    #[test]
    fn what_the_relay_does_not_carry_is_not_encoded() {
        let v = lunepack::Version::parse("1.0.0").unwrap();
        for event in [
            Event::warning(crate::events::Warning::GcBusy, None),
            Event::Phase {
                phase: Phase::Rollback,
                version: Some(v.clone()),
                reason: Some(crate::events::Reason::Crashed),
            },
            Event::Result {
                command: "setup",
                tree_version: None,
                outcome: "installed",
                version: Some(v),
            },
            Event::UiStopped {
                reason: "hung",
                exit_code: None,
            },
        ] {
            assert_eq!(encode(&event), None, "{event:?}");
        }
    }

    #[test]
    fn a_line_outside_the_grammar_is_refused() {
        for bad in [
            "",
            "phase",
            "phase nonsense",
            "phase install extra",
            "phase  install",
            "phase Install",
            "progress install 1",
            "progress install 1 2 3",
            "progress install -1 2",
            "progress install 01 2",
            "progress install 1 18446744073709551616",
            "progress install 1 +2",
            "progress install 1 2 ",
            " progress install 1 2",
            "progress\tinstall 1 2",
            "result installed",
            "phase install\r",
            "phase instal\u{6c}\u{301}",
        ] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
        assert_eq!(decode(&format!("phase {}", "x".repeat(MAX_LINE))), None);
    }

    fn lines_into(events: &Events) -> (MemDuplex, MemDuplex) {
        let _ = events;
        mem_duplex()
    }

    /// An `Events` that collects what the relay emits.
    fn collecting() -> (Events, Arc<Mutex<Vec<Event>>>) {
        let sink = Collect::default();
        let seen = Arc::clone(&sink.0);
        (Events::new(None, Some(Box::new(sink))), seen)
    }

    struct Ready(Mutex<Option<MemDuplex>>);

    impl EventConnector for Ready {
        fn connect(&self, _: &str, _: Duration) -> Result<Box<dyn Duplex>, Attempt> {
            self.0
                .lock()
                .unwrap()
                .take()
                .map(|d| Box::new(d) as Box<dyn Duplex>)
                .ok_or(Attempt::Refused)
        }
    }

    #[test]
    fn the_relay_forwards_every_line_and_ends_when_the_child_closes_its_end() {
        let (events, seen) = collecting();
        let (mut child, bootstrap) = lines_into(&events);
        let connector = Ready(Mutex::new(Some(bootstrap)));
        child
            .write_all(b"phase install\nprogress install 10 20\nprogress install 20 20\n")
            .unwrap();
        drop(child);
        let done = AtomicBool::new(false);
        assert_eq!(relay(&connector, "id", &events, &done), 3);
        events.finish(Duration::from_secs(2));
        // Consecutive progress of one phase coalesces into the newest (`Events`): the phase comes
        // first and the last progress is the last line.
        let seen = seen.lock().unwrap();
        assert_eq!(seen.first(), Some(&Event::phase(Phase::Install, None)));
        assert_eq!(seen.last(), Some(&progress(Phase::Install, 20, 20)));
        assert!(seen.len() <= 3 && seen.len() >= 2, "{seen:?}");
    }

    #[test]
    fn lines_split_across_reads_are_joined() {
        let (events, seen) = collecting();
        let (mut child, bootstrap) = mem_duplex();
        let connector = Ready(Mutex::new(Some(bootstrap)));
        let writer = std::thread::spawn(move || {
            for chunk in [
                &b"progress inst"[..],
                b"all 1",
                b"0 20\nph",
                b"ase install\n",
            ] {
                child.write_all(chunk).unwrap();
                std::thread::sleep(Duration::from_millis(30));
            }
        });
        let done = AtomicBool::new(false);
        assert_eq!(relay(&connector, "id", &events, &done), 2);
        writer.join().unwrap();
        events.finish(Duration::from_secs(2));
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[test]
    fn a_bad_line_ends_the_relay_and_what_came_before_it_stays() {
        let (events, seen) = collecting();
        let (mut child, bootstrap) = mem_duplex();
        let connector = Ready(Mutex::new(Some(bootstrap)));
        child
            .write_all(b"phase install\nC:\\secret path\nphase stage\n")
            .unwrap();
        drop(child);
        let done = AtomicBool::new(false);
        assert_eq!(relay(&connector, "id", &events, &done), 1);
        events.finish(Duration::from_secs(2));
        assert_eq!(
            *seen.lock().unwrap(),
            vec![Event::phase(Phase::Install, None)]
        );
    }

    #[test]
    fn an_endless_line_and_an_endless_stream_are_cut() {
        for payload in [vec![b'a'; MAX_LINE + 50], b"phase install\n".repeat(30_000)] {
            let (events, seen) = collecting();
            let (mut child, bootstrap) = mem_duplex();
            let connector = Ready(Mutex::new(Some(bootstrap)));
            let writer = std::thread::spawn(move || {
                let _ = child.write_all(&payload);
            });
            let done = AtomicBool::new(false);
            let relayed = relay(&connector, "id", &events, &done);
            writer.join().unwrap();
            events.finish(Duration::from_secs(2));
            assert!(relayed <= MAX_STREAM / 14 + 1, "{relayed}");
            assert!(seen.lock().unwrap().len() <= relayed);
        }
    }

    struct Never;

    impl EventConnector for Never {
        fn connect(&self, _: &str, wait: Duration) -> Result<Box<dyn Duplex>, Attempt> {
            std::thread::sleep(wait.min(Duration::from_millis(20)));
            Err(Attempt::NotYet)
        }
    }

    #[test]
    fn a_child_that_never_opens_its_pipe_ends_the_relay_once_it_has_ended() {
        let (events, _seen) = collecting();
        let done = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(100));
                done.store(true, Ordering::Release);
            });
            assert_eq!(relay(&Never, "id", &events, &done), 0);
        });
        assert!(done.load(Ordering::Acquire));
    }

    #[test]
    fn a_silent_open_pipe_is_left_when_the_child_has_ended() {
        let (events, _seen) = collecting();
        let (child, bootstrap) = mem_duplex();
        let connector = Ready(Mutex::new(Some(bootstrap)));
        let done = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(300));
                done.store(true, Ordering::Release);
            });
            assert_eq!(relay(&connector, "id", &events, &done), 0);
        });
        drop(child);
    }

    #[test]
    fn a_refused_pipe_relays_nothing_and_is_not_retried() {
        let (events, _seen) = collecting();
        let connector = Ready(Mutex::new(None));
        let done = AtomicBool::new(false);
        assert_eq!(relay(&connector, "id", &events, &done), 0);
    }

    #[test]
    fn the_sink_writes_lines_and_a_failing_write_drops_it() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut sink = RelaySink::new(Box::new(Broken));
        // An event the relay does not carry is fine; one it carries fails the sink.
        assert_eq!(
            sink.deliver(&Event::warning(crate::events::Warning::GcBusy, None)),
            Ok(())
        );
        assert_eq!(
            sink.deliver(&Event::phase(Phase::Install, None)),
            Err(SinkFailed)
        );

        let (child, mut bootstrap) = mem_duplex();
        let mut sink = RelaySink::new(Box::new(child));
        sink.deliver(&Event::phase(Phase::Install, None)).unwrap();
        sink.deliver(&progress(Phase::Install, 1, 2)).unwrap();
        drop(sink);
        let mut got = String::new();
        std::io::Read::read_to_string(&mut bootstrap, &mut got).unwrap();
        assert_eq!(got, "phase install\nprogress install 1 2\n");
    }

    #[test]
    fn the_pipe_name_is_the_prefix_and_the_id() {
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(pipe_name(id), format!("lunepack-setup-{id}"));
        // A name the Windows adapter accepts: letters, digits, `.`, `_`, `-`.
        assert!(
            pipe_name(id)
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        );
    }

    #[test]
    fn the_end_line_carries_a_code_and_nothing_follows_it() {
        assert_eq!(encode_end(25), "end 25");
        assert_eq!(decode_line("end 25"), Some(Line::End(25)));
        assert_eq!(decode_line("end 0"), Some(Line::End(0)));
        assert_eq!(
            decode_line("phase install"),
            Some(Line::Event(Event::phase(Phase::Install, None)))
        );
        for bad in [
            "end", "end ", "end 256", "end -1", "end 01", "end 1 2", "End 1", "end  1", "end +1",
        ] {
            assert_eq!(decode_line(bad), None, "{bad:?}");
        }
        // `decode` stays the events' own grammar.
        assert_eq!(decode("end 0"), None);
        // Over a pipe: events, then the end; the reader gets both. Lines after the end end the relay.
        for (stream, want) in [
            ("phase uninstall\nend 25\n", (1, Some(25))),
            ("end 0\n", (0, Some(0))),
            ("phase uninstall\n", (1, None)),
            ("end 25\nphase install\n", (0, Some(25))),
            ("end 25\nend 0\n", (0, Some(25))),
            ("phase uninstall\nend 300\nphase install\n", (1, None)),
        ] {
            let (mut child, reader) = mem_duplex();
            std::io::Write::write_all(&mut child, stream.as_bytes()).unwrap();
            drop(child);
            let connector = OneConnector(std::sync::Mutex::new(Some(reader)));
            let sink = Collect::default();
            let events = Events::new(None, Some(Box::new(sink.clone())));
            let done = AtomicBool::new(false);
            let got = relay_ending(&connector, "id", &events, &done);
            events.finish(Duration::from_secs(1));
            assert_eq!(got, want, "{stream:?}");
            assert_eq!(sink.0.lock().unwrap().len(), want.0, "{stream:?}");
        }
    }

    struct OneConnector(std::sync::Mutex<Option<MemDuplex>>);

    impl EventConnector for OneConnector {
        fn connect(&self, _: &str, _: Duration) -> Result<Box<dyn Duplex>, Attempt> {
            self.0
                .lock()
                .unwrap()
                .take()
                .map(|d| Box::new(d) as Box<dyn Duplex>)
                .ok_or(Attempt::Refused)
        }
    }

    #[test]
    fn a_writer_that_never_ends_is_followed_only_until_the_limit() {
        // The pipe stays open and silent: the relay stops at the limit, with nothing relayed.
        let (child, reader) = mem_duplex();
        let connector = OneConnector(std::sync::Mutex::new(Some(reader)));
        let events = Events::new(None, None);
        let started = Instant::now();
        let got = relay_to_the_end(&connector, "id", &events, Duration::from_millis(300));
        assert_eq!(got, (0, None));
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert!(started.elapsed() < Duration::from_secs(10));
        drop(child);
    }
    // ---- the child's standard output as the channel (Linux, M11-D9) ---------------------------

    fn stream_pair() -> (StreamConnector, std::io::PipeWriter) {
        let (reader, writer) = std::io::pipe().expect("a pipe");
        (StreamConnector::new(Box::new(reader)), writer)
    }

    #[test]
    fn a_child_stdout_relays_its_lines_and_ends_with_the_stream() {
        let (events, seen) = collecting();
        let (connector, mut writer) = stream_pair();
        let writer = std::thread::spawn(move || {
            for chunk in [
                &b"phase inst"[..],
                b"all
progress install 10 20
",
            ] {
                writer.write_all(chunk).unwrap();
                std::thread::sleep(Duration::from_millis(30));
            }
        });
        let done = AtomicBool::new(false);
        assert_eq!(relay(&connector, "stdout", &events, &done), 2);
        writer.join().unwrap();
        events.finish(Duration::from_secs(2));
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[test]
    fn the_stream_is_taken_once() {
        let (connector, _writer) = stream_pair();
        assert!(connector.connect("stdout", SLICE).is_ok());
        assert!(matches!(
            connector.connect("stdout", SLICE),
            Err(Attempt::Refused)
        ));
    }

    #[test]
    fn a_malformed_line_ends_the_relay_and_the_writer_is_never_stalled() {
        let (events, seen) = collecting();
        let (connector, mut writer) = stream_pair();
        // Well past a pipe's buffer after the bad line: a reader that stopped must not block it.
        let child = std::thread::spawn(move || {
            writer
                .write_all(
                    b"phase install
/home/x/secret
",
                )
                .unwrap();
            for _ in 0..4096 {
                writer.write_all(&[b'x'; 256]).unwrap();
            }
        });
        let done = AtomicBool::new(false);
        assert_eq!(relay(&connector, "stdout", &events, &done), 1);
        child.join().expect("the writer finished every write");
        events.finish(Duration::from_secs(2));
        assert_eq!(
            *seen.lock().unwrap(),
            vec![Event::phase(Phase::Install, None)]
        );
    }

    #[test]
    fn a_silent_stream_is_left_when_the_child_has_ended() {
        let (events, _seen) = collecting();
        let (connector, writer) = stream_pair();
        let done = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(300));
                done.store(true, Ordering::Release);
            });
            assert_eq!(relay(&connector, "stdout", &events, &done), 0);
        });
        drop(writer);
    }

    #[test]
    fn the_stream_channel_cannot_be_written_to() {
        let (connector, _writer) = stream_pair();
        let mut channel = connector.connect("stdout", SLICE).expect("a channel");
        assert!(channel.write(b"x").is_err());
    }
}
