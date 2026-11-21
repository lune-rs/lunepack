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
//! ```
//!
//! where `<name>` is one of the closed phase names and the numbers are decimal.

#![cfg_attr(not(windows), allow(dead_code))]

use std::io::{ErrorKind, Write};
use std::sync::atomic::{AtomicBool, Ordering};
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

/// Reads the child's lines into `events` until the pipe ends, `done` is set and nothing more
/// comes, or the stream breaks its caps. Returns the number of events relayed. Never reports a
/// failure: the relay is a view, not a result.
pub fn relay(
    connector: &dyn EventConnector,
    id: &str,
    events: &Events,
    done: &AtomicBool,
) -> usize {
    let start = Instant::now();
    let mut channel = loop {
        match connector.connect(id, SLICE) {
            Ok(channel) => break channel,
            Err(Attempt::Refused) => return 0,
            Err(Attempt::NotYet) => {
                if done.load(Ordering::Acquire) || start.elapsed() > CONNECT_LIMIT {
                    return 0;
                }
            }
        }
    };
    if channel.set_read_deadline(Some(SLICE)).is_err() {
        return 0;
    }
    let mut carry: Vec<u8> = Vec::new();
    let mut total = 0usize;
    let mut relayed = 0usize;
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
                        return relayed;
                    };
                    match decode(line) {
                        Some(event) => {
                            events.emit(&event);
                            relayed += 1;
                        }
                        // Outside the grammar: the stream is not what it should be.
                        None => return relayed,
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
    relayed
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
}
