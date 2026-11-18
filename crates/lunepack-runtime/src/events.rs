//! The runtime's typed events and where they go (C4, M5-D15).
//!
//! An [`Event`] is C9's progress, one of the runtime's phases (wait, apply, launch, confirm,
//! rollback with a closed reason), a warning with a closed code, or the final result or error.
//! [`to_json_line`] writes it as one schema-1 JSON line; the strings in it come only from the
//! signed documents (versions, relative paths) and closed sets, never from an error's text, a
//! path, an argument or the environment.
//!
//! [`Events`] fans every event out to its sinks: the log file ([`LogSink`], `R/logs/runtime.log`,
//! rotated at 1 MiB to `runtime.log.1`), stderr when there is no install yet ([`StderrSink`]),
//! and an optional UI sink that M6 fills. Each sink has its own thread behind a queue of at most
//! [`QUEUE_CAP`] events: [`Events::emit`] never blocks on a sink, consecutive progress events of
//! one phase coalesce into the newest (latest wins), and a sink that fails, or whose queue fills
//! with events that cannot coalesce, is dropped and logged once. No outcome depends on a sink.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lunepack::{FileWrite, Fs, FsErrorKind, Phase, Progress, Source, Version};

/// The schema every object carries.
pub const SCHEMA: u32 = 1;
/// Most events a sink's queue holds.
pub const QUEUE_CAP: usize = 64;
/// The size at which the log file is rotated.
pub const LOG_ROTATE_BYTES: u64 = 1024 * 1024;
/// The log file's name under `R/logs`.
pub const LOG_FILE: &str = "runtime.log";
/// The one older generation kept.
pub const LOG_FILE_OLD: &str = "runtime.log.1";

/// Why a version was rolled back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// It exited with a non-zero status or was ended by a signal before it confirmed.
    Crashed,
    /// It did not confirm within its health timeout.
    Timeout,
    /// It could not be started.
    SpawnFailed,
}

impl Reason {
    /// The JSON name.
    pub const fn name(self) -> &'static str {
        match self {
            Reason::Crashed => "crashed",
            Reason::Timeout => "timeout",
            Reason::SpawnFailed => "spawn_failed",
        }
    }
}

/// Something worth noting that does not change the outcome. Closed set of codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Warning {
    /// The `current` link could not be brought in line with the record (the next start does it).
    ReconcileFailed,
    /// The desktop integration could not be refreshed.
    IntegrationFailed,
    /// The desktop integration left an item in place that is not lunepack's.
    IntegrationKept,
    /// The previous version could not be started after a rollback.
    RelaunchFailed,
    /// The previous version's tree or config is missing, so the rollback could not be done.
    RollbackUnavailable,
    /// The install lock stayed held, so garbage collection was skipped.
    GcBusy,
    /// A version tree is still in use and was kept.
    GcInUse,
    /// A version tree could not be checked or removed and was kept.
    GcKept,
    /// The applied version was rolled back by another start before supervision decided.
    Superseded,
    /// A sink failed or stopped reading and receives nothing more.
    SinkDropped,
}

impl Warning {
    /// The JSON code.
    pub const fn code(self) -> &'static str {
        match self {
            Warning::ReconcileFailed => "reconcile_failed",
            Warning::IntegrationFailed => "integration_failed",
            Warning::IntegrationKept => "integration_kept",
            Warning::RelaunchFailed => "relaunch_failed",
            Warning::RollbackUnavailable => "rollback_unavailable",
            Warning::GcBusy => "gc_busy",
            Warning::GcInUse => "gc_in_use",
            Warning::GcKept => "gc_kept",
            Warning::Superseded => "superseded",
            Warning::SinkDropped => "sink_dropped",
        }
    }
}

/// One event of the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// C9 progress of an operation (download, stage, install).
    #[allow(dead_code)] // emitted by the install mode and the commands (steps 9, 12)
    Progress(Progress),
    /// A phase of the runtime began: `wait`, `apply`, `launch`, `confirm` or `rollback` (with
    /// its reason). `version` is the version the phase is about.
    Phase {
        /// The phase.
        phase: Phase,
        /// The version it is about.
        version: Option<Version>,
        /// Why, for a rollback.
        reason: Option<Reason>,
    },
    /// A note that does not change the outcome.
    Warning {
        /// What happened.
        warning: Warning,
        /// The version it is about, when one.
        version: Option<Version>,
    },
    /// The UI process was stopped (M6): the run goes on headless. `reason` is from the closed set
    /// of `ui_host::UiStop` (`stalled`, `hung`, `exited`, `protocol`, `build_mismatch`,
    /// `hello_timeout`, `spawn_failed`); `exit_code` is the UI's own, when it exited with one. A
    /// `warning` with code `ui_stopped` on the wire.
    #[allow(dead_code)] // emitted by the UI host
    UiStopped {
        /// Why.
        reason: &'static str,
        /// The UI's exit code.
        exit_code: Option<i32>,
    },
    /// The mode ended well (or with a decided outcome such as a rollback).
    Result {
        /// The mode or command.
        command: &'static str,
        /// The version of the tree this runtime belongs to.
        tree_version: Option<Version>,
        /// The outcome, from a closed set (`confirmed`, `rolled_back`, ...).
        outcome: &'static str,
        /// The version the outcome is about.
        version: Option<Version>,
    },
    /// The mode failed.
    Error {
        /// The mode or command.
        command: &'static str,
        /// The version of the tree this runtime belongs to, when known.
        tree_version: Option<Version>,
        /// The error kind name.
        kind: &'static str,
        /// The exit code.
        exit_code: u8,
    },
}

impl Event {
    /// A phase event.
    pub fn phase(phase: Phase, version: Option<&Version>) -> Event {
        Event::Phase {
            phase,
            version: version.cloned(),
            reason: None,
        }
    }

    /// A warning.
    pub fn warning(warning: Warning, version: Option<&Version>) -> Event {
        Event::Warning {
            warning,
            version: version.cloned(),
        }
    }

    fn coalesces_with(&self, older: &Event) -> bool {
        matches!((self, older), (Event::Progress(a), Event::Progress(b)) if a.phase == b.phase)
    }
}

/// The JSON name of a phase (snake case).
pub fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::Check => "check",
        Phase::Scan => "scan",
        Phase::Download => "download",
        Phase::Stage => "stage",
        Phase::Install => "install",
        Phase::Wait => "wait",
        Phase::Apply => "apply",
        Phase::Launch => "launch",
        Phase::Confirm => "confirm",
        Phase::Rollback => "rollback",
        Phase::Uninstall => "uninstall",
        _ => "other",
    }
}

fn source_name(source: Source) -> &'static str {
    match source {
        Source::Unchanged => "unchanged",
        Source::Range => "range",
        Source::FullPack => "full_pack",
        Source::Patch => "patch",
        _ => "other",
    }
}

/// `text` as a JSON string.
pub(crate) fn json_str(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub(crate) fn json_version(out: &mut String, v: Option<&Version>) {
    match v {
        Some(v) => json_str(out, &v.to_string()),
        None => out.push_str("null"),
    }
}

pub(crate) fn head(out: &mut String, kind: &str) {
    let _ = write!(out, "{{\"schema\":{SCHEMA},\"type\":");
    json_str(out, kind);
}

/// The schema-1 JSON line of `event`, without the trailing newline.
pub fn to_json_line(event: &Event) -> String {
    to_json(event, None)
}

/// [`to_json_line`] with a `time_ms` member (milliseconds since the Unix epoch), as the log
/// writes it.
pub fn to_json_line_at(event: &Event, time_ms: u64) -> String {
    to_json(event, Some(time_ms))
}

fn to_json(event: &Event, time_ms: Option<u64>) -> String {
    let mut out = String::with_capacity(128);
    match event {
        Event::Progress(p) => {
            head(&mut out, "progress");
            out.push_str(",\"phase\":");
            json_str(&mut out, phase_name(p.phase));
            let _ = write!(out, ",\"done\":{},\"total\":{},\"file\":", p.done, p.total);
            match &p.file {
                None => out.push_str("null"),
                Some(f) => {
                    out.push_str("{\"path\":");
                    json_str(&mut out, f.path.as_str());
                    let _ = write!(
                        out,
                        ",\"done\":{},\"total\":{},\"source\":",
                        f.done, f.total
                    );
                    json_str(&mut out, source_name(f.source));
                    out.push('}');
                }
            }
        }
        Event::Phase {
            phase,
            version,
            reason,
        } => {
            head(&mut out, "progress");
            out.push_str(",\"phase\":");
            json_str(&mut out, phase_name(*phase));
            out.push_str(",\"done\":0,\"total\":0,\"file\":null,\"version\":");
            json_version(&mut out, version.as_ref());
            if let Some(reason) = reason {
                out.push_str(",\"reason\":");
                json_str(&mut out, reason.name());
            }
        }
        Event::Warning { warning, version } => {
            head(&mut out, "warning");
            out.push_str(",\"code\":");
            json_str(&mut out, warning.code());
            out.push_str(",\"version\":");
            json_version(&mut out, version.as_ref());
        }
        Event::UiStopped { reason, exit_code } => {
            head(&mut out, "warning");
            out.push_str(",\"code\":\"ui_stopped\",\"version\":null,\"reason\":");
            json_str(&mut out, reason);
            if let Some(code) = exit_code {
                let _ = write!(out, ",\"ui_exit_code\":{code}");
            }
        }
        Event::Result {
            command,
            tree_version,
            outcome,
            version,
        } => {
            head(&mut out, "result");
            out.push_str(",\"command\":");
            json_str(&mut out, command);
            out.push_str(",\"tree_version\":");
            json_version(&mut out, tree_version.as_ref());
            out.push_str(",\"outcome\":");
            json_str(&mut out, outcome);
            out.push_str(",\"version\":");
            json_version(&mut out, version.as_ref());
        }
        Event::Error {
            command,
            tree_version,
            kind,
            exit_code,
        } => {
            head(&mut out, "error");
            out.push_str(",\"command\":");
            json_str(&mut out, command);
            out.push_str(",\"tree_version\":");
            json_version(&mut out, tree_version.as_ref());
            out.push_str(",\"kind\":");
            json_str(&mut out, kind);
            let _ = write!(out, ",\"exit_code\":{exit_code}");
        }
    }
    if let Some(t) = time_ms {
        let _ = write!(out, ",\"time_ms\":{t}");
    }
    out.push('}');
    out
}

/// The sink could not take the event; it receives nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkFailed;

/// Where events go. A sink runs on its own thread and may block; [`Events`] never waits for it
/// beyond the deadline given to [`Events::finish`].
pub trait Sink: Send + 'static {
    /// A fixed name (`log`, `stderr`, `ui`).
    fn name(&self) -> &'static str;

    /// Takes one event.
    fn deliver(&mut self, event: &Event) -> Result<(), SinkFailed>;
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Appends events as JSON lines to `<dir>/runtime.log` (created when missing), rotating it to
/// `runtime.log.1` (replacing an older one) before a line would take it past
/// [`LOG_ROTATE_BYTES`].
pub struct LogSink {
    fs: Arc<dyn Fs>,
    dir: PathBuf,
    max: u64,
    file: Option<Box<dyn FileWrite>>,
    size: u64,
}

impl LogSink {
    /// A sink for the log directory `dir` (`R/logs`).
    pub fn new(fs: Arc<dyn Fs>, dir: PathBuf) -> LogSink {
        LogSink::with_limit(fs, dir, LOG_ROTATE_BYTES)
    }

    /// [`LogSink::new`] with another rotation size.
    pub fn with_limit(fs: Arc<dyn Fs>, dir: PathBuf, max: u64) -> LogSink {
        LogSink {
            fs,
            dir,
            max,
            file: None,
            size: 0,
        }
    }

    fn open(&mut self) -> Result<(), SinkFailed> {
        self.fs.create_dir_all(&self.dir).map_err(|_| SinkFailed)?;
        let path = self.dir.join(LOG_FILE);
        let size = match self.fs.symlink_metadata(&path).map_err(|_| SinkFailed)? {
            None => {
                self.fs.create_new(&path).map_err(|_| SinkFailed)?;
                0
            }
            Some(meta) if meta.kind == lunepack::FileKind::File => meta.len,
            // Never write through a link or into something else.
            Some(_) => return Err(SinkFailed),
        };
        self.file = Some(self.fs.open_append(&path).map_err(|_| SinkFailed)?);
        self.size = size;
        Ok(())
    }

    fn rotate(&mut self) -> Result<(), SinkFailed> {
        self.file = None;
        let path = self.dir.join(LOG_FILE);
        let old = self.dir.join(LOG_FILE_OLD);
        match self.fs.remove_file(&old) {
            Ok(()) => {}
            Err(e) if e.kind == FsErrorKind::NotFound => {}
            Err(_) => return Err(SinkFailed),
        }
        self.fs.rename(&path, &old).map_err(|_| SinkFailed)?;
        self.open()
    }
}

impl Sink for LogSink {
    fn name(&self) -> &'static str {
        "log"
    }

    fn deliver(&mut self, event: &Event) -> Result<(), SinkFailed> {
        if self.file.is_none() {
            self.open()?;
        }
        let mut line = to_json_line_at(event, now_ms());
        line.push('\n');
        let len = line.len() as u64;
        if self.size > 0 && self.size + len > self.max {
            self.rotate()?;
        }
        let file = self.file.as_mut().ok_or(SinkFailed)?;
        file.write_all(line.as_bytes()).map_err(|_| SinkFailed)?;
        file.flush().map_err(|_| SinkFailed)?;
        self.size += len;
        Ok(())
    }
}

/// Writes events as JSON lines to stderr (a run with no install, whose log has no home yet).
pub struct StderrSink;

impl Sink for StderrSink {
    fn name(&self) -> &'static str {
        "stderr"
    }

    fn deliver(&mut self, event: &Event) -> Result<(), SinkFailed> {
        let mut line = to_json_line(event);
        line.push('\n');
        let mut err = std::io::stderr().lock();
        err.write_all(line.as_bytes()).map_err(|_| SinkFailed)?;
        err.flush().map_err(|_| SinkFailed)
    }
}

struct QueueState {
    items: VecDeque<Event>,
    closed: bool,
    dropped: bool,
    reported: bool,
}

struct Shared {
    state: Mutex<QueueState>,
    ready: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// One sink behind its bounded queue and its thread.
struct Queue {
    #[allow(dead_code)] // read by `Events::dropped`
    name: &'static str,
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}

impl Queue {
    fn start(mut sink: Box<dyn Sink>) -> Queue {
        let name = sink.name();
        let shared = Arc::new(Shared {
            state: Mutex::new(QueueState {
                items: VecDeque::with_capacity(QUEUE_CAP),
                closed: false,
                dropped: false,
                reported: false,
            }),
            ready: Condvar::new(),
        });
        let theirs = Arc::clone(&shared);
        let worker = std::thread::Builder::new()
            .name(format!("lunepack-sink-{name}"))
            .spawn(move || {
                loop {
                    let event = {
                        let mut st = theirs.lock();
                        loop {
                            if st.dropped {
                                return;
                            }
                            if let Some(e) = st.items.pop_front() {
                                break e;
                            }
                            if st.closed {
                                return;
                            }
                            st = theirs.ready.wait(st).unwrap_or_else(|e| e.into_inner());
                        }
                    };
                    if sink.deliver(&event).is_err() {
                        let mut st = theirs.lock();
                        st.dropped = true;
                        st.items.clear();
                        return;
                    }
                }
            })
            .ok();
        let queue = Queue {
            name,
            shared,
            worker,
        };
        if queue.worker.is_none() {
            queue.shared.lock().dropped = true;
        }
        queue
    }

    /// Queues `event` without blocking on the sink.
    fn push(&self, event: &Event) {
        let mut st = self.shared.lock();
        if st.dropped || st.closed {
            return;
        }
        if let Some(last) = st.items.back_mut()
            && event.coalesces_with(last)
        {
            *last = event.clone();
            return;
        }
        if st.items.len() >= QUEUE_CAP {
            // Latest wins: the oldest progress event makes room; with none, the sink is not
            // keeping up with events that matter, so it is dropped.
            match st
                .items
                .iter()
                .position(|e| matches!(e, Event::Progress(_)))
            {
                Some(at) => {
                    st.items.remove(at);
                }
                None => {
                    st.dropped = true;
                    st.items.clear();
                    return;
                }
            }
        }
        st.items.push_back(event.clone());
        drop(st);
        self.shared.ready.notify_one();
    }

    /// Whether the sink was dropped and that was not reported yet; marks it reported.
    fn newly_dropped(&self) -> bool {
        let mut st = self.shared.lock();
        if st.dropped && !st.reported {
            st.reported = true;
            return true;
        }
        false
    }

    fn close(&self) {
        self.shared.lock().closed = true;
        self.shared.ready.notify_all();
    }

    /// Waits until the worker ended or `until`; joins it when it ended.
    fn wait(&mut self, until: Instant) {
        let Some(worker) = self.worker.take() else {
            return;
        };
        while !worker.is_finished() && Instant::now() < until {
            std::thread::sleep(FINISH_POLL);
        }
        if worker.is_finished() {
            let _ = worker.join();
        }
    }
}

/// The fan-out of events to the sinks.
pub struct Events {
    log: Option<Queue>,
    ui: Option<Queue>,
}

/// How often [`Events::finish`] looks whether the sinks have drained.
const FINISH_POLL: Duration = Duration::from_millis(5);

impl Events {
    /// Events to `log` (the log file, or stderr) and, when there is one, a UI sink (M6).
    pub fn new(log: Option<Box<dyn Sink>>, ui: Option<Box<dyn Sink>>) -> Events {
        Events {
            log: log.map(Queue::start),
            ui: ui.map(Queue::start),
        }
    }

    /// Sends `event` to every sink. Never blocks on a sink.
    pub fn emit(&self, event: &Event) {
        self.note_dropped();
        if let Some(q) = &self.log {
            q.push(event);
        }
        if let Some(q) = &self.ui {
            q.push(event);
        }
    }

    /// Logs, once per sink, that a sink was dropped (a dropped log sink is not reported
    /// anywhere: the outcome is the exit code).
    fn note_dropped(&self) {
        if let Some(ui) = &self.ui
            && ui.newly_dropped()
            && let Some(log) = &self.log
        {
            log.push(&Event::warning(Warning::SinkDropped, None));
        }
        if let Some(log) = &self.log {
            log.newly_dropped();
        }
    }

    /// The names of the sinks that were dropped (tests ask; the binary reports through the log).
    #[allow(dead_code)]
    pub fn dropped(&self) -> Vec<&'static str> {
        [&self.log, &self.ui]
            .into_iter()
            .flatten()
            .filter(|q| q.shared.lock().dropped)
            .map(|q| q.name)
            .collect()
    }

    /// Lets the sinks drain what they hold for up to `deadline`, then returns; a sink still busy
    /// then is left behind (the process is about to exit). The UI sink gets the first half and
    /// ends first, so a drop it reports on the way still reaches the log.
    pub fn finish(mut self, deadline: Duration) {
        let now = Instant::now();
        let until = now + deadline;
        if let Some(ui) = self.ui.as_mut() {
            ui.close();
            ui.wait(now + deadline / 2);
        }
        self.note_dropped();
        if let Some(log) = self.log.as_mut() {
            log.close();
            log.wait(until);
        }
    }
}
