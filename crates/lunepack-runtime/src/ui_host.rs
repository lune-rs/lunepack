//! The engine's side of the UI channel (M6, C10): starts the separate `lunepack-ui` process, talks
//! to it over its standard input and output (M6-D1, M6-D2), validates every message it sends
//! against the core's flow reducer, and stops a UI that stalls, hangs, exits or breaks the
//! protocol. It is the only code that knows a UI process exists. The UI never decides anything,
//! and its failure never changes an outcome.
//!
//! Threads, all owned by one [`UiHost`]:
//!
//! - the **writer** is the only thread that writes to the child's standard input. Every frame
//!   (the sink's events, prompts, the outcome, `Ping`, `Close`) is handed to it through a bounded
//!   channel with `try_send`, so no other thread ever blocks on the UI; a full channel is a stall;
//! - the **reader** decodes the child's frames, checks each against the reducer
//!   ([`FlowState::accepts`]) and hands accepted choices to the prompt that waits for them; any
//!   other frame, a malformed one, or the end of the channel stops the UI;
//! - the **watchdog** stops a UI whose single write has been in progress longer than the stall
//!   bound, one that sends no hello in time, and one that exits.
//!
//! Stopping kills the child (only the own child) and makes the host headless; a prompt open then
//! resolves at once to its lost default (M6-D5), and the stop is logged once as `ui_stopped` with a
//! closed reason. While a prompt is open the host sends `Ping` every few seconds; a UI that does
//! not answer one within the hang bound is stopped. No thread is ever joined without a bound, so a
//! hung UI cannot keep the runtime alive.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use lunepack::{Child, ChildStdio, ExitKind, FileKind, Fs, HEALTH_TOKEN_VAR, Phase, Process};
use lunepack::{ProcessId, SpawnSpec};
use lunepack_core::ui::{
    self, AppCard, ChoiceValue, Details, EngineMsg, Flow, FlowState, Message, Outcome, PromptKind,
    StepItem, UiMsg,
};

use crate::events::{Event, Events, Sink, SinkFailed};

/// The UI binary's file name, beside the runtime.
#[cfg(windows)]
pub const UI_FILE: &str = "lunepack-ui.exe";
/// The UI binary's file name, beside the runtime.
#[cfg(not(windows))]
pub const UI_FILE: &str = "lunepack-ui";
/// The environment variable that makes every mode headless (M6-D6).
pub const NO_UI_VAR: &str = "LUNEPACK_NO_UI";
/// The UI's only argument.
pub const ENGINE_ARG: &str = "--engine";

/// Why the UI was stopped. Closed set; the names are the log's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UiStop {
    /// A frame could not be handed over, or one write took longer than the stall bound.
    Stalled,
    /// No answer to a `Ping` within the hang bound.
    Hung,
    /// The UI exited, or closed its end of the channel.
    Exited,
    /// The UI sent something the protocol or the flow does not allow.
    Protocol,
    /// The UI's build id is not this build's.
    BuildMismatch,
    /// No hello within the hello bound.
    HelloTimeout,
    /// The UI could not be started.
    SpawnFailed,
}

impl UiStop {
    /// The log name.
    pub const fn name(self) -> &'static str {
        match self {
            UiStop::Stalled => "stalled",
            UiStop::Hung => "hung",
            UiStop::Exited => "exited",
            UiStop::Protocol => "protocol",
            UiStop::BuildMismatch => "build_mismatch",
            UiStop::HelloTimeout => "hello_timeout",
            UiStop::SpawnFailed => "spawn_failed",
        }
    }

    /// The reason a UI exit code stands for (the UI's typed exit codes: 12 protocol error, 14
    /// build-id mismatch; any other exit is `exited`, and the code is logged beside it).
    pub const fn of_exit_code(code: Option<i32>) -> UiStop {
        match code {
            Some(12) => UiStop::Protocol,
            Some(14) => UiStop::BuildMismatch,
            _ => UiStop::Exited,
        }
    }
}

/// The time bounds of the channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// How long the UI has to send its hello after it was started.
    pub hello: Duration,
    /// How long one write may be in progress before it is a stall.
    pub stall: Duration,
    /// How often an open prompt sends a `Ping`.
    pub ping_every: Duration,
    /// How long a `Ping` may go unanswered before the UI counts as hung.
    pub pong_wait: Duration,
    /// How long the UI has to exit after `Close` before it is killed.
    pub close_wait: Duration,
    /// How often the watchdog looks.
    pub watch_tick: Duration,
}

impl Default for Bounds {
    fn default() -> Self {
        Bounds {
            hello: Duration::from_secs(20),
            stall: Duration::from_secs(2),
            ping_every: Duration::from_secs(5),
            pong_wait: Duration::from_secs(15),
            close_wait: Duration::from_secs(5),
            watch_tick: Duration::from_millis(200),
        }
    }
}

/// Most frames waiting for the writer; a frame that does not fit is a stall.
pub const WRITE_QUEUE: usize = 64;
/// Above this many waiting frames, the sink's byte progress is skipped (latest wins).
const PROGRESS_ROOM: usize = WRITE_QUEUE / 2;
/// How long the SIGTERM of a stopped UI may take before it is killed.
const KILL_GRACE: Duration = Duration::from_millis(100);
/// How often a waiting prompt looks for a choice or a stop.
const PROMPT_TICK: Duration = Duration::from_millis(20);
/// How long the reader waits for the exit status of a UI whose channel ended.
const EXIT_PEEK: Duration = Duration::from_secs(1);
/// The least time between two folder openings a UI asks for.
const REVEAL_EVERY: Duration = Duration::from_secs(1);

/// Whether a UI may be started at all, from the run's choice and the environment: never under
/// `--silent` or `--no-ui`, with `LUNEPACK_NO_UI` set to anything but empty or `0`, or, on Linux,
/// with neither `DISPLAY` nor `WAYLAND_DISPLAY` set (D41, M6-D6).
pub fn ui_wanted(quiet: bool, env: &dyn Fn(&str) -> Option<OsString>) -> bool {
    if quiet {
        return false;
    }
    if env(NO_UI_VAR).is_some_and(|v| !v.is_empty() && v != "0") {
        return false;
    }
    if cfg!(target_os = "linux") {
        let set = |name: &str| env(name).is_some_and(|v| !v.is_empty());
        return set("DISPLAY") || set("WAYLAND_DISPLAY");
    }
    true
}

/// The update window's helper app inside a bundle (macOS, M8-D6), relative to the bundle's
/// `Contents` directory.
#[cfg(target_os = "macos")]
const HELPER_UI: &str = "Helpers/lunepack-update.app/Contents/MacOS/lunepack-ui";

/// The UI binary of the runtime at `runtime_exe` (its resolved path): `lunepack-ui` in the same
/// directory, and only when it is a regular file there (not a link). On macOS an installed
/// bundle's runtime finds it first as the helper app nested in the bundle,
/// `Contents/Helpers/lunepack-update.app/Contents/MacOS/lunepack-ui` (M8-D6); the installer app
/// keeps it beside its runtime (M8-D7).
pub fn ui_program(fs: &dyn Fs, runtime_exe: &Path) -> Option<PathBuf> {
    let is_file =
        |p: &Path| matches!(fs.symlink_metadata(p), Ok(Some(m)) if m.kind == FileKind::File);
    let dir = runtime_exe.parent()?;
    #[cfg(target_os = "macos")]
    {
        // `<bundle>/Contents/MacOS/lunepack-runtime`: `Contents` is the directory above.
        if let Some(contents) = dir.parent() {
            let helper = contents.join(HELPER_UI);
            if is_file(&helper) {
                return Some(helper);
            }
        }
    }
    let program = dir.join(UI_FILE);
    is_file(&program).then_some(program)
}

/// What the stop log says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stopped {
    /// Why.
    pub reason: UiStop,
    /// The UI's exit code, when it exited with one.
    pub exit_code: Option<i32>,
}

struct Conv {
    state: FlowState,
    /// The UI's hello was accepted.
    hello: bool,
    stop: Option<Stopped>,
    /// The stop was logged (or needs no log: the normal end after `Close`).
    reported: bool,
    /// `Close` was sent: an exit is now the normal end.
    closing: bool,
    next_prompt: u32,
    ping_n: u32,
    /// The `Ping` waiting for its `Pong`, and when it was sent.
    ping_out: Option<(u32, Instant)>,
    last_ping: Option<Instant>,
}

struct Shared {
    bounds: Bounds,
    conv: Mutex<Conv>,
    tx: Mutex<Option<SyncSender<EngineMsg>>>,
    queued: AtomicUsize,
    write_started: Mutex<Option<Instant>>,
    child: Mutex<Box<dyn Child>>,
    child_id: ProcessId,
    spawned: Instant,
    done: AtomicBool,
    /// The reader has ended: everything the UI wrote before its end of the channel closed was
    /// read, or the reader stopped on its own.
    reader_done: AtomicBool,
    /// The UI is this process's parent (`--ui-stdio`, [`UiHost::over_parent`]): it is never
    /// stopped or waited for, only no longer written to.
    peer: bool,
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn exit_code(kind: ExitKind) -> Option<i32> {
    match kind {
        ExitKind::Success => Some(0),
        ExitKind::Failure(code) => Some(code),
        ExitKind::Signal(_) | ExitKind::Unknown => None,
    }
}

impl Shared {
    fn conv(&self) -> MutexGuard<'_, Conv> {
        guard(&self.conv)
    }

    fn stopped(&self) -> bool {
        self.conv().stop.is_some()
    }

    /// Stops the UI once: records why, ends the writer's channel and kills the own child.
    fn stop(&self, reason: UiStop, exit_code: Option<i32>) {
        self.stop_as(reason, exit_code, false);
    }

    /// Stops a UI that was seen to have exited with `code` (`None`: ended by a signal).
    fn stop_exited(&self, code: Option<i32>) {
        self.stop_as(UiStop::of_exit_code(code), code, code != Some(0));
    }

    /// [`Shared::stop`]. `died` says the UI was seen to end on its own, with a failure or by a
    /// signal. The engine cannot tell whether that came before or after it sent `Close` (the UI
    /// may have been killed on the first frame it read, while `Close` was already queued), so a
    /// stop while closing is left out of the log only when it is not a death.
    fn stop_as(&self, reason: UiStop, exit_code: Option<i32>, died: bool) {
        {
            let mut conv = self.conv();
            if conv.stop.is_some() {
                return;
            }
            conv.stop = Some(Stopped { reason, exit_code });
            // A clean exit after `Close` is the normal end, not worth a log line.
            if conv.closing && !died {
                conv.reported = true;
            }
        }
        guard(&self.tx).take();
        // The own child only. A writer blocked in a write gets a broken pipe, the reader the end
        // of file, once the child is gone.
        let _ = guard(&self.child).terminate(KILL_GRACE);
    }

    /// Applies `msg` to the reducer and hands it to the writer. A message the reducer refuses is
    /// not sent (the engine's own order decides; nothing is shown out of order). A full channel is
    /// a stall. Never blocks on the UI.
    fn send(&self, msg: EngineMsg) {
        let mut conv = self.conv();
        if conv.stop.is_some() {
            return;
        }
        if conv.state.apply(&msg).is_err() {
            return;
        }
        let result = match guard(&self.tx).as_ref() {
            Some(tx) => tx.try_send(msg),
            None => return,
        };
        match result {
            Ok(()) => {
                self.queued.fetch_add(1, Ordering::AcqRel);
            }
            Err(TrySendError::Full(_)) => {
                drop(conv);
                self.stop(UiStop::Stalled, None);
            }
            Err(TrySendError::Disconnected(_)) => {
                drop(conv);
                self.stop_gone();
            }
        }
    }

    /// Stops a UI whose channel ended: its exit code, when it has one within [`EXIT_PEEK`], says
    /// why.
    fn stop_gone(&self) {
        match self.exit_status(EXIT_PEEK) {
            Some(code) => self.stop_exited(code),
            None => self.stop(UiStop::Exited, None),
        }
    }

    /// Whether the UI said hello, once what it wrote before a stop was read: a stop seen by the
    /// watchdog or the writer (the UI's exit, a stall) can come before the reader got to a hello
    /// still in the pipe, so the reader gets up to `limit` to reach the end of the channel first.
    /// A UI that said hello and was then lost must get the lost answer (cancel before any
    /// change, M6-D5), never the headless one.
    fn said_hello(&self, limit: Duration) -> bool {
        let until = Instant::now() + limit;
        loop {
            if self.conv().hello {
                return true;
            }
            if self.reader_done.load(Ordering::Acquire) || Instant::now() >= until {
                return self.conv().hello;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The child's exit code once it has ended, waiting up to `limit` for it.
    fn exit_status(&self, limit: Duration) -> Option<Option<i32>> {
        let until = Instant::now() + limit;
        loop {
            if let Ok(Some(kind)) = guard(&self.child).try_wait() {
                return Some(exit_code(kind));
            }
            if Instant::now() >= until {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn writer(shared: Arc<Shared>, rx: Receiver<EngineMsg>, mut out: Box<dyn Write + Send>) {
    for msg in rx {
        *guard(&shared.write_started) = Some(Instant::now());
        let written = ui::write_frame(&mut out, &msg);
        *guard(&shared.write_started) = None;
        shared.queued.fetch_sub(1, Ordering::AcqRel);
        match written {
            Ok(()) => {}
            // The UI is gone.
            Err(ui::ProtocolError::Io(_)) => {
                if !shared.stopped() {
                    shared.stop_gone();
                }
                break;
            }
            // A message over a cap is not sent; the callers keep text within the caps.
            Err(_) => {}
        }
    }
    // Dropping the write end is the UI's end of file.
}

fn reader(
    shared: Arc<Shared>,
    input: Box<dyn Read + Send>,
    choices: SyncSender<(u32, ChoiceValue)>,
) {
    read_frames(&shared, input, choices);
    shared.reader_done.store(true, Ordering::Release);
}

fn read_frames(
    shared: &Shared,
    mut input: Box<dyn Read + Send>,
    choices: SyncSender<(u32, ChoiceValue)>,
) {
    loop {
        let msg = match ui::read_frame::<_, UiMsg>(&mut input) {
            Ok(msg) => msg,
            Err(e) => {
                if shared.stopped() {
                    return;
                }
                match e {
                    ui::ProtocolError::Closed | ui::ProtocolError::Io(_) => shared.stop_gone(),
                    _ => shared.stop(UiStop::Protocol, None),
                }
                return;
            }
        };
        let mut conv = shared.conv();
        if conv.stop.is_some() {
            // Stopped already (its exit seen by the watchdog, say): only a valid hello the UI
            // wrote before still counts, so that a UI that said hello and then died is a lost UI
            // and not an absent one. Nothing else is acted on.
            if !conv.hello
                && let UiMsg::Hello { build_id } = &msg
                && ui::check_hello(build_id).is_ok()
            {
                conv.hello = true;
            }
            return;
        }
        if !conv.hello {
            let verdict = match &msg {
                UiMsg::Hello { build_id } => match ui::check_hello(build_id) {
                    Ok(()) => None,
                    Err(_) => Some(UiStop::BuildMismatch),
                },
                _ => Some(UiStop::Protocol),
            };
            match verdict {
                None => conv.hello = true,
                Some(reason) => {
                    drop(conv);
                    shared.stop(reason, None);
                    return;
                }
            }
            continue;
        }
        if conv.closing {
            // Only a late `Pong` is valid now; nothing after `Close` is acted on.
            continue;
        }
        if !conv.state.accepts(&msg) || conv.state.answer(&msg).is_err() {
            drop(conv);
            shared.stop(UiStop::Protocol, None);
            return;
        }
        match msg {
            UiMsg::Pong { n } => {
                if conv.ping_out.is_some_and(|(out, _)| out == n) {
                    conv.ping_out = None;
                }
            }
            UiMsg::Choice { id, value } => {
                drop(conv);
                // Blocks this thread only, while no prompt takes choices.
                if choices.send((id, value)).is_err() {
                    return;
                }
            }
            // Not accepted in any state this host creates (it never offers a cancel while
            // running), so not reached.
            UiMsg::Cancel | UiMsg::Hello { .. } => {}
        }
    }
}

fn watchdog(shared: Arc<Shared>) {
    let b = shared.bounds;
    loop {
        std::thread::sleep(b.watch_tick);
        if shared.done.load(Ordering::Acquire) || shared.stopped() {
            return;
        }
        let stalled = guard(&shared.write_started).is_some_and(|t| t.elapsed() > b.stall);
        if stalled {
            shared.stop(UiStop::Stalled, None);
            return;
        }
        let (hello, closing) = {
            let conv = shared.conv();
            (conv.hello, conv.closing)
        };
        if !hello && shared.spawned.elapsed() > b.hello {
            shared.stop(UiStop::HelloTimeout, None);
            return;
        }
        if closing {
            continue;
        }
        let exited = guard(&shared.child).try_wait();
        if let Ok(Some(kind)) = exited {
            shared.stop_exited(exit_code(kind));
            return;
        }
    }
}

/// The UI of one run, or none (headless). Every call works on a headless host and returns at
/// once with the headless answer.
pub struct UiHost {
    shared: Option<Arc<Shared>>,
    choices: Option<Receiver<(u32, ChoiceValue)>>,
    flow: Flow,
    /// A stop before any thread existed (the spawn failed), still to be logged.
    early: Mutex<Option<Stopped>>,
    last_reveal: Mutex<Option<Instant>>,
    /// The UI itself answered the prompt after the outcome (done or failed): the user saw it.
    outcome_acknowledged: AtomicBool,
}

/// What a run starts the UI with.
pub struct Start<'a> {
    /// The processes adapter.
    pub process: Arc<dyn Process>,
    /// The filesystem adapter (to look at the UI binary).
    pub fs: &'a dyn Fs,
    /// The runtime's own resolved executable path; the UI is beside it.
    pub runtime_exe: &'a Path,
    /// The environment (`LUNEPACK_NO_UI`, `DISPLAY`, `WAYLAND_DISPLAY`).
    pub env: &'a dyn Fn(&str) -> Option<OsString>,
    /// `--silent` or `--no-ui`.
    pub quiet: bool,
}

impl UiHost {
    /// A host with no UI.
    pub fn headless(flow: Flow) -> UiHost {
        UiHost {
            shared: None,
            choices: None,
            flow,
            early: Mutex::new(None),
            last_reveal: Mutex::new(None),
            outcome_acknowledged: AtomicBool::new(false),
        }
    }

    /// Starts the UI for `flow` when one is wanted and present ([`ui_wanted`], [`ui_program`]);
    /// else a headless host. Never fails and never waits for the UI.
    pub fn start(start: &Start<'_>, flow: Flow, app: AppCard, details: Details) -> UiHost {
        UiHost::start_with(Bounds::default(), start, flow, app, details)
    }

    /// [`UiHost::start`] with other bounds (tests).
    pub fn start_with(
        bounds: Bounds,
        start: &Start<'_>,
        flow: Flow,
        app: AppCard,
        details: Details,
    ) -> UiHost {
        let mut host = UiHost::headless(flow);
        if !ui_wanted(start.quiet, start.env) {
            return host;
        }
        let Some(program) = ui_program(start.fs, start.runtime_exe) else {
            return host;
        };
        let hello = EngineMsg::Hello {
            build_id: ui::build_id(),
            flow,
            app,
            details,
        };
        // A hello over a cap would never reach the UI: no UI then.
        if hello.encode().is_err() {
            return host;
        }
        let spec = SpawnSpec {
            program,
            args: vec![OsString::from(ENGINE_ARG)],
            env_set: Vec::new(),
            env_remove: vec![OsString::from(HEALTH_TOKEN_VAR)],
            stdio: ChildStdio::Piped,
        };
        let mut child = match start.process.spawn_child(&spec) {
            Ok(child) => child,
            Err(_) => {
                *guard(&host.early) = Some(Stopped {
                    reason: UiStop::SpawnFailed,
                    exit_code: None,
                });
                return host;
            }
        };
        let (Some(input), Some(output)) = (child.take_stdin(), child.take_stdout()) else {
            let _ = child.terminate(KILL_GRACE);
            *guard(&host.early) = Some(Stopped {
                reason: UiStop::SpawnFailed,
                exit_code: None,
            });
            return host;
        };
        host.connect(bounds, hello, child, input, output, false);
        host
    }

    /// The UI of an installer app (macOS, M8-D7): the UI is this process's parent, which started
    /// it with `--ui-stdio`, and the frames go over this process's own standard output (`output`)
    /// and input (`input`), as they would over a child's. Everything the UI sends is checked as a
    /// child's is (C10). The parent is never signalled and never waited for: a UI that stalls,
    /// hangs, breaks the protocol, exits or closes its end is no longer written to, and the run
    /// goes on headless under the M6-D5 rules. `parent` names it (pid and start time), so its exit
    /// is seen even while its end of the channel stays open. `LUNEPACK_NO_UI` does not apply: no
    /// UI is started here.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    #[allow(clippy::too_many_arguments)]
    pub fn over_parent(
        bounds: Bounds,
        process: Arc<dyn Process>,
        parent: ProcessId,
        input: Box<dyn Read + Send>,
        output: Box<dyn Write + Send>,
        flow: Flow,
        app: AppCard,
        details: Details,
    ) -> UiHost {
        let mut host = UiHost::headless(flow);
        let hello = EngineMsg::Hello {
            build_id: ui::build_id(),
            flow,
            app,
            details,
        };
        if hello.encode().is_err() {
            return host;
        }
        let peer = Box::new(Parent {
            process,
            id: parent,
            gone: false,
        });
        host.connect(bounds, hello, peer, output, input, true);
        host
    }

    /// Starts the threads of a conversation with `child` over `input` (the UI's standard input)
    /// and `output` (its standard output), and sends `hello`.
    fn connect(
        &mut self,
        bounds: Bounds,
        hello: EngineMsg,
        child: Box<dyn Child>,
        input: Box<dyn Write + Send>,
        output: Box<dyn Read + Send>,
        peer: bool,
    ) {
        let flow = self.flow;
        let (tx, rx) = mpsc::sync_channel::<EngineMsg>(WRITE_QUEUE);
        let (choice_tx, choice_rx) = mpsc::sync_channel(4);
        let shared = Arc::new(Shared {
            bounds,
            conv: Mutex::new(Conv {
                state: FlowState::expecting(flow),
                hello: false,
                stop: None,
                reported: false,
                closing: false,
                next_prompt: 1,
                ping_n: 0,
                ping_out: None,
                last_ping: None,
            }),
            tx: Mutex::new(Some(tx)),
            queued: AtomicUsize::new(0),
            write_started: Mutex::new(None),
            child_id: child.id(),
            child: Mutex::new(child),
            spawned: Instant::now(),
            done: AtomicBool::new(false),
            reader_done: AtomicBool::new(false),
            peer,
        });
        let threads = [
            spawn_named("lunepack-ui-writer", {
                let shared = Arc::clone(&shared);
                move || writer(shared, rx, input)
            }),
            spawn_named("lunepack-ui-reader", {
                let shared = Arc::clone(&shared);
                move || reader(shared, output, choice_tx)
            }),
            spawn_named("lunepack-ui-watchdog", {
                let shared = Arc::clone(&shared);
                move || watchdog(shared)
            }),
        ];
        if !threads[1] {
            // No reader: nothing more will ever be read.
            shared.reader_done.store(true, Ordering::Release);
        }
        if threads.iter().any(|ok| !ok) {
            shared.stop(UiStop::SpawnFailed, None);
        }
        shared.send(hello);
        self.shared = Some(shared);
        self.choices = Some(choice_rx);
    }

    /// The sink that shows the run's events in the UI, when there is a UI.
    pub fn sink(&self) -> Option<Box<dyn Sink>> {
        let shared = self.shared.as_ref()?;
        Some(Box::new(UiSink {
            shared: Arc::clone(shared),
            flow: self.flow,
        }))
    }

    /// The UI process, while it was started by this host (to exclude it from an in-use scan).
    pub fn child_id(&self) -> Option<ProcessId> {
        self.shared.as_ref().map(|s| s.child_id)
    }

    /// Whether the UI itself answered the prompt after the outcome (done or failed), so the user
    /// saw how the run ended in the UI. `false` for a headless host, a UI that could not be
    /// started and a UI lost before that prompt was answered.
    pub fn outcome_acknowledged(&self) -> bool {
        self.outcome_acknowledged.load(Ordering::Acquire)
    }

    /// Why the UI stopped, if it did (the binary reports it through the log; tests ask).
    #[allow(dead_code)]
    pub fn stopped(&self) -> Option<Stopped> {
        if let Some(early) = *guard(&self.early) {
            return Some(early);
        }
        self.shared.as_ref().and_then(|s| s.conv().stop)
    }

    /// Logs a stop once (`ui_stopped`), when there is one not logged yet.
    pub fn report(&self, events: &Events) {
        if let Some(early) = guard(&self.early).take() {
            events.emit(&Event::UiStopped {
                reason: early.reason.name(),
                exit_code: early.exit_code,
            });
            return;
        }
        let Some(shared) = &self.shared else {
            return;
        };
        let stop = {
            let mut conv = shared.conv();
            match conv.stop {
                Some(stop) if !conv.reported => {
                    conv.reported = true;
                    Some(stop)
                }
                _ => None,
            }
        };
        if let Some(stop) = stop {
            events.emit(&Event::UiStopped {
                reason: stop.reason.name(),
                exit_code: stop.exit_code,
            });
        }
    }

    /// Reports items as done (they are dropped when the screen does not take them).
    pub fn steps(&self, items: &[StepItem]) {
        if let Some(shared) = &self.shared {
            for item in items {
                shared.send(EngineMsg::Step { item: *item });
            }
        }
    }

    /// Tells the UI how the operation ended.
    pub fn outcome(&self, outcome: Outcome) {
        if let Some(shared) = &self.shared {
            shared.send(EngineMsg::Outcome(outcome));
        }
    }

    /// Asks `kind` and waits for the answer. A headless host answers with the headless default at
    /// once: proceed, finish without launching, close, acknowledge; so does a UI that stopped
    /// before its hello, once the reader has read what the UI wrote before it ended (up to
    /// [`EXIT_PEEK`]): a hello found there counts. A UI lost after its hello answers with the lost
    /// default (M6-D5): cancel at a prompt before any change (welcome, confirm), the headless
    /// default at one after the outcome. A `reveal` keeps the prompt open: `on_reveal` gets its
    /// index (at most one a second; the reducer already checked it against the outcome's
    /// leftovers).
    pub fn prompt(
        &self,
        kind: PromptKind,
        events: &Events,
        on_reveal: &mut dyn FnMut(u32),
    ) -> ChoiceValue {
        let answer = self.ask(kind, on_reveal);
        self.report(events);
        answer
    }

    fn ask(&self, kind: PromptKind, on_reveal: &mut dyn FnMut(u32)) -> ChoiceValue {
        let headless = headless_answer(kind, self.flow);
        let (Some(shared), Some(choices)) = (&self.shared, &self.choices) else {
            return headless;
        };
        let lost = || {
            if shared.said_hello(EXIT_PEEK) {
                lost_answer(kind, self.flow)
            } else {
                headless
            }
        };
        let id = {
            let mut conv = shared.conv();
            if conv.stop.is_some() {
                drop(conv);
                return lost();
            }
            let id = conv.next_prompt;
            conv.next_prompt += 1;
            id
        };
        shared.send(EngineMsg::Prompt { id, kind });
        let b = shared.bounds;
        loop {
            if shared.stopped() {
                return lost();
            }
            // Liveness: one `Ping` out at a time, a new one `ping_every` after the last, and a
            // hang when one goes unanswered for `pong_wait`. Only once the UI said hello.
            let ping = {
                let mut conv = shared.conv();
                if !conv.hello {
                    None
                } else if let Some((_, sent)) = conv.ping_out {
                    if sent.elapsed() > b.pong_wait {
                        Some(None)
                    } else {
                        None
                    }
                } else if conv.last_ping.is_none_or(|t| t.elapsed() >= b.ping_every) {
                    conv.ping_n = conv.ping_n.wrapping_add(1);
                    let n = conv.ping_n;
                    conv.ping_out = Some((n, Instant::now()));
                    conv.last_ping = Some(Instant::now());
                    Some(Some(n))
                } else {
                    None
                }
            };
            match ping {
                Some(None) => {
                    shared.stop(UiStop::Hung, None);
                    return lost();
                }
                Some(Some(n)) => shared.send(EngineMsg::Ping { n }),
                None => {}
            }
            match choices.recv_timeout(PROMPT_TICK) {
                // A choice for an earlier prompt (the reader checked it then).
                Ok((got, _)) if got != id => {}
                Ok((_, ChoiceValue::Reveal { index })) => {
                    let mut last = guard(&self.last_reveal);
                    if last.is_none_or(|t| t.elapsed() >= REVEAL_EVERY) {
                        *last = Some(Instant::now());
                        drop(last);
                        on_reveal(index);
                    }
                }
                Ok((_, value)) => {
                    if matches!(kind, PromptKind::Done | PromptKind::Failed) {
                        self.outcome_acknowledged.store(true, Ordering::Release);
                    }
                    return value;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    shared.stop_gone();
                    return lost();
                }
            }
        }
    }

    /// Ends the conversation: `Close`, then up to the close bound for the UI to exit before it is
    /// killed. Logs a stop not logged yet. Bounded whatever the UI does.
    pub fn close(self, events: &Events) {
        if let Some(shared) = &self.shared {
            if !shared.stopped() {
                // Closing first: the UI's exit after `Close` is its normal end.
                shared.conv().closing = true;
                shared.send(EngineMsg::Close);
            }
            // The writer writes what it holds, then ends, which closes the UI's input.
            guard(&shared.tx).take();
            if shared.peer {
                // The parent outlives this process: only the frames still queued are written,
                // within the close bound.
                let until = Instant::now() + shared.bounds.close_wait;
                while shared.queued.load(Ordering::Acquire) > 0
                    && !shared.stopped()
                    && Instant::now() < until
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
            } else {
                // A UI that ended by itself on a failure or a signal did not end normally,
                // whatever the engine was doing when it did; the stop is then logged (a clean
                // exit is not).
                match shared.exit_status(shared.bounds.close_wait) {
                    Some(code) if code != Some(0) => shared.stop_exited(code),
                    Some(_) => {}
                    None => {
                        let _ = guard(&shared.child).terminate(KILL_GRACE);
                    }
                }
            }
            shared.done.store(true, Ordering::Release);
        }
        self.report(events);
    }
}

/// The parent that is the UI (`--ui-stdio`), in the place of a child. It is never signalled:
/// [`Child::terminate`] does nothing, so a stop only ends the conversation. It counts as ended
/// once no process runs with its pid and start time.
struct Parent {
    process: Arc<dyn Process>,
    id: ProcessId,
    gone: bool,
}

impl Child for Parent {
    fn id(&self) -> ProcessId {
        self.id
    }

    fn try_wait(&mut self) -> Result<Option<ExitKind>, lunepack_core::Error> {
        if !self.gone {
            // A look, not a wait; a process that cannot be read is taken to run.
            self.gone = matches!(
                self.process.wait_exit(&self.id, Duration::ZERO),
                Ok(lunepack::WaitOutcome::Exited)
            );
        }
        Ok(self.gone.then_some(ExitKind::Unknown))
    }

    fn terminate(&mut self, _grace: Duration) -> Result<(), lunepack_core::Error> {
        Ok(())
    }

    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        None
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        None
    }
}

fn spawn_named(name: &str, body: impl FnOnce() + Send + 'static) -> bool {
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(body)
        .is_ok()
}

/// The answer of a prompt when no UI shows it (D41: proceed; launch = no).
pub fn headless_answer(kind: PromptKind, flow: Flow) -> ChoiceValue {
    match kind {
        PromptKind::Welcome | PromptKind::Confirm => ChoiceValue::Proceed,
        PromptKind::Done if flow == Flow::Install => ChoiceValue::Finish { launch: false },
        PromptKind::Done | PromptKind::Failed => ChoiceValue::Close,
        PromptKind::RolledBack => ChoiceValue::Acknowledge,
    }
}

/// The answer of a prompt whose UI was lost after its hello (M6-D5): cancel before any change,
/// else the headless answer.
pub fn lost_answer(kind: PromptKind, flow: Flow) -> ChoiceValue {
    match kind {
        PromptKind::Welcome | PromptKind::Confirm => ChoiceValue::Cancel,
        _ => headless_answer(kind, flow),
    }
}

/// The run's events, shown in the UI. Never blocks and never fails: a UI that cannot keep up is
/// stopped by the host, and the run goes on.
struct UiSink {
    shared: Arc<Shared>,
    flow: Flow,
}

impl Sink for UiSink {
    fn name(&self) -> &'static str {
        "ui"
    }

    fn deliver(&mut self, event: &Event) -> Result<(), SinkFailed> {
        for msg in frames_of(self.flow, event) {
            let byte_progress = matches!(event, Event::Progress(_));
            if byte_progress && self.shared.queued.load(Ordering::Acquire) > PROGRESS_ROOM {
                continue;
            }
            self.shared.send(msg);
        }
        Ok(())
    }
}

/// The frames an event becomes in `flow`. The update flow shows the starting screen only once
/// the new version runs: its `launch` phase reports the apply as done, its `confirm` phase (after
/// the start) moves the screen.
fn frames_of(flow: Flow, event: &Event) -> Vec<EngineMsg> {
    let progress = |phase: Phase, done: u64, total: u64| EngineMsg::Progress { phase, done, total };
    match event {
        Event::Progress(p) => vec![progress(p.phase, p.done, p.total)],
        Event::Phase { phase, .. } => match (flow, phase) {
            (Flow::Update, Phase::Apply) => vec![
                EngineMsg::Step {
                    item: StepItem::WaitApp,
                },
                progress(Phase::Apply, 0, 0),
            ],
            (Flow::Update, Phase::Launch) => vec![EngineMsg::Step {
                item: StepItem::Apply,
            }],
            (Flow::Update, Phase::Confirm) => vec![
                EngineMsg::Step {
                    item: StepItem::Launch,
                },
                progress(Phase::Confirm, 0, 0),
            ],
            // The rollback screen comes with the outcome, after the previous version started.
            (Flow::Update, Phase::Rollback) => Vec::new(),
            (_, phase) => vec![progress(*phase, 0, 0)],
        },
        _ => Vec::new(),
    }
}

/// `text` when it fits `cap` bytes, else nothing.
pub fn within(text: String, cap: usize) -> Option<String> {
    (text.len() <= cap).then_some(text)
}

/// The leftovers an uninstall outcome can carry: at most [`ui::MAX_LEFTOVERS`] paths of at most
/// [`ui::MAX_LEFTOVER`] bytes each (others are left out).
pub fn leftovers(paths: Vec<String>) -> Vec<String> {
    paths
        .into_iter()
        .filter(|p| p.len() <= ui::MAX_LEFTOVER)
        .take(ui::MAX_LEFTOVERS)
        .collect()
}

/// The card of an app, its text cut to the caps (a name over the cap cannot come from a valid
/// config; a version over it is shown as nothing).
pub fn card(name: &str, version: &str, from: Option<&str>) -> AppCard {
    let fit = |t: &str, cap: usize| {
        if t.chars().count() <= cap {
            t.to_owned()
        } else {
            t.chars().take(cap).collect()
        }
    };
    AppCard {
        name: fit(name, ui::MAX_NAME),
        version: fit(version, ui::MAX_VERSION),
        from_version: from.map(|f| fit(f, ui::MAX_VERSION)),
        publisher: None,
        icon_png: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use lunepack_testkit::{ChildScript, FakeChildPipes, FakeProcess, abs_path};

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| OsString::from(v))
        }
    }

    struct World {
        _tmp: tempfile::TempDir,
        exe: PathBuf,
        fs: lunepack_fs::StdFs,
        process: FakeProcess,
    }

    fn world(with_ui: bool) -> World {
        let tmp = tempfile::tempdir().expect("tmp");
        let exe = tmp.path().join("lunepack-runtime");
        std::fs::write(&exe, b"").expect("exe");
        if with_ui {
            std::fs::write(tmp.path().join(UI_FILE), b"").expect("ui");
        }
        World {
            exe,
            _tmp: tmp,
            fs: lunepack_fs::StdFs::new(),
            process: FakeProcess::new("/fake/lunepack-runtime"),
        }
    }

    fn start(w: &World, quiet: bool, env: &dyn Fn(&str) -> Option<OsString>) -> UiHost {
        let process: Arc<dyn Process> = Arc::new(w.process.clone());
        UiHost::start(
            &Start {
                process,
                fs: &w.fs,
                runtime_exe: &w.exe,
                env,
                quiet,
            },
            Flow::Install,
            card("App", "1.0.0", None),
            Details {
                location: None,
                size_bytes: None,
            },
        )
    }

    #[test]
    fn silent_and_no_ui_start_no_process() {
        let display = env_of(&[("DISPLAY", ":0")]);
        let no_ui = env_of(&[("DISPLAY", ":0"), ("LUNEPACK_NO_UI", "1")]);
        let empty_display = env_of(&[("DISPLAY", ""), ("WAYLAND_DISPLAY", "")]);
        let w = world(true);
        for (quiet, env) in [
            (true, &display as &dyn Fn(&str) -> Option<OsString>),
            (false, &no_ui),
        ] {
            let host = start(&w, quiet, env);
            assert!(host.child_id().is_none());
        }
        if cfg!(target_os = "linux") {
            let host = start(&w, false, &empty_display);
            assert!(host.child_id().is_none());
        }
        assert_eq!(w.process.spawns().len(), 0, "a UI was started");
        // An absent binary starts nothing either.
        let bare = world(false);
        assert!(start(&bare, false, &display).child_id().is_none());
        assert_eq!(bare.process.spawns().len(), 0);
    }

    #[test]
    fn a_wanted_ui_is_started_beside_the_runtime_with_a_fixed_argv() {
        let w = world(true);
        w.process.script_child(ChildScript::runs());
        let display = env_of(&[("DISPLAY", ":0"), ("LUNEPACK_NO_UI", "0")]);
        let host = start(&w, false, &display);
        assert!(host.child_id().is_some());
        let spawns = w.process.spawns();
        assert_eq!(spawns.len(), 1);
        let s = &spawns[0];
        assert!(!s.detached);
        assert_eq!(s.program, w.exe.parent().expect("dir").join(UI_FILE));
        assert_eq!(s.args, vec![OsString::from(ENGINE_ARG)]);
        assert!(s.env_set.is_empty());
        assert_eq!(s.env_remove, vec![OsString::from(HEALTH_TOKEN_VAR)]);
        assert_eq!(s.stdio, ChildStdio::Piped);
    }

    /// An installed bundle's runtime finds the update window as the helper app nested in the
    /// bundle (M8-D6); the installer app's UI beside the runtime is the fallback (M8-D7); a linked
    /// or absent helper is none.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_runtime_of_a_bundle_finds_the_helper_app_first() {
        let tmp = tempfile::tempdir().expect("tmp");
        let contents = tmp.path().join("Hello.app/Contents");
        let macos = contents.join("MacOS");
        let helper_dir = contents.join("Helpers/lunepack-update.app/Contents/MacOS");
        std::fs::create_dir_all(&macos).expect("dirs");
        std::fs::create_dir_all(&helper_dir).expect("dirs");
        let exe = macos.join("lunepack-runtime");
        std::fs::write(&exe, b"").expect("exe");
        let fs = lunepack_fs::StdFs::new();
        assert!(ui_program(&fs, &exe).is_none(), "nothing to start yet");
        // The installer's layout: the UI beside the runtime.
        std::fs::write(macos.join(UI_FILE), b"").expect("sibling");
        assert_eq!(ui_program(&fs, &exe), Some(macos.join(UI_FILE)));
        // The helper app wins when the bundle has one.
        let helper = helper_dir.join("lunepack-ui");
        std::fs::write(&helper, b"").expect("helper");
        assert_eq!(ui_program(&fs, &exe), Some(helper.clone()));
        // A helper that is a link is not started; the sibling is.
        std::fs::remove_file(&helper).expect("remove");
        std::os::unix::fs::symlink("/bin/true", &helper).expect("link");
        assert_eq!(ui_program(&fs, &exe), Some(macos.join(UI_FILE)));
    }

    #[test]
    fn a_linked_ui_binary_is_not_started() {
        let w = world(false);
        #[cfg(unix)]
        std::os::unix::fs::symlink("/bin/true", w.exe.parent().expect("dir").join(UI_FILE))
            .expect("link");
        assert!(ui_program(&w.fs, &w.exe).is_none());
    }

    #[test]
    fn answers_without_a_ui() {
        use ChoiceValue as C;
        assert_eq!(
            headless_answer(PromptKind::Welcome, Flow::Install),
            C::Proceed
        );
        assert_eq!(
            headless_answer(PromptKind::Confirm, Flow::Uninstall),
            C::Proceed
        );
        assert_eq!(
            headless_answer(PromptKind::Done, Flow::Install),
            C::Finish { launch: false }
        );
        assert_eq!(headless_answer(PromptKind::Done, Flow::Uninstall), C::Close);
        assert_eq!(headless_answer(PromptKind::Failed, Flow::Install), C::Close);
        assert_eq!(
            headless_answer(PromptKind::RolledBack, Flow::Update),
            C::Acknowledge
        );
        assert_eq!(lost_answer(PromptKind::Welcome, Flow::Install), C::Cancel);
        assert_eq!(lost_answer(PromptKind::Confirm, Flow::Uninstall), C::Cancel);
        assert_eq!(
            lost_answer(PromptKind::Done, Flow::Install),
            C::Finish { launch: false }
        );
        assert_eq!(
            lost_answer(PromptKind::RolledBack, Flow::Update),
            C::Acknowledge
        );
    }

    /// Collects the lines the events become.
    struct Capture(Arc<Mutex<Vec<String>>>);

    impl Sink for Capture {
        fn name(&self) -> &'static str {
            "capture"
        }

        fn deliver(&mut self, event: &Event) -> Result<(), SinkFailed> {
            guard(&self.0).push(crate::events::to_json_line(event));
            Ok(())
        }
    }

    /// A host whose UI child follows `script`, with its pipes held open by the test (so only the
    /// child's exit says it is gone) and a watchdog that never looks.
    fn host_with(script: ChildScript) -> (World, UiHost, FakeChildPipes) {
        let w = world(true);
        w.process.script_child(script);
        let display = env_of(&[("DISPLAY", ":0")]);
        let process: Arc<dyn Process> = Arc::new(w.process.clone());
        let bounds = Bounds {
            watch_tick: Duration::from_secs(3600),
            close_wait: Duration::from_millis(500),
            ..Bounds::default()
        };
        let host = UiHost::start_with(
            bounds,
            &Start {
                process,
                fs: &w.fs,
                runtime_exe: &w.exe,
                env: &display,
                quiet: false,
            },
            Flow::Update,
            card("App", "2.0.0", Some("1.0.0")),
            Details {
                location: None,
                size_bytes: None,
            },
        );
        let id = host.child_id().expect("the UI was started");
        let pipes = w.process.take_child_pipes(id).expect("piped child");
        (w, host, pipes)
    }

    /// The log lines a run's end (`close`, after the UI exited as `script` says) produces.
    fn lines_after_close(script: ChildScript) -> Vec<String> {
        let (_w, host, _pipes) = host_with(script);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let events = Events::new(Some(Box::new(Capture(Arc::clone(&seen)))), None);
        host.close(&events);
        events.finish(Duration::from_secs(2));
        guard(&seen).clone()
    }

    #[test]
    fn a_ui_that_died_is_logged_even_when_the_run_was_already_closing() {
        // The UI is killed on the first frame it reads; the engine had already sent `Close` and
        // only sees the exit while it waits for it (row 10 of the end-to-end suite flaked on this).
        for (script, code) in [
            (ChildScript::exits(3, ExitKind::Signal(6)), None),
            (ChildScript::exits(3, ExitKind::Failure(1)), Some(1)),
        ] {
            let lines = lines_after_close(script);
            assert_eq!(lines.len(), 1, "{lines:?}");
            assert!(lines[0].contains("\"code\":\"ui_stopped\""), "{lines:?}");
            assert!(lines[0].contains("\"reason\":\"exited\""), "{lines:?}");
            assert_eq!(
                lines[0].contains(&format!("\"ui_exit_code\":{}", code.unwrap_or(0))),
                code.is_some(),
                "{lines:?}"
            );
        }
    }

    #[test]
    fn a_ui_that_exits_cleanly_after_close_is_not_logged() {
        let lines = lines_after_close(ChildScript::exits(3, ExitKind::Success));
        assert!(lines.is_empty(), "{lines:?}");
    }

    #[test]
    fn a_ui_that_must_be_killed_after_close_is_not_logged() {
        // Our own kill is not a stop to report.
        let lines = lines_after_close(ChildScript::runs());
        assert!(lines.is_empty(), "{lines:?}");
    }

    #[test]
    fn the_exit_seen_by_the_channel_while_closing_is_logged_only_for_a_death() {
        // The reader (or the writer) finds the channel ended after `Close` was queued.
        for (kind, logged) in [
            (ExitKind::Signal(6), true),
            (ExitKind::Failure(3), true),
            (ExitKind::Success, false),
        ] {
            let (_w, host, _pipes) = host_with(ChildScript::exits(0, kind));
            let shared = Arc::clone(host.shared.as_ref().expect("a UI"));
            shared.conv().closing = true;
            shared.stop_gone();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let events = Events::new(Some(Box::new(Capture(Arc::clone(&seen)))), None);
            host.report(&events);
            events.finish(Duration::from_secs(2));
            assert_eq!(guard(&seen).len(), usize::from(logged), "{kind:?}");
        }
    }

    #[test]
    fn exit_codes_map_to_the_closed_reasons() {
        assert_eq!(UiStop::of_exit_code(Some(12)), UiStop::Protocol);
        assert_eq!(UiStop::of_exit_code(Some(14)), UiStop::BuildMismatch);
        for code in [Some(0), Some(10), Some(11), Some(13), Some(1), None] {
            assert_eq!(UiStop::of_exit_code(code), UiStop::Exited);
        }
    }

    // ---- the UI as the parent (`--ui-stdio`, M8 step 8) ----

    const PARENT: ProcessId = ProcessId {
        pid: 4242,
        start_ticks: 7,
    };

    /// A host over a parent UI: the fake's pipes stand in for this process's standard streams.
    /// Returns the host and the parent's ends (what it reads, where it writes).
    fn parent_host(process: &FakeProcess, bounds: Bounds) -> (UiHost, FakeChildPipes) {
        let mut pipes = process
            .spawn_child(&SpawnSpec {
                program: abs_path("/fake/pipes"),
                args: Vec::new(),
                env_set: Vec::new(),
                env_remove: Vec::new(),
                stdio: ChildStdio::Piped,
            })
            .expect("pipes");
        let (output, input) = (
            pipes.take_stdin().expect("stdin"),
            pipes.take_stdout().expect("stdout"),
        );
        let ends = process.take_child_pipes(pipes.id()).expect("ends");
        process.mark_running(PARENT);
        let host = UiHost::over_parent(
            bounds,
            Arc::new(process.clone()),
            PARENT,
            input,
            output,
            Flow::Install,
            card("App", "1.0.0", None),
            Details {
                location: None,
                size_bytes: None,
            },
        );
        (host, ends)
    }

    /// The parent UI: hello, pongs, `proceed` at the welcome; after `answer_welcome` frames it
    /// stops reading when `stop_reading`.
    fn parent_ui(ends: FakeChildPipes, stop_reading: bool) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let FakeChildPipes {
                stdin: mut from_engine,
                stdout: mut to_engine,
            } = ends;
            while let Ok(msg) = ui::read_frame::<_, EngineMsg>(&mut from_engine) {
                let reply = match msg {
                    EngineMsg::Hello { build_id, .. } => UiMsg::Hello { build_id },
                    EngineMsg::Ping { n } => UiMsg::Pong { n },
                    EngineMsg::Prompt { id, .. } => UiMsg::Choice {
                        id,
                        value: ChoiceValue::Proceed,
                    },
                    _ => continue,
                };
                let hello = matches!(reply, UiMsg::Hello { .. });
                if ui::write_frame(&mut to_engine, &reply).is_err() {
                    return;
                }
                if hello && stop_reading {
                    // Holds both ends open and reads nothing more.
                    std::thread::sleep(Duration::from_secs(3));
                    return;
                }
            }
        })
    }

    fn wait_stopped(host: &UiHost) -> Stopped {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(stopped) = host.stopped() {
                return stopped;
            }
            assert!(Instant::now() < until, "the host never stopped the UI");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_parent_ui_answers_over_the_own_streams_and_its_exit_is_never_a_signal() {
        let process = FakeProcess::new("/fake/lunepack-runtime");
        let bounds = Bounds {
            watch_tick: Duration::from_millis(20),
            ..Bounds::default()
        };
        let (host, ends) = parent_host(&process, bounds);
        let ui = parent_ui(ends, false);
        let events = Events::new(None, None);
        assert_eq!(
            host.prompt(PromptKind::Welcome, &events, &mut |_| {}),
            ChoiceValue::Proceed
        );
        // The parent is gone (its end of the channel may stay open, as a crashed parent's
        // inherited descriptor would): the host stops talking and answers as when a UI is lost.
        process.mark_exited(PARENT);
        assert_eq!(wait_stopped(&host).reason, UiStop::Exited);
        assert_eq!(
            host.prompt(PromptKind::Done, &events, &mut |_| {}),
            ChoiceValue::Finish { launch: false }
        );
        let start = Instant::now();
        host.close(&events);
        assert!(start.elapsed() < Duration::from_secs(2), "close waited");
        ui.join().expect("ui");
        assert!(process.terminated().is_empty(), "a process was signalled");
    }

    #[test]
    fn a_parent_ui_that_stops_reading_is_dropped_and_never_signalled() {
        let process = FakeProcess::new("/fake/lunepack-runtime");
        process.set_pipe_capacity(256);
        let bounds = Bounds {
            stall: Duration::from_millis(100),
            ping_every: Duration::from_millis(10),
            pong_wait: Duration::from_millis(300),
            close_wait: Duration::from_millis(300),
            watch_tick: Duration::from_millis(20),
            ..Bounds::default()
        };
        let (host, ends) = parent_host(&process, bounds);
        let ui = parent_ui(ends, true);
        let events = Events::new(None, None);
        // Before any change: the lost answer is cancel (M6-D5).
        assert_eq!(
            host.prompt(PromptKind::Welcome, &events, &mut |_| {}),
            ChoiceValue::Cancel
        );
        assert!(matches!(
            wait_stopped(&host).reason,
            UiStop::Stalled | UiStop::Hung
        ));
        let start = Instant::now();
        host.close(&events);
        assert!(start.elapsed() < Duration::from_secs(2), "close waited");
        assert!(process.terminated().is_empty(), "a process was signalled");
        ui.join().expect("ui");
    }

    /// F11 (consent race): the UI's end is seen (here the parent's exit, by the watchdog) before
    /// the reader got to what the UI wrote before it ended. A valid hello among that is a UI that
    /// was shown and then lost: the welcome cancels (M6-D5); none, or a refused one, is no UI:
    /// the headless answer, within the drain bound.
    #[test]
    fn a_hello_read_after_the_uis_end_was_seen_still_counts() {
        let bounds = Bounds {
            watch_tick: Duration::from_millis(10),
            ..Bounds::default()
        };
        let good = UiMsg::Hello {
            build_id: ui::build_id(),
        };
        let other = UiMsg::Hello {
            build_id: "0.0.0+ui1.other".to_owned(),
        };
        for (wrote, want) in [
            (Some(good), ChoiceValue::Cancel),
            (Some(other), ChoiceValue::Proceed),
            (None, ChoiceValue::Proceed),
        ] {
            let process = FakeProcess::new("/fake/lunepack-runtime");
            let (host, ends) = parent_host(&process, bounds);
            let FakeChildPipes {
                stdin: _from_engine,
                stdout: to_engine,
            } = ends;
            process.mark_exited(PARENT);
            assert_eq!(wait_stopped(&host).reason, UiStop::Exited);
            let wrote_any = wrote.is_some();
            // Nothing written: the channel is left open until the end, and the drain bound
            // decides.
            let mut open = Some(to_engine);
            if let Some(msg) = &wrote
                && let Some(mut end) = open.take()
            {
                ui::write_frame(&mut end, msg).expect("hello");
            }
            let events = Events::new(None, None);
            let start = Instant::now();
            let got = host.prompt(PromptKind::Welcome, &events, &mut |_| {});
            assert_eq!(got, want, "{wrote:?}");
            let took = start.elapsed();
            assert!(took < EXIT_PEEK + Duration::from_secs(1), "{took:?}");
            if !wrote_any {
                assert!(
                    took >= EXIT_PEEK,
                    "the drain bound was not waited: {took:?}"
                );
            }
            host.close(&events);
            drop(open);
        }
    }
}
