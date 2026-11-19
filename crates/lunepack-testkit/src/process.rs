//! A scripted [`Process`] and the contract suite for the real ones.
//!
//! [`FakeProcess`] spawns nothing. It records every spawn, hands out [`Child`]s whose exits a test
//! scripts, answers `wait_exit` and `tree_in_use` from queues a test fills, and never touches the
//! host. Clones share one state, so a test keeps a handle while the code under test owns another.

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use lunepack_core::{
    Child, ChildStdio, Error, ExitKind, Process, ProcessError, ProcessErrorKind, ProcessId,
    SpawnSpec, WaitOutcome,
};

/// One call to `spawn_detached`, `spawn_child` or `spawn_app_background`, as the fake saw it.
#[derive(Clone, PartialEq, Eq)]
pub struct SpawnRecord {
    /// `true` for `spawn_detached`.
    pub detached: bool,
    /// `true` for `spawn_app_background` (M8-D13); its child is scripted as any other.
    pub background: bool,
    /// The program.
    pub program: PathBuf,
    /// Its arguments.
    pub args: Vec<OsString>,
    /// Variables set.
    pub env_set: Vec<(OsString, OsString)>,
    /// Variables removed.
    pub env_remove: Vec<OsString>,
    /// The id given to a spawned child (`None` for a detached spawn).
    pub child: Option<ProcessId>,
    /// What the spec asked for as standard input and output.
    pub stdio: ChildStdio,
}

impl std::fmt::Debug for SpawnRecord {
    /// Shows no argument or environment value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnRecord")
            .field("detached", &self.detached)
            .field("background", &self.background)
            .field("args", &self.args.len())
            .field("env_set", &self.env_set.len())
            .field("env_remove", &self.env_remove.len())
            .field("child", &self.child)
            .field("stdio", &self.stdio)
            .finish_non_exhaustive()
    }
}

/// How the next scripted child behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildScript {
    /// `try_wait` answers `None` this many times, then the exit.
    pub polls_before_exit: u32,
    /// The exit; `None` runs until [`Child::terminate`].
    pub exit: Option<ExitKind>,
}

impl ChildScript {
    /// A child that exits with `kind` after `polls` polls that find it running.
    pub fn exits(polls: u32, kind: ExitKind) -> ChildScript {
        ChildScript {
            polls_before_exit: polls,
            exit: Some(kind),
        }
    }

    /// A child that runs until it is terminated.
    pub fn runs() -> ChildScript {
        ChildScript {
            polls_before_exit: 0,
            exit: None,
        }
    }
}

/// The size of a Linux pipe buffer, the default capacity of the fake's pipes.
const DEFAULT_PIPE_CAPACITY: usize = 64 * 1024;

struct PipeState {
    buf: VecDeque<u8>,
    capacity: usize,
    writer_gone: bool,
    reader_gone: bool,
}

/// One in-memory pipe: a bounded byte queue with blocking reads and writes, like an OS pipe.
struct Pipe {
    state: Mutex<PipeState>,
    changed: Condvar,
}

impl Pipe {
    fn new(capacity: usize) -> Arc<Pipe> {
        Arc::new(Pipe {
            state: Mutex::new(PipeState {
                buf: VecDeque::new(),
                capacity: capacity.max(1),
                writer_gone: false,
                reader_gone: false,
            }),
            changed: Condvar::new(),
        })
    }

    fn state(&self) -> MutexGuard<'_, PipeState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait<'a>(&self, guard: MutexGuard<'a, PipeState>) -> MutexGuard<'a, PipeState> {
        self.changed
            .wait(guard)
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The reading end is gone: writes fail with a broken pipe.
    fn close_reader(&self) {
        self.state().reader_gone = true;
        self.changed.notify_all();
    }

    /// The writing end is gone: reads drain what is queued, then report the end of file.
    fn close_writer(&self) {
        self.state().writer_gone = true;
        self.changed.notify_all();
    }
}

/// The reading end of one of the fake's pipes. Dropping it closes the pipe for the writer.
pub struct FakePipeReader(Arc<Pipe>);

/// The writing end of one of the fake's pipes. Dropping it is the end of file for the reader.
pub struct FakePipeWriter(Arc<Pipe>);

impl Read for FakePipeReader {
    /// Blocks until a byte is queued or the writer is gone (then `Ok(0)`).
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut st = self.0.state();
        loop {
            if !st.buf.is_empty() {
                let n = out.len().min(st.buf.len());
                for (slot, byte) in out.iter_mut().zip(st.buf.drain(..n)) {
                    *slot = byte;
                }
                self.0.changed.notify_all();
                return Ok(n);
            }
            if st.writer_gone || st.reader_gone {
                return Ok(0);
            }
            st = self.0.wait(st);
        }
    }
}

impl Write for FakePipeWriter {
    /// Queues all of `data`, blocking while the pipe is full (as a blocking OS pipe does); a pipe
    /// whose reader is gone fails with `BrokenPipe`.
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut st = self.0.state();
        let mut written = 0;
        while written < data.len() {
            if st.reader_gone || st.writer_gone {
                return if written > 0 {
                    Ok(written)
                } else {
                    Err(io::ErrorKind::BrokenPipe.into())
                };
            }
            let room = st.capacity.saturating_sub(st.buf.len());
            if room == 0 {
                st = self.0.wait(st);
                continue;
            }
            let n = room.min(data.len() - written);
            st.buf.extend(&data[written..written + n]);
            written += n;
            self.0.changed.notify_all();
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for FakePipeReader {
    fn drop(&mut self) {
        self.0.close_reader();
    }
}

impl Drop for FakePipeWriter {
    fn drop(&mut self) {
        self.0.close_writer();
    }
}

impl std::fmt::Debug for FakePipeReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakePipeReader").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for FakePipeWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakePipeWriter").finish_non_exhaustive()
    }
}

/// The ends of a piped fake child's pipes that the child itself would hold: what it reads as
/// standard input and where it writes standard output. A test plays the child with these (taken
/// with [`FakeProcess::take_child_pipes`]); dropping one is the child closing that stream.
#[derive(Debug)]
pub struct FakeChildPipes {
    /// What the code under test wrote to the child's standard input.
    pub stdin: FakePipeReader,
    /// What the child writes as standard output, for the code under test to read.
    pub stdout: FakePipeWriter,
}

struct Inner {
    exe: PathBuf,
    me: ProcessId,
    parent: Option<ProcessId>,
    next_pid: u32,
    spawns: Vec<SpawnRecord>,
    scripts: VecDeque<ChildScript>,
    spawn_error: Option<ProcessErrorKind>,
    waits: VecDeque<WaitOutcome>,
    wait_log: Vec<(ProcessId, Duration)>,
    running: BTreeSet<ProcessId>,
    in_use: VecDeque<bool>,
    in_use_log: Vec<(PathBuf, Vec<ProcessId>)>,
    terminated: Vec<ProcessId>,
    pipe_capacity: usize,
    child_pipes: BTreeMap<ProcessId, FakeChildPipes>,
}

/// A scripted [`Process`].
#[derive(Clone)]
pub struct FakeProcess {
    inner: Arc<Mutex<Inner>>,
}

fn lock(m: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FakeProcess {
    /// A fake whose own process is pid 100 and whose executable is `exe`; its parent is pid 1's
    /// child 50 (`current_exe`, `current` and `parent` are settable).
    pub fn new(exe: impl Into<PathBuf>) -> FakeProcess {
        FakeProcess {
            inner: Arc::new(Mutex::new(Inner {
                exe: exe.into(),
                me: ProcessId {
                    pid: 100,
                    start_ticks: 1_000,
                },
                parent: Some(ProcessId {
                    pid: 50,
                    start_ticks: 500,
                }),
                next_pid: 1_000,
                spawns: Vec::new(),
                scripts: VecDeque::new(),
                spawn_error: None,
                waits: VecDeque::new(),
                wait_log: Vec::new(),
                running: BTreeSet::new(),
                in_use: VecDeque::new(),
                in_use_log: Vec::new(),
                terminated: Vec::new(),
                pipe_capacity: DEFAULT_PIPE_CAPACITY,
                child_pipes: BTreeMap::new(),
            })),
        }
    }

    /// Sets this process's id.
    pub fn set_current(&self, id: ProcessId) {
        lock(&self.inner).me = id;
    }

    /// Sets the parent (`None`: adopted).
    pub fn set_parent(&self, parent: Option<ProcessId>) {
        lock(&self.inner).parent = parent;
    }

    /// Makes every later spawn fail with `kind` (`None`: spawn works again).
    pub fn fail_spawns(&self, kind: Option<ProcessErrorKind>) {
        lock(&self.inner).spawn_error = kind;
    }

    /// Queues the behaviour of the next `spawn_child`; with nothing queued a child runs until it is
    /// terminated.
    pub fn script_child(&self, script: ChildScript) {
        lock(&self.inner).scripts.push_back(script);
    }

    /// Queues the answer of the next `wait_exit`; with nothing queued the answer is `TimedOut`
    /// for a process the fake knows to be running and `Exited` for any other id.
    pub fn script_wait(&self, outcome: WaitOutcome) {
        lock(&self.inner).waits.push_back(outcome);
    }

    /// Queues the answer of the next `tree_in_use` (`false` when nothing is queued).
    pub fn script_in_use(&self, answer: bool) {
        lock(&self.inner).in_use.push_back(answer);
    }

    /// Marks `id` as running, so an unscripted `wait_exit` on it times out.
    pub fn mark_running(&self, id: ProcessId) {
        lock(&self.inner).running.insert(id);
    }

    /// Marks `id` as ended.
    pub fn mark_exited(&self, id: ProcessId) {
        lock(&self.inner).running.remove(&id);
    }

    /// Sets the capacity in bytes of the pipes of later piped spawns (the default is 64 KiB, a
    /// Linux pipe's): a writer blocks while its pipe holds that much.
    pub fn set_pipe_capacity(&self, bytes: usize) {
        lock(&self.inner).pipe_capacity = bytes;
    }

    /// The child's ends of the pipes of piped child `id`, once (`None` for a child that is not
    /// piped, an unknown id and a second call). A test reads what the code under test sent and
    /// writes what the child would; the fake's own end of file and broken pipe follow the child's
    /// exit or termination.
    pub fn take_child_pipes(&self, id: ProcessId) -> Option<FakeChildPipes> {
        lock(&self.inner).child_pipes.remove(&id)
    }

    /// Every spawn so far, in order.
    pub fn spawns(&self) -> Vec<SpawnRecord> {
        lock(&self.inner).spawns.clone()
    }

    /// Every `wait_exit` call so far: the id and the timeout.
    pub fn waits(&self) -> Vec<(ProcessId, Duration)> {
        lock(&self.inner).wait_log.clone()
    }

    /// Every `tree_in_use` call so far: the tree and the excluded ids.
    pub fn in_use_calls(&self) -> Vec<(PathBuf, Vec<ProcessId>)> {
        lock(&self.inner).in_use_log.clone()
    }

    /// The children that were terminated, in order.
    pub fn terminated(&self) -> Vec<ProcessId> {
        lock(&self.inner).terminated.clone()
    }

    fn record(
        &self,
        detached: bool,
        background: bool,
        spec: &SpawnSpec,
    ) -> Result<Option<ProcessId>, Error> {
        let mut inner = lock(&self.inner);
        if !spec.program.is_absolute() || (detached && spec.stdio != ChildStdio::Null) {
            return Err(ProcessError::new(ProcessErrorKind::InvalidRequest, "spawn")
                .about(&spec.program)
                .into());
        }
        if let Some(kind) = inner.spawn_error {
            return Err(ProcessError::new(kind, "spawn").about(&spec.program).into());
        }
        let child = if detached {
            None
        } else {
            inner.next_pid += 1;
            let id = ProcessId {
                pid: inner.next_pid,
                start_ticks: u64::from(inner.next_pid) * 10,
            };
            inner.running.insert(id);
            Some(id)
        };
        inner.spawns.push(SpawnRecord {
            detached,
            background,
            program: spec.program.clone(),
            args: spec.args.clone(),
            env_set: spec.env_set.clone(),
            env_remove: spec.env_remove.clone(),
            child,
            stdio: spec.stdio,
        });
        Ok(child)
    }
}

/// The fake child's own pipe handles, to close its ends when it exits.
struct ChildPipes {
    stdin: Arc<Pipe>,
    stdout: Arc<Pipe>,
    /// The code under test's ends, until it takes them.
    engine_stdin: Option<FakePipeWriter>,
    engine_stdout: Option<FakePipeReader>,
}

impl ChildPipes {
    /// The child is gone: nothing reads its input and nothing more is written to its output.
    fn close(&self) {
        self.stdin.close_reader();
        self.stdout.close_writer();
    }
}

struct FakeChild {
    id: ProcessId,
    script: ChildScript,
    polls: u32,
    done: Option<ExitKind>,
    shared: Arc<Mutex<Inner>>,
    pipes: Option<ChildPipes>,
}

impl FakeChild {
    fn ended(&mut self) {
        if let Some(pipes) = &self.pipes {
            pipes.close();
        }
    }
}

impl Child for FakeChild {
    fn id(&self) -> ProcessId {
        self.id
    }

    fn try_wait(&mut self) -> Result<Option<ExitKind>, Error> {
        if let Some(done) = self.done {
            return Ok(Some(done));
        }
        let Some(exit) = self.script.exit else {
            return Ok(None);
        };
        if self.polls < self.script.polls_before_exit {
            self.polls += 1;
            return Ok(None);
        }
        self.done = Some(exit);
        lock(&self.shared).running.remove(&self.id);
        self.ended();
        Ok(Some(exit))
    }

    fn terminate(&mut self, _grace: Duration) -> Result<(), Error> {
        let mut shared = lock(&self.shared);
        shared.terminated.push(self.id);
        shared.running.remove(&self.id);
        if self.done.is_none() {
            self.done = Some(ExitKind::Signal(15));
        }
        drop(shared);
        self.ended();
        Ok(())
    }

    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        let w = self.pipes.as_mut()?.engine_stdin.take()?;
        Some(Box::new(w))
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        let r = self.pipes.as_mut()?.engine_stdout.take()?;
        Some(Box::new(r))
    }
}

impl Process for FakeProcess {
    fn current_exe(&self) -> Result<PathBuf, Error> {
        Ok(lock(&self.inner).exe.clone())
    }

    fn current(&self) -> Result<ProcessId, Error> {
        Ok(lock(&self.inner).me)
    }

    fn parent(&self) -> Result<Option<ProcessId>, Error> {
        Ok(lock(&self.inner).parent)
    }

    fn spawn_detached(&self, spec: &SpawnSpec) -> Result<(), Error> {
        self.record(true, false, spec).map(drop)
    }

    fn spawn_child(&self, spec: &SpawnSpec) -> Result<Box<dyn Child>, Error> {
        self.child(spec, false)
    }

    fn spawn_app_background(&self, spec: &SpawnSpec) -> Result<Box<dyn Child>, Error> {
        self.child(spec, true)
    }

    fn wait_exit(&self, id: &ProcessId, timeout: Duration) -> Result<WaitOutcome, Error> {
        self.wait(id, timeout)
    }

    fn tree_in_use(&self, tree: &Path, exclude: &[ProcessId]) -> Result<bool, Error> {
        self.in_use(tree, exclude)
    }
}

impl FakeProcess {
    /// A child spawn, recorded as a background one when `background`.
    fn child(&self, spec: &SpawnSpec, background: bool) -> Result<Box<dyn Child>, Error> {
        let id = self
            .record(false, background, spec)?
            .expect("a child spawn always has an id");
        let mut inner = lock(&self.inner);
        let script = inner.scripts.pop_front().unwrap_or_else(ChildScript::runs);
        let pipes = (spec.stdio == ChildStdio::Piped).then(|| {
            let stdin = Pipe::new(inner.pipe_capacity);
            let stdout = Pipe::new(inner.pipe_capacity);
            inner.child_pipes.insert(
                id,
                FakeChildPipes {
                    stdin: FakePipeReader(stdin.clone()),
                    stdout: FakePipeWriter(stdout.clone()),
                },
            );
            ChildPipes {
                engine_stdin: Some(FakePipeWriter(stdin.clone())),
                engine_stdout: Some(FakePipeReader(stdout.clone())),
                stdin,
                stdout,
            }
        });
        drop(inner);
        Ok(Box::new(FakeChild {
            id,
            script,
            polls: 0,
            done: None,
            shared: self.inner.clone(),
            pipes,
        }))
    }

    fn wait(&self, id: &ProcessId, timeout: Duration) -> Result<WaitOutcome, Error> {
        let mut inner = lock(&self.inner);
        inner.wait_log.push((*id, timeout));
        if let Some(outcome) = inner.waits.pop_front() {
            return Ok(outcome);
        }
        Ok(if inner.running.contains(id) {
            WaitOutcome::TimedOut
        } else {
            WaitOutcome::Exited
        })
    }

    fn in_use(&self, tree: &Path, exclude: &[ProcessId]) -> Result<bool, Error> {
        let mut inner = lock(&self.inner);
        inner.in_use_log.push((tree.to_owned(), exclude.to_vec()));
        Ok(inner.in_use.pop_front().unwrap_or(false))
    }
}

// ---- the contract suite ----

/// The contract suite for a real [`Process`]. `helper` is a test helper executable (built by the
/// adapter's own tests) that takes its command from its arguments:
///
/// - `exit <code>`: exits with `code`.
/// - `sleep <secs>`: sleeps, then exits 0.
/// - `sleep-ignore-term <secs> <ready-file>`: ignores SIGTERM (on Windows it has no signal to
///   ignore), creates `ready-file`, then sleeps.
/// - `write <file> <text>`: creates `file` holding `text`, then exits 0.
/// - `args <file> <arg>...`: creates `file` holding each `arg` followed by a newline.
/// - `env <file> <name>...`: creates `file` holding, for each `name`, one line `NAME=value` (the
///   value as the helper's environment holds it, lossy UTF-8) or `NAME unset`.
/// - `probe <file>`: creates `file` holding a first line and, for each of `stdin`, `stdout` and
///   `stderr`, `<name> null` or `<name> other` (the descriptor is `/dev/null` or `NUL`, or is not).
///   The first line is `session leader` or `session member` on Unix (the helper is, or is not, the
///   leader of its own session) and `no console` or `console` on Windows (the helper has no console
///   at all, as a detached program has, or has one, possibly hidden).
///
/// - `cat`: copies its standard input to its standard output until end of file, then exits 0.
///
/// A helper creates every file atomically (writes `<file>.tmp`, then renames it), so a reader that
/// sees `file` sees all of it.
///
/// The suite works in a directory of its own below the system temporary directory and removes it
/// at the end; it leaves no process behind. It checks: identity (`current_exe`, `current`,
/// `parent`); `spawn_child` and its exit kinds; `wait_exit` on a running child, on a zombie, on
/// an id with another start time (a reused pid) and on a pid that does not exist; `terminate`
/// (a polite request, then escalation after `grace`: SIGTERM then SIGKILL on Unix; on Windows a
/// child without a window cannot be asked, so it is ended when `grace` has passed, with exit code
/// 1); `spawn_detached` (arguments reach the program
/// verbatim without a shell, `env_set` and `env_remove`, a new session, null streams); piped
/// children (`ChildStdio::Piped`: a round trip through `cat` that is large enough to need both
/// directions at once, the end of file when the input is dropped, the error stream still null, the
/// pipe ends handed out once, and a child that ends while its pipes are held); refusals (a
/// relative program, a missing program, a detached spawn with pipes) that leak no argument,
/// environment value or directory; and `tree_in_use`.
pub fn run_process_suite(process: &dyn Process, helper: &Path) {
    let scratch = std::env::temp_dir().join(format!(
        "lunepack-process-suite-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir(&scratch).expect("create the suite directory");
    let scratch = std::fs::canonicalize(&scratch).expect("canonicalize the suite directory");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        process_cases(process, helper, &scratch);
    }));
    let _ = std::fs::remove_dir_all(&scratch);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

/// Ends a child when the suite unwinds, so a failed case leaves no process behind.
struct Reaper(Box<dyn Child>);

impl Drop for Reaper {
    fn drop(&mut self) {
        let _ = self.0.terminate(Duration::from_millis(200));
    }
}

const LIMIT: Duration = Duration::from_secs(20);

/// The grace period for a `terminate` that the polite request alone should satisfy. On Windows
/// the helper has no window to ask, so every terminate waits the whole grace period: keep it short.
fn polite_grace() -> Duration {
    if cfg!(windows) {
        Duration::from_millis(300)
    } else {
        Duration::from_secs(10)
    }
}

/// Whether `exit` is how a terminated child ends: a signal on Unix, a failure code on Windows.
fn is_terminated(exit: Option<ExitKind>) -> bool {
    if cfg!(windows) {
        matches!(exit, Some(ExitKind::Failure(_)))
    } else {
        matches!(exit, Some(ExitKind::Signal(_)))
    }
}

fn helper_spec(helper: &Path, args: &[&str]) -> SpawnSpec {
    let mut spec = SpawnSpec::new(helper);
    spec.args = args.iter().map(OsString::from).collect();
    spec
}

fn process_kind(err: &Error, what: &str) -> ProcessErrorKind {
    match err {
        Error::Process(e) => e.kind,
        other => panic!("{what}: expected a process error, got {other:?}"),
    }
}

fn wait_for_exit(child: &mut dyn Child, what: &str) -> ExitKind {
    let deadline = std::time::Instant::now() + LIMIT;
    loop {
        if let Some(exit) = child.try_wait().unwrap_or_else(|e| panic!("{what}: {e}")) {
            return exit;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{what}: the child did not end"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_file(path: &Path, what: &str) -> String {
    let deadline = std::time::Instant::now() + LIMIT;
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            return text;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{what}: the file did not appear"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn process_cases(process: &dyn Process, helper: &Path, scratch: &Path) {
    // Identity.
    let exe = process.current_exe().expect("current_exe");
    assert!(exe.is_absolute(), "current_exe is not absolute");
    assert_eq!(
        exe,
        std::fs::canonicalize(std::env::current_exe().expect("std current_exe"))
            .expect("canonicalize"),
        "current_exe is not the resolved running executable"
    );
    let me = process.current().expect("current");
    assert_eq!(me.pid, std::process::id(), "current().pid");
    assert_eq!(process.current().unwrap(), me, "current() is not stable");
    if let Some(parent) = process.parent().expect("parent") {
        assert!(parent.pid > 1 && parent.pid != me.pid, "parent {parent:?}");
    }

    // Children and their exits.
    for (args, want) in [
        (&["exit", "0"][..], ExitKind::Success),
        (&["exit", "7"][..], ExitKind::Failure(7)),
    ] {
        let mut child = process
            .spawn_child(&helper_spec(helper, args))
            .expect("spawn_child");
        assert_ne!(child.id().pid, me.pid);
        let got = wait_for_exit(child.as_mut(), "exit kind");
        assert_eq!(got, want, "exit kind of {args:?}");
        assert_eq!(
            child.try_wait().unwrap(),
            Some(want),
            "try_wait after the exit was seen"
        );
    }

    // A background start of a program that is not an app an OS launch service can start (here
    // the helper, outside any bundle) is a child start: the default, and every adapter's
    // fallback (M8-D13).
    let mut child = process
        .spawn_app_background(&helper_spec(helper, &["exit", "7"]))
        .expect("spawn_app_background");
    assert_eq!(
        wait_for_exit(child.as_mut(), "background exit kind"),
        ExitKind::Failure(7),
        "a background start that falls back to a child start"
    );

    // wait_exit: a running child times out and is left alone; an id with another start time, and
    // a pid that does not exist, count as ended at once; a terminated child is ended.
    let mut sleeper = Reaper(
        process
            .spawn_child(&helper_spec(helper, &["sleep", "600"]))
            .expect("spawn a sleeper"),
    );
    let id = sleeper.0.id();
    let started = std::time::Instant::now();
    assert_eq!(
        process.wait_exit(&id, Duration::from_millis(150)).unwrap(),
        WaitOutcome::TimedOut,
        "a running child"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(100),
        "wait_exit returned before its timeout"
    );
    assert_eq!(
        sleeper.0.try_wait().unwrap(),
        None,
        "wait_exit ended the child it only had to wait for"
    );
    let reused = ProcessId {
        pid: id.pid,
        start_ticks: id.start_ticks.wrapping_add(1),
    };
    let started = std::time::Instant::now();
    assert_eq!(
        process.wait_exit(&reused, Duration::from_secs(30)).unwrap(),
        WaitOutcome::Exited,
        "a reused pid (another start time) is not the process waited for"
    );
    assert!(started.elapsed() < Duration::from_secs(10), "reused pid");
    assert_eq!(
        process
            .wait_exit(
                &ProcessId {
                    pid: u32::MAX,
                    start_ticks: 1
                },
                Duration::from_secs(30)
            )
            .unwrap(),
        WaitOutcome::Exited,
        "a pid that does not exist"
    );
    let started = std::time::Instant::now();
    sleeper.0.terminate(polite_grace()).expect("terminate");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the polite request alone should have ended a sleeper (Windows: the grace period)"
    );
    assert!(
        is_terminated(sleeper.0.try_wait().unwrap()),
        "a terminated child ends by a signal (Windows: with a failure code)"
    );
    assert_eq!(
        process.wait_exit(&id, Duration::from_secs(10)).unwrap(),
        WaitOutcome::Exited,
        "a terminated child"
    );
    sleeper
        .0
        .terminate(Duration::from_millis(100))
        .expect("terminate a child that has ended");

    // A child that has ended but is not yet reaped (a zombie) counts as exited.
    let mut short = Reaper(
        process
            .spawn_child(&helper_spec(helper, &["sleep", "1"]))
            .expect("spawn a short sleeper"),
    );
    assert_eq!(
        process
            .wait_exit(&short.0.id(), Duration::from_secs(20))
            .unwrap(),
        WaitOutcome::Exited,
        "a child that ended on its own"
    );
    assert_eq!(
        wait_for_exit(short.0.as_mut(), "short sleeper"),
        ExitKind::Success
    );

    // terminate escalates after the grace period when SIGTERM is ignored.
    let ready = scratch.join("ready");
    let mut stubborn = Reaper(
        process
            .spawn_child(&helper_spec(
                helper,
                &["sleep-ignore-term", "600", &ready.to_string_lossy()],
            ))
            .expect("spawn a stubborn child"),
    );
    wait_for_file(&ready, "the stubborn child's ready file");
    let started = std::time::Instant::now();
    stubborn
        .0
        .terminate(Duration::from_millis(300))
        .expect("terminate a stubborn child");
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "terminate did not give the grace period"
    );
    assert_eq!(
        stubborn.0.try_wait().unwrap(),
        Some(if cfg!(windows) {
            ExitKind::Failure(1)
        } else {
            ExitKind::Signal(9)
        }),
        "the stubborn child is killed after the grace period"
    );

    detached_cases(process, helper, scratch);
    piped_cases(process, helper, scratch);
    refusal_cases(process, scratch);
    in_use_cases(process, helper, scratch);
}

fn detached_cases(process: &dyn Process, helper: &Path, scratch: &Path) {
    // Arguments arrive verbatim: no shell, no splitting, no expansion.
    let args_file = scratch.join("args");
    let odd = ["a b", "x;y", "$(true)", "'q'", "-n", "", "*", "ünï"];
    let mut spec = helper_spec(helper, &["args", &args_file.to_string_lossy()]);
    spec.args.extend(odd.iter().map(OsString::from));
    process.spawn_detached(&spec).expect("spawn_detached");
    let got = wait_for_file(&args_file, "args");
    let want: String = odd.iter().map(|a| format!("{a}\n")).collect();
    assert_eq!(got, want, "arguments did not arrive verbatim");

    // env_remove is applied before env_set: a removed inherited variable is gone, a variable in
    // both lists ends up set, env_set replaces, and the rest is inherited.
    let env_file = scratch.join("env");
    let mut spec = helper_spec(
        helper,
        &[
            "env",
            &env_file.to_string_lossy(),
            "LUNEPACK_SUITE_TOKEN",
            "LUNEPACK_SUITE_BOTH",
            "PATH",
            "HOME",
        ],
    );
    spec.env_set = vec![
        (
            OsString::from("LUNEPACK_SUITE_TOKEN"),
            OsString::from("tok en=1"),
        ),
        (
            OsString::from("LUNEPACK_SUITE_BOTH"),
            OsString::from("removed then set"),
        ),
    ];
    spec.env_remove = vec![
        OsString::from("LUNEPACK_SUITE_BOTH"),
        OsString::from("PATH"),
    ];
    process.spawn_detached(&spec).expect("spawn_detached env");
    let got = wait_for_file(&env_file, "env");
    let home = match std::env::var_os("HOME") {
        Some(h) => format!("HOME={}", h.to_string_lossy()),
        None => "HOME unset".to_owned(),
    };
    assert_eq!(
        got,
        format!(
            "LUNEPACK_SUITE_TOKEN=tok en=1\nLUNEPACK_SUITE_BOTH=removed then set\nPATH unset\n{home}\n"
        ),
        "environment of a spawned program"
    );

    // A detached program leads a new session and has null streams; a child has null streams.
    let probe = scratch.join("probe-detached");
    process
        .spawn_detached(&helper_spec(helper, &["probe", &probe.to_string_lossy()]))
        .expect("spawn_detached probe");
    assert_eq!(
        wait_for_file(&probe, "probe"),
        format!(
            "{}\nstdin null\nstdout null\nstderr null\n",
            if cfg!(windows) {
                "no console"
            } else {
                "session leader"
            }
        ),
        "a detached program"
    );
    let probe = scratch.join("probe-child");
    let mut child = process
        .spawn_child(&helper_spec(helper, &["probe", &probe.to_string_lossy()]))
        .expect("spawn_child probe");
    assert_eq!(wait_for_exit(child.as_mut(), "probe"), ExitKind::Success);
    let text = wait_for_file(&probe, "probe child");
    assert!(
        text.ends_with("stdin null\nstdout null\nstderr null\n"),
        "a child's streams: {text:?}"
    );
}

/// A `ChildStdio::Piped` spec for `helper args`.
fn piped_spec(helper: &Path, args: &[&str]) -> SpawnSpec {
    let mut spec = helper_spec(helper, args);
    spec.stdio = ChildStdio::Piped;
    spec
}

fn piped_cases(process: &dyn Process, helper: &Path, scratch: &Path) {
    // A null child hands out no pipe ends.
    let mut null = process
        .spawn_child(&helper_spec(helper, &["exit", "0"]))
        .expect("spawn a null child");
    assert!(
        null.take_stdin().is_none(),
        "a null child has no input pipe"
    );
    assert!(
        null.take_stdout().is_none(),
        "a null child has no output pipe"
    );
    wait_for_exit(null.as_mut(), "null child");

    // A round trip through `cat`. 300 KiB is more than a pipe holds in either direction, so the
    // writer and the reader must run at once; the end of the input is the end of the output.
    let mut cat = Reaper(
        process
            .spawn_child(&piped_spec(helper, &["cat"]))
            .expect("spawn a piped child"),
    );
    let mut stdin = cat.0.take_stdin().expect("the input pipe");
    let mut stdout = cat.0.take_stdout().expect("the output pipe");
    assert!(
        cat.0.take_stdin().is_none(),
        "the input pipe is handed out once"
    );
    assert!(
        cat.0.take_stdout().is_none(),
        "the output pipe is handed out once"
    );
    let payload: Vec<u8> = (0..300 * 1024u32).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let tx_read = tx.clone();
    std::thread::spawn(move || {
        let mut got = Vec::new();
        let result = stdout.read_to_end(&mut got).map(|_| got);
        let _ = tx_read.send(("read", result.ok()));
    });
    std::thread::spawn(move || {
        let ok = stdin
            .write_all(&payload)
            .and_then(|()| stdin.flush())
            .is_ok();
        // Dropping the input is the child's end of file.
        drop(stdin);
        let _ = tx.send(("write", ok.then(Vec::new)));
    });
    let mut read = None;
    let mut wrote = false;
    for _ in 0..2 {
        let (what, got) = rx
            .recv_timeout(LIMIT)
            .expect("the round trip through cat did not finish");
        match what {
            "read" => read = Some(got.expect("reading the child's output")),
            _ => wrote = got.is_some(),
        }
    }
    assert!(wrote, "writing the child's input");
    assert!(
        read.expect("read result") == expected,
        "cat returned other bytes than it was given"
    );
    assert_eq!(
        wait_for_exit(cat.0.as_mut(), "cat"),
        ExitKind::Success,
        "cat ends at the end of its input"
    );

    // The error stream of a piped child is still null; input and output are the pipes.
    let probe = scratch.join("probe-piped");
    let mut child = process
        .spawn_child(&piped_spec(helper, &["probe", &probe.to_string_lossy()]))
        .expect("spawn a piped probe");
    assert_eq!(
        wait_for_exit(child.as_mut(), "piped probe"),
        ExitKind::Success
    );
    let text = wait_for_file(&probe, "piped probe");
    assert!(
        text.ends_with("stdin other\nstdout other\nstderr null\n"),
        "a piped child's streams: {text:?}"
    );

    // A child that ends while the parent still holds its pipes: the output reaches its end of
    // file, and the input is a broken pipe.
    let mut sleeper = Reaper(
        process
            .spawn_child(&piped_spec(helper, &["sleep", "600"]))
            .expect("spawn a piped sleeper"),
    );
    let mut stdin = sleeper.0.take_stdin().expect("the input pipe");
    let mut stdout = sleeper.0.take_stdout().expect("the output pipe");
    sleeper
        .0
        .terminate(polite_grace())
        .expect("terminate the piped sleeper");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut rest = Vec::new();
        let read = stdout.read_to_end(&mut rest).map(|_| rest.len());
        let write = stdin.write_all(b"too late").and_then(|()| stdin.flush());
        let _ = tx.send((read.ok(), write.err().map(|e| e.kind())));
    });
    let (read, write) = rx
        .recv_timeout(LIMIT)
        .expect("the pipes of an ended child did not close");
    assert_eq!(read, Some(0), "the output of an ended child is at its end");
    assert_eq!(
        write,
        Some(std::io::ErrorKind::BrokenPipe),
        "the input of an ended child"
    );
}

fn refusal_cases(process: &dyn Process, scratch: &Path) {
    let mut relative = SpawnSpec::new("relative/program");
    relative.args = vec![OsString::from("SECRET-ARG-VALUE")];
    let missing_dir = scratch.join("no-such-dir-for-the-suite");
    let mut missing = SpawnSpec::new(missing_dir.join("no-such-program"));
    missing.args = vec![OsString::from("SECRET-ARG-VALUE")];
    missing.env_set = vec![(
        OsString::from("LUNEPACK_SUITE_SECRET"),
        OsString::from("SECRET-ENV-VALUE"),
    )];
    let dir_text = scratch.to_string_lossy().into_owned();
    for (name, spec, kinds) in [
        (
            "a relative program",
            &relative,
            &[ProcessErrorKind::InvalidRequest][..],
        ),
        (
            "a missing program",
            &missing,
            &[ProcessErrorKind::NotFound, ProcessErrorKind::SpawnFailed][..],
        ),
    ] {
        for detached in [false, true] {
            let err = if detached {
                process.spawn_detached(spec).map(drop)
            } else {
                process.spawn_child(spec).map(drop)
            }
            .expect_err(name);
            let kind = process_kind(&err, name);
            assert!(kinds.contains(&kind), "{name}: kind {kind:?}");
            let shown = format!("{err} / {err:?}");
            assert!(!shown.contains("SECRET-ARG-VALUE"), "{name}: {shown}");
            assert!(!shown.contains("SECRET-ENV-VALUE"), "{name}: {shown}");
            assert!(!shown.contains(&dir_text), "{name}: leaks a path: {shown}");
        }
    }

    // A detached program has no owner for pipes: refused, with a typed error that shows no argument.
    let mut piped = piped_spec(&scratch.join("never-started"), &["SECRET-ARG-VALUE"]);
    piped.args = vec![OsString::from("SECRET-ARG-VALUE")];
    let err = process
        .spawn_detached(&piped)
        .expect_err("a detached spawn with pipes");
    assert_eq!(
        process_kind(&err, "a detached spawn with pipes"),
        ProcessErrorKind::InvalidRequest
    );
    let shown = format!("{err} / {err:?}");
    assert!(!shown.contains("SECRET-ARG-VALUE"), "{shown}");
}

fn in_use_cases(process: &dyn Process, helper: &Path, scratch: &Path) {
    let tree = scratch.join("tree");
    let other = scratch.join("other");
    std::fs::create_dir(&tree).expect("create the tree");
    std::fs::create_dir(&other).expect("create another directory");
    let copy = tree.join("app-copy");
    std::fs::copy(helper, &copy).expect("copy the helper into the tree");
    assert!(
        !process.tree_in_use(&tree, &[]).expect("tree_in_use"),
        "a tree nothing runs from"
    );
    let mut running = Reaper(
        process
            .spawn_child(&helper_spec(&copy, &["sleep", "600"]))
            .expect("spawn from the tree"),
    );
    let id = running.0.id();
    assert!(
        process.tree_in_use(&tree, &[]).expect("tree_in_use"),
        "a process runs from the tree"
    );
    assert!(
        !process.tree_in_use(&tree, &[id]).expect("tree_in_use"),
        "an excluded process does not count"
    );
    assert!(
        !process.tree_in_use(&other, &[]).expect("tree_in_use"),
        "another directory is not in use"
    );
    running.0.terminate(polite_grace()).expect("terminate");
    assert!(
        !process.tree_in_use(&tree, &[]).expect("tree_in_use"),
        "the process ended"
    );
}
