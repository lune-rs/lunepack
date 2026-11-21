//! Fakes of the machine-install ports (M10): protected directories over a [`MemFs`], the service
//! registration, the policy source, the service connector, the elevation hand-off, and an
//! in-memory duplex pair for the service protocol.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use lunepack_core::service::Duplex;
use lunepack_core::{
    AppId, ConnectError, DirClass, Elevated, ElevatedChild, Elevation, ElevationError, FileKind,
    Fs, MachinePolicy, PolicySource, Protect, ProtectError, ServiceConnector, ServiceRegError,
    ServiceRegistrar, Standing,
};

use crate::memfs::MemFs;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---- Protect -------------------------------------------------------------------------------------

/// A [`Protect`] over a [`MemFs`]: it creates real directories in the fake filesystem and
/// remembers the class of each directory it created or was told about ([`FakeProtect::mark`]). A
/// check passes only for a directory of the requested class that is not marked unprotected.
/// Clones share one state.
#[derive(Clone)]
pub struct FakeProtect {
    fs: MemFs,
    inner: Arc<Mutex<ProtectState>>,
}

#[derive(Default)]
struct ProtectState {
    classes: BTreeMap<PathBuf, DirClass>,
    unprotected: BTreeSet<PathBuf>,
    created: Vec<(PathBuf, DirClass)>,
    fail_create: BTreeSet<PathBuf>,
}

impl FakeProtect {
    /// A fake over `fs` (a clone sharing its state).
    pub fn new(fs: &MemFs) -> FakeProtect {
        FakeProtect {
            fs: fs.clone(),
            inner: Arc::default(),
        }
    }

    /// Records `path` (an existing directory) as protected as `class`.
    pub fn mark(&self, path: &Path, class: DirClass) {
        lock(&self.inner).classes.insert(path.to_path_buf(), class);
    }

    /// Makes every later check of `path` fail with [`ProtectError::NotProtected`] (`false` undoes).
    pub fn set_unprotected(&self, path: &Path, unprotected: bool) {
        let mut st = lock(&self.inner);
        if unprotected {
            st.unprotected.insert(path.to_path_buf());
        } else {
            st.unprotected.remove(path);
        }
    }

    /// Makes [`Protect::create_dir`] of `path` fail with [`ProtectError::Os`].
    pub fn fail_create(&self, path: &Path) {
        lock(&self.inner).fail_create.insert(path.to_path_buf());
    }

    /// Every directory created through [`Protect::create_dir`], in order, with its class.
    pub fn created(&self) -> Vec<(PathBuf, DirClass)> {
        lock(&self.inner).created.clone()
    }

    /// The class recorded for `path`.
    pub fn class_of(&self, path: &Path) -> Option<DirClass> {
        lock(&self.inner).classes.get(path).copied()
    }
}

impl Protect for FakeProtect {
    fn create_dir(&self, path: &Path, class: DirClass) -> Result<(), ProtectError> {
        if lock(&self.inner).fail_create.contains(path) {
            return Err(ProtectError::Os("scripted"));
        }
        if self.fs.symlink_metadata(path)?.is_some() {
            return Err(ProtectError::Exists);
        }
        let parent = path.parent().ok_or(ProtectError::NotFound)?;
        match self.fs.symlink_metadata(parent)? {
            Some(m) if m.kind == FileKind::Dir => {}
            _ => return Err(ProtectError::NotFound),
        }
        self.fs.create_dir_all(path)?;
        let mut st = lock(&self.inner);
        st.classes.insert(path.to_path_buf(), class);
        st.created.push((path.to_path_buf(), class));
        Ok(())
    }

    fn check(&self, path: &Path, class: DirClass) -> Result<(), ProtectError> {
        match self.fs.symlink_metadata(path)? {
            None => return Err(ProtectError::NotFound),
            Some(m) if m.kind == FileKind::Dir => {}
            Some(_) => return Err(ProtectError::NotProtected),
        }
        let st = lock(&self.inner);
        if st.unprotected.contains(path) || st.classes.get(path) != Some(&class) {
            return Err(ProtectError::NotProtected);
        }
        Ok(())
    }
}

// ---- ServiceRegistrar ----------------------------------------------------------------------------

/// A [`ServiceRegistrar`] that keeps registrations in memory, records self-tests and fails the
/// self-test of images a test names. Clones share one state.
#[derive(Clone, Default)]
pub struct FakeRegistrar {
    inner: Arc<Mutex<RegistrarState>>,
}

#[derive(Default)]
struct RegistrarState {
    images: BTreeMap<String, PathBuf>,
    self_tests: Vec<PathBuf>,
    failing: BTreeSet<PathBuf>,
    fail_register: bool,
    registers: Vec<PathBuf>,
}

impl FakeRegistrar {
    /// Nothing registered.
    pub fn new() -> FakeRegistrar {
        FakeRegistrar::default()
    }

    /// Makes the self-test of `image` fail.
    pub fn fail_self_test(&self, image: &Path) {
        lock(&self.inner).failing.insert(image.to_path_buf());
    }

    /// Lets the self-test of `image` pass again.
    pub fn pass_self_test(&self, image: &Path) {
        lock(&self.inner).failing.remove(image);
    }

    /// Makes every `register` fail (`false` undoes).
    pub fn fail_register(&self, fail: bool) {
        lock(&self.inner).fail_register = fail;
    }

    /// The images `register` was called with, in order.
    pub fn registers(&self) -> Vec<PathBuf> {
        lock(&self.inner).registers.clone()
    }

    /// The images self-tested so far.
    pub fn self_tests(&self) -> Vec<PathBuf> {
        lock(&self.inner).self_tests.clone()
    }
}

impl ServiceRegistrar for FakeRegistrar {
    fn register(&self, app_id: &AppId, image: &Path) -> Result<(), ServiceRegError> {
        let mut st = lock(&self.inner);
        st.registers.push(image.to_path_buf());
        if st.fail_register {
            return Err(ServiceRegError::Os("scripted"));
        }
        st.images
            .insert(app_id.as_str().to_owned(), image.to_path_buf());
        Ok(())
    }

    fn image(&self, app_id: &AppId) -> Result<Option<PathBuf>, ServiceRegError> {
        Ok(lock(&self.inner).images.get(app_id.as_str()).cloned())
    }

    fn set_image(&self, app_id: &AppId, image: &Path) -> Result<(), ServiceRegError> {
        let mut st = lock(&self.inner);
        let slot = st
            .images
            .get_mut(app_id.as_str())
            .ok_or(ServiceRegError::NotRegistered)?;
        *slot = image.to_path_buf();
        Ok(())
    }

    fn self_test(&self, image: &Path) -> Result<(), ServiceRegError> {
        let mut st = lock(&self.inner);
        st.self_tests.push(image.to_path_buf());
        if st.failing.contains(image) {
            return Err(ServiceRegError::SelfTestFailed);
        }
        Ok(())
    }

    fn remove(&self, app_id: &AppId) -> Result<(), ServiceRegError> {
        lock(&self.inner).images.remove(app_id.as_str());
        Ok(())
    }
}

// ---- PolicySource --------------------------------------------------------------------------------

/// A [`PolicySource`] answering one settable policy for every app. Clones share one state.
#[derive(Clone, Default)]
pub struct FakePolicy {
    inner: Arc<Mutex<MachinePolicy>>,
}

impl FakePolicy {
    /// Everything off.
    pub fn new() -> FakePolicy {
        FakePolicy::default()
    }

    /// Replaces the policy.
    pub fn set(&self, policy: MachinePolicy) {
        *lock(&self.inner) = policy;
    }
}

impl PolicySource for FakePolicy {
    fn read(&self, _app_id: &AppId) -> MachinePolicy {
        *lock(&self.inner)
    }
}

// ---- ServiceConnector ----------------------------------------------------------------------------

type Connect = dyn Fn(&AppId) -> Result<Box<dyn Duplex>, ConnectError> + Send + Sync;

/// A [`ServiceConnector`] that answers through a closure (typically one that starts a server on
/// the other end of a [`mem_duplex`] pair) or with a scripted error.
pub struct FakeConnector {
    connect: Box<Connect>,
}

impl FakeConnector {
    /// Connects through `connect`.
    pub fn new(
        connect: impl Fn(&AppId) -> Result<Box<dyn Duplex>, ConnectError> + Send + Sync + 'static,
    ) -> FakeConnector {
        FakeConnector {
            connect: Box::new(connect),
        }
    }

    /// Always fails with `error`.
    pub fn failing(error: ConnectError) -> FakeConnector {
        FakeConnector::new(move |_| Err(error))
    }
}

impl ServiceConnector for FakeConnector {
    fn connect(&self, app_id: &AppId) -> Result<Box<dyn Duplex>, ConnectError> {
        (self.connect)(app_id)
    }
}

// ---- Elevation -----------------------------------------------------------------------------------

/// What [`FakeElevation`] does on the next `run_elevated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationScript {
    /// The child starts and exits with this code.
    Exit(i32),
    /// The user declines.
    Declined,
    /// The system refuses.
    Fails,
}

/// An [`Elevation`] with a fixed standing that records each hand-off and answers from a script
/// (an empty script declines). Clones share one state.
#[derive(Clone)]
pub struct FakeElevation {
    standing: Standing,
    inner: Arc<Mutex<ElevationState>>,
}

#[derive(Default)]
struct ElevationState {
    script: VecDeque<ElevationScript>,
    calls: Vec<(PathBuf, Vec<String>)>,
}

impl FakeElevation {
    /// A process of `standing` whose hand-offs answer `script` in order.
    pub fn new(standing: Standing, script: impl IntoIterator<Item = ElevationScript>) -> Self {
        FakeElevation {
            standing,
            inner: Arc::new(Mutex::new(ElevationState {
                script: script.into_iter().collect(),
                calls: Vec::new(),
            })),
        }
    }

    /// Every `(exe, args)` handed off so far.
    pub fn calls(&self) -> Vec<(PathBuf, Vec<String>)> {
        lock(&self.inner).calls.clone()
    }
}

struct FakeChild(i32);

impl ElevatedChild for FakeChild {
    fn wait(&mut self) -> Result<i32, ElevationError> {
        Ok(self.0)
    }
}

impl Elevation for FakeElevation {
    fn standing(&self) -> Standing {
        self.standing
    }

    fn run_elevated(&self, exe: &Path, args: &[String]) -> Result<Elevated, ElevationError> {
        let mut st = lock(&self.inner);
        st.calls.push((exe.to_path_buf(), args.to_vec()));
        match st.script.pop_front().unwrap_or(ElevationScript::Declined) {
            ElevationScript::Exit(code) => Ok(Elevated::Started(Box::new(FakeChild(code)))),
            ElevationScript::Declined => Ok(Elevated::Declined),
            ElevationScript::Fails => Err(ElevationError::Failed("scripted")),
        }
    }
}

// ---- an in-memory duplex -------------------------------------------------------------------------

/// One end of an in-memory duplex: what one end writes the other reads, in order. A read deadline
/// counts from the call that set it; a read still waiting at the deadline fails with
/// [`ErrorKind::TimedOut`]. Dropping one end is the peer closing: the other end reads to the end,
/// then `Ok(0)`, and its writes fail with [`ErrorKind::BrokenPipe`].
pub struct MemDuplex {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
    deadline: Option<Instant>,
}

/// A connected pair of [`MemDuplex`] ends.
pub fn mem_duplex() -> (MemDuplex, MemDuplex) {
    let (a_tx, b_rx) = mpsc::channel();
    let (b_tx, a_rx) = mpsc::channel();
    let end = |tx, rx| MemDuplex {
        tx,
        rx,
        buf: Vec::new(),
        pos: 0,
        deadline: None,
    };
    (end(a_tx, a_rx), end(b_tx, b_rx))
}

impl Read for MemDuplex {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.pos == self.buf.len() {
            let next = match self.deadline {
                Some(at) => {
                    let wait = at.saturating_duration_since(Instant::now());
                    match self.rx.recv_timeout(wait) {
                        Ok(chunk) => Some(chunk),
                        Err(RecvTimeoutError::Timeout) => {
                            return Err(io::Error::from(ErrorKind::TimedOut));
                        }
                        Err(RecvTimeoutError::Disconnected) => None,
                    }
                }
                None => self.rx.recv().ok(),
            };
            match next {
                Some(chunk) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                None => return Ok(0),
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Write for MemDuplex {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.tx
            .send(buf.to_vec())
            .map_err(|_| io::Error::from(ErrorKind::BrokenPipe))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Duplex for MemDuplex {
    fn set_read_deadline(&mut self, deadline: Option<Duration>) -> io::Result<()> {
        self.deadline = deadline.map(|d| Instant::now() + d);
        Ok(())
    }
}

// ---- a machine-scope integration -----------------------------------------------------------------

/// One call [`FakeMachineIntegration`] saw: the operation (`check`, `apply`, `remove`), the scope
/// and the version the request named.
pub type MachineIntegrationCall = (&'static str, lunepack_core::Scope, lunepack_core::Version);

/// An [`lunepack_core::OsIntegration`] that accepts machine scope (the testkit's
/// `FakeIntegration` refuses it, as the real adapters did before M10): it records every call and
/// fails the operation a test names. Clones share one state.
#[derive(Clone, Default)]
pub struct FakeMachineIntegration {
    inner: Arc<Mutex<MachineIntegrationState>>,
}

#[derive(Default)]
struct MachineIntegrationState {
    calls: Vec<MachineIntegrationCall>,
    fail: BTreeSet<&'static str>,
    applied: bool,
}

impl FakeMachineIntegration {
    /// Nothing applied.
    pub fn new() -> FakeMachineIntegration {
        FakeMachineIntegration::default()
    }

    /// Makes the operation `op` (`check`, `apply` or `remove`) fail.
    pub fn fail(&self, op: &'static str) {
        lock(&self.inner).fail.insert(op);
    }

    /// The calls so far.
    pub fn calls(&self) -> Vec<MachineIntegrationCall> {
        lock(&self.inner).calls.clone()
    }

    /// Whether an `apply` succeeded and no `remove` followed.
    pub fn is_applied(&self) -> bool {
        lock(&self.inner).applied
    }

    fn enter(
        &self,
        op: &'static str,
        scope: lunepack_core::Scope,
        req: &lunepack_core::IntegrationRequest,
    ) -> Result<MutexGuard<'_, MachineIntegrationState>, lunepack_core::IntegrationError> {
        let mut st = lock(&self.inner);
        st.calls.push((op, scope, req.version.clone()));
        if st.fail.contains(op) {
            return Err(lunepack_core::IntegrationError::Failed("scripted"));
        }
        Ok(st)
    }
}

impl lunepack_core::OsIntegration for FakeMachineIntegration {
    fn check(
        &self,
        scope: lunepack_core::Scope,
        req: &lunepack_core::IntegrationRequest,
    ) -> Result<(), lunepack_core::IntegrationError> {
        self.enter("check", scope, req).map(|_| ())
    }

    fn apply(
        &self,
        scope: lunepack_core::Scope,
        req: &lunepack_core::IntegrationRequest,
    ) -> Result<lunepack_core::IntegrationReport, lunepack_core::IntegrationError> {
        self.enter("apply", scope, req)?.applied = true;
        Ok(lunepack_core::IntegrationReport::default())
    }

    fn remove(
        &self,
        scope: lunepack_core::Scope,
        req: &lunepack_core::IntegrationRequest,
    ) -> Result<lunepack_core::IntegrationReport, lunepack_core::IntegrationError> {
        self.enter("remove", scope, req)?.applied = false;
        Ok(lunepack_core::IntegrationReport::default())
    }
}

// ---- a filesystem with injected faults -----------------------------------------------------------

/// A [`MemFs`] whose `rename` fails for the sources a test names (as a rename of a directory a
/// process runs from fails on Windows) and whose `create_new` fails under the directories a test
/// names; everything else is the `MemFs`'s.
#[derive(Clone)]
pub struct FaultFs {
    fs: MemFs,
    inner: Arc<Mutex<FaultState>>,
}

#[derive(Default)]
struct FaultState {
    rename_from: BTreeSet<PathBuf>,
    create_under: BTreeSet<PathBuf>,
}

impl FaultFs {
    /// Faults over `fs` (a clone sharing its state); none injected yet.
    pub fn new(fs: &MemFs) -> FaultFs {
        FaultFs {
            fs: fs.clone(),
            inner: Arc::default(),
        }
    }

    /// Makes `rename` of `from` fail.
    pub fn fail_rename_from(&self, from: &Path) {
        lock(&self.inner).rename_from.insert(from.to_path_buf());
    }

    /// Makes `create_new` of any file directly in `dir` fail.
    pub fn fail_create_in(&self, dir: &Path) {
        lock(&self.inner).create_under.insert(dir.to_path_buf());
    }

    fn fault(path: &Path, op: &'static str) -> lunepack_core::FsError {
        lunepack_core::FsError::new(lunepack_core::FsErrorKind::Locked, path, None).during(op)
    }
}

impl Fs for FaultFs {
    fn read_capped(&self, path: &Path, max: u64) -> Result<Vec<u8>, lunepack_core::FsError> {
        self.fs.read_capped(path, max)
    }
    fn open_read(
        &self,
        path: &Path,
    ) -> Result<Box<dyn lunepack_core::ReadAt>, lunepack_core::FsError> {
        self.fs.open_read(path)
    }
    fn create_new(
        &self,
        path: &Path,
    ) -> Result<Box<dyn lunepack_core::FileWrite>, lunepack_core::FsError> {
        if path
            .parent()
            .is_some_and(|p| lock(&self.inner).create_under.contains(p))
        {
            return Err(FaultFs::fault(path, "create"));
        }
        self.fs.create_new(path)
    }
    fn open_append(
        &self,
        path: &Path,
    ) -> Result<Box<dyn lunepack_core::FileWrite>, lunepack_core::FsError> {
        self.fs.open_append(path)
    }
    fn truncate(&self, path: &Path, len: u64) -> Result<(), lunepack_core::FsError> {
        self.fs.truncate(path, len)
    }
    fn rename(&self, from: &Path, to: &Path) -> Result<(), lunepack_core::FsError> {
        if lock(&self.inner).rename_from.contains(from) {
            return Err(FaultFs::fault(from, "rename"));
        }
        self.fs.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> Result<(), lunepack_core::FsError> {
        self.fs.remove_file(path)
    }
    fn remove_dir_all_nofollow(&self, path: &Path) -> Result<(), lunepack_core::FsError> {
        self.fs.remove_dir_all_nofollow(path)
    }
    fn create_dir_all(&self, path: &Path) -> Result<(), lunepack_core::FsError> {
        self.fs.create_dir_all(path)
    }
    fn list_dir(
        &self,
        path: &Path,
    ) -> Result<Vec<lunepack_core::DirEntryInfo>, lunepack_core::FsError> {
        self.fs.list_dir(path)
    }
    fn symlink_metadata(
        &self,
        path: &Path,
    ) -> Result<Option<lunepack_core::Meta>, lunepack_core::FsError> {
        self.fs.symlink_metadata(path)
    }
    fn sync_dir(&self, path: &Path) -> Result<(), lunepack_core::FsError> {
        self.fs.sync_dir(path)
    }
    fn copy_file(&self, from: &Path, to_new: &Path) -> Result<(), lunepack_core::FsError> {
        self.fs.copy_file(from, to_new)
    }
    fn set_exec(&self, path: &Path, exec: bool) -> Result<(), lunepack_core::FsError> {
        self.fs.set_exec(path, exec)
    }
    fn symlink(&self, target: &str, link_path: &Path) -> Result<(), lunepack_core::FsError> {
        self.fs.symlink(target, link_path)
    }
    fn read_link(&self, path: &Path) -> Result<String, lunepack_core::FsError> {
        self.fs.read_link(path)
    }
    fn replace_symlink(&self, target: &str, link: &Path) -> Result<(), lunepack_core::FsError> {
        self.fs.replace_symlink(target, link)
    }
    fn try_lock(
        &self,
        path: &Path,
    ) -> Result<Option<Box<dyn lunepack_core::LockGuard>>, lunepack_core::FsError> {
        self.fs.try_lock(path)
    }
}
