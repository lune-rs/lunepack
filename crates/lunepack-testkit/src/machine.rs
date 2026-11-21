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

    /// The images self-tested so far.
    pub fn self_tests(&self) -> Vec<PathBuf> {
        lock(&self.inner).self_tests.clone()
    }
}

impl ServiceRegistrar for FakeRegistrar {
    fn register(&self, app_id: &AppId, image: &Path) -> Result<(), ServiceRegError> {
        lock(&self.inner)
            .images
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
