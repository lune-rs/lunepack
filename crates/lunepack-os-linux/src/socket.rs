//! The update service's unix socket on Linux (M11-D3, M11-D4, M11-D5).
//!
//! The service takes its listening socket from systemd as descriptor 3 ([`ActivatedListener`]),
//! after checking that descriptor is exactly the socket its unit names; it reads no environment
//! variable. A client connects with [`UnixConnector`], which refuses to send a byte unless the
//! socket is root's, in a directory only root may change, and the peer runs as root. The server
//! takes no decision from the peer's identity (M11-D5).

use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use lunepack_core::endpoint;
use lunepack_core::layout::UnixOs;
use lunepack_core::service::Duplex;
use lunepack_core::{AppId, ConnectError, ServiceConnector};

/// The first descriptor systemd passes (`SD_LISTEN_FDS_START`).
pub const SYSTEMD_FD: RawFd = 3;
/// How long a client retries a socket that is missing or refuses (the unit starting).
pub const CONNECT_RETRY: Duration = Duration::from_secs(3);
const RETRY_STEP: Duration = Duration::from_millis(100);

/// A connected unix stream as a service-protocol [`Duplex`].
#[derive(Debug)]
pub struct UnixDuplex(UnixStream);

impl UnixDuplex {
    /// The stream.
    pub fn new(stream: UnixStream) -> UnixDuplex {
        UnixDuplex(stream)
    }
}

impl Read for UnixDuplex {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for UnixDuplex {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Duplex for UnixDuplex {
    fn set_read_deadline(&mut self, deadline: Option<Duration>) -> io::Result<()> {
        // A zero timeout means "none" to the socket: the shortest real one stands for it.
        let deadline = deadline.map(|d| d.max(Duration::from_millis(1)));
        self.0.set_read_timeout(deadline)
    }
}

impl Drop for UnixDuplex {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

// ---- the server's listener ------------------------------------------------------------------------

/// Why descriptor 3 is not the service's listening socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationError {
    /// The listener was taken already in this process.
    Taken,
    /// Descriptor 3 is not open, or not a socket.
    NotASocket,
    /// The socket does not listen.
    NotListening,
    /// The socket is not a unix stream socket.
    WrongKind,
    /// The socket's path is not the expected one.
    WrongPath,
}

static TAKEN: AtomicBool = AtomicBool::new(false);

/// The listening socket systemd passed (M11-D3, `Accept=no`).
#[derive(Debug)]
pub struct ActivatedListener {
    listener: UnixListener,
}

/// An `int` socket option of `fd`.
#[allow(unsafe_code)]
fn sockopt_int(fd: RawFd, option: libc::c_int) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `value` and `len` are valid for writes of the sizes `len` states; the kernel writes
    // at most `len` bytes and updates `len`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&raw mut value).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

/// The path `fd` is bound to (`None` for an unnamed or abstract address).
#[allow(unsafe_code)]
fn bound_path(fd: RawFd) -> io::Result<Option<PathBuf>> {
    let mut addr = MaybeUninit::<libc::sockaddr_un>::zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    // SAFETY: `addr` is a zeroed `sockaddr_un` with room for `len` bytes; the kernel writes at
    // most that many and updates `len`.
    let rc = unsafe { libc::getsockname(fd, addr.as_mut_ptr().cast(), &raw mut len) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the structure was zero-initialised and the kernel filled part of it.
    let addr = unsafe { addr.assume_init() };
    if i32::from(addr.sun_family) != libc::AF_UNIX {
        return Ok(None);
    }
    let offset = std::mem::size_of::<libc::sa_family_t>();
    let path_len = (len as usize)
        .saturating_sub(offset)
        .min(addr.sun_path.len());
    let raw: Vec<u8> = addr.sun_path[..path_len]
        .iter()
        .map(|&c| c as u8)
        .take_while(|&b| b != 0)
        .collect();
    if raw.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(OsStr::from_bytes(&raw))))
}

/// Checks that `fd` is a listening unix stream socket bound to `expected`.
pub fn check_listener(fd: RawFd, expected: &Path) -> Result<(), ActivationError> {
    let is_socket = {
        let mut st = MaybeUninit::<libc::stat>::zeroed();
        fstat_is_socket(fd, &mut st)
    };
    if !is_socket {
        return Err(ActivationError::NotASocket);
    }
    let accepting =
        sockopt_int(fd, libc::SO_ACCEPTCONN).map_err(|_| ActivationError::NotASocket)?;
    let domain = sockopt_int(fd, libc::SO_DOMAIN).map_err(|_| ActivationError::NotASocket)?;
    let kind = sockopt_int(fd, libc::SO_TYPE).map_err(|_| ActivationError::NotASocket)?;
    if domain != libc::AF_UNIX || kind != libc::SOCK_STREAM {
        return Err(ActivationError::WrongKind);
    }
    if accepting != 1 {
        return Err(ActivationError::NotListening);
    }
    match bound_path(fd) {
        Ok(Some(path)) if path == expected => Ok(()),
        _ => Err(ActivationError::WrongPath),
    }
}

#[allow(unsafe_code)]
fn fstat_is_socket(fd: RawFd, st: &mut MaybeUninit<libc::stat>) -> bool {
    // SAFETY: `st` is valid for writes of one `stat`; an invalid descriptor only fails.
    let rc = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if rc != 0 {
        return false;
    }
    // SAFETY: `fstat` succeeded, so it filled the structure.
    let st = unsafe { st.assume_init_ref() };
    st.st_mode & libc::S_IFMT == libc::S_IFSOCK
}

impl ActivatedListener {
    /// Takes descriptor 3 as the service's listener after [`check_listener`] with `expected` (the
    /// path the unit names, [`endpoint::socket_path`]); the descriptor is made close-on-exec. Only
    /// once per process: a second call is [`ActivationError::Taken`]. Nothing from the
    /// environment is read (`LISTEN_FDS` and `LISTEN_PID` are not trusted for anything).
    #[allow(unsafe_code)]
    pub fn from_systemd(expected: &Path) -> Result<ActivatedListener, ActivationError> {
        check_listener(SYSTEMD_FD, expected)?;
        if TAKEN.swap(true, Ordering::SeqCst) {
            return Err(ActivationError::Taken);
        }
        // SAFETY: descriptor 3 is an open listening unix stream socket (checked above) that
        // nothing else in this process owns: `TAKEN` lets this happen once, and the process
        // opens its own descriptors only after the systemd ones.
        let listener = unsafe { UnixListener::from_raw_fd(SYSTEMD_FD) };
        set_cloexec(listener.as_raw_fd());
        Ok(ActivatedListener { listener })
    }

    /// The next client; blocks.
    pub fn accept(&self) -> io::Result<UnixDuplex> {
        let (stream, _) = self.listener.accept()?;
        Ok(UnixDuplex(stream))
    }

    /// The listener (for `set_nonblocking` or a poll in the host's idle loop).
    pub fn listener(&self) -> &UnixListener {
        &self.listener
    }
}

#[allow(unsafe_code)]
fn set_cloexec(fd: RawFd) {
    // SAFETY: `fd` is a descriptor this process owns; F_SETFD with FD_CLOEXEC changes only its
    // close-on-exec flag.
    unsafe {
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }
}

// ---- the client's connector -----------------------------------------------------------------------

/// The peer's effective uid (`SO_PEERCRED`).
#[allow(unsafe_code)]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for writes of the sizes `len` states; the kernel writes
    // at most `len` bytes.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(cred.uid)
}

/// [`ServiceConnector`] over the service's unix socket (M11-D5).
#[derive(Debug, Clone)]
pub struct UnixConnector {
    dir: PathBuf,
    /// The uid the socket, its directory and the peer must have (0).
    owner: u32,
    retry: Duration,
}

impl Default for UnixConnector {
    fn default() -> Self {
        UnixConnector::new()
    }
}

/// What one attempt found.
enum Attempt {
    Connected(UnixStream),
    Missing,
    Refused,
}

impl UnixConnector {
    /// The sockets of [`endpoint::socket_path`] on Linux, owned by root.
    pub fn new() -> UnixConnector {
        UnixConnector {
            dir: PathBuf::from(endpoint::SOCKET_DIR_LINUX),
            owner: 0,
            retry: CONNECT_RETRY,
        }
    }

    /// For tests that cannot run as root: the sockets `<dir>/<app id>.sock`, owned by `owner`, and
    /// a retry of `retry`. Never used by a composition root.
    #[doc(hidden)]
    pub fn for_tests(dir: PathBuf, owner: u32, retry: Duration) -> UnixConnector {
        UnixConnector { dir, owner, retry }
    }

    fn socket_path(&self, app_id: &AppId) -> PathBuf {
        let name = endpoint::socket_path(UnixOs::Linux, app_id);
        match name.file_name() {
            Some(file) => self.dir.join(file),
            None => name,
        }
    }

    /// One attempt: the directory and the socket are the owner's and nobody else may change
    /// them, then the connection, then the peer's uid; nothing is written.
    fn attempt(&self, path: &Path) -> Result<Attempt, ConnectError> {
        let dir = fs::symlink_metadata(&self.dir).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => ConnectError::NotInstalled,
            _ => ConnectError::Failed("the socket directory could not be read"),
        })?;
        if !dir.is_dir() || dir.uid() != self.owner || dir.mode() & 0o022 != 0 {
            return Err(ConnectError::WrongOwner);
        }
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Attempt::Missing),
            Err(_) => return Err(ConnectError::Failed("the socket could not be read")),
        };
        if !meta.file_type().is_socket() || meta.uid() != self.owner {
            return Err(ConnectError::WrongOwner);
        }
        let stream = match UnixStream::connect(path) {
            Ok(stream) => stream,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Attempt::Missing),
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => return Ok(Attempt::Refused),
            Err(e) => {
                return Err(ConnectError::FailedCode(
                    "connect",
                    e.raw_os_error().unwrap_or(0).unsigned_abs(),
                ));
            }
        };
        match peer_uid(&stream) {
            Ok(uid) if uid == self.owner => Ok(Attempt::Connected(stream)),
            Ok(_) => Err(ConnectError::WrongOwner),
            Err(_) => Err(ConnectError::Failed("the peer could not be identified")),
        }
    }
}

impl ServiceConnector for UnixConnector {
    fn connect(&self, app_id: &AppId) -> Result<Box<dyn Duplex>, ConnectError> {
        let path = self.socket_path(app_id);
        let deadline = Instant::now() + self.retry;
        loop {
            let last = match self.attempt(&path)? {
                Attempt::Connected(stream) => return Ok(Box::new(UnixDuplex(stream))),
                Attempt::Missing => ConnectError::NotInstalled,
                Attempt::Refused => ConnectError::Disabled,
            };
            if Instant::now() >= deadline {
                return Err(last);
            }
            std::thread::sleep(RETRY_STEP);
        }
    }
}
