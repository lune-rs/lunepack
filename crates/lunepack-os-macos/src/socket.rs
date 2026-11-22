//! The update service's unix socket on macOS (M11-D3, M11-D4, M11-D5).
//!
//! The service takes its listening socket from launchd with `launch_activate_socket` under the
//! plist's socket name ([`endpoint::LAUNCHD_SOCKET_NAME`]): exactly one descriptor, which must be a
//! unix stream socket (launchd binds it to a path of its own and reports no listening flag, so
//! neither can be checked further; probed). A client connects with [`UnixConnector`], which
//! refuses to send a byte unless the socket is root's, in a directory only root and system
//! services may change (`/var/run`, root:daemon 0775, accepted by M11-D5), and the peer
//! (launchd, which made the socket) runs as root. The server takes no decision from the peer's
//! identity.

#![allow(unsafe_code)]

use std::ffi::{CString, c_char, c_int, c_void};
use std::fs;
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use lunepack_core::endpoint;
use lunepack_core::layout::UnixOs;
use lunepack_core::service::Duplex;
use lunepack_core::{AppId, ConnectError, ServiceConnector};

/// How long a client retries a socket that is missing or refuses (launchd makes the socket within
/// about a second of `bootstrap`; probed).
pub const CONNECT_RETRY: Duration = Duration::from_secs(3);
const RETRY_STEP: Duration = Duration::from_millis(100);
/// The group of system services (`daemon`), which may write `/var/run` (M11-D5).
const DAEMON_GID: u32 = 1;

unsafe extern "C" {
    fn launch_activate_socket(name: *const c_char, fds: *mut *mut c_int, cnt: *mut usize) -> c_int;
}

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
        match self.0.set_read_timeout(deadline) {
            // setsockopt(2) on macOS: "EINVAL: the socket has been shut down". A read of a
            // shut-down socket ends at once, so it needs no deadline.
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => Ok(()),
            other => other,
        }
    }
}

impl Drop for UnixDuplex {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

// ---- the server's listener ------------------------------------------------------------------------

/// Why launchd's socket could not be taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationError {
    /// The listener was taken already in this process.
    Taken,
    /// `launch_activate_socket` failed (not started by launchd for this socket), with its error.
    NotActivated(i32),
    /// launchd passed no descriptor or more than one.
    WrongCount(usize),
    /// The descriptor is not a socket.
    NotASocket,
    /// The socket is not a unix stream socket.
    WrongKind,
}

static TAKEN: AtomicBool = AtomicBool::new(false);

/// The listening socket launchd passed (M11-D3).
#[derive(Debug)]
pub struct ActivatedListener {
    listener: UnixListener,
}

/// An `int` socket option of `fd`.
fn sockopt_int(fd: RawFd, option: c_int) -> io::Result<c_int> {
    let mut value: c_int = 0;
    let mut len = std::mem::size_of::<c_int>() as libc::socklen_t;
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

/// The address family `fd` is bound with.
fn bound_family(fd: RawFd) -> io::Result<c_int> {
    let mut addr = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `addr` is a zeroed `sockaddr_storage` with room for `len` bytes; the kernel writes
    // at most that many and updates `len`.
    let rc = unsafe { libc::getsockname(fd, addr.as_mut_ptr().cast(), &raw mut len) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: zero-initialised, then partly filled by the kernel: every byte is initialised.
    let addr = unsafe { addr.assume_init() };
    Ok(c_int::from(addr.ss_family))
}

/// Whether `fd` is an open socket.
fn is_socket(fd: RawFd) -> bool {
    let mut st = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `st` is valid for writes of one `stat`; an invalid descriptor only fails.
    let rc = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if rc != 0 {
        return false;
    }
    // SAFETY: `fstat` succeeded, so it filled the structure.
    let st = unsafe { st.assume_init_ref() };
    st.st_mode & libc::S_IFMT == libc::S_IFSOCK
}

/// Checks that `fd` is a unix stream socket (what launchd's socket must be).
pub fn check_listener(fd: RawFd) -> Result<(), ActivationError> {
    if !is_socket(fd) {
        return Err(ActivationError::NotASocket);
    }
    let kind = sockopt_int(fd, libc::SO_TYPE).map_err(|_| ActivationError::NotASocket)?;
    let family = bound_family(fd).map_err(|_| ActivationError::NotASocket)?;
    if kind != libc::SOCK_STREAM || family != libc::AF_UNIX {
        return Err(ActivationError::WrongKind);
    }
    Ok(())
}

/// Closes `fd`, which this process owns.
fn close(fd: RawFd) {
    // SAFETY: `fd` was handed to this process by launchd and is owned by nothing else here; it is
    // closed once.
    unsafe {
        libc::close(fd);
    }
}

impl ActivatedListener {
    /// Takes launchd's socket `name` (the plist's `Sockets` key): `launch_activate_socket` must
    /// answer exactly one descriptor, which must pass [`check_listener`]; it is made close-on-exec.
    /// Any other count is refused and every descriptor received is closed. Only once per process.
    /// Outside launchd the call fails: [`ActivationError::NotActivated`], never a panic.
    pub fn from_launchd(name: &str) -> Result<ActivatedListener, ActivationError> {
        let c_name = CString::new(name).map_err(|_| ActivationError::NotActivated(libc::EINVAL))?;
        let mut fds: *mut c_int = std::ptr::null_mut();
        let mut count: usize = 0;
        // SAFETY: `c_name` is a valid NUL-terminated string; `fds` and `count` are valid for one
        // write each. On success launchd stores a heap array of `count` descriptors in `fds`,
        // which this function frees with `free` below.
        let rc = unsafe { launch_activate_socket(c_name.as_ptr(), &raw mut fds, &raw mut count) };
        if rc != 0 {
            return Err(ActivationError::NotActivated(rc));
        }
        let received: Vec<RawFd> = if fds.is_null() {
            Vec::new()
        } else {
            // SAFETY: on success `fds` points to `count` initialised descriptors.
            let slice = unsafe { std::slice::from_raw_parts(fds, count) };
            slice.to_vec()
        };
        // SAFETY: `fds` was allocated by launchd with `malloc` (launch(3)); freed once, and not
        // used after (the descriptors were copied out).
        unsafe {
            libc::free(fds.cast::<c_void>());
        }
        let [fd] = received[..] else {
            for fd in received {
                close(fd);
            }
            return Err(ActivationError::WrongCount(count));
        };
        if let Err(e) = check_listener(fd) {
            close(fd);
            return Err(e);
        }
        if TAKEN.swap(true, Ordering::SeqCst) {
            close(fd);
            return Err(ActivationError::Taken);
        }
        // SAFETY: `fd` is an open unix stream socket (checked above) that launchd handed to this
        // process for this call and that nothing else here owns.
        let listener = unsafe { UnixListener::from_raw_fd(fd) };
        // SAFETY: `fd` is owned by `listener`; F_SETFD with FD_CLOEXEC changes only its
        // close-on-exec flag.
        unsafe {
            libc::fcntl(listener.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
        }
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

// ---- the client's connector -----------------------------------------------------------------------

/// The peer's effective uid (`getpeereid`).
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut uid: libc::uid_t = u32::MAX;
    let mut gid: libc::gid_t = u32::MAX;
    // SAFETY: `uid` and `gid` are valid for one write each; the descriptor is the stream's own.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &raw mut uid, &raw mut gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
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
    /// The sockets of [`endpoint::socket_path`] on macOS, owned by root.
    pub fn new() -> UnixConnector {
        UnixConnector {
            dir: PathBuf::from(endpoint::SOCKET_DIR_MACOS),
            owner: 0,
            retry: CONNECT_RETRY,
        }
    }

    /// For tests that cannot run as root: the sockets `<dir>/lunepack-<app id>.sock`, owned by
    /// `owner`, and a retry of `retry`. Never used by a composition root.
    #[doc(hidden)]
    pub fn for_tests(dir: PathBuf, owner: u32, retry: Duration) -> UnixConnector {
        UnixConnector { dir, owner, retry }
    }

    /// The socket directory as the system resolves it (`/var/run` is a link to
    /// `/private/var/run`, both made by the system in root's directories), checked: a real
    /// directory of the owner that others may not write and whose group may write only when it is
    /// the owner's or `daemon`.
    fn checked_dir(&self) -> Result<PathBuf, ConnectError> {
        let dir = fs::canonicalize(&self.dir).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => ConnectError::NotInstalled,
            _ => ConnectError::Failed("the socket directory could not be read"),
        })?;
        let meta = fs::symlink_metadata(&dir)
            .map_err(|_| ConnectError::Failed("the socket directory could not be read"))?;
        let group_ok = meta.mode() & 0o020 == 0 || meta.gid() == DAEMON_GID || meta.gid() == 0;
        if !meta.is_dir() || meta.uid() != self.owner || meta.mode() & 0o002 != 0 || !group_ok {
            return Err(ConnectError::WrongOwner);
        }
        Ok(dir)
    }

    /// One attempt: the directory and the socket are trusted, then the connection, then the
    /// peer's uid; nothing is written.
    fn attempt(&self, app_id: &AppId) -> Result<Attempt, ConnectError> {
        let dir = self.checked_dir()?;
        let name = endpoint::socket_path(UnixOs::Macos, app_id);
        let path = dir.join(
            name.file_name()
                .ok_or(ConnectError::Failed("socket name"))?,
        );
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Attempt::Missing),
            Err(_) => return Err(ConnectError::Failed("the socket could not be read")),
        };
        if !meta.file_type().is_socket() || meta.uid() != self.owner {
            return Err(ConnectError::WrongOwner);
        }
        let stream = match UnixStream::connect(&path) {
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
        let deadline = Instant::now() + self.retry;
        loop {
            let last = match self.attempt(app_id)? {
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
