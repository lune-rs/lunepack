//! The named pipe of the per-machine install (M10 step 8): [`PipeServer`] and [`PipeClient`],
//! both a [`Duplex`] with real read deadlines.
//!
//! # The server
//!
//! [`PipeServer::create`] makes exactly one instance of `\\.\pipe\<name>` with
//! `FILE_FLAG_FIRST_PIPE_INSTANCE` (a name that exists already is [`PipeError::Exists`], never
//! joined), `PIPE_REJECT_REMOTE_CLIENTS`, byte mode and an explicit descriptor whose owner is set
//! in the descriptor itself; a creator whose token cannot assign that owner gets
//! [`PipeError::OwnerNotAssignable`] and no pipe (there is no fallback to a default owner). The one
//! instance is kept for the server's whole life and reused: [`PipeServer::accept`] waits for a
//! client, [`PipeServer::disconnect`] lets it go, and the name is never free while the server
//! lives. Between the two the server itself is the channel to its client.
//!
//! Two shapes ([`PipeAccess`]):
//!
//! - `Service`: owner LocalSystem; LocalSystem and Administrators full control; Users exactly
//!   [`PEER_MASK`] (read data, write data, read EA, read attributes, read control, synchronize).
//! - `Elevation { sid }`: owner Administrators; the same entries with `sid` in place of Users;
//!   outbound only (the server writes, the client reads).
//!
//! No entry for a non-administrator holds `FILE_CREATE_PIPE_INSTANCE` (the bit of append data),
//! write DAC or write owner, so nobody else can add an instance and receive the clients.
//!
//! # The client
//!
//! [`PipeClient::connect`] opens the pipe with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`
//! (the server can identify the caller but never act as it), waits while the instance is busy
//! until its timeout ([`PipeError::Busy`]), then reads the pipe's owner from the handle and closes
//! it without sending a byte ([`PipeError::Untrusted`]) unless the owner is exactly the one
//! [`ExpectedOwner`] names. The rights it asks for are spelled out (never a generic write, which
//! would include the create-instance right).
//!
//! # Deadlines and peer loss
//!
//! Every operation is overlapped and always settled before it returns (cancelled with
//! `CancelIoEx` and waited for when its time is up), so no buffer outlives its operation. A read
//! past the deadline [`Duplex::set_read_deadline`] set fails with [`std::io::ErrorKind::TimedOut`]
//! and leaves the channel usable for closing; bytes that arrived in the same instant are returned,
//! never dropped. A peer that disappears reads as the end of the channel (`Ok(0)`) and writes as
//! [`std::io::ErrorKind::BrokenPipe`]. A server's writes wait at most
//! [`SERVER_WRITE_TIMEOUT`] by default (a client that never reads cannot hold the service);
//! [`PipeCanceller::cancel`] ends a blocked accept, read or write of its server for good (shutdown).
//!
//! This module uses no impersonation API and reads no environment variable.

use std::fmt;
use std::time::Duration;

use crate::security::{SID_ADMINISTRATORS, SID_SYSTEM};

/// The rights of the peer entry of both shapes: `FILE_READ_DATA` (0x1), `FILE_WRITE_DATA` (0x2),
/// `FILE_READ_EA` (0x8), `FILE_READ_ATTRIBUTES` (0x80), `READ_CONTROL` (0x2_0000) and
/// `SYNCHRONIZE` (0x10_0000). No `FILE_CREATE_PIPE_INSTANCE` (0x4), write DAC or write owner.
pub const PEER_MASK: u32 = 0x0001 | 0x0002 | 0x0008 | 0x0080 | 0x0002_0000 | 0x0010_0000;

/// `FILE_CREATE_PIPE_INSTANCE`, the same bit as `FILE_APPEND_DATA`.
pub const FILE_CREATE_PIPE_INSTANCE: u32 = 0x0004;

/// How long a server's write waits for the client to make room by default.
pub const SERVER_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest pipe name accepted (the part after `\\.\pipe\`).
const MAX_NAME: usize = 200;

/// Who may use a pipe the server creates, and who owns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipeAccess {
    /// The update service's pipe: owner LocalSystem, Users may read and write data.
    Service,
    /// The elevation hand-off's pipe: owner Administrators, only `sid` may read (`S-1-...` text),
    /// outbound only.
    Elevation {
        /// The SID of the one account that may connect, as `S-1-...` text.
        sid: String,
    },
    /// Tests only: owned by `sid` (the test's own user), which may also read and write data.
    #[cfg(test)]
    TestOwned {
        /// The owner, as `S-1-...` text.
        sid: String,
    },
}

/// The owner a client requires of the pipe it opened; anything else is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedOwner {
    /// LocalSystem: the update service's pipe, opened for reading and writing.
    LocalSystem,
    /// Administrators: the elevation hand-off's pipe, opened for reading only.
    Administrators,
    /// Tests only: the given SID, opened for reading and writing.
    #[cfg(test)]
    TestOwner(String),
}

/// Why a pipe could not be created or connected. Carries no path and no OS message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PipeError {
    /// The pipe name is empty, too long or has a character outside `[A-Za-z0-9._-]`.
    InvalidName,
    /// The SID of an `Elevation` pipe is not `S-1-` followed by numbers.
    InvalidSid,
    /// The name exists already (Windows reports this as access denied for a first instance).
    Exists,
    /// The creator's token cannot assign the owner the descriptor names; no pipe was made.
    OwnerNotAssignable,
    /// The pipe's only instance stayed busy until the timeout.
    Busy,
    /// No pipe of that name appeared before the timeout.
    NotFound,
    /// The pipe's owner is not the expected one, or could not be read; nothing was sent.
    Untrusted,
    /// No client came before the timeout.
    Timeout,
    /// The server was cancelled.
    Cancelled,
    /// Another failure: what was attempted and the Windows error code.
    Os {
        /// The attempted operation (a fixed description).
        what: &'static str,
        /// The Windows error code.
        code: u32,
    },
}

impl fmt::Display for PipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PipeError::InvalidName => f.write_str("not a valid pipe name"),
            PipeError::InvalidSid => f.write_str("not a valid SID"),
            PipeError::Exists => f.write_str("the pipe exists already"),
            PipeError::OwnerNotAssignable => f.write_str("the pipe's owner cannot be assigned"),
            PipeError::Busy => f.write_str("the pipe is busy"),
            PipeError::NotFound => f.write_str("the pipe does not exist"),
            PipeError::Untrusted => f.write_str("the pipe has an unexpected owner"),
            PipeError::Timeout => f.write_str("no client connected in time"),
            PipeError::Cancelled => f.write_str("the pipe server was cancelled"),
            PipeError::Os { what, code } => write!(f, "{what} failed (Windows error {code})"),
        }
    }
}

impl std::error::Error for PipeError {}

/// `\\.\pipe\<name>` for a valid `name`.
fn pipe_path(name: &str) -> Result<String, PipeError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !valid {
        return Err(PipeError::InvalidName);
    }
    Ok(format!(r"\\.\pipe\{name}"))
}

/// Whether `sid` is `S-1-` followed by one to fifteen dash-separated decimal numbers of at most
/// fifteen digits each (so nothing but digits and dashes reaches the descriptor text).
fn valid_sid(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("S-1-") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('-').collect();
    (1..=16).contains(&parts.len())
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 15 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The descriptor text of `access`: the owner set explicitly, a protected DACL with no
/// inheritance flags.
fn sddl(access: &PipeAccess) -> Result<String, PipeError> {
    let entries = |peer: &str| format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;{PEER_MASK:#x};;;{peer})");
    match access {
        PipeAccess::Service => Ok(format!("O:SY{}", entries("BU"))),
        PipeAccess::Elevation { sid } => {
            if !valid_sid(sid) {
                return Err(PipeError::InvalidSid);
            }
            Ok(format!("O:BA{}", entries(sid)))
        }
        #[cfg(test)]
        PipeAccess::TestOwned { sid } => {
            if !valid_sid(sid) {
                return Err(PipeError::InvalidSid);
            }
            Ok(format!("O:{sid}{}", entries(sid)))
        }
    }
}

impl ExpectedOwner {
    /// The owner's SID as text.
    fn sid(&self) -> &str {
        match self {
            ExpectedOwner::LocalSystem => SID_SYSTEM,
            ExpectedOwner::Administrators => SID_ADMINISTRATORS,
            #[cfg(test)]
            ExpectedOwner::TestOwner(sid) => sid,
        }
    }

    /// Whether the client only reads (the elevation pipe is outbound only).
    fn read_only(&self) -> bool {
        matches!(self, ExpectedOwner::Administrators)
    }
}

#[cfg(windows)]
pub use ffi::{PipeCanceller, PipeClient, PipeServer, pipe_descriptor};

#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi {
    use std::io::{self, Read, Write};
    use std::ptr::{null, null_mut};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use lunepack_core::service::Duplex;
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_INVALID_OWNER,
        ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY,
        ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, ERROR_PRIVILEGE_NOT_HELD, GetLastError,
        HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES,
        FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, PIPE_ACCESS_OUTBOUND,
        READ_CONTROL, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, SYNCHRONIZE,
        WriteFile,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, WaitNamedPipeW,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, INFINITE, ResetEvent, SetEvent, WaitForMultipleObjects, WaitForSingleObject,
    };

    use super::{ExpectedOwner, PipeAccess, PipeError, SERVER_WRITE_TIMEOUT, pipe_path, sddl};
    use crate::security::{
        CheckError, Descriptor, HandleGuard, LocalGuard, handle_descriptor, handle_owner,
        sd_descriptor, wide,
    };

    /// Each direction's buffer.
    const BUFFER: u32 = 64 * 1024;
    /// How long [`PipeServer::disconnect`] waits for the client to close its end, so that it can
    /// read what was written last.
    const LINGER: Duration = Duration::from_secs(2);
    /// The most bytes [`PipeServer::disconnect`] discards while it waits.
    const LINGER_BYTES: usize = 1024 * 1024;
    /// The pause between two attempts to open a pipe that does not exist yet.
    const RETRY: Duration = Duration::from_millis(50);

    /// The last Windows error code.
    fn last_error() -> u32 {
        // SAFETY: `GetLastError` takes no argument.
        unsafe { GetLastError() }
    }

    /// An owned pipe handle; closed on drop.
    struct Pipe(HandleGuard);

    // SAFETY: a pipe handle is a kernel handle usable from any thread; this wrapper owns it alone
    // and every use goes through `&mut` of its owner, so it is never used from two threads at once.
    unsafe impl Send for Pipe {}

    impl Pipe {
        fn raw(&self) -> HANDLE {
            self.0.0
        }
    }

    /// An owned manual-reset event; closed on drop.
    struct Event(HandleGuard);

    // SAFETY: an event handle is a kernel handle; setting, resetting and waiting on it are
    // thread-safe system calls, and the handle stays open until the last owner drops it.
    unsafe impl Send for Event {}
    // SAFETY: as above; `&Event` only allows those thread-safe calls.
    unsafe impl Sync for Event {}

    impl Event {
        fn new() -> io::Result<Event> {
            // SAFETY: null security attributes and a null name make an unnamed event with the
            // default descriptor; manual reset, initially not signalled.
            let handle = unsafe { CreateEventW(null(), 1, 0, null()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Event(HandleGuard(handle)))
        }

        fn raw(&self) -> HANDLE {
            self.0.0
        }

        fn is_set(&self) -> bool {
            // SAFETY: the handle is an open event; a zero timeout only polls its state.
            unsafe { WaitForSingleObject(self.raw(), 0) == WAIT_OBJECT_0 }
        }
    }

    /// The whole milliseconds of `limit`, rounded up, below `INFINITE`; `None` is `INFINITE`.
    fn millis(limit: Option<Duration>) -> u32 {
        match limit {
            None => INFINITE,
            Some(d) => {
                let ms = d.as_nanos().div_ceil(1_000_000);
                u32::try_from(ms).unwrap_or(INFINITE - 1).min(INFINITE - 1)
            }
        }
    }

    /// How an overlapped operation ended.
    enum Outcome {
        /// Completed, with the bytes transferred.
        Done(u32),
        /// Failed with this code.
        Failed(u32),
        /// Its time ran out and it was cancelled.
        TimedOut,
        /// The canceller was signalled and it was cancelled.
        Cancelled,
    }

    /// Starts one overlapped operation through `start` (which gets the `OVERLAPPED` to pass),
    /// waits for it up to `limit` or until `cancel` is signalled, and settles it before
    /// returning in every case: an operation still running is cancelled and waited for, so neither
    /// the `OVERLAPPED` nor the caller's buffer is in use afterwards. An operation that completed
    /// while it was being cancelled counts as done.
    fn run(
        pipe: &Pipe,
        event: &Event,
        cancel: Option<&Event>,
        limit: Option<Duration>,
        start: impl FnOnce(*mut OVERLAPPED) -> i32,
    ) -> Outcome {
        if cancel.is_some_and(Event::is_set) {
            return Outcome::Cancelled;
        }
        // SAFETY: an all-zero `OVERLAPPED` is a valid value (integers and a null event).
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = event.raw();
        // SAFETY: the handle is an open event.
        unsafe { ResetEvent(event.raw()) };
        let mut cut: Option<Outcome> = None;
        if start(&mut ov) == 0 {
            let code = last_error();
            if code != ERROR_IO_PENDING {
                // Not started: nothing to settle.
                return Outcome::Failed(code);
            }
            let handles = [event.raw(), cancel.map_or(event.raw(), Event::raw)];
            let count = if cancel.is_some() { 2 } else { 1 };
            // SAFETY: `handles` holds `count` open event handles and outlives the call.
            let waited =
                unsafe { WaitForMultipleObjects(count, handles.as_ptr(), 0, millis(limit)) };
            if waited != WAIT_OBJECT_0 {
                cut = Some(match waited {
                    WAIT_TIMEOUT => Outcome::TimedOut,
                    w if w == WAIT_OBJECT_0 + 1 => Outcome::Cancelled,
                    _ => Outcome::Failed(last_error()),
                });
                // SAFETY: `ov` is the `OVERLAPPED` of the operation started on this handle above;
                // cancelling an operation that has completed meanwhile is a harmless no-op.
                unsafe { CancelIoEx(pipe.raw(), &ov) };
            }
        }
        let mut n = 0u32;
        // SAFETY: `ov` belongs to the operation started on this handle; waiting (`TRUE`) returns
        // only once it has completed or been cancelled, after which the system no longer touches
        // `ov` or the buffer.
        let ok = unsafe { GetOverlappedResult(pipe.raw(), &ov, &mut n, 1) };
        if ok != 0 {
            return Outcome::Done(n);
        }
        let code = last_error();
        match cut {
            Some(outcome) if code == ERROR_OPERATION_ABORTED => outcome,
            _ => Outcome::Failed(code),
        }
    }

    /// One end's I/O state.
    struct Io {
        pipe: Pipe,
        event: Event,
        cancel: Option<Arc<Event>>,
        read_deadline: Option<Instant>,
        write_timeout: Option<Duration>,
    }

    impl Io {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
            let limit = self
                .read_deadline
                .map(|d| d.saturating_duration_since(Instant::now()));
            let raw = self.pipe.raw();
            let ptr = buf.as_mut_ptr();
            // SAFETY (inside the closure): `ptr` points at `len` writable bytes of `buf`, which
            // stays borrowed until `run` returns, and `run` settles the operation before that.
            let outcome = run(
                &self.pipe,
                &self.event,
                self.cancel.as_deref(),
                limit,
                |ov| {
                    // SAFETY: see above; the handle is open and `ov` is valid for the operation.
                    unsafe { ReadFile(raw, ptr, len, null_mut(), ov) }
                },
            );
            match outcome {
                Outcome::Done(n) => Ok(n as usize),
                Outcome::Failed(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA) => {
                    Ok(0)
                }
                Outcome::Failed(code) => Err(io::Error::from_raw_os_error(code as i32)),
                Outcome::TimedOut => Err(io::Error::from(io::ErrorKind::TimedOut)),
                Outcome::Cancelled => Err(io::Error::from(io::ErrorKind::ConnectionAborted)),
            }
        }

        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
            let raw = self.pipe.raw();
            let ptr = buf.as_ptr();
            let outcome = run(
                &self.pipe,
                &self.event,
                self.cancel.as_deref(),
                self.write_timeout,
                |ov| {
                    // SAFETY: `ptr` points at `len` readable bytes of `buf`, borrowed until `run`
                    // returns, which settles the operation first; the handle is open.
                    unsafe { WriteFile(raw, ptr, len, null_mut(), ov) }
                },
            );
            match outcome {
                Outcome::Done(n) => Ok(n as usize),
                Outcome::Failed(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA) => {
                    Err(io::Error::from(io::ErrorKind::BrokenPipe))
                }
                Outcome::Failed(code) => Err(io::Error::from_raw_os_error(code as i32)),
                Outcome::TimedOut => Err(io::Error::from(io::ErrorKind::TimedOut)),
                Outcome::Cancelled => Err(io::Error::from(io::ErrorKind::ConnectionAborted)),
            }
        }

        fn set_read_deadline(&mut self, deadline: Option<Duration>) {
            self.read_deadline = deadline.map(|d| Instant::now() + d);
        }
    }

    /// Builds the descriptor of `access` in memory; `f` gets it while it is alive.
    fn with_descriptor<T>(
        access: &PipeAccess,
        f: impl FnOnce(PSECURITY_DESCRIPTOR) -> Result<T, PipeError>,
    ) -> Result<T, PipeError> {
        let text = wide(&sddl(access)?);
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `text` is a NUL-terminated `u16` buffer that outlives the call; `sd` is a valid
        // out pointer and the size out pointer is null. On success `sd` is a `LocalAlloc` buffer
        // the guard frees.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(PipeError::Os {
                what: "descriptor",
                code: last_error(),
            });
        }
        let _sd = LocalGuard(sd);
        f(sd)
    }

    fn read_back(e: CheckError) -> PipeError {
        PipeError::Os {
            what: match e {
                CheckError::Os(what) => what,
                _ => "read the descriptor",
            },
            code: 0,
        }
    }

    /// The owner and the DACL of the descriptor a server of `access` creates its pipe with, read
    /// back from the descriptor built in memory (no pipe is made).
    pub fn pipe_descriptor(access: &PipeAccess) -> Result<Descriptor, PipeError> {
        with_descriptor(access, |sd| sd_descriptor(sd).map_err(read_back))
    }

    /// Ends a [`PipeServer`]'s blocked accept, read or write, and every later one (shutdown).
    /// Cheap to clone; usable from any thread.
    #[derive(Clone)]
    pub struct PipeCanceller(Arc<Event>);

    impl PipeCanceller {
        /// Cancels the server for good.
        pub fn cancel(&self) {
            // SAFETY: the handle is an open event, kept open by the `Arc`.
            unsafe { SetEvent(self.0.raw()) };
        }
    }

    /// The server end: one pipe instance for its whole life, one client at a time. Between a
    /// successful [`PipeServer::accept`] and [`PipeServer::disconnect`] it is the channel to that
    /// client; otherwise reads and writes fail with `NotConnected`.
    pub struct PipeServer {
        io: Io,
        cancel: Arc<Event>,
        outbound: bool,
        connected: bool,
    }

    impl PipeServer {
        /// Creates the only instance of `\\.\pipe\<name>` with the descriptor of `access`.
        pub fn create(name: &str, access: &PipeAccess) -> Result<PipeServer, PipeError> {
            let path = wide(&pipe_path(name)?);
            let outbound = matches!(access, PipeAccess::Elevation { .. });
            let event = Event::new().map_err(|_| PipeError::Os {
                what: "create an event",
                code: last_error(),
            })?;
            let cancel = Event::new().map_err(|_| PipeError::Os {
                what: "create an event",
                code: last_error(),
            })?;
            let direction = if outbound {
                PIPE_ACCESS_OUTBOUND
            } else {
                PIPE_ACCESS_DUPLEX
            };
            let handle = with_descriptor(access, |sd| {
                let attributes = SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: sd,
                    bInheritHandle: 0,
                };
                // SAFETY: `path` is a NUL-terminated `u16` buffer and `attributes` a valid
                // `SECURITY_ATTRIBUTES` whose descriptor stays allocated during the call. The
                // descriptor is applied by the create call itself; a name that exists already
                // fails the call (`FILE_FLAG_FIRST_PIPE_INSTANCE`) and is never joined.
                let handle = unsafe {
                    CreateNamedPipeW(
                        path.as_ptr(),
                        direction | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                        PIPE_TYPE_BYTE
                            | PIPE_READMODE_BYTE
                            | PIPE_WAIT
                            | PIPE_REJECT_REMOTE_CLIENTS,
                        1,
                        BUFFER,
                        if outbound { 0 } else { BUFFER },
                        0,
                        &attributes,
                    )
                };
                if handle == INVALID_HANDLE_VALUE {
                    return Err(match last_error() {
                        ERROR_ACCESS_DENIED | ERROR_PIPE_BUSY => PipeError::Exists,
                        ERROR_INVALID_OWNER | ERROR_PRIVILEGE_NOT_HELD => {
                            PipeError::OwnerNotAssignable
                        }
                        code => PipeError::Os {
                            what: "create the pipe",
                            code,
                        },
                    });
                }
                Ok(handle)
            })?;
            let cancel = Arc::new(cancel);
            Ok(PipeServer {
                cancel: Arc::clone(&cancel),
                io: Io {
                    pipe: Pipe(HandleGuard(handle)),
                    event,
                    cancel: Some(cancel),
                    read_deadline: None,
                    write_timeout: Some(SERVER_WRITE_TIMEOUT),
                },
                outbound,
                connected: false,
            })
        }

        /// A handle that cancels this server from another thread.
        pub fn canceller(&self) -> PipeCanceller {
            PipeCanceller(Arc::clone(&self.cancel))
        }

        /// Waits up to `timeout` (`None`: no limit) for a client, after letting go of the current
        /// one. On success the server is the channel to the new client, with no read deadline.
        pub fn accept(&mut self, timeout: Option<Duration>) -> Result<(), PipeError> {
            self.disconnect();
            let end = timeout.map(|t| Instant::now() + t);
            let cancel = self.io.cancel.clone();
            loop {
                let limit = end.map(|e| e.saturating_duration_since(Instant::now()));
                let raw = self.io.pipe.raw();
                let outcome = run(
                    &self.io.pipe,
                    &self.io.event,
                    cancel.as_deref(),
                    limit,
                    |ov| {
                        // SAFETY: the handle is the server end of an open pipe and `ov` is valid
                        // until `run` settles the operation.
                        unsafe { ConnectNamedPipe(raw, ov) }
                    },
                );
                match outcome {
                    Outcome::Done(_) | Outcome::Failed(ERROR_PIPE_CONNECTED) => break,
                    Outcome::Failed(ERROR_NO_DATA) => {
                        // A client came and went before the call: reset and listen again.
                        self.reset();
                    }
                    Outcome::TimedOut => {
                        self.reset();
                        return Err(PipeError::Timeout);
                    }
                    Outcome::Cancelled => {
                        self.reset();
                        return Err(PipeError::Cancelled);
                    }
                    Outcome::Failed(code) => {
                        self.reset();
                        return Err(PipeError::Os {
                            what: "accept a client",
                            code,
                        });
                    }
                }
            }
            self.connected = true;
            self.io.read_deadline = None;
            Ok(())
        }

        /// Puts the instance back into the disconnected state; a client still attached is cut.
        fn reset(&mut self) {
            // SAFETY: the handle is the server end of an open pipe; disconnecting a pipe that is
            // not connected fails harmlessly.
            unsafe { DisconnectNamedPipe(self.io.pipe.raw()) };
        }

        /// Lets the current client go: waits up to two seconds for it to close its end (so it can
        /// read what was written last; bytes it still sends are discarded), then disconnects. The
        /// instance stays, ready for the next [`PipeServer::accept`]. The outbound-only elevation
        /// pipe cannot see the client close; drop that server instead, which keeps written bytes
        /// readable for the client.
        pub fn disconnect(&mut self) {
            if !self.connected {
                return;
            }
            self.connected = false;
            if !self.outbound {
                let saved = self.io.read_deadline;
                self.io.set_read_deadline(Some(LINGER));
                let mut scratch = [0u8; 4096];
                let mut drained = 0usize;
                while drained < LINGER_BYTES {
                    match self.io.read(&mut scratch) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => drained += n,
                    }
                }
                self.io.read_deadline = saved;
            }
            self.reset();
        }

        /// Bounds every later write: one that cannot hand its bytes over within `timeout` fails
        /// with `TimedOut`. `None` lifts the bound. The default is [`SERVER_WRITE_TIMEOUT`].
        pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
            self.io.write_timeout = timeout;
        }

        /// The owner and the DACL of the pipe, read back from its handle.
        pub fn descriptor(&self) -> Result<Descriptor, PipeError> {
            handle_descriptor(self.io.pipe.raw(), SE_KERNEL_OBJECT).map_err(read_back)
        }

        fn connected(&self) -> io::Result<()> {
            if self.connected {
                Ok(())
            } else {
                Err(io::Error::from(io::ErrorKind::NotConnected))
            }
        }
    }

    impl Read for PipeServer {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.connected()?;
            self.io.read(buf)
        }
    }

    impl Write for PipeServer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.connected()?;
            self.io.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Duplex for PipeServer {
        fn set_read_deadline(&mut self, deadline: Option<Duration>) -> io::Result<()> {
            self.io.set_read_deadline(deadline);
            Ok(())
        }
    }

    /// The client end, connected to a pipe whose owner was checked.
    pub struct PipeClient {
        io: Io,
    }

    impl PipeClient {
        /// Opens `\\.\pipe\<name>`, waiting up to `timeout` while it is busy or not there yet,
        /// and keeps it only when its owner is exactly `expected`. For
        /// [`ExpectedOwner::Administrators`] the pipe is opened for reading only.
        pub fn connect(
            name: &str,
            expected: ExpectedOwner,
            timeout: Duration,
        ) -> Result<PipeClient, PipeError> {
            let path = wide(&pipe_path(name)?);
            let access = if expected.read_only() {
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
            } else {
                FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
            };
            let end = Instant::now() + timeout;
            let handle = loop {
                // SAFETY: `path` is a NUL-terminated `u16` buffer that outlives the call; no
                // security attributes, no template. `SECURITY_SQOS_PRESENT` makes the system honour
                // `SECURITY_IDENTIFICATION`: the server may identify this caller, never act as it.
                let handle = unsafe {
                    CreateFileW(
                        path.as_ptr(),
                        access,
                        0,
                        null(),
                        OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                        null_mut(),
                    )
                };
                if handle != INVALID_HANDLE_VALUE {
                    break HandleGuard(handle);
                }
                let code = last_error();
                let left = end.saturating_duration_since(Instant::now());
                match code {
                    ERROR_PIPE_BUSY => {
                        if left.is_zero() {
                            return Err(PipeError::Busy);
                        }
                        // SAFETY: `path` is a NUL-terminated `u16` buffer; the wait is bounded by
                        // the time left (at least one millisecond, as zero means a default wait).
                        unsafe { WaitNamedPipeW(path.as_ptr(), millis(Some(left)).max(1)) };
                    }
                    ERROR_FILE_NOT_FOUND => {
                        if left.is_zero() {
                            return Err(PipeError::NotFound);
                        }
                        std::thread::sleep(left.min(RETRY));
                    }
                    code => {
                        return Err(PipeError::Os {
                            what: "open the pipe",
                            code,
                        });
                    }
                }
            };
            // The handle is closed (dropped) on every refusal below, before anything is sent.
            match handle_owner(handle.0, SE_KERNEL_OBJECT) {
                Ok(owner) if owner == expected.sid() => {}
                _ => return Err(PipeError::Untrusted),
            }
            let event = Event::new().map_err(|_| PipeError::Os {
                what: "create an event",
                code: last_error(),
            })?;
            Ok(PipeClient {
                io: Io {
                    pipe: Pipe(handle),
                    event,
                    cancel: None,
                    read_deadline: None,
                    write_timeout: None,
                },
            })
        }

        /// Bounds every later write: one that cannot hand its bytes over within `timeout` fails
        /// with `TimedOut`. `None` (the default) lifts the bound.
        pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
            self.io.write_timeout = timeout;
        }
    }

    impl Read for PipeClient {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.io.read(buf)
        }
    }

    impl Write for PipeClient {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.io.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Duplex for PipeClient {
        fn set_read_deadline(&mut self, deadline: Option<Duration>) -> io::Result<()> {
            self.io.set_read_deadline(deadline);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_peer_mask_is_exactly_the_listed_rights_and_nothing_that_creates_or_rewrites() {
        assert_eq!(PEER_MASK, 0x0012_008b);
        // FILE_CREATE_PIPE_INSTANCE, WRITE_DAC, WRITE_OWNER, DELETE, write EA and attributes.
        for bit in [
            FILE_CREATE_PIPE_INSTANCE,
            0x0004_0000,
            0x0008_0000,
            0x0001_0000,
            0x10,
            0x100,
        ] {
            assert_eq!(PEER_MASK & bit, 0, "bit {bit:#x}");
        }
    }

    #[test]
    fn each_shape_names_its_owner_explicitly() {
        assert_eq!(
            sddl(&PipeAccess::Service).unwrap(),
            "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12008b;;;BU)"
        );
        assert_eq!(
            sddl(&PipeAccess::Elevation {
                sid: "S-1-5-21-1-2-3-1001".into()
            })
            .unwrap(),
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12008b;;;S-1-5-21-1-2-3-1001)"
        );
    }

    #[test]
    fn only_a_numeric_sid_reaches_the_descriptor_text() {
        for bad in [
            "",
            "BU",
            "WD",
            "S-1-",
            "S-1-5-",
            "S-1-5--1",
            "S-1-5-18)(A;;FA;;;WD",
            "S-1-5-x",
            "s-1-5-18",
            "S-2-5-18",
            "S-1-5-1234567890123456",
        ] {
            assert_eq!(
                sddl(&PipeAccess::Elevation { sid: bad.into() }),
                Err(PipeError::InvalidSid),
                "{bad:?}"
            );
        }
        assert!(valid_sid("S-1-5-18"));
        assert!(valid_sid("S-1-5-21-3623811015-3361044348-30300820-1013"));
    }

    #[test]
    fn a_pipe_name_is_a_plain_word() {
        assert_eq!(
            pipe_path("lunepack-a.b_c").unwrap(),
            r"\\.\pipe\lunepack-a.b_c"
        );
        for bad in [
            "",
            "a\\b",
            "a/b",
            "..\\x",
            "a b",
            "a\0",
            "ä",
            &"x".repeat(MAX_NAME + 1),
        ] {
            assert_eq!(pipe_path(bad), Err(PipeError::InvalidName), "{bad:?}");
        }
    }

    #[test]
    fn the_client_reads_only_from_the_elevation_pipe() {
        assert!(ExpectedOwner::Administrators.read_only());
        assert!(!ExpectedOwner::LocalSystem.read_only());
        assert_eq!(ExpectedOwner::LocalSystem.sid(), "S-1-5-18");
        assert_eq!(ExpectedOwner::Administrators.sid(), "S-1-5-32-544");
    }

    #[cfg(windows)]
    mod real {
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::time::{Duration, Instant};

        use lunepack_core::ServiceError;
        use lunepack_core::service::{Duplex, Frame, KIND_MESSAGE, read_frame, write_frame};

        use super::super::{ExpectedOwner, PipeAccess, PipeClient, PipeError, PipeServer};
        use crate::security::current_user_sid;

        fn unique() -> String {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            format!(
                "lunepack-test-{}-{}-{nanos}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )
        }

        fn me() -> String {
            current_user_sid().expect("the current user's SID")
        }

        fn test_server(name: &str) -> PipeServer {
            PipeServer::create(name, &PipeAccess::TestOwned { sid: me() }).expect("create")
        }

        fn test_client(name: &str) -> PipeClient {
            PipeClient::connect(name, ExpectedOwner::TestOwner(me()), Duration::from_secs(5))
                .expect("connect")
        }

        /// Accepts on another thread: after a disconnect or a timed-out accept the instance is
        /// listening again only once `accept` runs (a client meanwhile sees it busy).
        fn accept_on_a_thread(
            mut server: PipeServer,
        ) -> std::thread::JoinHandle<(Result<(), PipeError>, PipeServer)> {
            std::thread::spawn(move || (server.accept(Some(Duration::from_secs(10))), server))
        }

        /// A connected pair over a fresh test-owned pipe: the client connects to the listening
        /// instance, then the server's accept sees it.
        fn pair() -> (PipeServer, PipeClient) {
            let name = unique();
            let mut server = test_server(&name);
            let client = test_client(&name);
            server.accept(Some(Duration::from_secs(5))).expect("accept");
            (server, client)
        }

        #[test]
        fn the_service_channel_suite_passes_over_a_real_pipe_both_ways() {
            lunepack_testkit::run_service_channel_suite(&|| {
                let (server, client) = pair();
                (Box::new(client), Box::new(server))
            });
            lunepack_testkit::run_service_channel_suite(&|| {
                let (server, client) = pair();
                (Box::new(server), Box::new(client))
            });
        }

        #[test]
        fn a_second_server_on_the_same_name_fails() {
            let name = unique();
            let mut first = test_server(&name);
            assert_eq!(
                PipeServer::create(&name, &PipeAccess::TestOwned { sid: me() }).err(),
                Some(PipeError::Exists)
            );
            // Also while a client is attached and after it left: the one instance is reused,
            // the name is never free.
            let client = test_client(&name);
            first.accept(Some(Duration::from_secs(5))).expect("accept");
            assert_eq!(
                PipeServer::create(&name, &PipeAccess::TestOwned { sid: me() }).err(),
                Some(PipeError::Exists)
            );
            drop(client);
            first.disconnect();
            assert_eq!(
                PipeServer::create(&name, &PipeAccess::TestOwned { sid: me() }).err(),
                Some(PipeError::Exists)
            );
            let listener = accept_on_a_thread(first);
            let mut again = test_client(&name);
            let (accepted, mut first) = listener.join().expect("listener");
            accepted.expect("accept again");
            again.write_all(b"x").expect("write");
            let mut byte = [0u8; 1];
            first
                .set_read_deadline(Some(Duration::from_secs(5)))
                .unwrap();
            first.read_exact(&mut byte).expect("read");
            assert_eq!(&byte, b"x");
        }

        #[test]
        fn a_client_expecting_local_system_refuses_a_pipe_anyone_else_owns() {
            // The squatting case: this (non-system) process made the pipe. The server listens
            // first, so the refused client's connection is seen before it closes.
            let name = unique();
            let mut server = test_server(&name);
            let listener = std::thread::spawn(move || {
                let accepted = server.accept(Some(Duration::from_secs(10)));
                (accepted, server)
            });
            std::thread::sleep(Duration::from_millis(200));
            assert_eq!(
                PipeClient::connect(&name, ExpectedOwner::LocalSystem, Duration::from_secs(5))
                    .err(),
                Some(PipeError::Untrusted)
            );
            let (accepted, mut server) = listener.join().expect("listener");
            accepted.expect("the refused client's connection");
            server
                .set_read_deadline(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buf = [0u8; 16];
            assert_eq!(server.read(&mut buf).expect("read"), 0, "nothing was sent");
            server.disconnect();
            // The same pipe with the expectation set to its real owner connects.
            let listener = accept_on_a_thread(server);
            let mut client = test_client(&name);
            let (accepted, mut server) = listener.join().expect("listener");
            accepted.expect("accept");
            client.write_all(b"ok").expect("write");
            server.read_exact(&mut buf[..2]).expect("read");
            assert_eq!(&buf[..2], b"ok");
        }

        #[test]
        fn a_client_that_stops_sending_is_cut_at_the_deadline() {
            let (mut server, mut client) = pair();
            server
                .set_read_deadline(Some(Duration::from_millis(200)))
                .unwrap();
            let started = Instant::now();
            assert_eq!(read_frame(&mut server), Err(ServiceError::Timeout));
            let took = started.elapsed();
            assert!(
                took >= Duration::from_millis(150) && took < Duration::from_secs(5),
                "{took:?}"
            );
            // The handle is still usable: the server lets the client go, the client sees the end.
            server.disconnect();
            client
                .set_read_deadline(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buf = [0u8; 1];
            assert_eq!(client.read(&mut buf).expect("read"), 0);
            assert_eq!(
                client.write(b"x").map_err(|e| e.kind()),
                Err(std::io::ErrorKind::BrokenPipe)
            );
        }

        #[test]
        fn a_frame_written_before_the_server_lets_go_still_reaches_the_client() {
            let (mut server, mut client) = pair();
            write_frame(&mut server, KIND_MESSAGE, b"{}").expect("write");
            let reader = std::thread::spawn(move || {
                client
                    .set_read_deadline(Some(Duration::from_secs(5)))
                    .unwrap();
                let frame = read_frame(&mut client);
                drop(client);
                frame
            });
            server.disconnect();
            assert_eq!(
                reader.join().expect("reader"),
                Ok(Some(Frame::Message(b"{}".to_vec())))
            );
        }

        #[test]
        fn a_blocked_accept_is_cancelled_for_shutdown() {
            let name = unique();
            let mut server = test_server(&name);
            let cancel = server.canceller();
            let waiter = std::thread::spawn(move || {
                let started = Instant::now();
                let result = server.accept(None);
                (result, started.elapsed(), server)
            });
            std::thread::sleep(Duration::from_millis(200));
            cancel.cancel();
            let (result, took, mut server) = waiter.join().expect("waiter");
            assert_eq!(result, Err(PipeError::Cancelled));
            assert!(took < Duration::from_secs(5), "{took:?}");
            // Cancelled for good.
            assert_eq!(
                server.accept(Some(Duration::from_secs(1))),
                Err(PipeError::Cancelled)
            );
        }

        #[test]
        fn a_blocked_read_is_cancelled_for_shutdown() {
            let (mut server, _client) = pair();
            let cancel = server.canceller();
            let reader = std::thread::spawn(move || {
                let mut buf = [0u8; 4];
                server.read(&mut buf).map_err(|e| e.kind())
            });
            std::thread::sleep(Duration::from_millis(200));
            cancel.cancel();
            assert_eq!(
                reader.join().expect("reader"),
                Err(std::io::ErrorKind::ConnectionAborted)
            );
        }

        #[test]
        fn an_accept_that_times_out_leaves_the_instance_ready() {
            let name = unique();
            let mut server = test_server(&name);
            let started = Instant::now();
            assert_eq!(
                server.accept(Some(Duration::from_millis(200))),
                Err(PipeError::Timeout)
            );
            assert!(started.elapsed() < Duration::from_secs(5));
            let listener = accept_on_a_thread(server);
            let mut client = test_client(&name);
            let (accepted, mut server) = listener.join().expect("listener");
            accepted.expect("accept");
            client.write_all(b"y").expect("write");
            let mut byte = [0u8; 1];
            server
                .set_read_deadline(Some(Duration::from_secs(5)))
                .unwrap();
            server.read_exact(&mut byte).expect("read");
            assert_eq!(&byte, b"y");
        }

        #[test]
        fn a_second_client_gets_busy_while_the_instance_is_taken() {
            let name = unique();
            let mut server = test_server(&name);
            let _first = test_client(&name);
            server.accept(Some(Duration::from_secs(5))).expect("accept");
            let started = Instant::now();
            assert_eq!(
                PipeClient::connect(
                    &name,
                    ExpectedOwner::TestOwner(me()),
                    Duration::from_millis(300)
                )
                .err(),
                Some(PipeError::Busy)
            );
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        #[test]
        fn a_vanished_server_is_the_end_of_the_channel_never_a_hang() {
            let (server, mut client) = pair();
            drop(server);
            client
                .set_read_deadline(Some(Duration::from_secs(5)))
                .unwrap();
            assert_eq!(read_frame(&mut client), Ok(None));
            assert_eq!(
                client.write(b"x").map_err(|e| e.kind()),
                Err(std::io::ErrorKind::BrokenPipe)
            );
            assert_eq!(
                PipeClient::connect(
                    &unique(),
                    ExpectedOwner::LocalSystem,
                    Duration::from_millis(100)
                )
                .err(),
                Some(PipeError::NotFound)
            );
        }
    }
}
