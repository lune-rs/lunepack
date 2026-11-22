//! The Linux and macOS host (M11-D3, M11-D4): builds the engine's ports from the adapters, opens
//! the engine of the install the binary lives in, takes the listening socket the init system
//! passed and serves one connection at a time until nobody has come for [`crate::session::IDLE_EXIT`]. It mirrors
//! the Windows host (`host.rs`): the same structure, the same exit codes, the same log.
//!
//! The process is a socket-activated daemon of systemd (`Accept=no`, the listener is descriptor 3)
//! or launchd (`launch_activate_socket`): the init system owns the socket, so the service may exit
//! when idle and be started again by the next client. Started by anything else it finds no socket
//! and ends with exit 2, having done nothing else.
//!
//! Nothing here starts a process (the registrar's self-test is the engine's), reads the
//! environment or follows a path a caller gave: the root comes from the image's own path, the
//! machine home is a constant resolved the way the kernel names image paths, and the update bytes
//! arrive over the socket and are written by the engine into admin-only storage under `R`. No
//! decision is taken from who the peer is (M11-D5): any local user may talk to the service, as on
//! Windows.
//!
//! Signals: `SIGTERM` has its default action, the process ends. That is safe: the engine's lock is
//! an operating-system lock released with the process, and every engine operation is crash-safe
//! (the machine record commits last and `open` finishes what a cut-off operation left).

use std::io::{self, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::engine::{Engine, Ports, serve};
use lunepack_core::{AppId, Clock, MachineScheme, ServerSession};
use lunepack_crypto::{Ed25519Verifier, OsRng, Sha256Hasher};
use lunepack_fs::StdFs;

#[cfg(target_os = "linux")]
use lunepack_os_linux as os;
#[cfg(target_os = "macos")]
use lunepack_os_macos as os;

use crate::args::Mode;
use crate::exit;
use crate::location::{self, Located};
use crate::logfile::Log;
use crate::session::{CONNECTION_LIMIT, Capped, engine_code, idle_exit};

/// How long one accept waits before the loop looks at the idle clock.
pub const ACCEPT_SLICE: Duration = Duration::from_secs(1);
/// How often a waiting accept looks again (the listener is non-blocking).
const ACCEPT_POLL: Duration = Duration::from_millis(20);

/// The scheme of this OS's machine installs.
#[cfg(target_os = "linux")]
pub const SCHEME: MachineScheme = MachineScheme::LINUX;
/// The scheme of this OS's machine installs.
#[cfg(target_os = "macos")]
pub const SCHEME: MachineScheme = MachineScheme::MACOS;

/// The wall clock, for the log's time stamps and the engine's document expiry.
#[derive(Debug, Clone, Copy)]
struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        now_secs()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Every adapter the engine's ports name.
#[cfg(target_os = "linux")]
struct Adapters {
    fs: StdFs,
    codec: LzmaCodec,
    hasher: Sha256Hasher,
    verifier: Ed25519Verifier,
    clock: SystemClock,
    rng: OsRng,
    integration: os::MachineIntegration,
    publisher: os::NoPublisherCheck,
    protect: os::LinuxProtect,
    policy: os::FilePolicy,
    registrar: os::SystemdRegistrar,
    process: os::LinuxProcess,
}

/// Every adapter the engine's ports name.
#[cfg(target_os = "macos")]
struct Adapters {
    fs: StdFs,
    codec: LzmaCodec,
    hasher: Sha256Hasher,
    verifier: Ed25519Verifier,
    clock: SystemClock,
    rng: OsRng,
    integration: os::MacMachineIntegration,
    publisher: os::MacPublisherCheck,
    protect: os::MacProtect,
    policy: os::FilePolicy,
    registrar: os::LaunchdRegistrar,
    process: os::MacProcess,
}

impl Adapters {
    #[cfg(target_os = "linux")]
    fn new() -> Adapters {
        Adapters {
            fs: StdFs::new(),
            codec: LzmaCodec,
            hasher: Sha256Hasher,
            verifier: Ed25519Verifier,
            clock: SystemClock,
            rng: OsRng,
            integration: os::MachineIntegration::new(),
            publisher: os::NoPublisherCheck,
            protect: os::LinuxProtect::new(),
            policy: os::FilePolicy::new(),
            registrar: os::SystemdRegistrar::new(),
            process: os::LinuxProcess::new(),
        }
    }

    // The bundle identifier of the signed install metadata is not known to the service: a
    // re-registration it runs (the engine's undo of a refused switch) writes the plist without
    // `AssociatedBundleIdentifiers`.
    #[cfg(target_os = "macos")]
    fn new() -> Adapters {
        Adapters {
            fs: StdFs::new(),
            codec: LzmaCodec,
            hasher: Sha256Hasher,
            verifier: Ed25519Verifier,
            clock: SystemClock,
            rng: OsRng,
            integration: os::MacMachineIntegration::new(),
            publisher: os::MacPublisherCheck,
            protect: os::MacProtect::new(),
            policy: os::FilePolicy::new(),
            registrar: os::LaunchdRegistrar::new(None),
            process: os::MacProcess::new(),
        }
    }

    fn ports(&self) -> Ports<'_> {
        Ports {
            fs: &self.fs,
            codec: &self.codec,
            hasher: &self.hasher,
            verifier: &self.verifier,
            clock: &self.clock,
            rng: &self.rng,
            integration: &self.integration,
            publisher: &self.publisher,
            protect: &self.protect,
            policy: &self.policy,
            registrar: &self.registrar,
            process: &self.process,
            scheme: SCHEME,
        }
    }
}

/// The binary's own path as the kernel reports it: the `/proc/self/exe` link on Linux,
/// `proc_pidpath` on macOS. Both name the file the process runs, with every link of the stable
/// service link resolved, so the init system's start through `R/.lunepack/machine/lunepack-service`
/// shows the `service/<version>` image.
#[cfg(target_os = "linux")]
fn own_image() -> io::Result<PathBuf> {
    std::fs::read_link("/proc/self/exe")
}

/// The binary's own path as the kernel reports it (see the Linux variant).
#[cfg(target_os = "macos")]
fn own_image() -> io::Result<PathBuf> {
    os::libproc::exe_path(std::process::id())?
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
}

/// The machine home of this OS (`/opt`, `/Library/Application Support/lunepack`) in the form
/// [`own_image`] reports paths in: on Linux the resolved path (a link `/opt` names its target, as
/// `/proc/self/exe` does); on macOS the kernel's own name for it (`F_GETPATH`, the source
/// `proc_pidpath` reports from, exact for case and Unicode normalisation, as the in-use scan
/// compares), never a `canonicalize`. The constant is never taken from the environment; one that
/// does not exist or cannot be read is an error.
pub fn machine_home() -> io::Result<PathBuf> {
    let constant = SCHEME
        .home
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    resolve_home(Path::new(constant))
}

/// [`machine_home`] of an arbitrary constant (tests use a scratch folder).
#[cfg(target_os = "linux")]
pub fn resolve_home(constant: &Path) -> io::Result<PathBuf> {
    std::fs::canonicalize(constant)
}

/// [`machine_home`] of an arbitrary constant (tests use a scratch folder).
#[cfg(target_os = "macos")]
pub fn resolve_home(constant: &Path) -> io::Result<PathBuf> {
    os::libproc::kernel_path(constant)
}

/// Runs the process as `mode` and returns its exit code.
pub fn run(mode: Mode) -> u8 {
    // The location rule comes before everything else: a copy of the binary anywhere else does
    // nothing at all, not even log.
    let Ok(image) = own_image() else {
        return exit::LOCATION;
    };
    let Ok(home) = machine_home() else {
        return exit::LOCATION;
    };
    run_at(mode, &image, &home, &mut io::stderr())
}

/// [`run`] for an image and machine home already found (tests give their own); one line goes to
/// `err` when the process was not started by the init system for its socket.
pub fn run_at(mode: Mode, image: &Path, home: &Path, err: &mut dyn Write) -> u8 {
    let Ok(located) = location::locate_unix(image, home, SCHEME) else {
        return exit::LOCATION;
    };
    match mode {
        Mode::SelfTest => self_test(&located),
        Mode::Service => service(located, err),
    }
}

/// What the engine's `open` verifies before it would change anything (`Engine::check`: the tree's
/// protection and the machine record), without the engine's lock: the registrar starts this check
/// from inside the engine that is switching the service, which holds that lock.
fn self_test(located: &Located) -> u8 {
    let adapters = Adapters::new();
    match Engine::check(&adapters.ports(), located.layout.root()) {
        Ok(()) => exit::OK,
        Err(_) => exit::ENGINE,
    }
}

/// The listener the init system passed for `app`'s socket.
#[cfg(target_os = "linux")]
fn activate(app: &AppId) -> Result<os::ActivatedListener, ()> {
    let expected = lunepack_core::endpoint::socket_path(lunepack_core::UnixOs::Linux, app);
    os::ActivatedListener::from_systemd(&expected).map_err(drop)
}

/// The listener the init system passed for `app`'s socket.
#[cfg(target_os = "macos")]
fn activate(_app: &AppId) -> Result<os::ActivatedListener, ()> {
    os::ActivatedListener::from_launchd(lunepack_core::endpoint::LAUNCHD_SOCKET_NAME).map_err(drop)
}

fn service(located: Located, err: &mut dyn Write) -> u8 {
    // The install root is named by its app id: the socket to take is that app's.
    let Some(app) = location::root_app_id(&located.layout) else {
        return exit::LOCATION;
    };
    // The socket comes before anything is written or locked: started by anything but the init
    // system for this socket, the process says so once and does nothing else.
    let Ok(listener) = activate(&app) else {
        let _ = writeln!(err, "lunepack-service: not started by the init system");
        return exit::USAGE;
    };
    serve_all(listener.listener(), &located, &app)
}

/// The service body: opens the engine, then serves `listener` until it has been idle for
/// [`crate::session::IDLE_EXIT`]. The exit code of the process.
fn serve_all(listener: &UnixListener, located: &Located, app: &AppId) -> u8 {
    let log = Log::new(location::log_path(&located.layout), now_secs);
    log.info("the service starts");
    let adapters = Adapters::new();
    let mut engine = match Engine::open(adapters.ports(), located.layout.root()) {
        Ok(engine) => engine.with_service_version(located.version.clone()),
        Err(e) => {
            log.error("the engine did not open", engine_code(&e));
            return exit::ENGINE;
        }
    };
    // The record belongs to the app the root is named for: a service must not serve one app's
    // socket from another app's engine.
    if engine.app_id() != app {
        log.error("the record is not this app's", 0);
        return exit::ENGINE;
    }
    if listener.set_nonblocking(true).is_err() {
        log.error("the socket could not be set up", 0);
        return exit::FAILED;
    }
    let started = Instant::now();
    let monotonic = move || started.elapsed();
    let mut idle_since = Instant::now();
    loop {
        match accept_within(listener, ACCEPT_SLICE) {
            Ok(Some(stream)) => {
                let served = catch_unwind(AssertUnwindSafe(|| {
                    connection(stream, &mut engine, app, &monotonic, &log);
                }));
                if served.is_err() {
                    // The engine's lock is an operating-system lock, released as the panic
                    // unwound; the process ends rather than serve on from an unknown state.
                    log.error("a connection panicked", 0);
                    return exit::FAILED;
                }
                idle_since = Instant::now();
            }
            Ok(None) => {
                if idle_exit(idle_since.elapsed(), engine.lease_running(monotonic())) {
                    log.info("the service is idle and stops");
                    return exit::OK;
                }
            }
            Err(_) => {
                log.error("the socket failed", 0);
                return exit::FAILED;
            }
        }
    }
}

/// The next client of the non-blocking `listener`, or `None` after `slice` without one. The
/// stream it returns is blocking: a socket accepted from a non-blocking listener may inherit the
/// flag (the BSDs do).
pub fn accept_within(listener: &UnixListener, slice: Duration) -> io::Result<Option<UnixStream>> {
    let end = Instant::now() + slice;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                return Ok(Some(stream));
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionAborted
                ) =>
            {
                if Instant::now() >= end {
                    return Ok(None);
                }
                std::thread::sleep(ACCEPT_POLL);
            }
            Err(e) => return Err(e),
        }
    }
}

/// One client: the hello, then requests until it leaves, is cut or the protocol ends the session.
/// The stream is closed when the session ends, so the next client (waiting in the socket's queue,
/// M11-D15) is served at once.
fn connection(
    stream: UnixStream,
    engine: &mut Engine<'_>,
    app: &AppId,
    monotonic: &dyn Fn() -> Duration,
    log: &Log,
) {
    let io = Capped::new(os::UnixDuplex::new(stream), CONNECTION_LIMIT);
    match ServerSession::accept(io, app.clone()) {
        Ok(session) => {
            if serve(session, engine, monotonic).is_err() {
                log.info("a connection ended with an error");
            }
        }
        Err(_) => log.info("a client's hello was refused"),
    }
}
