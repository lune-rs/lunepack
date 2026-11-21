//! The Windows host (M10-D7): builds the engine's ports from the adapters, opens the engine of the
//! install the binary lives in, creates the service's pipe and serves one connection at a time
//! until the control manager stops the service or nobody has come for [`IDLE_EXIT`].
//!
//! Nothing here starts a process (the registrar's self-test is the engine's), loads a library by a
//! relative name or impersonates a caller: the update bytes arrive over the pipe and are written by
//! the engine into admin-only storage under `R`.

use std::io::{self, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::engine::{Engine, EngineError, Ports, serve};
use lunepack_core::service::ErrorCode;
use lunepack_core::{AppId, Clock, Duplex, ServerSession};
use lunepack_crypto::{Ed25519Verifier, OsRng, Sha256Hasher};
use lunepack_fs::StdFs;
use lunepack_os_windows::{
    PipeAccess, PipeError, PipeServer, RegistryPolicy, ServiceControl, WinPublisherCheck, WinScope,
    WindowsIntegration, WindowsProcess, WindowsProtect, WindowsRegistrar, pipe_name, program_files,
    run_service,
};

use crate::args::Mode;
use crate::exit;
use crate::location::{self, Located};
use crate::logfile::Log;
use crate::session::{CONNECTION_LIMIT, Capped, idle_exit, self_test_passes};

/// The name handed to the control manager's dispatcher. The service is registered as an own-process
/// service, for which the manager ignores the name; the app's own name is read from the machine
/// record only after the service has reported running.
const DISPATCH_NAME: &str = "lunepack-service";
/// How long one `accept` waits before the loop looks at the stop flag and the idle clock.
const ACCEPT_SLICE: Duration = Duration::from_secs(1);

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
struct Adapters {
    fs: StdFs,
    codec: LzmaCodec,
    hasher: Sha256Hasher,
    verifier: Ed25519Verifier,
    clock: SystemClock,
    rng: OsRng,
    integration: WindowsIntegration,
    publisher: WinPublisherCheck,
    protect: WindowsProtect,
    policy: RegistryPolicy,
    registrar: WindowsRegistrar,
    process: WindowsProcess,
}

impl Adapters {
    /// `app_name` is what the registrar shows as the service's display name (`<name> Update
    /// Service`): the install folder's name, which is the app's display name.
    fn new(app_name: &str) -> Option<Adapters> {
        Some(Adapters {
            fs: StdFs::new(),
            codec: LzmaCodec,
            hasher: Sha256Hasher,
            verifier: Ed25519Verifier,
            clock: SystemClock,
            rng: OsRng,
            // The per-user scope is never used here (the engine has no user): the real
            // current-user layout only completes the pair.
            integration: WindowsIntegration::current_user().with_machine(WinScope::machine())?,
            publisher: WinPublisherCheck,
            protect: WindowsProtect,
            policy: RegistryPolicy::new(),
            registrar: WindowsRegistrar::new(app_name),
            process: WindowsProcess::new(),
        })
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
        }
    }
}

/// Runs the process as `mode` and returns its exit code.
pub fn run(mode: Mode) -> u8 {
    // The location rule comes before everything else: a copy of the binary anywhere else does
    // nothing at all, not even log.
    let Ok(image) = std::env::current_exe() else {
        return exit::LOCATION;
    };
    let Ok(program_files) = program_files() else {
        return exit::LOCATION;
    };
    let Ok(located) = location::locate(&image, &program_files) else {
        return exit::LOCATION;
    };
    match mode {
        Mode::SelfTest => self_test(&located),
        Mode::Service => service(located),
    }
}

/// Everything up to and including opening the engine, then done.
fn self_test(located: &Located) -> u8 {
    let name = location::display_name(&located.layout).unwrap_or_default();
    let Some(adapters) = Adapters::new(&name) else {
        return exit::FAILED;
    };
    let opened = Engine::open(adapters.ports(), located.layout.root()).map(drop);
    if self_test_passes(&opened) {
        exit::OK
    } else {
        exit::ENGINE
    }
}

fn service(located: Located) -> u8 {
    let log = Log::new(location::log_path(&located.layout), now_secs);
    match run_service(DISPATCH_NAME, move |control| {
        serve_all(&control, &located, &log)
    }) {
        Ok(()) => exit::OK,
        Err(_) => {
            // Started from a console (or a second dispatcher): nothing ran.
            eprintln!("lunepack-service: not started by the service control manager");
            exit::USAGE
        }
    }
}

/// The index of `code` in the protocol's closed set, for the log.
fn code_number(code: ErrorCode) -> u32 {
    ErrorCode::ALL
        .iter()
        .position(|c| *c == code)
        .map_or(0, |i| u32::try_from(i).unwrap_or(0))
}

fn engine_code(e: &EngineError) -> u32 {
    code_number(e.code)
}

fn pipe_code(e: &PipeError) -> u32 {
    match e {
        PipeError::Os { code, .. } => *code,
        PipeError::InvalidName => 1,
        PipeError::InvalidSid => 2,
        PipeError::Exists => 3,
        PipeError::OwnerNotAssignable => 4,
        PipeError::Busy => 5,
        PipeError::NotFound => 6,
        PipeError::Untrusted => 7,
        PipeError::Timeout => 8,
        PipeError::Cancelled => 9,
        _ => 0,
    }
}

/// The service body: runs on the dispatcher's thread after it reported running, returns the exit
/// code reported with the stop.
fn serve_all(control: &ServiceControl, located: &Located, log: &Log) -> u32 {
    log.info("the service starts");
    let name = location::display_name(&located.layout).unwrap_or_default();
    let Some(adapters) = Adapters::new(&name) else {
        log.error("the adapters could not be made", 0);
        return u32::from(exit::FAILED);
    };
    let mut engine = match Engine::open(adapters.ports(), located.layout.root()) {
        Ok(engine) => engine.with_service_version(located.version.clone()),
        Err(e) => {
            log.error("the engine did not open", engine_code(&e));
            return u32::from(exit::ENGINE);
        }
    };
    let app = engine.app_id().clone();
    let mut server = match PipeServer::create(&pipe_name(&app), &PipeAccess::Service) {
        Ok(server) => server,
        Err(e) => {
            log.error("the pipe could not be made", pipe_code(&e));
            return u32::from(exit::FAILED);
        }
    };
    let canceller = server.canceller();
    control.on_stop(move || canceller.cancel());
    let started = Instant::now();
    let monotonic = move || started.elapsed();
    let mut idle_since = Instant::now();
    while !control.stop_requested() {
        match server.accept(Some(ACCEPT_SLICE)) {
            Ok(()) => {
                let served = catch_unwind(AssertUnwindSafe(|| {
                    connection(&mut server, &mut engine, &app, &monotonic, log);
                }));
                // The next client must find the pipe listening at once, or it is told `busy`.
                server.disconnect();
                if served.is_err() {
                    // The engine's lock is an operating-system lock, released as the panic
                    // unwound; the process ends rather than serve on from an unknown state.
                    log.error("a connection panicked", 0);
                    return u32::from(exit::FAILED);
                }
                idle_since = Instant::now();
            }
            Err(PipeError::Timeout) => {
                if idle_exit(idle_since.elapsed(), engine.lease_running(monotonic())) {
                    log.info("the service is idle and stops");
                    return u32::from(exit::OK);
                }
            }
            Err(PipeError::Cancelled) => break,
            Err(e) => {
                log.error("the pipe failed", pipe_code(&e));
                return u32::from(exit::FAILED);
            }
        }
    }
    log.info("the service stops");
    u32::from(exit::OK)
}

/// A server lent to a session, so the session's end does not take the pipe with it.
struct Lend<'a>(&'a mut PipeServer);

impl Read for Lend<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Lend<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Duplex for Lend<'_> {
    fn set_read_deadline(&mut self, deadline: Option<Duration>) -> io::Result<()> {
        self.0.set_read_deadline(deadline)
    }
}

/// One client: the hello, then requests until it leaves, is cut or the protocol ends the session.
fn connection(
    server: &mut PipeServer,
    engine: &mut Engine<'_>,
    app: &AppId,
    monotonic: &dyn Fn() -> Duration,
    log: &Log,
) {
    let io = Capped::new(Lend(server), CONNECTION_LIMIT);
    match ServerSession::accept(io, app.clone()) {
        Ok(session) => {
            if serve(session, engine, monotonic).is_err() {
                log.info("a connection ended with an error");
            }
        }
        Err(_) => log.info("a client's hello was refused"),
    }
}
