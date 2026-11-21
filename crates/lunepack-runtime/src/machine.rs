//! The all-users install of a Windows setup file (M10 step 16, M10-D4, M10-D14, M10-D15).
//!
//! A setup file installs for all users in one of three ways, all ending in the core's engine
//! ([`lunepack_core::engine::install`]) running with an administrator's token:
//!
//! - in this process, headless, when the process is an administrator's (`--all-users` as `Admin`
//!   or `UacElevated`): [`install_all`];
//! - in an elevated copy of the setup, the hidden `machine-install` mode ([`run_mode`]), started
//!   by the unelevated setup through the system's elevation prompt ([`hand_off`]); the copy writes
//!   its progress into an outbound pipe it owns ([`crate::relay`]) and its exit code is the result;
//! - never in a process that is not an administrator's.
//!
//! What the elevated side trusts is the setup image it runs from, nothing else: the payload is
//! copied from the image's own file into a new folder only administrators can use, directly under
//! the Program Files known folder, and verified there against the digests the image carries of its
//! own payload in a resource it reads from its mapped memory (the anchor, M10-D4). The engine then
//! builds the install from that copy. This module reads no environment variable, makes no temporary
//! directory, looks at no current directory, takes no path from a command line and opens nothing
//! under a user's profile: it has no per-user lookup of any kind (the check for an install of the
//! installing user belongs to the unelevated side, [`crate::setup`], before it elevates anything).

#![cfg_attr(not(windows), allow(dead_code))]

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use lunepack::{Phase, Progress, Version};
use lunepack_core::engine::{InstallRequest, Installed, MachineOpError, Ports, install};
use lunepack_core::limits::Limits;
use lunepack_core::setup::{
    ReadAtWindow, SetupAnchor, SetupPart, VerifiedSetup, verify_setup_anchored,
};
use lunepack_core::state::MachineStore;
use lunepack_core::{
    AppId, Clock, ClockReading, Codec, DirClass, Elevated, Elevation, Fs, FsError, FsErrorKind,
    Hasher, LayoutScheme, MachineLayout, Protect, ReadAt, Rng, RootChoice, Scope, Standing,
    Verifier, resolve_root_scoped,
};

use crate::events::{Event, Events};
use crate::modes::{Kind, MACHINE_INSTALL, MachineArgs, SetupArgs};
use crate::relay::{EventConnector, RelaySink};
use crate::setup::Found;

/// How long the elevated copy waits for the unelevated setup to open its pipe before it goes on
/// without a reader.
pub const ACCEPT_WAIT: Duration = Duration::from_secs(30);
/// The name of the folder the payload is copied into, before the 32 hex characters of its id.
pub const PAYLOAD_PREFIX: &str = ".lunepack-install-";
/// The copied pack's file name in that folder.
pub const PACK_FILE: &str = "pack";
/// The most bytes copied at once.
const COPY_CHUNK: usize = 1 << 20;

// ---- the choice ------------------------------------------------------------------------------

/// What a Windows setup run does, decided from who runs it and what it was asked
/// ([`route`]; M10-D15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// The per-user flow, with its window when one may be shown. `offer`: the welcome screen
    /// offers the all-users choice. `forced`: the choice is taken before it is made
    /// (`--all-users` without `--silent`, as a standard user).
    User { offer: bool, forced: bool },
    /// Install for all users in this process, with no window. `check_user`: look for an install
    /// of the installing user first (only an unelevated process does).
    InProcess { check_user: bool },
    /// Nothing is done: this exit.
    Refuse(Kind),
    /// `--all-users --silent` as a standard user: look for an install of the installing user
    /// (that answer, `already_installed`, comes first), then exit `elevation_required`. The
    /// elevation prompt is never shown.
    ElevationRequired,
    /// An elevated process started without `--all-users`: one fixed message box, then the usage
    /// code. The window of a setup never runs with a full token.
    Notice,
}

/// The offer rule: the welcome screen offers the all-users choice when the release carries the
/// update service and this process does not hold a full administrator token.
pub fn offered(standing: Standing, has_service: bool) -> bool {
    has_service && standing != Standing::UacElevated
}

/// The run's route (M10-D15). `has_service`: the verified manifest lists the update service
/// beside the entry.
pub fn route(standing: Standing, args: SetupArgs, has_service: bool) -> Route {
    use Standing::{Admin, Standard, UacElevated};
    match (standing, args.all_users) {
        (UacElevated, false) => Route::Notice,
        (_, false) => Route::User {
            offer: offered(standing, has_service),
            forced: false,
        },
        // The release has no service: nothing to elevate for, whoever asks.
        (_, true) if !has_service => Route::Refuse(Kind::PerMachineUnavailable),
        (UacElevated, true) => Route::InProcess { check_user: false },
        (Admin, true) => Route::InProcess { check_user: true },
        (Standard, true) if args.silent => Route::ElevationRequired,
        (Standard, true) => Route::User {
            offer: true,
            forced: true,
        },
    }
}

/// What a Windows setup run does next, with the one lookup the unelevated side makes folded in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Exit with this kind; nothing was changed.
    Exit(Kind),
    /// Show the fixed message of an elevated setup and exit with the usage code.
    Notice,
    /// Install for all users in this process.
    InProcess,
    /// The per-user flow, with its window when one may be shown ([`Route::User`]).
    Window { offer: bool, forced: bool },
}

/// [`route`], with the check for an install of the installing user ([`Route::InProcess`],
/// [`Route::ElevationRequired`]) made through `user_install_there`: it is asked only by an
/// unelevated process, before it installs or refuses, and never by one that holds a full token
/// (M10-D14: such a process opens nothing under any user's profile). An answer that is an error is
/// that exit.
pub fn decide(
    standing: Standing,
    args: SetupArgs,
    has_service: bool,
    user_install_there: &dyn Fn() -> Result<bool, Kind>,
) -> Decision {
    match route(standing, args, has_service) {
        Route::Refuse(kind) => Decision::Exit(kind),
        Route::Notice => Decision::Notice,
        Route::ElevationRequired => Decision::Exit(match user_install_there() {
            Ok(true) => Kind::AlreadyInstalled,
            Ok(false) => Kind::ElevationRequired,
            Err(kind) => kind,
        }),
        Route::InProcess { check_user } => {
            if check_user {
                match user_install_there() {
                    Ok(false) => {}
                    Ok(true) => return Decision::Exit(Kind::AlreadyInstalled),
                    Err(kind) => return Decision::Exit(kind),
                }
            }
            Decision::InProcess
        }
        Route::User { offer, forced } => Decision::Window { offer, forced },
    }
}

// ---- what is in the machine home -------------------------------------------------------------

/// An install of the app in the machine home, read the way the engine reads it (M10-D8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Machine {
    /// None.
    Absent,
    /// One, with this root and its current version (`None` before its first install completed).
    Present(PathBuf, Option<Version>),
    /// A folder of the app's name holds a record that cannot be read.
    Unreadable,
}

/// The install of `app_id` named `name` under `home` (the Program Files known folder): looked up
/// in the machine record only.
pub fn find(fs: &dyn Fs, hasher: &dyn Hasher, home: &Path, app_id: &AppId, name: &str) -> Machine {
    match resolve_root_scoped(
        fs,
        hasher,
        home,
        app_id,
        name,
        LayoutScheme::WINDOWS,
        Scope::Machine,
    ) {
        Ok(RootChoice::Existing(root)) => {
            let store = MachineStore {
                dir: MachineLayout::new(&root).state_dir(),
                app_id: app_id.clone(),
            };
            match store.load(fs, hasher) {
                Ok(loaded) => {
                    let current = loaded.record.and_then(|r| r.current).map(|c| c.version);
                    Machine::Present(root, current)
                }
                Err(_) => Machine::Unreadable,
            }
        }
        Err(lunepack_core::error::LayoutError::InstallUnreadable) => Machine::Unreadable,
        // New, or a folder that is not this app's: no install of this app.
        _ => Machine::Absent,
    }
}

/// Whether a machine install of the app is there to stop a per-user install (one visible install,
/// M10-D14): present, or present but unreadable.
pub fn blocks_user_install(machine: &Machine) -> bool {
    !matches!(machine, Machine::Absent)
}

// ---- the elevated side -----------------------------------------------------------------------

/// Where progress goes in the elevated copy: an outbound pipe the unelevated setup reads.
pub enum PipeFail {
    /// The SID is not one the system parses.
    InvalidSid,
    /// The pipe could not be made.
    Failed,
}

/// The elevated copy's pipe (a fake in tests).
pub trait EventPipes: Send + Sync {
    /// Creates the outbound pipe `id`, readable by the account `sid` only, and waits up to `wait`
    /// for that account to open it. `Ok(None)`: nobody came; the run goes on without a reader.
    fn open(
        &self,
        id: &str,
        sid: &str,
        wait: Duration,
    ) -> Result<Option<Box<dyn Write + Send>>, PipeFail>;
}

/// The parts of the engine's ports the copy and its verification use.
#[derive(Clone, Copy)]
pub struct Base<'a> {
    pub fs: &'a dyn Fs,
    pub codec: &'a dyn Codec,
    pub hasher: &'a dyn Hasher,
    pub verifier: &'a dyn Verifier,
    pub clock: &'a dyn Clock,
    pub rng: &'a dyn Rng,
    pub protect: &'a dyn Protect,
    /// The machine home: the Program Files known folder, canonical.
    pub home: &'a Path,
}

impl<'a> Base<'a> {
    /// The base of `ports` over `home`.
    pub fn of(ports: &Ports<'a>, home: &'a Path) -> Base<'a> {
        Base {
            fs: ports.fs,
            codec: ports.codec,
            hasher: ports.hasher,
            verifier: ports.verifier,
            clock: ports.clock,
            rng: ports.rng,
            protect: ports.protect,
            home,
        }
    }
}

/// The folder a payload is copied into; removed when this is dropped (the engine removes it as
/// well when it runs).
struct PayloadDir<'a> {
    fs: &'a dyn Fs,
    path: PathBuf,
}

impl Drop for PayloadDir<'_> {
    fn drop(&mut self) {
        let _ = self.fs.remove_dir_all_nofollow(&self.path);
    }
}

/// A payload copied into the admin-only folder and verified there against the anchor.
pub struct Staged<'a> {
    dir: PayloadDir<'a>,
    pack: PathBuf,
    setup: VerifiedSetup,
    keyset_version: u64,
}

impl Staged<'_> {
    /// The app's display name, from the verified config.
    pub fn name(&self) -> &str {
        &self.setup.config.install.name
    }

    /// The version the payload installs.
    pub fn version(&self) -> &Version {
        &self.setup.config.version
    }
}

/// A file of the copied payload: the key set and the manifest from memory, the pack from its copy,
/// each at the position it has in the setup file.
struct CopiedPayload {
    end: u64,
    keys: (u64, Vec<u8>),
    manifest: (u64, Vec<u8>),
    pack: (u64, u64, Box<dyn ReadAt>),
}

fn out_of_range() -> FsError {
    FsError::new(
        FsErrorKind::Other,
        Path::new("payload"),
        Some(io::Error::from(io::ErrorKind::UnexpectedEof)),
    )
}

impl ReadAt for CopiedPayload {
    fn size(&self) -> Result<u64, FsError> {
        Ok(self.end)
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FsError> {
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(out_of_range)?;
        for (at, bytes) in [&self.keys, &self.manifest] {
            let stop = at + bytes.len() as u64;
            if offset >= *at && end <= stop {
                let from = usize::try_from(offset - at).map_err(|_| out_of_range())?;
                buf.copy_from_slice(&bytes[from..from + buf.len()]);
                return Ok(());
            }
        }
        let (at, len, file) = &self.pack;
        if offset >= *at && end <= at + len {
            return file.read_exact_at(offset - at, buf);
        }
        Err(out_of_range())
    }
}

/// `part` of `file`, within `cap`.
fn read_part(file: &dyn ReadAt, part: SetupPart, cap: u64) -> Result<Vec<u8>, Kind> {
    if part.length > cap {
        return Err(Kind::Verify);
    }
    let window = ReadAtWindow::new(file, part).map_err(|_| Kind::Verify)?;
    let mut bytes = vec![0u8; usize::try_from(part.length).map_err(|_| Kind::Verify)?];
    window
        .read_exact_at(0, &mut bytes)
        .map_err(|_| Kind::Verify)?;
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Copies the payload of the setup `found` into a new admin-only folder under the machine home and
/// verifies it there against `anchor` (M10-D4): the trailer block, the key set and the manifest by
/// their digests, then the whole payload as [`verify_setup_anchored`] does, over the copy only.
/// Nothing is installed. Any failure removes the folder.
pub fn stage_payload<'a>(
    base: &Base<'a>,
    found: &Found,
    anchor: &SetupAnchor,
    events: &Events,
) -> Result<Staged<'a>, Kind> {
    // The block must be the one the anchor names before anything is copied.
    if anchor.is_placeholder() || base.hasher.sha256(&found.block) != anchor.trailer {
        return Err(Kind::Verify);
    }
    let trailer = &found.trailer;
    events.emit(&Event::phase(Phase::Install, Some(&trailer.version)));
    let keys = read_part(&*found.file, trailer.keys, Limits::V1.keys_doc_bytes)?;
    let manifest = read_part(
        &*found.file,
        trailer.manifest,
        Limits::V1.manifest_doc_bytes,
    )?;
    let source = ReadAtWindow::new(&*found.file, trailer.pack).map_err(|_| Kind::Verify)?;

    let mut id = [0u8; 16];
    base.rng.fill(&mut id).map_err(|_| Kind::Internal)?;
    let path = base.home.join(format!("{PAYLOAD_PREFIX}{}", hex(&id)));
    base.protect
        .create_dir(&path, DirClass::AdminOnly)
        .map_err(|_| Kind::NotProtected)?;
    let dir = PayloadDir {
        fs: base.fs,
        path: path.clone(),
    };

    // The pack, chunk by chunk, into a file of the new folder.
    let pack_path = path.join(PACK_FILE);
    let total = trailer.pack.length;
    let mut out = base.fs.create_new(&pack_path).map_err(|_| Kind::Fs)?;
    let mut buf = vec![0u8; usize::try_from(total.min(COPY_CHUNK as u64)).unwrap_or(0)];
    let mut done = 0u64;
    while done < total {
        let n = usize::try_from((total - done).min(COPY_CHUNK as u64)).unwrap_or(0);
        source
            .read_exact_at(done, &mut buf[..n])
            .map_err(|_| Kind::Verify)?;
        out.write_all(&buf[..n]).map_err(|_| Kind::Fs)?;
        done += n as u64;
        events.emit(&Event::Progress(Progress {
            phase: Phase::Install,
            done,
            total,
            file: None,
        }));
    }
    out.sync().map_err(|_| Kind::Fs)?;
    drop(out);

    let copied = CopiedPayload {
        end: found.end,
        keys: (trailer.keys.offset, keys),
        manifest: (trailer.manifest.offset, manifest),
        pack: (
            trailer.pack.offset,
            total,
            base.fs.open_read(&pack_path).map_err(|_| Kind::Fs)?,
        ),
    };
    let clock = ClockReading::read(base.clock, None);
    let anchored = verify_setup_anchored(
        anchor,
        &found.block,
        &copied,
        found.end,
        &clock,
        base.codec,
        base.hasher,
        base.verifier,
    )
    .map_err(|e| Kind::of(&lunepack::Error::from(e)))?;
    Ok(Staged {
        dir,
        pack: pack_path,
        setup: anchored.setup,
        keyset_version: anchored.keyset_version,
    })
}

/// What a machine-install failure is, as an exit kind.
pub fn kind_of(e: MachineOpError) -> Kind {
    match e {
        MachineOpError::AlreadyInstalled => Kind::AlreadyInstalled,
        MachineOpError::FolderTaken => Kind::InstallMismatch,
        MachineOpError::NameNotAllowed => Kind::UpdateConfig,
        MachineOpError::PerMachineUnavailable => Kind::PerMachineUnavailable,
        MachineOpError::InUse => Kind::InUse,
        MachineOpError::NotProtected => Kind::NotProtected,
        MachineOpError::Busy => Kind::Busy,
        MachineOpError::Verify => Kind::Verify,
        MachineOpError::Integration => Kind::Integration,
        MachineOpError::SelfTest => Kind::Process,
        // `Failed` and whatever a later core adds.
        _ => Kind::Internal,
    }
}

/// Runs the engine's first install over a staged payload.
pub fn install_staged(
    ports: Ports<'_>,
    home: &Path,
    staged: &Staged<'_>,
) -> Result<Installed, Kind> {
    install(
        ports,
        &InstallRequest {
            machine_home: home,
            display_name: staged.name(),
            setup: &staged.setup,
            keyset_version: staged.keyset_version,
            payload_dir: &staged.dir.path,
            pack: &staged.pack,
        },
    )
    .map_err(kind_of)
}

/// Builds the engine's ports for an install of the app named `name` and runs the install over a
/// staged payload. The Windows composition root builds adapters here (the registrar carries the
/// app's name, known only once the payload verified); tests build fakes.
pub trait Installer: Send + Sync {
    /// The first install of `staged` under `home`.
    fn install(&self, home: &Path, staged: &Staged<'_>) -> Result<Installed, Kind>;
}

/// Copies, verifies and installs: the whole all-users install of the setup `found` in this
/// process.
pub fn install_all(
    base: &Base<'_>,
    installer: &dyn Installer,
    found: &Found,
    anchor: &SetupAnchor,
    events: &Events,
) -> Result<Installed, Kind> {
    let staged = stage_payload(base, found, anchor, events)?;
    installer.install(base.home, &staged)
}

/// The hidden `machine-install` mode (M10 step 16): refused (usage) unless the process is an
/// administrator's and the image carries an anchor; creates the outbound pipe before any other
/// effect; installs ([`install_all`]); and returns the exit kind, which is the whole result.
/// Progress goes to the pipe's reader while there is one; a reader that is slow, gone or never
/// came changes nothing.
#[allow(clippy::too_many_arguments)]
pub fn run_mode(
    base: &Base<'_>,
    installer: &dyn Installer,
    pipes: &dyn EventPipes,
    standing: Standing,
    args: &MachineArgs,
    found: &Found,
    anchor: Option<&SetupAnchor>,
    wait: Duration,
) -> Kind {
    if standing == Standing::Standard {
        return Kind::Usage;
    }
    // An image without an anchor, or with the placeholder the packager stamps before the payload
    // exists, is not a setup to install from (and nothing was made yet).
    let Some(anchor) = anchor.filter(|a| !a.is_placeholder()) else {
        return Kind::Usage;
    };
    let writer = match pipes.open(&args.events, &args.for_sid, wait) {
        Ok(writer) => writer,
        Err(PipeFail::InvalidSid) => return Kind::Usage,
        Err(PipeFail::Failed) => return Kind::Process,
    };
    let events = Events::new(
        None,
        writer.map(|w| Box::new(RelaySink::new(w)) as Box<dyn crate::events::Sink>),
    );
    let result = install_all(base, installer, found, anchor, &events);
    // Drains the relay and drops its end of the pipe: the reader sees the end of the stream.
    events.finish(Duration::from_secs(2));
    match result {
        Ok(_) => Kind::Ok,
        Err(kind) => kind,
    }
}

// ---- the unelevated side ---------------------------------------------------------------------

/// What the unelevated setup hands the work off with.
pub struct HandOff<'a> {
    /// Starts the elevated copy.
    pub elevation: &'a dyn Elevation,
    /// Opens the copy's pipe.
    pub connector: &'a dyn EventConnector,
    /// The id of the pipe is drawn from here.
    pub rng: &'a dyn Rng,
    /// This setup's own image: the program the elevated copy runs.
    pub own_exe: &'a Path,
    /// The installing user's SID, as text: the only account that may read the pipe.
    pub sid: &'a str,
}

/// Starts the elevated copy ([`MACHINE_INSTALL`] with the pipe's id and `sid`), relays its progress
/// into `events` while it runs and returns when it has ended. The result is the copy's exit code
/// and, for `0`, `installed`: whether the machine record shows the install (never a line from the
/// pipe). A declined prompt is `elevation_declined`; one that cannot be shown, `process`.
pub fn hand_off(
    h: &HandOff<'_>,
    events: &Events,
    installed: &dyn Fn() -> bool,
) -> Result<(), Kind> {
    let mut id = [0u8; 16];
    h.rng.fill(&mut id).map_err(|_| Kind::Internal)?;
    let id = hex(&id);
    let args = [
        MACHINE_INSTALL.to_owned(),
        "--events".to_owned(),
        id.clone(),
        "--for-sid".to_owned(),
        h.sid.to_owned(),
    ];
    let mut child = match h.elevation.run_elevated(h.own_exe, &args) {
        Ok(Elevated::Started(child)) => child,
        Ok(Elevated::Declined) => return Err(Kind::ElevationDeclined),
        Err(_) => return Err(Kind::Process),
    };
    let ended = AtomicBool::new(false);
    let code = std::thread::scope(|scope| {
        scope.spawn(|| crate::relay::relay(h.connector, &id, events, &ended));
        let code = child.wait();
        ended.store(true, Ordering::Release);
        code
    });
    let code = code.map_err(|_| Kind::Process)?;
    match Kind::from_exit_code(code) {
        Kind::Ok if installed() => Ok(()),
        // A child that says it installed, with no record to show for it.
        Kind::Ok => Err(Kind::State),
        kind => Err(kind),
    }
}

/// [`hand_off`] after the check an unelevated setup makes before it asks for anything: an install
/// of the installing user (`user_install_there`) is `already_installed` and the elevation prompt is
/// never shown (M10-D14).
pub fn hand_off_unless(
    h: &HandOff<'_>,
    events: &Events,
    user_install_there: &dyn Fn() -> bool,
    installed: &dyn Fn() -> bool,
) -> Result<(), Kind> {
    if user_install_there() {
        return Err(Kind::AlreadyInstalled);
    }
    hand_off(h, events, installed)
}

// ---- the Windows adapters --------------------------------------------------------------------

/// The Windows adapters of the all-users install: the engine's ports, the elevation pipe's two
/// ends, the Program Files folder.
#[cfg(windows)]
pub mod native {
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use lunepack::SystemClock;
    use lunepack_codec_lzma::LzmaCodec;
    use lunepack_core::engine::{Installed, Ports};
    use lunepack_core::service::Duplex;
    use lunepack_crypto::{Ed25519Verifier, OsRng, Sha256Hasher};
    use lunepack_fs::StdFs;
    use lunepack_os_windows::{
        ExpectedOwner, PipeAccess, PipeClient, PipeError, PipeServer, RegistryPolicy,
        WinPublisherCheck, WinScope, WindowsIntegration, WindowsProcess, WindowsProtect,
        WindowsRegistrar, program_files,
    };

    use super::{EventPipes, Installer, PipeFail, Staged, install_staged};
    use crate::modes::Kind;
    use crate::relay::{Attempt, EventConnector, pipe_name};

    /// The machine home: the Program Files known folder, canonical (the shell's answer; no
    /// environment variable).
    pub fn machine_home() -> Option<PathBuf> {
        let dir = program_files().ok()?;
        std::fs::canonicalize(&dir).ok().or(Some(dir))
    }

    /// Every adapter the engine's ports name.
    pub struct Adapters {
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
        /// `app_name`: the display name the service is registered under (`<name> Update
        /// Service`).
        pub fn new(app_name: &str) -> Option<Adapters> {
            Some(Adapters {
                fs: StdFs::new(),
                codec: LzmaCodec,
                hasher: Sha256Hasher,
                verifier: Ed25519Verifier,
                clock: SystemClock,
                rng: OsRng,
                // Only the machine scope is used here; the per-user scope only completes the pair
                // (building it opens nothing).
                integration: WindowsIntegration::current_user().with_machine(WinScope::machine())?,
                publisher: WinPublisherCheck,
                protect: WindowsProtect,
                policy: RegistryPolicy::new(),
                registrar: WindowsRegistrar::new(app_name),
                process: WindowsProcess::new(),
            })
        }

        /// The engine's ports.
        pub fn ports(&self) -> Ports<'_> {
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

    /// The engine over the Windows adapters.
    pub struct NativeInstaller;

    impl Installer for NativeInstaller {
        fn install(&self, home: &Path, staged: &Staged<'_>) -> Result<Installed, Kind> {
            let adapters = Adapters::new(staged.name()).ok_or(Kind::Internal)?;
            install_staged(adapters.ports(), home, staged)
        }
    }

    /// The elevated copy's pipe, over the named-pipe adapter.
    pub struct NativePipes;

    impl EventPipes for NativePipes {
        fn open(
            &self,
            id: &str,
            sid: &str,
            wait: Duration,
        ) -> Result<Option<Box<dyn Write + Send>>, PipeFail> {
            let access = PipeAccess::Elevation {
                sid: sid.to_owned(),
            };
            let mut server =
                PipeServer::create(&crate::relay::pipe_name(id), &access).map_err(|e| match e {
                    PipeError::InvalidSid => PipeFail::InvalidSid,
                    _ => PipeFail::Failed,
                })?;
            match server.accept(Some(wait)) {
                Ok(()) => Ok(Some(Box::new(server))),
                // Nobody came (or the wait ended): the install does not depend on a reader.
                Err(_) => Ok(None),
            }
        }
    }

    /// The unelevated setup's end of the pipe: opened for reading only, and kept only when the
    /// pipe's owner is Administrators.
    pub struct NativeConnector;

    impl EventConnector for NativeConnector {
        fn connect(&self, id: &str, wait: Duration) -> Result<Box<dyn Duplex>, Attempt> {
            match PipeClient::connect(&pipe_name(id), ExpectedOwner::Administrators, wait) {
                Ok(client) => Ok(Box::new(client)),
                Err(PipeError::NotFound | PipeError::Busy | PipeError::Timeout) => {
                    Err(Attempt::NotYet)
                }
                Err(_) => Err(Attempt::Refused),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::sync::atomic::AtomicBool;
        use std::sync::{Arc, Mutex};

        use super::*;
        use crate::events::{Event, Events, Sink, SinkFailed};

        struct Collect(Arc<Mutex<Vec<Event>>>);

        impl Sink for Collect {
            fn name(&self) -> &'static str {
                "collect"
            }
            fn deliver(&mut self, event: &Event) -> Result<(), SinkFailed> {
                self.0.lock().unwrap().push(event.clone());
                Ok(())
            }
        }

        /// The elevated copy's real pipe and the unelevated setup's real connector, in one
        /// process: progress written into the pipe reaches the relay, whose client keeps the pipe
        /// only because its owner is Administrators. Needs an administrator's full token to
        /// create the pipe (the same token the elevated copy has); without one it says so.
        #[test]
        fn the_native_pipe_and_connector_carry_the_childs_progress() {
            let sid = lunepack_os_windows::current_user_sid().expect("the user's SID");
            let mut raw = [0u8; 16];
            lunepack::Rng::fill(&OsRng, &mut raw).expect("random");
            let id: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let events = Events::new(None, Some(Box::new(Collect(Arc::clone(&seen)))));
            let ended = AtomicBool::new(false);
            let outcome = std::thread::scope(|scope| {
                let server = scope.spawn(|| {
                    let writer = NativePipes.open(&id, &sid, Duration::from_secs(20));
                    match writer {
                        Ok(Some(mut w)) => {
                            w.write_all(b"phase install\nprogress install 5 9\n")
                                .expect("write");
                            Ok(())
                        }
                        Ok(None) => Err("nobody connected"),
                        Err(_) => Err("the pipe could not be made (no full administrator token?)"),
                    }
                });
                let relayed = crate::relay::relay(&NativeConnector, &id, &events, &ended);
                (server.join().expect("server"), relayed)
            });
            match outcome {
                (Ok(()), relayed) => {
                    assert_eq!(relayed, 2);
                    events.finish(Duration::from_secs(2));
                    assert_eq!(seen.lock().unwrap().len(), 2);
                }
                (Err(why), _) => println!("skipped: {why}"),
            }
        }

        /// The connector says "not yet" for a pipe nobody made, and a pipe of another id is not
        /// reached.
        #[test]
        fn a_pipe_nobody_made_is_not_yet() {
            let got = NativeConnector.connect(&"0".repeat(32), Duration::from_millis(100));
            assert!(matches!(got, Err(Attempt::NotYet)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use lunepack::{Channel, InstallMeta, RelPath, Target, UpdateConfig};
    use lunepack_core::engine::Ports;
    use lunepack_core::setup::{SetupTrailer, TRAILER_SIZE};
    use lunepack_core::{CodecId, PayloadKind, TrustedRoot, UPDATE_CONFIG_FILE};
    use lunepack_testkit::{
        ChainFixture, ElevationScript, FakeClock, FakeCodec, FakeElevation, FakeHasher,
        FakeMachineIntegration, FakePolicy, FakeProcess, FakeProtect, FakePublisherCheck,
        FakeRegistrar, FakeRng, FakeVerifier, MemFs, PackBuilder, SUITE_T0, abs_path, mem_duplex,
    };

    const TARGET: Target = Target::WindowsX86_64;
    const ID: &str = "0123456789abcdef0123456789abcdef";
    const SID: &str = "S-1-5-21-1-2-3-1001";

    fn meta() -> InstallMeta {
        InstallMeta {
            entry: RelPath::parse("app.exe").unwrap(),
            name: "Hello".into(),
            comment: None,
            icon: None,
            categories: Vec::new(),
            bin: None,
            terminal: false,
            publisher: None,
            file_types: Vec::new(),
            url_schemes: Vec::new(),
            autostart: false,
        }
    }

    /// A setup file: filler runtime, key set, manifest, pack, trailer (each part 8-aligned).
    struct Built {
        file: Vec<u8>,
        trailer: SetupTrailer,
        keys: Vec<u8>,
        manifest: Vec<u8>,
    }

    impl Built {
        fn new(root_seed: u8, version: &str, service: bool) -> Built {
            let fx = ChainFixture::fake();
            let root: TrustedRoot = fx.trusted_root(1, 1, &[root_seed]);
            let config = UpdateConfig::new(
                &root,
                lunepack::Version::parse(version).unwrap(),
                TARGET,
                "https://updates.example.org/hello/",
                Channel::parse("stable").unwrap(),
                60,
                meta(),
            )
            .unwrap()
            .to_bytes()
            .unwrap();
            let mut pack = PackBuilder::new();
            pack.file(fx.hasher, "app.exe", b"entry", CodecId::Lzma2);
            if service {
                pack.file(
                    fx.hasher,
                    lunepack_core::SERVICE_FILE,
                    b"service",
                    CodecId::Lzma2,
                );
            }
            pack.file(fx.hasher, UPDATE_CONFIG_FILE, &config, CodecId::Stored);
            let keys = fx.envelope(
                PayloadKind::Keys,
                &fx.keyset_document(1, 1, None, 1, &[5]).to_payload(),
                &[root_seed],
            );
            let manifest = fx.envelope(
                PayloadKind::Manifest,
                &fx.manifest_document(version, TARGET, &pack).to_payload(),
                &[5],
            );
            let mut file = vec![0x4du8; 1000];
            let place = |file: &mut Vec<u8>, bytes: &[u8]| {
                while !file.len().is_multiple_of(8) {
                    file.push(0);
                }
                let part = SetupPart {
                    offset: file.len() as u64,
                    length: bytes.len() as u64,
                };
                file.extend_from_slice(bytes);
                part
            };
            let k = place(&mut file, &keys);
            let m = place(&mut file, &manifest);
            let p = place(&mut file, &pack.bytes);
            while !file.len().is_multiple_of(8) {
                file.push(0);
            }
            let trailer = SetupTrailer {
                root,
                version: lunepack::Version::parse(version).unwrap(),
                target: TARGET,
                keys: k,
                manifest: m,
                pack: p,
            };
            file.extend_from_slice(&trailer.encode().unwrap());
            Built {
                file,
                trailer,
                keys,
                manifest,
            }
        }

        fn block(&self) -> Vec<u8> {
            self.file[self.file.len() - TRAILER_SIZE as usize..].to_vec()
        }

        fn anchor(&self) -> SetupAnchor {
            SetupAnchor::of(&self.block(), &self.keys, &self.manifest, &FakeHasher)
        }

        fn found(&self) -> Found {
            let mem = MemFs::new();
            let path = abs_path("/dl/setup.exe");
            mem.create_dir_all(path.parent().unwrap()).unwrap();
            let mut w = mem.create_new(&path).unwrap();
            w.write_all(&self.file).unwrap();
            Found {
                trailer: self.trailer.clone(),
                file: Arc::from(mem.open_read(&path).unwrap()),
                block: self.block(),
                end: self.file.len() as u64,
            }
        }
    }

    /// A machine home with every port faked.
    struct Host {
        mem: MemFs,
        protect: FakeProtect,
        policy: FakePolicy,
        integration: FakeMachineIntegration,
        publisher: FakePublisherCheck,
        registrar: FakeRegistrar,
        process: FakeProcess,
        rng: FakeRng,
        clock: FakeClock,
        codec: FakeCodec,
        home: PathBuf,
    }

    impl Host {
        fn new() -> Host {
            let mem = MemFs::new();
            let home = abs_path("/pf");
            mem.create_dir_all(&home).unwrap();
            Host {
                protect: FakeProtect::new(&mem),
                policy: FakePolicy::new(),
                integration: FakeMachineIntegration::new(),
                publisher: FakePublisherCheck::new([]),
                registrar: FakeRegistrar::new(),
                process: FakeProcess::new(abs_path("/pf/Hello/app/1.0.0/app.exe")),
                rng: FakeRng::new(11),
                clock: FakeClock::new(SUITE_T0 + 3600),
                codec: FakeCodec::new(),
                home,
                mem,
            }
        }

        fn ports(&self) -> Ports<'_> {
            Ports {
                fs: &self.mem,
                codec: &self.codec,
                hasher: &FakeHasher,
                verifier: &FakeVerifier,
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

        fn base(&self) -> Base<'_> {
            Base::of(&self.ports(), &self.home)
        }

        fn payload_dirs(&self) -> Vec<String> {
            use lunepack_core::Fs as _;
            self.mem
                .list_dir(&self.home)
                .unwrap()
                .into_iter()
                .map(|e| e.name.to_string_lossy().into_owned())
                .filter(|n| n.starts_with(PAYLOAD_PREFIX))
                .collect()
        }

        fn machine(&self) -> Machine {
            find(
                &self.mem,
                &FakeHasher,
                &self.home,
                &AppId::parse(lunepack_testkit::SUITE_APP_ID).unwrap(),
                "Hello",
            )
        }
    }

    /// The engine over the host's fakes.
    struct FakeInstaller<'h>(&'h Host);

    impl Installer for FakeInstaller<'_> {
        fn install(&self, home: &Path, staged: &Staged<'_>) -> Result<Installed, Kind> {
            install_staged(self.0.ports(), home, staged)
        }
    }

    /// A pipe pair: the elevated end writes into `tx`, the reader holds the other.
    struct FakePipes {
        reader: Mutex<Option<lunepack_testkit::MemDuplex>>,
        opened: Mutex<Vec<(String, String)>>,
        fail: Option<fn() -> PipeFail>,
        nobody_comes: bool,
    }

    impl FakePipes {
        fn new() -> (FakePipes, lunepack_testkit::MemDuplex) {
            let (child, reader) = mem_duplex();
            (
                FakePipes {
                    reader: Mutex::new(Some(child)),
                    opened: Mutex::new(Vec::new()),
                    fail: None,
                    nobody_comes: false,
                },
                reader,
            )
        }
    }

    impl EventPipes for FakePipes {
        fn open(
            &self,
            id: &str,
            sid: &str,
            _: Duration,
        ) -> Result<Option<Box<dyn Write + Send>>, PipeFail> {
            self.opened
                .lock()
                .unwrap()
                .push((id.to_owned(), sid.to_owned()));
            if let Some(fail) = self.fail {
                return Err(fail());
            }
            if self.nobody_comes {
                return Ok(None);
            }
            Ok(self
                .reader
                .lock()
                .unwrap()
                .take()
                .map(|d| Box::new(d) as Box<dyn Write + Send>))
        }
    }

    fn args() -> MachineArgs {
        MachineArgs {
            events: ID.to_owned(),
            for_sid: SID.to_owned(),
        }
    }

    // ---- the choice -------------------------------------------------------------------------

    fn run(silent: bool, all_users: bool) -> SetupArgs {
        SetupArgs { silent, all_users }
    }

    #[test]
    fn the_choice_is_offered_to_a_process_without_a_full_token_when_the_release_has_a_service() {
        for (standing, service, want) in [
            (Standing::Standard, true, true),
            (Standing::Admin, true, true),
            (Standing::UacElevated, true, false),
            (Standing::Standard, false, false),
            (Standing::Admin, false, false),
            (Standing::UacElevated, false, false),
        ] {
            assert_eq!(offered(standing, service), want, "{standing:?} {service}");
        }
    }

    #[test]
    fn every_standing_and_flag_has_one_route() {
        use Standing::{Admin, Standard, UacElevated};
        let user = |offer, forced| Route::User { offer, forced };
        // No flag: the window, with the choice when it may be offered; an elevated process shows
        // one message and leaves.
        assert_eq!(route(Standard, run(false, false), true), user(true, false));
        assert_eq!(route(Admin, run(true, false), true), user(true, false));
        assert_eq!(
            route(Standard, run(false, false), false),
            user(false, false)
        );
        assert_eq!(route(UacElevated, run(false, false), true), Route::Notice);
        assert_eq!(route(UacElevated, run(true, false), false), Route::Notice);
        // `--all-users`: an administrator installs in this process, with no window.
        assert_eq!(
            route(Admin, run(false, true), true),
            Route::InProcess { check_user: true }
        );
        assert_eq!(
            route(Admin, run(true, true), true),
            Route::InProcess { check_user: true }
        );
        assert_eq!(
            route(UacElevated, run(false, true), true),
            Route::InProcess { check_user: false }
        );
        assert_eq!(
            route(UacElevated, run(true, true), true),
            Route::InProcess { check_user: false }
        );
        // A standard user: silent never asks; otherwise the box is as good as ticked.
        assert_eq!(
            route(Standard, run(true, true), true),
            Route::ElevationRequired
        );
        assert_eq!(route(Standard, run(false, true), true), user(true, true));
        // No service in the release: 34 for everyone, before anything else.
        for standing in [Standard, Admin, UacElevated] {
            for silent in [false, true] {
                assert_eq!(
                    route(standing, run(silent, true), false),
                    Route::Refuse(Kind::PerMachineUnavailable),
                    "{standing:?} {silent}"
                );
            }
        }
    }

    // ---- the elevated side ------------------------------------------------------------------

    #[test]
    fn an_anchored_payload_is_copied_verified_and_installed_and_the_copy_is_gone() {
        let host = Host::new();
        let b = Built::new(0, "1.0.0", true);
        let (events, seen) = collecting();
        let staged = stage_payload(&host.base(), &b.found(), &b.anchor(), &events).expect("staged");
        // The copy exists, admin-only, until the install (or a drop) removes it.
        let dirs = host.payload_dirs();
        assert_eq!(dirs.len(), 1, "{dirs:?}");
        assert_eq!(
            host.protect.class_of(&host.home.join(&dirs[0])),
            Some(DirClass::AdminOnly)
        );
        assert_eq!(staged.name(), "Hello");
        let installed = install_staged(host.ports(), &host.home, &staged).expect("installed");
        assert_eq!(installed.version.to_string(), "1.0.0");
        assert!(host.payload_dirs().is_empty(), "the copy was removed");
        match host.machine() {
            Machine::Present(root, Some(v)) => {
                assert_eq!(root, host.home.join("Hello"));
                assert_eq!(v.to_string(), "1.0.0");
            }
            other => panic!("{other:?}"),
        }
        drop(staged);
        events.finish(Duration::from_secs(1));
        let seen = seen.lock().unwrap();
        assert!(
            matches!(seen.first(), Some(Event::Phase { .. })),
            "{seen:?}"
        );
        assert!(
            seen.iter().any(
                |e| matches!(e, Event::Progress(p) if p.done == p.total && p.total == b.trailer.pack.length)
            ),
            "the copy's last progress"
        );
    }

    #[test]
    fn a_wrong_or_missing_anchor_is_a_verify_error_and_nothing_stays() {
        let host = Host::new();
        let b = Built::new(0, "1.0.0", true);
        let (events, _) = collecting();
        let good = b.anchor();
        let mut bad = Vec::new();
        for i in 0..3 {
            let mut enc = good.encode();
            enc[8 + 32 * i] ^= 1;
            bad.push(SetupAnchor::parse(&enc).unwrap());
        }
        bad.push(SetupAnchor::parse(&SetupAnchor::PLACEHOLDER).unwrap());
        for anchor in bad {
            let got = stage_payload(&host.base(), &b.found(), &anchor, &events);
            assert!(matches!(got, Err(Kind::Verify)), "{:?}", got.err());
            assert!(host.payload_dirs().is_empty());
            assert_eq!(host.machine(), Machine::Absent);
        }
        // Another valid payload under the same anchor.
        let other = Built::new(9, "1.0.0", true);
        let got = stage_payload(&host.base(), &other.found(), &good, &events);
        assert!(matches!(got, Err(Kind::Verify)));
        assert!(host.payload_dirs().is_empty());
    }

    #[test]
    fn a_pack_flipped_after_the_anchor_was_made_is_refused_over_the_copy() {
        let host = Host::new();
        let mut b = Built::new(0, "1.0.0", true);
        let anchor = b.anchor();
        // The anchor covers the trailer, key set and manifest; the pack is bound by the manifest.
        let at = (b.trailer.pack.offset + b.trailer.pack.length / 2) as usize;
        b.file[at] ^= 1;
        let (events, _) = collecting();
        let got = stage_payload(&host.base(), &b.found(), &anchor, &events);
        assert!(matches!(got, Err(Kind::Verify)), "{:?}", got.err());
        assert!(host.payload_dirs().is_empty());
    }

    #[test]
    fn an_unprotectable_folder_is_not_protected_and_a_release_without_a_service_is_34() {
        let host = Host::new();
        let b = Built::new(0, "1.0.0", true);
        let (events, _) = collecting();
        host.protect.fail_create(&host.home.join(format!(
            "{PAYLOAD_PREFIX}{}",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        )));
        // The fake rng's first 16 bytes name the folder; make that one fail.
        let probe = FakeRng::new(11);
        let mut first = [0u8; 16];
        lunepack_core::Rng::fill(&probe, &mut first).unwrap();
        host.protect
            .fail_create(&host.home.join(format!("{PAYLOAD_PREFIX}{}", hex(&first))));
        let got = stage_payload(&host.base(), &b.found(), &b.anchor(), &events);
        assert!(matches!(got, Err(Kind::NotProtected)));

        let host = Host::new();
        let b = Built::new(0, "1.0.0", false);
        let staged = stage_payload(&host.base(), &b.found(), &b.anchor(), &events).unwrap();
        let got = install_staged(host.ports(), &host.home, &staged);
        assert!(matches!(got, Err(Kind::PerMachineUnavailable)));
        assert_eq!(Kind::PerMachineUnavailable.code(), 34);
        drop(staged);
        assert!(host.payload_dirs().is_empty());
        assert_eq!(host.machine(), Machine::Absent);
    }

    #[test]
    fn an_existing_machine_install_is_already_installed() {
        let host = Host::new();
        let b = Built::new(0, "1.0.0", true);
        let (events, _) = collecting();
        install_all(
            &host.base(),
            &FakeInstaller(&host),
            &b.found(),
            &b.anchor(),
            &events,
        )
        .expect("first");
        let again = install_all(
            &host.base(),
            &FakeInstaller(&host),
            &b.found(),
            &b.anchor(),
            &events,
        );
        assert!(
            matches!(again, Err(Kind::AlreadyInstalled)),
            "{:?}",
            again.err()
        );
        assert!(host.payload_dirs().is_empty());
    }

    #[test]
    fn the_mode_is_for_administrators_with_an_anchor_and_a_pipe_it_can_make() {
        let host = Host::new();
        let b = Built::new(0, "1.0.0", true);
        let anchor = b.anchor();
        let go = |standing, anchor: Option<&SetupAnchor>, pipes: &FakePipes| {
            run_mode(
                &host.base(),
                &FakeInstaller(&host),
                pipes,
                standing,
                &args(),
                &b.found(),
                anchor,
                Duration::from_millis(10),
            )
        };
        // A standard user's process, or an image without an anchor: usage, and the pipe is never
        // made.
        let (pipes, _r) = FakePipes::new();
        assert_eq!(go(Standing::Standard, Some(&anchor), &pipes), Kind::Usage);
        assert_eq!(go(Standing::Admin, None, &pipes), Kind::Usage);
        let placeholder = SetupAnchor::parse(&SetupAnchor::PLACEHOLDER).unwrap();
        assert_eq!(
            go(Standing::UacElevated, Some(&placeholder), &pipes),
            Kind::Usage
        );
        assert!(pipes.opened.lock().unwrap().is_empty());
        assert_eq!(host.machine(), Machine::Absent);
        // A SID the system refuses: usage; any other failure to make the pipe: process. Nothing
        // is installed either way.
        let (mut pipes, _r) = FakePipes::new();
        pipes.fail = Some(|| PipeFail::InvalidSid);
        assert_eq!(go(Standing::Admin, Some(&anchor), &pipes), Kind::Usage);
        pipes.fail = Some(|| PipeFail::Failed);
        assert_eq!(
            go(Standing::UacElevated, Some(&anchor), &pipes),
            Kind::Process
        );
        assert_eq!(host.machine(), Machine::Absent);
        assert!(host.payload_dirs().is_empty());
    }

    #[test]
    fn the_mode_installs_relays_its_progress_and_answers_with_its_exit_kind() {
        for standing in [Standing::Admin, Standing::UacElevated] {
            let host = Host::new();
            let b = Built::new(0, "1.0.0", true);
            let (pipes, mut reader) = FakePipes::new();
            let kind = run_mode(
                &host.base(),
                &FakeInstaller(&host),
                &pipes,
                standing,
                &args(),
                &b.found(),
                Some(&b.anchor()),
                Duration::from_millis(10),
            );
            assert_eq!(kind, Kind::Ok);
            assert_eq!(
                *pipes.opened.lock().unwrap(),
                vec![(ID.to_owned(), SID.to_owned())]
            );
            // The pipe was closed by the end of the run: the reader reads to the end.
            let mut text = String::new();
            std::io::Read::read_to_string(&mut reader, &mut text).unwrap();
            assert!(text.starts_with("phase install\n"), "{text}");
            assert!(
                text.lines().all(|l| crate::relay::decode(l).is_some()),
                "{text}"
            );
            assert!(matches!(host.machine(), Machine::Present(_, Some(_))));
        }
    }

    #[test]
    fn a_reader_that_never_comes_or_is_gone_changes_nothing_about_the_install() {
        // Nobody opens the pipe.
        let host = Host::new();
        let b = Built::new(0, "1.0.0", true);
        let (mut pipes, _reader) = FakePipes::new();
        pipes.nobody_comes = true;
        let kind = run_mode(
            &host.base(),
            &FakeInstaller(&host),
            &pipes,
            Standing::Admin,
            &args(),
            &b.found(),
            Some(&b.anchor()),
            Duration::from_millis(10),
        );
        assert_eq!(kind, Kind::Ok);
        assert!(matches!(host.machine(), Machine::Present(_, Some(_))));
        // The reader's end is dropped before the run: every write fails.
        let host = Host::new();
        let (pipes, reader) = FakePipes::new();
        drop(reader);
        let kind = run_mode(
            &host.base(),
            &FakeInstaller(&host),
            &pipes,
            Standing::Admin,
            &args(),
            &b.found(),
            Some(&b.anchor()),
            Duration::from_millis(10),
        );
        assert_eq!(kind, Kind::Ok);
        assert!(matches!(host.machine(), Machine::Present(_, Some(_))));
    }

    #[test]
    fn a_failed_install_is_the_exit_kind_and_leaves_no_copy() {
        let host = Host::new();
        let b = Built::new(0, "1.0.0", true);
        let (events, _) = collecting();
        install_all(
            &host.base(),
            &FakeInstaller(&host),
            &b.found(),
            &b.anchor(),
            &events,
        )
        .unwrap();
        let (pipes, mut reader) = FakePipes::new();
        let kind = run_mode(
            &host.base(),
            &FakeInstaller(&host),
            &pipes,
            Standing::Admin,
            &args(),
            &b.found(),
            Some(&b.anchor()),
            Duration::from_millis(10),
        );
        assert_eq!(kind, Kind::AlreadyInstalled);
        let mut text = String::new();
        std::io::Read::read_to_string(&mut reader, &mut text).unwrap();
        assert!(!text.contains("installed"), "{text}");
        assert!(host.payload_dirs().is_empty());
    }

    // ---- the unelevated side ----------------------------------------------------------------

    /// The elevated copy, run in place: the mode over the host's fakes, finished before the
    /// hand-off's relay starts reading (the pipe pair buffers what it wrote).
    struct RunsTheMode<'h> {
        host: &'h Host,
        built: &'h Built,
        standing: Standing,
        calls: Mutex<Vec<(PathBuf, Vec<String>)>>,
        pipes: FakePipes,
        /// Answers taken from the end; an empty script runs the mode.
        script: Mutex<Vec<ElevationScript>>,
    }

    struct Done(i32);

    impl lunepack_core::ElevatedChild for Done {
        fn wait(&mut self) -> Result<i32, lunepack_core::error::ElevationError> {
            Ok(self.0)
        }
    }

    impl Elevation for RunsTheMode<'_> {
        fn standing(&self) -> Standing {
            Standing::Standard
        }

        fn run_elevated(
            &self,
            exe: &Path,
            args: &[String],
        ) -> Result<Elevated, lunepack_core::error::ElevationError> {
            self.calls
                .lock()
                .unwrap()
                .push((exe.to_path_buf(), args.to_vec()));
            if let Some(ElevationScript::Declined) = self.script.lock().unwrap().pop() {
                return Ok(Elevated::Declined);
            }
            let os: Vec<std::ffi::OsString> = args.iter().map(std::ffi::OsString::from).collect();
            let Ok(crate::modes::SetupCommand::MachineInstall(parsed)) =
                crate::modes::parse_setup_command_with(&os, true)
            else {
                panic!("not the mode: {args:?}");
            };
            let kind = run_mode(
                &self.host.base(),
                &FakeInstaller(self.host),
                &self.pipes,
                self.standing,
                &parsed,
                &self.built.found(),
                Some(&self.built.anchor()),
                Duration::from_millis(10),
            );
            Ok(Elevated::Started(Box::new(Done(i32::from(kind.code())))))
        }
    }

    struct ReaderConnector(Mutex<Option<lunepack_testkit::MemDuplex>>);

    impl EventConnector for ReaderConnector {
        fn connect(
            &self,
            _: &str,
            _: Duration,
        ) -> Result<Box<dyn lunepack_core::service::Duplex>, crate::relay::Attempt> {
            self.0
                .lock()
                .unwrap()
                .take()
                .map(|d| Box::new(d) as Box<dyn lunepack_core::service::Duplex>)
                .ok_or(crate::relay::Attempt::Refused)
        }
    }

    fn collecting() -> (Events, Arc<Mutex<Vec<Event>>>) {
        use crate::events::{Sink, SinkFailed};
        struct Collect(Arc<Mutex<Vec<Event>>>);
        impl Sink for Collect {
            fn name(&self) -> &'static str {
                "collect"
            }
            fn deliver(&mut self, event: &Event) -> Result<(), SinkFailed> {
                self.0.lock().unwrap().push(event.clone());
                Ok(())
            }
        }
        let seen = Arc::new(Mutex::new(Vec::new()));
        (
            Events::new(None, Some(Box::new(Collect(Arc::clone(&seen))))),
            seen,
        )
    }

    #[test]
    fn a_hand_off_to_a_copy_that_runs_the_mode_installs_and_relays() {
        let host = Host::new();
        let b = Built::new(0, "1.0.0", true);
        let (pipes, reader) = FakePipes::new();
        let elevation = RunsTheMode {
            host: &host,
            built: &b,
            standing: Standing::UacElevated,
            calls: Mutex::new(Vec::new()),
            pipes,
            script: Mutex::new(Vec::new()),
        };
        let connector = ReaderConnector(Mutex::new(Some(reader)));
        let own = abs_path("/dl/setup.exe");
        let h = HandOff {
            elevation: &elevation,
            connector: &connector,
            rng: &FakeRng::new(3),
            own_exe: &own,
            sid: SID,
        };
        let (events, seen) = collecting();
        let app = AppId::parse(lunepack_testkit::SUITE_APP_ID).unwrap();
        let installed = || {
            matches!(
                find(&host.mem, &FakeHasher, &host.home, &app, "Hello"),
                Machine::Present(_, Some(v)) if v.to_string() == "1.0.0"
            )
        };
        hand_off(&h, &events, &installed).expect("installed");
        events.finish(Duration::from_secs(1));
        // The child was started with the mode, a 32-hex id and the user's SID; nothing else.
        let calls = elevation.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, own);
        assert_eq!(calls[0].1[0], MACHINE_INSTALL);
        assert_eq!(calls[0].1[1], "--events");
        assert_eq!(calls[0].1[2].len(), 32);
        assert_eq!(calls[0].1[3..], ["--for-sid".to_owned(), SID.to_owned()]);
        // The id the child made its pipe with is the one the relay opened.
        assert_eq!(elevation.pipes.opened.lock().unwrap()[0].0, calls[0].1[2]);
        // The relay saw the child's progress.
        assert!(
            seen.lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, Event::Phase { .. })),
            "{:?}",
            seen.lock().unwrap()
        );
    }

    #[test]
    fn a_declined_prompt_is_31_and_a_second_try_installs() {
        let host = Host::new();
        let b = Built::new(0, "1.0.0", true);
        let (pipes, reader) = FakePipes::new();
        let elevation = RunsTheMode {
            host: &host,
            built: &b,
            standing: Standing::UacElevated,
            calls: Mutex::new(Vec::new()),
            pipes,
            script: Mutex::new(vec![ElevationScript::Declined]),
        };
        let connector = ReaderConnector(Mutex::new(Some(reader)));
        let own = abs_path("/dl/setup.exe");
        let h = HandOff {
            elevation: &elevation,
            connector: &connector,
            rng: &FakeRng::new(3),
            own_exe: &own,
            sid: SID,
        };
        let (events, _) = collecting();
        let app = AppId::parse(lunepack_testkit::SUITE_APP_ID).unwrap();
        let installed = || {
            matches!(
                find(&host.mem, &FakeHasher, &host.home, &app, "Hello"),
                Machine::Present(..)
            )
        };
        assert_eq!(
            hand_off(&h, &events, &installed),
            Err(Kind::ElevationDeclined)
        );
        assert_eq!(host.machine(), Machine::Absent);
        assert_eq!(hand_off(&h, &events, &installed), Ok(()));
        assert_eq!(elevation.calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn the_result_is_the_exit_code_and_the_record_never_the_pipe() {
        let never = ReaderConnector(Mutex::new(None));
        let own = abs_path("/dl/setup.exe");
        let (events, _) = collecting();
        let go = |script: ElevationScript, record: bool| {
            let elevation = FakeElevation::new(Standing::Standard, [script]);
            let h = HandOff {
                elevation: &elevation,
                connector: &never,
                rng: &FakeRng::new(3),
                own_exe: &own,
                sid: SID,
            };
            hand_off(&h, &events, &|| record)
        };
        assert_eq!(go(ElevationScript::Exit(0), true), Ok(()));
        // A zero exit with no record to show for it.
        assert_eq!(go(ElevationScript::Exit(0), false), Err(Kind::State));
        assert_eq!(
            go(ElevationScript::Exit(23), true),
            Err(Kind::AlreadyInstalled)
        );
        assert_eq!(
            go(ElevationScript::Exit(35), false),
            Err(Kind::NotProtected)
        );
        assert_eq!(
            go(ElevationScript::Exit(34), false),
            Err(Kind::PerMachineUnavailable)
        );
        assert_eq!(go(ElevationScript::Exit(7), false), Err(Kind::Verify));
        // An unknown code, or a crash code: process.
        assert_eq!(go(ElevationScript::Exit(1), true), Err(Kind::Process));
        assert_eq!(
            go(ElevationScript::Exit(-1073741819), true),
            Err(Kind::Process)
        );
        assert_eq!(
            go(ElevationScript::Declined, true),
            Err(Kind::ElevationDeclined)
        );
        assert_eq!(go(ElevationScript::Fails, true), Err(Kind::Process));
    }

    #[test]
    fn the_machine_is_found_by_its_record_and_an_unreadable_one_blocks_a_user_install() {
        let host = Host::new();
        let app = AppId::parse(lunepack_testkit::SUITE_APP_ID).unwrap();
        assert_eq!(host.machine(), Machine::Absent);
        assert!(!blocks_user_install(&host.machine()));
        let b = Built::new(0, "1.0.0", true);
        let (events, _) = collecting();
        install_all(
            &host.base(),
            &FakeInstaller(&host),
            &b.found(),
            &b.anchor(),
            &events,
        )
        .unwrap();
        let found = host.machine();
        assert!(matches!(found, Machine::Present(..)));
        assert!(blocks_user_install(&found));
        assert!(blocks_user_install(&Machine::Unreadable));
        // A folder of the app's name that is not an install of it is not an install.
        let other = Host::new();
        other.mem.create_dir_all(&other.home.join("Hello")).unwrap();
        let mut w = other
            .mem
            .create_new(&other.home.join("Hello").join("x.txt"))
            .unwrap();
        w.write_all(b"x").unwrap();
        assert_eq!(
            find(&other.mem, &FakeHasher, &other.home, &app, "Hello"),
            Machine::Absent
        );
    }

    // ---- what the unelevated side looks up, and what the elevated side never touches ----------

    fn decision(
        standing: Standing,
        args: SetupArgs,
        service: bool,
        user: Result<bool, Kind>,
    ) -> (Decision, u32) {
        let asked = std::cell::Cell::new(0u32);
        let d = decide(standing, args, service, &|| {
            asked.set(asked.get() + 1);
            user
        });
        (d, asked.get())
    }

    #[test]
    fn the_install_of_the_installing_user_is_looked_up_by_an_unelevated_process_only() {
        use Standing::{Admin, Standard, UacElevated};
        // `--all-users --silent` as a standard user: 23 when the user has an install, else 30;
        // 34 first when the release has no service (nothing is looked up then).
        assert_eq!(
            decision(Standard, run(true, true), true, Ok(true)),
            (Decision::Exit(Kind::AlreadyInstalled), 1)
        );
        assert_eq!(
            decision(Standard, run(true, true), true, Ok(false)),
            (Decision::Exit(Kind::ElevationRequired), 1)
        );
        assert_eq!(
            decision(Standard, run(true, true), false, Ok(false)),
            (Decision::Exit(Kind::PerMachineUnavailable), 0)
        );
        assert_eq!(
            decision(Standard, run(true, true), true, Err(Kind::Fs)),
            (Decision::Exit(Kind::Fs), 1)
        );
        // An administrator without a split token: the same lookup, then the install here.
        assert_eq!(
            decision(Admin, run(false, true), true, Ok(true)),
            (Decision::Exit(Kind::AlreadyInstalled), 1)
        );
        assert_eq!(
            decision(Admin, run(true, true), true, Ok(false)),
            (Decision::InProcess, 1)
        );
        // A full token: nothing is looked up, whatever the user has; the documented overlap.
        for silent in [false, true] {
            assert_eq!(
                decision(UacElevated, run(silent, true), true, Ok(true)),
                (Decision::InProcess, 0)
            );
        }
        // The window flows look nothing up here (the all-users choice checks when it is made).
        assert_eq!(
            decision(Standard, run(false, false), true, Ok(true)),
            (
                Decision::Window {
                    offer: true,
                    forced: false
                },
                0
            )
        );
        assert_eq!(
            decision(Standard, run(false, true), true, Ok(true)),
            (
                Decision::Window {
                    offer: true,
                    forced: true
                },
                0
            )
        );
        assert_eq!(
            decision(UacElevated, run(false, false), true, Ok(true)),
            (Decision::Notice, 0)
        );
    }

    #[test]
    fn an_install_of_the_user_is_23_before_the_prompt_and_the_elevation_is_never_called() {
        let elevation = FakeElevation::new(Standing::Standard, [ElevationScript::Exit(0)]);
        let never = ReaderConnector(Mutex::new(None));
        let own = abs_path("/dl/setup.exe");
        let h = HandOff {
            elevation: &elevation,
            connector: &never,
            rng: &FakeRng::new(3),
            own_exe: &own,
            sid: SID,
        };
        let (events, _) = collecting();
        assert_eq!(
            hand_off_unless(&h, &events, &|| true, &|| true),
            Err(Kind::AlreadyInstalled)
        );
        assert!(elevation.calls().is_empty(), "the prompt was never asked");
        // Without an install of the user the hand-off goes ahead.
        assert_eq!(hand_off_unless(&h, &events, &|| false, &|| true), Ok(()));
        assert_eq!(elevation.calls().len(), 1);
    }

    /// A filesystem that records every path under `forbidden` it is asked about (a user's
    /// profile): the elevated side must never be one of its callers.
    struct Watch {
        inner: MemFs,
        forbidden: PathBuf,
        hits: Mutex<Vec<PathBuf>>,
    }

    impl Watch {
        fn note(&self, p: &Path) {
            if p.starts_with(&self.forbidden) {
                self.hits.lock().unwrap().push(p.to_path_buf());
            }
        }
    }

    macro_rules! watched {
        ($($name:ident($($arg:ident: $ty:ty),*) -> $ret:ty => [$($note:ident),*];)*) => {
            $(fn $name(&self, $($arg: $ty),*) -> $ret {
                $(self.note($note);)*
                self.inner.$name($($arg),*)
            })*
        };
    }

    impl Fs for Watch {
        watched! {
            read_capped(path: &Path, max: u64) -> Result<Vec<u8>, FsError> => [path];
            open_read(path: &Path) -> Result<Box<dyn ReadAt>, FsError> => [path];
            create_new(path: &Path) -> Result<Box<dyn lunepack_core::FileWrite>, FsError> => [path];
            open_append(path: &Path) -> Result<Box<dyn lunepack_core::FileWrite>, FsError> => [path];
            truncate(path: &Path, len: u64) -> Result<(), FsError> => [path];
            rename(from: &Path, to: &Path) -> Result<(), FsError> => [from, to];
            remove_file(path: &Path) -> Result<(), FsError> => [path];
            remove_dir_all_nofollow(path: &Path) -> Result<(), FsError> => [path];
            create_dir_all(path: &Path) -> Result<(), FsError> => [path];
            list_dir(path: &Path) -> Result<Vec<lunepack_core::fs::DirEntryInfo>, FsError> => [path];
            symlink_metadata(path: &Path) -> Result<Option<lunepack_core::fs::Meta>, FsError> => [path];
            sync_dir(path: &Path) -> Result<(), FsError> => [path];
            copy_file(from: &Path, to_new: &Path) -> Result<(), FsError> => [from, to_new];
            set_exec(path: &Path, exec: bool) -> Result<(), FsError> => [path];
            symlink(target: &str, link_path: &Path) -> Result<(), FsError> => [link_path];
            read_link(path: &Path) -> Result<String, FsError> => [path];
            replace_symlink(target: &str, link: &Path) -> Result<(), FsError> => [link];
            try_lock(path: &Path) -> Result<Option<Box<dyn lunepack_core::fs::LockGuard>>, FsError> => [path];
        }
    }

    #[test]
    fn the_elevated_mode_never_touches_a_users_profile() {
        let host = Host::new();
        // A user's profile exists beside the machine home, with a per-user install in it.
        let profile = abs_path("/Users/someone/AppData/Local");
        host.mem
            .create_dir_all(&profile.join("Programs/Hello"))
            .unwrap();
        let watch = Watch {
            inner: host.mem.clone(),
            forbidden: abs_path("/Users"),
            hits: Mutex::new(Vec::new()),
        };
        let ports = Ports {
            fs: &watch,
            ..host.ports()
        };
        let b = Built::new(0, "1.0.0", true);
        let (pipes, _reader) = FakePipes::new();
        struct Over<'a>(&'a Host, &'a Watch);
        impl Installer for Over<'_> {
            fn install(&self, home: &Path, staged: &Staged<'_>) -> Result<Installed, Kind> {
                install_staged(
                    Ports {
                        fs: self.1,
                        ..self.0.ports()
                    },
                    home,
                    staged,
                )
            }
        }
        // Standing UacElevated, with a per-user install of the app present: it installs for all
        // users anyway (the documented overlap), and the profile is never asked about.
        let kind = run_mode(
            &Base::of(&ports, &host.home),
            &Over(&host, &watch),
            &pipes,
            Standing::UacElevated,
            &args(),
            &b.found(),
            Some(&b.anchor()),
            Duration::from_millis(10),
        );
        assert_eq!(kind, Kind::Ok);
        assert!(matches!(host.machine(), Machine::Present(..)));
        assert_eq!(*watch.hits.lock().unwrap(), Vec::<PathBuf>::new());
        // The instrument works: a lookup under the profile is recorded.
        let _ = watch.symlink_metadata(&profile);
        assert_eq!(watch.hits.lock().unwrap().len(), 1);
    }

    /// The UI is killed after the hand-off (its sink fails on the first event it is given, and the
    /// relay's pipe is gone): the install still completes and the answer is still success.
    #[test]
    fn a_ui_killed_after_the_hand_off_changes_nothing_about_the_install() {
        use crate::events::{Sink, SinkFailed};
        struct Dead;
        impl Sink for Dead {
            fn name(&self) -> &'static str {
                "ui"
            }
            fn deliver(&mut self, _: &Event) -> Result<(), SinkFailed> {
                Err(SinkFailed)
            }
        }
        let host = Host::new();
        let b = Built::new(0, "1.0.0", true);
        let (pipes, reader) = FakePipes::new();
        let elevation = RunsTheMode {
            host: &host,
            built: &b,
            standing: Standing::UacElevated,
            calls: Mutex::new(Vec::new()),
            pipes,
            script: Mutex::new(Vec::new()),
        };
        let connector = ReaderConnector(Mutex::new(Some(reader)));
        let own = abs_path("/dl/setup.exe");
        let h = HandOff {
            elevation: &elevation,
            connector: &connector,
            rng: &FakeRng::new(3),
            own_exe: &own,
            sid: SID,
        };
        let events = Events::new(None, Some(Box::new(Dead)));
        let app = AppId::parse(lunepack_testkit::SUITE_APP_ID).unwrap();
        let installed = || {
            matches!(
                find(&host.mem, &FakeHasher, &host.home, &app, "Hello"),
                Machine::Present(..)
            )
        };
        assert_eq!(hand_off(&h, &events, &installed), Ok(()));
        events.finish(Duration::from_secs(1));
        assert!(installed());
    }
}
