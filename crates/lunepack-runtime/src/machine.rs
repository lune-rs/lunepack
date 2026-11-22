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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lunepack::{FileKind, Phase, Process, Progress, Version};
use lunepack_core::engine::{InstallRequest, Installed, MachineOpError, Ports, install};
use lunepack_core::limits::Limits;
use lunepack_core::setup::{
    ReadAtWindow, SetupAnchor, SetupPart, VerifiedSetup, verify_setup_anchored,
};
use lunepack_core::state::MachineStore;
use lunepack_core::{
    AppId, Clock, ClockReading, Codec, DirClass, Elevated, Elevation, Fs, FsError, FsErrorKind,
    Hasher, LayoutScheme, MachineLayout, PolicySource, Protect, ReadAt, Rng, RootChoice, Scope,
    ServiceConnector, Standing, Verifier, resolve_root_scoped, root_valid_for_uninstall,
};

use crate::events::{Event, Events};
use crate::modes::{
    Kind, MACHINE_INSTALL, MACHINE_REPAIR, MACHINE_UNINSTALL, MachineArgs, SetupArgs,
};
use crate::relay::{EventConnector, RelaySink};
use crate::setup::Found;

/// How long the elevated copy waits for the unelevated setup to open its pipe before it goes on
/// without a reader.
pub const ACCEPT_WAIT: Duration = Duration::from_secs(30);
/// The name of the folder the payload is copied into, before the 32 hex characters of its id.
pub const PAYLOAD_PREFIX: &str = ".lunepack-install-";
/// The copied pack's file name in that folder.
pub const PACK_FILE: &str = "pack";
/// The lock file in that folder: held by the run that made the folder for as long as it lives, so
/// a later run can tell a folder whose run is gone (F1).
pub const PAYLOAD_LOCK: &str = "lock";
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

/// The folder a payload is copied into, with its lock held; removed when this is dropped (the
/// engine removes it as well when it runs), the lock released first.
struct PayloadDir<'a> {
    fs: &'a dyn Fs,
    path: PathBuf,
    lock: Option<Box<dyn lunepack_core::LockGuard>>,
}

impl Drop for PayloadDir<'_> {
    fn drop(&mut self) {
        drop(self.lock.take());
        let _ = self.fs.remove_dir_all_nofollow(&self.path);
    }
}

/// Removes the payload folders earlier runs left under the machine home when one was cut off (a
/// crash, a power loss, a reboot, F1): each real directory named `.lunepack-install-<32 lowercase
/// hex>` whose lock file is a regular file that can be taken, so the run that made it is gone. A
/// folder whose run is alive, or that has no lock file yet (made a moment ago), is left. Exempt from
/// the removal guard (M10-D20): the folders are admin-only and no path into one is handed out.
fn sweep_payload_dirs(base: &Base<'_>) {
    let Ok(entries) = base.fs.list_dir(base.home) else {
        return;
    };
    for entry in entries {
        let named = entry
            .name
            .to_str()
            .and_then(|n| n.strip_prefix(PAYLOAD_PREFIX))
            .is_some_and(crate::modes::is_events_id);
        if entry.kind != FileKind::Dir || !named {
            continue;
        }
        let dir = base.home.join(&entry.name);
        let lock = dir.join(PAYLOAD_LOCK);
        let is = |p: &Path, kind: FileKind| matches!(base.fs.symlink_metadata(p), Ok(Some(m)) if m.kind == kind);
        if !is(&dir, FileKind::Dir) || !is(&lock, FileKind::File) {
            continue;
        }
        if let Ok(Some(guard)) = base.fs.try_lock(&lock) {
            drop(guard);
            let _ = base.fs.remove_dir_all_nofollow(&dir);
        }
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

    sweep_payload_dirs(base);
    let mut id = [0u8; 16];
    base.rng.fill(&mut id).map_err(|_| Kind::Internal)?;
    let path = base.home.join(format!("{PAYLOAD_PREFIX}{}", hex(&id)));
    base.protect
        .create_dir(&path, DirClass::AdminOnly)
        .map_err(|_| Kind::NotProtected)?;
    let mut dir = PayloadDir {
        fs: base.fs,
        path: path.clone(),
        lock: None,
    };
    // The lock file is made first and held for the folder's life (an adapter need not create it).
    let lock_path = path.join(PAYLOAD_LOCK);
    drop(base.fs.create_new(&lock_path).map_err(|_| Kind::Fs)?);
    dir.lock = Some(
        base.fs
            .try_lock(&lock_path)
            .ok()
            .flatten()
            .ok_or(Kind::Fs)?,
    );

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

// ---- repair and uninstall of an installed machine tree (M10 step 18) -------------------------

/// How long phase 2 of the machine uninstall waits for phase 1 to exit before it goes on (the
/// engine's removal guard then decides).
pub const SECOND_WAIT: Duration = Duration::from_secs(10);
/// How long the unelevated side follows phase 2 through its pipe before it judges the result by
/// the machine record alone.
pub const SECOND_LIMIT: Duration = Duration::from_secs(10 * 60);
/// The prefix of the folder phase 1 copies the runtime into, before the 32 hex characters of its id.
pub const UNINSTALL_PREFIX: &str = ".lunepack-uninstall-";
/// The runtime's file name in that folder.
pub const UNINSTALL_COPY: &str = "lunepack-runtime.exe";
/// The marker's file name in that folder.
pub const UNINSTALL_MARKER: &str = "marker";
/// The most bytes of a marker read.
const MARKER_MAX: u64 = 4096;
/// The first line of a marker.
const MARKER_HEAD: &str = "lunepack-uninstall 1";

/// The one-shot operations of the engine and the process effects of the elevated modes: the
/// Windows adapters on Windows, a fake in tests.
pub trait Ops: Send + Sync {
    /// The engine's `repair` of the install at `root`, whose service is registered under `name`.
    fn repair(&self, root: &Path, name: &str) -> Result<Version, Kind>;
    /// The engine's `uninstall` of the install at `root`.
    fn uninstall(&self, root: &Path, name: &str) -> Result<(), Kind>;
    /// Makes `dir` this process's working directory (so nothing of this process stays in `R`).
    fn enter(&self, dir: &Path) -> bool;
    /// Registers `path` (a file, or a folder that is empty by then) for deletion at the next
    /// restart of the system.
    fn delete_at_restart(&self, path: &Path) -> bool;
}

/// What an unelevated process hands the work of `repair` and `uninstall` to.
pub struct Host<'a> {
    /// The system's elevation.
    pub elevation: &'a dyn Elevation,
    /// The engine's one-shot operations, for a process that is an administrator's already.
    pub ops: &'a dyn Ops,
    /// Opens an elevated child's pipe.
    pub pipes: &'a dyn EventConnector,
    /// The install's update service.
    pub service: &'a dyn ServiceConnector,
    /// The administrator's policy.
    pub policy: &'a dyn PolicySource,
    /// The ids of pipes come from here.
    pub rng: &'a dyn Rng,
    /// The user's SID, as text: the one account that may read an elevated child's pipe.
    pub sid: Option<&'a str>,
}

/// Whether an administrator's policy makes the runtime of the install of `app_id` headless
/// (`NoUpdateUi`, M10-D12), as `LUNEPACK_NO_UI` does for every install: only a machine install is
/// ruled by the policy of its machine.
pub fn no_update_ui(is_machine: bool, policy: &dyn PolicySource, app_id: &AppId) -> bool {
    is_machine && policy.read(app_id).no_update_ui
}

/// Whether `a` is the directory `b` (as paths; on Windows without regard to case).
fn same_dir(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    } else {
        a == b
    }
}

/// The install root `R` and the version tree the runtime image at `exe` stands in:
/// `<home>\<R>\app\<version>\…\<exe>`, `R` directly in the machine home. Pure path logic; nothing
/// is read.
pub fn tree_of(exe: &Path, home: &Path) -> Option<(PathBuf, PathBuf)> {
    for tree in exe.ancestors().skip(1) {
        let Some(app) = tree.parent() else {
            continue;
        };
        let is_app = app
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("app"));
        if !is_app {
            continue;
        }
        let root = app.parent()?;
        if root.parent().is_some_and(|p| same_dir(p, home))
            && root
                .file_name()
                .is_some_and(|n| n.as_encoded_bytes().first() != Some(&b'.'))
        {
            return Some((root.to_path_buf(), tree.to_path_buf()));
        }
        return None;
    }
    None
}

/// The machine install an elevated runtime stands in, as its own files and the machine record say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    /// The install root `R`.
    pub root: PathBuf,
    /// The app.
    pub app_id: AppId,
    /// The display name: the service is registered under it.
    pub name: String,
    /// The tree's own version.
    pub version: Version,
}

/// Finds the install the runtime image at `exe` belongs to, from its own path, its tree's update
/// configuration and the machine record (never from an argument or the environment): `exe` is in
/// `<home>\<R>\app\<version>\`, `R` is a real directory directly in the machine home, and the
/// record of the app named by the tree's configuration lives in `R`. Anything else is refused
/// before any effect: `usage` for a place that is no machine tree, `install_mismatch` for one that
/// is not the install the machine record knows.
pub fn locate(fs: &dyn Fs, hasher: &dyn Hasher, home: &Path, exe: &Path) -> Result<Located, Kind> {
    let (root, tree) = tree_of(exe, home).ok_or(Kind::Usage)?;
    let version = tree
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| Version::parse(n).ok().filter(|v| v.to_string() == n))
        .ok_or(Kind::Usage)?;
    let mut config_path = tree.clone();
    for part in LayoutScheme::WINDOWS.config.split('/') {
        config_path.push(part);
    }
    let bytes = fs
        .read_capped(
            &config_path,
            lunepack_core::update_config::MAX_UPDATE_CONFIG_BYTES,
        )
        .map_err(|_| Kind::UpdateConfig)?;
    let config = lunepack::UpdateConfig::parse(&bytes).map_err(|_| Kind::UpdateConfig)?;
    if config.version != version || config.version.to_string() != version.to_string() {
        return Err(Kind::UpdateConfig);
    }
    let name = config.install.name.clone();
    match find(fs, hasher, home, &config.app_id, &name) {
        Machine::Present(found, _) if same_dir(&found, &root) => {}
        _ => return Err(Kind::InstallMismatch),
    }
    if !root_valid_for_uninstall(fs, home, &root, &config.app_id, LayoutScheme::WINDOWS) {
        return Err(Kind::InstallMismatch);
    }
    Ok(Located {
        root,
        app_id: config.app_id,
        name,
        version,
    })
}

/// The hidden `machine-repair` mode: the engine's `repair` for the install the image stands in,
/// in an elevated process (an unelevated one is a usage error). The arguments of the mode have the
/// shape of `machine-install`'s and name nothing this mode uses: its result is its exit code.
pub fn run_repair_mode(
    ops: &dyn Ops,
    fs: &dyn Fs,
    hasher: &dyn Hasher,
    home: &Path,
    standing: Standing,
    exe: &Path,
) -> Kind {
    if standing == Standing::Standard {
        return Kind::Usage;
    }
    let located = match locate(fs, hasher, home, exe) {
        Ok(located) => located,
        Err(kind) => return kind,
    };
    match ops.repair(&located.root, &located.name) {
        Ok(_) => Kind::Ok,
        Err(kind) => kind,
    }
}

/// What the unelevated side of `repair` and `uninstall` knows of the install.
#[derive(Debug, Clone)]
pub struct Site {
    /// The install root `R`.
    pub root: PathBuf,
    /// The app.
    pub app_id: AppId,
    /// The display name.
    pub name: String,
    /// The runtime of the install's current version inside `R`: the elevated image.
    pub runtime: PathBuf,
}

/// The unelevated side's view of the machine install `inst` is a version of: `None` when it is
/// not one. The elevated image is the runtime of the record's current version inside `R`, which
/// nobody but an administrator can have written; the running tree's own is the fallback.
pub fn target_of(fs: &dyn Fs, hasher: &dyn Hasher, inst: &lunepack::Installation) -> Option<Site> {
    let layout = inst.machine_layout()?;
    let store = MachineStore {
        dir: layout.state_dir(),
        app_id: inst.app_id().clone(),
    };
    let current = store
        .load(fs, hasher)
        .ok()
        .and_then(|loaded| loaded.record)
        .and_then(|record| record.current)
        .and_then(|c| inst.version_installation(&c.version).ok());
    Some(Site {
        root: layout.root().to_path_buf(),
        app_id: inst.app_id().clone(),
        name: inst.meta().name.clone(),
        runtime: current
            .as_ref()
            .map_or_else(|| inst.runtime_path(), |c| c.runtime_path()),
    })
}

fn elevated_args(mode: &str, id: &str, sid: &str) -> [String; 5] {
    [
        mode.to_owned(),
        "--events".to_owned(),
        id.to_owned(),
        "--for-sid".to_owned(),
        sid.to_owned(),
    ]
}

/// Starts `target.runtime` elevated in `mode` with a fresh pipe id and waits for its exit code.
fn run_elevated_mode(host: &Host<'_>, target: &Site, mode: &str) -> Result<(String, i32), Kind> {
    let sid = host.sid.ok_or(Kind::Process)?;
    let mut raw = [0u8; 16];
    host.rng.fill(&mut raw).map_err(|_| Kind::Internal)?;
    let id = hex(&raw);
    let mut child = match host
        .elevation
        .run_elevated(&target.runtime, &elevated_args(mode, &id, sid))
    {
        Ok(Elevated::Started(child)) => child,
        Ok(Elevated::Declined) => return Err(Kind::ElevationDeclined),
        Err(_) => return Err(Kind::Process),
    };
    let code = child.wait().map_err(|_| Kind::Process)?;
    Ok((id, code))
}

/// `repair` (M10-D13): an administrator's process (`Admin`, `UacElevated`) runs the engine's
/// `repair` itself; a standard user's asks for the system's elevation and has the runtime of the
/// current version inside `R` run `machine-repair`, the result being its exit code. With `silent`
/// a standard user's run exits `elevation_required` and nothing is asked.
pub fn repair(host: &Host<'_>, target: &Site, silent: bool) -> Result<(), Kind> {
    match host.elevation.standing() {
        Standing::Admin | Standing::UacElevated => {
            host.ops.repair(&target.root, &target.name).map(|_| ())
        }
        Standing::Standard if silent => Err(Kind::ElevationRequired),
        Standing::Standard => {
            let (_, code) = run_elevated_mode(host, target, MACHINE_REPAIR)?;
            match Kind::from_exit_code(code) {
                Kind::Ok => Ok(()),
                kind => Err(kind),
            }
        }
    }
}

/// The marker phase 1 of the uninstall leaves in its folder: what phase 2 does is derived from it
/// and from the machine record, never from its own arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    /// The app.
    pub app_id: AppId,
    /// The display name.
    pub name: String,
    /// The install root to remove.
    pub root: PathBuf,
    /// The id of the pipe phase 2 reports into.
    pub events: String,
    /// The account that may read that pipe.
    pub sid: String,
}

impl Marker {
    fn encode(&self) -> Option<String> {
        let root = self.root.to_str()?;
        let plain = |t: &str| !t.is_empty() && !t.chars().any(char::is_control);
        (plain(&self.name) && plain(root)).then(|| {
            format!(
                "{MARKER_HEAD}\napp {}\nname {}\nroot {root}\nevents {}\nsid {}\n",
                self.app_id.as_str(),
                self.name,
                self.events,
                self.sid
            )
        })
    }

    /// The marker of `text`; `None` for anything but exactly the lines `encode` writes, each value
    /// of its form.
    pub fn parse(text: &str) -> Option<Marker> {
        let mut lines = text.strip_suffix('\n')?.split('\n');
        if lines.next()? != MARKER_HEAD {
            return None;
        }
        let mut value = |key: &str| -> Option<String> {
            lines
                .next()?
                .strip_prefix(key)?
                .strip_prefix(' ')
                .filter(|v| !v.is_empty() && !v.chars().any(char::is_control))
                .map(str::to_owned)
        };
        let app_id = AppId::parse(&value("app")?).ok()?;
        let name = value("name")?;
        let root = PathBuf::from(value("root")?);
        let events = value("events")?;
        let sid = value("sid")?;
        if lines.next().is_some()
            || !root.is_absolute()
            || !crate::modes::is_events_id(&events)
            || !crate::modes::is_sid_text(&sid)
        {
            return None;
        }
        Some(Marker {
            app_id,
            name,
            root,
            events,
            sid,
        })
    }
}

/// Phase 1 of the machine uninstall (the hidden `machine-uninstall` mode with `--events` and
/// `--for-sid`), run elevated from the runtime inside `R`: that image cannot be deleted while it
/// runs, so it copies itself into a new admin-only folder `.lunepack-uninstall-<32 hex>` directly
/// under the machine home with a marker naming the install, makes that folder its working
/// directory, starts the copy with the wait arguments only (nothing from the command line or the
/// environment) and ends. It deletes nothing and starts nothing from a place a standard user can
/// write. Any failure removes the folder.
pub fn run_uninstall_start(
    base: &Base<'_>,
    ops: &dyn Ops,
    process: &dyn Process,
    standing: Standing,
    args: &MachineArgs,
    exe: &Path,
) -> Kind {
    if standing == Standing::Standard {
        return Kind::Usage;
    }
    let located = match locate(base.fs, base.hasher, base.home, exe) {
        Ok(located) => located,
        Err(kind) => return kind,
    };
    let Ok(me) = process.current() else {
        return Kind::Process;
    };
    let marker = Marker {
        app_id: located.app_id,
        name: located.name,
        root: located.root,
        events: args.events.clone(),
        sid: args.for_sid.clone(),
    };
    let Some(text) = marker.encode() else {
        return Kind::UpdateConfig;
    };
    let mut raw = [0u8; 16];
    if base.rng.fill(&mut raw).is_err() {
        return Kind::Internal;
    }
    let dir = base.home.join(format!("{UNINSTALL_PREFIX}{}", hex(&raw)));
    if base.protect.create_dir(&dir, DirClass::AdminOnly).is_err() {
        return Kind::NotProtected;
    }
    let started = (|| {
        let copy = dir.join(UNINSTALL_COPY);
        base.fs.copy_file(exe, &copy).map_err(|_| Kind::Fs)?;
        let mut out = base
            .fs
            .create_new(&dir.join(UNINSTALL_MARKER))
            .map_err(|_| Kind::Fs)?;
        out.write_all(text.as_bytes()).map_err(|_| Kind::Fs)?;
        out.sync().map_err(|_| Kind::Fs)?;
        drop(out);
        // The copy inherits this directory, not one inside `R`.
        if !ops.enter(&dir) {
            return Err(Kind::Fs);
        }
        let mut spec = lunepack::SpawnSpec::new(copy);
        spec.args = vec![
            MACHINE_UNINSTALL.into(),
            "--wait-pid".into(),
            me.pid.to_string().into(),
            "--wait-start".into(),
            me.start_ticks.to_string().into(),
        ];
        spec.env_remove = vec![std::ffi::OsString::from(lunepack::HEALTH_TOKEN_VAR)];
        process.spawn_detached(&spec).map_err(|_| Kind::Process)
    })();
    match started {
        Ok(()) => Kind::Ok,
        Err(kind) => {
            let _ = base.fs.remove_dir_all_nofollow(&dir);
            kind
        }
    }
}

/// How `uninstall` of a machine install leaves `R` (M10-D19, S1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UninstallRoute {
    /// A standard user's process: the hand-off through a copy in the user's temp folder, which
    /// asks, then has the system's elevation run the runtime inside `R`. Nothing elevated runs
    /// from that copy's folder.
    TempHandOff,
    /// A process with an administrator's token (`Admin`, `UacElevated`): no copy in the user's
    /// temp folder, which the administrator's unelevated processes can write, and no UI. This
    /// process runs phase 1 itself ([`uninstall_in_place`]), headless, and ends.
    InPlace,
}

/// The route of `uninstall` of a machine install for a process of `standing`.
pub fn uninstall_route(standing: Standing) -> UninstallRoute {
    match standing {
        Standing::Standard => UninstallRoute::TempHandOff,
        Standing::Admin | Standing::UacElevated => UninstallRoute::InPlace,
    }
}

/// The machine uninstall of an administrator's process, from the runtime inside `R` (`exe`): phase
/// 1 ([`run_uninstall_start`]) in this process, with a fresh pipe id and this account's SID
/// (`sid`), so its copy goes into an admin-only folder under the machine home and phase 2 waits
/// for this process to end before anything is removed. Headless: no prompt and no UI (S1). A
/// standard user's process is refused (usage) before any effect.
pub fn uninstall_in_place(
    base: &Base<'_>,
    ops: &dyn Ops,
    process: &dyn Process,
    standing: Standing,
    sid: &str,
    exe: &Path,
) -> Kind {
    if uninstall_route(standing) != UninstallRoute::InPlace {
        return Kind::Usage;
    }
    let mut raw = [0u8; 16];
    if base.rng.fill(&mut raw).is_err() {
        return Kind::Internal;
    }
    let args = MachineArgs {
        events: hex(&raw),
        for_sid: sid.to_owned(),
    };
    run_uninstall_start(base, ops, process, standing, &args, exe)
}

/// Phase 2's own-folder rule: `exe` is the runtime copy directly inside a real, admin-only folder
/// `.lunepack-uninstall-<32 lowercase hex>` directly under the machine home, which holds a
/// marker. The folder, or `None` anywhere else (a usage error before any action).
pub fn own_folder(fs: &dyn Fs, protect: &dyn Protect, home: &Path, exe: &Path) -> Option<PathBuf> {
    let dir = exe.parent()?;
    let name = dir.file_name()?.to_str()?;
    let id = name.strip_prefix(UNINSTALL_PREFIX)?;
    let exe_ok = exe
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case(UNINSTALL_COPY));
    if !exe_ok
        || !crate::modes::is_events_id(id)
        || !dir.parent().is_some_and(|p| same_dir(p, home))
    {
        return None;
    }
    let is = |path: &Path, kind: FileKind| matches!(fs.symlink_metadata(path), Ok(Some(m)) if m.kind == kind);
    (is(dir, FileKind::Dir)
        && is(&dir.join(UNINSTALL_MARKER), FileKind::File)
        && protect.check(dir, DirClass::AdminOnly).is_ok())
    .then(|| dir.to_path_buf())
}

/// A pipe end shared by the events sink and the final `end` line.
#[derive(Clone)]
struct Shared(Arc<Mutex<Box<dyn Write + Send>>>);

impl Write for Shared {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("poisoned"))?
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("poisoned"))?
            .flush()
    }
}

/// Phase 2 of the machine uninstall (the hidden `machine-uninstall` mode with the wait arguments),
/// run elevated from its own folder: the own-folder rule first (a usage error, nothing done), the
/// marker next, then the wait for phase 1, the pipe the unelevated side reads, the re-validation of
/// the install the marker names against the machine record (`install_mismatch` when it is not a
/// valid machine install: nothing is removed), and the engine's `uninstall`. The folder is
/// registered for deletion at restart whatever the result, and the exit code is written to the pipe
/// last. The unelevated side judges success by the record and takes the code as advice.
#[allow(clippy::too_many_arguments)]
pub fn run_uninstall_second(
    base: &Base<'_>,
    ops: &dyn Ops,
    process: &dyn Process,
    pipes: &dyn EventPipes,
    standing: Standing,
    wait: &lunepack::ProcessId,
    exe: &Path,
    accept: Duration,
) -> Kind {
    if standing == Standing::Standard {
        return Kind::Usage;
    }
    let Some(dir) = own_folder(base.fs, base.protect, base.home, exe) else {
        return Kind::Usage;
    };
    let marker = base
        .fs
        .read_capped(&dir.join(UNINSTALL_MARKER), MARKER_MAX)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|text| Marker::parse(&text));
    let Some(marker) = marker else {
        return Kind::InstallMismatch;
    };
    // Nothing of this process stays in `R` (the strict removal guard sees a working directory).
    if !ops.enter(&dir) {
        return Kind::Fs;
    }
    // A timeout or an unreadable process is not an error here: the removal guard decides.
    let _ = process.wait_exit(wait, SECOND_WAIT);
    let writer = match pipes.open(&marker.events, &marker.sid, accept) {
        Ok(writer) => writer.map(|w| Shared(Arc::new(Mutex::new(w)))),
        Err(PipeFail::InvalidSid) => return Kind::Usage,
        // The uninstall does not depend on a reader.
        Err(PipeFail::Failed) => None,
    };
    let events = Events::new(
        None,
        writer
            .clone()
            .map(|w| Box::new(RelaySink::new(Box::new(w))) as Box<dyn crate::events::Sink>),
    );
    events.emit(&Event::phase(Phase::Uninstall, None));
    let valid = matches!(
        find(base.fs, base.hasher, base.home, &marker.app_id, &marker.name),
        Machine::Present(found, _) if same_dir(&found, &marker.root)
    ) && root_valid_for_uninstall(
        base.fs,
        base.home,
        &marker.root,
        &marker.app_id,
        LayoutScheme::WINDOWS,
    );
    let kind = if valid {
        match ops.uninstall(&marker.root, &marker.name) {
            Ok(()) => Kind::Ok,
            Err(kind) => kind,
        }
    } else {
        Kind::InstallMismatch
    };
    // Files first, then the folder: the system processes them in this order at the restart.
    for path in [exe, &dir.join(UNINSTALL_MARKER), &dir] {
        let _ = ops.delete_at_restart(path);
    }
    events.finish(Duration::from_secs(2));
    if let Some(mut writer) = writer {
        crate::relay::write_end(&mut writer, kind.code());
    }
    kind
}

/// What the unelevated side of `uninstall` does after the user confirmed: has the runtime inside
/// `R` run `machine-uninstall` elevated (always through the system's elevation, whatever this
/// process's standing: this process is a copy outside `R`, and the engine is not run from here),
/// follows phase 2 through its pipe, and judges the result by the machine record: the install
/// being gone is success. With `silent` a standard user's run exits `elevation_required` and
/// nothing is asked. The caller removes this user's own home afterwards.
pub fn uninstall(
    host: &Host<'_>,
    fs: &dyn Fs,
    hasher: &dyn Hasher,
    home: &Path,
    target: &Site,
    silent: bool,
    events: &Events,
) -> Result<(), Kind> {
    if host.elevation.standing() == Standing::Standard && silent {
        return Err(Kind::ElevationRequired);
    }
    let (id, code) = run_elevated_mode(host, target, MACHINE_UNINSTALL)?;
    match Kind::from_exit_code(code) {
        Kind::Ok => {}
        kind => return Err(kind),
    }
    // Phase 1 only started phase 2: its progress, and its end, come through the pipe.
    let (_, end) = crate::relay::relay_to_the_end(host.pipes, &id, events, SECOND_LIMIT);
    match find(fs, hasher, home, &target.app_id, &target.name) {
        Machine::Absent => Ok(()),
        _ => Err(match end.map(|c| Kind::from_exit_code(i32::from(c))) {
            Some(Kind::Ok) => Kind::State,
            Some(kind) => kind,
            None => Kind::Process,
        }),
    }
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
    use lunepack::Version;
    use lunepack_codec_lzma::LzmaCodec;
    use lunepack_core::engine::{Engine, Installed, MachineOpError, Ports};
    use lunepack_core::service::Duplex;
    use lunepack_crypto::{Ed25519Verifier, OsRng, Sha256Hasher};
    use lunepack_fs::StdFs;
    use lunepack_os_windows::{
        ExpectedOwner, PipeAccess, PipeClient, PipeError, PipeServer, RegistryPolicy,
        WinPublisherCheck, WinScope, WindowsIntegration, WindowsProcess, WindowsProtect,
        WindowsRegistrar, program_files,
    };

    use super::{EventPipes, Installer, Ops, PipeFail, Staged, install_staged, kind_of};
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

    /// The engine's one-shot operations and the process effects of the elevated modes, over the
    /// Windows adapters. `enter` is the one thing this module does not do itself: it makes a
    /// directory the working directory (the composition root passes it in).
    pub struct NativeOps {
        /// Makes the directory this process's working directory.
        pub enter: fn(&Path) -> bool,
    }

    impl Ops for NativeOps {
        fn repair(&self, root: &Path, name: &str) -> Result<Version, Kind> {
            let adapters = Adapters::new(name).ok_or(Kind::Internal)?;
            let engine = Engine::open(adapters.ports(), root)
                .map_err(|e| kind_of(MachineOpError::from(e)))?;
            engine.repair().map_err(kind_of)
        }

        fn uninstall(&self, root: &Path, name: &str) -> Result<(), Kind> {
            let adapters = Adapters::new(name).ok_or(Kind::Internal)?;
            let engine = Engine::open(adapters.ports(), root)
                .map_err(|e| kind_of(MachineOpError::from(e)))?;
            engine.uninstall().map_err(kind_of)
        }

        fn enter(&self, dir: &Path) -> bool {
            (self.enter)(dir)
        }

        fn delete_at_restart(&self, path: &Path) -> bool {
            lunepack_os_windows::delete_at_restart(path).is_ok()
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

    use lunepack::ProcessId;
    use lunepack::{Channel, InstallMeta, RelPath, Target, UpdateConfig};
    use lunepack_core::ServiceRegistrar as _;
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
    fn payload_folders_of_runs_that_are_gone_are_swept_before_a_copy() {
        use lunepack_core::Fs as _;
        let host = Host::new();
        let folder = |n: u8| host.home.join(format!("{PAYLOAD_PREFIX}{}", hex(&[n; 16])));
        // A run cut off (its lock free), a run still copying (its lock held), a folder made a
        // moment ago (no lock file yet), and a name that is not a payload folder's.
        for n in [1u8, 2, 3] {
            host.mem.create_dir_all(&folder(n)).unwrap();
        }
        let mut pack = host.mem.create_new(&folder(1).join(PACK_FILE)).unwrap();
        pack.write_all(b"half a pack").unwrap();
        drop(pack);
        for n in [1u8, 2] {
            drop(host.mem.create_new(&folder(n).join(PAYLOAD_LOCK)).unwrap());
        }
        let held = host
            .mem
            .try_lock(&folder(2).join(PAYLOAD_LOCK))
            .unwrap()
            .unwrap();
        let other = host.home.join(format!("{PAYLOAD_PREFIX}not-hex"));
        host.mem.create_dir_all(&other).unwrap();

        let b = Built::new(0, "1.0.0", true);
        let (events, _) = collecting();
        let staged = stage_payload(&host.base(), &b.found(), &b.anchor(), &events).expect("staged");
        let exists = |p: &Path| host.mem.symlink_metadata(p).unwrap().is_some();
        assert!(!exists(&folder(1)), "the cut-off run's folder is gone");
        assert!(exists(&folder(2)), "a live run's folder stays");
        assert!(exists(&folder(3)), "a folder without its lock yet stays");
        assert!(exists(&other));
        // This run's own folder holds its lock while it lives: a second sweep leaves it.
        let mine = staged.dir.path.clone();
        sweep_payload_dirs(&host.base());
        assert!(exists(&mine));
        drop(staged);
        assert!(!exists(&mine));
        drop(held);
    }

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

    // ---- repair and uninstall of an installed machine tree (M10 step 18) ----------------------

    /// A machine install of 1.0.0 made by the engine over the host's fakes, and the runtime image
    /// inside its tree.
    fn installed(host: &Host) -> PathBuf {
        let b = Built::new(0, "1.0.0", true);
        let (events, _) = collecting();
        let staged = stage_payload(&host.base(), &b.found(), &b.anchor(), &events).expect("staged");
        install_staged(host.ports(), &host.home, &staged).expect("installed");
        drop(staged);
        let exe = host.home.join("Hello/app/1.0.0").join(UNINSTALL_COPY);
        let mut w = host.mem.create_new(&exe).expect("runtime");
        w.write_all(b"runtime").expect("write");
        w.sync().expect("sync");
        exe
    }

    /// The engine's operations over the host's fakes, recording the effects the elevated modes
    /// ask of their process.
    struct EngineOps<'h> {
        host: &'h Host,
        entered: Mutex<Vec<PathBuf>>,
        deleted: Mutex<Vec<PathBuf>>,
        engine_calls: Mutex<Vec<&'static str>>,
    }

    impl<'h> EngineOps<'h> {
        fn new(host: &'h Host) -> Self {
            EngineOps {
                host,
                entered: Mutex::new(Vec::new()),
                deleted: Mutex::new(Vec::new()),
                engine_calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Ops for EngineOps<'_> {
        fn repair(&self, root: &Path, _: &str) -> Result<Version, Kind> {
            self.engine_calls.lock().unwrap().push("repair");
            let engine = lunepack_core::engine::Engine::open(self.host.ports(), root)
                .map_err(|e| kind_of(MachineOpError::from(e)))?;
            engine.repair().map_err(kind_of)
        }

        fn uninstall(&self, root: &Path, _: &str) -> Result<(), Kind> {
            self.engine_calls.lock().unwrap().push("uninstall");
            let engine = lunepack_core::engine::Engine::open(self.host.ports(), root)
                .map_err(|e| kind_of(MachineOpError::from(e)))?;
            engine.uninstall().map_err(kind_of)
        }

        fn enter(&self, dir: &Path) -> bool {
            self.entered.lock().unwrap().push(dir.to_path_buf());
            true
        }

        fn delete_at_restart(&self, path: &Path) -> bool {
            self.deleted.lock().unwrap().push(path.to_path_buf());
            true
        }
    }

    fn app_id() -> AppId {
        AppId::parse(lunepack_testkit::SUITE_APP_ID).unwrap()
    }

    #[test]
    fn the_root_and_tree_of_a_runtime_are_found_only_directly_under_the_machine_home() {
        let home = abs_path("/pf");
        let exe = |p: &str| abs_path(p);
        let (root, tree) = tree_of(&exe("/pf/Hello/app/1.0.0/rt.exe"), &home).expect("tree");
        assert_eq!(root, abs_path("/pf/Hello"));
        assert_eq!(tree, abs_path("/pf/Hello/app/1.0.0"));
        // The runtime beside a nested entry.
        let (root, tree) = tree_of(&exe("/pf/Hello/app/1.0.0/bin/rt.exe"), &home).expect("tree");
        assert_eq!(
            (root, tree),
            (abs_path("/pf/Hello"), abs_path("/pf/Hello/app/1.0.0"))
        );
        for bad in [
            "/pf/app/1.0.0/rt.exe",
            "/pf/Hello/sub/app/1.0.0/rt.exe",
            "/elsewhere/Hello/app/1.0.0/rt.exe",
            "/pf/.hidden/app/1.0.0/rt.exe",
            "/pf/Hello/versions/1.0.0/rt.exe",
            "/pf/Hello/rt.exe",
        ] {
            assert_eq!(tree_of(&exe(bad), &home), None, "{bad}");
        }
    }

    #[test]
    fn a_runtime_is_located_by_its_own_files_and_the_machine_record_or_refused() {
        let host = Host::new();
        let exe = installed(&host);
        let located = locate(&host.mem, &FakeHasher, &host.home, &exe).expect("located");
        assert_eq!(located.root, host.home.join("Hello"));
        assert_eq!(located.name, "Hello");
        assert_eq!(located.app_id, app_id());
        assert_eq!(located.version.to_string(), "1.0.0");
        // A place that is no machine tree: usage, nothing read.
        let other = abs_path("/dl/rt.exe");
        assert_eq!(
            locate(&host.mem, &FakeHasher, &host.home, &other),
            Err(Kind::Usage)
        );
        // A tree in the home without a machine record of the app: not the install.
        let stray = host.home.join("Other/app/1.0.0");
        host.mem.create_dir_all(&stray).unwrap();
        let config = host
            .mem
            .read_capped(
                &host.home.join("Hello/app/1.0.0").join(UPDATE_CONFIG_FILE),
                1 << 16,
            )
            .unwrap();
        let mut w = host
            .mem
            .create_new(&stray.join(UPDATE_CONFIG_FILE))
            .unwrap();
        w.write_all(&config).unwrap();
        w.sync().unwrap();
        assert_eq!(
            locate(
                &host.mem,
                &FakeHasher,
                &host.home,
                &stray.join(UNINSTALL_COPY)
            ),
            Err(Kind::InstallMismatch)
        );
        // A tree whose version directory does not name its config's version.
        let renamed = host.home.join("Hello/app/9.9.9");
        host.mem.create_dir_all(&renamed).unwrap();
        let mut w = host
            .mem
            .create_new(&renamed.join(UPDATE_CONFIG_FILE))
            .unwrap();
        w.write_all(&config).unwrap();
        w.sync().unwrap();
        assert_eq!(
            locate(
                &host.mem,
                &FakeHasher,
                &host.home,
                &renamed.join(UNINSTALL_COPY)
            ),
            Err(Kind::UpdateConfig)
        );
    }

    fn target(host: &Host) -> Site {
        Site {
            root: host.home.join("Hello"),
            app_id: app_id(),
            name: "Hello".to_owned(),
            runtime: host.home.join("Hello/app/1.0.0").join(UNINSTALL_COPY),
        }
    }

    fn unelevated<'a>(
        elevation: &'a FakeElevation,
        ops: &'a EngineOps<'_>,
        pipes: &'a ReaderConnector,
        host: &'a Host,
        sid: Option<&'a str>,
    ) -> Host_<'a> {
        Host_ {
            elevation,
            ops,
            pipes,
            service: &NoService,
            policy: &host.policy,
            rng: &host.rng,
            sid,
        }
    }

    /// The unelevated side's host (the module's `Host` is the engine fixture's name in these tests).
    type Host_<'a> = super::Host<'a>;

    struct NoService;

    impl lunepack_core::ServiceConnector for NoService {
        fn connect(
            &self,
            _: &AppId,
        ) -> Result<Box<dyn lunepack_core::service::Duplex>, lunepack_core::ConnectError> {
            panic!("repair and uninstall never reach the update service")
        }
    }

    #[test]
    fn repair_in_each_standing_asks_only_a_standard_user_to_elevate() {
        for (standing, silent) in [
            (Standing::Admin, false),
            (Standing::UacElevated, false),
            (Standing::Admin, true),
            (Standing::UacElevated, true),
        ] {
            let host = Host::new();
            installed(&host);
            // The registration is gone; the engine's `repair` makes it again.
            host.registrar.remove(&app_id()).unwrap();
            assert_eq!(host.registrar.image(&app_id()).unwrap(), None);
            let elevation = FakeElevation::new(standing, []);
            let ops = EngineOps::new(&host);
            let (_, reader) = lunepack_testkit::mem_duplex();
            let pipes = ReaderConnector(Mutex::new(Some(reader)));
            let h = unelevated(&elevation, &ops, &pipes, &host, Some(SID));
            assert_eq!(repair(&h, &target(&host), silent), Ok(()), "{standing:?}");
            assert!(elevation.calls().is_empty(), "{standing:?}: no prompt");
            assert!(
                host.registrar.image(&app_id()).unwrap().is_some(),
                "{standing:?}"
            );
        }
        // A standard user: one prompt, the runtime of the current version, the hidden mode's
        // shape; the result is the child's exit code.
        for (script, want) in [
            (ElevationScript::Exit(0), Ok(())),
            (ElevationScript::Exit(25), Err(Kind::InUse)),
            (ElevationScript::Exit(35), Err(Kind::NotProtected)),
            (
                ElevationScript::Exit(0xC000_0005_u32 as i32),
                Err(Kind::Process),
            ),
            (ElevationScript::Declined, Err(Kind::ElevationDeclined)),
            (ElevationScript::Fails, Err(Kind::Process)),
        ] {
            let host = Host::new();
            installed(&host);
            let elevation = FakeElevation::new(Standing::Standard, [script]);
            let ops = EngineOps::new(&host);
            let (_, reader) = lunepack_testkit::mem_duplex();
            let pipes = ReaderConnector(Mutex::new(Some(reader)));
            let h = unelevated(&elevation, &ops, &pipes, &host, Some(SID));
            assert_eq!(repair(&h, &target(&host), false), want, "{script:?}");
            let calls = elevation.calls();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, target(&host).runtime);
            assert_eq!(calls[0].1[0], "machine-repair");
            assert_eq!(calls[0].1[1], "--events");
            assert!(crate::modes::is_events_id(&calls[0].1[2]));
            assert_eq!((&calls[0].1[3][..], &calls[0].1[4][..]), ("--for-sid", SID));
            // The unelevated side ran no engine operation of its own.
            assert!(ops.engine_calls.lock().unwrap().is_empty());
        }
        // `--silent` as a standard user: 30, and the prompt is never shown.
        let host = Host::new();
        installed(&host);
        let elevation = FakeElevation::new(Standing::Standard, [ElevationScript::Exit(0)]);
        let ops = EngineOps::new(&host);
        let (_, reader) = lunepack_testkit::mem_duplex();
        let pipes = ReaderConnector(Mutex::new(Some(reader)));
        let h = unelevated(&elevation, &ops, &pipes, &host, Some(SID));
        assert_eq!(
            repair(&h, &target(&host), true),
            Err(Kind::ElevationRequired)
        );
        assert!(elevation.calls().is_empty());
        // No SID to name the pipe's reader: nothing is asked.
        let h = unelevated(&elevation, &ops, &pipes, &host, None);
        assert_eq!(repair(&h, &target(&host), false), Err(Kind::Process));
        assert!(elevation.calls().is_empty());
    }

    #[test]
    fn the_elevated_repair_mode_is_for_administrators_and_for_an_install_it_finds() {
        let host = Host::new();
        let exe = installed(&host);
        let ops = EngineOps::new(&host);
        let run = |standing, exe: &Path| {
            run_repair_mode(&ops, &host.mem, &FakeHasher, &host.home, standing, exe)
        };
        assert_eq!(run(Standing::Standard, &exe), Kind::Usage);
        assert!(ops.engine_calls.lock().unwrap().is_empty());
        assert_eq!(
            run(Standing::UacElevated, &abs_path("/dl/rt.exe")),
            Kind::Usage
        );
        host.registrar.remove(&app_id()).unwrap();
        assert_eq!(run(Standing::UacElevated, &exe), Kind::Ok);
        assert!(host.registrar.image(&app_id()).unwrap().is_some());
        assert_eq!(run(Standing::Admin, &exe), Kind::Ok);
        // Not protected as it must be: the engine refuses and says so.
        host.protect.set_unprotected(&host.home.join("Hello"), true);
        assert_eq!(run(Standing::UacElevated, &exe), Kind::NotProtected);
    }

    #[test]
    fn a_marker_round_trips_and_nothing_else_parses() {
        let marker = Marker {
            app_id: app_id(),
            name: "My Hello App".to_owned(),
            root: abs_path("/pf/My Hello App"),
            events: ID.to_owned(),
            sid: SID.to_owned(),
        };
        let text = marker.encode().expect("encoded");
        assert_eq!(Marker::parse(&text), Some(marker.clone()));
        for bad in [
            String::new(),
            text.replace("lunepack-uninstall 1", "lunepack-uninstall 2"),
            text.replace("app ", "App "),
            text.trim_end().to_owned(),
            format!("{text}extra\n"),
            text.replace(ID, "short"),
            text.replace(SID, "not-a-sid"),
            text.replace(
                &format!("root {}", marker.root.display()),
                "root relative/dir",
            ),
            text.replace("name My Hello App", "name "),
            text.replace("name My Hello App", "name My\tHello"),
            text.replace("\nroot ", "\r\nroot "),
        ] {
            assert_ne!(bad, text, "the edit changed nothing");
            assert_eq!(Marker::parse(&bad), None, "{bad:?}");
        }
        // A name with a control character is not written at all.
        let mut odd = marker;
        odd.name = "a\nb".to_owned();
        assert_eq!(odd.encode(), None);
    }

    fn uninstall_folders(host: &Host) -> Vec<String> {
        host.mem
            .list_dir(&host.home)
            .unwrap()
            .into_iter()
            .map(|e| e.name.to_string_lossy().into_owned())
            .filter(|n| n.starts_with(UNINSTALL_PREFIX))
            .collect()
    }

    /// Phase 1 for the install, returning the folder it made and the spawn it did.
    fn start_phase_one(host: &Host, ops: &EngineOps<'_>, exe: &Path) -> (PathBuf, Vec<String>) {
        let kind = run_uninstall_start(
            &host.base(),
            ops,
            &host.process,
            Standing::UacElevated,
            &args(),
            exe,
        );
        assert_eq!(kind, Kind::Ok);
        let folders = uninstall_folders(host);
        assert_eq!(folders.len(), 1, "{folders:?}");
        let dir = host.home.join(&folders[0]);
        let spawns = host.process.spawns();
        assert_eq!(spawns.len(), 1);
        assert!(spawns[0].detached);
        assert_eq!(spawns[0].program, dir.join(UNINSTALL_COPY));
        let args = spawns[0]
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        (dir, args)
    }

    #[test]
    fn phase_one_copies_the_runtime_into_an_admin_only_folder_and_starts_it_with_the_wait_only() {
        let host = Host::new();
        let exe = installed(&host);
        let ops = EngineOps::new(&host);
        let (dir, args) = start_phase_one(&host, &ops, &exe);
        assert_eq!(host.protect.class_of(&dir), Some(DirClass::AdminOnly));
        // The wait arguments, and nothing else: no path, no pipe id, no SID.
        let me = host.process.current().expect("me");
        assert_eq!(
            args,
            vec![
                "machine-uninstall".to_owned(),
                "--wait-pid".to_owned(),
                me.pid.to_string(),
                "--wait-start".to_owned(),
                me.start_ticks.to_string(),
            ]
        );
        assert_eq!(*ops.entered.lock().unwrap(), vec![dir.clone()], "outside R");
        // The marker names the install and the pipe; the copy is the runtime's bytes.
        let marker = host
            .mem
            .read_capped(&dir.join(UNINSTALL_MARKER), 4096)
            .unwrap();
        let marker = Marker::parse(&String::from_utf8(marker).unwrap()).expect("marker");
        assert_eq!(marker.root, host.home.join("Hello"));
        assert_eq!((marker.events.as_str(), marker.sid.as_str()), (ID, SID));
        assert_eq!(
            host.mem
                .read_capped(&dir.join(UNINSTALL_COPY), 100)
                .unwrap(),
            b"runtime"
        );
        // Nothing was deleted and nothing of the install changed.
        assert!(matches!(host.machine(), Machine::Present(..)));
        assert!(ops.engine_calls.lock().unwrap().is_empty());
        // Refusals that start nothing: a standard user, a place that is no install.
        let again = |standing, exe: &Path| {
            run_uninstall_start(&host.base(), &ops, &host.process, standing, &args_(), exe)
        };
        assert_eq!(again(Standing::Standard, &exe), Kind::Usage);
        assert_eq!(
            again(Standing::UacElevated, &abs_path("/dl/rt.exe")),
            Kind::Usage
        );
        assert_eq!(uninstall_folders(&host).len(), 1);
        assert_eq!(host.process.spawns().len(), 1);
    }

    fn args_() -> MachineArgs {
        args()
    }

    /// S1: an administrator's process never takes the temp-folder hand-off; it runs phase 1 in
    /// place from the runtime inside `R` (its copy in an admin-only folder under the machine home,
    /// waiting for this process), with no UI. A standard user's process is refused in place.
    #[test]
    fn an_administrators_uninstall_runs_phase_one_in_place_and_never_hands_off_through_temp() {
        assert_eq!(
            uninstall_route(Standing::Standard),
            UninstallRoute::TempHandOff
        );
        for standing in [Standing::Admin, Standing::UacElevated] {
            assert_eq!(uninstall_route(standing), UninstallRoute::InPlace);
            let host = Host::new();
            let exe = installed(&host);
            let ops = EngineOps::new(&host);
            assert_eq!(
                uninstall_in_place(&host.base(), &ops, &host.process, standing, SID, &exe),
                Kind::Ok,
                "{standing:?}"
            );
            let folders = uninstall_folders(&host);
            assert_eq!(folders.len(), 1, "{folders:?}");
            let dir = host.home.join(&folders[0]);
            assert_eq!(host.protect.class_of(&dir), Some(DirClass::AdminOnly));
            // The only process started is the copy in that folder, waiting for this one.
            let spawns = host.process.spawns();
            assert_eq!(spawns.len(), 1);
            assert_eq!(spawns[0].program, dir.join(UNINSTALL_COPY));
            let me = host.process.current().expect("me");
            assert_eq!(
                spawns[0].args,
                [
                    "machine-uninstall",
                    "--wait-pid",
                    &me.pid.to_string(),
                    "--wait-start",
                    &me.start_ticks.to_string()
                ]
                .map(std::ffi::OsString::from)
                .to_vec()
            );
            let marker = host
                .mem
                .read_capped(&dir.join(UNINSTALL_MARKER), 4096)
                .unwrap();
            let marker = Marker::parse(&String::from_utf8(marker).unwrap()).expect("marker");
            assert_eq!(marker.root, host.home.join("Hello"));
            assert!(crate::modes::is_events_id(&marker.events));
            assert_eq!(marker.sid, SID);
            assert!(ops.engine_calls.lock().unwrap().is_empty());
        }
        let host = Host::new();
        let exe = installed(&host);
        let ops = EngineOps::new(&host);
        assert_eq!(
            uninstall_in_place(
                &host.base(),
                &ops,
                &host.process,
                Standing::Standard,
                SID,
                &exe
            ),
            Kind::Usage
        );
        assert!(uninstall_folders(&host).is_empty());
        assert!(host.process.spawns().is_empty());
    }

    /// Runs phase 2 from the folder phase 1 made, with the pipe's reader kept.
    fn run_phase_two(
        host: &Host,
        ops: &EngineOps<'_>,
        dir: &Path,
        standing: Standing,
    ) -> (Kind, String) {
        let (pipes, mut reader) = FakePipes::new();
        let wait = ProcessId {
            pid: 4242,
            start_ticks: 17,
        };
        let kind = run_uninstall_second(
            &host.base(),
            ops,
            &host.process,
            &pipes,
            standing,
            &wait,
            &dir.join(UNINSTALL_COPY),
            Duration::from_millis(10),
        );
        assert_eq!(host.process.waits().last().map(|w| w.0), Some(wait));
        let mut seen = String::new();
        std::io::Read::read_to_string(&mut reader, &mut seen).expect("the pipe");
        (kind, seen)
    }

    #[test]
    fn phase_two_removes_the_install_reports_through_the_pipe_and_registers_its_folder_for_the_restart()
     {
        let host = Host::new();
        let exe = installed(&host);
        let ops = EngineOps::new(&host);
        let (dir, _) = start_phase_one(&host, &ops, &exe);
        ops.entered.lock().unwrap().clear();
        let (kind, seen) = run_phase_two(&host, &ops, &dir, Standing::UacElevated);
        assert_eq!(kind, Kind::Ok);
        assert!(
            matches!(host.machine(), Machine::Absent),
            "the install is gone"
        );
        assert_eq!(seen, "phase uninstall\nend 0\n");
        assert_eq!(*ops.engine_calls.lock().unwrap(), vec!["uninstall"]);
        // Its own folder is its working directory, and is registered for the restart: the files
        // first, the folder last.
        assert_eq!(*ops.entered.lock().unwrap(), vec![dir.clone()]);
        assert_eq!(
            *ops.deleted.lock().unwrap(),
            vec![
                dir.join(UNINSTALL_COPY),
                dir.join(UNINSTALL_MARKER),
                dir.clone()
            ]
        );
        // The removal asked the strict guard, as the engine does, about the install.
        assert!(!host.process.strict_calls().is_empty());
    }

    #[test]
    fn phase_two_refused_while_a_process_runs_from_the_install_leaves_it_whole_and_says_25() {
        let host = Host::new();
        let exe = installed(&host);
        let ops = EngineOps::new(&host);
        let (dir, _) = start_phase_one(&host, &ops, &exe);
        host.process.script_in_use_strict(true);
        let (kind, seen) = run_phase_two(&host, &ops, &dir, Standing::UacElevated);
        assert_eq!(kind, Kind::InUse);
        assert_eq!(seen, "phase uninstall\nend 25\n");
        match host.machine() {
            Machine::Present(root, Some(v)) => {
                assert_eq!(
                    (root, v.to_string()),
                    (host.home.join("Hello"), "1.0.0".into())
                );
            }
            other => panic!("{other:?}"),
        }
        // The service stays registered (the engine undoes what it did before it refused).
        assert!(host.registrar.image(&app_id()).unwrap().is_some());
        // The folder is registered for deletion all the same: a retry makes a new copy.
        assert_eq!(ops.deleted.lock().unwrap().len(), 3);
    }

    #[test]
    fn phase_two_ignores_a_marker_that_names_no_valid_machine_install() {
        for (what, edit) in [
            (
                "another folder",
                Box::new(|m: &mut Marker| m.root = abs_path("/pf/Other"))
                    as Box<dyn Fn(&mut Marker)>,
            ),
            (
                "another app",
                Box::new(|m: &mut Marker| {
                    m.app_id = AppId::parse("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").unwrap();
                }),
            ),
            (
                "outside the home",
                Box::new(|m: &mut Marker| m.root = abs_path("/elsewhere/Hello")),
            ),
            (
                "the home itself",
                Box::new(|m: &mut Marker| m.root = abs_path("/pf")),
            ),
            (
                "a hidden folder",
                Box::new(|m: &mut Marker| m.root = abs_path("/pf/.lunepack-x")),
            ),
        ] {
            let host = Host::new();
            let exe = installed(&host);
            let ops = EngineOps::new(&host);
            let (dir, _) = start_phase_one(&host, &ops, &exe);
            let text = host
                .mem
                .read_capped(&dir.join(UNINSTALL_MARKER), 4096)
                .unwrap();
            let mut marker = Marker::parse(&String::from_utf8(text).unwrap()).unwrap();
            edit(&mut marker);
            host.mem.remove_file(&dir.join(UNINSTALL_MARKER)).unwrap();
            let mut w = host.mem.create_new(&dir.join(UNINSTALL_MARKER)).unwrap();
            w.write_all(marker.encode().unwrap().as_bytes()).unwrap();
            w.sync().unwrap();
            let (kind, _) = run_phase_two(&host, &ops, &dir, Standing::UacElevated);
            assert_eq!(kind, Kind::InstallMismatch, "{what}");
            assert!(
                ops.engine_calls.lock().unwrap().is_empty(),
                "{what}: the engine ran"
            );
            assert!(matches!(host.machine(), Machine::Present(..)), "{what}");
        }
    }

    #[test]
    fn phase_two_runs_only_from_its_own_admin_only_folder_for_an_administrator() {
        let host = Host::new();
        let exe = installed(&host);
        let ops = EngineOps::new(&host);
        let (dir, _) = start_phase_one(&host, &ops, &exe);
        let (pipes, _reader) = FakePipes::new();
        let wait = ProcessId {
            pid: 1,
            start_ticks: 1,
        };
        let go = |standing, copy: &Path| {
            run_uninstall_second(
                &host.base(),
                &ops,
                &host.process,
                &pipes,
                standing,
                &wait,
                copy,
                Duration::from_millis(10),
            )
        };
        // A standard user's process, the runtime inside `R`, a copy somewhere else, a folder with
        // another name: a usage error before any action.
        assert_eq!(
            go(Standing::Standard, &dir.join(UNINSTALL_COPY)),
            Kind::Usage
        );
        assert_eq!(go(Standing::UacElevated, &exe), Kind::Usage);
        assert_eq!(
            go(Standing::UacElevated, &abs_path("/dl/lunepack-runtime.exe")),
            Kind::Usage
        );
        let wrong = host
            .home
            .join(format!("{UNINSTALL_PREFIX}{}", "f".repeat(31)));
        assert_eq!(
            go(Standing::UacElevated, &wrong.join(UNINSTALL_COPY)),
            Kind::Usage
        );
        // A folder a standard user could write in is no folder of ours.
        host.protect.set_unprotected(&dir, true);
        assert_eq!(
            go(Standing::UacElevated, &dir.join(UNINSTALL_COPY)),
            Kind::Usage
        );
        host.protect.set_unprotected(&dir, false);
        assert!(ops.engine_calls.lock().unwrap().is_empty());
        assert!(ops.entered.lock().unwrap().iter().all(|d| d == &dir));
        assert_eq!(
            ops.entered.lock().unwrap().len(),
            1,
            "only phase 1 entered a folder"
        );
        assert!(
            pipes.opened.lock().unwrap().is_empty(),
            "no pipe before the rule held"
        );
        assert!(matches!(host.machine(), Machine::Present(..)));
    }

    #[test]
    fn the_unelevated_side_asks_then_follows_phase_two_and_judges_by_the_record() {
        // Gone: success, whatever the pipe said.
        for (script, lines, installed_still, want) in [
            (
                ElevationScript::Exit(0),
                "phase uninstall\nend 0\n",
                false,
                Ok(()),
            ),
            (ElevationScript::Exit(0), "", false, Ok(())),
            (
                ElevationScript::Exit(0),
                "phase uninstall\nend 25\n",
                true,
                Err(Kind::InUse),
            ),
            (
                ElevationScript::Exit(0),
                "phase uninstall\nend 0\n",
                true,
                Err(Kind::State),
            ),
            (ElevationScript::Exit(0), "", true, Err(Kind::Process)),
            (
                ElevationScript::Exit(0),
                "phase uninstall\nnonsense\n",
                true,
                Err(Kind::Process),
            ),
            (ElevationScript::Exit(35), "", true, Err(Kind::NotProtected)),
            (
                ElevationScript::Declined,
                "",
                true,
                Err(Kind::ElevationDeclined),
            ),
        ] {
            let host = Host::new();
            installed(&host);
            if !installed_still {
                host.mem
                    .remove_dir_all_nofollow(&host.home.join("Hello"))
                    .unwrap();
            }
            let elevation = FakeElevation::new(Standing::Admin, [script]);
            let ops = EngineOps::new(&host);
            let (mut child, reader) = lunepack_testkit::mem_duplex();
            std::io::Write::write_all(&mut child, lines.as_bytes()).unwrap();
            drop(child);
            let pipes = ReaderConnector(Mutex::new(Some(reader)));
            let h = unelevated(&elevation, &ops, &pipes, &host, Some(SID));
            let (events, seen) = collecting();
            let got = super::uninstall(
                &h,
                &host.mem,
                &FakeHasher,
                &host.home,
                &target(&host),
                false,
                &events,
            );
            assert_eq!(got, want, "{script:?} {lines:?}");
            events.finish(Duration::from_secs(1));
            // One prompt, whatever this process's standing: the runtime inside `R`, always.
            let calls = elevation.calls();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, target(&host).runtime);
            assert_eq!(calls[0].1[0], "machine-uninstall");
            // Progress came through, as events.
            if lines.starts_with("phase uninstall") && matches!(script, ElevationScript::Exit(0)) {
                assert_eq!(seen.lock().unwrap().len(), 1, "{lines:?}");
            }
            assert!(
                ops.engine_calls.lock().unwrap().is_empty(),
                "the engine does not run here"
            );
        }
        // `--silent` as a standard user asks nothing.
        let host = Host::new();
        installed(&host);
        let elevation = FakeElevation::new(Standing::Standard, [ElevationScript::Exit(0)]);
        let ops = EngineOps::new(&host);
        let (_, reader) = lunepack_testkit::mem_duplex();
        let pipes = ReaderConnector(Mutex::new(Some(reader)));
        let h = unelevated(&elevation, &ops, &pipes, &host, Some(SID));
        let (events, _) = collecting();
        let got = super::uninstall(
            &h,
            &host.mem,
            &FakeHasher,
            &host.home,
            &target(&host),
            true,
            &events,
        );
        assert_eq!(got, Err(Kind::ElevationRequired));
        assert!(elevation.calls().is_empty());
    }

    #[test]
    fn the_policy_that_switches_the_update_window_off_rules_machine_installs_only() {
        let policy = FakePolicy::new();
        assert!(!no_update_ui(true, &policy, &app_id()));
        policy.set(lunepack_core::MachinePolicy {
            self_update_disabled: false,
            no_update_ui: true,
        });
        assert!(no_update_ui(true, &policy, &app_id()));
        assert!(
            !no_update_ui(false, &policy, &app_id()),
            "a user install is not ruled by it"
        );
        // `DisableSelfUpdate` alone does not hide the window.
        policy.set(lunepack_core::MachinePolicy {
            self_update_disabled: true,
            no_update_ui: false,
        });
        assert!(!no_update_ui(true, &policy, &app_id()));
    }
}
