//! Setup mode (M6 step 7, M6-D4, M7): this runtime is a setup file (Linux or Windows), its own release's runtime
//! with one version's signed payload and a trailer appended (FORMAT.md 14), and it installs exactly
//! that version with no network.
//!
//! At start, before the command line is read, the runtime looks for the trailer in its resolved
//! executable ([`detect`]): in the last [`TRAILER_SIZE`] bytes, or in the [`TRAILER_SIZE`] bytes
//! before a signed PE's certificate table (M7-D11). No magic there: the run is an ordinary runtime
//! run, unchanged. The magic and anything malformed after it: exit 7 `verify`, never a fall-through
//! to the ordinary modes. A setup run takes no argument or `--silent` (D41); anything else is a
//! usage error.
//!
//! Then, in order: the payload is verified under the trailer's root ([`verify_setup`]: the key set,
//! the manifest with no feed, the whole pack, the update config read from the pack naming exactly
//! that root); when a UI may start, `lunepack-ui` is read out of the pack through its signed frame
//! ([`read_entry`](lunepack_core::read_entry)) into a fresh private directory, under the app's
//! cache on Linux (M6-D7), directly under the user's temp dir on Windows (M7-D13), and started from
//! there; the welcome prompt (name, version, publisher, location and size, all from the verified
//! manifest and config); [`lunepack::Updater::install_from_payload`] (the commit and the desktop
//! integration); the done prompt, whose `finish{launch:true}` starts the installed entry. The UI's
//! directory is removed at exit; earlier runs' directories are removed only when they carry the
//! setup marker naming a process that no longer runs (Linux: and this app; Windows: of any app,
//! and no process runs from them, `crate::tempdirs`).
//!
//! `R` is found after verification and before anything is written ([`lunepack_core::resolve_root`]
//! under the platform's layout scheme: `<data home>/<app id>` on Linux; on Windows the folder of an
//! existing install of the app id, whatever its name, else one named after the display name,
//! M7-D16, M7-D17); a refusal there ends the run with nothing written under the data home.
//!
//! Nothing from the payload runs, or is written anywhere, before its signature or hash checked.
//!
//! macOS (M8-D7): the installer is an app, `<I>` = `Install <name>.app`, whose main executable
//! is the release's UI and whose `Contents/MacOS/lunepack-runtime` is this runtime. The runtime
//! is in setup mode when its resolved path is that one and
//! `<I>/Contents/Resources/lunepack-setup.payload` is a regular file ([`detect_installer`]):
//! FORMAT.md 14's payload and trailer without the runtime part, verified exactly as a setup
//! file's. Its command line is empty (the UI beside it is started as on the other systems, never
//! extracted), `--silent`, or the internal `--ui-stdio` ([`InstallerRun`]): the UI is the parent
//! and the frames go over this process's own standard streams ([`UiHost::over_parent`]). The
//! install goes into the live bundle in the apps folder (M8-D1, D2) by the facade's bundle
//! install; only that folder's place is judged (M8-D4), never the installer's own (a read-only
//! disk image, a translocated copy).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use lunepack::{
    ChildStdio, DownloadOptions, Fs, HEALTH_TOKEN_VAR, Installation, Layout, OfflinePayload,
    PayloadPart, Phase, Progress, ReadAt, SpawnSpec, TrustedRoot, UpdaterBuilder, UserLayout,
    Version,
};
use lunepack_core::setup::{
    Located, SetupPart, SetupTrailer, TRAILER_SIZE, VerifiedSetup, locate_file, verify_setup,
};
use lunepack_core::ui::{ChoiceValue, Outcome, PromptKind, StepItem};
use lunepack_core::{ClockReading, Hasher, Verifier};

use crate::events::{Event, Events, Warning};
use crate::modes::{Adapters, Kind};
use crate::ui_host::{self, UiHost};

/// The mode's name in events.
pub const COMMAND: &str = "setup";
/// The result's outcome.
pub const OUTCOME: &str = "installed";
/// The prefix of the UI directories a setup makes under the app's cache.
pub const UI_DIR_PREFIX: &str = "setup-ui-";
/// The marker file inside such a directory.
pub const MARKER_FILE: &str = "lunepack-setup-ui";
/// How often the progress forwarder looks whether the install ended.
const FORWARD_POLL: Duration = Duration::from_millis(50);

/// A setup file, found at the end of this runtime's executable.
pub struct Found {
    /// The parsed trailer.
    pub trailer: SetupTrailer,
    /// The executable, open for reading.
    pub file: Arc<dyn ReadAt>,
}

/// What the end of the executable holds.
pub enum Detect {
    /// No setup trailer: an ordinary runtime.
    None,
    /// A setup file.
    Setup(Found),
    /// The magic, then something malformed.
    Malformed,
}

/// How the macOS installer's runtime was started (M8-D7).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallerRun {
    /// No argument: the UI beside the runtime is started, when one may be.
    Ui,
    /// `--silent`: no UI, every prompt its default (D41).
    Silent,
    /// `--ui-stdio` (internal): the installer's UI started this runtime and talks to it over its
    /// standard input and output.
    UiStdio,
}

/// The option the installer's UI starts the runtime with.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const UI_STDIO_ARG: &str = "--ui-stdio";

/// The macOS installer's command line: nothing, `--silent` or `--ui-stdio`, once; anything else
/// is a usage error.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_installer(args: &[OsString]) -> Result<InstallerRun, crate::modes::UsageError> {
    match args {
        [] => Ok(InstallerRun::Ui),
        [flag] if flag == "--silent" => Ok(InstallerRun::Silent),
        [flag] if flag == UI_STDIO_ARG => Ok(InstallerRun::UiStdio),
        _ => Err(crate::modes::UsageError),
    }
}

/// The installer's runtime (macOS, M8-D7): when `exe` (the resolved executable) is
/// `<I>/Contents/MacOS/lunepack-runtime` and `<I>/Contents/Resources/lunepack-setup.payload` is a
/// regular file (not a link), that file parsed as a payload file
/// ([`lunepack_core::setup::parse_payload_file`]); a payload file that cannot be read or parsed
/// is [`Detect::Malformed`] (exit 7), never an ordinary run. Anything else is [`Detect::None`].
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn detect_installer(
    fs: &dyn Fs,
    exe: &Path,
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Detect {
    let named = |path: Option<&Path>, name: &str| {
        path.and_then(Path::file_name)
            .is_some_and(|n| n == std::ffi::OsStr::new(name))
    };
    let macos_dir = exe.parent();
    let contents = macos_dir.and_then(Path::parent);
    if !named(Some(exe), "lunepack-runtime")
        || !named(macos_dir, "MacOS")
        || !named(contents, "Contents")
    {
        return Detect::None;
    }
    let Some(installer) = contents.and_then(Path::parent) else {
        return Detect::None;
    };
    let payload = lunepack_core::update_config::MACOS_INSTALLER_PAYLOAD
        .split('/')
        .fold(installer.to_path_buf(), |dir, name| dir.join(name));
    match fs.symlink_metadata(&payload) {
        Ok(Some(meta)) if meta.kind == lunepack::FileKind::File => {}
        _ => return Detect::None,
    }
    let Ok(file) = fs.open_read(&payload) else {
        return Detect::Malformed;
    };
    match lunepack_core::setup::parse_payload_file(file.as_ref(), hasher, verifier) {
        Ok(trailer) => Detect::Setup(Found {
            trailer,
            file: Arc::from(file),
        }),
        Err(_) => Detect::Malformed,
    }
}

/// Looks for a setup trailer in `exe` (the resolved executable) through the core's locator
/// ([`locate_file`], M7-D11): at the end of the file, or before a signed PE's certificate table.
/// A file that cannot be opened or read, that is shorter than a trailer or that carries no trailer
/// magic is an ordinary runtime, whatever its headers say.
pub fn detect(fs: &dyn Fs, exe: &Path, hasher: &dyn Hasher, verifier: &dyn Verifier) -> Detect {
    let Ok(file) = fs.open_read(exe) else {
        return Detect::None;
    };
    let end = match locate_file(file.as_ref()) {
        Ok(Located::None) | Err(_) => return Detect::None,
        Ok(Located::Malformed) => return Detect::Malformed,
        Ok(Located::Setup { end }) => end,
    };
    let mut tail = vec![0u8; TRAILER_SIZE as usize];
    if file.read_exact_at(end - TRAILER_SIZE, &mut tail).is_err() {
        return Detect::None;
    }
    // The trailer's parts lie before `end`: a certificate table after it is not setup data.
    match SetupTrailer::parse(&tail, end, hasher, verifier) {
        Ok(trailer) => Detect::Setup(Found {
            trailer,
            file: Arc::from(file),
        }),
        Err(_) => Detect::Malformed,
    }
}

/// Where a setup's UI directory goes: Linux, the per-user cache home (the app's directory is
/// made under it, M6-D7); Windows, the user's temp dir (M7-D13).
pub fn ui_home(env: &dyn Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let _ = env;
        crate::tempdirs::temp_home()
    }
    #[cfg(not(windows))]
    cache_home(env)
}

/// The per-user cache home (`XDG_CACHE_HOME` when absolute, else `$HOME/.cache`).
#[cfg_attr(windows, allow(dead_code))]
pub fn cache_home(env: &dyn Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    if let Some(dir) = env("XDG_CACHE_HOME").map(PathBuf::from)
        && dir.is_absolute()
    {
        return Some(dir);
    }
    let home = PathBuf::from(env("HOME")?);
    home.is_absolute().then(|| home.join(".cache"))
}

/// A verified setup, ready for its prompts.
pub struct Prepared {
    found: Found,
    verified: VerifiedSetup,
    /// `R`.
    install_root: PathBuf,
    data_home: PathBuf,
    /// The UI's private directory, when one was made.
    ui_dir: Option<PathBuf>,
    /// macOS: the apps folder the live bundle goes in (M8-D2).
    apps_dir: Option<PathBuf>,
}

impl Prepared {
    /// The version the setup installs.
    pub fn version(&self) -> &Version {
        &self.found.trailer.version
    }

    /// The app's display name, from the verified config.
    pub fn name(&self) -> &str {
        &self.verified.config.install.name
    }

    /// The UI's directory, when the UI was extracted.
    pub fn ui_dir(&self) -> Option<&Path> {
        self.ui_dir.as_deref()
    }

    /// macOS: the install is a bundle install into `apps_dir` (the canonical `~/Applications`,
    /// M8-D2), which the welcome screen shows as the location.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn with_apps_dir(mut self, apps_dir: PathBuf) -> Prepared {
        self.apps_dir = Some(apps_dir);
        self
    }

    /// Removes the UI's directory (after the UI has exited). Best effort.
    pub fn cleanup(&self, fs: &dyn Fs) {
        if let Some(dir) = &self.ui_dir {
            let _ = fs.remove_dir_all_nofollow(dir);
        }
    }
}

/// The liveness test of an earlier run's marker: whether process `pid` started at `start` runs.
pub type Alive<'a> = &'a dyn Fn(u32, u64) -> bool;

/// Why [`prepare`] refused a setup: the exit kind, and the app's display name when the payload was
/// verified before the refusal (a refused root: a taken folder, an unreadable or ambiguous
/// install), `None` when the payload itself was refused.
pub struct Refused {
    pub kind: Kind,
    pub name: Option<String>,
}

/// Verifies the setup, finds `R`, and, when `want_ui`, extracts the UI under `ui_home` ([`ui_home`];
/// M6-D7, M7-D13) with a marker naming `own` (this process). A verification failure or a refused
/// root is its exit kind ([`Refused`]), with nothing written; a UI that cannot be extracted means a
/// headless run.
pub fn prepare(
    ad: &Adapters,
    found: Found,
    data_home: &Path,
    ui_home: Option<&Path>,
    want_ui: bool,
    own: Option<lunepack::ProcessId>,
    alive: Alive<'_>,
) -> Result<Prepared, Refused> {
    let clock = ClockReading::read(&lunepack::SystemClock, None);
    let verified = verify_setup(
        &found.trailer,
        &*found.file,
        &clock,
        &*ad.codec,
        &*ad.hasher,
        &*ad.verifier,
    )
    .map_err(|e| Refused {
        kind: Kind::of(&lunepack::Error::from(e)),
        name: None,
    })?;
    // M7-D16: `R` is found by record (or named) under the platform's layout scheme;
    // `<data home>/<app id>` under XDG.
    let install_root = lunepack_core::resolve_root(
        &*ad.fs,
        &*ad.hasher,
        data_home,
        found.trailer.root.app_id(),
        &verified.config.install.name,
        ad.platform.layout_scheme(),
    )
    .map_err(|e| Refused {
        kind: Kind::of(&lunepack::Error::from(lunepack_core::Error::Layout(e))),
        name: Some(verified.config.install.name.clone()),
    })?
    .into_path();
    let mut prepared = Prepared {
        found,
        verified,
        install_root,
        data_home: data_home.to_path_buf(),
        ui_dir: None,
        apps_dir: None,
    };
    if want_ui && let (Some(home), Some(own)) = (ui_home, own) {
        prepared.ui_dir = extract_ui(ad, &prepared, home, own, alive);
    }
    Ok(prepared)
}

/// The marker text of a UI directory made by process `me` for `app`.
fn marker_text(app: &str, pid: u32, start: u64) -> String {
    format!("lunepack setup ui {app} {pid} {start}\n")
}

/// Removes the UI directories of earlier runs under `app_cache`: real directories named
/// `setup-ui-*` holding a regular marker file for `app` whose process no longer runs. Nothing else
/// is touched.
fn clear_stale(ad: &Adapters, app_cache: &Path, app: &str, alive: Alive<'_>) {
    let Ok(entries) = ad.fs.list_dir(app_cache) else {
        return;
    };
    for entry in entries {
        let Some(name) = entry.name.to_str() else {
            continue;
        };
        if !name.starts_with(UI_DIR_PREFIX) || entry.kind != lunepack::FileKind::Dir {
            continue;
        }
        let dir = app_cache.join(name);
        let marker = dir.join(MARKER_FILE);
        match ad.fs.symlink_metadata(&marker) {
            Ok(Some(meta)) if meta.kind == lunepack::FileKind::File => {}
            _ => continue,
        }
        let Ok(text) = ad.fs.read_capped(&marker, 256) else {
            continue;
        };
        let Ok(text) = String::from_utf8(text) else {
            continue;
        };
        let mut words = text.trim_end().rsplitn(3, ' ');
        let (Some(start), Some(pid), Some(head)) = (words.next(), words.next(), words.next())
        else {
            continue;
        };
        let (Ok(pid), Ok(start)) = (pid.parse::<u32>(), start.parse::<u64>()) else {
            continue;
        };
        if marker_text(app, pid, start) != text || head != format!("lunepack setup ui {app}") {
            continue;
        }
        if !alive(pid, start) {
            let _ = ad.fs.remove_dir_all_nofollow(&dir);
        }
    }
}

/// The release's `lunepack-ui`, read out of the verified pack through its signed frame; `None`
/// when the release has none or it cannot be read.
fn ui_bytes(ad: &Adapters, prepared: &Prepared) -> Option<Vec<u8>> {
    use lunepack_core::read_entry;
    use lunepack_core::setup::MAX_SETUP_UI_BYTES;

    let trailer = &prepared.found.trailer;
    let ui_at = prepared.verified.ui_path().ok()?;
    let pack = lunepack_core::setup::ReadAtWindow::new(&*prepared.found.file, trailer.pack).ok()?;
    read_entry(
        &prepared.verified.manifest,
        &ui_at,
        &pack,
        &*ad.codec,
        &*ad.hasher,
        MAX_SETUP_UI_BYTES,
    )
    .ok()
}

/// Reads `lunepack-ui` out of the pack ([`ui_bytes`]) and writes it into a fresh 0700 directory
/// `<cache home>/<app id>/setup-ui-<random>` this run creates (never an existing path), with the
/// marker. `None` (a headless run) when the release has no UI or anything fails; a directory made
/// before the failure is removed.
#[cfg(unix)]
fn extract_ui(
    ad: &Adapters,
    prepared: &Prepared,
    cache_home: &Path,
    own: lunepack::ProcessId,
    alive: Alive<'_>,
) -> Option<PathBuf> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

    let app = prepared.found.trailer.root.app_id().as_str();
    let app_cache = &cache_home.join(app);
    let bytes = ui_bytes(ad, prepared)?;

    // The app's cache directory: made 0700 when missing; an existing one must be a real directory.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(app_cache)
        .ok()?;
    if !std::fs::symlink_metadata(app_cache).is_ok_and(|m| m.is_dir()) {
        return None;
    }
    clear_stale(ad, app_cache, app, alive);

    let mut random = [0u8; 16];
    ad.rng.fill(&mut random).ok()?;
    let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let dir = app_cache.join(format!("{UI_DIR_PREFIX}{name}"));
    // `mkdir` of a new name: fails on anything already there, follows nothing.
    std::fs::DirBuilder::new().mode(0o700).create(&dir).ok()?;
    let written = (|| -> std::io::Result<()> {
        let write = |path: &Path, bytes: &[u8], mode: u32| -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(path)?;
            file.write_all(bytes)?;
            file.sync_all()
        };
        write(
            &dir.join(MARKER_FILE),
            marker_text(app, own.pid, own.start_ticks).as_bytes(),
            0o600,
        )?;
        write(&dir.join(ui_host::UI_FILE), &bytes, 0o700)
    })();
    if written.is_err() {
        let _ = ad.fs.remove_dir_all_nofollow(&dir);
        return None;
    }
    Some(dir)
}

/// Windows (M7-D13): reads `lunepack-ui.exe` out of the pack ([`ui_bytes`]) into a fresh
/// `<temp dir>\lunepack-setup-ui-<16 hex>` this run creates new, with a marker naming the app and
/// `own`; earlier runs' stale directories were cleared before (`tempdirs::clear_stale`). `None` (a
/// headless run) when the release has no UI or anything fails; a directory made before the failure
/// is removed.
#[cfg(windows)]
fn extract_ui(
    ad: &Adapters,
    prepared: &Prepared,
    temp: &Path,
    own: lunepack::ProcessId,
    _alive: Alive<'_>,
) -> Option<PathBuf> {
    use crate::tempdirs::{self, Marker};

    let bytes = ui_bytes(ad, prepared)?;
    let marker = Marker {
        app_id: prepared.found.trailer.root.app_id().as_str().to_owned(),
        owner: own,
    };
    let dir = tempdirs::create(&*ad.fs, &*ad.rng, temp, tempdirs::SETUP_UI_PREFIX, &marker).ok()?;
    if tempdirs::write_new(&dir.join(ui_host::UI_FILE), &bytes).is_err() {
        let _ = ad.fs.remove_dir_all_nofollow(&dir);
        return None;
    }
    Some(dir)
}

#[cfg(not(any(unix, windows)))]
fn extract_ui(
    _: &Adapters,
    _: &Prepared,
    _: &Path,
    _: lunepack::ProcessId,
    _: Alive<'_>,
) -> Option<PathBuf> {
    None
}

/// The UI card and details of the welcome screen, from the verified manifest and config.
pub fn welcome(prepared: &Prepared) -> (lunepack_core::ui::AppCard, lunepack_core::ui::Details) {
    let install = &prepared.verified.config.install;
    let mut card = ui_host::card(&install.name, &prepared.version().to_string(), None);
    card.publisher = install
        .publisher
        .clone()
        .filter(|p| p.chars().count() <= lunepack_core::ui::MAX_NAME);
    let details = lunepack_core::ui::Details {
        location: prepared
            .apps_dir
            .as_ref()
            .unwrap_or(&prepared.install_root)
            .to_str()
            .map(str::to_owned)
            .and_then(|t| ui_host::within(t, lunepack_core::ui::MAX_LOCATION)),
        size_bytes: Some(prepared.verified.installed_bytes()),
    };
    (card, details)
}

/// Runs the install flow of a prepared setup with its prompts in `ui`. Returns the exit kind and
/// the final event.
pub fn run_setup(
    ad: &Adapters,
    prepared: &Prepared,
    events: &Events,
    ui: &UiHost,
) -> (Kind, Event) {
    if ui.prompt(PromptKind::Welcome, events, &mut |_| {}) != ChoiceValue::Proceed {
        ui.outcome(Outcome::Cancelled);
        return report(prepared, Err(Kind::Cancelled));
    }
    loop {
        let result = install(ad, prepared, events);
        match &result {
            Ok(_) => {
                ui.steps(&[
                    StepItem::Verify,
                    StepItem::Stage,
                    StepItem::Commit,
                    StepItem::Integrate,
                ]);
                ui.outcome(Outcome::Installed);
            }
            Err(kind) => ui.outcome(Outcome::Failed {
                code: u32::from(kind.code()),
            }),
        }
        let kind = match &result {
            Ok(_) => PromptKind::Done,
            Err(_) => PromptKind::Failed,
        };
        match ui.prompt(kind, events, &mut |_| {}) {
            ChoiceValue::Retry => continue,
            ChoiceValue::Finish { launch: true } => {
                if let Ok(version) = &result {
                    launch(ad, prepared, version, events);
                }
            }
            _ => {}
        }
        return report(prepared, result);
    }
}

/// The event of a setup that ended before its install ran (verification, a malformed trailer).
pub fn failed(kind: Kind, version: Option<Version>) -> Event {
    Event::Error {
        command: COMMAND,
        tree_version: version,
        kind: kind.name(),
        exit_code: kind.code(),
        reason: kind.reason(),
    }
}

fn report(prepared: &Prepared, result: Result<Version, Kind>) -> (Kind, Event) {
    let tree_version = Some(prepared.version().clone());
    match result {
        Ok(version) => (
            Kind::Ok,
            Event::Result {
                command: COMMAND,
                tree_version,
                outcome: OUTCOME,
                version: Some(version),
            },
        ),
        Err(kind) => (kind, failed(kind, tree_version)),
    }
}

fn part(p: SetupPart) -> PayloadPart {
    PayloadPart {
        offset: p.offset,
        length: p.length,
    }
}

fn install(ad: &Adapters, prepared: &Prepared, events: &Events) -> Result<Version, Kind> {
    let trailer = &prepared.found.trailer;
    let config = &prepared.verified.config;
    let root: TrustedRoot = trailer.root.clone();
    let updater = UpdaterBuilder::new(
        root.app_id().clone(),
        root.clone(),
        &config.feed,
        config.channel.clone(),
        Layout::user(&UserLayout::from_root(
            prepared.install_root.clone(),
            ad.platform.layout_scheme(),
        )),
    )
    .fs(Arc::clone(&ad.fs))
    .hasher(Arc::clone(&ad.hasher))
    .verifier(Arc::clone(&ad.verifier))
    .codec(Arc::clone(&ad.codec))
    .rng(Arc::clone(&ad.rng))
    .integration(Arc::clone(&ad.integration));
    let updater = match &prepared.apps_dir {
        Some(apps_dir) => updater.bundle_layout(apps_dir.clone()),
        None => updater,
    }
    .build()
    .map_err(|e| Kind::of(&e))?;
    events.emit(&Event::phase(Phase::Install, Some(prepared.version())));
    let payload = OfflinePayload {
        file: Arc::clone(&prepared.found.file),
        keys: part(trailer.keys),
        manifest: part(trailer.manifest),
        pack: part(trailer.pack),
        version: trailer.version.clone(),
        target: trailer.target,
    };

    // Progress arrives on the polling thread; a scoped forwarder hands it to the sinks.
    let (tx, rx) = mpsc::channel::<Progress>();
    let done = AtomicBool::new(false);
    let result = std::thread::scope(|scope| {
        let done = &done;
        scope.spawn(move || {
            loop {
                match rx.recv_timeout(FORWARD_POLL) {
                    Ok(progress) => events.emit(&Event::Progress(progress)),
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) if done.load(Ordering::Acquire) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        });
        let options = DownloadOptions {
            progress: Some(Box::new(move |p: &Progress| {
                let _ = tx.send(p.clone());
            })),
            cancel: None,
        };
        let result = lunepack::block_on(updater.install_from_payload(payload, root, options));
        done.store(true, Ordering::Release);
        result
    });
    let installed = result.map_err(|e| Kind::of(&e))?;
    Ok(installed.version().clone())
}

/// Starts the installed version's entry, detached, with no arguments and without a health token;
/// a failure is a warning.
fn launch(ad: &Adapters, prepared: &Prepared, version: &Version, events: &Events) {
    let layout = UserLayout::from_root(prepared.install_root.clone(), ad.platform.layout_scheme());
    // The bundle layout (macOS) puts the installed version in the live bundle.
    let tree = match layout.bundle_path(&*ad.fs) {
        Ok(Some(bundle)) => bundle,
        _ => layout.version_dir(version),
    };
    let entry = prepared
        .verified
        .config
        .install
        .entry
        .components()
        .fold(tree, |dir, part| dir.join(part));
    let platform = ad
        .platform
        .clone()
        .with_data_home(prepared.data_home.clone());
    let started = Installation::from_exe_with(&entry, platform)
        .ok()
        .and_then(|installed| {
            let spec = SpawnSpec {
                program: installed.entry_path(),
                args: Vec::new(),
                env_set: Vec::new(),
                env_remove: vec![OsString::from(HEALTH_TOKEN_VAR)],
                stdio: ChildStdio::Null,
            };
            ad.process.spawn_detached(&spec).ok()
        });
    if started.is_none() {
        events.emit(&Event::warning(Warning::RelaunchFailed, Some(version)));
    }
}
