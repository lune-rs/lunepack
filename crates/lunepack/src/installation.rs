//! Where the running executable stands (C4 Locating, M5-D17): [`Installation`] finds the version
//! tree an executable belongs to from its own path, reads that tree's update config (FORMAT.md
//! 13) and, when the tree is under an install's `versions` directory, the install's layout
//! (M5-D2).
//!
//! The adapters the lifecycle calls use are a [`Platform`]: the native one wires the default
//! filesystem, crypto and randomness everywhere, the Linux process and desktop integration
//! adapters on Linux, the Windows ones (per-user, M7) on Windows and the macOS ones (per-user,
//! M8) on macOS. On other platforms the process and integration calls are
//! [`Error::Unsupported`] until their adapters exist.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lunepack_core::state::UserScope;
use lunepack_core::update_config::{MAX_UPDATE_CONFIG_BYTES, runtime_file};
use lunepack_core::{
    AppId, BundleDiscovery, BundleProbe, Discovery, FeedKind, FileKind, Fs, FsErrorKind, Hasher,
    InstallMeta, LayoutError, LayoutScheme, LockGuard, OsIntegration, Process, Projection, RelPath,
    Rng, UPDATE_CONFIG_FILE, UpdateConfig, UpdateConfigError, UserLayout, Verifier, Version,
    discover, discover_bundle, resolve_root, tree_candidates,
};

use crate::{Error, Layout, UpdaterBuilder, check_config_feed};

/// The environment variable that carries the health token of a supervised start (M5-D5): 32
/// random bytes as 64 lowercase hex digits. It is set only on the supervised child; the record
/// keeps only the SHA-256 of the raw bytes.
pub const HEALTH_TOKEN_VAR: &str = "LUNEPACK_HEALTH_TOKEN";

/// How long a lifecycle call retries a held install lock before [`Error::Busy`].
const DEFAULT_BUSY_WAIT: Duration = Duration::from_secs(2);
/// The pause between two tries of a held lock.
const BUSY_POLL: Duration = Duration::from_millis(50);

/// The adapters the lifecycle calls ([`Installation`], `startup`, `confirm`, `apply_and_restart`,
/// [`Updater::install`](crate::Updater::install)) run on. [`Platform::native`] is the default
/// composition; each adapter can be replaced (tests use the testkit's fakes).
#[derive(Clone)]
pub struct Platform {
    pub(crate) fs: Arc<dyn Fs>,
    pub(crate) native_fs: bool,
    pub(crate) hasher: Arc<dyn Hasher>,
    pub(crate) verifier: Arc<dyn Verifier>,
    pub(crate) process: Arc<dyn Process>,
    pub(crate) integration: Arc<dyn OsIntegration>,
    pub(crate) rng: Arc<dyn Rng>,
    pub(crate) health_token: Option<OsString>,
    pub(crate) data_home: Option<PathBuf>,
    pub(crate) home: Option<PathBuf>,
    pub(crate) layout_scheme: LayoutScheme,
    pub(crate) busy_wait: Duration,
}

impl fmt::Debug for Platform {
    /// Shows nothing of the token, only whether one is present.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Platform")
            .field("native_fs", &self.native_fs)
            .field("health_token", &self.health_token.is_some())
            .field("layout_scheme", &self.layout_scheme)
            .field("busy_wait", &self.busy_wait)
            .finish_non_exhaustive()
    }
}

impl Platform {
    /// The default adapters: `lunepack-fs`, `lunepack-crypto` (SHA-256, Ed25519, the OS random
    /// source), and on Linux `lunepack-os-linux` (processes, the XDG desktop integration). The
    /// health token is read from [`HEALTH_TOKEN_VAR`] now; the data home is worked out from the
    /// environment when it is needed (M5-D2).
    pub fn native() -> Platform {
        Platform {
            fs: Arc::new(lunepack_fs::StdFs::new()),
            native_fs: true,
            hasher: Arc::new(lunepack_crypto::Sha256Hasher),
            verifier: Arc::new(lunepack_crypto::Ed25519Verifier),
            process: default_process(),
            integration: default_integration(),
            rng: Arc::new(lunepack_crypto::OsRng),
            health_token: std::env::var_os(HEALTH_TOKEN_VAR),
            data_home: None,
            home: None,
            layout_scheme: native_layout_scheme(),
            busy_wait: DEFAULT_BUSY_WAIT,
        }
    }

    /// The filesystem. Paths are then used as given (the native one canonicalises the
    /// executable's path first, because it refuses symlinked components).
    pub fn with_fs(mut self, fs: Arc<dyn Fs>) -> Platform {
        self.fs = fs;
        self.native_fs = false;
        self
    }

    /// SHA-256.
    pub fn with_hasher(mut self, hasher: Arc<dyn Hasher>) -> Platform {
        self.hasher = hasher;
        self
    }

    /// The signature verifier (used to rebuild the config's trusted root).
    pub fn with_verifier(mut self, verifier: Arc<dyn Verifier>) -> Platform {
        self.verifier = verifier;
        self
    }

    /// Processes.
    pub fn with_process(mut self, process: Arc<dyn Process>) -> Platform {
        self.process = process;
        self
    }

    /// The desktop integration.
    pub fn with_integration(mut self, integration: Arc<dyn OsIntegration>) -> Platform {
        self.integration = integration;
        self
    }

    /// The random source.
    pub fn with_rng(mut self, rng: Arc<dyn Rng>) -> Platform {
        self.rng = rng;
        self
    }

    /// The health token this process was started with, instead of [`HEALTH_TOKEN_VAR`].
    pub fn with_health_token(mut self, token: Option<OsString>) -> Platform {
        self.health_token = token;
        self
    }

    /// The data home, instead of the environment's (`XDG_DATA_HOME`, else
    /// `$HOME/.local/share` on Linux; the user's program files folder on Windows): a
    /// not-installed tree installs into the root the layout scheme resolves there
    /// (`<data home>/<app id>` under [`LayoutScheme::XDG`]).
    pub fn with_data_home(mut self, data_home: PathBuf) -> Platform {
        self.data_home = Some(data_home);
        self
    }

    /// The user's home directory (canonical), instead of `HOME`'s: macOS discovery needs it to
    /// tell a bundle in the Trash from one that was moved (M8-D17). Used only under
    /// [`LayoutScheme::MACOS`].
    pub fn with_home(mut self, home: PathBuf) -> Platform {
        self.home = Some(home);
        self
    }

    /// The per-user layout scheme (M7-D2): which names an install root has and how it is found.
    /// Independent of the data home, so a test can use [`LayoutScheme::WINDOWS`] in a temporary
    /// data home on any OS.
    pub fn with_layout_scheme(mut self, scheme: LayoutScheme) -> Platform {
        self.layout_scheme = scheme;
        self
    }

    /// The per-user layout scheme.
    pub fn layout_scheme(&self) -> LayoutScheme {
        self.layout_scheme
    }

    /// How long a held install lock is retried before [`Error::Busy`] (default 2 s).
    pub fn with_busy_wait(mut self, wait: Duration) -> Platform {
        self.busy_wait = wait;
        self
    }

    /// The per-user data home: the override, else the native one (Linux, macOS, Windows).
    fn data_home(&self) -> Result<PathBuf, Error> {
        if let Some(home) = &self.data_home {
            return Ok(home.clone());
        }
        native_data_home()
    }

    /// The user's canonical home directory: the override, else `HOME`'s (M8-D1).
    fn home(&self) -> Result<PathBuf, Error> {
        if let Some(home) = &self.home {
            return Ok(home.clone());
        }
        canonical_home(std::env::var_os("HOME").as_deref())
    }
}

/// `HOME` as the macOS layout uses it (M8-D1 amended): set, non-empty, absolute, UTF-8 and an
/// existing directory, canonicalised once (a `HOME` under `/var` is `/private/var`), else the
/// home error of the desktop integration.
#[cfg_attr(not(unix), allow(dead_code))]
fn canonical_home(raw: Option<&std::ffi::OsStr>) -> Result<PathBuf, Error> {
    let home = || Error::from(lunepack_core::IntegrationError::Home);
    let raw = raw
        .and_then(std::ffi::OsStr::to_str)
        .filter(|s| !s.is_empty() && Path::new(s).is_absolute())
        .ok_or_else(home)?;
    let canonical = std::fs::canonicalize(raw).map_err(|_| home())?;
    if canonical.is_dir() {
        Ok(canonical)
    } else {
        Err(home())
    }
}

/// The native layout scheme: [`LayoutScheme::WINDOWS`] on Windows (M7-D2), [`LayoutScheme::MACOS`]
/// on macOS (M8-D1), [`LayoutScheme::XDG`] everywhere else.
fn native_layout_scheme() -> LayoutScheme {
    if cfg!(windows) {
        LayoutScheme::WINDOWS
    } else if cfg!(target_os = "macos") {
        LayoutScheme::MACOS
    } else {
        LayoutScheme::XDG
    }
}

#[cfg(target_os = "linux")]
fn default_process() -> Arc<dyn Process> {
    Arc::new(lunepack_os_linux::LinuxProcess::new())
}

#[cfg(target_os = "linux")]
pub(crate) fn default_integration() -> Arc<dyn OsIntegration> {
    Arc::new(lunepack_os_linux::XdgIntegration::from_process_env())
}

#[cfg(target_os = "linux")]
fn native_data_home() -> Result<PathBuf, Error> {
    let dirs = lunepack_os_linux::xdg_dirs(&lunepack_os_linux::XdgEnv::from_process())?;
    Ok(dirs.data_home().to_path_buf())
}

#[cfg(windows)]
fn default_process() -> Arc<dyn Process> {
    Arc::new(lunepack_os_windows::WindowsProcess::new())
}

#[cfg(windows)]
pub(crate) fn default_integration() -> Arc<dyn OsIntegration> {
    Arc::new(lunepack_os_windows::WindowsIntegration::current_user())
}

/// The per-user program files folder, the parent of an install root (M7-D2).
#[cfg(windows)]
fn native_data_home() -> Result<PathBuf, Error> {
    lunepack_os_windows::user_program_files()
        .map_err(|_| Error::Config("the per-user program files folder is not available"))
}

#[cfg(target_os = "macos")]
fn default_process() -> Arc<dyn Process> {
    Arc::new(lunepack_os_macos::MacProcess::new())
}

#[cfg(target_os = "macos")]
pub(crate) fn default_integration() -> Arc<dyn OsIntegration> {
    Arc::new(lunepack_os_macos::MacIntegration::from_process_env())
}

/// `$HOME/Library/Application Support`, the parent of an install root (M8-D1).
#[cfg(target_os = "macos")]
fn native_data_home() -> Result<PathBuf, Error> {
    let home = canonical_home(std::env::var_os("HOME").as_deref())?;
    Ok(home.join("Library").join("Application Support"))
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
fn default_process() -> Arc<dyn Process> {
    Arc::new(unsupported::Unsupported)
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
pub(crate) fn default_integration() -> Arc<dyn OsIntegration> {
    Arc::new(unsupported::Unsupported)
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
fn native_data_home() -> Result<PathBuf, Error> {
    Err(Error::Unsupported)
}

/// The stand-in adapters of a platform without its own yet: every call is unsupported.
#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
mod unsupported {
    use core::time::Duration;
    use std::path::{Path, PathBuf};

    use lunepack_core::{
        Child, IntegrationError, IntegrationReport, IntegrationRequest, OsIntegration, Process,
        ProcessError, ProcessErrorKind, ProcessId, Scope, SpawnSpec, WaitOutcome,
    };

    pub(super) struct Unsupported;

    fn no<T>(op: &'static str) -> lunepack_core::Result<T> {
        Err(ProcessError::new(ProcessErrorKind::Unsupported, op).into())
    }

    impl Process for Unsupported {
        fn current_exe(&self) -> lunepack_core::Result<PathBuf> {
            no("current_exe")
        }
        fn current(&self) -> lunepack_core::Result<ProcessId> {
            no("current")
        }
        fn parent(&self) -> lunepack_core::Result<Option<ProcessId>> {
            no("parent")
        }
        fn spawn_detached(&self, _: &SpawnSpec) -> lunepack_core::Result<()> {
            no("spawn")
        }
        fn spawn_child(&self, _: &SpawnSpec) -> lunepack_core::Result<Box<dyn Child>> {
            no("spawn")
        }
        fn wait_exit(&self, _: &ProcessId, _: Duration) -> lunepack_core::Result<WaitOutcome> {
            no("wait")
        }
        fn tree_in_use(&self, _: &Path, _: &[ProcessId]) -> lunepack_core::Result<bool> {
            no("in-use scan")
        }
    }

    impl OsIntegration for Unsupported {
        fn check(&self, _: Scope, _: &IntegrationRequest) -> Result<(), IntegrationError> {
            Err(IntegrationError::Unsupported)
        }
        fn apply(
            &self,
            _: Scope,
            _: &IntegrationRequest,
        ) -> Result<IntegrationReport, IntegrationError> {
            Err(IntegrationError::Unsupported)
        }
        fn remove(
            &self,
            _: Scope,
            _: &IntegrationRequest,
        ) -> Result<IntegrationReport, IntegrationError> {
            Err(IntegrationError::Unsupported)
        }
    }
}

/// The update config's path inside the tree `tree`, as `scheme` places it.
pub(crate) fn scheme_config_path(tree: &Path, scheme: LayoutScheme) -> PathBuf {
    let mut out = tree.to_path_buf();
    for name in scheme.config.split('/') {
        out.push(name);
    }
    out
}

/// Where the running bundle `tree` stands under [`LayoutScheme::MACOS`] (M8-D1, M8-D4, M8-D17):
/// the install's layout, when it is the install's (and whether it was found moved), `None` when
/// it is another copy. A refused place is [`Error::UnsupportedLocation`].
fn bundle_layout(
    platform: &Platform,
    exe: &Path,
    tree: &Path,
    k: usize,
    config: &UpdateConfig,
) -> Result<(Option<UserLayout>, bool), Error> {
    let facts = platform.fs.place(tree)?;
    let data_home = platform.data_home()?;
    let home = platform.home()?;
    let probe = BundleProbe {
        exe,
        tree,
        k,
        config,
        facts: &facts,
        data_home: &data_home,
        home: &home,
    };
    let scheme = platform.layout_scheme;
    match discover_bundle(&*platform.fs, &*platform.hasher, &probe) {
        Ok(BundleDiscovery::Installed { root, .. }) => {
            Ok((Some(UserLayout::from_root(root, scheme)), false))
        }
        Ok(BundleDiscovery::MovedFrom { root, .. }) => {
            Ok((Some(UserLayout::from_root(root, scheme)), true))
        }
        Ok(BundleDiscovery::NotInstalled) => Ok((None, false)),
        Err(LayoutError::NotThisTree) => Err(config_rule(
            "install.entry",
            "the executable is not in the entry's directory",
        )),
        Err(e) => Err(Error::from(lunepack_core::Error::Layout(e))),
    }
}

/// An update-config rule broken by where the file is, not by its bytes.
fn config_rule(field: &'static str, rule: &'static str) -> Error {
    Error::UpdateConfig(UpdateConfigError::Invalid { field, rule })
}

/// Reads the update config at `path`: a regular file (not followed when it is a symlink) of at
/// most 64 KiB, parsed by the core's reader. `Ok(None)` when nothing is there.
pub(crate) fn read_config(fs: &dyn Fs, path: &Path) -> Result<Option<UpdateConfig>, Error> {
    match fs.symlink_metadata(path) {
        Ok(None) => return Ok(None),
        Ok(Some(meta)) if meta.kind == FileKind::File => {}
        Ok(Some(_)) => {
            return Err(config_rule(UPDATE_CONFIG_FILE, "is not a regular file"));
        }
        Err(e) if e.kind == FsErrorKind::NotFound || e.kind == FsErrorKind::NotADirectory => {
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    }
    let bytes = match fs.read_capped(path, MAX_UPDATE_CONFIG_BYTES) {
        Ok(bytes) => bytes,
        Err(e) if e.kind == FsErrorKind::TooLarge => {
            return Err(Error::UpdateConfig(UpdateConfigError::TooLarge {
                size: MAX_UPDATE_CONFIG_BYTES + 1,
                cap: MAX_UPDATE_CONFIG_BYTES,
            }));
        }
        Err(e) => return Err(e.into()),
    };
    UpdateConfig::parse(&bytes)
        .map(Some)
        .map_err(Error::UpdateConfig)
}

/// `base` joined with every component of `rel`.
pub(crate) fn join_rel(base: &Path, rel: &RelPath) -> PathBuf {
    let mut out = base.to_path_buf();
    for c in rel.components() {
        out.push(c);
    }
    out
}

/// Text equality of two versions (equal precedence with other build metadata is another tree).
pub(crate) fn same_version(a: &Version, b: &Version) -> bool {
    a == b && a.to_string() == b.to_string()
}

/// Takes `<state dir>/lock`, retrying a held lock for up to `platform`'s busy wait.
pub(crate) fn lock_state(
    platform: &Platform,
    state_dir: &Path,
) -> Result<Box<dyn LockGuard>, Error> {
    platform.fs.create_dir_all(state_dir)?;
    let path = state_dir.join("lock");
    let deadline = Instant::now() + platform.busy_wait;
    loop {
        if let Some(guard) = platform.fs.try_lock(&path)? {
            return Ok(guard);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(Error::Busy);
        }
        std::thread::sleep(BUSY_POLL.min(deadline - now));
    }
}

/// The version tree an executable belongs to, its update config and, when it is installed, the
/// install's layout (C4 Locating, M5-D17).
#[derive(Clone)]
pub struct Installation {
    pub(crate) platform: Platform,
    tree: PathBuf,
    config: UpdateConfig,
    layout: Option<UserLayout>,
    /// The running bundle is the install's, found where it was moved to (M8-D17): the install
    /// follows it under the lock ([`Installation::follow_move`], and `startup_for`).
    moved: bool,
}

impl fmt::Debug for Installation {
    /// Shows the app id, the tree's version and whether it is installed; no path.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Installation")
            .field("app_id", &self.config.app_id.as_str())
            .field("version", &self.config.version.to_string())
            .field("installed", &self.layout.is_some())
            .finish_non_exhaustive()
    }
}

impl Installation {
    /// The installation of the running executable ([`Process::current_exe`]), with the native
    /// adapters.
    pub fn from_current_exe() -> Result<Installation, Error> {
        Installation::from_current_exe_with(Platform::native())
    }

    /// [`Installation::from_current_exe`] on `platform`.
    pub fn from_current_exe_with(platform: Platform) -> Result<Installation, Error> {
        let exe = platform.process.current_exe()?;
        Installation::from_exe_with(&exe, platform)
    }

    /// The installation of the executable at `exe`, with the native adapters.
    pub fn from_exe(exe: &Path) -> Result<Installation, Error> {
        Installation::from_exe_with(exe, Platform::native())
    }

    /// The installation of the executable at `exe` on `platform` (P3, P4):
    ///
    /// - Each directory from the exe's own up (at most 31 above it) is tested for
    ///   `lunepack-update.json`, without following a symlink. The first one found decides: a
    ///   file that is not regular, a config the reader refuses, or an exe that is not in that
    ///   config's entry directory is [`Error::UpdateConfig`], and no directory further up is
    ///   tried.
    /// - No directory holds one: [`Error::NoUpdateConfig`].
    /// - An installed tree (`R/versions/<its version>` under [`LayoutScheme::XDG`],
    ///   `R\app\<its version>` under [`LayoutScheme::WINDOWS`], whatever `R` is named) also has
    ///   its install state under `R` loaded, which must carry the config's app id.
    /// - Under [`LayoutScheme::MACOS`] the config is at `Contents/Resources/lunepack-update.json`
    ///   of the bundle, and the running tree's location is judged first (M8-D4): a tree
    ///   translocated by Gatekeeper, or on a read-only volume (a mounted disk image), is
    ///   [`Error::UnsupportedLocation`], whatever else is true of it. The tree is then the
    ///   install's when `R/bundle` names it or it is an old instance in `R/versions`; a bundle
    ///   moved on its volume is the install's too ([`Installation::moved`], M8-D17); any other
    ///   copy is not installed.
    pub fn from_exe_with(exe: &Path, platform: Platform) -> Result<Installation, Error> {
        // The native filesystem refuses symlinked components: resolve the exe (a launch through
        // `R/current` or a command link lands in its real tree).
        let exe = if platform.native_fs {
            std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf())
        } else {
            exe.to_path_buf()
        };
        for (tree, k) in tree_candidates(&exe) {
            let scheme = platform.layout_scheme;
            let config_path = scheme_config_path(&tree, scheme);
            let Some(config) = read_config(&*platform.fs, &config_path)? else {
                continue;
            };
            let (layout, moved) = if scheme.projection == Projection::Bundle {
                bundle_layout(&platform, &exe, &tree, k, &config)?
            } else {
                let layout = match discover(&exe, &tree, k, &config, scheme) {
                    Ok(Discovery::Installed { root, .. }) => {
                        Some(UserLayout::from_root(root, scheme))
                    }
                    Ok(Discovery::NotInstalled) => None,
                    Err(_) => {
                        return Err(config_rule(
                            "install.entry",
                            "the executable is not in the entry's directory",
                        ));
                    }
                };
                (layout, false)
            };
            if let Some(layout) = &layout {
                let store = UserScope {
                    dir: layout.state_dir(),
                    app_id: config.app_id.clone(),
                };
                store.load(&*platform.fs, &*platform.hasher)?;
            }
            return Ok(Installation {
                platform,
                tree,
                config,
                layout,
                moved,
            });
        }
        Err(Error::NoUpdateConfig)
    }

    /// Another version `version` of the same install, from that version's tree's config (no
    /// walk, M5-D17). Its config must name this app id and that version.
    pub fn version_installation(&self, version: &Version) -> Result<Installation, Error> {
        let layout = self.layout.as_ref().ok_or(Error::NotInstalled)?;
        let path = layout.version_config_path(version);
        let config = read_config(&*self.platform.fs, &path)?.ok_or(Error::NoUpdateConfig)?;
        if config.app_id != self.config.app_id {
            return Err(Error::UpdateConfig(UpdateConfigError::RootMismatch(
                "app_id",
            )));
        }
        if !same_version(&config.version, version) {
            return Err(config_rule(
                "version",
                "is not the version of its directory",
            ));
        }
        Ok(Installation {
            platform: self.platform.clone(),
            tree: layout.version_dir(version),
            config,
            layout: Some(layout.clone()),
            moved: false,
        })
    }

    /// The app id.
    pub fn app_id(&self) -> &AppId {
        &self.config.app_id
    }

    /// The tree's own version.
    pub fn tree_version(&self) -> &Version {
        &self.config.version
    }

    /// Whether the tree is a version of an install (`R/versions/<version>`).
    pub fn is_installed(&self) -> bool {
        self.layout.is_some()
    }

    /// The install's layout, when the tree is installed.
    pub fn layout(&self) -> Option<&UserLayout> {
        self.layout.as_ref()
    }

    /// Whether this macOS bundle is the install's, found where the user moved it (M8-D17): the
    /// install is followed to its new place by [`follow_move`](crate::follow_move), which
    /// [`startup_for`](crate::startup_for) does under the lock, and not before.
    pub fn moved(&self) -> bool {
        self.moved
    }

    /// The tree the install's current version runs from: under [`LayoutScheme::MACOS`] the live
    /// bundle `R/bundle` names (the running tree itself when the install was found moved),
    /// otherwise `None` (the current tree is `<versions>/<current>`, M4-D4).
    pub(crate) fn live_tree(&self) -> Result<Option<PathBuf>, Error> {
        let Some(layout) = &self.layout else {
            return Ok(None);
        };
        if layout.scheme().projection != Projection::Bundle {
            return Ok(None);
        }
        if self.moved {
            return Ok(Some(self.tree.clone()));
        }
        layout
            .current_tree_with(&*self.platform.fs)
            .map_err(|e| Error::from(lunepack_core::Error::Layout(e)))
    }

    /// The path of the entry that starts `version`'s tree once it is current: under the bundle
    /// layout the live bundle's, since the version's own tree is where it was staged only until
    /// the swap puts it in the bundle; elsewhere `tree_entry`.
    pub(crate) fn live_entry(
        &self,
        tree_entry: PathBuf,
        entry: &RelPath,
    ) -> Result<PathBuf, Error> {
        Ok(match self.live_tree()? {
            Some(bundle) => join_rel(&bundle, entry),
            None => tree_entry,
        })
    }

    /// The version tree's root directory.
    pub fn tree_root(&self) -> &Path {
        &self.tree
    }

    /// The tree's runtime: `lunepack-runtime` (`.exe` on Windows) beside the entry (C4).
    pub fn runtime_path(&self) -> PathBuf {
        let entry = join_rel(&self.tree, &self.config.install.entry);
        entry
            .parent()
            .unwrap_or(&self.tree)
            .join(runtime_file(self.config.target))
    }

    /// The tree's entry executable.
    pub fn entry_path(&self) -> PathBuf {
        join_rel(&self.tree, &self.config.install.entry)
    }

    /// The install metadata of the tree's config.
    pub fn meta(&self) -> &InstallMeta {
        &self.config.install
    }

    /// The tree's whole update config.
    pub fn config(&self) -> &UpdateConfig {
        &self.config
    }

    /// The install root `R`: the installed tree's, else where this tree installs per user, as
    /// [`resolve_root`] finds it under the platform's layout scheme (`<data home>/<app id>` under
    /// [`LayoutScheme::XDG`], M5-D2; under [`LayoutScheme::WINDOWS`] the folder of an existing
    /// install of this app id, else one named after the display name, M7-D16, M7-D17). The data
    /// home comes from the platform or the environment.
    pub fn install_root(&self) -> Result<PathBuf, Error> {
        Ok(self.install_layout()?.root().to_path_buf())
    }

    /// The install's layout: the installed tree's, else the one under
    /// [`Installation::install_root`] with the platform's layout scheme.
    pub fn install_layout(&self) -> Result<UserLayout, Error> {
        if let Some(layout) = &self.layout {
            return Ok(layout.clone());
        }
        let p = &self.platform;
        let root = resolve_root(
            &*p.fs,
            &*p.hasher,
            &p.data_home()?,
            &self.config.app_id,
            &self.config.install.name,
            p.layout_scheme,
        )
        .map_err(|e| Error::from(lunepack_core::Error::Layout(e)))?;
        Ok(UserLayout::from_root(root.into_path(), p.layout_scheme))
    }

    /// The [`Layout`] the updater of this install runs on: the installed tree's, whose live tree
    /// under the bundle layout is the bundle (M8-D1; the unchanged-file scan reads it), else the
    /// layout under [`Installation::install_root`] with this tree as the bootstrap's current tree.
    pub(crate) fn updater_layout(&self) -> Result<Layout, Error> {
        Ok(match &self.layout {
            Some(layout) => {
                let mut user = Layout::user(layout);
                if let (Layout::User { current_tree, .. }, Some(live)) =
                    (&mut user, self.live_tree()?)
                {
                    *current_tree = Some(live);
                }
                user
            }
            None => {
                let user = self.install_layout()?;
                Layout::User {
                    state_dir: user.state_dir(),
                    cache_dir: user.cache_dir(),
                    versions_dir: user.versions_dir(),
                    current_tree: Some(self.tree.clone()),
                }
            }
        })
    }

    /// An [`UpdaterBuilder`] for this install, from the config alone: its trusted root, feed and
    /// channel (a later [`UpdaterBuilder::channel`] may follow another channel), and the
    /// platform's filesystem, crypto, randomness and integration.
    ///
    /// The feed passes [`check_config_feed`] again first (a tree written by another packager is
    /// not trusted to have run it); a refusal is [`Error::UpdateConfig`] before any request. An
    /// `http:` feed (loopback only) is fetched with no proxy and no redirect (M5-D16). A `file:`
    /// feed is served by the default directory source rooted at the parent of the release
    /// directory the URL names.
    ///
    /// A not-installed tree (a bootstrap) gets the layout under [`Installation::install_root`],
    /// with itself as the current tree, for [`Updater::install`](crate::Updater::install).
    pub fn updater_builder(&self) -> Result<UpdaterBuilder, Error> {
        let kind = check_config_feed(&self.config.feed).map_err(Error::UpdateConfig)?;
        let p = &self.platform;
        let root =
            self.config
                .root
                .to_trusted(self.config.app_id.clone(), &*p.hasher, &*p.verifier)?;
        let layout = self.updater_layout()?;
        let mut builder = UpdaterBuilder::new(
            self.config.app_id.clone(),
            root,
            &self.config.feed,
            self.config.channel.clone(),
            layout,
        )
        .fs(Arc::clone(&p.fs))
        .hasher(Arc::clone(&p.hasher))
        .verifier(Arc::clone(&p.verifier))
        .rng(Arc::clone(&p.rng))
        .integration(Arc::clone(&p.integration));
        if kind == FeedKind::HttpLoopback {
            let options = lunepack_http::UreqOptions {
                direct: true,
                max_redirects: 0,
                ..lunepack_http::UreqOptions::default()
            };
            builder = builder.blocking_transport(Arc::new(
                lunepack_http::UreqTransport::with_options(&options),
            ));
        }
        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lunepack_core::FeedRule;
    use lunepack_testkit::{FakeHasher, FakeVerifier, MemFs, sample_update_config};

    /// The builder runs the feed rule itself: a config edited through the typed document after it
    /// was read is refused before an updater (and so any request) exists.
    #[test]
    fn the_builder_refuses_a_feed_edited_after_reading() {
        for feed in [
            "http://10.0.0.1/",
            "http://localhost:8080/",
            "ftp://example.com/",
        ] {
            let mut config = sample_update_config();
            config.feed = feed.to_owned();
            let inst = Installation {
                platform: Platform::native()
                    .with_fs(Arc::new(MemFs::new()))
                    .with_hasher(Arc::new(FakeHasher))
                    .with_verifier(Arc::new(FakeVerifier))
                    .with_data_home(PathBuf::from("/data")),
                tree: PathBuf::from("/boot/tree"),
                config,
                layout: None,
                moved: false,
            };
            let got = inst.updater_builder();
            assert!(
                matches!(got, Err(Error::UpdateConfig(UpdateConfigError::Feed(_)))),
                "{feed}: {:?}",
                got.err()
            );
        }
        assert!(matches!(
            check_config_feed("http://10.0.0.1/"),
            Err(UpdateConfigError::Feed(FeedRule::HttpNotLoopback))
        ));
    }

    fn windows_platform(fs: &Arc<MemFs>, data_home: &Path) -> Platform {
        Platform::native()
            .with_fs(Arc::clone(fs) as Arc<dyn Fs>)
            .with_hasher(Arc::new(FakeHasher))
            .with_verifier(Arc::new(FakeVerifier))
            .with_data_home(data_home.to_path_buf())
            .with_layout_scheme(LayoutScheme::WINDOWS)
    }

    /// Writes `config` as the tree at `tree` and returns its entry's path.
    fn put_tree(fs: &MemFs, tree: &Path, config: &UpdateConfig) -> PathBuf {
        use std::io::Write as _;
        fs.create_dir_all(tree).unwrap();
        let mut f = fs.create_new(&tree.join(UPDATE_CONFIG_FILE)).unwrap();
        f.write_all(&config.to_bytes().unwrap()).unwrap();
        f.sync().unwrap();
        join_rel(tree, &config.install.entry)
    }

    /// Commits a first record of `config`'s app id under `root`'s Windows state directory.
    fn put_record(fs: &MemFs, root: &Path, config: &UpdateConfig) {
        let layout = UserLayout::from_root(root.to_path_buf(), LayoutScheme::WINDOWS);
        fs.create_dir_all(&layout.state_dir()).unwrap();
        let store = UserScope {
            dir: layout.state_dir(),
            app_id: config.app_id.clone(),
        };
        let loaded = store.load(fs, &FakeHasher).unwrap();
        let record = lunepack_core::InstallState::new(
            1,
            config.app_id.clone(),
            lunepack_core::Scope::User,
            [3; 16],
            config.target,
        );
        store.commit(fs, &loaded, &record, &FakeHasher).unwrap();
    }

    /// Under the Windows scheme a bootstrap's install root is resolved by record (M7-D16): an
    /// install under an older display name is found, else a folder named after the app.
    #[test]
    fn a_bootstrap_resolves_its_root_by_record_under_the_windows_scheme() {
        let fs = Arc::new(MemFs::new());
        let dh = lunepack_testkit::abs_path("/Programs");
        let config = sample_update_config();
        let exe = put_tree(&fs, &lunepack_testkit::abs_path("/Downloads/boot"), &config);
        let inst = Installation::from_exe_with(&exe, windows_platform(&fs, &dh)).unwrap();
        assert!(!inst.is_installed());
        assert_eq!(inst.install_root().unwrap(), dh.join(&config.install.name));
        let layout = inst.install_layout().unwrap();
        assert_eq!(layout.scheme(), LayoutScheme::WINDOWS);

        put_record(&fs, &dh.join("Old Name"), &config);
        assert_eq!(inst.install_root().unwrap(), dh.join("Old Name"));
        assert_eq!(
            inst.updater_builder()
                .map(|_| ())
                .err()
                .map(|e| e.to_string()),
            None
        );
    }

    /// An installed tree under the Windows scheme is `R\app\<version>`, whatever `R` is named; the
    /// same tree under a `versions` directory is a bootstrap.
    #[test]
    fn an_installed_tree_is_found_under_app_by_the_windows_scheme() {
        let fs = Arc::new(MemFs::new());
        let dh = lunepack_testkit::abs_path("/Programs");
        let config = sample_update_config();
        let root = dh.join("Any Folder Name");
        let tree = root.join("app").join(config.version.to_string());
        let exe = put_tree(&fs, &tree, &config);
        put_record(&fs, &root, &config);
        let inst = Installation::from_exe_with(&exe, windows_platform(&fs, &dh)).unwrap();
        let layout = inst.layout().expect("installed");
        assert_eq!(layout.root(), root);
        assert_eq!(layout.state_dir(), root.join(".lunepack").join("state"));
        assert_eq!(inst.install_root().unwrap(), root);

        let other = dh
            .join("X")
            .join("versions")
            .join(config.version.to_string());
        let exe = put_tree(&fs, &other, &config);
        let inst = Installation::from_exe_with(&exe, windows_platform(&fs, &dh)).unwrap();
        assert!(!inst.is_installed());
    }

    /// A display name the Windows rule refuses is an update-config error (exit `config`).
    #[test]
    fn a_name_the_windows_rule_refuses_is_an_update_config_error() {
        let fs = Arc::new(MemFs::new());
        let dh = lunepack_testkit::abs_path("/Programs");
        let mut config = sample_update_config();
        config.install.name = "CON".to_owned();
        let exe = put_tree(&fs, &lunepack_testkit::abs_path("/Downloads/boot"), &config);
        let inst = Installation::from_exe_with(&exe, windows_platform(&fs, &dh)).unwrap();
        assert!(matches!(
            inst.install_root(),
            Err(Error::UpdateConfig(UpdateConfigError::Invalid {
                field: "name",
                ..
            }))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn home_is_canonicalised_once() {
        let tmp = tempfile::tempdir().expect("tmp");
        let real = std::fs::canonicalize(tmp.path()).expect("canonical");
        std::fs::create_dir(real.join("home")).expect("home");
        std::os::unix::fs::symlink(real.join("home"), real.join("alias")).expect("symlink");
        let got = canonical_home(Some(real.join("alias").as_os_str())).expect("home");
        assert_eq!(got, real.join("home"));
        // Unset, empty, relative, missing and not-a-directory homes are the home error.
        std::fs::write(real.join("file"), b"x").expect("file");
        for bad in [
            None,
            Some(std::ffi::OsString::new()),
            Some(std::ffi::OsString::from("relative")),
            Some(real.join("missing").into_os_string()),
            Some(real.join("file").into_os_string()),
        ] {
            let got = canonical_home(bad.as_deref());
            assert!(
                matches!(
                    got,
                    Err(Error::Integration(lunepack_core::IntegrationError::Home))
                ),
                "{got:?}"
            );
        }
    }

    /// The updater of a bundle install reads the live bundle `R/bundle` names, whichever tree runs;
    /// a bundle found moved is its own live tree; a bootstrap's is itself.
    #[test]
    fn the_updater_of_a_bundle_install_reads_the_live_bundle() {
        use lunepack_core::{Target, set_bundle_pointer, write_bundle_identity};
        let fs = Arc::new(MemFs::new());
        let home = lunepack_testkit::abs_path("/Users/u");
        let data_home = home.join("Library").join("Application Support");
        let mut config = sample_update_config();
        config.target = Target::MacosAarch64;
        config.install.entry = RelPath::parse("Contents/MacOS/hello").unwrap();
        let layout =
            UserLayout::from_root(data_home.join(config.app_id.as_str()), LayoutScheme::MACOS);
        let bundle = home.join("Applications").join("Hello.app");
        let old = layout.version_dir(&config.version);
        for tree in [&bundle, &old] {
            let exe = put_bundle(&fs, tree, &config);
            assert!(exe.ends_with("Contents/MacOS/hello"));
        }
        fs.create_dir_all(&layout.state_dir()).unwrap();
        set_bundle_pointer(&*fs, &layout, &bundle).unwrap();
        write_bundle_identity(&*fs, &layout, &bundle).unwrap();
        let record = lunepack_core::InstallState::new(
            1,
            config.app_id.clone(),
            lunepack_core::Scope::User,
            [3; 16],
            config.target,
        )
        .install(config.version.clone(), 10, config.target, [3; 16]);
        let store = UserScope {
            dir: layout.state_dir(),
            app_id: config.app_id.clone(),
        };
        let loaded = store.load(&*fs, &FakeHasher).unwrap();
        store.commit(&*fs, &loaded, &record, &FakeHasher).unwrap();
        let platform = || {
            Platform::native()
                .with_fs(Arc::clone(&fs) as Arc<dyn Fs>)
                .with_hasher(Arc::new(FakeHasher))
                .with_verifier(Arc::new(FakeVerifier))
                .with_data_home(data_home.clone())
                .with_home(home.clone())
                .with_layout_scheme(LayoutScheme::MACOS)
        };
        let current_tree = |layout: Layout| match layout {
            Layout::User { current_tree, .. } => current_tree,
            other => panic!("not a user layout: {other:?}"),
        };
        // The bundle itself and an old instance both name the bundle.
        for exe in [
            bundle.join("Contents/MacOS/hello"),
            old.join("Contents/MacOS/hello"),
        ] {
            let inst = Installation::from_exe_with(&exe, platform()).unwrap();
            assert!(inst.is_installed());
            assert_eq!(
                current_tree(inst.updater_layout().unwrap()),
                Some(bundle.clone())
            );
        }
        // A copy that is not the install's is its own bootstrap tree.
        let stray = home.join("Downloads").join("Hello.app");
        put_bundle(&fs, &stray, &config);
        let inst =
            Installation::from_exe_with(&stray.join("Contents/MacOS/hello"), platform()).unwrap();
        assert!(!inst.is_installed());
        assert_eq!(current_tree(inst.updater_layout().unwrap()), Some(stray));
        // The bundle moved: the moved bundle is the live tree.
        let moved = home.join("Documents").join("Hello.app");
        fs.create_dir_all(moved.parent().unwrap()).unwrap();
        fs.rename(&bundle, &moved).unwrap();
        let inst =
            Installation::from_exe_with(&moved.join("Contents/MacOS/hello"), platform()).unwrap();
        assert!(inst.moved());
        assert_eq!(current_tree(inst.updater_layout().unwrap()), Some(moved));
    }

    /// A bundle tree at `tree` (the config and the entry); returns the entry's path.
    fn put_bundle(fs: &MemFs, tree: &Path, config: &UpdateConfig) -> PathBuf {
        use std::io::Write as _;
        let write = |path: PathBuf, bytes: &[u8]| {
            fs.create_dir_all(path.parent().unwrap()).unwrap();
            let mut f = fs.create_new(&path).unwrap();
            f.write_all(bytes).unwrap();
            f.sync().unwrap();
            path
        };
        write(
            tree.join("Contents/Resources").join(UPDATE_CONFIG_FILE),
            &config.to_bytes().unwrap(),
        );
        write(tree.join("Contents/MacOS/hello"), b"app")
    }
}
