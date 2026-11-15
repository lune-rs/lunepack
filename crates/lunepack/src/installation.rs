//! Where the running executable stands (C4 Locating, M5-D17): [`Installation`] finds the version
//! tree an executable belongs to from its own path, reads that tree's update config (FORMAT.md
//! 13) and, when the tree is under an install's `versions` directory, the install's layout
//! (M5-D2).
//!
//! The adapters the lifecycle calls use are a [`Platform`]: the native one wires the default
//! filesystem, crypto and randomness everywhere, and the Linux process and desktop integration
//! adapters on Linux. On other platforms the process and integration calls are
//! [`Error::Unsupported`] until their adapters exist.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lunepack_core::state::UserScope;
use lunepack_core::update_config::{MAX_UPDATE_CONFIG_BYTES, runtime_file};
use lunepack_core::{
    AppId, Discovery, FeedKind, FileKind, Fs, FsErrorKind, Hasher, InstallMeta, LockGuard,
    OsIntegration, Process, RelPath, Rng, UPDATE_CONFIG_FILE, UpdateConfig, UpdateConfigError,
    UserLayout, Verifier, Version, discover, tree_candidates, version_config_path,
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
    pub(crate) busy_wait: Duration,
}

impl fmt::Debug for Platform {
    /// Shows nothing of the token, only whether one is present.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Platform")
            .field("native_fs", &self.native_fs)
            .field("health_token", &self.health_token.is_some())
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
    /// `$HOME/.local/share`): a not-installed tree installs into `<data home>/<app id>`.
    pub fn with_data_home(mut self, data_home: PathBuf) -> Platform {
        self.data_home = Some(data_home);
        self
    }

    /// How long a held install lock is retried before [`Error::Busy`] (default 2 s).
    pub fn with_busy_wait(mut self, wait: Duration) -> Platform {
        self.busy_wait = wait;
        self
    }

    /// The per-user data home: the override, else the environment's (Linux).
    fn data_home(&self) -> Result<PathBuf, Error> {
        if let Some(home) = &self.data_home {
            return Ok(home.clone());
        }
        native_data_home()
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

#[cfg(not(target_os = "linux"))]
fn default_process() -> Arc<dyn Process> {
    Arc::new(unsupported::Unsupported)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn default_integration() -> Arc<dyn OsIntegration> {
    Arc::new(unsupported::Unsupported)
}

#[cfg(not(target_os = "linux"))]
fn native_data_home() -> Result<PathBuf, Error> {
    Err(Error::Unsupported)
}

/// The stand-in adapters of a platform without its own yet: every call is unsupported.
#[cfg(not(target_os = "linux"))]
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
    /// - An installed tree (`R/versions/<its version>`) also has its install state at `R/state`
    ///   loaded, which must carry the config's app id.
    pub fn from_exe_with(exe: &Path, platform: Platform) -> Result<Installation, Error> {
        // The native filesystem refuses symlinked components: resolve the exe (a launch through
        // `R/current` or a command link lands in its real tree).
        let exe = if platform.native_fs {
            std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf())
        } else {
            exe.to_path_buf()
        };
        for (tree, k) in tree_candidates(&exe) {
            let Some(config) = read_config(&*platform.fs, &tree.join(UPDATE_CONFIG_FILE))? else {
                continue;
            };
            let layout = match discover(&exe, &tree, k, &config) {
                Ok(Discovery::Installed { root, .. }) => Some(UserLayout::from_root(root)),
                Ok(Discovery::NotInstalled) => None,
                Err(_) => {
                    return Err(config_rule(
                        "install.entry",
                        "the executable is not in the entry's directory",
                    ));
                }
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
            });
        }
        Err(Error::NoUpdateConfig)
    }

    /// Another version `version` of the same install, from `R/versions/<version>`'s config (no
    /// walk, M5-D17). Its config must name this app id and that version.
    pub fn version_installation(&self, version: &Version) -> Result<Installation, Error> {
        let layout = self.layout.as_ref().ok_or(Error::NotInstalled)?;
        let path = version_config_path(layout.root(), version);
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

    /// The install root `R`: the installed tree's, else where this tree installs per user,
    /// `<data home>/<app id>` (M5-D2; the data home from the platform or the environment).
    pub fn install_root(&self) -> Result<PathBuf, Error> {
        match &self.layout {
            Some(layout) => Ok(layout.root().to_path_buf()),
            None => Ok(self.platform.data_home()?.join(self.config.app_id.as_str())),
        }
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
        let layout = match &self.layout {
            Some(layout) => Layout::user(layout),
            None => {
                let user = UserLayout::from_root(self.install_root()?);
                Layout::User {
                    state_dir: user.state_dir(),
                    cache_dir: user.cache_dir(),
                    versions_dir: user.versions_dir(),
                    current_tree: Some(self.tree.clone()),
                }
            }
        };
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
}
