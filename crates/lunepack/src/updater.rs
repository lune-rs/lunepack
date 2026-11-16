//! The [`Updater`] (C9): check for an update, download it resumably and stage a verified version
//! tree, on any async executor (or none, through [`crate::blocking`]).
//!
//! Every operation takes the updater lock (`<state dir>/lock`; for a machine install the user
//! state dir) on a short job when it starts, and a held lock is [`Error::Busy`] at once. The
//! operation's future holds one clone of the lock and every job it spawns holds another, so the
//! lock is released only when the future and all of its workers are gone (M4-D15). All file I/O
//! runs on lunepack worker threads; transports are polled on the caller's task (M4-D2).
//!
//! State changes only at a commit: `check` raises the floors after a fully verified check, `stage`
//! records the staged tree after it is complete. A failing or cancelled operation leaves the state
//! as it was (FORMAT.md 11.1).

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::{Future, poll_fn};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use lunepack_core::fetch::FetchPolicy;
use lunepack_core::state::{CurrentRef, Scope};
use lunepack_core::state::{
    Floors, InstallCounters, InstallState, Loaded, MachineScope as MachineStore, RootParts,
    StagedRef, UserScope,
};
use lunepack_core::update_config::MAX_UPDATE_CONFIG_BYTES;
use lunepack_core::{
    AppId, BlockingResponse, BlockingTransport, CancelToken, Channel, ClockReading, Codec,
    FileKind, Fs, Hasher, IntegrationRequest, Limits, OsIntegration, Phase, Progress, ReadAt,
    RelPath, Request, Rng, Sha256Digest, SourceFor, StageEnv, StageError, StageInput, Target,
    Transport, TransportError, TrustedRoot, UPDATE_CONFIG_FILE, UpdateConfig, UpdateConfigError,
    VerifiedEntry, VerifiedManifest, Verifier, Version, advance_root, read_entry, select_candidate,
    verify_feed, verify_key_set, verify_manifest, verify_payload_manifest,
};

use crate::cache::{Cache, CacheKind, PartTools};
use crate::fetch::{self, FeedUrls, FetchCtx, FrameNeed, PackTarget, cancellable};
use crate::progress::{ProgressPump, ProgressSink, progress};
use crate::task::{OpLock, spawn_job};
use crate::worker_transport::WorkerTransport;
use crate::{Error, SystemClock};

/// The most root rotations one check walks (a bound on a hostile mirror's root chain).
const MAX_ROOT_STEPS: u64 = 1024;
/// The default stage memory budget (M4-D11).
const DEFAULT_BUDGET: u64 = 256 * 1024 * 1024;

// ---- configuration -------------------------------------------------------------------------------

/// Where an install keeps its state, cache and version trees (M4-D4).
///
/// Version `V`'s tree is `<versions_dir>/<V's version text>`. The current tree is `current_tree`
/// when given (for a layout whose live tree is not under `versions_dir`), else
/// `<versions_dir>/<current version>`; it counts only when it is a real directory (not a
/// symlink). Without a current tree every file is fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Layout {
    /// A per-user install.
    User {
        /// The install-state directory.
        state_dir: PathBuf,
        /// The download cache.
        cache_dir: PathBuf,
        /// Where version trees are staged.
        versions_dir: PathBuf,
        /// The live tree, when it is not `<versions_dir>/<current>`.
        current_tree: Option<PathBuf>,
    },
    /// A per-machine install: the library reads the machine state and tree, never writes them, and
    /// keeps this user's floors and cache in the user's directories (C3).
    Machine {
        /// The machine install's state directory (read-only here).
        machine_state_dir: PathBuf,
        /// This user's state directory (counters records and the lock).
        user_state_dir: PathBuf,
        /// This user's download cache.
        cache_dir: PathBuf,
        /// The machine install's version trees (read-only), if readable.
        versions_dir: Option<PathBuf>,
        /// The machine install's live tree, when it is not under `versions_dir`.
        current_tree: Option<PathBuf>,
    },
}

impl Layout {
    /// The layout of a per-user install rooted at `layout`'s root (M5-D2): its `state`, `cache`
    /// and `versions` directories, and no separate live tree (the current tree is
    /// `versions/<current>`, M4-D4).
    pub fn user(layout: &lunepack_core::UserLayout) -> Layout {
        Layout::User {
            state_dir: layout.state_dir(),
            cache_dir: layout.cache_dir(),
            versions_dir: layout.versions_dir(),
            current_tree: layout.current_tree(),
        }
    }

    fn lock_dir(&self) -> &Path {
        match self {
            Layout::User { state_dir, .. } => state_dir,
            Layout::Machine { user_state_dir, .. } => user_state_dir,
        }
    }

    fn cache_dir(&self) -> &Path {
        match self {
            Layout::User { cache_dir, .. } | Layout::Machine { cache_dir, .. } => cache_dir,
        }
    }

    fn versions_dir(&self) -> Option<&Path> {
        match self {
            Layout::User { versions_dir, .. } => Some(versions_dir),
            Layout::Machine { versions_dir, .. } => versions_dir.as_deref(),
        }
    }

    fn current_tree(&self) -> Option<&Path> {
        match self {
            Layout::User { current_tree, .. } | Layout::Machine { current_tree, .. } => {
                current_tree.as_deref()
            }
        }
    }

    /// The layout with `f` applied to every directory and `tree` to the live tree.
    fn map(&self, f: impl Fn(&Path) -> PathBuf, tree: impl Fn(&Path) -> PathBuf) -> Layout {
        match self {
            Layout::User {
                state_dir,
                cache_dir,
                versions_dir,
                current_tree,
            } => Layout::User {
                state_dir: f(state_dir),
                cache_dir: f(cache_dir),
                versions_dir: f(versions_dir),
                current_tree: current_tree.as_deref().map(&tree),
            },
            Layout::Machine {
                machine_state_dir,
                user_state_dir,
                cache_dir,
                versions_dir,
                current_tree,
            } => Layout::Machine {
                machine_state_dir: f(machine_state_dir),
                user_state_dir: f(user_state_dir),
                cache_dir: f(cache_dir),
                versions_dir: versions_dir.as_deref().map(&f),
                current_tree: current_tree.as_deref().map(&tree),
            },
        }
    }
}

/// Timeouts of the default HTTP transport (M4-D14). There is no global timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Longest wait for a connection, TLS included.
    pub connect: Duration,
    /// Longest wait for one read.
    pub read: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            connect: Duration::from_secs(30),
            read: Duration::from_secs(30),
        }
    }
}

/// Builds an [`Updater`]; every capability has a default adapter and can be replaced.
pub struct UpdaterBuilder {
    app_id: AppId,
    root: TrustedRoot,
    feed_url: String,
    channel: Channel,
    layout: Layout,
    transport: Option<Arc<dyn Transport>>,
    blocking_transport: Option<Arc<dyn BlockingTransport>>,
    fs: Option<Arc<dyn Fs>>,
    codec: Option<Arc<dyn Codec>>,
    hasher: Option<Arc<dyn Hasher>>,
    verifier: Option<Arc<dyn Verifier>>,
    clock: Option<Arc<dyn lunepack_core::Clock>>,
    rng: Option<Arc<dyn Rng>>,
    integration: Option<Arc<dyn OsIntegration>>,
    workers: Option<usize>,
    budget: u64,
    policy: FetchPolicy,
    timeouts: Timeouts,
}

impl fmt::Debug for UpdaterBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdaterBuilder").finish_non_exhaustive()
    }
}

impl UpdaterBuilder {
    /// A builder for the app `app_id`, trusting `trusted_root` (kept in the app's code, D44 note),
    /// reading the feed at `feed_url` on `channel`, with the install's `layout`.
    pub fn new(
        app_id: AppId,
        trusted_root: TrustedRoot,
        feed_url: &str,
        channel: Channel,
        layout: Layout,
    ) -> Self {
        UpdaterBuilder {
            app_id,
            root: trusted_root,
            feed_url: feed_url.to_owned(),
            channel,
            layout,
            transport: None,
            blocking_transport: None,
            fs: None,
            codec: None,
            hasher: None,
            verifier: None,
            clock: None,
            rng: None,
            integration: None,
            workers: None,
            budget: DEFAULT_BUDGET,
            policy: FetchPolicy::default(),
            timeouts: Timeouts::default(),
        }
    }

    /// An async transport (polled on the caller's task); wins over every other transport.
    pub fn transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// A blocking transport, run on lunepack worker threads.
    pub fn blocking_transport(mut self, transport: Arc<dyn BlockingTransport>) -> Self {
        self.blocking_transport = Some(transport);
        self
    }

    /// The filesystem (default: `lunepack-fs`).
    pub fn fs(mut self, fs: Arc<dyn Fs>) -> Self {
        self.fs = Some(fs);
        self
    }

    /// The frame decoder (default: `lunepack-codec-lzma`).
    pub fn codec(mut self, codec: Arc<dyn Codec>) -> Self {
        self.codec = Some(codec);
        self
    }

    /// SHA-256 (default: `lunepack-crypto`).
    pub fn hasher(mut self, hasher: Arc<dyn Hasher>) -> Self {
        self.hasher = Some(hasher);
        self
    }

    /// The signature verifier (default: `lunepack-crypto` Ed25519).
    pub fn verifier(mut self, verifier: Arc<dyn Verifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// The clock (default: [`SystemClock`]).
    pub fn clock(mut self, clock: Arc<dyn lunepack_core::Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// The channel to follow instead of the one given to [`UpdaterBuilder::new`] (a valid name,
    /// FORMAT.md 10.5).
    pub fn channel(mut self, channel: Channel) -> Self {
        self.channel = channel;
        self
    }

    /// The random source of [`Updater::install`]'s install id (default: the OS's).
    pub fn rng(mut self, rng: Arc<dyn Rng>) -> Self {
        self.rng = Some(rng);
        self
    }

    /// The desktop integration [`Updater::install`] applies (default: XDG on Linux; elsewhere
    /// [`Error::Unsupported`]).
    pub fn integration(mut self, integration: Arc<dyn OsIntegration>) -> Self {
        self.integration = Some(integration);
        self
    }

    /// Worker threads for scan and stage (default `min(available_parallelism, 8)`).
    pub fn workers(mut self, workers: usize) -> Self {
        self.workers = Some(workers);
        self
    }

    /// The stage memory budget in bytes (default 256 MiB, M4-D11).
    pub fn memory_budget(mut self, bytes: u64) -> Self {
        self.budget = bytes;
        self
    }

    /// The fetch strategy (M4-D8).
    pub fn fetch_policy(mut self, policy: FetchPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Timeouts of the default HTTP transport.
    pub fn timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Wires the defaults and checks the configuration. A development run with no install state
    /// builds fine; its operations report [`Error::NotInstalled`].
    pub fn build(self) -> Result<Updater, Error> {
        let urls = FeedUrls::new(&self.feed_url)?;
        if self.root.app_id() != &self.app_id {
            return Err(Error::Verify(lunepack_core::Error::AppIdMismatch));
        }
        let (fs, layout): (Arc<dyn Fs>, Layout) = match self.fs {
            Some(fs) => (fs, self.layout),
            None => (
                Arc::new(lunepack_fs::StdFs::new()),
                // lunepack-fs refuses symlinked components (macOS /var, a symlinked home):
                // resolve the layout's directories once. The live tree keeps its final component
                // as given, so a symlink there still fails "is a real directory" (M4-D4).
                self.layout.map(canonical, canonical_parent),
            ),
        };
        let transport = match (self.transport, self.blocking_transport) {
            (Some(t), _) => Transports::Async(t),
            (None, Some(b)) => Transports::Worker(WorkerTransport::new(DynBlocking(b))),
            (None, None) => default_transport(&self.feed_url, self.timeouts)?,
        };
        let workers = self.workers.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map_or(1, |n| n.get())
                .min(8)
        });
        let feed_url = urls.feed(&self.channel)?;
        Ok(Updater {
            inner: Arc::new(Inner {
                app_id: self.app_id,
                root: self.root,
                urls,
                feed_url,
                channel: self.channel,
                layout,
                transport,
                fs,
                codec: self
                    .codec
                    .unwrap_or_else(|| Arc::new(lunepack_codec_lzma::LzmaCodec)),
                hasher: self
                    .hasher
                    .unwrap_or_else(|| Arc::new(lunepack_crypto::Sha256Hasher)),
                verifier: self
                    .verifier
                    .unwrap_or_else(|| Arc::new(lunepack_crypto::Ed25519Verifier)),
                clock: self.clock.unwrap_or_else(|| Arc::new(SystemClock)),
                rng: self.rng.unwrap_or_else(|| Arc::new(lunepack_crypto::OsRng)),
                integration: self
                    .integration
                    .unwrap_or_else(crate::installation::default_integration),
                workers: workers.max(1),
                budget: self.budget,
                policy: self.policy,
            }),
        })
    }
}

/// `path` with its longest existing ancestor resolved through the OS (symlinks included), the rest
/// appended as given.
fn canonical(path: &Path) -> PathBuf {
    let mut head = path.to_path_buf();
    let mut tail = Vec::new();
    loop {
        if let Ok(resolved) = std::fs::canonicalize(&head) {
            let mut out = resolved;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (head.file_name().map(|n| n.to_os_string()), head.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name);
                head = parent.to_path_buf();
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// `path` with its parent resolved through the OS (as [`canonical`]) and the final component kept
/// as given, so a symlink at `path` itself is not followed.
fn canonical_parent(path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
            canonical(parent).join(name)
        }
        _ => canonical(path),
    }
}

/// How operations reach the network: an async transport polled on the caller's task, or a blocking
/// one run on lunepack worker threads.
enum Transports {
    Async(Arc<dyn Transport>),
    Worker(WorkerTransport<DynBlocking>),
}

impl Transports {
    /// The transport for one operation. A worker transport's request and body jobs hold a clone of
    /// the operation's `lock`, so a worker still in a blocked read keeps the lock held and the next
    /// operation gets [`Error::Busy`] until it returns (M4-D15).
    fn for_op(&self, lock: &OpLock) -> Arc<dyn Transport> {
        match self {
            Transports::Async(t) => Arc::clone(t),
            Transports::Worker(w) => Arc::new(w.for_op(lock)),
        }
    }
}

/// The default transport: ureq for `http`/`https`, the directory source for `file:`.
fn default_transport(feed_url: &str, timeouts: Timeouts) -> Result<Transports, Error> {
    let url =
        url::Url::parse(feed_url).map_err(|_| Error::Config("feed URL is not a valid URL"))?;
    if url.scheme() == "file" {
        let path = url
            .to_file_path()
            .map_err(|()| Error::Config("feed file URL has no local path"))?;
        let root = path
            .parent()
            .map(Path::to_path_buf)
            .ok_or(Error::Config("feed file URL has no directory"))?;
        return Ok(Transports::Worker(WorkerTransport::new(DynBlocking(
            Arc::new(lunepack_http::DirSource::new(root)),
        ))));
    }
    let options = lunepack_http::UreqOptions {
        connect_timeout: timeouts.connect,
        read_timeout: timeouts.read,
        ..lunepack_http::UreqOptions::default()
    };
    Ok(Transports::Worker(WorkerTransport::new(DynBlocking(
        Arc::new(lunepack_http::UreqTransport::with_options(&options)),
    ))))
}

/// A shared blocking transport, so an `Arc<dyn BlockingTransport>` can run on worker threads.
struct DynBlocking(Arc<dyn BlockingTransport>);

impl BlockingTransport for DynBlocking {
    fn get(
        &self,
        request: &Request,
        cancel: &CancelToken,
    ) -> Result<BlockingResponse, TransportError> {
        self.0.get(request, cancel)
    }
}

// ---- public values -------------------------------------------------------------------------------

/// An update found by [`Updater::check`]: a verified manifest of a newer version.
#[derive(Clone)]
pub struct UpdateInfo {
    version: Version,
    version_text: String,
    target: Target,
    issued: u64,
    feed_seq: u64,
    time_checked: bool,
    manifest: Arc<VerifiedManifest>,
    manifest_sha256: Sha256Digest,
    pack: PackTarget,
}

impl fmt::Debug for UpdateInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateInfo")
            .field("version", &self.version_text)
            .field("target", &self.target)
            .field("issued", &self.issued)
            .field("feed_seq", &self.feed_seq)
            .field("time_checked", &self.time_checked)
            .finish_non_exhaustive()
    }
}

impl UpdateInfo {
    /// The new version.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// The version as the feed writes it.
    pub fn version_text(&self) -> &str {
        &self.version_text
    }

    /// The manifest's target.
    pub fn target(&self) -> Target {
        self.target
    }

    /// The manifest's `issued` time.
    pub fn issued(&self) -> u64 {
        self.issued
    }

    /// The `seq` of the feed it came from.
    pub fn feed_seq(&self) -> u64 {
        self.feed_seq
    }

    /// Whether expiry and key windows were checked; `false` when the clock was implausible
    /// (before the installed version's `issued`) and they were skipped (FORMAT.md 11.3).
    pub fn time_checked(&self) -> bool {
        self.time_checked
    }

    /// The most bytes a download can fetch: the pack's signed size.
    pub fn download_size_max(&self) -> u64 {
        self.pack.size
    }
}

/// The installed version (from the install state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledVersion {
    version: Version,
    issued: u64,
    target: Target,
}

impl InstalledVersion {
    /// The installed version.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// Its manifest's `issued` time.
    pub fn issued(&self) -> u64 {
        self.issued
    }

    /// The target the install uses.
    pub fn target(&self) -> Target {
        self.target
    }
}

/// A staged version tree, ready for the apply step (C4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedVersion {
    version: Version,
    target: Target,
    tree: PathBuf,
}

impl StagedVersion {
    /// The staged version.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// Its target.
    pub fn target(&self) -> Target {
        self.target
    }

    /// The tree's directory.
    pub fn tree(&self) -> &Path {
        &self.tree
    }
}

/// A progress callback; it runs on the thread that polls the operation.
pub type ProgressCallback = Box<dyn FnMut(&Progress) + Send>;

/// Options of [`Updater::download`] (and, carried by [`Downloaded`], of [`Updater::stage`]).
#[derive(Default)]
pub struct DownloadOptions {
    /// Called with coalesced progress events on the polling thread; no phase that ran is skipped.
    pub progress: Option<ProgressCallback>,
    /// Cancels the operation (dropping its future does too).
    pub cancel: Option<CancelToken>,
}

impl fmt::Debug for DownloadOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DownloadOptions")
            .field("progress", &self.progress.is_some())
            .field("cancel", &self.cancel)
            .finish()
    }
}

/// A completed download, the input of [`Updater::stage`].
pub struct Downloaded {
    info: UpdateInfo,
    /// Per manifest entry: the current-tree file that already matches it.
    unchanged: Vec<Option<PathBuf>>,
    frames: HashMap<Sha256Digest, PathBuf>,
    pack: Option<PathBuf>,
    options: DownloadOptions,
}

impl fmt::Debug for Downloaded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Downloaded")
            .field("info", &self.info)
            .field("frames", &self.frames.len())
            .field("pack", &self.pack.is_some())
            .finish_non_exhaustive()
    }
}

impl Downloaded {
    /// The update it downloaded.
    pub fn info(&self) -> &UpdateInfo {
        &self.info
    }

    /// Replaces the options `stage` runs with.
    pub fn with_options(mut self, options: DownloadOptions) -> Self {
        self.options = options;
        self
    }
}

/// One part of an offline payload: `length` bytes at `offset` of the payload file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadPart {
    /// Where the part starts in the payload file.
    pub offset: u64,
    /// Its length in bytes.
    pub length: u64,
}

/// An offline payload (M6-D4), the input of [`Updater::install_from_payload`]: a file holding a
/// release's key set, manifest and pack, and the version and target it was built for. Nothing in
/// it is trusted: every part is checked before use.
pub struct OfflinePayload {
    /// The file the parts are read from.
    pub file: Arc<dyn ReadAt>,
    /// The key set (`keys.json`).
    pub keys: PayloadPart,
    /// The manifest of `version` for `target`.
    pub manifest: PayloadPart,
    /// The release's pack.
    pub pack: PayloadPart,
    /// The version the payload installs; the manifest must name it byte for byte.
    pub version: Version,
    /// The target the payload is for.
    pub target: Target,
}

impl fmt::Debug for OfflinePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfflinePayload")
            .field("keys", &self.keys)
            .field("manifest", &self.manifest)
            .field("pack", &self.pack)
            .field("version", &self.version)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

// ---- the updater ---------------------------------------------------------------------------------

/// The updater handle: cheap to clone (an `Arc`), `Send + Sync`.
#[derive(Clone)]
pub struct Updater {
    inner: Arc<Inner>,
}

impl fmt::Debug for Updater {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Updater").finish_non_exhaustive()
    }
}

struct Inner {
    app_id: AppId,
    root: TrustedRoot,
    urls: FeedUrls,
    feed_url: String,
    channel: Channel,
    layout: Layout,
    transport: Transports,
    fs: Arc<dyn Fs>,
    codec: Arc<dyn Codec>,
    hasher: Arc<dyn Hasher>,
    verifier: Arc<dyn Verifier>,
    clock: Arc<dyn lunepack_core::Clock>,
    rng: Arc<dyn Rng>,
    integration: Arc<dyn OsIntegration>,
    workers: usize,
    budget: u64,
    policy: FetchPolicy,
}

/// The loaded state of either scope.
#[derive(Clone)]
enum Snapshot {
    User {
        store: UserScope,
        loaded: Box<Loaded<InstallState>>,
        record: InstallState,
    },
    Machine {
        store: MachineStore,
        machine: InstallState,
        counters: Box<Loaded<InstallCounters>>,
    },
}

impl Snapshot {
    /// The record that describes the install.
    fn record(&self) -> &InstallState {
        match self {
            Snapshot::User { record, .. } => record,
            Snapshot::Machine { machine, .. } => machine,
        }
    }

    /// The floors a check starts from (machine: the higher of machine and user, C3).
    fn floors(&self) -> Floors {
        match self {
            Snapshot::User { record, .. } => record.floors.clone(),
            Snapshot::Machine {
                machine, counters, ..
            } => MachineStore::effective_floors(machine, counters.record.as_ref()),
        }
    }
}

impl Inner {
    /// Loads the install state (blocking; on a job, or directly for the read-only calls).
    fn load(&self) -> Result<Snapshot, Error> {
        match &self.layout {
            Layout::User { state_dir, .. } => {
                let store = UserScope {
                    dir: state_dir.clone(),
                    app_id: self.app_id.clone(),
                };
                let loaded = store.load(&*self.fs, &*self.hasher)?;
                let record = loaded.record.clone().ok_or(Error::NotInstalled)?;
                Ok(Snapshot::User {
                    store,
                    loaded: Box::new(loaded),
                    record,
                })
            }
            Layout::Machine {
                machine_state_dir,
                user_state_dir,
                ..
            } => {
                let store = MachineStore {
                    machine_dir: machine_state_dir.clone(),
                    user_dir: user_state_dir.clone(),
                    app_id: self.app_id.clone(),
                };
                let loaded = store.load_machine(&*self.fs, &*self.hasher)?;
                let machine = loaded.record.ok_or(Error::NotInstalled)?;
                let counters = store.load_counters(&*self.fs, &machine, &*self.hasher)?;
                Ok(Snapshot::Machine {
                    store,
                    machine,
                    counters: Box::new(counters),
                })
            }
        }
    }

    /// Commits `floors` (raised with max, never lowered): the user record, or this user's counters
    /// for a machine install. Nothing is written when no floor rises.
    fn commit_floors(&self, snap: &Snapshot, floors: &Floors) -> Result<(), Error> {
        match snap {
            Snapshot::User {
                store,
                loaded,
                record,
            } => {
                if record.floors.max(floors) == record.floors {
                    return Ok(());
                }
                let next = record.raise_floors(floors);
                store.commit(&*self.fs, loaded, &next, &*self.hasher)?;
            }
            Snapshot::Machine {
                store,
                machine,
                counters,
            } => {
                let base = counters.record.clone().unwrap_or_else(|| {
                    InstallCounters::new(counters.next_seq, self.app_id.clone(), machine.install_id)
                });
                let effective = MachineStore::effective_floors(machine, counters.record.as_ref());
                if counters.record.is_some() && effective.max(floors) == effective {
                    return Ok(());
                }
                let next = base.raise_floors(floors);
                store.commit_counters(&*self.fs, machine, counters, &next, &*self.hasher)?;
            }
        }
        Ok(())
    }

    /// The current tree per M4-D4: `current_tree`, else `<versions_dir>/<current>`, counted only
    /// as a real directory.
    fn current_tree(&self, current: Option<&Version>) -> Result<Option<PathBuf>, Error> {
        let candidate = match (
            self.layout.current_tree(),
            self.layout.versions_dir(),
            current,
        ) {
            (Some(tree), _, _) => tree.to_path_buf(),
            (None, Some(versions), Some(v)) => versions.join(v.to_string()),
            _ => return Ok(None),
        };
        Ok(is_real_dir(&*self.fs, &candidate)?.then_some(candidate))
    }

    fn cache(&self) -> Cache {
        Cache::new(Arc::clone(&self.fs), self.layout.cache_dir().to_path_buf())
    }
}

/// Whether `path` is a real directory (not a symlink); a missing path or parent is `false`.
fn is_real_dir(fs: &dyn Fs, path: &Path) -> Result<bool, Error> {
    match fs.symlink_metadata(path) {
        Ok(meta) => Ok(meta.is_some_and(|m| m.kind == FileKind::Dir)),
        Err(e) if e.kind == lunepack_core::FsErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Runs `f` over the updater on a job that holds `lock`, cancellable through `cancel`.
///
/// `f` gets the job's own token. It is cancelled when the job's future is dropped, which happens
/// when the operation's future is dropped and also when `cancel` fires (`cancellable` then returns
/// and drops the job future). A token of the operation alone would leave the worker running to the
/// end after a drop (C9: dropping the future cancels).
async fn on_job<T, F>(
    inner: &Arc<Inner>,
    lock: Option<&OpLock>,
    cancel: &CancelToken,
    name: &'static str,
    f: F,
) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce(&Inner, &CancelToken) -> Result<T, Error> + Send + 'static,
{
    let inner = Arc::clone(inner);
    let future = spawn_job(name, CancelToken::new(), lock.cloned(), move |job| {
        f(&inner, job)
    });
    cancellable(cancel, future).await??
}

/// The updater lock's file name in the lock directory.
const LOCK_FILE: &str = "lock";

/// Takes the updater lock on a short job: [`Error::Busy`] when it is held.
async fn take_lock(inner: &Arc<Inner>, cancel: &CancelToken) -> Result<OpLock, Error> {
    on_job(inner, None, cancel, "lock", |inner, _| {
        let dir = inner.layout.lock_dir();
        inner.fs.create_dir_all(dir)?;
        match inner.fs.try_lock(&dir.join(LOCK_FILE))? {
            Some(guard) => Ok(OpLock::new(guard)),
            None => Err(Error::Busy),
        }
    })
    .await
}

/// Runs `future`, pumping `pump` into `callback` on every poll (and once at the end), so progress
/// callbacks run only on the polling thread.
async fn with_progress<F: Future>(
    pump: &mut ProgressPump,
    callback: &mut Option<ProgressCallback>,
    future: F,
) -> F::Output {
    let mut future = pin!(future);
    poll_fn(|cx| {
        pump.register_waker(cx.waker());
        let out = future.as_mut().poll(cx);
        if let Some(cb) = callback.as_mut() {
            pump.pump(&mut |p: &Progress| cb(p));
        }
        out
    })
    .await
}

/// Forwards a core progress event (a running total) into a sink as deltas. The core knows the
/// phase's real total (scan hashes only the files that could match), so it replaces the sink's.
fn forward(sink: &ProgressSink, last: &AtomicU64, event: &Progress) {
    if event.total > 0 {
        sink.set_total(event.total);
    }
    let before = last.swap(event.done, Ordering::SeqCst);
    sink.add_done(event.done.saturating_sub(before));
    sink.set_file(event.file.clone());
}

fn frames_of(manifest: &VerifiedManifest) -> Vec<(usize, FrameNeed)> {
    manifest
        .entries()
        .iter()
        .enumerate()
        .filter_map(|(i, e)| match e {
            VerifiedEntry::File { frame: Some(f), .. } => Some((
                i,
                FrameNeed {
                    offset: f.offset(),
                    length: f.length(),
                    sha256: f.sha256(),
                },
            )),
            _ => None,
        })
        .collect()
}

/// The decoded bytes of every file of `manifest` (a phase total for scan and stage).
fn file_bytes(manifest: &VerifiedManifest) -> u64 {
    manifest.entries().iter().fold(0u64, |sum, e| match e {
        VerifiedEntry::File { frame: Some(f), .. } => sum.saturating_add(f.file_size()),
        _ => sum,
    })
}

impl Updater {
    /// Checks the feed for an update (FORMAT.md 11.1): walks the root from the higher of the stored
    /// and the embedded root, verifies the key set and the feed against the floors, selects the
    /// candidate and fetches and verifies its manifest. Then the floors are raised (user record,
    /// or this user's counters for a machine install). A failing check changes no state.
    pub fn check(
        &self,
    ) -> impl Future<Output = Result<Option<UpdateInfo>, Error>> + Send + 'static {
        let inner = Arc::clone(&self.inner);
        async move { check(inner).await }
    }

    /// Downloads what staging `info` needs that the current tree and the cache lack: scan (phase
    /// `Scan`), then Range runs or the full pack (phase `Download`). Resumable: an interrupted
    /// download continues on the next call.
    pub fn download(
        &self,
        info: &UpdateInfo,
        options: DownloadOptions,
    ) -> impl Future<Output = Result<Downloaded, Error>> + Send + 'static {
        let inner = Arc::clone(&self.inner);
        let info = info.clone();
        async move { download(inner, info, options).await }
    }

    /// Builds and verifies the version tree from a download (phase `Stage`), fetching what fails by
    /// Range and then by the full pack (D27, M4-D20), and records it as staged. User scope only.
    pub fn stage(
        &self,
        downloaded: Downloaded,
    ) -> impl Future<Output = Result<StagedVersion, Error>> + Send + 'static {
        let inner = Arc::clone(&self.inner);
        async move { stage(inner, downloaded).await }
    }

    /// The first install (M5-D8), for an updater whose layout is a per-user install root's
    /// ([`Layout::user`]) with the bootstrap tree it runs from as `current_tree`:
    ///
    /// 1. the bootstrap's update config must name this app; its desktop integration passes the
    ///    preflight, and an install root that already exists must be lunepack's (empty, this
    ///    app's install state, or what a cut-off run left; else [`Error::ForeignInstallRoot`]),
    ///    before anything is written; then, when the install root is `<parent>/<app id>`, what an
    ///    uninstall cut off before its end left beside it (its tombstones, F18) is removed;
    /// 2. the install state is created when there is none (a fresh install id from the random
    ///    source); a record with no current version resumes, one with a current version is
    ///    [`Error::AlreadyInstalled`] once `current` is put back from it (a run cut off after its
    ///    commit, before the link, still ends startable; a failing link is that error instead);
    /// 3. the check runs with no current version (no floor time, any release of the channel), the
    ///    newest candidate is downloaded and staged, reusing the bootstrap's files that match; no
    ///    candidate at all, or a newest candidate older than the bootstrap's own version (never a
    ///    downgrade from the tree the user ran), is [`Error::NoRelease`];
    /// 4. under the lock the installed tree's own config is read, the integration preflight runs
    ///    again on it, the integration is applied, the record names the version as current (events
    ///    `installed` and `first_run`) and `current` is linked. A failure before that commit
    ///    leaves a record with no current version, so a rerun resumes; a failure (or a cut-off
    ///    run) after it leaves `current` to a rerun, which links it and is
    ///    [`Error::AlreadyInstalled`].
    ///
    /// A machine layout is [`Error::MachineScope`].
    pub fn install(
        &self,
        options: DownloadOptions,
    ) -> impl Future<Output = Result<InstalledVersion, Error>> + Send + 'static {
        let inner = Arc::clone(&self.inner);
        async move { install(inner, options).await }
    }

    /// The first install from an offline payload (M6-D4: a setup file), with no network: the
    /// payload installs exactly its own version. For the same layouts as [`Updater::install`]; no
    /// bootstrap tree is needed, and the transport is never used.
    ///
    /// 1. Under the lock, an install whose record names a current version is
    ///    [`Error::AlreadyInstalled`] (after `current` is put back from it, as `install`).
    /// 2. Verification, before anything is written, in FORMAT.md 11.1 order: `root` is the
    ///    trusted root (the setup file's); the key set verifies against it with no floors (a first
    ///    install) and its expiry at the clock's `now`; the manifest verifies against the key set
    ///    ([`lunepack_core::verify_payload_manifest`]: release keys valid at `now`, the app id
    ///    the key set's, the version and target the payload's); the pack part's size is the
    ///    manifest's. The update config is read from the pack before staging
    ///    ([`lunepack_core::read_entry`]) and must name this app, the payload's version and
    ///    target and exactly `root` ([`UpdateConfigError::RootMismatch`] otherwise); its desktop
    ///    integration passes the preflight. Each part is read within its cap.
    /// 3. The install root must be lunepack's (as `install`: [`Error::ForeignInstallRoot`]), and
    ///    the install state is created when there is none, as `install` does.
    /// 4. Every file entry's frame is copied out of the pack into the cache (phase `Install`),
    ///    each checked against its signed hash; the tree is staged from those frames (phase
    ///    `Stage`). The staged tree's config must again be exactly `root`'s; otherwise the tree is
    ///    removed and the install fails with no current version recorded.
    /// 5. As `install`'s commit: under the lock the integration preflight runs on the staged tree's
    ///    config, the integration is applied, the record names the version as current (events
    ///    `installed` and `first_run`) with the floors raised to `root`, the key set's version and
    ///    no feed `seq`, and `current` is linked.
    ///
    /// A failure or cancel leaves no current version and no floor raised; a rerun resumes.
    pub fn install_from_payload(
        &self,
        payload: OfflinePayload,
        root: TrustedRoot,
        options: DownloadOptions,
    ) -> impl Future<Output = Result<InstalledVersion, Error>> + Send + 'static {
        let inner = Arc::clone(&self.inner);
        async move { install_from_payload(inner, payload, root, options).await }
    }

    /// The installed version; `Ok(None)` in a development run (no install state). Takes no lock.
    pub fn installed(&self) -> Result<Option<InstalledVersion>, Error> {
        let snap = match self.inner.load() {
            Ok(snap) => snap,
            Err(Error::NotInstalled) => return Ok(None),
            Err(e) => return Err(e),
        };
        let record = snap.record();
        Ok(record.current.as_ref().map(|c| InstalledVersion {
            version: c.version.clone(),
            issued: c.issued,
            target: record.target,
        }))
    }

    /// The staged version, when it is newer than the installed one, not marked bad, of the
    /// install's target, and its tree is a real directory (M4-D18). Takes no lock.
    pub fn staged(&self) -> Result<Option<StagedVersion>, Error> {
        let snap = match self.inner.load() {
            Ok(snap) => snap,
            Err(Error::NotInstalled) => return Ok(None),
            Err(e) => return Err(e),
        };
        let record = snap.record();
        let Some(staged) = &record.staged else {
            return Ok(None);
        };
        if record
            .current
            .as_ref()
            .is_some_and(|c| staged.version <= c.version)
            || record.bad.contains(&staged.version)
            || staged.target != record.target
        {
            return Ok(None);
        }
        let Some(versions) = self.inner.layout.versions_dir() else {
            return Ok(None);
        };
        let tree = versions.join(&staged.tree);
        Ok(is_real_dir(&*self.inner.fs, &tree)?.then(|| StagedVersion {
            version: staged.version.clone(),
            target: staged.target,
            tree,
        }))
    }
}

async fn check(inner: Arc<Inner>) -> Result<Option<UpdateInfo>, Error> {
    let cancel = CancelToken::new();
    let lock = take_lock(&inner, &cancel).await?;
    let snap = on_job(&inner, Some(&lock), &cancel, "state-load", |inner, _| {
        inner.load()
    })
    .await?;
    let current = snap.record().current.clone().ok_or(Error::NotInstalled)?;
    check_from(&inner, &lock, &cancel, snap, Some(current)).await
}

/// The check of [`Updater::install`]: the record exists and has no current version, so there is
/// no floor time and any release of the channel is a candidate (M5-D8).
async fn check_first(
    inner: &Arc<Inner>,
    cancel: &CancelToken,
    root: &Path,
) -> Result<Option<UpdateInfo>, Error> {
    let lock = take_lock(inner, cancel).await?;
    let snap = on_job(inner, Some(&lock), cancel, "state-load", |inner, _| {
        inner.load()
    })
    .await?;
    if snap.record().current.is_some() {
        let record = snap.record().clone();
        let root = root.to_path_buf();
        let outcome = on_job(inner, Some(&lock), cancel, "reconcile", move |inner, _| {
            Ok(already_installed(&*inner.fs, &root, &record))
        })
        .await;
        return Err(match outcome {
            Ok(e) | Err(e) => e,
        });
    }
    check_from(inner, &lock, cancel, snap, None).await
}

/// The check proper, under `lock`, from the loaded `snap` whose current version is `current`.
async fn check_from(
    inner: &Arc<Inner>,
    lock: &OpLock,
    cancel: &CancelToken,
    snap: Snapshot,
    current: Option<CurrentRef>,
) -> Result<Option<UpdateInfo>, Error> {
    let record = snap.record().clone();
    let floors = snap.floors();
    let clock = ClockReading::read(&*inner.clock, current.as_ref().map(|c| c.issued));
    let hasher = &*inner.hasher;
    let verifier = &*inner.verifier;
    let transport_arc = inner.transport.for_op(lock);
    let transport = &*transport_arc;

    // Root walk (FORMAT.md 5.2) from the higher of the stored and the embedded root.
    let mut root = match &floors.root {
        Some(parts) if parts.version > inner.root.version() => {
            parts.to_trusted(inner.app_id.clone(), hasher, verifier)?
        }
        _ => inner.root.clone(),
    };
    for _ in 0..MAX_ROOT_STEPS {
        let url = inner.urls.root(root.version().saturating_add(1))?;
        match fetch::fetch_root_doc(transport, &url, Limits::V1.root_doc_bytes).await? {
            None => break,
            Some(bytes) => root = advance_root(&root, &bytes, hasher, verifier)?,
        }
    }
    if root.app_id() != &inner.app_id {
        return Err(Error::Verify(lunepack_core::Error::AppIdMismatch));
    }
    let floor = floors.to_rollback_floor();
    let keys_bytes =
        fetch::fetch_document(transport, &inner.urls.keys()?, Limits::V1.keys_doc_bytes).await?;
    let keys = verify_key_set(&root, &keys_bytes, &floor, &clock, hasher, verifier)?;
    let feed_bytes =
        fetch::fetch_document(transport, &inner.feed_url, Limits::V1.feed_doc_bytes).await?;
    let feed = verify_feed(
        &keys,
        &feed_bytes,
        &inner.app_id,
        &inner.channel,
        &floor,
        &clock,
        verifier,
    )?;
    let candidate = select_candidate(
        &feed,
        current.as_ref().map(|c| &c.version),
        record.target,
        &record.bad,
        &record.install_id,
        hasher,
    );
    let info = match candidate {
        None => None,
        Some(candidate) => {
            let reference = candidate.entry.reference();
            let url = inner.urls.reference(reference)?;
            let bytes = fetch::fetch_document(transport, &url, reference.size()).await?;
            let manifest = verify_manifest(&keys, &candidate.entry, &bytes, hasher, verifier)?;
            let pack = manifest.pack();
            let pack = PackTarget {
                url: inner.urls.reference(pack)?,
                size: pack.size(),
                sha256: pack.sha256(),
            };
            Some(UpdateInfo {
                version: manifest.version().clone(),
                version_text: candidate.entry.version_text().to_owned(),
                target: manifest.target(),
                issued: manifest.issued(),
                feed_seq: feed.seq(),
                time_checked: feed.time_checked() && keys.expiry_checked(),
                manifest_sha256: reference.sha256(),
                manifest: Arc::new(manifest),
                pack,
            })
        }
    };
    let mut raised = Floors {
        root: Some(RootParts::from_trusted(&root)),
        keyset_version: keys.version(),
        ..Floors::default()
    };
    raised.feed_seq.insert(inner.channel.clone(), feed.seq());
    on_job(
        inner,
        Some(lock),
        cancel,
        "state-commit",
        move |inner, _| inner.commit_floors(&snap, &raised),
    )
    .await?;
    Ok(info)
}

/// Re-loads the state under the lock and refuses an update that is no longer newer, or bad.
async fn load_fresh(
    inner: &Arc<Inner>,
    lock: &OpLock,
    cancel: &CancelToken,
    info: &UpdateInfo,
) -> Result<Snapshot, Error> {
    let snap = on_job(inner, Some(lock), cancel, "state-load", |inner, _| {
        inner.load()
    })
    .await?;
    let record = snap.record();
    let stale = record
        .current
        .as_ref()
        .is_some_and(|c| c.version >= info.version)
        || record.bad.contains(&info.version);
    if stale {
        return Err(Error::Stale);
    }
    Ok(snap)
}

fn fetch_ctx(inner: &Inner, lock: &OpLock, cancel: &CancelToken, sink: &ProgressSink) -> FetchCtx {
    FetchCtx {
        transport: inner.transport.for_op(lock),
        cache: inner.cache(),
        hasher: Arc::clone(&inner.hasher),
        lock: Some(lock.clone()),
        cancel: cancel.clone(),
        progress: Some(sink.clone()),
        policy: inner.policy,
    }
}

async fn download(
    inner: Arc<Inner>,
    info: UpdateInfo,
    mut options: DownloadOptions,
) -> Result<Downloaded, Error> {
    let cancel = options.cancel.clone().unwrap_or_default();
    let (sink, mut pump) = progress(Phase::Scan, 0);
    let mut callback = options.progress.take();
    let result = with_progress(&mut pump, &mut callback, async {
        let lock = take_lock(&inner, &cancel).await?;
        let snap = load_fresh(&inner, &lock, &cancel, &info).await?;
        let current = snap.record().current.as_ref().map(|c| c.version.clone());
        let manifest = Arc::clone(&info.manifest);
        let frames = frames_of(&manifest);

        // Cache entries the plan does not name go first (M4-D17).
        let keep_frames: HashSet<Sha256Digest> = frames.iter().map(|(_, f)| f.sha256).collect();
        let keep_packs = HashSet::from([info.pack.sha256]);
        let tree = on_job(
            &inner,
            Some(&lock),
            &cancel,
            "cache-clean",
            move |inner, _| {
                let cache = inner.cache();
                cache.ensure_dirs()?;
                cache.cleanup(&keep_frames, &keep_packs)?;
                inner.current_tree(current.as_ref())
            },
        )
        .await?;

        // The total is the bytes scan hashes, which only its first event knows.
        sink.set_phase(Phase::Scan, 0);
        let scan_sink = sink.clone();
        let scan_manifest = Arc::clone(&manifest);
        let unchanged = on_job(
            &inner,
            Some(&lock),
            &cancel,
            "scan",
            move |inner, cancel| {
                let last = AtomicU64::new(0);
                Ok(lunepack_core::scan(
                    &scan_manifest,
                    tree.as_deref(),
                    &*inner.fs,
                    &*inner.hasher,
                    inner.workers,
                    cancel,
                    &|p| forward(&scan_sink, &last, &p),
                )?)
            },
        )
        .await?;

        let needed: Vec<FrameNeed> = frames
            .iter()
            .filter(|(i, _)| unchanged.get(*i).is_none_or(Option::is_none))
            .map(|(_, f)| f.clone())
            .collect();
        // The total is what the download will move: `fetch::download` adds it once it has planned.
        sink.set_phase(Phase::Download, 0);
        let ctx = fetch_ctx(&inner, &lock, &cancel, &sink);
        let fetched = fetch::download(&ctx, &info.pack, &needed).await?;
        let frames: HashMap<Sha256Digest, PathBuf> = needed
            .iter()
            .filter_map(|f| {
                fetched
                    .frame(&f.sha256)
                    .map(|p| (f.sha256, p.to_path_buf()))
            })
            .collect();
        Ok::<_, Error>((unchanged, frames, fetched.pack().map(Path::to_path_buf)))
    })
    .await;
    let (unchanged, frames, pack) = result?;
    options.progress = callback;
    Ok(Downloaded {
        info,
        unchanged,
        frames,
        pack,
        options,
    })
}

/// The stage sources: the matching current file, else the cached frame (its expected path, which
/// the stage reports as `NeedFetch` when missing), else the pack when the entry was moved to it.
fn sources(
    manifest: &VerifiedManifest,
    unchanged: &[Option<PathBuf>],
    frames: &HashMap<Sha256Digest, PathBuf>,
    pack: Option<&Path>,
    use_pack: &HashSet<usize>,
    cache: &Cache,
) -> Vec<SourceFor> {
    manifest
        .entries()
        .iter()
        .enumerate()
        .map(|(i, e)| {
            if let Some(Some(path)) = unchanged.get(i) {
                return SourceFor::Unchanged(path.clone());
            }
            let VerifiedEntry::File {
                frame: Some(frame), ..
            } = e
            else {
                // Directories, symlinks and empty files ignore their source.
                return SourceFor::Frame(PathBuf::new());
            };
            let sha = frame.sha256();
            match (frames.get(&sha), pack) {
                (_, Some(pack)) if use_pack.contains(&i) => SourceFor::Pack(pack.to_path_buf()),
                (Some(path), _) => SourceFor::Frame(path.clone()),
                (None, Some(pack)) => SourceFor::Pack(pack.to_path_buf()),
                (None, None) => SourceFor::Frame(cache.path(CacheKind::Frame, &sha)),
            }
        })
        .collect()
}

/// Refuses to stage a version whose directory name differs only in ASCII letter case from that of
/// the current, previous, pending or staged version or from an entry of the versions directory: on
/// a case-insensitive file system (Windows, macOS default) both names are one directory, and
/// staging would rebuild a kept version's tree under a different version's name (F11).
async fn refuse_case_collision(
    inner: &Arc<Inner>,
    lock: &OpLock,
    cancel: &CancelToken,
    record: &InstallState,
    version: &Version,
    versions_dir: &Path,
) -> Result<(), Error> {
    let mut names: Vec<String> = record
        .current
        .iter()
        .map(|c| c.version.to_string())
        .chain(record.previous.iter().map(|p| p.version.to_string()))
        .chain(record.pending.iter().map(|p| p.version.to_string()))
        .chain(record.staged.iter().map(|s| s.tree.clone()))
        .collect();
    let candidate = version.to_string();
    let dir = versions_dir.to_path_buf();
    on_job(
        inner,
        Some(lock),
        cancel,
        "version-dirs",
        move |inner, _| {
            match inner.fs.list_dir(&dir) {
                Ok(entries) => names.extend(
                    entries
                        .into_iter()
                        .map(|e| e.name.to_string_lossy().into_owned()),
                ),
                Err(e) if e.kind == lunepack_core::FsErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            let partial = format!("{candidate}{}", lunepack_core::stage::PARTIAL_SUFFIX);
            let collides = names.iter().any(|n| {
                (n != &candidate && n.eq_ignore_ascii_case(&candidate))
                    || (n != &partial && n.eq_ignore_ascii_case(&partial))
            });
            if collides {
                return Err(Error::VersionDirCollision);
            }
            Ok(())
        },
    )
    .await
}

async fn stage(inner: Arc<Inner>, downloaded: Downloaded) -> Result<StagedVersion, Error> {
    let Layout::User { versions_dir, .. } = &inner.layout else {
        return Err(Error::MachineScope);
    };
    let versions_dir = versions_dir.clone();
    let Downloaded {
        info,
        mut unchanged,
        mut frames,
        mut pack,
        mut options,
    } = downloaded;
    let cancel = options.cancel.clone().unwrap_or_default();
    let (sink, mut pump) = progress(Phase::Stage, 0);
    let mut callback = options.progress.take();
    with_progress(&mut pump, &mut callback, async {
        let lock = take_lock(&inner, &cancel).await?;
        let snap = load_fresh(&inner, &lock, &cancel, &info).await?;
        let manifest = Arc::clone(&info.manifest);
        refuse_case_collision(
            &inner,
            &lock,
            &cancel,
            snap.record(),
            &info.version,
            &versions_dir,
        )
        .await?;
        let all_frames = frames_of(&manifest);
        let mut use_pack: HashSet<usize> = HashSet::new();
        let (mut range_tried, mut pack_tried) = (false, false);
        let staged = loop {
            let input_sources = sources(
                &manifest,
                &unchanged,
                &frames,
                pack.as_deref(),
                &use_pack,
                &inner.cache(),
            );
            sink.set_phase(Phase::Stage, file_bytes(&manifest));
            let stage_sink = sink.clone();
            let stage_manifest = Arc::clone(&manifest);
            let dir = versions_dir.clone();
            let outcome = on_job(
                &inner,
                Some(&lock),
                &cancel,
                "stage",
                move |inner, cancel| {
                    let last = AtomicU64::new(0);
                    let progress = |p: Progress| forward(&stage_sink, &last, &p);
                    let input = StageInput {
                        manifest: &stage_manifest,
                        versions_dir: dir,
                        sources: input_sources,
                    };
                    let env = StageEnv {
                        fs: &*inner.fs,
                        codec: &*inner.codec,
                        hasher: &*inner.hasher,
                        workers: inner.workers,
                        budget_bytes: inner.budget,
                        cancel,
                        progress: &progress,
                    };
                    Ok(lunepack_core::stage(&input, &env))
                },
            )
            .await?;
            let paths = match outcome {
                Ok(staged) => break staged,
                Err(StageError::NeedFetch(paths)) => paths,
                Err(StageError::Cancelled) => return Err(Error::Cancelled),
                Err(StageError::Unsupported) => {
                    return Err(Error::Config("the manifest needs an unsupported source"));
                }
                Err(StageError::Other(e)) => return Err(e.into()),
                Err(_) => return Err(Error::Config("stage failed")),
            };
            let failed: Vec<usize> = manifest
                .entries()
                .iter()
                .enumerate()
                .filter(|(_, e)| paths.contains(e.path()))
                .map(|(i, _)| i)
                .collect();
            for &i in &failed {
                if let Some(slot) = unchanged.get_mut(i) {
                    *slot = None;
                }
            }
            let failed_frames: Vec<FrameNeed> = all_frames
                .iter()
                .filter(|(i, _)| failed.contains(i))
                .map(|(_, f)| f.clone())
                .collect();
            let ctx = fetch_ctx(&inner, &lock, &cancel, &sink);
            if !range_tried {
                // Rung 2 (D27): the failing frames again, by Range.
                range_tried = true;
                let stale: Vec<Sha256Digest> = failed_frames.iter().map(|f| f.sha256).collect();
                on_job(
                    &inner,
                    Some(&lock),
                    &cancel,
                    "cache-drop",
                    move |inner, _| {
                        let cache = inner.cache();
                        for sha in &stale {
                            cache.remove_entry(CacheKind::Frame, sha)?;
                        }
                        Ok(())
                    },
                )
                .await?;
                for f in &failed_frames {
                    frames.remove(&f.sha256);
                }
                sink.set_phase(Phase::Download, 0);
                let fetched = fetch::download(&ctx, &info.pack, &failed_frames).await?;
                for f in &failed_frames {
                    if let Some(p) = fetched.frame(&f.sha256) {
                        frames.insert(f.sha256, p.to_path_buf());
                    }
                }
                if let Some(p) = fetched.pack() {
                    pack = Some(p.to_path_buf());
                    use_pack.extend(failed.iter().copied());
                }
            } else if !pack_tried {
                // Rung 3: the full pack, fetched fresh.
                pack_tried = true;
                let sha = info.pack.sha256;
                on_job(
                    &inner,
                    Some(&lock),
                    &cancel,
                    "cache-drop",
                    move |inner, _| Ok(inner.cache().remove_entry(CacheKind::Pack, &sha)?),
                )
                .await?;
                // `fetch_pack` adds the pack's size to the total.
                sink.set_phase(Phase::Download, 0);
                pack = Some(fetch::fetch_pack(&ctx, &info.pack, None).await?);
                use_pack.extend(failed.iter().copied());
            } else {
                return Err(Error::NeedFetchExhausted(paths));
            }
        };

        // Record the tree, then drop the version's cache entries (M4-D17).
        let staged_ref =
            StagedRef::new(staged.version.clone(), staged.target, info.manifest_sha256);
        // The staged manifest's `issued` goes with it: an apply makes it the floor time (P9).
        let staged_issued = info.issued();
        let drop_frames: Vec<Sha256Digest> = all_frames.iter().map(|(_, f)| f.sha256).collect();
        let pack_sha = info.pack.sha256;
        on_job(
            &inner,
            Some(&lock),
            &cancel,
            "state-commit",
            move |inner, _| {
                let Snapshot::User {
                    store,
                    loaded,
                    record,
                } = &snap
                else {
                    return Err(Error::MachineScope);
                };
                let next = record.set_staged(Some((staged_ref, staged_issued)));
                store.commit(&*inner.fs, loaded, &next, &*inner.hasher)?;
                // The tree is in place and recorded: dropping the cache entries is housekeeping
                // (M4-D17), so a failure here (a file held open by a scanner, a permission change)
                // is not an error of `stage`. The next `download` removes leftovers.
                let cache = inner.cache();
                for sha in &drop_frames {
                    let _ = cache.remove_entry(CacheKind::Frame, sha);
                }
                let _ = cache.remove_entry(CacheKind::Pack, &pack_sha);
                Ok(())
            },
        )
        .await?;
        Ok(StagedVersion {
            version: staged.version,
            target: staged.target,
            tree: staged.tree,
        })
    })
    .await
}

// ---- first install -------------------------------------------------------------------------------

/// The install root `R` of a per-user layout made by [`Layout::user`]: `versions` and `state`
/// directly under one directory.
fn install_root_of(state_dir: &Path, versions_dir: &Path) -> Result<PathBuf, Error> {
    let root = versions_dir
        .parent()
        .filter(|r| {
            versions_dir == r.join(lunepack_core::layout::VERSIONS_DIR)
                && state_dir == r.join(lunepack_core::layout::STATE_DIR)
        })
        .ok_or(Error::Config(
            "install needs the per-user layout of an install root",
        ))?;
    Ok(root.to_path_buf())
}

/// What a first install that finds a current version returns (F15). `current` is first put
/// back from the record (idempotent, and never ahead of it), so a run cut off between the install
/// commit and the link, or whose reconcile failed, still ends with a startable install; a
/// reconcile that fails again is that error, so a retry can still fix it.
fn already_installed(fs: &dyn Fs, root: &Path, record: &InstallState) -> Error {
    match lunepack_core::reconcile_current(fs, root, record) {
        Ok(()) => Error::AlreadyInstalled,
        Err(e) => Error::from(lunepack_core::Error::Layout(e)),
    }
}

/// Removes the tombstones an uninstall cut off before its end left beside `root` (F18), when
/// `root` is `<parent>/<app id>` (the derivation of M5-D2; tombstones are named after the app id
/// only and never sit anywhere else). Best effort: a tombstone is never the install root, so one
/// that stays changes nothing about the install and the next install or uninstall tries again.
fn clear_tombstones(inner: &Inner, root: &Path) {
    if let Some(parent) = root.parent()
        && root.file_name().is_some_and(|n| n == inner.app_id.as_str())
    {
        let _ = lunepack_core::remove_tombstones(&*inner.fs, parent, &inner.app_id);
    }
}

/// Whether the first install may take over `root`, its install root (S2): `root` does not exist
/// yet, or is a real directory that is empty, or whose `state` directory (`state_dir`) holds a
/// record of this app id, or that holds only what a run cut off before its first record leaves
/// (a `state` directory with nothing but the lock and record files). Anything else (the app's own
/// user data from before lunepack, another packaging's directory, a shared directory, a symlink)
/// is [`Error::ForeignInstallRoot`]: uninstall removes `root` whole, so it must hold nothing
/// lunepack did not make. Reads only. An uninstall renames `root` to a tombstone beside it before
/// removing it (F18), so a cut-off uninstall leaves `root` whole or absent, never half removed;
/// a tombstone is never looked at here.
fn adoptable(inner: &Inner, root: &Path, state_dir: &Path) -> Result<(), Error> {
    match inner.fs.symlink_metadata(root) {
        Ok(None) => return Ok(()),
        Ok(Some(meta)) if meta.kind == FileKind::Dir => {}
        Ok(Some(_)) => return Err(Error::ForeignInstallRoot),
        Err(e) if e.kind == lunepack_core::FsErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    let entries = inner.fs.list_dir(root)?;
    if entries.is_empty() {
        return Ok(());
    }
    let state_name = state_dir.file_name();
    let has_state = entries
        .iter()
        .any(|e| Some(e.name.as_os_str()) == state_name && e.kind == FileKind::Dir);
    let only_state = has_state && entries.len() == 1;
    if !has_state {
        return Err(Error::ForeignInstallRoot);
    }
    let store = UserScope {
        dir: state_dir.to_path_buf(),
        app_id: inner.app_id.clone(),
    };
    if store.load(&*inner.fs, &*inner.hasher)?.record.is_some() {
        return Ok(());
    }
    let only_ours = inner.fs.list_dir(state_dir)?.iter().all(|e| {
        e.kind == FileKind::File
            && e.name
                .to_str()
                .is_some_and(|n| n == LOCK_FILE || is_record_name(n))
    });
    if only_state && only_ours {
        Ok(())
    } else {
        Err(Error::ForeignInstallRoot)
    }
}

/// A record file name of the state store, `<20 digits>.rec` (FORMAT.md 12.4).
fn is_record_name(name: &str) -> bool {
    name.strip_suffix(".rec")
        .is_some_and(|digits| digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// The integration request for `meta` of the install at `root`.
fn integration_request(
    app_id: &AppId,
    root: &Path,
    meta: lunepack_core::InstallMeta,
) -> IntegrationRequest {
    IntegrationRequest {
        app_id: app_id.clone(),
        install_root: root.to_path_buf(),
        meta,
        stale_bins: Vec::new(),
    }
}

/// The update config of the tree at `tree`, which must name `app_id`.
fn tree_config(
    fs: &dyn Fs,
    app_id: &AppId,
    tree: &Path,
) -> Result<lunepack_core::UpdateConfig, Error> {
    let config = crate::installation::read_config(fs, &tree.join(UPDATE_CONFIG_FILE))?
        .ok_or(Error::NoUpdateConfig)?;
    if &config.app_id != app_id {
        return Err(Error::UpdateConfig(UpdateConfigError::RootMismatch(
            "app_id",
        )));
    }
    Ok(config)
}

async fn install(inner: Arc<Inner>, options: DownloadOptions) -> Result<InstalledVersion, Error> {
    let Layout::User {
        state_dir,
        versions_dir,
        current_tree,
        ..
    } = &inner.layout
    else {
        return Err(Error::MachineScope);
    };
    let root = install_root_of(state_dir, versions_dir)?;
    let bootstrap = current_tree.clone().ok_or(Error::Config(
        "install needs the bootstrap tree as the current tree",
    ))?;
    let cancel = options.cancel.clone().unwrap_or_default();

    // The bootstrap's config, the integration preflight and the root's owner, before the first
    // write to the install (the lock is the first); only an earlier uninstall's tombstones beside
    // the root are removed in between (F18).
    let boot_root = root.clone();
    let boot_state = state_dir.clone();
    let (target, boot_version) = on_job(&inner, None, &cancel, "bootstrap", move |inner, _| {
        let config = tree_config(&*inner.fs, &inner.app_id, &bootstrap)?;
        let request = integration_request(&inner.app_id, &boot_root, config.install.clone());
        inner.integration.check(Scope::User, &request)?;
        clear_tombstones(inner, &boot_root);
        adoptable(inner, &boot_root, &boot_state)?;
        Ok((config.target, config.version))
    })
    .await?;

    // The record: created when missing, resumed when it has no current version.
    {
        let lock = take_lock(&inner, &cancel).await?;
        let state_root = root.clone();
        on_job(
            &inner,
            Some(&lock),
            &cancel,
            "state-create",
            move |inner, _| {
                let Layout::User { state_dir, .. } = &inner.layout else {
                    return Err(Error::MachineScope);
                };
                let store = UserScope {
                    dir: state_dir.clone(),
                    app_id: inner.app_id.clone(),
                };
                let loaded = store.load(&*inner.fs, &*inner.hasher)?;
                match &loaded.record {
                    Some(record) if record.current.is_some() => {
                        Err(already_installed(&*inner.fs, &state_root, record))
                    }
                    Some(_) => Ok(()),
                    None => {
                        let mut install_id = [0u8; lunepack_core::policy::INSTALL_ID_BYTES];
                        inner.rng.fill(&mut install_id)?;
                        let record = InstallState::new(
                            loaded.next_seq,
                            inner.app_id.clone(),
                            lunepack_core::Scope::User,
                            install_id,
                            target,
                        );
                        store.commit(&*inner.fs, &loaded, &record, &*inner.hasher)?;
                        Ok(())
                    }
                }
            },
        )
        .await?;
    }

    // The bootstrap's own version is the floor (S1, D25): a replayed, still unexpired feed whose
    // newest release is older than the tree the user ran installs nothing.
    let info = check_first(&inner, &cancel, &root)
        .await?
        .filter(|info| info.version >= boot_version)
        .ok_or(Error::NoRelease)?;
    // A run that staged this release before it was cut off goes straight to the commit.
    let staged_info = info.clone();
    let already = on_job(&inner, None, &cancel, "state-load", move |inner, _| {
        let snap = inner.load()?;
        let record = snap.record();
        let bound = record.staged.as_ref().is_some_and(|s| {
            crate::installation::same_version(&s.version, &staged_info.version)
                && s.manifest_sha256 == staged_info.manifest_sha256
        }) && record.staged_issued_bound().is_some();
        let tree = inner
            .layout
            .versions_dir()
            .map(|v| v.join(staged_info.version.to_string()));
        Ok(bound && tree.is_some_and(|t| is_real_dir(&*inner.fs, &t).unwrap_or(false)))
    })
    .await?;
    if !already {
        let downloaded = download(Arc::clone(&inner), info.clone(), options).await?;
        stage(Arc::clone(&inner), downloaded).await?;
    }

    let lock = take_lock(&inner, &cancel).await?;
    on_job(
        &inner,
        Some(&lock),
        &cancel,
        "install-commit",
        move |inner, _| {
            let Layout::User {
                state_dir,
                versions_dir,
                ..
            } = &inner.layout
            else {
                return Err(Error::MachineScope);
            };
            let store = UserScope {
                dir: state_dir.clone(),
                app_id: inner.app_id.clone(),
            };
            let loaded = store.load(&*inner.fs, &*inner.hasher)?;
            let record = loaded.record.clone().ok_or(Error::NotInstalled)?;
            if record.current.is_some() {
                return Err(already_installed(&*inner.fs, &root, &record));
            }
            let version = info.version.clone();
            let staged_here = record
                .staged
                .as_ref()
                .is_some_and(|s| crate::installation::same_version(&s.version, &version));
            let issued = record
                .staged_issued_bound()
                .filter(|_| staged_here)
                .ok_or(Error::NothingStaged)?;
            let tree = versions_dir.join(version.to_string());
            let config = tree_config(&*inner.fs, &inner.app_id, &tree)?;
            if !crate::installation::same_version(&config.version, &version) {
                return Err(Error::UpdateConfig(UpdateConfigError::Invalid {
                    field: "version",
                    rule: "is not the version of its directory",
                }));
            }
            let request = integration_request(&inner.app_id, &root, config.install);
            inner.integration.check(Scope::User, &request)?;
            let next =
                lunepack_core::install_first(&record, version.clone(), issued, record.install_id)?;
            // The integration goes in before the commit (F11, Q42): once the record names a
            // current version a rerun is `AlreadyInstalled`, so nothing that can fail may be left
            // for after it. Its entries point through `R/current`, which the reconcile below makes
            // valid; when the commit fails they dangle until a rerun, which applies them again.
            // When the reconcile fails, or the run ends before it, a rerun links `current` from
            // the committed record before it reports `AlreadyInstalled` (F15).
            inner.integration.apply(Scope::User, &request)?;
            let committed = store.commit(&*inner.fs, &loaded, &next, &*inner.hasher)?;
            lunepack_core::reconcile_current(&*inner.fs, &root, &committed)
                .map_err(|e| Error::from(lunepack_core::Error::Layout(e)))?;
            Ok(InstalledVersion {
                version,
                issued,
                target: committed.target,
            })
        },
    )
    .await
}

// ---- offline install -----------------------------------------------------------------------------

/// The pack inside an offline payload: `length` bytes at `offset` of `file`, which the caller has
/// checked lie inside it.
struct PayloadWindow {
    file: Arc<dyn ReadAt>,
    offset: u64,
    length: u64,
}

impl ReadAt for PayloadWindow {
    fn size(&self) -> Result<u64, lunepack_core::FsError> {
        Ok(self.length)
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), lunepack_core::FsError> {
        let inside = offset
            .checked_add(buf.len() as u64)
            .is_some_and(|end| end <= self.length);
        if !inside {
            return Err(lunepack_core::FsError::new(
                lunepack_core::FsErrorKind::Other,
                Path::new("payload"),
                Some(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            ));
        }
        self.file.read_exact_at(self.offset + offset, buf)
    }
}

/// `part` must lie inside a file of `file_size` bytes.
fn check_part(part: PayloadPart, file_size: u64) -> Result<(), Error> {
    match part.offset.checked_add(part.length) {
        Some(end) if end <= file_size => Ok(()),
        _ => Err(Error::Verify(lunepack_core::Error::Field(
            "payload part lies outside the payload file",
        ))),
    }
}

/// The bytes of `part` of `file`, refused above `cap` before anything is read.
fn read_part(
    file: &dyn ReadAt,
    part: PayloadPart,
    what: &'static str,
    cap: u64,
) -> Result<Vec<u8>, Error> {
    if part.length > cap {
        return Err(Error::Verify(lunepack_core::Error::TooLarge {
            what,
            size: part.length,
            cap,
        }));
    }
    check_part(part, file.size()?)?;
    let mut bytes = vec![0u8; usize::try_from(part.length).unwrap_or(0)];
    file.read_exact_at(part.offset, &mut bytes)?;
    Ok(bytes)
}

/// What the offline verification produced.
struct VerifiedPayload {
    manifest: Arc<VerifiedManifest>,
    pack: Arc<PayloadWindow>,
    floors: Floors,
}

/// Step 2 of [`Updater::install_from_payload`]: reads only.
fn verify_payload(
    inner: &Inner,
    payload: &OfflinePayload,
    root: &TrustedRoot,
    install_root: &Path,
) -> Result<VerifiedPayload, Error> {
    let (hasher, verifier) = (&*inner.hasher, &*inner.verifier);
    let file = &*payload.file;
    // A first install: no floor time (the clock is plausible) and no stored floors (P6).
    let clock = ClockReading::read(&*inner.clock, None);
    let keys_bytes = read_part(file, payload.keys, "keys", Limits::V1.keys_doc_bytes)?;
    let keys = verify_key_set(
        root,
        &keys_bytes,
        &lunepack_core::RollbackFloor::default(),
        &clock,
        hasher,
        verifier,
    )?;
    let manifest_bytes = read_part(
        file,
        payload.manifest,
        "manifest",
        Limits::V1.manifest_doc_bytes,
    )?;
    let manifest = verify_payload_manifest(
        &keys,
        (&payload.version, payload.target),
        &manifest_bytes,
        clock.now(),
        hasher,
        verifier,
    )?;
    check_part(payload.pack, file.size()?)?;
    if payload.pack.length != manifest.pack().size() {
        return Err(Error::Verify(lunepack_core::Error::ArtifactSize {
            expected: manifest.pack().size(),
            actual: payload.pack.length,
        }));
    }
    let pack = Arc::new(PayloadWindow {
        file: Arc::clone(&payload.file),
        offset: payload.pack.offset,
        length: payload.pack.length,
    });

    // FORMAT.md 13.6: the config before staging, so a foreign root writes nothing.
    let config_path = RelPath::parse(UPDATE_CONFIG_FILE)
        .map_err(|_| Error::Config("the update config's name is not a path"))?;
    let config_bytes = read_entry(
        &manifest,
        &config_path,
        &*pack,
        &*inner.codec,
        hasher,
        MAX_UPDATE_CONFIG_BYTES,
    )?;
    let config = UpdateConfig::parse(&config_bytes).map_err(Error::UpdateConfig)?;
    check_payload_config(
        &inner.app_id,
        &config,
        root,
        manifest.version(),
        manifest.target(),
    )?;
    let request = integration_request(&inner.app_id, install_root, config.install);
    inner.integration.check(Scope::User, &request)?;

    Ok(VerifiedPayload {
        manifest: Arc::new(manifest),
        pack,
        floors: Floors {
            // The walk from the payload's root reaches only that root offline; the key set named
            // it (`root_version`), so it is the highest root this install verified.
            root: Some(RootParts::from_trusted(root)),
            keyset_version: keys.version(),
            feed_seq: std::collections::BTreeMap::new(),
        },
    })
}

/// A payload's (or its staged tree's) config must be this app's, of the manifest's version and
/// target, under exactly `root` (M6-D4: the installed app trusts the root that verified it).
fn check_payload_config(
    app_id: &AppId,
    config: &UpdateConfig,
    root: &TrustedRoot,
    version: &Version,
    target: Target,
) -> Result<(), Error> {
    if &config.app_id != app_id {
        return Err(Error::UpdateConfig(UpdateConfigError::RootMismatch(
            "app_id",
        )));
    }
    config.check_root(root).map_err(Error::UpdateConfig)?;
    if !crate::installation::same_version(&config.version, version) || config.target != target {
        return Err(Error::UpdateConfig(UpdateConfigError::Invalid {
            field: "version",
            rule: "is not the version of its directory",
        }));
    }
    Ok(())
}

/// Loads the user record under `lock`: an install with a current version is
/// [`Error::AlreadyInstalled`] (after `current` is put back from it).
async fn refuse_installed(
    inner: &Arc<Inner>,
    lock: &OpLock,
    cancel: &CancelToken,
    root: &Path,
) -> Result<(), Error> {
    let root = root.to_path_buf();
    on_job(inner, Some(lock), cancel, "state-check", move |inner, _| {
        let Layout::User { state_dir, .. } = &inner.layout else {
            return Err(Error::MachineScope);
        };
        let store = UserScope {
            dir: state_dir.clone(),
            app_id: inner.app_id.clone(),
        };
        match store.load(&*inner.fs, &*inner.hasher)?.record {
            Some(record) if record.current.is_some() => {
                Err(already_installed(&*inner.fs, &root, &record))
            }
            _ => Ok(()),
        }
    })
    .await
}

async fn install_from_payload(
    inner: Arc<Inner>,
    payload: OfflinePayload,
    root: TrustedRoot,
    mut options: DownloadOptions,
) -> Result<InstalledVersion, Error> {
    let Layout::User {
        state_dir,
        versions_dir,
        ..
    } = &inner.layout
    else {
        return Err(Error::MachineScope);
    };
    let (state_dir, versions_dir) = (state_dir.clone(), versions_dir.clone());
    let install_root = install_root_of(&state_dir, &versions_dir)?;
    if root.app_id() != &inner.app_id {
        return Err(Error::Verify(lunepack_core::Error::AppIdMismatch));
    }
    let cancel = options.cancel.clone().unwrap_or_default();
    let (sink, mut pump) = progress(Phase::Install, 0);
    let mut callback = options.progress.take();
    with_progress(&mut pump, &mut callback, async {
        // 1. An installed record is `AlreadyInstalled` before anything else.
        {
            let lock = take_lock(&inner, &cancel).await?;
            refuse_installed(&inner, &lock, &cancel, &install_root).await?;
        }

        // 2. Verification; nothing is written.
        let check_root = root.clone();
        let check_install_root = install_root.clone();
        let verified = on_job(&inner, None, &cancel, "payload-verify", move |inner, _| {
            verify_payload(inner, &payload, &check_root, &check_install_root)
        })
        .await?;
        let manifest = Arc::clone(&verified.manifest);
        let version = manifest.version().clone();
        let target = manifest.target();

        // 3. The install root, then the record, as `install`.
        let boot_root = install_root.clone();
        let boot_state = state_dir.clone();
        on_job(&inner, None, &cancel, "bootstrap", move |inner, _| {
            clear_tombstones(inner, &boot_root);
            adoptable(inner, &boot_root, &boot_state)
        })
        .await?;
        let lock = take_lock(&inner, &cancel).await?;
        let state_root = install_root.clone();
        let snap = on_job(
            &inner,
            Some(&lock),
            &cancel,
            "state-create",
            move |inner, _| {
                let store = UserScope {
                    dir: state_dir.clone(),
                    app_id: inner.app_id.clone(),
                };
                let loaded = store.load(&*inner.fs, &*inner.hasher)?;
                match &loaded.record {
                    Some(record) if record.current.is_some() => {
                        return Err(already_installed(&*inner.fs, &state_root, record));
                    }
                    Some(_) => {}
                    None => {
                        let mut install_id = [0u8; lunepack_core::policy::INSTALL_ID_BYTES];
                        inner.rng.fill(&mut install_id)?;
                        let record = InstallState::new(
                            loaded.next_seq,
                            inner.app_id.clone(),
                            lunepack_core::Scope::User,
                            install_id,
                            target,
                        );
                        store.commit(&*inner.fs, &loaded, &record, &*inner.hasher)?;
                    }
                }
                inner.load()
            },
        )
        .await?;
        refuse_case_collision(
            &inner,
            &lock,
            &cancel,
            snap.record(),
            &version,
            &versions_dir,
        )
        .await?;

        // 4. The frames into the cache (phase `Install`), then the tree (phase `Stage`).
        let frames = frames_of(&manifest);
        let copy_total = {
            let mut seen = HashSet::new();
            frames
                .iter()
                .filter(|(_, f)| seen.insert(f.sha256))
                .fold(0u64, |sum, (_, f)| sum.saturating_add(f.length))
        };
        sink.set_phase(Phase::Install, copy_total);
        let copy_sink = sink.clone();
        let copy_pack = Arc::clone(&verified.pack);
        let copy_frames: Vec<FrameNeed> = frames.iter().map(|(_, f)| f.clone()).collect();
        on_job(
            &inner,
            Some(&lock),
            &cancel,
            "payload-copy",
            move |inner, cancel| {
                let cache = inner.cache();
                cache.ensure_dirs()?;
                let keep: HashSet<Sha256Digest> = copy_frames.iter().map(|f| f.sha256).collect();
                cache.cleanup(&keep, &HashSet::new())?;
                let tools = PartTools {
                    hasher: &*inner.hasher,
                    cancel,
                };
                let mut done = HashSet::new();
                for f in &copy_frames {
                    if !done.insert(f.sha256) {
                        continue;
                    }
                    let added = |n: u64| copy_sink.add_done(n);
                    if !cache.store_frame(
                        &*copy_pack,
                        f.offset,
                        f.length,
                        &f.sha256,
                        &tools,
                        &added,
                    )? {
                        return Err(Error::Verify(lunepack_core::Error::Frame(
                            lunepack_core::error::FrameError::FrameHash,
                        )));
                    }
                }
                Ok(())
            },
        )
        .await?;

        sink.set_phase(Phase::Stage, file_bytes(&manifest));
        let stage_sink = sink.clone();
        let stage_manifest = Arc::clone(&manifest);
        let dir = versions_dir.clone();
        let outcome = on_job(
            &inner,
            Some(&lock),
            &cancel,
            "stage",
            move |inner, cancel| {
                let cache = inner.cache();
                let sources = stage_manifest
                    .entries()
                    .iter()
                    .map(|e| match e {
                        VerifiedEntry::File {
                            frame: Some(frame), ..
                        } => SourceFor::Frame(cache.path(CacheKind::Frame, &frame.sha256())),
                        // Directories, symlinks and empty files ignore their source.
                        _ => SourceFor::Frame(PathBuf::new()),
                    })
                    .collect();
                let last = AtomicU64::new(0);
                let progress = |p: Progress| forward(&stage_sink, &last, &p);
                let input = StageInput {
                    manifest: &stage_manifest,
                    versions_dir: dir,
                    sources,
                };
                let env = StageEnv {
                    fs: &*inner.fs,
                    codec: &*inner.codec,
                    hasher: &*inner.hasher,
                    workers: inner.workers,
                    budget_bytes: inner.budget,
                    cancel,
                    progress: &progress,
                };
                Ok(lunepack_core::stage(&input, &env))
            },
        )
        .await?;
        let staged = match outcome {
            Ok(staged) => staged,
            Err(StageError::Cancelled) => return Err(Error::Cancelled),
            // The frames were hash-checked as they were copied: a failing source is local damage,
            // and there is nothing to fetch it from.
            Err(StageError::NeedFetch(paths)) => return Err(Error::NeedFetchExhausted(paths)),
            Err(StageError::Unsupported) => {
                return Err(Error::Config("the manifest needs an unsupported source"));
            }
            Err(StageError::Other(e)) => return Err(e.into()),
            Err(_) => return Err(Error::Config("stage failed")),
        };

        // The staged tree's own config, again exactly the payload's root; else the tree goes.
        let tree = staged.tree.clone();
        let tree_root = root.clone();
        let tree_version = version.clone();
        on_job(
            &inner,
            Some(&lock),
            &cancel,
            "payload-root",
            move |inner, _| {
                let checked =
                    crate::installation::read_config(&*inner.fs, &tree.join(UPDATE_CONFIG_FILE))
                        .and_then(|c| c.ok_or(Error::NoUpdateConfig))
                        .and_then(|config| {
                            check_payload_config(
                                &inner.app_id,
                                &config,
                                &tree_root,
                                &tree_version,
                                target,
                            )
                        });
                if let Err(e) = checked {
                    inner.fs.remove_dir_all_nofollow(&tree)?;
                    return Err(e);
                }
                Ok(())
            },
        )
        .await?;

        // 5. The commit, as `install`'s.
        let floors = verified.floors;
        let issued = manifest.issued();
        let drop_frames: Vec<Sha256Digest> = frames.iter().map(|(_, f)| f.sha256).collect();
        on_job(
            &inner,
            Some(&lock),
            &cancel,
            "install-commit",
            move |inner, _| {
                let Layout::User { state_dir, .. } = &inner.layout else {
                    return Err(Error::MachineScope);
                };
                let store = UserScope {
                    dir: state_dir.clone(),
                    app_id: inner.app_id.clone(),
                };
                let loaded = store.load(&*inner.fs, &*inner.hasher)?;
                let record = loaded.record.clone().ok_or(Error::NotInstalled)?;
                if record.current.is_some() {
                    return Err(already_installed(&*inner.fs, &install_root, &record));
                }
                let tree = staged.tree;
                let config = tree_config(&*inner.fs, &inner.app_id, &tree)?;
                let request = integration_request(&inner.app_id, &install_root, config.install);
                inner.integration.check(Scope::User, &request)?;
                let next = lunepack_core::install_first(
                    &record.raise_floors(&floors),
                    version.clone(),
                    issued,
                    record.install_id,
                )?;
                // As `install` (F11, Q42): the integration before the commit.
                inner.integration.apply(Scope::User, &request)?;
                let committed = store.commit(&*inner.fs, &loaded, &next, &*inner.hasher)?;
                lunepack_core::reconcile_current(&*inner.fs, &install_root, &committed)
                    .map_err(|e| Error::from(lunepack_core::Error::Layout(e)))?;
                // Housekeeping (M4-D17): a failure here is not an error of the install.
                let cache = inner.cache();
                for sha in &drop_frames {
                    let _ = cache.remove_entry(CacheKind::Frame, sha);
                }
                Ok(InstalledVersion {
                    version,
                    issued,
                    target: committed.target,
                })
            },
        )
        .await
    })
    .await
}
