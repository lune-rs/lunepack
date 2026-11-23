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

use lunepack_core::codesign::{Decision, PublisherOutcome, decide};
use lunepack_core::fetch::FetchPolicy;
use lunepack_core::layout::LOCK_FILE;
use lunepack_core::service::CommitOutcome;
use lunepack_core::state::MAX_BAD_VERSIONS;
use lunepack_core::state::{CurrentRef, Scope, is_record_name};
use lunepack_core::state::{
    Floors, InstallCounters, InstallState, Loaded, MachineScope as MachineStore, RootParts,
    StagedRef, UserScope,
};
use lunepack_core::update_config::MAX_UPDATE_CONFIG_BYTES;
use lunepack_core::{
    AppId, BlockingResponse, BlockingTransport, CancelToken, Channel, ClockReading, Codec,
    Documents, FileKind, Fs, Hasher, IntegrationError, IntegrationRequest, Limits, OsIntegration,
    PatchSource, Phase, Progress, ReadAt, RelPath, Request, Rng, RootNaming, RootWalk,
    Sha256Digest, SourceFor, StageEnv, StageError, StageInput, Target, Transport, TransportError,
    TrustedRoot, UpdateConfig, UpdateConfigError, UserLayout, VerifiedEntry, VerifiedManifest,
    Verifier, Version, raised_floors, read_entry, select_candidate, verify_first_install_keys,
    verify_manifest, verify_payload_manifest,
};
use lunepack_core::{
    LayoutError, LayoutScheme, LocationReason, PublisherCheck, PublisherPolicy, SignedTree,
};

use crate::cache::{Cache, CacheKind, PartTools};
use crate::fetch::{self, FeedUrls, FetchCtx, FrameNeed, PackTarget, cancellable};
use crate::machine::{self, Offer, SignedDocs, StageSession};
use crate::progress::{ProgressPump, ProgressSink, progress};
use crate::task::{OpLock, spawn_job};
use crate::worker_transport::WorkerTransport;
use crate::{Error, SystemClock};

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
    publisher: Option<Arc<dyn PublisherCheck>>,
    service: Option<Arc<dyn lunepack_core::ServiceConnector>>,
    policy_source: Option<Arc<dyn lunepack_core::PolicySource>>,
    workers: Option<usize>,
    budget: u64,
    policy: FetchPolicy,
    timeouts: Timeouts,
    bundle: Option<BundleSetup>,
    adopt: Option<PathBuf>,
}

/// The macOS bundle layout of an install (M8-D1, D2): where the first install puts the live
/// bundle. Without it the install root's directories are read as the first scheme that names
/// them (XDG, then Windows).
#[derive(Debug, Clone)]
struct BundleSetup {
    /// The apps folder (canonical): `~/Applications`.
    apps_dir: PathBuf,
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
            publisher: None,
            service: None,
            policy_source: None,
            workers: None,
            budget: DEFAULT_BUDGET,
            policy: FetchPolicy::default(),
            timeouts: Timeouts::default(),
            bundle: None,
            adopt: None,
        }
    }

    /// The install is a macOS bundle install ([`LayoutScheme::MACOS`], M8-D1): the first
    /// [`Updater::install`] puts the live bundle in `apps_dir`, the canonical apps folder (the
    /// user's `~/Applications`, created private when missing), after checking that it is on the
    /// install's volume and the user can write it ([`Error::UnsupportedLocation`]). The updater's
    /// layout must be that of an install root under that scheme.
    pub fn bundle_layout(mut self, apps_dir: PathBuf) -> Self {
        self.bundle = Some(BundleSetup { apps_dir });
        self
    }

    /// The check may adopt the bundle at `bundle` (M8-D9): the running bundle, which the facade's
    /// discovery found adoptable ([`crate::Installation::adoptable`]), with a
    /// [`UpdaterBuilder::bundle_layout`] layout whose current tree it is.
    pub(crate) fn adopt_bundle(mut self, bundle: PathBuf) -> Self {
        self.adopt = Some(bundle);
        self
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

    /// The publisher-continuity check [`Updater::stage`] runs (M9-D9; default: WinVerifyTrust on
    /// Windows, Security.framework on macOS, none elsewhere). Whether it runs and what it refuses
    /// is the installed tree's own `publisher_check` policy (M9-D6); no builder option changes it.
    pub fn publisher_check(mut self, publisher: Arc<dyn PublisherCheck>) -> Self {
        self.publisher = Some(publisher);
        self
    }

    /// How the update service of a per-machine install is reached (M10, C8): a [`Layout::Machine`]
    /// updater stages through it. Without one, staging a machine layout is [`Error::MachineScope`]
    /// (the library never writes a machine install itself). An updater of
    /// [`crate::Installation::updater_builder`] has the platform's connector.
    pub fn service_connector(
        mut self,
        connector: Arc<dyn lunepack_core::ServiceConnector>,
    ) -> Self {
        self.service = Some(connector);
        self
    }

    /// Where the administrator's policy for a per-machine install is read (M10-D12): with
    /// self-update disabled, `check`, `download` and `stage` of a [`Layout::Machine`] updater are
    /// [`Error::DisabledByPolicy`] before any request. Without a source nothing is disabled. An
    /// updater of [`crate::Installation::updater_builder`] has the platform's.
    pub fn policy_source(mut self, source: Arc<dyn lunepack_core::PolicySource>) -> Self {
        self.policy_source = Some(source);
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
                publisher: self
                    .publisher
                    .unwrap_or_else(crate::installation::default_publisher),
                service: self.service,
                policy_source: self.policy_source,
                workers: workers.max(1),
                budget: self.budget,
                policy: self.policy,
                bundle: self.bundle,
                adopt: self.adopt,
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
    /// The documents the check verified, as it read them (a machine install's stage sends them).
    docs: Arc<SignedDocs>,
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
    publisher: Option<PublisherOutcome>,
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

    /// What the publisher check (M9-D9) reported when it let this version through: `Some` under
    /// a `warn` policy for any finding other than "same publisher" or "not applicable", and under
    /// `enforce` for an installed version with no code signature (no baseline yet). `None` when
    /// the check found the same publisher, did not apply, or did not run, and always for a version
    /// re-opened by [`Updater::staged`] (the finding is not recorded).
    pub fn publisher(&self) -> Option<PublisherOutcome> {
        self.publisher
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

/// Options of [`Updater::check_with`].
#[derive(Default)]
pub struct CheckOptions {
    /// Called with coalesced progress events on the polling thread. Only an adoption reports
    /// any (phase [`Phase::Adopt`], M8-D9).
    pub progress: Option<ProgressCallback>,
    /// Cancels the operation (dropping its future does too).
    pub cancel: Option<CancelToken>,
}

impl fmt::Debug for CheckOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckOptions")
            .field("progress", &self.progress.is_some())
            .field("cancel", &self.cancel)
            .finish()
    }
}

/// What [`Updater::check_with`] found.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CheckOutcome {
    /// The update, or none.
    pub update: Option<UpdateInfo>,
    /// Whether this check adopted the running bundle before it checked (M8-D9); `true` in that
    /// one check only.
    pub adopted: bool,
}

/// A completed download, the input of [`Updater::stage`].
pub struct Downloaded {
    info: UpdateInfo,
    /// Per manifest entry: the current-tree file that already matches it.
    unchanged: Vec<Option<PathBuf>>,
    frames: HashMap<Sha256Digest, PathBuf>,
    pack: Option<PathBuf>,
    /// Per manifest entry: the delta patch chosen for it (M12-D5), its bytes in the cache.
    patches: Vec<Option<PatchSource>>,
    /// The delta file the patches come from, for the cache's housekeeping.
    delta: Option<Sha256Digest>,
    options: DownloadOptions,
}

impl fmt::Debug for Downloaded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Downloaded")
            .field("info", &self.info)
            .field("frames", &self.frames.len())
            .field("patches", &self.patches.iter().flatten().count())
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
    publisher: Arc<dyn PublisherCheck>,
    /// The update service of a per-machine install, when the updater has one.
    service: Option<Arc<dyn lunepack_core::ServiceConnector>>,
    policy_source: Option<Arc<dyn lunepack_core::PolicySource>>,
    workers: usize,
    budget: u64,
    policy: FetchPolicy,
    bundle: Option<BundleSetup>,
    /// The bundle the check adopts when the app has no live install (M8-D9).
    adopt: Option<PathBuf>,
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

    /// M10-D12: an administrator's policy switched self-update off for this per-machine install.
    /// Read before every operation that would reach for an update, so no request is made.
    fn refuse_if_disabled(&self) -> Result<(), Error> {
        let disabled = matches!(self.layout, Layout::Machine { .. })
            && self
                .policy_source
                .as_ref()
                .is_some_and(|source| source.read(&self.app_id).self_update_disabled);
        if disabled {
            return Err(Error::DisabledByPolicy);
        }
        Ok(())
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
    ///
    /// An updater of a macOS bundle that is not installed but adoptable
    /// ([`crate::Installation::adoptable`], M8-D9) adopts it first, when the app has no live
    /// install for the user and the bundle is directly in `~/Applications` or `/Applications`
    /// (anywhere else it is a development run: no request, nothing written; adoption happens here
    /// and in no other call, never in `startup`): the bundle's own release (exactly its config's version and target)
    /// is verified from the bundle's own root as above, the bundle is proved equal to that
    /// release's signed manifest file by file ([`lunepack_core::verify_tree`]: nothing missing,
    /// nothing extra, sizes, hashes, executable bits and link targets; the bundle is never
    /// written, moved or removed), and only then is it recorded as the install's current
    /// version (events `installed` and `first_run`; an orphaned install, or one whose live bundle
    /// the user replaced at its own path, keeps its floors and gets a new install id). The check
    /// then goes on as an installed one. A failure leaves the bundle as it was, at most a record
    /// with no current version and floors raised from verified documents, and the next check
    /// tries again. A live install makes it [`Error::NotInstalled`] with no request made. See [`Updater::check_with`].
    pub fn check(
        &self,
    ) -> impl Future<Output = Result<Option<UpdateInfo>, Error>> + Send + 'static {
        let inner = Arc::clone(&self.inner);
        async move {
            check(inner, CheckOptions::default())
                .await
                .map(|outcome| outcome.update)
        }
    }

    /// [`Updater::check`] with progress and a cancel token, also saying whether it adopted the
    /// running bundle ([`CheckOutcome::adopted`]).
    pub fn check_with(
        &self,
        options: CheckOptions,
    ) -> impl Future<Output = Result<CheckOutcome, Error>> + Send + 'static {
        let inner = Arc::clone(&self.inner);
        async move { check(inner, options).await }
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
    ///
    /// Before the record, when the install has a current version, the publisher check runs
    /// (M9-D9) under the policy of the **installed** tree's update config (`publisher_check`,
    /// M9-D6; no config, or no such member, is `off`; a config that cannot be read fails the
    /// stage): `off` runs nothing; `warn` goes on and reports any finding in
    /// [`StagedVersion::publisher`] and a `tracing` warning; `enforce` refuses with
    /// [`Error::PublisherMismatch`], records nothing staged, and in the same state commit marks the
    /// version bad when the finding is about the candidate (`different`, `candidate_unsigned`,
    /// `candidate_invalid`). The candidate's own config never sets its own policy. A first install
    /// (no current version) has no installed publisher and runs no check.
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
    ///
    /// A macOS bundle install ([`UpdaterBuilder::bundle_layout`]) goes as `install` does there:
    /// before anything is written, the apps folder's place ([`Error::UnsupportedLocation`]:
    /// `other_volume`, `not_writable`, `read_only`, `translocated`; where the payload itself is
    /// read from is not judged); a record whose live bundle the user removed (M8-D16) is not
    /// installed: under the lock it is reset to its floors with a new install id and the install
    /// goes on; in step 3 the live bundle's name is chosen in the apps folder and the integration's
    /// preflight runs against it; the commit writes `R/bundle` before the record, and the
    /// reconcile after it places the staged tree as the bundle. A rerun on a live install applies
    /// the integration of the live bundle again and is [`Error::AlreadyInstalled`].
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
    /// An updater of an adoptable bundle ([`crate::Installation::adoptable`]) is a development
    /// run until its check adopted the bundle: `Ok(None)` while the record is not the bundle's
    /// (none, no current version, orphaned, or replaced by this bundle).
    pub fn installed(&self) -> Result<Option<InstalledVersion>, Error> {
        let snap = match self.inner.load() {
            Ok(snap) => snap,
            Err(Error::NotInstalled) => return Ok(None),
            Err(e) => return Err(e),
        };
        let record = snap.record();
        if let (
            Some(bundle),
            Layout::User {
                state_dir,
                versions_dir,
                ..
            },
        ) = (&self.inner.adopt, &self.inner.layout)
        {
            let root = install_root_of(state_dir, versions_dir, scheme_of(&self.inner))?;
            let fs = &*self.inner.fs;
            if !names_bundle(fs, &root, bundle) || taken_over(fs, &root, record, bundle) {
                return Ok(None);
            }
        }
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
            publisher: None,
        }))
    }
}

async fn check(inner: Arc<Inner>, options: CheckOptions) -> Result<CheckOutcome, Error> {
    inner.refuse_if_disabled()?;
    if let Some(bundle) = inner.adopt.clone() {
        return check_adopting(inner, bundle, options).await;
    }
    let cancel = options.cancel.unwrap_or_default();
    let lock = take_lock(&inner, &cancel).await?;
    let snap = on_job(&inner, Some(&lock), &cancel, "state-load", |inner, _| {
        inner.load()
    })
    .await?;
    let current = snap.record().current.clone().ok_or(Error::NotInstalled)?;
    let update = check_from(&inner, &lock, &cancel, snap, Some(current)).await?;
    Ok(CheckOutcome {
        update,
        adopted: false,
    })
}

/// The check of [`Updater::install`]: the record exists and has no current version, so there is
/// no floor time and any release of the channel is a candidate (M5-D8).
async fn check_first(
    inner: &Arc<Inner>,
    cancel: &CancelToken,
    root: &UserLayout,
) -> Result<Option<UpdateInfo>, Error> {
    let lock = take_lock(inner, cancel).await?;
    let snap = on_job(inner, Some(&lock), cancel, "state-load", |inner, _| {
        inner.load()
    })
    .await?;
    if snap.record().current.is_some() {
        let record = snap.record().clone();
        let root = root.clone();
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

    let (Documents { root, keys, feed }, mut docs) =
        verify_documents(inner, transport, &floors, &clock).await?;
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
            docs.manifest = bytes.to_vec();
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
                docs: Arc::new(docs),
            })
        }
    };
    let raised = raised_floors(&root, &keys, &feed, &inner.channel);
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

/// The documents of a check, in FORMAT.md 11.1 order: the root walk (FORMAT.md 5.2) from the
/// higher of the stored (`floors`) and the embedded root, then the key set and the feed against
/// `floors` and `clock`. The core's [`RootWalk`] verifies; this only fetches. Nothing is committed.
/// Also returns the bytes it read (the manifest is the caller's): a machine install's stage sends
/// them to the service.
///
/// On a machine install the walk starts from the machine record's root whenever it has one, never
/// from a higher embedded root: the service verifies from that root alone (M10-D17), so the
/// rotation documents it is sent must follow it.
async fn verify_documents(
    inner: &Inner,
    transport: &dyn Transport,
    floors: &Floors,
    clock: &ClockReading,
) -> Result<(Documents, SignedDocs), Error> {
    let hasher = &*inner.hasher;
    let verifier = &*inner.verifier;
    let machine = matches!(inner.layout, Layout::Machine { .. });
    let start = match &floors.root {
        Some(parts) if machine || parts.version > inner.root.version() => {
            parts.to_trusted(inner.app_id.clone(), hasher, verifier)?
        }
        _ => inner.root.clone(),
    };
    let mut docs = SignedDocs::default();
    let mut walk = RootWalk::new(start);
    while let Some(next) = walk.next_version() {
        let url = inner.urls.root(next)?;
        match fetch::fetch_root_doc(transport, &url, Limits::V1.root_doc_bytes).await? {
            None => break,
            Some(bytes) => {
                walk.advance(&bytes, hasher, verifier)?;
                docs.roots.push(bytes);
            }
        }
    }
    walk.check_app_id(&inner.app_id)?;
    let keys_bytes =
        fetch::fetch_document(transport, &inner.urls.keys()?, Limits::V1.keys_doc_bytes).await?;
    let chain = walk.verify_keys(&inner.app_id, floors, &keys_bytes, clock, hasher, verifier)?;
    let feed_bytes =
        fetch::fetch_document(transport, &inner.feed_url, Limits::V1.feed_doc_bytes).await?;
    let documents =
        chain.verify_feed(&inner.app_id, &inner.channel, &feed_bytes, clock, verifier)?;
    docs.keys = keys_bytes;
    docs.feed = feed_bytes;
    Ok((documents, docs))
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
    inner.refuse_if_disabled()?;
    let cancel = options.cancel.clone().unwrap_or_default();
    let (sink, mut pump) = progress(Phase::Scan, 0);
    let mut callback = options.progress.take();
    let result = with_progress(&mut pump, &mut callback, async {
        let lock = take_lock(&inner, &cancel).await?;
        let snap = load_fresh(&inner, &lock, &cancel, &info).await?;
        let current = snap.record().current.as_ref().map(|c| c.version.clone());
        let manifest = Arc::clone(&info.manifest);
        let frames = frames_of(&manifest);
        // M12-D5: the delta whose `from` is the installed version's text, byte for byte (build
        // metadata included). A machine install's stage uploads the patches to a version-2
        // service, and the frames instead to a version-1 one (M12-D6).
        let delta_at = current.as_ref().and_then(|v| {
            let text = v.to_string();
            manifest.deltas().iter().position(|d| d.from_text() == text)
        });

        // Cache entries the plan does not name go first (M4-D17).
        let keep_frames: HashSet<Sha256Digest> = frames.iter().map(|(_, f)| f.sha256).collect();
        let keep_packs = HashSet::from([info.pack.sha256]);
        let (keep_patches, keep_deltas): (HashSet<Sha256Digest>, HashSet<Sha256Digest>) =
            match delta_at.map(|d| &manifest.deltas()[d]) {
                Some(d) => (
                    d.patches().iter().map(|p| p.sha256()).collect(),
                    HashSet::from([d.file().sha256()]),
                ),
                None => (HashSet::new(), HashSet::new()),
            };
        let tree = on_job(
            &inner,
            Some(&lock),
            &cancel,
            "cache-clean",
            move |inner, _| {
                let cache = inner.cache();
                cache.ensure_dirs()?;
                cache.cleanup(&[
                    (CacheKind::Frame, &keep_frames),
                    (CacheKind::Pack, &keep_packs),
                    (CacheKind::Patch, &keep_patches),
                    (CacheKind::Delta, &keep_deltas),
                ])?;
                inner.current_tree(current.as_ref())
            },
        )
        .await?;

        // The total is the bytes scan hashes, which only its first event knows.
        sink.set_phase(Phase::Scan, 0);
        let scan_sink = sink.clone();
        let scan_manifest = Arc::clone(&manifest);
        let scan_tree = tree.clone();
        let unchanged = on_job(
            &inner,
            Some(&lock),
            &cancel,
            "scan",
            move |inner, cancel| {
                let last = AtomicU64::new(0);
                Ok(lunepack_core::scan(
                    &scan_manifest,
                    scan_tree.as_deref(),
                    &*inner.fs,
                    &*inner.hasher,
                    inner.workers,
                    cancel,
                    &|p| forward(&scan_sink, &last, &p),
                )?)
            },
        )
        .await?;

        let needed: Vec<(usize, FrameNeed)> = frames
            .iter()
            .filter(|(i, _)| unchanged.get(*i).is_none_or(Option::is_none))
            .cloned()
            .collect();
        let mut patches = match (delta_at, tree) {
            (Some(d), Some(tree)) => {
                choose_patches(&inner, &lock, &cancel, &sink, &info, d, &unchanged, tree).await?
            }
            _ => vec![None; manifest.entries().len()],
        };
        // The total is what the download will move: `fetch::download` adds it once it has planned.
        sink.set_phase(Phase::Download, 0);
        let ctx = fetch_ctx(&inner, &lock, &cancel, &sink);
        let mut delta = None;
        if let Some(d) = delta_at.filter(|_| patches.iter().any(Option::is_some)) {
            let file = manifest.deltas()[d].file();
            delta = Some(file.sha256());
            let target = PackTarget {
                url: inner.urls.reference(file)?,
                size: file.size(),
                sha256: file.sha256(),
            };
            fetch_patches(&inner, &lock, &cancel, &ctx, &target, &mut patches).await?;
        }
        let frame_needed: Vec<FrameNeed> = needed
            .iter()
            .filter(|(i, _)| patches.get(*i).is_none_or(Option::is_none))
            .map(|(_, f)| f.clone())
            .collect();
        let fetched = fetch::download(&ctx, &info.pack, &frame_needed).await?;
        let frames: HashMap<Sha256Digest, PathBuf> = frame_needed
            .iter()
            .filter_map(|f| {
                fetched
                    .frame(&f.sha256)
                    .map(|p| (f.sha256, p.to_path_buf()))
            })
            .collect();
        Ok::<_, Error>((
            unchanged,
            frames,
            fetched.pack().map(Path::to_path_buf),
            patches,
            delta,
        ))
    })
    .await;
    let (unchanged, frames, pack, patches, delta) = result?;
    options.progress = callback;
    Ok(Downloaded {
        info,
        unchanged,
        frames,
        pack,
        patches,
        delta,
        options,
    })
}

/// The bytes a fetch plan of `spans` (offset, length) over an artifact of `size` bytes moves:
/// the runs with their merged gaps, or the whole artifact; nothing for no span.
fn plan_bytes(spans: &[(u64, u64)], size: u64, policy: FetchPolicy) -> u64 {
    if spans.is_empty() {
        return 0;
    }
    match lunepack_core::plan_fetch(spans, size, policy) {
        lunepack_core::FetchPlan::FullPack => size,
        lunepack_core::FetchPlan::Runs(runs) => runs
            .iter()
            .fold(0u64, |sum, r| sum.saturating_add(r.last - r.first + 1)),
    }
}

/// M12-D5: the patches of delta `d` worth using, per manifest entry. A file not `unchanged` gets
/// its patch when the current file at its path has exactly the patch's base size and SHA-256
/// ([`lunepack_core::base_digests`], run only when the delta has a patch for such a file) and the
/// patch is shorter than the file's frame. Then the whole plan: the bytes of the patches (by
/// Range runs or the whole delta file) plus those of the remaining frames (runs or the full
/// pack) must be strictly fewer than the bytes of the plan without patches, else no patch is
/// used.
#[allow(clippy::too_many_arguments)]
async fn choose_patches(
    inner: &Arc<Inner>,
    lock: &OpLock,
    cancel: &CancelToken,
    sink: &ProgressSink,
    info: &UpdateInfo,
    d: usize,
    unchanged: &[Option<PathBuf>],
    tree: PathBuf,
) -> Result<Vec<Option<PatchSource>>, Error> {
    let manifest = &info.manifest;
    let entries = manifest.entries();
    let mut out: Vec<Option<PatchSource>> = vec![None; entries.len()];
    let delta = &manifest.deltas()[d];
    let index: HashMap<&RelPath, usize> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| (e.path(), i))
        .collect();
    let wanted = delta.patches().iter().any(|p| {
        index
            .get(p.path())
            .is_some_and(|i| unchanged.get(*i).is_none_or(Option::is_none))
    });
    if !wanted {
        return Ok(out);
    }
    let digest_manifest = Arc::clone(manifest);
    let digest_unchanged = unchanged.to_vec();
    let digest_tree = tree.clone();
    let digest_sink = sink.clone();
    let digests = on_job(
        inner,
        Some(lock),
        cancel,
        "base-digests",
        move |inner, cancel| {
            let last = AtomicU64::new(0);
            Ok(lunepack_core::base_digests(
                &digest_manifest,
                &digest_manifest.deltas()[d],
                &digest_unchanged,
                Some(&digest_tree),
                &*inner.fs,
                &*inner.hasher,
                inner.workers,
                cancel,
                &|p| forward(&digest_sink, &last, &p),
            )?)
        },
    )
    .await?;
    for patch in delta.patches() {
        let Some(&i) = index.get(patch.path()) else {
            continue;
        };
        let VerifiedEntry::File {
            frame: Some(frame), ..
        } = &entries[i]
        else {
            continue;
        };
        if digests.get(i).copied().flatten() != Some(patch.base_sha256())
            || patch.length() >= frame.length()
        {
            continue;
        }
        let mut base = tree.clone();
        for c in patch.path().components() {
            base.push(c);
        }
        out[i] = Some(PatchSource {
            patch: inner.cache().path(CacheKind::Patch, &patch.sha256()),
            base,
            desc: patch.clone(),
        });
    }

    // The whole plan, with and without the patches (equal shares counted once).
    let mut without: Vec<(u64, u64)> = Vec::new();
    let mut frames_left: Vec<(u64, u64)> = Vec::new();
    let mut patch_spans: Vec<(u64, u64)> = Vec::new();
    let (mut seen_frames, mut seen_left, mut seen_patches) =
        (HashSet::new(), HashSet::new(), HashSet::new());
    for (i, e) in entries.iter().enumerate() {
        let VerifiedEntry::File {
            frame: Some(frame), ..
        } = e
        else {
            continue;
        };
        if unchanged.get(i).is_some_and(Option::is_some) {
            continue;
        }
        let span = (frame.offset(), frame.length());
        if seen_frames.insert(frame.sha256()) {
            without.push(span);
        }
        match &out[i] {
            Some(p) => {
                if seen_patches.insert(p.desc.sha256()) {
                    patch_spans.push((p.desc.offset(), p.desc.length()));
                }
            }
            None => {
                if seen_left.insert(frame.sha256()) {
                    frames_left.push(span);
                }
            }
        }
    }
    let policy = inner.policy;
    let pack_size = info.pack.size;
    let with = plan_bytes(&patch_spans, delta.file().size(), policy).saturating_add(plan_bytes(
        &frames_left,
        pack_size,
        policy,
    ));
    if patch_spans.is_empty() || with >= plan_bytes(&without, pack_size, policy) {
        out.iter_mut().for_each(|p| *p = None);
    }
    Ok(out)
}

/// Fetches the chosen patches of `delta` into `patches/` (M12-D5): by Range runs, or as the whole
/// delta file (verified, as packs are, M4-D17), which is then split into one cache file per patch.
/// A patch that did not arrive with its signed SHA-256 loses its patch (its frame is fetched
/// instead); a delta file the server does not serve (an HTTP error, a wrong size or hash) drops
/// every patch. Cancel and an interrupted body stay errors, so the next call resumes them.
async fn fetch_patches(
    inner: &Arc<Inner>,
    lock: &OpLock,
    cancel: &CancelToken,
    ctx: &FetchCtx,
    target: &PackTarget,
    patches: &mut [Option<PatchSource>],
) -> Result<(), Error> {
    let mut needs: Vec<FrameNeed> = Vec::new();
    for p in patches.iter().flatten() {
        if !needs.iter().any(|n| n.sha256 == p.desc.sha256()) {
            needs.push(FrameNeed {
                offset: p.desc.offset(),
                length: p.desc.length(),
                sha256: p.desc.sha256(),
            });
        }
    }
    let fetched = match fetch::download_in(ctx, target, &needs, fetch::Kinds::DELTA).await {
        Ok(fetched) => fetched,
        Err(e @ (Error::Cancelled | Error::Incomplete | Error::Fs(_) | Error::WorkerPanicked)) => {
            return Err(e);
        }
        Err(e) => {
            tracing::warn!(error = %e, "the delta file cannot be fetched; frames instead");
            patches.iter_mut().for_each(|p| *p = None);
            return Ok(());
        }
    };
    let have: HashSet<Sha256Digest> = match fetched.pack() {
        Some(whole) => {
            let whole = whole.to_path_buf();
            on_job(
                inner,
                Some(lock),
                cancel,
                "delta-split",
                move |inner, cancel| {
                    let cache = inner.cache();
                    let reader = inner.fs.open_read(&whole)?;
                    let tools = PartTools {
                        hasher: &*inner.hasher,
                        cancel,
                    };
                    let mut have = HashSet::new();
                    for n in &needs {
                        let stored = cache.is_complete(CacheKind::Patch, &n.sha256, n.length)?
                            || cache.store_frame(
                                CacheKind::Patch,
                                &*reader,
                                n.offset,
                                n.length,
                                &n.sha256,
                                &tools,
                                &|_| {},
                            )?;
                        if stored {
                            have.insert(n.sha256);
                        }
                    }
                    Ok(have)
                },
            )
            .await?
        }
        None => needs
            .iter()
            .filter(|n| fetched.frame(&n.sha256).is_some())
            .map(|n| n.sha256)
            .collect(),
    };
    for p in patches.iter_mut() {
        if p.as_ref().is_some_and(|p| !have.contains(&p.desc.sha256())) {
            *p = None;
        }
    }
    Ok(())
}

/// The stage sources: the matching current file, else the pack when the entry was moved to it,
/// else its delta patch unless that patch failed in this call (`no_patch`), else the cached frame
/// (its expected path, which the stage reports as `NeedFetch` when missing), else the pack.
#[allow(clippy::too_many_arguments)]
fn sources(
    manifest: &VerifiedManifest,
    unchanged: &[Option<PathBuf>],
    frames: &HashMap<Sha256Digest, PathBuf>,
    pack: Option<&Path>,
    use_pack: &HashSet<usize>,
    patches: &[Option<PatchSource>],
    no_patch: &HashSet<usize>,
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
            // An entry moved to the pack failed once, so it is in `no_patch` too.
            if let Some(patch) = patches.get(i).and_then(Option::as_ref)
                && !no_patch.contains(&i)
                && !use_pack.contains(&i)
            {
                return SourceFor::Patch(patch.clone());
            }
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
    if matches!(inner.layout, Layout::Machine { .. }) {
        // C8: the library never writes a machine install; the service does, from the same bytes.
        inner.refuse_if_disabled()?;
        return stage_machine(inner, downloaded).await;
    }
    let Layout::User { versions_dir, .. } = &inner.layout else {
        return Err(Error::MachineScope);
    };
    let versions_dir = versions_dir.clone();
    let Downloaded {
        info,
        mut unchanged,
        mut frames,
        mut pack,
        patches,
        delta,
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
        // A path whose patch failed is never given a patch again in this call (D27).
        let mut no_patch: HashSet<usize> = HashSet::new();
        let (mut range_tried, mut pack_tried) = (false, false);
        let staged = loop {
            let input_sources = sources(
                &manifest,
                &unchanged,
                &frames,
                pack.as_deref(),
                &use_pack,
                &patches,
                &no_patch,
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
            no_patch.extend(failed.iter().copied());
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

        // M9-D9: the publisher check, under the installed tree's policy, before anything is
        // recorded. Only an install with a current version has an installed publisher to compare
        // with (a first install has none).
        let decision = match snap.record().current.as_ref() {
            Some(current) => {
                let current = current.version.clone();
                let candidate = staged.tree.clone();
                on_job(
                    &inner,
                    Some(&lock),
                    &cancel,
                    "publisher",
                    move |inner, _| publisher_decision(inner, &current, candidate),
                )
                .await?
            }
            None => Decision::Proceed(None),
        };
        if let Decision::Refuse { reason, .. } | Decision::Proceed(Some(reason)) = decision {
            // The code only: never a path, a subject name or an OS message.
            tracing::warn!(publisher = reason.code(), "publisher check finding");
        }
        if let Decision::Refuse { reason, mark_bad } = decision {
            // Nothing is staged; the tree is left to GC, and the cache to the next download
            // (its frames serve a retry after a local fault).
            if mark_bad {
                let bad = staged.version.clone();
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
                        // A full list (only an older writer gets there) cannot take one more: the
                        // refusal stands, unmarked.
                        if !record.bad.contains(&bad) && record.bad.len() < MAX_BAD_VERSIONS {
                            let next = record.mark_bad(bad);
                            store.commit(&*inner.fs, loaded, &next, &*inner.hasher)?;
                        }
                        Ok(())
                    },
                )
                .await?;
            }
            return Err(Error::PublisherMismatch { reason });
        }
        let publisher = match decision {
            Decision::Proceed(found) => found,
            Decision::Refuse { .. } => None,
        };

        // Record the tree, then drop the version's cache entries (M4-D17).
        let staged_ref =
            StagedRef::new(staged.version.clone(), staged.target, info.manifest_sha256);
        // The staged manifest's `issued` goes with it: an apply makes it the floor time (P9).
        let staged_issued = info.issued();
        let drop_frames: Vec<Sha256Digest> = all_frames.iter().map(|(_, f)| f.sha256).collect();
        let drop_patches: Vec<Sha256Digest> =
            patches.iter().flatten().map(|p| p.desc.sha256()).collect();
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
                for sha in &drop_patches {
                    let _ = cache.remove_entry(CacheKind::Patch, sha);
                }
                let _ = cache.remove_entry(CacheKind::Pack, &pack_sha);
                if let Some(sha) = &delta {
                    let _ = cache.remove_entry(CacheKind::Delta, sha);
                }
                Ok(())
            },
        )
        .await?;
        Ok(StagedVersion {
            version: staged.version,
            target: staged.target,
            tree: staged.tree,
            publisher,
        })
    })
    .await
}

/// What `stage` of a machine layout sends the service for `downloaded`: every frame the download
/// holds, the patch of each file it holds no frame for (M12-D6; only kept for a version-2
/// service) and, when some file still has neither, the pack it holds. (The service chooses its own
/// sources: the unchanged files of its tree first.)
fn offers(downloaded: &Downloaded) -> Vec<Offer> {
    let manifest = &downloaded.info.manifest;
    let mut out = Vec::new();
    let mut needs_pack = false;
    for (i, need) in frames_of(manifest) {
        if downloaded.unchanged.get(i).is_some_and(Option::is_some) {
            continue;
        }
        let patch = downloaded.patches.get(i).and_then(Option::as_ref);
        match (downloaded.frames.get(&need.sha256), patch) {
            (Some(path), _) => {
                if !out.iter().any(|o: &Offer| o.sha256 == need.sha256) {
                    out.push(Offer {
                        kind: lunepack_core::service::ObjectKind::Frame,
                        sha256: need.sha256,
                        size: need.length,
                        path: path.clone(),
                    });
                }
            }
            (None, Some(p)) => {
                let sha256 = p.desc.sha256();
                if !out.iter().any(|o: &Offer| o.sha256 == sha256) {
                    out.push(Offer {
                        kind: lunepack_core::service::ObjectKind::Patch,
                        sha256,
                        size: p.desc.length(),
                        path: p.patch.clone(),
                    });
                }
            }
            (None, None) => needs_pack = true,
        }
    }
    if let (true, Some(pack)) = (needs_pack, downloaded.pack.as_ref()) {
        out.push(Offer {
            kind: lunepack_core::service::ObjectKind::Pack,
            sha256: downloaded.info.pack.sha256,
            size: downloaded.info.pack.size,
            path: pack.clone(),
        });
    }
    out
}

/// `stage` of a per-machine install (C8): the documents the check verified and the objects the
/// download holds go to the service's stage session, which verifies them again and builds the
/// tree. A `need_fetch` is answered by fetching what is missing (the failing frames by Range,
/// then the whole pack, the D27 ladder) and committing again, within the session's three commits.
/// Dropping the future, or a cancel, ends the session: the service discards what it holds.
async fn stage_machine(inner: Arc<Inner>, downloaded: Downloaded) -> Result<StagedVersion, Error> {
    if !matches!(
        inner.layout,
        Layout::Machine {
            versions_dir: Some(_),
            ..
        }
    ) {
        return Err(Error::MachineScope);
    }
    let Some(connector) = inner.service.clone() else {
        // No way to reach a service was given: the library has no other way to stage (C8).
        return Err(Error::MachineScope);
    };
    let Downloaded {
        info,
        unchanged,
        mut frames,
        mut pack,
        patches,
        delta,
        mut options,
    } = downloaded;
    let cancel = options.cancel.clone().unwrap_or_default();
    let (sink, mut pump) = progress(Phase::Stage, 0);
    let mut callback = options.progress.take();
    with_progress(&mut pump, &mut callback, async {
        let lock = take_lock(&inner, &cancel).await?;
        // The same freshness rule as the user stage, from the machine record.
        load_fresh(&inner, &lock, &cancel, &info).await?;
        let all_frames = frames_of(&info.manifest);
        let mut held = Downloaded {
            info: info.clone(),
            unchanged: unchanged.clone(),
            frames: frames.clone(),
            pack: pack.clone(),
            patches,
            delta,
            options: DownloadOptions::default(),
        };
        let drop_patches: Vec<Sha256Digest> = held
            .patches
            .iter()
            .flatten()
            .map(|p| p.desc.sha256())
            .collect();
        let first = first_round(
            &inner,
            &lock,
            &cancel,
            &sink,
            &connector,
            FirstRound::of(&held),
        )
        .await?;
        let (session, mut round) = match first {
            Some(first) => first,
            None => {
                // M12-D6: a version-1 service takes no patch, so the patched files' frames are
                // fetched now, before the first commit, and the stage runs without patches.
                let need: Vec<FrameNeed> = all_frames
                    .iter()
                    .filter(|(i, f)| {
                        held.patches.get(*i).is_some_and(Option::is_some)
                            && !frames.contains_key(&f.sha256)
                    })
                    .map(|(_, f)| f.clone())
                    .collect();
                held.patches = Vec::new();
                let ctx = fetch_ctx(&inner, &lock, &cancel, &sink);
                sink.set_phase(Phase::Download, 0);
                let fetched = fetch::download(&ctx, &info.pack, &need).await?;
                for f in &need {
                    if let Some(p) = fetched.frame(&f.sha256) {
                        frames.insert(f.sha256, p.to_path_buf());
                    }
                }
                if let Some(p) = fetched.pack() {
                    pack = Some(p.to_path_buf());
                }
                held.frames = frames.clone();
                held.pack = pack.clone();
                sink.set_phase(Phase::Stage, 0);
                first_round(
                    &inner,
                    &lock,
                    &cancel,
                    &sink,
                    &connector,
                    FirstRound::of(&held),
                )
                .await?
                .ok_or(Error::Config(
                    "a version-1 service refused a stage without patches",
                ))?
            }
        };
        let session = Arc::new(std::sync::Mutex::new(Some(session)));
        let (mut range_tried, mut pack_tried) = (false, false);
        let staged_version = loop {
            let (outcome, rejected) = round;
            // What the service refused is gone from the cache; it is not offered again unless it
            // is fetched anew below.
            for (kind, sha) in rejected {
                match kind {
                    lunepack_core::service::ObjectKind::Frame => {
                        frames.remove(&sha);
                    }
                    lunepack_core::service::ObjectKind::Pack => pack = None,
                    lunepack_core::service::ObjectKind::Patch => {
                        for p in &mut held.patches {
                            if p.as_ref().is_some_and(|p| p.desc.sha256() == sha) {
                                *p = None;
                            }
                        }
                    }
                }
            }
            let paths = match outcome {
                CommitOutcome::Staged(v) => break v,
                CommitOutcome::NeedFetch { paths, .. } => paths,
            };
            let failed: Vec<usize> = info
                .manifest
                .entries()
                .iter()
                .enumerate()
                .filter(|(_, e)| paths.contains(e.path()))
                .map(|(i, _)| i)
                .collect();
            let failed_frames: Vec<FrameNeed> = all_frames
                .iter()
                .filter(|(i, _)| failed.contains(i))
                .map(|(_, f)| f.clone())
                .collect();
            // The service's scan found these changed: whatever the user's scan said, they need
            // an object now.
            for &i in &failed {
                if let Some(slot) = held.unchanged.get_mut(i) {
                    *slot = None;
                }
                // A failed patch is never offered again in this call (D27); its frame follows.
                if let Some(slot) = held.patches.get_mut(i) {
                    *slot = None;
                }
            }
            let ctx = fetch_ctx(&inner, &lock, &cancel, &sink);
            if !range_tried {
                range_tried = true;
                sink.set_phase(Phase::Download, 0);
                let fetched = fetch::download(&ctx, &info.pack, &failed_frames).await?;
                for f in &failed_frames {
                    if let Some(p) = fetched.frame(&f.sha256) {
                        frames.insert(f.sha256, p.to_path_buf());
                    }
                }
                if let Some(p) = fetched.pack() {
                    pack = Some(p.to_path_buf());
                }
            } else if !pack_tried {
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
                sink.set_phase(Phase::Download, 0);
                pack = Some(fetch::fetch_pack(&ctx, &info.pack, None).await?);
            } else {
                return Err(Error::NeedFetchExhausted(paths));
            }
            held.frames = frames.clone();
            held.pack = pack.clone();
            // Frames the service has taken are not sent again; the pack goes when files still
            // lack a frame.
            let more = offers(&held);
            let session = Arc::clone(&session);
            let progress_sink = sink.clone();
            sink.set_phase(Phase::Stage, 0);
            round = on_job(
                &inner,
                Some(&lock),
                &cancel,
                "service-stage",
                move |inner, cancel| {
                    let mut guard = session.lock().map_err(|_| Error::WorkerPanicked)?;
                    let stage = guard.as_mut().ok_or(Error::Cancelled)?;
                    stage.upload(&*inner.fs, &more, cancel)?;
                    let rejected = drop_rejected(inner, stage);
                    Ok((commit(stage, &progress_sink)?, rejected))
                },
            )
            .await?;
        };
        // The session ends here: the service's folder for it goes with the connection.
        drop(session);

        // The service recorded the tree; read where, and drop the version's cache entries.
        let drop_frames: Vec<Sha256Digest> = all_frames.iter().map(|(_, f)| f.sha256).collect();
        let pack_sha = info.pack.sha256;
        let version = staged_version.clone();
        let staged = on_job(
            &inner,
            Some(&lock),
            &cancel,
            "service-staged",
            move |inner, _| {
                let snap = inner.load()?;
                let record = snap.record();
                let staged = record
                    .staged
                    .as_ref()
                    .filter(|s| s.version == version && record.staged_issued_bound().is_some())
                    .ok_or(Error::NothingStaged)?;
                let tree = inner
                    .layout
                    .versions_dir()
                    .ok_or(Error::NothingStaged)?
                    .join(&staged.tree);
                let cache = inner.cache();
                for sha in &drop_frames {
                    let _ = cache.remove_entry(CacheKind::Frame, sha);
                }
                for sha in &drop_patches {
                    let _ = cache.remove_entry(CacheKind::Patch, sha);
                }
                let _ = cache.remove_entry(CacheKind::Pack, &pack_sha);
                if let Some(sha) = &delta {
                    let _ = cache.remove_entry(CacheKind::Delta, sha);
                }
                Ok(StagedVersion {
                    version,
                    target: staged.target,
                    tree,
                    publisher: None,
                })
            },
        )
        .await?;
        Ok(staged)
    })
    .await
}

/// What one upload-and-commit round of a machine stage ends with: the commit's outcome and the
/// objects the service refused.
type Round = (
    CommitOutcome,
    Vec<(lunepack_core::service::ObjectKind, Sha256Digest)>,
);

/// What [`first_round`] sends, taken from the held download.
struct FirstRound {
    offers: Vec<Offer>,
    with_patches: bool,
    docs: Arc<SignedDocs>,
    version: Version,
}

impl FirstRound {
    fn of(held: &Downloaded) -> FirstRound {
        FirstRound {
            offers: offers(held),
            with_patches: held.patches.iter().any(Option::is_some),
            docs: Arc::clone(&held.info.docs),
            version: held.info.version.clone(),
        }
    }
}

/// The first round of a machine stage: opens the session, begins the stage with the verified
/// documents, uploads what `held` offers and commits. `Ok(None)` when `held` has patches and the
/// service speaks only version 1 (M12-D6): the connection is closed before `stage_begin`, so the
/// caller fetches the frames and calls again without patches.
async fn first_round(
    inner: &Arc<Inner>,
    lock: &OpLock,
    cancel: &CancelToken,
    sink: &ProgressSink,
    connector: &Arc<dyn lunepack_core::ServiceConnector>,
    plan: FirstRound,
) -> Result<Option<(StageSession, Round)>, Error> {
    let FirstRound {
        offers,
        with_patches,
        docs,
        version,
    } = plan;
    let channel = inner.channel.clone();
    let app_id = inner.app_id.clone();
    let progress_sink = sink.clone();
    let connector = Arc::clone(connector);
    on_job(
        inner,
        Some(lock),
        cancel,
        "service-stage",
        move |inner, cancel| {
            let session = machine::open_session(&*connector, &app_id)?;
            if with_patches && session.version() < lunepack_core::service::PROTOCOL_PATCH {
                return Ok(None);
            }
            let (mut stage, offered) = StageSession::begin(session, &channel, &docs)?;
            let Some(offered) = offered else {
                // The service sees no update where the check found one: it is stale.
                return Err(Error::Stale);
            };
            if offered != version {
                return Err(Error::Stale);
            }
            stage.upload(&*inner.fs, &offers, cancel)?;
            let rejected = drop_rejected(inner, &mut stage);
            let outcome = commit(&mut stage, &progress_sink)?;
            Ok(Some((stage, (outcome, rejected))))
        },
    )
    .await
}

/// Removes from the user's cache each object the service refused in `stage` as not matching the
/// manifest (F2): the entry is damaged, and kept it would be offered again on every stage. The
/// objects are returned so the caller stops offering them. A removal that fails leaves the entry;
/// the cache re-checks it before the next use.
fn drop_rejected(
    inner: &Inner,
    stage: &mut StageSession,
) -> Vec<(lunepack_core::service::ObjectKind, Sha256Digest)> {
    let rejected = stage.take_rejected();
    let cache = inner.cache();
    for (kind, sha) in &rejected {
        let kind = match kind {
            lunepack_core::service::ObjectKind::Frame => CacheKind::Frame,
            lunepack_core::service::ObjectKind::Pack => CacheKind::Pack,
            lunepack_core::service::ObjectKind::Patch => CacheKind::Patch,
        };
        let _ = cache.remove_entry(kind, sha);
    }
    rejected
}

/// `stage_commit` with the service's progress forwarded as the stage phase's.
fn commit(stage: &mut StageSession, sink: &ProgressSink) -> Result<CommitOutcome, Error> {
    let last = AtomicU64::new(0);
    stage.commit(&mut |done, total| {
        if total > 0 {
            sink.set_total(total);
        }
        let before = last.swap(done, Ordering::SeqCst);
        sink.add_done(done.saturating_sub(before));
    })
}

/// The publisher decision (M9-D9) for staging `candidate` over the install's current version
/// `current`. The policy is the installed tree's (M9-D6): no installed tree, or no update config
/// in it, is `off`, as is a config without the member; a config that is there but cannot be read,
/// or names another app, fails closed (the error, nothing marked). Unless the policy is `off`, the
/// candidate's own config is read for its entry (failing closed the same way, and when it has
/// none) and the check runs; its result goes through [`decide`].
fn publisher_decision(
    inner: &Inner,
    current: &Version,
    candidate: PathBuf,
) -> Result<Decision, Error> {
    let Some(installed_root) = inner.current_tree(Some(current))? else {
        return Ok(Decision::Proceed(None));
    };
    let Some(installed) = any_tree_config(&*inner.fs, &inner.app_id, &installed_root)? else {
        return Ok(Decision::Proceed(None));
    };
    let policy = installed.publisher_check;
    if policy == PublisherPolicy::Off {
        return Ok(Decision::Proceed(None));
    }
    let candidate_config =
        any_tree_config(&*inner.fs, &inner.app_id, &candidate)?.ok_or(Error::NoUpdateConfig)?;
    let result = inner.publisher.same_publisher(
        &SignedTree {
            root: installed_root,
            entry: installed.install.entry,
        },
        &SignedTree {
            root: candidate,
            entry: candidate_config.install.entry,
        },
    );
    Ok(decide(policy, result))
}

/// The update config of the tree at `tree` wherever a scheme puts it: the tree's root (Linux,
/// Windows), else a bundle's resources folder (macOS; FORMAT.md 13.1), so the answer does not
/// depend on how the updater's layout was given. `Ok(None)` when neither place holds one; one that
/// names another app is a refusal. The packager never writes both (13.1).
fn any_tree_config(
    fs: &dyn Fs,
    app_id: &AppId,
    tree: &Path,
) -> Result<Option<lunepack_core::UpdateConfig>, Error> {
    let mut found = None;
    for scheme in [LayoutScheme::XDG, LayoutScheme::MACOS] {
        let at = crate::installation::scheme_config_path(tree, scheme);
        found = crate::installation::read_config(fs, &at)?;
        if found.is_some() {
            break;
        }
    }
    match found {
        Some(config) if &config.app_id != app_id => Err(Error::UpdateConfig(
            UpdateConfigError::RootMismatch("app_id"),
        )),
        other => Ok(other),
    }
}

// ---- first install -------------------------------------------------------------------------------

/// The per-user layout of an install root made by [`Layout::user`]: the versions and state
/// directories of one root under a scheme this build knows ([`UserLayout::from_dirs`]).
fn install_root_of(
    state_dir: &Path,
    versions_dir: &Path,
    scheme: Option<LayoutScheme>,
) -> Result<UserLayout, Error> {
    match scheme {
        Some(scheme) => UserLayout::from_dirs_as(state_dir, versions_dir, scheme),
        None => UserLayout::from_dirs(state_dir, versions_dir),
    }
    .ok_or(Error::Config(
        "install needs the per-user layout of an install root",
    ))
}

/// The scheme a bundle install runs under.
fn scheme_of(inner: &Inner) -> Option<LayoutScheme> {
    inner.bundle.as_ref().map(|_| LayoutScheme::MACOS)
}

/// Before anything is written (M8-D4): the apps folder (or the nearest folder that exists above
/// it) is not read-only, is on the volume the install's versions will be on (the nearest existing
/// folder above `versions_dir`) and the user can create entries in it.
fn check_bundle_place(fs: &dyn Fs, setup: &BundleSetup, versions_dir: &Path) -> Result<(), Error> {
    let refuse = |reason| Error::UnsupportedLocation { reason };
    let apps = nearest(fs, &setup.apps_dir)?;
    let versions = nearest(fs, versions_dir)?;
    if apps.fs_type == lunepack_core::layout::TRANSLOCATION_FS_TYPE {
        return Err(refuse(LocationReason::Translocated));
    }
    if apps.read_only {
        return Err(refuse(LocationReason::ReadOnly));
    }
    if apps.device != versions.device {
        return Err(refuse(LocationReason::OtherVolume));
    }
    if !apps.writable {
        return Err(refuse(LocationReason::NotWritable));
    }
    Ok(())
}

/// [`Fs::place`] of `path`, or of the nearest folder above it that exists.
fn nearest(fs: &dyn Fs, path: &Path) -> Result<lunepack_core::PlaceFacts, Error> {
    let mut at = path.to_path_buf();
    loop {
        match fs.place(&at) {
            Ok(facts) => return Ok(facts),
            Err(e) if e.kind == lunepack_core::FsErrorKind::NotFound => {
                if !at.pop() {
                    return Err(Error::from(e));
                }
            }
            Err(e) => return Err(Error::from(e)),
        }
    }
}

/// The location rules of M8-D4 for a bundle to adopt, read only and in [`lunepack_core::check_place`]'s
/// order, before anything is written: neither `bundle` nor its folder translocated or read-only,
/// the folder on the volume the install's versions are on (the nearest existing folder above
/// `versions_dir`), `bundle` the caller's, and the folder writable by the caller.
fn check_adopt_place(fs: &dyn Fs, bundle: &Path, versions_dir: &Path) -> Result<(), Error> {
    let refuse = |reason| Error::UnsupportedLocation { reason };
    let folder = bundle
        .parent()
        .ok_or(Error::Config("a bundle to adopt has a folder"))?;
    let folder = fs.place(folder)?;
    let own = fs.place(bundle)?;
    for facts in [&folder, &own] {
        if facts.fs_type == lunepack_core::layout::TRANSLOCATION_FS_TYPE {
            return Err(refuse(LocationReason::Translocated));
        }
        if facts.read_only {
            return Err(refuse(LocationReason::ReadOnly));
        }
    }
    if nearest(fs, versions_dir)?.device != folder.device {
        return Err(refuse(LocationReason::OtherVolume));
    }
    if !own.owned_by_caller {
        // M8-D4: a root-owned `B` is a machine install (scope by ownership, D10).
        return Err(if own.owned_by_root {
            Error::MachineScope
        } else {
            refuse(LocationReason::NotOwned)
        });
    }
    if !folder.writable {
        return Err(refuse(LocationReason::NotWritable));
    }
    Ok(())
}

/// M7-D16 rule 3, first thing under the lock of a first install: `state_dir` holds no record of
/// another app id ([`Error::ForeignInstallRoot`]), so two apps with one display name cannot both
/// take a new folder.
fn refuse_foreign_record(inner: &Inner, state_dir: &Path) -> Result<(), Error> {
    lunepack_core::ensure_no_foreign_record(&*inner.fs, &*inner.hasher, state_dir, &inner.app_id)
        .map_err(|e| Error::from(lunepack_core::Error::Layout(e)))
}

/// What a first install that finds a current version returns (F15). `current` is first put
/// back from the record (idempotent, and never ahead of it), so a run cut off between the install
/// commit and the link, or whose reconcile failed, still ends with a startable install; a
/// reconcile that fails again is that error, so a retry can still fix it.
fn already_installed(fs: &dyn Fs, root: &UserLayout, record: &InstallState) -> Error {
    match root.reconcile(fs, record) {
        Ok(()) => Error::AlreadyInstalled,
        Err(e) => Error::from(lunepack_core::Error::Layout(e)),
    }
}

/// Removes the tombstones an uninstall cut off before its end left beside `root` (F18), when
/// `root` is `<parent>/<app id>` (the derivation of M5-D2; tombstones are named after the app id
/// only and never sit anywhere else), and, on macOS, the ones it left beside the live bundle
/// `bundle` (M8-D5: `B` is renamed to a tombstone in its own folder, which hides a whole app from
/// the user). Best effort: a tombstone is never the install root or `B`, so one that stays changes
/// nothing about the install and the next install or uninstall tries again.
fn clear_tombstones(inner: &Inner, layout: &UserLayout, bundle: Option<&Path>) {
    if let Some(folder) = bundle.and_then(Path::parent) {
        let _ = lunepack_core::remove_tombstones(&*inner.fs, folder, &inner.app_id);
    }
    let root = layout.root();
    let derived = match layout.scheme().root {
        RootNaming::AppId => root.file_name().is_some_and(|n| n == inner.app_id.as_str()),
        // A display-name root is found in the data home by its record (M7-D16); the tombstones
        // are named after the app id only, so the parent is the place to look.
        RootNaming::DisplayName => true,
    };
    if let Some(parent) = root.parent()
        && derived
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
fn adoptable(inner: &Inner, layout: &UserLayout) -> Result<(), Error> {
    let root = layout.root();
    let state_dir = layout.state_dir();
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
    // The state directory's names from `root` down (one under XDG, `.lunepack/state` under
    // Windows): each must be a real directory, and "only state" means each level holds nothing
    // but the next name.
    let mut only_state = true;
    let mut dir = root.to_path_buf();
    let mut listing = entries;
    for name in layout.scheme().state.split('/') {
        let has = listing
            .iter()
            .any(|e| e.name.as_os_str() == std::ffi::OsStr::new(name) && e.kind == FileKind::Dir);
        if !has {
            return Err(Error::ForeignInstallRoot);
        }
        only_state &= listing.len() == 1;
        dir.push(name);
        if dir != state_dir {
            listing = inner.fs.list_dir(&dir)?;
        }
    }
    // Another app's record is never taken over (M7-D16: two apps with one display name).
    refuse_foreign_record(inner, &state_dir)?;
    let store = UserScope {
        dir: state_dir.clone(),
        app_id: inner.app_id.clone(),
    };
    if store.load(&*inner.fs, &*inner.hasher)?.record.is_some() {
        return Ok(());
    }
    let only_ours = inner.fs.list_dir(&state_dir)?.iter().all(|e| {
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

/// The integration request for the first install of `config`'s tree at `root` (no outgoing
/// version).
fn integration_request(
    app_id: &AppId,
    root: &Path,
    config: &lunepack_core::UpdateConfig,
) -> IntegrationRequest {
    IntegrationRequest {
        app_id: app_id.clone(),
        install_root: root.to_path_buf(),
        version: config.version.clone(),
        meta: config.install.clone(),
        previous: None,
        stale_bins: Vec::new(),
    }
}

/// The update config of the tree at `tree`, which must name `app_id`.
fn tree_config(
    fs: &dyn Fs,
    app_id: &AppId,
    tree: &Path,
    scheme: LayoutScheme,
) -> Result<lunepack_core::UpdateConfig, Error> {
    let config = crate::installation::read_config(
        fs,
        &crate::installation::scheme_config_path(tree, scheme),
    )?
    .ok_or(Error::NoUpdateConfig)?;
    if &config.app_id != app_id {
        return Err(Error::UpdateConfig(UpdateConfigError::RootMismatch(
            "app_id",
        )));
    }
    Ok(config)
}

// ---- adoption (M8-D9) ----------------------------------------------------------------------------

/// What the install is when an adopting check takes the lock.
enum AdoptStart {
    /// No live install: adopt, from this snapshot (the record exists now).
    Adopt(Snapshot),
    /// The bundle is the install's already (an earlier check on this updater adopted it).
    Installed(Snapshot, CurrentRef),
}

/// Whether `R/bundle` names `bundle`, which exists (the install's live bundle).
fn names_bundle(fs: &dyn Fs, root: &UserLayout, bundle: &Path) -> bool {
    matches!(root.bundle_path(fs), Ok(Some(b)) if b.as_os_str() == bundle.as_os_str())
        && is_real_dir(fs, bundle).unwrap_or(false)
}

/// Whether an adoption of `bundle` may take over `record`, which names a current version: it is
/// orphaned (M8-D16), or `bundle` replaced the live bundle at its own path (M8-D16 amended). One
/// predicate for the start check and the commit re-check, as discovery uses at the pointer.
fn taken_over(fs: &dyn Fs, root: &UserLayout, record: &InstallState, bundle: &Path) -> bool {
    lunepack_core::bundle_orphaned(fs, root, record)
        || lunepack_core::bundle_replaced(fs, root, record, bundle)
}

/// The check of an updater whose running bundle is adoptable (M8-D9; see [`Updater::check`]).
///
/// Order: before the lock, the bundle's config (this app), its place (M8-D4), the integration
/// preflight and the install root's owner (as `install`); under the lock, the record is created
/// when missing, kept when it has no current version, is orphaned or is replaced, and a live
/// install is [`Error::NotInstalled`] before any request; the documents are verified from the record's
/// floors and the bundle's release is selected exactly; its manifest is verified and the floors
/// are raised; the bundle is proved equal to it ([`lunepack_core::verify_tree`]); then, after the
/// record is read again, the commit runs in the crash-safe order of M8-D9: `R/bundle.id`, the
/// integration, the record, `R/bundle`, and a reconcile that moves nothing. The lock is held from
/// the record to the end, so nothing else commits in between; the record is read again anyway.
async fn check_adopting(
    inner: Arc<Inner>,
    bundle: PathBuf,
    mut options: CheckOptions,
) -> Result<CheckOutcome, Error> {
    let cancel = options.cancel.clone().unwrap_or_default();
    let Layout::User {
        state_dir,
        versions_dir,
        ..
    } = &inner.layout
    else {
        return Err(Error::MachineScope);
    };
    let scheme = scheme_of(&inner).ok_or(Error::Config(
        "adoption needs the macOS bundle layout of an install root",
    ))?;
    let root = install_root_of(state_dir, versions_dir, Some(scheme))?;

    // Read only, before the first write (the lock): the bundle's own config, its place, the
    // integration preflight and the install root's owner.
    let (pre_root, pre_bundle) = (root.clone(), bundle.clone());
    let config = on_job(&inner, None, &cancel, "adopt-preflight", move |inner, _| {
        let config = tree_config(&*inner.fs, &inner.app_id, &pre_bundle, pre_root.scheme())?;
        check_adopt_place(&*inner.fs, &pre_bundle, &pre_root.versions_dir())?;
        let request = integration_request(&inner.app_id, &pre_bundle, &config);
        inner.integration.check(Scope::User, &request)?;
        clear_tombstones(inner, &pre_root, Some(&pre_bundle));
        adoptable(inner, &pre_root)?;
        Ok(config)
    })
    .await?;

    let lock = take_lock(&inner, &cancel).await?;
    let (start_root, start_bundle, target) = (root.clone(), bundle.clone(), config.target);
    let start = on_job(
        &inner,
        Some(&lock),
        &cancel,
        "adopt-state",
        move |inner, _| {
            let fs = &*inner.fs;
            refuse_foreign_record(inner, &start_root.state_dir())?;
            let store = UserScope {
                dir: start_root.state_dir(),
                app_id: inner.app_id.clone(),
            };
            let loaded = store.load(fs, &*inner.hasher)?;
            match &loaded.record {
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
                    store.commit(fs, &loaded, &record, &*inner.hasher)?;
                }
                Some(record) if record.current.is_none() => {}
                Some(record) => {
                    let taken_over = taken_over(fs, &start_root, record, &start_bundle);
                    if names_bundle(fs, &start_root, &start_bundle) && !taken_over {
                        let snap = inner.load()?;
                        let current = record.current.clone().ok_or(Error::NotInstalled)?;
                        return Ok(AdoptStart::Installed(snap, current));
                    }
                    // One install per app id per user: only an orphaned or replaced one is
                    // taken over.
                    if !taken_over {
                        return Err(Error::NotInstalled);
                    }
                }
            }
            let snap = inner.load()?;
            if snap.record().target != target {
                return Err(Error::NotInstalled);
            }
            Ok(AdoptStart::Adopt(snap))
        },
    )
    .await?;
    let snap = match start {
        AdoptStart::Installed(snap, current) => {
            let update = check_from(&inner, &lock, &cancel, snap, Some(current)).await?;
            return Ok(CheckOutcome {
                update,
                adopted: false,
            });
        }
        AdoptStart::Adopt(snap) => snap,
    };

    // The bundle's own release, verified as a check verifies (no floor time: nothing is current).
    let floors = snap.floors();
    let clock = ClockReading::read(&*inner.clock, None);
    let transport_arc = inner.transport.for_op(&lock);
    let transport = &*transport_arc;
    let Documents {
        root: trusted,
        keys,
        feed,
    } = verify_documents(&inner, transport, &floors, &clock)
        .await?
        .0;
    let version_text = config.version.to_string();
    let entry = feed
        .releases()
        .iter()
        .position(|r| r.version() == &config.version && r.version_text() == version_text)
        .and_then(|i| feed.target_entry(i, config.target))
        .ok_or(Error::NoRelease)?;
    let reference = entry.reference();
    let url = inner.urls.reference(reference)?;
    let bytes = fetch::fetch_document(transport, &url, reference.size()).await?;
    let manifest = verify_manifest(&keys, &entry, &bytes, &*inner.hasher, &*inner.verifier)?;
    let issued = manifest.issued();
    let raised = raised_floors(&trusted, &keys, &feed, &inner.channel);
    on_job(
        &inner,
        Some(&lock),
        &cancel,
        "state-commit",
        move |inner, _| inner.commit_floors(&snap, &raised),
    )
    .await?;

    // The proof: the bundle is exactly the signed release (phase `Adopt`).
    let (sink, mut pump) = progress(Phase::Adopt, 0);
    let mut callback = options.progress.take();
    let verify_bundle = bundle.clone();
    with_progress(
        &mut pump,
        &mut callback,
        on_job(
            &inner,
            Some(&lock),
            &cancel,
            "adopt-verify",
            move |inner, job| {
                let last = AtomicU64::new(0);
                lunepack_core::verify_tree(
                    &manifest,
                    &verify_bundle,
                    &*inner.fs,
                    &*inner.hasher,
                    job,
                    &|p| forward(&sink, &last, &p),
                )
                .map_err(|e| Error::from(lunepack_core::Error::from(e)))
            },
        ),
    )
    .await?;

    // The commit: id, integration, record, pointer, reconcile (M8-D9).
    let (commit_root, commit_bundle) = (root.clone(), bundle.clone());
    let version = config.version.clone();
    on_job(
        &inner,
        Some(&lock),
        &cancel,
        "adopt-commit",
        move |inner, _| {
            let fs = &*inner.fs;
            let layout_err = |e: LayoutError| Error::from(lunepack_core::Error::Layout(e));
            let store = UserScope {
                dir: commit_root.state_dir(),
                app_id: inner.app_id.clone(),
            };
            let loaded = store.load(fs, &*inner.hasher)?;
            let record = loaded.record.clone().ok_or(Error::NotInstalled)?;
            let orphaned = match &record.current {
                None => false,
                Some(_) if taken_over(fs, &commit_root, &record, &commit_bundle) => true,
                // Installed meanwhile: never overwritten.
                Some(_) => return Err(Error::NotInstalled),
            };
            if record.target != config.target {
                return Err(Error::NotInstalled);
            }
            // An install's layout holds `R/versions` (staging makes it on every other path), and
            // `check_place` and reconcile rely on it; adoption stages nothing, so it is made here,
            // durable before anything is committed.
            fs.create_dir_all(&commit_root.versions_dir())?;
            fs.sync_dir(commit_root.root())?;
            lunepack_core::write_bundle_identity(fs, &commit_root, &commit_bundle)
                .map_err(layout_err)?;
            let request = integration_request(&inner.app_id, &commit_bundle, &config);
            inner.integration.check(Scope::User, &request)?;
            inner.integration.apply(Scope::User, &request)?;
            let next = if orphaned {
                let mut install_id = [0u8; lunepack_core::policy::INSTALL_ID_BYTES];
                inner.rng.fill(&mut install_id)?;
                lunepack_core::reinstall_orphaned(&record, version, issued, install_id)?
            } else {
                lunepack_core::install_first(&record, version, issued, record.install_id)?
            };
            let committed = store.commit(fs, &loaded, &next, &*inner.hasher)?;
            lunepack_core::set_bundle_pointer(fs, &commit_root, &commit_bundle)
                .map_err(layout_err)?;
            commit_root.reconcile(fs, &committed).map_err(layout_err)?;
            Ok(())
        },
    )
    .await?;

    // Then the check of an installed bundle.
    let snap = on_job(&inner, Some(&lock), &cancel, "state-load", |inner, _| {
        inner.load()
    })
    .await?;
    let current = snap.record().current.clone().ok_or(Error::NotInstalled)?;
    let update = check_from(&inner, &lock, &cancel, snap, Some(current)).await?;
    Ok(CheckOutcome {
        update,
        adopted: true,
    })
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
    let root = install_root_of(state_dir, versions_dir, scheme_of(&inner))?;
    let bootstrap = current_tree.clone().ok_or(Error::Config(
        "install needs the bootstrap tree as the current tree",
    ))?;
    let cancel = options.cancel.clone().unwrap_or_default();

    // The bootstrap's config, the integration preflight and the root's owner, before the first
    // write to the install (the lock is the first); only an earlier uninstall's tombstones beside
    // the root are removed in between (F18).
    let boot_root = root.clone();
    let (target, boot_version, bundle) =
        on_job(&inner, None, &cancel, "bootstrap", move |inner, _| {
            let config = tree_config(&*inner.fs, &inner.app_id, &bootstrap, boot_root.scheme())?;
            // macOS (M8-D1, D4): the place is judged before anything is written, then the live
            // bundle's name is chosen (the apps folder is made private when it is missing).
            let bundle = match &inner.bundle {
                Some(setup) => {
                    let Layout::User { versions_dir, .. } = &inner.layout else {
                        return Err(Error::MachineScope);
                    };
                    check_bundle_place(&*inner.fs, setup, versions_dir)?;
                    Some(
                        lunepack_core::resolve_bundle_target(
                            &*inner.fs,
                            &setup.apps_dir,
                            &config.install.name,
                            &inner.app_id,
                        )
                        .map_err(|e| Error::from(lunepack_core::Error::Layout(e)))?,
                    )
                }
                None => None,
            };
            let request = integration_request(
                &inner.app_id,
                bundle.as_deref().unwrap_or_else(|| boot_root.root()),
                &config,
            );
            inner.integration.check(Scope::User, &request)?;
            clear_tombstones(inner, &boot_root, bundle.as_deref());
            adoptable(inner, &boot_root)?;
            Ok((config.target, config.version, bundle))
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
                refuse_foreign_record(inner, state_dir)?;
                let store = UserScope {
                    dir: state_dir.clone(),
                    app_id: inner.app_id.clone(),
                };
                let loaded = store.load(&*inner.fs, &*inner.hasher)?;
                match &loaded.record {
                    Some(record) if record.current.is_some() => {
                        // macOS (M8-D16): the bundle was removed by the user, so the record
                        // names a current version no tree holds. That is a fresh install that
                        // keeps the floors: the record is reset to them (new install id) and
                        // the install goes on as from a cut-off run.
                        if inner.bundle.is_some()
                            && matches!(
                                state_root.reconcile(&*inner.fs, record),
                                Err(LayoutError::Orphaned)
                            )
                        {
                            let mut install_id = [0u8; lunepack_core::policy::INSTALL_ID_BYTES];
                            inner.rng.fill(&mut install_id)?;
                            let reset = lunepack_core::reset_orphaned(record, install_id)?;
                            store.commit(&*inner.fs, &loaded, &reset, &*inner.hasher)?;
                            return Ok(());
                        }
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
            let config = tree_config(&*inner.fs, &inner.app_id, &tree, root.scheme())?;
            if !crate::installation::same_version(&config.version, &version) {
                return Err(Error::UpdateConfig(UpdateConfigError::Invalid {
                    field: "version",
                    rule: "is not the version of its directory",
                }));
            }
            let request = integration_request(
                &inner.app_id,
                bundle.as_deref().unwrap_or_else(|| root.root()),
                &config,
            );
            inner.integration.check(Scope::User, &request)?;
            let next =
                lunepack_core::install_first(&record, version.clone(), issued, record.install_id)?;
            // macOS: `R/bundle` names the live bundle before the record does (M8-D1); the
            // reconcile after the commit places the staged tree in it and writes its identity.
            if let Some(bundle) = &bundle {
                lunepack_core::set_bundle_pointer(&*inner.fs, &root, bundle)
                    .map_err(|e| Error::from(lunepack_core::Error::Layout(e)))?;
            }
            // The integration goes in before the commit (F11, Q42): once the record names a
            // current version a rerun is `AlreadyInstalled`, so nothing that can fail may be left
            // for after it. Its entries point through `R/current`, which the reconcile below makes
            // valid; when the commit fails they dangle until a rerun, which applies them again.
            // When the reconcile fails, or the run ends before it, a rerun links `current` from
            // the committed record before it reports `AlreadyInstalled` (F15).
            inner.integration.apply(Scope::User, &request)?;
            let committed = store.commit(&*inner.fs, &loaded, &next, &*inner.hasher)?;
            root.reconcile(&*inner.fs, &committed)
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
    /// The update config read from the pack.
    config: lunepack_core::UpdateConfig,
}

/// Step 2 of [`Updater::install_from_payload`]: reads only.
fn verify_payload(
    inner: &Inner,
    payload: &OfflinePayload,
    root: &TrustedRoot,
    install_root: &Path,
) -> Result<VerifiedPayload, Error> {
    // A bundle install (macOS) has its integration checked against the live bundle once that is
    // chosen ([`install_from_payload`] step 3); it is not known yet.
    let (hasher, verifier) = (&*inner.hasher, &*inner.verifier);
    let file = &*payload.file;
    // A first install: no floor time (the clock is plausible) and no stored floors (P6).
    let clock = ClockReading::read(&*inner.clock, None);
    let keys_bytes = read_part(file, payload.keys, "keys", Limits::V1.keys_doc_bytes)?;
    let keys = verify_first_install_keys(root, &keys_bytes, &clock, hasher, verifier)?;
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

    // FORMAT.md 13.6: the config before staging, so a foreign root writes nothing. Its place in
    // the tree is the target's (`Contents/Resources/lunepack-update.json` in a macOS bundle).
    let config_path = RelPath::parse(lunepack_core::update_config::config_path(payload.target))
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
    if inner.bundle.is_none() {
        let request = integration_request(&inner.app_id, install_root, &config);
        inner.integration.check(Scope::User, &request)?;
    }

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
        config,
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
    root: &UserLayout,
) -> Result<(), Error> {
    let root = root.clone();
    on_job(inner, Some(lock), cancel, "state-check", move |inner, _| {
        let Layout::User { state_dir, .. } = &inner.layout else {
            return Err(Error::MachineScope);
        };
        refuse_foreign_record(inner, state_dir)?;
        let store = UserScope {
            dir: state_dir.clone(),
            app_id: inner.app_id.clone(),
        };
        match store.load(&*inner.fs, &*inner.hasher)?.record {
            // macOS (M8-D16): a record whose current version no tree holds (the bundle went to
            // the Trash) is installed anew, as `install` does; the record is reset under the lock
            // in step 3.
            Some(record) if record.current.is_some() && orphaned_bundle(inner, &root, &record) => {
                Ok(())
            }
            Some(record) if record.current.is_some() => Err(rerun_installed(inner, &root, &record)),
            _ => Ok(()),
        }
    })
    .await
}

/// Whether `record`, which names a current version, is a macOS bundle install the user removed
/// (M8-D16: [`LayoutError::Orphaned`] from the reconcile, which never moves anything into a
/// missing bundle): the first install then installs anew, keeping the floors.
fn orphaned_bundle(inner: &Inner, root: &UserLayout, record: &InstallState) -> bool {
    inner.bundle.is_some()
        && matches!(
            root.reconcile(&*inner.fs, record),
            Err(LayoutError::Orphaned)
        )
}

/// What a Setup rerun on an installed app returns (M7-D8: a setup rerun is an integration apply).
/// [`already_installed`] first, then the integration of the *installed* current version is
/// applied again under the same lock (the stub at `R`, the shortcut, the uninstall entry and the
/// declarations), so a run cut off between the two renames of a stub self-replace, or an entry
/// the user deleted, is repaired by running Setup again. The payload's own config is not used:
/// the rerun changes nothing about which version is installed. It still ends as
/// [`Error::AlreadyInstalled`]; a failure of the repair is that error, so another rerun can try
/// again. An entry that is not lunepack's is left alone ([`IntegrationError::Conflict`]): nothing
/// was asked of the rerun beyond the repair, so that leaves the answer as it was.
fn rerun_installed(inner: &Inner, root: &UserLayout, record: &InstallState) -> Error {
    let outcome = already_installed(&*inner.fs, root, record);
    if !matches!(outcome, Error::AlreadyInstalled) {
        return outcome;
    }
    let Some(current) = record.current.as_ref() else {
        return outcome;
    };
    // macOS: the live tree is the bundle `R/bundle` names, and the integration points at it.
    let bundle = match inner.bundle {
        Some(_) => match root.bundle_path(&*inner.fs) {
            Ok(Some(bundle)) => Some(bundle),
            Ok(None) => return outcome,
            Err(e) => return Error::from(lunepack_core::Error::Layout(e)),
        },
        None => None,
    };
    let tree = bundle
        .clone()
        .unwrap_or_else(|| root.version_dir(&current.version));
    let repaired =
        tree_config(&*inner.fs, &inner.app_id, &tree, root.scheme()).and_then(|config| {
            let request = integration_request(
                &inner.app_id,
                bundle.as_deref().unwrap_or_else(|| root.root()),
                &config,
            );
            match inner.integration.apply(Scope::User, &request) {
                Ok(_) | Err(IntegrationError::Conflict(_)) => Ok(()),
                Err(e) => Err(Error::from(e)),
            }
        });
    match repaired {
        Ok(()) => outcome,
        Err(e) => e,
    }
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
    let install_root = install_root_of(&state_dir, &versions_dir, scheme_of(&inner))?;
    if root.app_id() != &inner.app_id {
        return Err(Error::Verify(lunepack_core::Error::AppIdMismatch));
    }
    let cancel = options.cancel.clone().unwrap_or_default();
    // macOS (M8-D4): the apps folder's place is judged before anything is written, the lock
    // included; the installer's own place (a read-only disk image, a translocated copy) is not.
    if let Some(setup) = &inner.bundle {
        check_bundle_place(&*inner.fs, setup, &versions_dir)?;
    }
    let (sink, mut pump) = progress(Phase::Install, 0);
    let mut callback = options.progress.take();
    with_progress(&mut pump, &mut callback, async {
        // 1. An installed record is `AlreadyInstalled` before anything else (an orphaned bundle
        //    install is not installed, M8-D16).
        {
            let lock = take_lock(&inner, &cancel).await?;
            refuse_installed(&inner, &lock, &cancel, &install_root).await?;
        }

        // 2. Verification; nothing is written.
        let check_root = root.clone();
        let check_install_root = install_root.root().to_path_buf();
        let verified = on_job(&inner, None, &cancel, "payload-verify", move |inner, _| {
            verify_payload(inner, &payload, &check_root, &check_install_root)
        })
        .await?;
        let manifest = Arc::clone(&verified.manifest);
        let version = manifest.version().clone();
        let target = manifest.target();

        // 3. The install root, then the record, as `install`. macOS (M8-D1): the live bundle's
        //    name is chosen (the apps folder is made private when missing) and the integration's
        //    preflight runs against it.
        let boot_root = install_root.clone();
        let boot_config = verified.config.clone();
        let bundle = on_job(&inner, None, &cancel, "bootstrap", move |inner, _| {
            let bundle = match &inner.bundle {
                Some(setup) => {
                    let bundle = lunepack_core::resolve_bundle_target(
                        &*inner.fs,
                        &setup.apps_dir,
                        &boot_config.install.name,
                        &inner.app_id,
                    )
                    .map_err(|e| Error::from(lunepack_core::Error::Layout(e)))?;
                    let request = integration_request(&inner.app_id, &bundle, &boot_config);
                    inner.integration.check(Scope::User, &request)?;
                    Some(bundle)
                }
                None => None,
            };
            clear_tombstones(inner, &boot_root, bundle.as_deref());
            adoptable(inner, &boot_root)?;
            Ok(bundle)
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
                refuse_foreign_record(inner, &state_dir)?;
                let store = UserScope {
                    dir: state_dir.clone(),
                    app_id: inner.app_id.clone(),
                };
                let loaded = store.load(&*inner.fs, &*inner.hasher)?;
                match &loaded.record {
                    // M8-D16: reset to its floors (a new install id), then installed as from a
                    // cut-off run, as `install` does.
                    Some(record)
                        if record.current.is_some()
                            && orphaned_bundle(inner, &state_root, record) =>
                    {
                        let mut install_id = [0u8; lunepack_core::policy::INSTALL_ID_BYTES];
                        inner.rng.fill(&mut install_id)?;
                        let reset = lunepack_core::reset_orphaned(record, install_id)?;
                        store.commit(&*inner.fs, &loaded, &reset, &*inner.hasher)?;
                    }
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
                cache.cleanup(&[(CacheKind::Frame, &keep)])?;
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
                        CacheKind::Frame,
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
            Err(StageError::Other(e)) => return Err(e.into()),
            Err(_) => return Err(Error::Config("stage failed")),
        };

        // The staged tree's own config, again exactly the payload's root; else the tree goes.
        let tree = staged.tree.clone();
        let tree_root = root.clone();
        let tree_version = version.clone();
        let tree_scheme = install_root.scheme();
        on_job(
            &inner,
            Some(&lock),
            &cancel,
            "payload-root",
            move |inner, _| {
                let at = crate::installation::scheme_config_path(&tree, tree_scheme);
                let checked = crate::installation::read_config(&*inner.fs, &at)
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
                let config = tree_config(&*inner.fs, &inner.app_id, &tree, install_root.scheme())?;
                let request = integration_request(
                    &inner.app_id,
                    bundle.as_deref().unwrap_or_else(|| install_root.root()),
                    &config,
                );
                inner.integration.check(Scope::User, &request)?;
                let next = lunepack_core::install_first(
                    &record.raise_floors(&floors),
                    version.clone(),
                    issued,
                    record.install_id,
                )?;
                // macOS: `R/bundle` names the live bundle before the record does (M8-D1); the
                // reconcile after the commit places the staged tree in it and writes its identity.
                if let Some(bundle) = &bundle {
                    lunepack_core::set_bundle_pointer(&*inner.fs, &install_root, bundle)
                        .map_err(|e| Error::from(lunepack_core::Error::Layout(e)))?;
                }
                // As `install` (F11, Q42): the integration before the commit.
                inner.integration.apply(Scope::User, &request)?;
                let committed = store.commit(&*inner.fs, &loaded, &next, &*inner.hasher)?;
                install_root
                    .reconcile(&*inner.fs, &committed)
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
