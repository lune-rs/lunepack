//! Per-machine installs in the facade (M10 step 17, M10-D14, D16, C8).
//!
//! An app is a machine install when its running tree is `X\app\<version>` with `X` directly in the
//! machine home and the newest record in `X\.lunepack\state` of scope `machine` for this app
//! ([`detect`]); never by an argument, an environment variable or a registry value. Everything the
//! library does for one is either a read (the machine record, the tree) or a request to the
//! install's update service over the core's protocol client ([`lunepack_core::ClientSession`]):
//! no code here, or in the updater's machine paths, writes under `R`, to the machine record or to
//! the registry. What the library keeps for the user is in this user's home
//! (`<local data>/lunepack/<app id>`: `state` with the counters record and the lock, `cache`,
//! `logs`).
//!
//! The service is never started with elevation and never asked to do what the library could do
//! itself: `check` and `download` run as the user ([`crate::Updater`]); `stage` uploads the
//! documents the check verified and the objects the download holds, and the service verifies them
//! again; `apply` is the runtime's call; `startup` and `confirm` use `attempt` and `confirm`.

use std::collections::HashSet;
use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use lunepack_core::service::{
    AttemptAnswer, ClientSession, ClientTimeouts, CommitOutcome, ConfirmAnswer, DocumentKind,
    Duplex, ObjectKind, OutgoingDocument, StageBegun, Token,
};
use lunepack_core::state::{InstallCounters, InstallState, MachineScope};
use lunepack_core::{
    AppId, CancelToken, Channel, ChildStdio, ConfirmOutcome, ConnectError, FileKind, Fs,
    LifecycleEvent, MachineLayout, ReadAt, ServiceConnector, ServiceError, Sha256Digest, SpawnSpec,
    UpdateConfig, Version,
};

use crate::Error;
#[cfg(not(windows))]
use lunepack_core::{MachinePolicy, PolicySource};

use crate::error::ServiceReason;
use crate::installation::{HEALTH_TOKEN_VAR, Installation, Platform, lock_state, same_version};
use crate::lifecycle::{Startup, StartupAction, Token as EnvToken, read_token};
use crate::updater::Layout;

/// How long the service may take to say hello.
const HELLO_WAIT: Duration = Duration::from_secs(10);
/// How long the service may take to answer one request, or to send the next `progress`.
const ANSWER_WAIT: Duration = Duration::from_secs(60);
/// The default time the start of an app waits for its attempt: the app starts anyway after it.
pub(crate) const STARTUP_WAIT: Duration = Duration::from_secs(10);

/// The client's deadlines.
const TIMEOUTS: ClientTimeouts = ClientTimeouts {
    hello: Some(HELLO_WAIT),
    answer: Some(ANSWER_WAIT),
};

// ---- the install and where it is -------------------------------------------------------------

/// A per-machine install found for the running tree.
#[derive(Debug, Clone)]
pub(crate) struct MachineInstall {
    layout: MachineLayout,
    user_home: PathBuf,
}

impl MachineInstall {
    pub(crate) fn layout(&self) -> &MachineLayout {
        &self.layout
    }

    pub(crate) fn user_home(&self) -> &Path {
        &self.user_home
    }

    /// This user's state directory: counters records and the lock.
    pub(crate) fn user_state_dir(&self) -> PathBuf {
        self.user_home.join("state")
    }

    /// The updater's layout of the install: the machine state and trees read-only, this user's
    /// state and cache.
    pub(crate) fn updater_layout(&self) -> Layout {
        Layout::Machine {
            machine_state_dir: self.layout.state_dir(),
            user_state_dir: self.user_state_dir(),
            cache_dir: self.user_home.join("cache"),
            versions_dir: Some(self.layout.app_dir()),
            current_tree: None,
        }
    }

    /// The state store of the install for `app_id`.
    pub(crate) fn scope(&self, app_id: &AppId) -> MachineScope {
        MachineScope {
            machine_dir: self.layout.state_dir(),
            user_dir: self.user_state_dir(),
            app_id: app_id.clone(),
        }
    }
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

/// The machine install the tree under `root` is a version of, if it is one (M10-D14): `root` is
/// directly in the platform's machine home, and the newest record in its state directory is a
/// machine record of this app. A machine record anywhere else is not a machine install; a user
/// record here is not either (it resolves as before).
pub(crate) fn detect(
    platform: &Platform,
    root: &Path,
    config: &UpdateConfig,
) -> Result<Option<MachineInstall>, Error> {
    let Some(home) = platform.machine_home() else {
        return Ok(None);
    };
    if !root.parent().is_some_and(|parent| same_dir(parent, &home)) {
        return Ok(None);
    }
    let layout = MachineLayout::new(root);
    let scope = MachineScope {
        machine_dir: layout.state_dir(),
        user_dir: PathBuf::new(),
        app_id: config.app_id.clone(),
    };
    match scope.load_machine(&*platform.fs, &*platform.hasher) {
        Ok(loaded) if loaded.record.is_some() => {}
        _ => return Ok(None),
    }
    let user_home = platform.user_home(&config.app_id)?;
    Ok(Some(MachineInstall { layout, user_home }))
}

/// Stand-in connector of a system with no update service: there is none to start.
#[cfg(not(windows))]
pub(crate) struct NoService;

#[cfg(not(windows))]
impl ServiceConnector for NoService {
    fn connect(&self, _: &AppId) -> Result<Box<dyn Duplex>, ConnectError> {
        Err(ConnectError::NotInstalled)
    }
}

/// Stand-in policy source of a system with no policy: nothing is disabled.
#[cfg(not(windows))]
pub(crate) struct NoPolicy;

#[cfg(not(windows))]
impl PolicySource for NoPolicy {
    fn read(&self, _: &AppId) -> MachinePolicy {
        MachinePolicy::default()
    }
}

// ---- errors ----------------------------------------------------------------------------------

/// What a connection failure is to the app.
pub fn connect_error(e: ConnectError) -> Error {
    let unavailable = |reason| Error::ServiceUnavailable { reason };
    match e {
        ConnectError::NotInstalled => unavailable(ServiceReason::NotInstalled),
        ConnectError::Disabled => unavailable(ServiceReason::Disabled),
        ConnectError::Busy => Error::Busy,
        ConnectError::WrongOwner => unavailable(ServiceReason::Untrusted),
        // Anything else (a start that failed, a pipe that never came).
        _ => unavailable(ServiceReason::StartFailed),
    }
}

/// What a failed exchange with the service is to the app. Carries no value from the wire.
pub fn service_error(e: ServiceError) -> Error {
    use lunepack_core::service::ErrorCode as Code;
    let unavailable = |reason| Error::ServiceUnavailable { reason };
    match e {
        ServiceError::Unsupported { .. } => Error::ServiceUnsupported,
        ServiceError::Timeout => unavailable(ServiceReason::Timeout),
        ServiceError::Answered { code, class } => match code {
            Code::Busy => Error::Busy,
            Code::DisabledByPolicy => Error::DisabledByPolicy,
            Code::NothingStaged => Error::NothingStaged,
            Code::VersionMismatch => Error::UnexpectedVersion,
            Code::TokenMismatch => Error::TokenMismatch,
            Code::Timeout => unavailable(ServiceReason::Timeout),
            other => Error::ServiceRefused { code: other, class },
        },
        ServiceError::Io(io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => {
            unavailable(ServiceReason::Timeout)
        }
        // A closed or broken channel, a protocol break, a refused encoding.
        _ => unavailable(ServiceReason::Protocol),
    }
}

/// A session with the service of `app_id`.
pub(crate) type Session = ClientSession<Box<dyn Duplex>>;

/// Connects and says hello. Never elevates and never prompts.
pub(crate) fn open_session(
    connector: &dyn ServiceConnector,
    app_id: &AppId,
) -> Result<Session, Error> {
    let io = connector.connect(app_id).map_err(connect_error)?;
    ClientSession::connect(io, app_id.clone(), TIMEOUTS).map_err(service_error)
}

// ---- stage ------------------------------------------------------------------------------------

/// The documents a check verified, as it read them: what `stage` sends the service so the service
/// verifies the same bytes again (M10-D2).
#[derive(Debug, Clone, Default)]
pub(crate) struct SignedDocs {
    /// The rotation documents the walk used, in the order it took them.
    pub roots: Vec<Vec<u8>>,
    /// The key set.
    pub keys: Vec<u8>,
    /// The channel's feed.
    pub feed: Vec<u8>,
    /// The candidate's manifest.
    pub manifest: Vec<u8>,
}

/// One object the library holds for the manifest: a file on disk and what the manifest says of it.
#[derive(Debug, Clone)]
pub(crate) struct Offer {
    pub kind: ObjectKind,
    pub sha256: Sha256Digest,
    pub size: u64,
    pub path: PathBuf,
}

/// A stage session in progress: the connection and the objects already accepted (each is accepted
/// once).
pub(crate) struct StageSession {
    session: Session,
    sent: HashSet<Sha256Digest>,
}

impl StageSession {
    /// `stage_begin` with `docs`: `Ok(None)` when the service offers this machine no update.
    pub(crate) fn begin(
        mut session: Session,
        channel: &Channel,
        docs: &SignedDocs,
    ) -> Result<(StageSession, Option<Version>), Error> {
        let mut out: Vec<OutgoingDocument<'_>> = docs
            .roots
            .iter()
            .map(|bytes| OutgoingDocument {
                kind: DocumentKind::Root,
                bytes,
            })
            .collect();
        for (kind, bytes) in [
            (DocumentKind::Keys, &docs.keys),
            (DocumentKind::Feed, &docs.feed),
            (DocumentKind::Manifest, &docs.manifest),
        ] {
            out.push(OutgoingDocument { kind, bytes });
        }
        let begun = session.stage_begin(channel, &out).map_err(service_error)?;
        let version = match begun {
            StageBegun::Ready(v) => Some(v),
            StageBegun::NoUpdate => None,
        };
        Ok((
            StageSession {
                session,
                sent: HashSet::new(),
            },
            version,
        ))
    }

    /// Uploads each of `offers` the session has not taken yet, reading the files through `fs`; a
    /// cancelled `cancel` stops between reads, which ends the session.
    pub(crate) fn upload(
        &mut self,
        fs: &dyn Fs,
        offers: &[Offer],
        cancel: &CancelToken,
    ) -> Result<(), Error> {
        for offer in offers {
            if self.sent.contains(&offer.sha256) {
                continue;
            }
            let file = fs.open_read(&offer.path)?;
            let mut reader = FileReader {
                file,
                at: 0,
                size: offer.size,
                cancel: cancel.clone(),
                failure: None,
            };
            let result = self
                .session
                .put(offer.kind, offer.sha256, offer.size, &mut reader);
            match result {
                Ok(()) => {
                    self.sent.insert(offer.sha256);
                }
                Err(e) => {
                    // The read that failed says why better than the session does.
                    return Err(reader.failure.take().unwrap_or_else(|| service_error(e)));
                }
            }
        }
        Ok(())
    }

    /// `stage_commit`, forwarding the service's progress.
    pub(crate) fn commit(
        &mut self,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<CommitOutcome, Error> {
        self.session.stage_commit(progress).map_err(service_error)
    }
}

/// A file read as a stream of exactly `size` bytes, checking `cancel` before each read.
struct FileReader {
    file: Box<dyn ReadAt>,
    at: u64,
    size: u64,
    cancel: CancelToken,
    failure: Option<Error>,
}

impl Read for FileReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            self.failure = Some(Error::Cancelled);
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let left = self.size - self.at;
        let n = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
        if n == 0 {
            return Ok(0);
        }
        match self.file.read_exact_at(self.at, &mut buf[..n]) {
            Ok(()) => {
                self.at += n as u64;
                Ok(n)
            }
            Err(e) => {
                self.failure = Some(Error::Fs(e));
                Err(io::Error::from(io::ErrorKind::UnexpectedEof))
            }
        }
    }
}

// ---- startup, confirm, apply -----------------------------------------------------------------

/// The token an `attempt` issued to this process: kept for the `confirm` that follows.
#[derive(Clone)]
pub(crate) struct Kept {
    app_id: AppId,
    version: Version,
    token: Token,
}

impl std::fmt::Debug for Kept {
    /// Shows nothing of the token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kept").finish_non_exhaustive()
    }
}

/// The token kept for `inst`'s own version, if one was.
fn kept_for(inst: &Installation) -> Option<Token> {
    let guard = inst.platform.kept.lock().ok()?;
    guard
        .as_ref()
        .filter(|k| &k.app_id == inst.app_id() && same_version(&k.version, inst.tree_version()))
        .map(|k| k.token.clone())
}

fn keep(inst: &Installation, token: Token) {
    if let Ok(mut guard) = inst.platform.kept.lock() {
        *guard = Some(Kept {
            app_id: inst.app_id().clone(),
            version: inst.tree_version().clone(),
            token,
        });
    }
}

/// The token a process-wide convenience call ([`crate::startup`]) hands on to the next one
/// ([`crate::confirm_healthy`]), which builds its own installation.
static PROCESS_TOKEN: std::sync::Mutex<Option<Kept>> = std::sync::Mutex::new(None);

/// Moves the token `inst` kept into the process-wide slot.
pub(crate) fn export_kept(inst: &Installation) {
    let kept = inst.platform.kept.lock().ok().and_then(|g| g.clone());
    if let (Some(kept), Ok(mut slot)) = (kept, PROCESS_TOKEN.lock()) {
        *slot = Some(kept);
    }
}

/// Moves the process-wide token into `inst`.
pub(crate) fn import_kept(inst: &Installation) {
    let kept = PROCESS_TOKEN.lock().ok().and_then(|g| g.clone());
    if let (Some(kept), Ok(mut mine)) = (kept, inst.platform.kept.lock()) {
        *mine = Some(kept);
    }
}

fn is_pending(record: &InstallState, own: &Version) -> bool {
    record
        .pending
        .as_ref()
        .is_some_and(|p| same_version(&p.version, own))
}

/// Runs `f` on a helper thread and waits at most `wait` for its answer; `None` when it did not
/// come in time (the thread finishes on its own, its answer dropped).
fn within<T: Send + 'static>(wait: Duration, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("lunepack-service-wait".into())
        .spawn(move || {
            let _ = tx.send(f());
        })
        .ok()?;
    rx.recv_timeout(wait).ok()
}

/// What an `attempt` at start decided.
enum Attempted {
    /// Counted: this process holds the token.
    Counted(Token),
    /// A supervisor is running, or the version is no longer pending.
    Nothing,
    /// The version was rolled back.
    RolledBack,
}

fn attempt(inst: &Installation, own: &Version) -> Result<Attempted, Error> {
    let connector = inst.platform.service_connector();
    let mut session = open_session(&*connector, inst.app_id())?;
    Ok(match session.attempt(own).map_err(service_error)? {
        AttemptAnswer::Counted { token, .. } => Attempted::Counted(token),
        AttemptAnswer::Supervised | AttemptAnswer::NotPending => Attempted::Nothing,
        AttemptAnswer::RolledBack { .. } => Attempted::RolledBack,
    })
}

/// The start of a per-machine install's version (M10-D3, M10-D16). The machine record is read, not
/// locked: when this version is pending and the process holds no well-formed token, the service's
/// `attempt` decides (a service that cannot be reached in [`Platform::with_service_wait`] never stops the app from
/// starting); then the events of this user's `last_run` are delivered, once.
pub(crate) fn startup(
    inst: &Installation,
    machine: &MachineInstall,
    args: Vec<OsString>,
) -> Result<Startup, Error> {
    let p = &inst.platform;
    let own = inst.tree_version();
    let scope = machine.scope(inst.app_id());
    let loaded = scope.load_machine(&*p.fs, &*p.hasher)?;
    let Some(record) = loaded.record else {
        return Ok(Startup::go_on(Vec::new(), false));
    };
    if record.current.is_none() {
        return Ok(Startup::go_on(Vec::new(), false));
    }
    let mut pending = is_pending(&record, own);
    let has_token = matches!(read_token(p.health_token.as_ref()), EnvToken::WellFormed(_))
        || kept_for(inst).is_some();
    if pending && !has_token {
        let (probe, own_version) = (inst.clone(), own.clone());
        match within(p.service_wait, move || attempt(&probe, &own_version)) {
            Some(Ok(Attempted::Counted(token))) => keep(inst, token),
            Some(Ok(Attempted::Nothing)) => {}
            Some(Ok(Attempted::RolledBack)) => {
                relaunch_stub(inst, machine, args);
                return Ok(Startup {
                    events: Vec::new(),
                    action: StartupAction::Exit,
                    pending: false,
                });
            }
            // The service cannot be reached (or did not answer in time): the app starts, still
            // waiting for its health check.
            Some(Err(_)) | None => {}
        }
        // `attempt` said the version is no longer pending: no check to wait for.
        pending = is_pending(
            &scope
                .load_machine(&*p.fs, &*p.hasher)?
                .record
                .unwrap_or(record.clone()),
            own,
        );
    }
    let events = deliver_events(inst, machine, &scope, &record, own)?;
    Ok(Startup::go_on(events, pending))
}

/// Starts the install's launcher stub (`R\<entry name>`) detached, with the arguments of the start
/// that rolled back and no health token. A failure is ignored: the rollback is committed.
fn relaunch_stub(inst: &Installation, machine: &MachineInstall, args: Vec<OsString>) {
    let Some(name) = inst.meta().entry.as_str().rsplit('/').next() else {
        return;
    };
    let _ = inst.platform.process.spawn_detached(&SpawnSpec {
        program: machine.layout().root().join(name),
        args,
        env_set: Vec::new(),
        env_remove: vec![OsString::from(HEALTH_TOKEN_VAR)],
        stdio: ChildStdio::Null,
    });
}

/// The events this user has not had for `own` (M10-D16), derived from `last_run` in this user's
/// counters and delivered at most once: the counters are committed before they are returned.
///
/// No `last_run` is a first run; a lower one is an update and a first run; an equal or higher one
/// (after a rollback) is nothing. `installed` is never delivered. `last_run` becomes `own`.
fn deliver_events(
    inst: &Installation,
    machine: &MachineInstall,
    scope: &MachineScope,
    record: &InstallState,
    own: &Version,
) -> Result<Vec<LifecycleEvent>, Error> {
    let p = &inst.platform;
    let guard = lock_state(p, &machine.user_state_dir())?;
    let counters = scope.load_counters(&*p.fs, record, &*p.hasher)?;
    let last = counters.record.as_ref().and_then(|c| c.last_run.clone());
    if last.as_ref().is_some_and(|l| same_version(l, own)) {
        return Ok(Vec::new());
    }
    let events = match &last {
        None => vec![LifecycleEvent::FirstRun {
            version: own.clone(),
        }],
        Some(from) if from < own => vec![
            LifecycleEvent::Updated {
                from: from.clone(),
                to: own.clone(),
            },
            LifecycleEvent::FirstRun {
                version: own.clone(),
            },
        ],
        Some(_) => Vec::new(),
    };
    let mut next = counters.record.clone().unwrap_or_else(|| {
        InstallCounters::new(counters.next_seq, inst.app_id().clone(), record.install_id)
    });
    next.last_run = Some(own.clone());
    scope.commit_counters(&*p.fs, record, &counters, &next, &*p.hasher)?;
    drop(guard);
    Ok(events)
}

/// `confirm_healthy` of a per-machine install (M10-D3): with the token of the supervised start
/// (environment) or the one an `attempt` issued (kept), the service's `confirm`; with none, or when
/// it is refused as another's, one `attempt`, and its token confirms. A supervisor that is running,
/// or a version that is not pending, is nothing to do.
pub(crate) fn confirm(
    inst: &Installation,
    machine: &MachineInstall,
) -> Result<ConfirmOutcome, Error> {
    let p = &inst.platform;
    let own = inst.tree_version();
    let env = match read_token(p.health_token.as_ref()) {
        EnvToken::Absent => None,
        EnvToken::WellFormed(raw) => Some(Token::from_bytes(raw)),
        EnvToken::Malformed => return Err(Error::TokenMismatch),
    };
    let scope = machine.scope(inst.app_id());
    let Some(record) = scope.load_machine(&*p.fs, &*p.hasher)?.record else {
        return Ok(ConfirmOutcome::NothingPending);
    };
    if !is_pending(&record, own) {
        return Ok(ConfirmOutcome::NothingPending);
    }
    let connector = p.service_connector();
    let mut session = open_session(&*connector, inst.app_id())?;
    let confirmed = |answer: ConfirmAnswer| match answer {
        ConfirmAnswer::Confirmed => ConfirmOutcome::Confirmed,
        _ => ConfirmOutcome::NothingPending,
    };
    if let Some(token) = env.or_else(|| kept_for(inst)) {
        match session.confirm(own, &token) {
            Ok(answer) => return Ok(confirmed(answer)),
            Err(ServiceError::Answered {
                code: lunepack_core::service::ErrorCode::TokenMismatch,
                ..
            }) => {}
            Err(e) => return Err(service_error(e)),
        }
    }
    match session.attempt(own).map_err(service_error)? {
        AttemptAnswer::Counted { token, .. } => {
            let answer = session.confirm(own, &token).map_err(service_error)?;
            Ok(confirmed(answer))
        }
        AttemptAnswer::Supervised | AttemptAnswer::NotPending => Ok(ConfirmOutcome::NothingPending),
        // Rolled back: the token of this start is dead.
        _ => Err(Error::TokenMismatch),
    }
}

/// The usable staged version of a per-machine install, with its tree in place and `staged_issued`
/// bound; [`Error::NothingStaged`] otherwise. Reads the machine record; takes no lock.
pub(crate) fn staged_version(
    inst: &Installation,
    machine: &MachineInstall,
) -> Result<Version, Error> {
    let p = &inst.platform;
    let scope = machine.scope(inst.app_id());
    let record = scope
        .load_machine(&*p.fs, &*p.hasher)?
        .record
        .ok_or(Error::NothingStaged)?;
    let (Some(current), Some(staged)) = (&record.current, &record.staged) else {
        return Err(Error::NothingStaged);
    };
    let usable = staged.version > current.version
        && !record.bad.contains(&staged.version)
        && staged.target == record.target
        && record.staged_issued_bound().is_some();
    if !usable {
        return Err(Error::NothingStaged);
    }
    let tree = machine.layout().app_dir().join(&staged.tree);
    let real_dir = match p.fs.symlink_metadata(&tree) {
        Ok(meta) => meta.is_some_and(|m| m.kind == FileKind::Dir),
        Err(e) if e.kind == lunepack_core::FsErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    if !real_dir {
        return Err(Error::NothingStaged);
    }
    Ok(staged.version.clone())
}
