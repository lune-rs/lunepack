//! The privileged engine of a per-machine install (M10, C8): the only writer of the machine tree
//! `R` (`<Program Files>\<display name>` on Windows). It runs as LocalSystem inside the update
//! service, or once as an administrator after consent, and serves the requests of the service
//! protocol ([`crate::service`]) through [`serve`].
//!
//! Trust (M4-SEC-obs1, M10-D2, M10-D17): the engine takes the install root from its host and
//! nothing else about location. The trust root and the floors come from the machine record alone;
//! the channel from the installed tree's own update configuration; the candidate from its own
//! [`select_candidate`] over the feed it verified. Every byte a client sends is first written into
//! a folder only administrators can reach (`R\.lunepack\machine\incoming\<random>\`), hashed while
//! written, and kept only when it is an object of the verified manifest. It reads no clock,
//! randomness, environment or filesystem except through its ports; the supervision lease's
//! monotonic time is passed in by the host.
//!
//! Every operation goes: take the engine's lock (`R\.lunepack\machine\lock`), check the tree's
//! protection, load the machine record, make one pure transition, commit it, then the side
//! effects (integration), then answer. A refusal changes nothing.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// `Duration` is a plain value (no clock is read); the purity test forbids `std::time` as a whole.
use core::time::Duration;

use crate::cancel::CancelToken;
use crate::chain::{RootWalk, raised_floors};
use crate::codesign::{Decision, decide};
use crate::digest::Sha256Digest;
use crate::encoding::hex_encode;
use crate::error::{Error, LifecycleError, ServiceError, StageError};
use crate::fs::{FileKind, FileWrite, Fs, FsErrorKind, LockGuard};
use crate::ident::{AppId, Channel};
use crate::integration::{IntegrationRequest, OsIntegration};
use crate::lifecycle::{AttemptOutcome, ConfirmOutcome, machine};
use crate::manifest::{VerifiedEntry, VerifiedManifest, verify_manifest};
use crate::policy::select_candidate;
use crate::progress::Progress;
use crate::root::TrustedRoot;
use crate::service::{
    AttemptAnswer, CommitOutcome, ConfirmAnswer, Duplex, ErrorCode, MAX_COMMITS, MAX_NEED_FETCH,
    ObjectKind, PendingStatus, Request, Response, ServerSession, StatusReport, Token, VerifyClass,
};
use crate::stage::{PARTIAL_SUFFIX, SourceFor, StageEnv, StageInput, scan, stage};
use crate::state::{
    InstallState, Loaded, MAX_BAD_VERSIONS, MachineStore, Scope, StagedRef, load_any,
};
use crate::traits::{
    Clock, Codec, DirClass, HashState, Hasher, PolicySource, Protect, PublisherCheck, Rng,
    SignedTree, Verifier,
};
use crate::trust::ClockReading;
use crate::update_config::{
    MAX_UPDATE_CONFIG_BYTES, PublisherPolicy, UPDATE_CONFIG_FILE, UpdateConfig,
};
use crate::version::Version;

/// The version trees' directory under `R`.
pub const APP_DIR: &str = "app";
/// The machine tree's private directory under `R`.
pub const LUNEPACK_DIR: &str = ".lunepack";
/// The machine record's directory under `R\.lunepack`.
pub const STATE_DIR: &str = "state";
/// The admin-only directory under `R\.lunepack`.
pub const MACHINE_DIR: &str = "machine";
/// The upload staging directory under `R\.lunepack\machine`.
pub const INCOMING_DIR: &str = "incoming";
/// The engine's lock file under `R\.lunepack\machine`.
pub const LOCK_FILE: &str = "lock";
/// Added to the health timeout for a supervision lease.
pub const LEASE_GRACE: Duration = Duration::from_secs(15);
/// The health timeout a lease uses is clamped to this range (seconds).
pub const HEALTH_TIMEOUT_RANGE: (u64, u64) = (5, 3600);
/// Bytes of the random name of a session's upload folder.
pub const SESSION_NAME_BYTES: usize = 16;
/// The stage budget the engine runs with (one worker).
pub const STAGE_BUDGET_BYTES: u64 = 256 * 1024 * 1024;
/// Suffix of an upload being written.
pub const PART_SUFFIX: &str = ".part";

/// Why an engine operation was refused: one protocol code (and a class for `verify_failed`).
/// Nothing else crosses the boundary; the engine changed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineError {
    /// The code.
    pub code: ErrorCode,
    /// The verification class, for [`ErrorCode::VerifyFailed`].
    pub class: Option<VerifyClass>,
}

impl EngineError {
    fn of(code: ErrorCode) -> EngineError {
        EngineError { code, class: None }
    }

    fn verify(e: &Error) -> EngineError {
        EngineError {
            code: ErrorCode::VerifyFailed,
            class: Some(verify_class(e)),
        }
    }

    /// The `error` answer.
    pub fn to_response(self) -> Response {
        Response::Error {
            code: self.code,
            class: self.class,
        }
    }
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.class {
            Some(c) => write!(f, "{} ({c})", self.code),
            None => write!(f, "{}", self.code),
        }
    }
}

impl std::error::Error for EngineError {}

/// The closed verification class of a core verification error; the detail stays local.
fn verify_class(e: &Error) -> VerifyClass {
    match e {
        Error::Signature(_)
        | Error::SignatureCount { .. }
        | Error::SignatureLength { .. }
        | Error::KeyIdSyntax(_)
        | Error::Threshold { .. }
        | Error::KeyIdMismatch
        | Error::DuplicatePublicKey
        | Error::KeyThreshold { .. }
        | Error::KeyWindow
        | Error::RootVersion { .. } => VerifyClass::Signature,
        Error::Expired { .. } => VerifyClass::Expired,
        Error::Rollback { .. } | Error::KeySetRootVersion { .. } => VerifyClass::Rollback,
        Error::ArtifactSize { .. } | Error::ArtifactHash => VerifyClass::Hash,
        Error::AppIdMismatch => VerifyClass::AppMismatch,
        _ => VerifyClass::Format,
    }
}

fn lifecycle_code(e: LifecycleError) -> EngineError {
    EngineError::of(match e {
        LifecycleError::NothingStaged | LifecycleError::StagedIssuedUnbound => {
            ErrorCode::NothingStaged
        }
        LifecycleError::StagedVersionMismatch => ErrorCode::VersionMismatch,
        LifecycleError::PendingExists => ErrorCode::PendingExists,
        LifecycleError::NotPending => ErrorCode::NotPending,
        LifecycleError::TokenMismatch => ErrorCode::TokenMismatch,
        LifecycleError::BadFull => ErrorCode::BadFull,
        // A record of the wrong scope cannot reach here (the store refuses it), nor can the
        // other refusals of the first-install transitions.
        _ => ErrorCode::Internal,
    })
}

fn internal<E>(_: E) -> EngineError {
    EngineError::of(ErrorCode::Internal)
}

/// The capabilities the engine runs with; nothing else reaches it.
#[derive(Clone, Copy)]
pub struct Ports<'a> {
    /// The filesystem.
    pub fs: &'a dyn Fs,
    /// The frame decoder.
    pub codec: &'a dyn Codec,
    /// SHA-256.
    pub hasher: &'a dyn Hasher,
    /// Signature verification.
    pub verifier: &'a dyn Verifier,
    /// Wall time, for document expiry only (never for the lease).
    pub clock: &'a dyn Clock,
    /// Randomness (tokens, session folder names).
    pub rng: &'a dyn Rng,
    /// The machine-scope desktop integration.
    pub integration: &'a dyn OsIntegration,
    /// The publisher-continuity check (M9).
    pub publisher: &'a dyn PublisherCheck,
    /// Protected directories.
    pub protect: &'a dyn Protect,
    /// The administrator's policy.
    pub policy: &'a dyn PolicySource,
}

/// A running supervision lease (M10-D3): only in memory, lost on restart.
#[derive(Debug, Clone)]
struct Lease {
    version: Version,
    until: Duration,
}

/// Text equality of versions (two versions of equal precedence but different build metadata are
/// different trees).
fn same(a: &Version, b: &Version) -> bool {
    a == b && a.to_string() == b.to_string()
}

/// The engine of one machine install.
pub struct Engine<'a> {
    p: Ports<'a>,
    root: PathBuf,
    app_id: AppId,
    store: MachineStore,
    lease: Option<Lease>,
    service_version: Option<Version>,
}

impl std::fmt::Debug for Engine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("app_id", &self.app_id)
            .finish_non_exhaustive()
    }
}

/// The admin-only folder of one stage session and what was uploaded into it. Dropping it removes
/// the folder and, when the session started a stage that did not finish, the partial tree.
pub struct StageSession<'a> {
    fs: &'a dyn Fs,
    dir: PathBuf,
    lock: PathBuf,
    versions_dir: PathBuf,
    manifest: VerifiedManifest,
    manifest_sha256: Sha256Digest,
    current: Version,
    objects: BTreeMap<[u8; 32], PathBuf>,
    commits: u32,
    staged: bool,
}

impl std::fmt::Debug for StageSession<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StageSession")
            .field("version", self.manifest.version())
            .field("commits", &self.commits)
            .finish_non_exhaustive()
    }
}

impl StageSession<'_> {
    /// The version this session stages.
    pub fn version(&self) -> &Version {
        self.manifest.version()
    }

    /// `stage_commit` requests made so far.
    pub fn commits(&self) -> u32 {
        self.commits
    }
}

impl Drop for StageSession<'_> {
    fn drop(&mut self) {
        let _ = self.fs.remove_dir_all_nofollow(&self.dir);
        if self.commits > 0 && !self.staged {
            // Only under the engine's lock: a partial tree is the engine's state.
            if let Ok(Some(_guard)) = self.fs.try_lock(&self.lock) {
                let partial = self
                    .versions_dir
                    .join(format!("{}{PARTIAL_SUFFIX}", self.manifest.version()));
                let _ = self.fs.remove_dir_all_nofollow(&partial);
            }
        }
    }
}

/// An upload being written: hashed while written, capped at its declared size.
pub struct PartWriter {
    file: Box<dyn FileWrite>,
    hash: Box<dyn HashState>,
    path: PathBuf,
    written: u64,
    size: u64,
}

impl std::fmt::Debug for PartWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartWriter")
            .field("written", &self.written)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl Write for PartWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written.saturating_add(buf.len() as u64) > self.size {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.file.write_all(buf)?;
        self.hash.update(buf);
        self.written += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl PartWriter {
    /// Removes the part file (an upload that did not finish).
    pub fn discard(self, fs: &dyn Fs) {
        let path = self.path.clone();
        drop(self);
        let _ = fs.remove_file(&path);
    }
}

impl<'a> Engine<'a> {
    /// Opens the engine of the machine install at `root`: checks the tree's protection, takes the
    /// lock, reads the machine record (which must be a machine record with a trust root) and
    /// removes upload folders a previous run left.
    pub fn open(ports: Ports<'a>, root: &Path) -> Result<Engine<'a>, EngineError> {
        let root = root.to_path_buf();
        check_protection(&ports, &root)?;
        let _guard = take_lock(ports.fs, &lock_path(&root))?;
        let record = load_any::<InstallState>(ports.fs, &state_dir(&root), ports.hasher)
            .map_err(|_| EngineError::of(ErrorCode::NotProtected))?
            .ok_or(EngineError::of(ErrorCode::NotProtected))?;
        if record.scope != Scope::Machine || record.floors.root.is_none() {
            return Err(EngineError::of(ErrorCode::NotProtected));
        }
        let app_id = record.app_id.clone();
        let engine = Engine {
            p: ports,
            store: MachineStore {
                dir: state_dir(&root),
                app_id: app_id.clone(),
            },
            root,
            app_id,
            lease: None,
            service_version: None,
        };
        engine.remove_leftover_uploads();
        Ok(engine)
    }

    /// The same engine reporting `version` as the running service's own version in `status`
    /// (the host knows it from its own path); without it `status` reports the current version.
    pub fn with_service_version(mut self, version: Version) -> Engine<'a> {
        self.service_version = Some(version);
        self
    }

    /// The app this engine serves.
    pub fn app_id(&self) -> &AppId {
        &self.app_id
    }

    fn remove_leftover_uploads(&self) {
        let incoming = incoming_dir(&self.root);
        if let Ok(entries) = self.p.fs.list_dir(&incoming) {
            for e in entries {
                let _ = self.p.fs.remove_dir_all_nofollow(&incoming.join(&e.name));
            }
        }
    }

    /// The lock and the protection check every operation starts with.
    fn guard(&self) -> Result<Box<dyn LockGuard>, EngineError> {
        let guard = take_lock(self.p.fs, &lock_path(&self.root))?;
        check_protection(&self.p, &self.root)?;
        Ok(guard)
    }

    fn load(&self) -> Result<(Loaded<InstallState>, InstallState), EngineError> {
        let loaded = self
            .store
            .load(self.p.fs, self.p.hasher)
            .map_err(|_| EngineError::of(ErrorCode::NotProtected))?;
        let record = loaded
            .record
            .clone()
            .ok_or(EngineError::of(ErrorCode::NotProtected))?;
        if record.current.is_none() || record.floors.root.is_none() {
            return Err(EngineError::of(ErrorCode::NotProtected));
        }
        Ok((loaded, record))
    }

    fn commit(
        &self,
        loaded: &Loaded<InstallState>,
        next: &InstallState,
    ) -> Result<InstallState, EngineError> {
        self.store
            .commit(self.p.fs, loaded, next, self.p.hasher)
            .map_err(internal)
    }

    /// The trust root of the machine record, and nothing else (M4-SEC-obs1).
    fn trusted_root(&self, record: &InstallState) -> Result<TrustedRoot, EngineError> {
        record
            .floors
            .root
            .as_ref()
            .ok_or(EngineError::of(ErrorCode::NotProtected))?
            .to_trusted(self.app_id.clone(), self.p.hasher, self.p.verifier)
            .map_err(|_| EngineError::of(ErrorCode::NotProtected))
    }

    fn versions_dir(&self) -> PathBuf {
        self.root.join(APP_DIR)
    }

    fn tree(&self, version: &Version) -> PathBuf {
        self.versions_dir().join(version.to_string())
    }

    /// The update configuration of the installed tree of `version` (admin-only, so trusted): a
    /// real directory holding a regular config file for this app and that version.
    fn tree_config(&self, version: &Version) -> Result<UpdateConfig, EngineError> {
        let tree = self.tree(version);
        let fs = self.p.fs;
        match fs.symlink_metadata(&tree) {
            Ok(Some(m)) if m.kind == FileKind::Dir => {}
            _ => return Err(EngineError::of(ErrorCode::Internal)),
        }
        let path = tree.join(UPDATE_CONFIG_FILE);
        match fs.symlink_metadata(&path) {
            Ok(Some(m)) if m.kind == FileKind::File => {}
            _ => return Err(EngineError::of(ErrorCode::Internal)),
        }
        let bytes = fs
            .read_capped(&path, MAX_UPDATE_CONFIG_BYTES)
            .map_err(internal)?;
        let config = UpdateConfig::parse(&bytes).map_err(internal)?;
        if config.app_id != self.app_id || !same(&config.version, version) {
            return Err(EngineError::of(ErrorCode::Internal));
        }
        Ok(config)
    }

    fn lease_length(&self, version: &Version) -> Duration {
        let (lo, hi) = HEALTH_TIMEOUT_RANGE;
        // An unreadable config errs towards supervision: the longest lease.
        let secs = self
            .tree_config(version)
            .map_or(hi, |c| c.health_timeout_secs.clamp(lo, hi));
        Duration::from_secs(secs) + LEASE_GRACE
    }

    /// Refreshes the machine integration after a committed change from `from` to `to` (the
    /// runtime's order for a user install: commit, then the integration). Its result is not the
    /// operation's: the record is committed either way.
    fn refresh_integration(&self, from: Option<&UpdateConfig>, to: &UpdateConfig) {
        let stale_bins = match from.and_then(|f| f.install.bin.clone()) {
            Some(bin) if to.install.bin.as_ref() != Some(&bin) => vec![bin],
            _ => Vec::new(),
        };
        let request = IntegrationRequest {
            app_id: self.app_id.clone(),
            install_root: self.root.clone(),
            version: to.version.clone(),
            meta: to.install.clone(),
            previous: from.map(|f| f.install.clone()),
            stale_bins,
        };
        let _ = self.p.integration.apply(Scope::Machine, &request);
    }

    // ---- operations ------------------------------------------------------------------------------

    /// `status`: the record's versions, the service's version and the policy; no token digest,
    /// install id or path.
    pub fn status(&self) -> Result<StatusReport, EngineError> {
        let _guard = self.guard()?;
        let (_, record) = self.load()?;
        let current = record
            .current
            .as_ref()
            .ok_or(EngineError::of(ErrorCode::NotProtected))?
            .version
            .clone();
        Ok(StatusReport {
            service: self.service_version.clone().unwrap_or(current.clone()),
            current,
            previous: record.previous.map(|p| p.version),
            pending: record.pending.map(|p| PendingStatus {
                version: p.version,
                attempts: p.attempts,
            }),
            staged: record.staged.map(|s| s.version),
            self_update_disabled: self.p.policy.read(&self.app_id).self_update_disabled,
        })
    }

    /// `stage_begin`: verifies `roots`, `keys`, `feed` against the machine record's root and
    /// floors for the installed tree's channel, commits raised floors, selects the candidate and
    /// verifies `manifest` against it. `None`: no update. `Some`: a session whose admin-only
    /// upload folder exists.
    pub fn stage_begin(
        &mut self,
        channel: &Channel,
        roots: &[&[u8]],
        keys: &[u8],
        feed: &[u8],
        manifest: &[u8],
    ) -> Result<Option<StageSession<'a>>, EngineError> {
        let _guard = self.guard()?;
        if self.p.policy.read(&self.app_id).self_update_disabled {
            return Err(EngineError::of(ErrorCode::DisabledByPolicy));
        }
        let (loaded, mut record) = self.load()?;
        if record.pending.is_some() {
            return Err(EngineError::of(ErrorCode::PendingExists));
        }
        let current = record
            .current
            .clone()
            .ok_or(EngineError::of(ErrorCode::NotProtected))?;
        let config = self.tree_config(&current.version)?;
        if &config.channel != channel {
            return Err(EngineError::of(ErrorCode::ChannelNotAllowed));
        }
        let mut walk = RootWalk::new(self.trusted_root(&record)?);
        for bytes in roots {
            walk.advance(bytes, self.p.hasher, self.p.verifier)
                .map_err(|e| EngineError::verify(&e))?;
        }
        let clock = ClockReading::read(self.p.clock, Some(current.issued));
        let docs = walk
            .finish(
                &self.app_id,
                channel,
                &record.floors,
                keys,
                feed,
                &clock,
                self.p.hasher,
                self.p.verifier,
            )
            .map_err(|e| EngineError::verify(&e))?;
        let raised = raised_floors(&docs.root, &docs.keys, &docs.feed, channel);
        if !record.floors.is_at_least(&raised) {
            record = self.commit(&loaded, &record.raise_floors(&raised))?;
        }
        let Some(candidate) = select_candidate(
            &docs.feed,
            Some(&current.version),
            record.target,
            &record.bad,
            &record.install_id,
            self.p.hasher,
        ) else {
            return Ok(None);
        };
        let verified = verify_manifest(
            &docs.keys,
            &candidate.entry,
            manifest,
            self.p.hasher,
            self.p.verifier,
        )
        .map_err(|e| EngineError::verify(&e))?;
        let dir = self.new_upload_dir()?;
        Ok(Some(StageSession {
            fs: self.p.fs,
            dir,
            lock: lock_path(&self.root),
            versions_dir: self.versions_dir(),
            manifest_sha256: self.p.hasher.sha256(manifest),
            manifest: verified,
            current: current.version,
            objects: BTreeMap::new(),
            commits: 0,
            staged: false,
        }))
    }

    /// `R\.lunepack\machine\incoming\<32 hex from Rng>`, created admin-only.
    fn new_upload_dir(&self) -> Result<PathBuf, EngineError> {
        let incoming = incoming_dir(&self.root);
        match self.p.fs.symlink_metadata(&incoming) {
            Ok(None) => self
                .p
                .protect
                .create_dir(&incoming, DirClass::AdminOnly)
                .map_err(|_| EngineError::of(ErrorCode::NotProtected))?,
            Ok(Some(_)) => self
                .p
                .protect
                .check(&incoming, DirClass::AdminOnly)
                .map_err(|_| EngineError::of(ErrorCode::NotProtected))?,
            Err(_) => return Err(EngineError::of(ErrorCode::Internal)),
        }
        let mut name = [0u8; SESSION_NAME_BYTES];
        self.p.rng.fill(&mut name).map_err(internal)?;
        let dir = incoming.join(hex_encode(&name));
        self.p
            .protect
            .create_dir(&dir, DirClass::AdminOnly)
            .map_err(|_| EngineError::of(ErrorCode::Internal))?;
        Ok(dir)
    }

    /// `put`, before any byte: the object must be the manifest's pack or one of its frames, of
    /// that size, and not uploaded before in this session (a repeat is `malformed`).
    pub fn put_check(
        &self,
        session: &StageSession<'_>,
        kind: ObjectKind,
        sha256: &Sha256Digest,
        size: u64,
    ) -> Result<(), EngineError> {
        let _guard = self.guard()?;
        let want = match kind {
            ObjectKind::Pack => {
                let pack = session.manifest.pack();
                (pack.sha256() == *sha256).then(|| pack.size())
            }
            ObjectKind::Frame => session.manifest.entries().iter().find_map(|e| match e {
                VerifiedEntry::File { frame: Some(f), .. } if f.sha256() == *sha256 => {
                    Some(f.length())
                }
                _ => None,
            }),
        };
        let want = want.ok_or(EngineError::of(ErrorCode::NotInManifest))?;
        if want != size {
            return Err(EngineError::of(ErrorCode::SizeMismatch));
        }
        if session.objects.contains_key(sha256.as_bytes()) {
            return Err(EngineError::of(ErrorCode::Malformed));
        }
        Ok(())
    }

    /// Creates the part file the object's bytes are written to.
    pub fn put_open(
        &self,
        session: &StageSession<'_>,
        sha256: &Sha256Digest,
        size: u64,
    ) -> Result<PartWriter, EngineError> {
        let path = session
            .dir
            .join(format!("{}{PART_SUFFIX}", sha256.to_hex()));
        let file = self.p.fs.create_new(&path).map_err(internal)?;
        Ok(PartWriter {
            file,
            hash: self.p.hasher.sha256_start(),
            path,
            written: 0,
            size,
        })
    }

    /// Ends an upload: the bytes written must be the declared size and hash to `sha256`; then the
    /// part file is renamed to its SHA-256 name. Otherwise it is removed.
    pub fn put_finish(
        &self,
        session: &mut StageSession<'_>,
        sha256: &Sha256Digest,
        writer: PartWriter,
    ) -> Result<(), EngineError> {
        let PartWriter {
            mut file,
            hash,
            path,
            written,
            size,
        } = writer;
        let synced = file.flush().is_ok() && file.sync().is_ok();
        drop(file);
        let digest = hash.finalize();
        let fail = |code| {
            let _ = self.p.fs.remove_file(&path);
            Err(EngineError::of(code))
        };
        if !synced {
            return fail(ErrorCode::Internal);
        }
        if written != size {
            return fail(ErrorCode::SizeMismatch);
        }
        if digest != *sha256 {
            return fail(ErrorCode::HashMismatch);
        }
        let _guard = match self.guard() {
            Ok(g) => g,
            Err(e) => {
                let _ = self.p.fs.remove_file(&path);
                return Err(e);
            }
        };
        let kept = session.dir.join(sha256.to_hex());
        if self.p.fs.rename(&path, &kept).is_err() {
            return fail(ErrorCode::Internal);
        }
        session.objects.insert(*sha256.as_bytes(), kept);
        Ok(())
    }

    /// `stage_commit`: builds the session's version under `R\app` from the current tree and the
    /// uploaded objects, runs the publisher check under the installed tree's policy and records
    /// the tree as staged. Paths no source covers are answered as `need_fetch`.
    pub fn stage_commit(
        &mut self,
        session: &mut StageSession<'_>,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<CommitOutcome, EngineError> {
        if session.commits >= MAX_COMMITS {
            return Err(EngineError::of(ErrorCode::Malformed));
        }
        session.commits += 1;
        let _guard = self.guard()?;
        let (loaded, record) = self.load()?;
        if record.pending.is_some() {
            return Err(EngineError::of(ErrorCode::PendingExists));
        }
        let current = record
            .current
            .clone()
            .ok_or(EngineError::of(ErrorCode::NotProtected))?;
        if !same(&current.version, &session.current) {
            return Err(EngineError::of(ErrorCode::VersionMismatch));
        }
        let version = session.manifest.version().clone();
        self.refuse_case_collision(&record, &version)?;
        let cancel = CancelToken::new();
        let current_tree = self.tree(&current.version);
        let unchanged = scan(
            &session.manifest,
            Some(&current_tree),
            self.p.fs,
            self.p.hasher,
            1,
            &cancel,
            &|_| {},
        )
        .map_err(internal)?;
        let pack = session
            .objects
            .get(session.manifest.pack().sha256().as_bytes())
            .cloned();
        let mut sources = Vec::with_capacity(unchanged.len());
        let mut missing = Vec::new();
        for (entry, same_file) in session.manifest.entries().iter().zip(unchanged) {
            let source = match entry {
                VerifiedEntry::File { frame: Some(f), .. } => {
                    if let Some(p) = same_file {
                        SourceFor::Unchanged(p)
                    } else if let Some(p) = session.objects.get(f.sha256().as_bytes()) {
                        SourceFor::Frame(p.clone())
                    } else if let Some(p) = &pack {
                        SourceFor::Pack(p.clone())
                    } else {
                        missing.push(entry.path().clone());
                        SourceFor::Patch
                    }
                }
                // Directories, symlinks and empty files take no bytes; the source is ignored.
                _ => SourceFor::Unchanged(PathBuf::new()),
            };
            sources.push(source);
        }
        if !missing.is_empty() {
            return Ok(need_fetch(missing));
        }
        let progress = RefCell::new(progress);
        let on_progress = |p: Progress| (progress.borrow_mut())(p.done, p.total);
        let input = StageInput {
            manifest: &session.manifest,
            versions_dir: self.versions_dir(),
            sources,
        };
        let env = StageEnv {
            fs: self.p.fs,
            codec: self.p.codec,
            hasher: self.p.hasher,
            workers: 1,
            budget_bytes: STAGE_BUDGET_BYTES,
            cancel: &cancel,
            progress: &on_progress,
        };
        let staged = match stage(&input, &env) {
            Ok(staged) => staged,
            Err(StageError::NeedFetch(paths)) => return Ok(need_fetch(paths)),
            Err(_) => return Err(EngineError::of(ErrorCode::Internal)),
        };
        // M9-D9, the facade's decision for the same inputs: the installed tree's policy, then
        // the check, through the shared `decide`.
        match self.publisher_decision(&current.version, &staged.tree)? {
            Decision::Proceed(_) => {}
            Decision::Refuse { mark_bad, .. } => {
                if mark_bad && !record.bad.contains(&version) && record.bad.len() < MAX_BAD_VERSIONS
                {
                    self.commit(&loaded, &record.mark_bad(version))?;
                }
                return Err(EngineError::of(ErrorCode::PublisherMismatch));
            }
        }
        let staged_ref = StagedRef::new(version.clone(), staged.target, session.manifest_sha256);
        let next = record.set_staged(Some((staged_ref, session.manifest.issued())));
        self.commit(&loaded, &next)?;
        session.staged = true;
        Ok(CommitOutcome::Staged(version))
    }

    /// The facade's publisher decision (M9-D9) over the installed tree of `current` and the
    /// candidate tree: no installed config or policy `off` proceeds; a candidate without a
    /// readable config fails closed.
    fn publisher_decision(
        &self,
        current: &Version,
        candidate: &Path,
    ) -> Result<Decision, EngineError> {
        let installed = self.tree_config(current)?;
        if installed.publisher_check == PublisherPolicy::Off {
            return Ok(Decision::Proceed(None));
        }
        let candidate_config = read_config_at(self.p.fs, &candidate.join(UPDATE_CONFIG_FILE))?;
        if candidate_config.app_id != self.app_id {
            return Err(EngineError::of(ErrorCode::Internal));
        }
        let result = self.p.publisher.same_publisher(
            &SignedTree {
                root: self.tree(current),
                entry: installed.install.entry,
            },
            &SignedTree {
                root: candidate.to_path_buf(),
                entry: candidate_config.install.entry,
            },
        );
        Ok(decide(installed.publisher_check, result))
    }

    /// Refuses a version whose directory name differs only in ASCII case from a kept version's
    /// or from an entry of `R\app` (one directory on a case-insensitive file system, F11).
    fn refuse_case_collision(
        &self,
        record: &InstallState,
        version: &Version,
    ) -> Result<(), EngineError> {
        let mut names: Vec<String> = record
            .current
            .iter()
            .map(|c| c.version.to_string())
            .chain(record.previous.iter().map(|p| p.version.to_string()))
            .chain(record.pending.iter().map(|p| p.version.to_string()))
            .chain(record.staged.iter().map(|s| s.tree.clone()))
            .collect();
        match self.p.fs.list_dir(&self.versions_dir()) {
            Ok(entries) => names.extend(
                entries
                    .into_iter()
                    .map(|e| e.name.to_string_lossy().into_owned()),
            ),
            Err(e) if e.kind == FsErrorKind::NotFound => {}
            Err(_) => return Err(EngineError::of(ErrorCode::Internal)),
        }
        let candidate = version.to_string();
        let partial = format!("{candidate}{PARTIAL_SUFFIX}");
        let collides = names.iter().any(|n| {
            (n != &candidate && n.eq_ignore_ascii_case(&candidate))
                || (n != &partial && n.eq_ignore_ascii_case(&partial))
        });
        if collides {
            return Err(EngineError::of(ErrorCode::VersionMismatch));
        }
        Ok(())
    }

    /// `apply{version}`: makes the staged `version` current and pending with a fresh token (only
    /// its SHA-256 is recorded), refreshes the integration and starts the supervision lease at
    /// `now` (monotonic).
    pub fn apply(&mut self, version: &Version, now: Duration) -> Result<Token, EngineError> {
        let _guard = self.guard()?;
        if self.p.policy.read(&self.app_id).self_update_disabled {
            return Err(EngineError::of(ErrorCode::DisabledByPolicy));
        }
        let (loaded, record) = self.load()?;
        if record.pending.is_some() {
            return Err(EngineError::of(ErrorCode::PendingExists));
        }
        let staged_is_v = record
            .staged
            .as_ref()
            .is_some_and(|s| same(&s.version, version));
        if !staged_is_v {
            return Err(EngineError::of(if record.staged.is_some() {
                ErrorCode::VersionMismatch
            } else {
                ErrorCode::NothingStaged
            }));
        }
        // The new version's own config decides its timeout and integration; without a usable
        // one nothing is committed.
        let incoming = self
            .tree_config(version)
            .map_err(|_| EngineError::of(ErrorCode::NothingStaged))?;
        let outgoing = record
            .current
            .as_ref()
            .and_then(|c| self.tree_config(&c.version).ok());
        let mut raw = [0u8; 32];
        self.p.rng.fill(&mut raw).map_err(internal)?;
        let token = Token::from_bytes(raw);
        let next =
            machine::apply(&record, version, self.p.hasher.sha256(&raw)).map_err(lifecycle_code)?;
        self.commit(&loaded, &next)?;
        self.refresh_integration(outgoing.as_ref(), &incoming);
        self.lease = Some(Lease {
            version: version.clone(),
            until: now + self.lease_length(version),
        });
        Ok(token)
    }

    /// `attempt{version}`: a start of the pending `version` without a token (M10-D3). Under a
    /// running lease: `supervised`, nothing committed. Otherwise one attempt is counted with a
    /// fresh token and a new lease, or, past the limit, the version is rolled back and marked bad.
    pub fn attempt(
        &mut self,
        version: &Version,
        now: Duration,
    ) -> Result<AttemptAnswer, EngineError> {
        let _guard = self.guard()?;
        let (loaded, record) = self.load()?;
        let pending = record
            .pending
            .as_ref()
            .is_some_and(|p| same(&p.version, version));
        if !pending {
            return Ok(AttemptAnswer::NotPending);
        }
        if self
            .lease
            .as_ref()
            .is_some_and(|l| same(&l.version, version) && now < l.until)
        {
            return Ok(AttemptAnswer::Supervised);
        }
        let mut raw = [0u8; 32];
        self.p.rng.fill(&mut raw).map_err(internal)?;
        let (next, outcome) = machine::attempt(&record, version, self.p.hasher.sha256(&raw))
            .map_err(lifecycle_code)?;
        match outcome {
            AttemptOutcome::Counted(attempts) => {
                self.commit(&loaded, &next)?;
                self.lease = Some(Lease {
                    version: version.clone(),
                    until: now + self.lease_length(version),
                });
                Ok(AttemptAnswer::Counted {
                    attempts,
                    token: Token::from_bytes(raw),
                })
            }
            AttemptOutcome::RollBack => {
                let (from, to) = self.rollback_configs(&record, version)?;
                let next = machine::rollback_at_limit(&record, version).map_err(lifecycle_code)?;
                let committed = self.commit(&loaded, &next)?;
                self.refresh_integration(from.as_ref(), &to);
                self.lease = None;
                Ok(AttemptAnswer::RolledBack {
                    current: committed
                        .current
                        .map(|c| c.version)
                        .ok_or(EngineError::of(ErrorCode::Internal))?,
                })
            }
        }
    }

    /// The configs a rollback of `version` refreshes the integration with: the outgoing pending
    /// version's (if readable) and the previous version's, which must be readable (otherwise
    /// nothing is rolled back, as the runtime does).
    fn rollback_configs(
        &self,
        record: &InstallState,
        version: &Version,
    ) -> Result<(Option<UpdateConfig>, UpdateConfig), EngineError> {
        let previous = record
            .previous
            .as_ref()
            .ok_or(EngineError::of(ErrorCode::Internal))?;
        let to = self.tree_config(&previous.version)?;
        Ok((self.tree_config(version).ok(), to))
    }

    /// `confirm{version, token}`: the pending `version` presenting its token is healthy.
    pub fn confirm(
        &mut self,
        version: &Version,
        token: &Token,
    ) -> Result<ConfirmAnswer, EngineError> {
        let _guard = self.guard()?;
        let (loaded, record) = self.load()?;
        let presented = self.p.hasher.sha256(token.as_bytes());
        let (next, outcome) =
            machine::confirm(&record, version, presented).map_err(lifecycle_code)?;
        match outcome {
            ConfirmOutcome::Confirmed => {
                self.commit(&loaded, &next)?;
                self.lease = None;
                Ok(ConfirmAnswer::Confirmed)
            }
            ConfirmOutcome::NothingPending => Ok(ConfirmAnswer::NothingPending),
        }
    }

    /// `rollback{version, token}`: the pending `version` failed; the previous version becomes
    /// current, `version` is marked bad and the integration is refreshed from the previous
    /// version's config.
    pub fn rollback(&mut self, version: &Version, token: &Token) -> Result<Version, EngineError> {
        let _guard = self.guard()?;
        let (loaded, record) = self.load()?;
        let presented = self.p.hasher.sha256(token.as_bytes());
        // The token first, so a bystander learns nothing from the config checks.
        let next = machine::rollback(&record, version, presented).map_err(lifecycle_code)?;
        let (from, to) = self.rollback_configs(&record, version)?;
        let committed = self.commit(&loaded, &next)?;
        self.refresh_integration(from.as_ref(), &to);
        self.lease = None;
        committed
            .current
            .map(|c| c.version)
            .ok_or(EngineError::of(ErrorCode::Internal))
    }
}

/// A `need_fetch` answer with as many of `paths` as fit in one message (at most
/// [`MAX_NEED_FETCH`] and within the message cap); `more` when some were left out.
fn need_fetch(paths: Vec<crate::path::RelPath>) -> CommitOutcome {
    let total = paths.len();
    let mut kept = Vec::new();
    for p in paths {
        kept.push(p);
        let fits = kept.len() <= MAX_NEED_FETCH
            && Response::NeedFetch {
                paths: kept.clone(),
                more: true,
            }
            .encode()
            .is_ok();
        if !fits {
            kept.pop();
            break;
        }
    }
    let more = kept.len() < total;
    CommitOutcome::NeedFetch { paths: kept, more }
}

fn read_config_at(fs: &dyn Fs, path: &Path) -> Result<UpdateConfig, EngineError> {
    match fs.symlink_metadata(path) {
        Ok(Some(m)) if m.kind == FileKind::File => {}
        _ => return Err(EngineError::of(ErrorCode::Internal)),
    }
    let bytes = fs
        .read_capped(path, MAX_UPDATE_CONFIG_BYTES)
        .map_err(internal)?;
    UpdateConfig::parse(&bytes).map_err(internal)
}

fn state_dir(root: &Path) -> PathBuf {
    root.join(LUNEPACK_DIR).join(STATE_DIR)
}

fn machine_dir(root: &Path) -> PathBuf {
    root.join(LUNEPACK_DIR).join(MACHINE_DIR)
}

fn incoming_dir(root: &Path) -> PathBuf {
    machine_dir(root).join(INCOMING_DIR)
}

fn lock_path(root: &Path) -> PathBuf {
    machine_dir(root).join(LOCK_FILE)
}

fn take_lock(fs: &dyn Fs, path: &Path) -> Result<Box<dyn LockGuard>, EngineError> {
    match fs.try_lock(path) {
        Ok(Some(guard)) => Ok(guard),
        Ok(None) => Err(EngineError::of(ErrorCode::Busy)),
        Err(_) => Err(EngineError::of(ErrorCode::Internal)),
    }
}

/// The directories the engine checks at every start and operation (M10-D9).
pub fn protected_dirs(root: &Path) -> [(PathBuf, DirClass); 5] {
    [
        (root.to_path_buf(), DirClass::MachineTree),
        (root.join(APP_DIR), DirClass::MachineTree),
        (root.join(LUNEPACK_DIR), DirClass::MachineTree),
        (state_dir(root), DirClass::MachineTree),
        (machine_dir(root), DirClass::AdminOnly),
    ]
}

fn check_protection(ports: &Ports<'_>, root: &Path) -> Result<(), EngineError> {
    for (dir, class) in protected_dirs(root) {
        ports
            .protect
            .check(&dir, class)
            .map_err(|_| EngineError::of(ErrorCode::NotProtected))?;
    }
    Ok(())
}

// ---- the dispatcher ------------------------------------------------------------------------------

fn end_malformed<D: Duplex>(
    session: &mut ServerSession<D>,
    why: &'static str,
) -> Result<(), ServiceError> {
    let _ = session.reply(&Response::error(ErrorCode::Malformed));
    Err(ServiceError::Malformed(why))
}

/// Serves one connection: maps each request to the engine and answers it. A request out of order
/// (`put` or `stage_commit` without a stage session, a second `stage_begin`, a repeated object, a
/// fourth commit) answers `malformed` and ends the connection without touching the engine. The
/// stage session lives here; when the connection ends for any reason it is dropped, which removes
/// its upload folder and an unfinished partial tree. `monotonic` is the host's monotonic time for
/// the supervision lease.
pub fn serve<D: Duplex>(
    mut session: ServerSession<D>,
    engine: &mut Engine<'_>,
    monotonic: &dyn Fn() -> Duration,
) -> Result<(), ServiceError> {
    let mut stage: Option<StageSession<'_>> = None;
    while let Some(request) = session.next_request()? {
        let answer = match request {
            Request::Status => engine.status().map(Response::Status),
            Request::StageBegin { channel, documents } => {
                if stage.is_some() {
                    return end_malformed(&mut session, "a second stage_begin");
                }
                let mut data = Vec::new();
                session.read_data(documents.iter().map(|d| d.bytes).sum(), &mut data)?;
                let mut at = 0usize;
                let mut roots: Vec<&[u8]> = Vec::new();
                let (mut keys, mut feed, mut manifest): (&[u8], &[u8], &[u8]) = (&[], &[], &[]);
                for d in &documents {
                    // The sizes were checked against FORMAT 4's caps and read in full.
                    let len = usize::try_from(d.bytes).unwrap_or(usize::MAX);
                    let bytes = &data[at..at + len];
                    at += len;
                    match d.kind {
                        crate::service::DocumentKind::Root => roots.push(bytes),
                        crate::service::DocumentKind::Keys => keys = bytes,
                        crate::service::DocumentKind::Feed => feed = bytes,
                        crate::service::DocumentKind::Manifest => manifest = bytes,
                    }
                }
                match engine.stage_begin(&channel, &roots, keys, feed, manifest) {
                    Ok(Some(s)) => {
                        let version = s.version().clone();
                        stage = Some(s);
                        Ok(Response::StageReady { version })
                    }
                    Ok(None) => Ok(Response::NoUpdate),
                    Err(e) => Err(e),
                }
            }
            Request::Put { sha256, size, kind } => {
                let Some(s) = stage.as_mut() else {
                    return end_malformed(&mut session, "put without a stage session");
                };
                match engine.put_check(s, kind, &sha256, size) {
                    Err(e) if e.code == ErrorCode::Malformed => {
                        return end_malformed(&mut session, "an object uploaded twice");
                    }
                    Err(e) => {
                        // Refused before any byte: the declared bytes are read and dropped so
                        // the connection stays in step.
                        session.read_data(size, &mut io::sink())?;
                        Err(e)
                    }
                    Ok(()) => match engine.put_open(s, &sha256, size) {
                        Err(e) => {
                            session.read_data(size, &mut io::sink())?;
                            Err(e)
                        }
                        Ok(mut writer) => match session.read_data(size, &mut writer) {
                            Ok(()) => engine
                                .put_finish(s, &sha256, writer)
                                .map(|()| Response::PutOk),
                            Err(ServiceError::Sink(_)) => {
                                writer.discard(engine.p.fs);
                                let _ = session.reply(&Response::error(ErrorCode::Internal));
                                return Ok(());
                            }
                            Err(e) => {
                                writer.discard(engine.p.fs);
                                return Err(e);
                            }
                        },
                    },
                }
            }
            Request::StageCommit => {
                let Some(s) = stage.as_mut() else {
                    return end_malformed(&mut session, "stage_commit without a stage session");
                };
                if s.commits() >= MAX_COMMITS {
                    return end_malformed(&mut session, "a fourth stage_commit");
                }
                let mut failed = None;
                let outcome = engine.stage_commit(s, &mut |done, total| {
                    if failed.is_none()
                        && let Err(e) = session.reply(&Response::Progress { done, total })
                    {
                        failed = Some(e);
                    }
                });
                if let Some(e) = failed {
                    return Err(e);
                }
                match outcome {
                    Ok(CommitOutcome::Staged(version)) => {
                        stage = None;
                        Ok(Response::Staged { version })
                    }
                    Ok(CommitOutcome::NeedFetch { paths, more }) => {
                        Ok(Response::NeedFetch { paths, more })
                    }
                    Err(e) => Err(e),
                }
            }
            Request::Apply { version } => engine
                .apply(&version, monotonic())
                .map(|token| Response::Applied { version, token }),
            Request::Attempt { version } => {
                engine.attempt(&version, monotonic()).map(Response::Attempt)
            }
            Request::Confirm { version, token } => {
                engine.confirm(&version, &token).map(|a| match a {
                    ConfirmAnswer::Confirmed => Response::Confirmed,
                    ConfirmAnswer::NothingPending => Response::NothingPending,
                })
            }
            Request::Rollback { version, token } => engine
                .rollback(&version, &token)
                .map(|current| Response::RolledBack { current }),
        };
        session.reply(&answer.unwrap_or_else(EngineError::to_response))?;
    }
    Ok(())
}
