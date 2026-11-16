//! The facade's error type (C9).
//!
//! No variant's `Display` holds a URL query, a full user path or key bytes: core errors name only
//! file names and origins, and the facade adds fixed text.

use lunepack_core::{
    FsError, IntegrationError, LayoutError, LifecycleError, ProcessError, ProcessErrorKind,
    RangeError, RelPath, StateError, TransportError, UpdateConfigError,
};

/// Every way an [`Updater`](crate::Updater) operation fails.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// There is no committed install state (a development run, or before the first install).
    #[error("not installed: no install state")]
    NotInstalled,
    /// Another operation holds the updater lock.
    #[error("another lunepack operation is running")]
    Busy,
    /// The operation was cancelled.
    #[error("cancelled")]
    Cancelled,
    /// The update is no longer applicable: the installed version is at or above it, or it was
    /// marked bad since the check.
    #[error("the update is stale")]
    Stale,
    /// Staging a per-machine install is the privileged engine's job (C8).
    #[error("staging is not available for a per-machine install")]
    MachineScope,
    /// The new version's directory name differs only in letter case from that of an installed,
    /// staged or kept version, so on a case-insensitive file system both would be one directory
    /// (FORMAT.md 12). Nothing is staged.
    #[error("the version's directory name collides, ignoring case, with an existing version")]
    VersionDirCollision,
    /// The install state was written by a newer build; nothing is written (M4-D22 c).
    #[error("the install state is from a newer lunepack")]
    StateTooNew,
    /// Bytes or documents failed verification or a format rule (the core's error).
    #[error("{0}")]
    Verify(lunepack_core::Error),
    /// A transport failed to produce a response or a body chunk.
    #[error("{0}")]
    Transport(#[from] TransportError),
    /// A filesystem operation failed.
    #[error("{0}")]
    Fs(#[from] FsError),
    /// The install-state store failed.
    #[error("install state: {0}")]
    State(StateError),
    /// A download ended early (a dropped connection, a short body); the part is kept and the next
    /// call resumes it.
    #[error("download incomplete; it resumes on the next call")]
    Incomplete,
    /// These files could not be placed after a Range retry and a full-pack try (D27 ladder).
    #[error("{} files could not be staged", .0.len())]
    NeedFetchExhausted(Vec<RelPath>),
    /// A lunepack worker thread panicked (or could not be started); the panic message is not
    /// shown.
    #[error("a lunepack worker thread panicked")]
    WorkerPanicked,
    /// The configuration is unusable (for example a feed URL with an unsupported scheme).
    #[error("configuration: {0}")]
    Config(&'static str),
    /// This platform has no adapter for the call yet (processes and desktop integration outside
    /// Linux in M5).
    #[error("not supported on this platform")]
    Unsupported,
    /// No directory from the executable's own up holds an update config (a development run).
    #[error("no update config was found for this executable")]
    NoUpdateConfig,
    /// The update config found for the executable is unusable: refused by the reader or the feed
    /// rule, not a regular file, or the executable is not in its entry's directory.
    #[error("update config: {0}")]
    UpdateConfig(UpdateConfigError),
    /// Nothing usable is staged (none, not newer, bad, its tree missing, or its `issued` not
    /// bound to it); the app stages again.
    #[error("nothing is staged")]
    NothingStaged,
    /// The staged version is not the one the app expected.
    #[error("the staged version is not the expected one")]
    UnexpectedVersion,
    /// The install already has a current version.
    #[error("already installed")]
    AlreadyInstalled,
    /// The first install's root exists and is not lunepack's: it is not a real directory, or it
    /// is not empty and holds neither this app's install state nor only what a run cut off
    /// before its first record leaves. Uninstall removes the root whole, so the install takes
    /// over nothing it did not make; nothing was written.
    #[error("the install root holds files lunepack did not make")]
    ForeignInstallRoot,
    /// The first install found no release for this install: the channel offers none, none whose
    /// rollout admits this install yet, or none at or above the bootstrap tree's own version.
    /// Nothing was installed; a later try may succeed.
    #[error("no release is available for this install")]
    NoRelease,
    /// The health token does not match the supervised start's, or is malformed.
    #[error("the health token does not match")]
    TokenMismatch,
    /// A process operation failed.
    #[error("{0}")]
    Process(ProcessError),
    /// The desktop integration failed or is in the way.
    #[error("{0}")]
    Integration(IntegrationError),
    /// There is no previous version to roll back to.
    #[error("no previous version to roll back to")]
    RollbackUnavailable,
}

/// Sorts a core error into the variant an app can act on: a disk failure is [`Error::Fs`] (so
/// "free some space" can be offered), not [`Error::Verify`], which stays for refused documents,
/// hashes and signatures.
impl From<lunepack_core::Error> for Error {
    fn from(e: lunepack_core::Error) -> Self {
        match e {
            lunepack_core::Error::Fs(e) => Error::Fs(e),
            lunepack_core::Error::Transport(e) => Error::Transport(e),
            lunepack_core::Error::Cancelled => Error::Cancelled,
            lunepack_core::Error::State(e) => Error::from(e),
            lunepack_core::Error::Process(e) => Error::from(e),
            lunepack_core::Error::Integration(e) => Error::from(e),
            lunepack_core::Error::Lifecycle(e) => Error::from(e),
            lunepack_core::Error::Layout(LayoutError::Fs(e)) => Error::Fs(e),
            other => Error::Verify(other),
        }
    }
}

impl From<ProcessError> for Error {
    fn from(e: ProcessError) -> Self {
        match e.kind {
            ProcessErrorKind::Unsupported => Error::Unsupported,
            _ => Error::Process(e),
        }
    }
}

impl From<IntegrationError> for Error {
    fn from(e: IntegrationError) -> Self {
        match e {
            IntegrationError::Unsupported => Error::Unsupported,
            IntegrationError::Fs(e) => Error::Fs(e),
            other => Error::Integration(other),
        }
    }
}

/// A refused transition as the app sees it: a staged entry that cannot be applied is nothing
/// staged (C9), and the rest keep the core's reason.
impl From<LifecycleError> for Error {
    fn from(e: LifecycleError) -> Self {
        match e {
            LifecycleError::MachineScope => Error::MachineScope,
            LifecycleError::NotInstalled => Error::NotInstalled,
            LifecycleError::AlreadyInstalled => Error::AlreadyInstalled,
            LifecycleError::NothingStaged | LifecycleError::StagedIssuedUnbound => {
                Error::NothingStaged
            }
            LifecycleError::StagedVersionMismatch => Error::UnexpectedVersion,
            LifecycleError::NoPrevious => Error::RollbackUnavailable,
            LifecycleError::TokenMismatch => Error::TokenMismatch,
            other => Error::Verify(lunepack_core::Error::Lifecycle(other)),
        }
    }
}

impl From<RangeError> for Error {
    fn from(e: RangeError) -> Self {
        Error::Verify(lunepack_core::Error::Range(e))
    }
}

impl From<StateError> for Error {
    fn from(e: StateError) -> Self {
        match e {
            StateError::NewerFormat => Error::StateTooNew,
            other => Error::State(other),
        }
    }
}
