//! Operating-system integration behind a trait (hard rule 3): what makes an installed app visible
//! to the desktop (a menu entry, a command on the path) is created, refreshed and removed through
//! [`OsIntegration`]. The Linux implementation (XDG desktop entry and a bin link) is in
//! `lunepack-os-linux`; the testkit's `FakeIntegration` records the calls.
//!
//! The integration is built from the app's [`InstallMeta`] (the update-config document, FORMAT.md
//! 13) and the install root. It never needs the install tree to exist when it runs: on Linux,
//! entries point through `<install root>/current`, so a version flip needs no rewrite; on Windows
//! there is no `current` link, so every apply recomputes what points into the version tree from
//! the request's [`IntegrationRequest::version`] (M7-D8). Removal is checked by a marker: only
//! what lunepack created for this app id is removed.
//!
//! Errors name an item and a rule, never a value from the metadata or a path.

use std::path::PathBuf;

use crate::error::DesktopPathError;
use crate::fs::FsError;
use crate::ident::AppId;
use crate::state::Scope;
use crate::update_config::InstallMeta;
use crate::version::Version;

/// What the integration creates for an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IntegrationItem {
    /// The menu entry (a `.desktop` file on Linux).
    DesktopEntry,
    /// The command link on the user's path.
    BinLink,
    /// The launcher stub at the install root (Windows, M7-D8).
    Stub,
    /// The Start-menu shortcut (Windows, M7-D15).
    Shortcut,
    /// The "Apps & features" uninstall entry (Windows, M7-D15).
    UninstallEntry,
    /// A file-type association: a `MimeType=` line on Linux, an "Open with" entry on Windows
    /// (M7-D3).
    FileType,
    /// A URL-scheme handler (M7-D3).
    UrlScheme,
    /// The start-at-sign-in entry: an XDG autostart file on Linux, a `Run` value on Windows
    /// (M7-D3).
    Autostart,
}

impl IntegrationItem {
    /// A fixed description.
    pub const fn describe(self) -> &'static str {
        match self {
            IntegrationItem::DesktopEntry => "desktop entry",
            IntegrationItem::BinLink => "command link",
            IntegrationItem::Stub => "launcher stub",
            IntegrationItem::Shortcut => "Start-menu shortcut",
            IntegrationItem::UninstallEntry => "uninstall entry",
            IntegrationItem::FileType => "file-type association",
            IntegrationItem::UrlScheme => "URL-scheme handler",
            IntegrationItem::Autostart => "autostart entry",
        }
    }
}

/// Why an integration operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IntegrationError {
    /// This scope or platform has no integration (machine scope in M5).
    #[error("integration is not supported here")]
    Unsupported,
    /// An entry of this kind exists and is not lunepack's for this app, so it is left alone.
    #[error("a {} that does not belong to this app is in the way", .0.describe())]
    Conflict(IntegrationItem),
    /// A path cannot be written into the entry.
    #[error("{what} cannot go into a desktop entry: {reason}")]
    UnsafePath {
        /// The field.
        what: &'static str,
        /// The rule it broke.
        #[source]
        reason: DesktopPathError,
    },
    /// A text field cannot go into the entry (a control character, a separator, a bad name). The
    /// value is not shown.
    #[error("field {0} cannot go into a desktop entry")]
    UnsafeField(&'static str),
    /// The environment names no usable home directory (`HOME` is unset, not absolute or not
    /// UTF-8).
    #[error("the environment names no usable home directory")]
    Home,
    /// A filesystem operation failed.
    #[error("{0}")]
    Fs(#[from] FsError),
    /// Anything else (the environment names no home, a directory is not usable, ...).
    #[error("integration failed: {0}")]
    Failed(&'static str),
}

/// What the integration is built from.
#[derive(Debug, Clone)]
pub struct IntegrationRequest {
    /// The app's id (it names the entry and is the marker removal checks).
    pub app_id: AppId,
    /// The install root `R` (absolute); on Linux, entries point through `R/current`; on Windows
    /// they point into `R`'s version tree for [`IntegrationRequest::version`]. It need not exist.
    pub install_root: PathBuf,
    /// The version whose tree `meta` was read from: the one that becomes (or, for `remove`, is)
    /// current. Windows entries point into its tree; Linux ignores it.
    pub version: Version,
    /// The metadata from the version's update config.
    pub meta: InstallMeta,
    /// The outgoing version's metadata, when there is one (an update or a rollback): the
    /// integration removes what it made from `previous` and `meta` no longer names (a stub under
    /// a changed entry file name, M7-D8). `None` for a first install and for `remove`. Linux
    /// still uses `stale_bins`.
    pub previous: Option<InstallMeta>,
    /// Command-link names from the outgoing version's config that the new `meta.bin` no longer
    /// uses. `apply` removes each of them that lunepack made and leaves any other. Empty for a
    /// first install and for `remove`.
    pub stale_bins: Vec<String>,
}

/// What `apply` and `remove` report: the items they found and left alone because they are not
/// lunepack's for this app (a foreign file at the entry's path, a link that points elsewhere).
/// Empty when everything was handled.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct IntegrationReport {
    /// The items left in place, in the order met. An item can be named twice (the command link
    /// and a stale command link).
    pub kept: Vec<IntegrationItem>,
}

/// Creates, refreshes and removes an app's desktop integration. Object-safe and `Send + Sync`.
///
/// Per-machine scope is [`IntegrationError::Unsupported`] in M5 for all three operations.
pub trait OsIntegration: Send + Sync {
    /// The preflight: refuses what [`OsIntegration::apply`] would refuse (a conflicting entry, an
    /// unsafe path or field) and writes nothing.
    fn check(&self, scope: Scope, req: &IntegrationRequest) -> Result<(), IntegrationError>;

    /// Creates the integration, or refreshes it from `req` when it exists; running it again with
    /// the same request changes nothing. On an error nothing foreign is overwritten. A stale
    /// command link (`req.stale_bins`) that is not lunepack's is left and reported in `kept`.
    fn apply(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError>;

    /// Removes what [`OsIntegration::apply`] created for `req.app_id`, and only that: an entry
    /// without lunepack's marker for this app id is left alone and reported in `kept`. Removing
    /// what is not there is not an error.
    fn remove(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError>;
}
