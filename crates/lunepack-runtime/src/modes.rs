//! The runtime's modes, their argument grammar and the one table of exit codes (C4, M5-D11,
//! M5-D12).
//!
//! The parser is hand-written over `args_os` and closed: every option is named, given exactly
//! once and carries a value of a fixed form. It never echoes an argument: a refusal is the one
//! fixed [`USAGE_LINE`] on stderr and exit code 2, before anything else happens.
//!
//! The internal modes are `apply` (step 8), `install` and `uninstall` (step 9); the app-facing
//! commands (step 12) extend [`Mode`] and the table here.

use std::ffi::{OsStr, OsString};
use std::sync::Arc;

use lunepack::{
    Codec, Fs, Hasher, OsIntegration, Platform, Process, ProcessId, PublisherOutcome, Rng,
    Verifier, Version,
};

/// The line a usage error prints on stderr. It names no argument value.
pub const USAGE_LINE: &str = "lunepack-runtime: usage error";

/// Why a place is not one lunepack updates (macOS, M8-D4): the closed set of `reason` of the
/// `unsupported_location` outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Place {
    /// Translocated by Gatekeeper.
    Translocated,
    /// On a read-only volume (a mounted disk image).
    ReadOnly,
    /// The bundle's folder and the install's versions are on different volumes.
    OtherVolume,
    /// The bundle is not owned by the user.
    NotOwned,
    /// The user cannot write the bundle's folder.
    NotWritable,
}

impl Place {
    /// Every reason, in the order the docs list them.
    #[allow(dead_code)]
    pub const ALL: [Place; 5] = [
        Place::Translocated,
        Place::ReadOnly,
        Place::OtherVolume,
        Place::NotOwned,
        Place::NotWritable,
    ];

    /// The `reason` text.
    pub const fn name(self) -> &'static str {
        match self {
            Place::Translocated => "translocated",
            Place::ReadOnly => "read_only",
            Place::OtherVolume => "other_volume",
            Place::NotOwned => "not_owned",
            Place::NotWritable => "not_writable",
        }
    }

    /// The reason the core reports, `None` for one this build does not know.
    pub fn of(reason: lunepack_core::LocationReason) -> Option<Place> {
        use lunepack_core::LocationReason as R;
        Some(match reason {
            R::Translocated => Place::Translocated,
            R::ReadOnly => Place::ReadOnly,
            R::OtherVolume => Place::OtherVolume,
            R::NotOwned => Place::NotOwned,
            R::NotWritable => Place::NotWritable,
            _ => return None,
        })
    }
}

/// The reasons of exit 29 `publisher_mismatch`, in the order the docs list them: every outcome a
/// refusal can carry (`installed_unsigned` proceeds under every policy, so it is never one).
#[allow(dead_code)]
pub const PUBLISHER_REASONS: [PublisherOutcome; 5] = [
    PublisherOutcome::Different,
    PublisherOutcome::InstalledInvalid,
    PublisherOutcome::CandidateUnsigned,
    PublisherOutcome::CandidateInvalid,
    PublisherOutcome::Os,
];

/// The outcome classes of the runtime, each with a stable exit code and a stable `kind` name
/// (C4: one per error class of the facade's error enum, plus the runtime's own outcomes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Success.
    Ok,
    /// The arguments do not follow the grammar.
    Usage,
    /// The tree is not installed, or there is no install state.
    NotInstalled,
    /// Another lunepack operation holds the install lock.
    Busy,
    /// The operation was cancelled.
    Cancelled,
    /// The update is no longer applicable.
    Stale,
    /// A document, hash or signature was refused.
    Verify,
    /// The transport failed.
    Transport,
    /// A filesystem operation failed.
    Fs,
    /// The install state store failed or is too new.
    State,
    /// A download ended early.
    Incomplete,
    /// Nothing usable is staged.
    NothingStaged,
    /// `--expect-schema` names another schema.
    #[allow(dead_code)] // the commands' outcome (step 12)
    SchemaMismatch,
    /// The update config is missing or unusable.
    UpdateConfig,
    /// The staged version is not the expected one.
    UnexpectedVersion,
    /// The health token does not match.
    TokenMismatch,
    /// The install is per machine.
    MachineScope,
    /// Not supported on this platform.
    Unsupported,
    /// A process operation failed.
    Process,
    /// The applied version failed its health check and was rolled back.
    RolledBack,
    /// The process to wait for did not exit in time; nothing changed.
    WaitTimeout,
    /// The version failed its health check but its predecessor cannot be started; it stays
    /// pending.
    RollbackUnavailable,
    /// The install already has a current version.
    AlreadyInstalled,
    /// The desktop integration failed or is in the way.
    Integration,
    /// A process still runs from the install.
    InUse,
    /// The install this runtime stands in is not the one the environment derives, or is not a
    /// real, canonical directory holding this app's record (`install`, `uninstall`; M5-D10).
    InstallMismatch,
    /// The channel offers no release for this install yet: none at all, or none whose rollout
    /// admits it (`install`; retryable, nothing was installed).
    NoRelease,
    /// The running app or the install's bundle is somewhere lunepack does not update (macOS,
    /// M8-D4); the output names the reason, a closed code.
    UnsupportedLocation(Place),
    /// The installed version's publisher policy refused the update (M9-D9); the output names the
    /// reason, a closed code (`different`, `installed_invalid`, `candidate_unsigned`,
    /// `candidate_invalid`, `os`). Nothing was staged.
    PublisherMismatch(PublisherOutcome),
    /// Anything else (a worker panic, a facade error this build does not know).
    Internal,
}

impl Kind {
    /// Every kind, in code order (for the golden of step 12).
    #[allow(dead_code)]
    pub const ALL: [Kind; 30] = [
        Kind::Ok,
        Kind::Usage,
        Kind::NotInstalled,
        Kind::Busy,
        Kind::Cancelled,
        Kind::Stale,
        Kind::Verify,
        Kind::Transport,
        Kind::Fs,
        Kind::State,
        Kind::Incomplete,
        Kind::NothingStaged,
        Kind::SchemaMismatch,
        Kind::UpdateConfig,
        Kind::UnexpectedVersion,
        Kind::TokenMismatch,
        Kind::MachineScope,
        Kind::Unsupported,
        Kind::Process,
        Kind::RolledBack,
        Kind::WaitTimeout,
        Kind::RollbackUnavailable,
        Kind::AlreadyInstalled,
        Kind::Integration,
        Kind::InUse,
        Kind::InstallMismatch,
        Kind::NoRelease,
        // One representative: the five reasons share the code and the name (`Place::ALL`).
        Kind::UnsupportedLocation(Place::Translocated),
        // One representative: every reason shares the code and the name (`PUBLISHER_REASONS`).
        Kind::PublisherMismatch(PublisherOutcome::Different),
        Kind::Internal,
    ];

    /// The process exit code.
    pub const fn code(self) -> u8 {
        match self {
            Kind::Ok => 0,
            Kind::Usage => 2,
            Kind::NotInstalled => 3,
            Kind::Busy => 4,
            Kind::Cancelled => 5,
            Kind::Stale => 6,
            Kind::Verify => 7,
            Kind::Transport => 8,
            Kind::Fs => 9,
            Kind::State => 10,
            Kind::Incomplete => 11,
            Kind::NothingStaged => 12,
            Kind::SchemaMismatch => 13,
            Kind::UpdateConfig => 14,
            Kind::UnexpectedVersion => 15,
            Kind::TokenMismatch => 16,
            Kind::MachineScope => 17,
            Kind::Unsupported => 18,
            Kind::Process => 19,
            Kind::RolledBack => 20,
            Kind::WaitTimeout => 21,
            Kind::RollbackUnavailable => 22,
            Kind::AlreadyInstalled => 23,
            Kind::Integration => 24,
            Kind::InUse => 25,
            Kind::InstallMismatch => 26,
            Kind::NoRelease => 27,
            Kind::UnsupportedLocation(_) => 28,
            Kind::PublisherMismatch(_) => 29,
            Kind::Internal => 70,
        }
    }

    /// The `kind` name of the JSON error object and the log.
    pub const fn name(self) -> &'static str {
        match self {
            Kind::Ok => "ok",
            Kind::Usage => "usage",
            Kind::NotInstalled => "not_installed",
            Kind::Busy => "busy",
            Kind::Cancelled => "cancelled",
            Kind::Stale => "stale",
            Kind::Verify => "verify",
            Kind::Transport => "transport",
            Kind::Fs => "fs",
            Kind::State => "state",
            Kind::Incomplete => "incomplete",
            Kind::NothingStaged => "nothing_staged",
            Kind::SchemaMismatch => "schema_mismatch",
            Kind::UpdateConfig => "update_config",
            Kind::UnexpectedVersion => "unexpected_version",
            Kind::TokenMismatch => "token_mismatch",
            Kind::MachineScope => "machine_scope",
            Kind::Unsupported => "unsupported",
            Kind::Process => "process",
            Kind::RolledBack => "rolled_back",
            Kind::WaitTimeout => "wait_timeout",
            Kind::RollbackUnavailable => "rollback_unavailable",
            Kind::AlreadyInstalled => "already_installed",
            Kind::Integration => "integration",
            Kind::InUse => "in_use",
            Kind::InstallMismatch => "install_mismatch",
            Kind::NoRelease => "no_release",
            Kind::UnsupportedLocation(_) => "unsupported_location",
            Kind::PublisherMismatch(_) => "publisher_mismatch",
            Kind::Internal => "internal",
        }
    }

    /// The `reason` member of the error object, for the kinds that have one.
    pub const fn reason(self) -> Option<&'static str> {
        match self {
            Kind::UnsupportedLocation(place) => Some(place.name()),
            Kind::PublisherMismatch(reason) => Some(reason.code()),
            _ => None,
        }
    }

    /// The class of a facade error. The facade's `Display` text is never used.
    pub fn of(e: &lunepack::Error) -> Kind {
        use lunepack::Error as E;
        match e {
            E::NotInstalled => Kind::NotInstalled,
            E::Busy => Kind::Busy,
            E::Cancelled => Kind::Cancelled,
            E::Stale => Kind::Stale,
            E::MachineScope => Kind::MachineScope,
            E::VersionDirCollision => Kind::Fs,
            E::StateTooNew => Kind::State,
            E::Verify(_) => Kind::Verify,
            E::Transport(_) => Kind::Transport,
            E::Fs(_) => Kind::Fs,
            E::State(_) => Kind::State,
            E::Incomplete => Kind::Incomplete,
            E::NeedFetchExhausted(_) => Kind::Verify,
            E::Config(_) => Kind::UpdateConfig,
            E::Unsupported => Kind::Unsupported,
            E::NoUpdateConfig => Kind::UpdateConfig,
            E::UpdateConfig(_) => Kind::UpdateConfig,
            E::NothingStaged => Kind::NothingStaged,
            E::UnexpectedVersion => Kind::UnexpectedVersion,
            E::AlreadyInstalled => Kind::AlreadyInstalled,
            E::ForeignInstallRoot => Kind::InstallMismatch,
            E::TokenMismatch => Kind::TokenMismatch,
            E::Process(_) => Kind::Process,
            E::Integration(_) => Kind::Integration,
            E::RollbackUnavailable => Kind::RollbackUnavailable,
            E::NoRelease => Kind::NoRelease,
            E::UnsupportedLocation { reason } => {
                Place::of(*reason).map_or(Kind::Internal, Kind::UnsupportedLocation)
            }
            E::PublisherMismatch { reason } => Kind::PublisherMismatch(*reason),
            // WorkerPanicked, and any variant a later facade adds (the enum is non-exhaustive).
            _ => Kind::Internal,
        }
    }
}

/// The adapters a mode runs on, wired by `main.rs` (the composition root). `platform` carries the
/// same adapters for the facade's [`lunepack::Installation`].
#[derive(Clone)]
pub struct Adapters {
    /// The filesystem.
    pub fs: Arc<dyn Fs>,
    /// SHA-256.
    pub hasher: Arc<dyn Hasher>,
    /// Signature verification (setup mode, M6-D4).
    pub verifier: Arc<dyn Verifier>,
    /// The frame decoder (setup mode reads single entries, FORMAT.md 13.6).
    pub codec: Arc<dyn Codec>,
    /// Processes.
    pub process: Arc<dyn Process>,
    /// The desktop integration.
    pub integration: Arc<dyn OsIntegration>,
    /// Randomness (the health token).
    pub rng: Arc<dyn Rng>,
    /// The facade's platform over the same adapters.
    pub platform: Platform,
}

/// The arguments of `apply`.
#[derive(Clone, PartialEq, Eq)]
pub struct ApplyArgs {
    /// The process to wait for.
    pub wait: ProcessId,
    /// The staged version to apply.
    pub version: Version,
    /// The arguments the new version (or, after a rollback, the previous one) is started with.
    pub restart: Vec<OsString>,
    /// `--no-ui`: no update window (D41).
    pub no_ui: bool,
    /// `--background`: the new version (and after a rollback the previous one) starts without
    /// coming to the front (M8-D13; macOS only, no effect elsewhere).
    pub background: bool,
}

impl std::fmt::Debug for ApplyArgs {
    /// Shows the number of restart arguments, not their values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplyArgs")
            .field("wait", &self.wait)
            .field("version", &self.version.to_string())
            .field("restart", &self.restart.len())
            .field("no_ui", &self.no_ui)
            .field("background", &self.background)
            .finish()
    }
}

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// `apply --wait-pid <u32> --wait-start <u64> --version <ver> [--no-ui] [--background]
    /// [-- <args>…]`.
    Apply(ApplyArgs),
    /// `install [--silent]`: the first install from the bootstrap tree this runtime belongs to.
    Install {
        /// `--silent`: no UI and no prompt (D41).
        silent: bool,
    },
    /// `uninstall [--silent]`: removes the install this runtime belongs to (on Windows: phase 1,
    /// the hand-off to a copy outside the install, M7-D5).
    Uninstall {
        /// `--silent` (or `/S` on Windows): no UI and no prompt (D41).
        silent: bool,
    },
    /// Windows only: `uninstall --install-root <R> --wait-pid <u32> --wait-start <u64>
    /// [--silent | /S]`, phase 2 of the hand-off, accepted only from the uninstaller's own temp
    /// copy (checked before any action, M7-D5).
    UninstallHandOff(HandOffArgs),
    /// An app-facing command (`check`, `download`, `startup`, `confirm`).
    Command(crate::cli::args::Parsed),
}

/// The arguments of phase 2 of the Windows uninstall hand-off.
#[derive(Clone, PartialEq, Eq)]
pub struct HandOffArgs {
    /// The install root phase 1 derived from its own path; validated again before any action.
    pub install_root: std::path::PathBuf,
    /// Phase 1, waited for before anything changes.
    pub wait: ProcessId,
    /// No UI and no prompt.
    pub silent: bool,
}

impl std::fmt::Debug for HandOffArgs {
    /// Shows no path.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandOffArgs")
            .field("wait", &self.wait)
            .field("silent", &self.silent)
            .finish_non_exhaustive()
    }
}

/// The arguments do not follow the grammar. Carries nothing about them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageError;

/// Parses the arguments after the program name.
pub fn parse(args: &[OsString]) -> Result<Mode, UsageError> {
    let (mode, rest) = args.split_first().ok_or(UsageError)?;
    match mode.to_str() {
        Some("apply") => parse_apply(rest).map(Mode::Apply),
        // Only `--silent`: everything they use is derived, nothing comes from argv (M5-D10).
        Some("install") => silent_only(rest).map(|silent| Mode::Install { silent }),
        Some("uninstall") if HAND_OFF && rest.iter().any(|a| a == "--install-root") => {
            parse_hand_off(rest).map(Mode::UninstallHandOff)
        }
        Some("uninstall") => silent_or_s(rest).map(|silent| Mode::Uninstall { silent }),
        Some(word) => match crate::cli::args::Command::named(word) {
            Some(command) => crate::cli::args::parse(command, rest).map(Mode::Command),
            None => Err(UsageError),
        },
        None => Err(UsageError),
    }
}

/// The arguments of a setup file's run (M6 step 7): nothing, or `--silent` (or `/S` on Windows)
/// once; anything else is a usage error.
pub fn parse_setup(args: &[OsString]) -> Result<bool, UsageError> {
    silent_or_s(args)
}

/// Whether `uninstall` has a phase 2 (`--install-root`): Windows only (M7-D5).
const HAND_OFF: bool = cfg!(windows);

/// Whether `flag` asks for a silent run: `--silent`, or on Windows also `/S` (M7).
fn is_silent_flag(flag: &OsStr) -> bool {
    flag == "--silent" || (cfg!(windows) && flag == "/S")
}

/// The options of `install`: nothing, or `--silent` once.
fn silent_only(rest: &[OsString]) -> Result<bool, UsageError> {
    match rest {
        [] => Ok(false),
        [flag] if flag == "--silent" => Ok(true),
        _ => Err(UsageError),
    }
}

/// The options of `uninstall` and a setup run: nothing, or one silent flag ([`is_silent_flag`]).
fn silent_or_s(rest: &[OsString]) -> Result<bool, UsageError> {
    match rest {
        [] => Ok(false),
        [flag] if is_silent_flag(flag) => Ok(true),
        _ => Err(UsageError),
    }
}

/// Phase 2's options, in any order, each once: `--install-root <path>` (non-empty),
/// `--wait-pid <u32>` (not 0), `--wait-start <u64>`, and at most one silent flag.
fn parse_hand_off(args: &[OsString]) -> Result<HandOffArgs, UsageError> {
    let mut root: Option<std::path::PathBuf> = None;
    let mut pid: Option<u32> = None;
    let mut start: Option<u64> = None;
    let mut silent = false;
    let mut i = 0;
    while i < args.len() {
        if is_silent_flag(&args[i]) {
            if silent {
                return Err(UsageError);
            }
            silent = true;
            i += 1;
            continue;
        }
        let name = args[i].to_str().ok_or(UsageError)?;
        let value = args.get(i + 1).ok_or(UsageError)?;
        match name {
            "--install-root" if root.is_none() && !value.is_empty() => {
                root = Some(std::path::PathBuf::from(value));
            }
            "--wait-pid" if pid.is_none() => {
                let p: u32 = decimal(value)?;
                if p == 0 {
                    return Err(UsageError);
                }
                pid = Some(p);
            }
            "--wait-start" if start.is_none() => start = Some(decimal(value)?),
            _ => return Err(UsageError),
        }
        i += 2;
    }
    match (root, pid, start) {
        (Some(install_root), Some(pid), Some(start_ticks)) => Ok(HandOffArgs {
            install_root,
            wait: ProcessId { pid, start_ticks },
            silent,
        }),
        _ => Err(UsageError),
    }
}

/// A decimal number: ASCII digits only (no sign, no space, no leading zero but `0` itself).
pub(crate) fn decimal<T: std::str::FromStr>(value: &OsStr) -> Result<T, UsageError> {
    let text = value.to_str().ok_or(UsageError)?;
    let plain = !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if !plain {
        return Err(UsageError);
    }
    text.parse().map_err(|_| UsageError)
}

fn parse_apply(args: &[OsString]) -> Result<ApplyArgs, UsageError> {
    let mut pid: Option<u32> = None;
    let mut start: Option<u64> = None;
    let mut version: Option<Version> = None;
    let mut restart = Vec::new();
    let mut no_ui = false;
    let mut background = false;
    let mut i = 0;
    while i < args.len() {
        let name = args[i].to_str().ok_or(UsageError)?;
        if name == "--" {
            restart.extend_from_slice(&args[i + 1..]);
            break;
        }
        if name == "--no-ui" {
            if no_ui {
                return Err(UsageError);
            }
            no_ui = true;
            i += 1;
            continue;
        }
        if name == "--background" {
            if background {
                return Err(UsageError);
            }
            background = true;
            i += 1;
            continue;
        }
        let value = args.get(i + 1).ok_or(UsageError)?;
        match name {
            "--wait-pid" if pid.is_none() => {
                let p: u32 = decimal(value)?;
                if p == 0 {
                    return Err(UsageError);
                }
                pid = Some(p);
            }
            "--wait-start" if start.is_none() => start = Some(decimal(value)?),
            "--version" if version.is_none() => {
                let text = value.to_str().ok_or(UsageError)?;
                let v = Version::parse(text).map_err(|_| UsageError)?;
                // The version names a directory: only its canonical text is accepted.
                if v.to_string() != text {
                    return Err(UsageError);
                }
                version = Some(v);
            }
            _ => return Err(UsageError),
        }
        i += 2;
    }
    match (pid, start, version) {
        (Some(pid), Some(start_ticks), Some(version)) => Ok(ApplyArgs {
            wait: ProcessId { pid, start_ticks },
            version,
            restart,
            no_ui,
            background,
        }),
        _ => Err(UsageError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn apply_parses_in_any_order_with_restart_args() {
        let got = parse(&os(&[
            "apply",
            "--version",
            "1.1.0",
            "--wait-start",
            "77",
            "--wait-pid",
            "42",
            "--",
            "--version",
            "x",
        ]))
        .expect("parse");
        let Mode::Apply(a) = got else {
            panic!("not apply");
        };
        assert_eq!(
            a.wait,
            ProcessId {
                pid: 42,
                start_ticks: 77
            }
        );
        assert_eq!(a.version.to_string(), "1.1.0");
        assert_eq!(a.restart, os(&["--version", "x"]));
        assert!(!a.no_ui);
        let got = parse(&os(&[
            "apply",
            "--no-ui",
            "--version",
            "1.1.0",
            "--wait-start",
            "77",
            "--wait-pid",
            "42",
            "--",
            "--no-ui",
        ]))
        .expect("parse");
        let Mode::Apply(a) = got else {
            panic!("not apply");
        };
        assert!(a.no_ui);
        assert!(!a.background);
        assert_eq!(a.restart, os(&["--no-ui"]));
        let got = parse(&os(&[
            "apply",
            "--background",
            "--version",
            "1.1.0",
            "--wait-start",
            "77",
            "--wait-pid",
            "42",
            "--",
            "--background",
        ]))
        .expect("parse");
        let Mode::Apply(a) = got else {
            panic!("not apply");
        };
        assert!(a.background && !a.no_ui);
        assert_eq!(a.restart, os(&["--background"]));
    }

    #[test]
    fn every_malformed_command_line_is_a_usage_error() {
        let base = ["--wait-pid", "1", "--wait-start", "2", "--version", "1.0.0"];
        let ok = |extra: &[&str]| {
            let mut v = vec!["apply"];
            v.extend_from_slice(&base);
            v.extend_from_slice(extra);
            os(&v)
        };
        assert!(parse(&ok(&[])).is_ok());
        let bad: Vec<Vec<OsString>> = vec![
            os(&[]),
            os(&["Apply"]),
            os(&["install", "--root"]),
            os(&["install", "/tmp/r"]),
            os(&["uninstall", "--"]),
            os(&["uninstall", "/tmp/r"]),
            os(&["Uninstall"]),
            os(&["apply"]),
            ok(&["--wait-pid", "3"]),
            ok(&["--json"]),
            ok(&["--no-ui", "--no-ui"]),
            ok(&["--no-ui=1"]),
            ok(&["--no-ui", "1"]),
            ok(&["--background", "--background"]),
            ok(&["--background=1"]),
            ok(&["--background", "1"]),
            os(&["install", "--background"]),
            os(&["uninstall", "--background"]),
            os(&["install", "--silent", "--silent"]),
            os(&["install", "--silent=1"]),
            os(&["install", "--silent", "x"]),
            os(&["install", "--Silent"]),
            os(&["uninstall", "--silent", "--silent"]),
            os(&["uninstall", "--silent=yes"]),
            os(&["uninstall", "--no-ui"]),
            ok(&["extra"]),
            os(&["apply", "--wait-pid", "1", "--wait-start", "2"]),
            os(&[
                "apply",
                "--wait-pid",
                "0",
                "--wait-start",
                "2",
                "--version",
                "1.0.0",
            ]),
            os(&[
                "apply",
                "--wait-pid",
                "+1",
                "--wait-start",
                "2",
                "--version",
                "1.0.0",
            ]),
            os(&[
                "apply",
                "--wait-pid",
                "01",
                "--wait-start",
                "2",
                "--version",
                "1.0.0",
            ]),
            os(&[
                "apply",
                "--wait-pid",
                "1",
                "--wait-start",
                "-2",
                "--version",
                "1.0.0",
            ]),
            os(&[
                "apply",
                "--wait-pid",
                "4294967296",
                "--wait-start",
                "2",
                "--version",
                "1.0.0",
            ]),
            os(&[
                "apply",
                "--wait-pid",
                "1",
                "--wait-start",
                "2",
                "--version",
                "v1.0.0",
            ]),
            os(&[
                "apply",
                "--wait-pid",
                "1",
                "--wait-start",
                "2",
                "--version",
                "1.0",
            ]),
            os(&[
                "apply",
                "--wait-pid=1",
                "--wait-start",
                "2",
                "--version",
                "1.0.0",
            ]),
            os(&["apply", "--wait-pid", "1", "--wait-start", "2", "--version"]),
        ];
        for args in bad {
            assert_eq!(parse(&args), Err(UsageError), "{args:?}");
        }
    }

    #[test]
    fn install_and_uninstall_take_only_silent() {
        assert_eq!(
            parse(&os(&["install"])),
            Ok(Mode::Install { silent: false })
        );
        assert_eq!(
            parse(&os(&["uninstall"])),
            Ok(Mode::Uninstall { silent: false })
        );
        assert_eq!(
            parse(&os(&["install", "--silent"])),
            Ok(Mode::Install { silent: true })
        );
        assert_eq!(
            parse(&os(&["uninstall", "--silent"])),
            Ok(Mode::Uninstall { silent: true })
        );
    }

    #[test]
    fn slash_s_is_silent_for_setup_and_uninstall_on_windows_only() {
        let s = os(&["/S"]);
        let uninstall = parse(&os(&["uninstall", "/S"]));
        if cfg!(windows) {
            assert_eq!(parse_setup(&s), Ok(true));
            assert_eq!(uninstall, Ok(Mode::Uninstall { silent: true }));
        } else {
            assert_eq!(parse_setup(&s), Err(UsageError));
            assert_eq!(uninstall, Err(UsageError));
        }
        assert_eq!(parse_setup(&os(&["--silent"])), Ok(true));
        assert_eq!(parse_setup(&os(&[])), Ok(false));
        for bad in [
            &["/s"][..],
            &["/S", "/S"],
            &["/S", "--silent"],
            &["--silent", "/S"],
            &["/Silent"],
            &["S"],
        ] {
            assert_eq!(parse_setup(&os(bad)), Err(UsageError), "{bad:?}");
            let mut args = vec!["uninstall"];
            args.extend_from_slice(bad);
            assert_eq!(parse(&os(&args)), Err(UsageError), "{bad:?}");
        }
        // `install` keeps `--silent` only.
        assert_eq!(parse(&os(&["install", "/S"])), Err(UsageError));
    }

    #[test]
    fn the_hand_off_grammar_is_windows_only_and_closed() {
        let good = os(&[
            "uninstall",
            "--wait-start",
            "2",
            "--install-root",
            r"C:\Users\a\Programs\App",
            "--wait-pid",
            "1",
            "/S",
        ]);
        let parsed = parse(&good);
        if !cfg!(windows) {
            assert_eq!(parsed, Err(UsageError));
            return;
        }
        let Ok(Mode::UninstallHandOff(args)) = parsed else {
            panic!("not the hand-off");
        };
        assert_eq!(
            args.wait,
            ProcessId {
                pid: 1,
                start_ticks: 2
            }
        );
        assert!(args.silent);
        assert_eq!(
            args.install_root,
            std::path::PathBuf::from(r"C:\Users\a\Programs\App")
        );
        assert!(!format!("{args:?}").contains("Programs"), "a path in Debug");
        let base = [
            "--install-root",
            "R",
            "--wait-pid",
            "1",
            "--wait-start",
            "2",
        ];
        let with = |extra: &[&str]| {
            let mut v = vec!["uninstall"];
            v.extend_from_slice(&base);
            v.extend_from_slice(extra);
            os(&v)
        };
        assert!(matches!(
            parse(&with(&["--silent"])),
            Ok(Mode::UninstallHandOff(HandOffArgs { silent: true, .. }))
        ));
        let bad: Vec<Vec<OsString>> = vec![
            with(&["--silent", "/S"]),
            with(&["--install-root", "R"]),
            with(&["--wait-pid", "1"]),
            with(&["--version", "1.0.0"]),
            with(&["extra"]),
            os(&["uninstall", "--install-root", "R", "--wait-pid", "1"]),
            os(&["uninstall", "--install-root", "R", "--wait-start", "2"]),
            os(&[
                "uninstall",
                "--install-root",
                "",
                "--wait-pid",
                "1",
                "--wait-start",
                "2",
            ]),
            os(&[
                "uninstall",
                "--install-root",
                "R",
                "--wait-pid",
                "0",
                "--wait-start",
                "2",
            ]),
            os(&[
                "uninstall",
                "--install-root",
                "R",
                "--wait-pid",
                "01",
                "--wait-start",
                "2",
            ]),
            os(&[
                "uninstall",
                "--install-root",
                "R",
                "--wait-pid",
                "1",
                "--wait-start",
                "-2",
            ]),
            os(&["uninstall", "--install-root"]),
            os(&["uninstall", "--silent", "--install-root", "R"]),
        ];
        for args in bad {
            assert_eq!(parse(&args), Err(UsageError), "{args:?}");
        }
    }

    #[test]
    fn codes_and_names_are_unique() {
        let mut codes: Vec<u8> = Kind::ALL.iter().map(|k| k.code()).collect();
        let mut names: Vec<&str> = Kind::ALL.iter().map(|k| k.name()).collect();
        codes.sort_unstable();
        names.sort_unstable();
        codes.dedup();
        names.dedup();
        assert_eq!(codes.len(), Kind::ALL.len());
        assert_eq!(names.len(), Kind::ALL.len());
        assert_eq!(Kind::UpdateConfig.code(), 14);
        assert_eq!(Kind::RolledBack.code(), 20);
        assert_eq!(Kind::WaitTimeout.code(), 21);
        assert_eq!(Kind::RollbackUnavailable.code(), 22);
        assert_eq!(Kind::InUse.code(), 25);
        assert_eq!(Kind::InstallMismatch.code(), 26);
        assert_eq!(Kind::NoRelease.code(), 27);
        assert_eq!(Kind::of(&lunepack::Error::NoRelease), Kind::NoRelease);
        for place in Place::ALL {
            let kind = Kind::UnsupportedLocation(place);
            assert_eq!((kind.code(), kind.name()), (28, "unsupported_location"));
            assert_eq!(kind.reason(), Some(place.name()));
        }
        assert_eq!(Kind::Usage.reason(), None);
    }

    /// The rows `| <code> | `<kind>` | ... |` of the exit-code table in `docs/RUNTIME.md`.
    fn documented_codes() -> Vec<(u8, String)> {
        let doc = include_str!("../../../docs/RUNTIME.md");
        let table = doc
            .split("## Exit codes")
            .nth(1)
            .and_then(|rest| rest.split("\n## ").next())
            .expect("the exit-code section");
        table
            .lines()
            .filter_map(|line| {
                let mut cells = line.split('|').skip(1).map(str::trim);
                let code: u8 = cells.next()?.parse().ok()?;
                let kind = cells.next()?.trim_matches('`').to_owned();
                Some((code, kind))
            })
            .collect()
    }

    #[test]
    fn the_documented_exit_codes_are_the_code_table() {
        let documented = documented_codes();
        // Success is the one row with no kind name.
        let mut table: Vec<(u8, String)> = Kind::ALL
            .iter()
            .map(|k| {
                let name = if *k == Kind::Ok { "" } else { k.name() };
                (k.code(), name.to_owned())
            })
            .collect();
        table.sort();
        let mut doc = documented;
        doc.sort();
        assert_eq!(doc, table, "docs/RUNTIME.md and the code table differ");
    }

    #[test]
    fn every_kind_has_a_golden_error_object() {
        let golden = include_str!("../tests/golden/objects.jsonl");
        for kind in Kind::ALL.iter().filter(|k| **k != Kind::Ok) {
            // The object ends there, or goes on with its `reason` (kinds that have one).
            let want = format!("\"kind\":\"{}\",\"exit_code\":{}", kind.name(), kind.code());
            assert!(
                golden.lines().any(|l| l.ends_with(&format!("{want}}}"))
                    || l.contains(&format!("{want},\"reason\":"))),
                "no golden error object for kind {}",
                kind.name()
            );
        }
    }

    /// Every reason of exit 28 is a closed code of its own, and every core reason maps to one.
    #[test]
    fn every_location_reason_has_a_closed_code_and_a_golden_object() {
        use lunepack_core::LocationReason as R;
        let golden = include_str!("../tests/golden/objects.jsonl");
        for (core, place) in [
            (R::Translocated, Place::Translocated),
            (R::ReadOnly, Place::ReadOnly),
            (R::OtherVolume, Place::OtherVolume),
            (R::NotOwned, Place::NotOwned),
            (R::NotWritable, Place::NotWritable),
        ] {
            assert_eq!(Place::of(core), Some(place));
            assert_eq!(
                core.as_str(),
                place.name(),
                "the core's code and ours agree"
            );
            let want = format!(
                "\"kind\":\"unsupported_location\",\"exit_code\":28,\"reason\":\"{}\"}}",
                place.name()
            );
            assert!(
                golden.lines().any(|l| l.ends_with(&want)),
                "{}",
                place.name()
            );
            assert_eq!(
                Kind::of(&lunepack::Error::UnsupportedLocation { reason: core }),
                Kind::UnsupportedLocation(place)
            );
        }
    }

    /// Every reason of exit 29 is a closed code, maps from the facade's error, and has a golden
    /// object; the reasons are exactly the refusals the core's policy table can make.
    #[test]
    fn every_publisher_reason_has_a_closed_code_and_a_golden_object() {
        use lunepack::{PublisherError, PublisherPolicy};
        let golden = include_str!("../tests/golden/objects.jsonl");
        for reason in PUBLISHER_REASONS {
            let want = format!(
                "\"kind\":\"publisher_mismatch\",\"exit_code\":29,\"reason\":\"{}\"}}",
                reason.code()
            );
            assert!(
                golden.lines().any(|l| l.ends_with(&want)),
                "{}",
                reason.code()
            );
            assert_eq!(
                Kind::of(&lunepack::Error::PublisherMismatch { reason }),
                Kind::PublisherMismatch(reason)
            );
            assert_eq!(Kind::PublisherMismatch(reason).code(), 29);
        }
        // The refusals `enforce` makes over every check result are exactly these reasons.
        let mut refused: Vec<&str> = [
            Ok(true),
            Ok(false),
            Err(PublisherError::InstalledUnsigned),
            Err(PublisherError::InstalledInvalid),
            Err(PublisherError::CandidateUnsigned),
            Err(PublisherError::CandidateInvalid),
            Err(PublisherError::NotApplicable),
            Err(PublisherError::Os),
        ]
        .into_iter()
        .filter_map(
            |r| match lunepack_core::codesign::decide(PublisherPolicy::Enforce, r) {
                lunepack_core::codesign::Decision::Refuse { reason, .. } => Some(reason.code()),
                lunepack_core::codesign::Decision::Proceed(_) => None,
            },
        )
        .collect();
        let mut listed: Vec<&str> = PUBLISHER_REASONS.iter().map(|r| r.code()).collect();
        refused.sort_unstable();
        listed.sort_unstable();
        assert_eq!(refused, listed);
    }

    #[test]
    fn the_documented_commands_are_the_parsed_ones() {
        let doc = include_str!("../../../docs/RUNTIME.md");
        for name in [
            "check",
            "download",
            "startup",
            "confirm",
            "apply-and-restart",
        ] {
            assert!(crate::cli::args::Command::named(name).is_some(), "{name}");
            assert!(
                doc.contains(&format!("| `{name}` |")),
                "{name} is not in the command table of docs/RUNTIME.md"
            );
        }
        for name in ["apply", "install", "uninstall"] {
            assert!(
                doc.contains(&format!("`{name}")),
                "{name} is not in docs/RUNTIME.md"
            );
        }
    }
}
