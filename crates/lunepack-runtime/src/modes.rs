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

use lunepack::{Fs, Hasher, OsIntegration, Platform, Process, ProcessId, Rng, Version};

/// The line a usage error prints on stderr. It names no argument value.
pub const USAGE_LINE: &str = "lunepack-runtime: usage error";

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
    /// Anything else (a worker panic, a facade error this build does not know).
    Internal,
}

impl Kind {
    /// Every kind, in code order (for the golden of step 12).
    #[allow(dead_code)]
    pub const ALL: [Kind; 28] = [
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
            Kind::Internal => "internal",
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
}

impl std::fmt::Debug for ApplyArgs {
    /// Shows the number of restart arguments, not their values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplyArgs")
            .field("wait", &self.wait)
            .field("version", &self.version.to_string())
            .field("restart", &self.restart.len())
            .field("no_ui", &self.no_ui)
            .finish()
    }
}

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// `apply --wait-pid <u32> --wait-start <u64> --version <ver> [--no-ui] [-- <args>…]`.
    Apply(ApplyArgs),
    /// `install [--silent]`: the first install from the bootstrap tree this runtime belongs to.
    Install {
        /// `--silent`: no UI and no prompt (D41).
        silent: bool,
    },
    /// `uninstall [--silent]`: removes the install this runtime belongs to.
    Uninstall {
        /// `--silent`: no UI and no prompt (D41).
        silent: bool,
    },
    /// An app-facing command (`check`, `download`, `startup`, `confirm`).
    Command(crate::cli::args::Parsed),
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
        Some("uninstall") => silent_only(rest).map(|silent| Mode::Uninstall { silent }),
        Some(word) => match crate::cli::args::Command::named(word) {
            Some(command) => crate::cli::args::parse(command, rest).map(Mode::Command),
            None => Err(UsageError),
        },
        None => Err(UsageError),
    }
}

/// The options of `install` and `uninstall`: nothing, or `--silent` once.
fn silent_only(rest: &[OsString]) -> Result<bool, UsageError> {
    match rest {
        [] => Ok(false),
        [flag] if flag == "--silent" => Ok(true),
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
        assert_eq!(a.restart, os(&["--no-ui"]));
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
            let want = format!(
                "\"kind\":\"{}\",\"exit_code\":{}}}",
                kind.name(),
                kind.code()
            );
            assert!(
                golden.lines().any(|l| l.ends_with(&want)),
                "no golden error object for kind {}",
                kind.name()
            );
        }
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
