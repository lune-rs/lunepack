//! The grammar of the app-facing commands (C4, M5-D11): `lunepack-runtime <command> [options]
//! [-- <args>]`, hand-written and closed.
//!
//! Global options: `--json` (a flag) and `--expect-schema <N>`. `check` and `download` take
//! `--channel <name>`; `download` and `apply-and-restart` take `--expect-version <version>`;
//! `apply-and-restart` takes `--wait-pid <pid>` (a pid above 1), the flag `--no-ui` (the
//! applier shows no update window) and the flag `--background` (the new version starts without
//! coming to the front; macOS only, accepted and without effect elsewhere, M8-D13); `startup` and
//! `apply-and-restart` take `-- <args>`.
//! Each option is allowed once, and anything else (an unknown name, a repeat, a value that does not
//! parse, a missing value, `=` forms, a stray word) is a [`UsageError`] that names nothing of
//! the arguments. Nothing happens before the whole line has been parsed.

use std::ffi::OsString;

use lunepack::{Channel, Version};

use crate::modes::{UsageError, decimal};

/// An app-facing command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Looks for an update.
    Check,
    /// Checks, then downloads and stages what it found.
    Download,
    /// The app's start: delivers the pending lifecycle events.
    Startup,
    /// The app confirms its health.
    Confirm,
    /// Hands the staged version to a detached applier, which applies it and restarts the app once
    /// the waited-for process has exited.
    ApplyAndRestart,
}

impl Command {
    /// The command's name, as typed and as it appears in results.
    pub const fn name(self) -> &'static str {
        match self {
            Command::Check => "check",
            Command::Download => "download",
            Command::Startup => "startup",
            Command::Confirm => "confirm",
            Command::ApplyAndRestart => "apply-and-restart",
        }
    }

    /// The command a first argument names.
    pub fn named(word: &str) -> Option<Command> {
        match word {
            "check" => Some(Command::Check),
            "download" => Some(Command::Download),
            "startup" => Some(Command::Startup),
            "confirm" => Some(Command::Confirm),
            "apply-and-restart" => Some(Command::ApplyAndRestart),
            _ => None,
        }
    }
}

/// A parsed app-facing command line.
#[derive(Clone, PartialEq, Eq)]
pub struct Parsed {
    /// The command.
    pub command: Command,
    /// Whether the output is JSON Lines.
    pub json: bool,
    /// The schema the caller expects, when it said.
    pub expect_schema: Option<u64>,
    /// The channel to follow instead of the config's.
    pub channel: Option<Channel>,
    /// The version the app expects `download` to fetch, or `apply-and-restart` to apply.
    pub expect_version: Option<Version>,
    /// The process `apply-and-restart` waits for instead of its parent: a pid above 1.
    pub wait_pid: Option<u32>,
    /// `--no-ui`: the applier `apply-and-restart` starts shows no update window (D41).
    pub no_ui: bool,
    /// `--background`: the applier starts the new version without bringing it to the front
    /// (M8-D13; macOS only).
    pub background: bool,
    /// The arguments after `--`: the app's own arguments (`startup`, which a rolled-back start
    /// passes on), or the arguments the new version is started with (`apply-and-restart`).
    pub passed_args: Vec<OsString>,
}

impl std::fmt::Debug for Parsed {
    /// Shows the number of startup arguments, not their values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Parsed")
            .field("command", &self.command)
            .field("json", &self.json)
            .field("expect_schema", &self.expect_schema)
            .field("channel", &self.channel.as_ref().map(ToString::to_string))
            .field(
                "expect_version",
                &self.expect_version.as_ref().map(ToString::to_string),
            )
            .field("wait_pid", &self.wait_pid)
            .field("no_ui", &self.no_ui)
            .field("background", &self.background)
            .field("passed_args", &self.passed_args.len())
            .finish()
    }
}

/// Whether `--json` stands before any `--`: then even a usage error is a JSON object.
pub fn wants_json(args: &[OsString]) -> bool {
    args.iter()
        .take_while(|a| *a != "--")
        .any(|a| a == "--json")
}

/// Parses the words after the command name.
pub fn parse(command: Command, rest: &[OsString]) -> Result<Parsed, UsageError> {
    let mut parsed = Parsed {
        command,
        json: false,
        expect_schema: None,
        channel: None,
        expect_version: None,
        wait_pid: None,
        no_ui: false,
        background: false,
        passed_args: Vec::new(),
    };
    let mut i = 0;
    while i < rest.len() {
        let name = rest[i].to_str().ok_or(UsageError)?;
        if name == "--" {
            if !matches!(command, Command::Startup | Command::ApplyAndRestart) {
                return Err(UsageError);
            }
            parsed.passed_args = rest[i + 1..].to_vec();
            break;
        }
        if name == "--json" {
            if parsed.json {
                return Err(UsageError);
            }
            parsed.json = true;
            i += 1;
            continue;
        }
        if name == "--no-ui" {
            if parsed.no_ui || command != Command::ApplyAndRestart {
                return Err(UsageError);
            }
            parsed.no_ui = true;
            i += 1;
            continue;
        }
        if name == "--background" {
            if parsed.background || command != Command::ApplyAndRestart {
                return Err(UsageError);
            }
            parsed.background = true;
            i += 1;
            continue;
        }
        let value = rest.get(i + 1).ok_or(UsageError)?;
        match name {
            "--expect-schema" if parsed.expect_schema.is_none() => {
                parsed.expect_schema = Some(decimal(value)?);
            }
            "--channel"
                if parsed.channel.is_none()
                    && matches!(command, Command::Check | Command::Download) =>
            {
                let text = value.to_str().ok_or(UsageError)?;
                parsed.channel = Some(Channel::parse(text).map_err(|_| UsageError)?);
            }
            "--expect-version"
                if parsed.expect_version.is_none()
                    && matches!(command, Command::Download | Command::ApplyAndRestart) =>
            {
                let text = value.to_str().ok_or(UsageError)?;
                let v = Version::parse(text).map_err(|_| UsageError)?;
                // Compared as text with the feed's, so only the canonical form is accepted.
                if v.to_string() != text {
                    return Err(UsageError);
                }
                parsed.expect_version = Some(v);
            }
            "--wait-pid" if parsed.wait_pid.is_none() && command == Command::ApplyAndRestart => {
                let pid: u32 = decimal(value)?;
                // 0 is no process, and 1 (init) never exits: neither can be waited for.
                if pid <= 1 {
                    return Err(UsageError);
                }
                parsed.wait_pid = Some(pid);
            }
            _ => return Err(UsageError),
        }
        i += 2;
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn options_parse_in_any_order() {
        let p = parse(
            Command::Download,
            &os(&[
                "--expect-version",
                "1.2.3",
                "--json",
                "--channel",
                "beta",
                "--expect-schema",
                "1",
            ]),
        )
        .expect("parse");
        assert!(p.json);
        assert_eq!(p.expect_schema, Some(1));
        assert_eq!(p.channel.expect("channel").to_string(), "beta");
        assert_eq!(p.expect_version.expect("version").to_string(), "1.2.3");
    }

    #[test]
    fn startup_takes_everything_after_the_separator() {
        let p = parse(
            Command::Startup,
            &os(&["--json", "--", "--json", "x", "--"]),
        )
        .expect("parse");
        assert!(p.json);
        assert_eq!(p.passed_args, os(&["--json", "x", "--"]));
    }

    #[test]
    fn apply_and_restart_takes_a_wait_pid_a_version_and_restart_args() {
        let p = parse(
            Command::ApplyAndRestart,
            &os(&[
                "--wait-pid",
                "4242",
                "--json",
                "--expect-version",
                "1.2.3",
                "--",
                "--wait-pid",
                "x",
            ]),
        )
        .expect("parse");
        assert!(p.json);
        assert_eq!(p.wait_pid, Some(4242));
        assert_eq!(p.expect_version.expect("version").to_string(), "1.2.3");
        assert_eq!(p.passed_args, os(&["--wait-pid", "x"]));
        assert!(!p.no_ui);
        let p = parse(Command::ApplyAndRestart, &[]).expect("parse");
        assert_eq!(p.wait_pid, None);
        assert!(p.passed_args.is_empty());
        assert!(!p.no_ui);
        let p = parse(
            Command::ApplyAndRestart,
            &os(&["--no-ui", "--json", "--", "--no-ui"]),
        )
        .expect("parse");
        assert!(p.no_ui);
        assert!(!p.background);
        assert_eq!(p.passed_args, os(&["--no-ui"]));
        // `--background` (M8-D13), alone or with `--no-ui`; after `--` it is the app's.
        let p = parse(
            Command::ApplyAndRestart,
            &os(&["--background", "--no-ui", "--", "--background"]),
        )
        .expect("parse");
        assert!(p.background && p.no_ui);
        assert_eq!(p.passed_args, os(&["--background"]));
        let p = parse(Command::ApplyAndRestart, &os(&["--", "--background"])).expect("parse");
        assert!(!p.background);
    }

    #[test]
    fn every_malformed_command_line_is_a_usage_error() {
        let bad: &[(Command, &[&str])] = &[
            (Command::Check, &["--json", "--json"]),
            (Command::Check, &["--channel", "a", "--channel", "b"]),
            (Command::Check, &["--channel"]),
            (Command::Check, &["--channel", "UPPER"]),
            (Command::Check, &["--channel", ""]),
            (Command::Check, &["--channel=stable"]),
            (Command::Check, &["--expect-version", "1.0.0"]),
            (Command::Check, &["extra"]),
            (Command::Check, &["--"]),
            (Command::Check, &["--", "x"]),
            (Command::Check, &["--unknown", "1"]),
            (Command::Check, &["--json=true"]),
            (Command::Check, &["--expect-schema"]),
            (Command::Check, &["--expect-schema", "x"]),
            (Command::Check, &["--expect-schema", "-1"]),
            (Command::Check, &["--expect-schema", "01"]),
            (
                Command::Check,
                &["--expect-schema", "1", "--expect-schema", "1"],
            ),
            (Command::Download, &["--expect-version", "v1.0.0"]),
            (Command::Download, &["--expect-version", "1.0"]),
            (Command::Download, &["--expect-version"]),
            (
                Command::Download,
                &["--expect-version", "1.0.0", "--expect-version", "1.0.0"],
            ),
            (Command::Startup, &["--channel", "stable"]),
            (Command::Startup, &["stray", "--"]),
            (Command::Confirm, &["--"]),
            (Command::Confirm, &["--channel", "stable"]),
            (Command::Confirm, &["--expect-version", "1.0.0"]),
            (Command::Confirm, &["--wait-pid", "42"]),
            (Command::Download, &["--wait-pid", "42"]),
            (Command::ApplyAndRestart, &["--wait-pid"]),
            (Command::ApplyAndRestart, &["--wait-pid", "0"]),
            (Command::ApplyAndRestart, &["--wait-pid", "1"]),
            (Command::ApplyAndRestart, &["--wait-pid", "-5"]),
            (Command::ApplyAndRestart, &["--wait-pid", "+5"]),
            (Command::ApplyAndRestart, &["--wait-pid", "05"]),
            (Command::ApplyAndRestart, &["--wait-pid", "4294967296"]),
            (Command::ApplyAndRestart, &["--wait-pid", "x"]),
            (Command::ApplyAndRestart, &["--wait-pid=5"]),
            (
                Command::ApplyAndRestart,
                &["--wait-pid", "5", "--wait-pid", "5"],
            ),
            (Command::ApplyAndRestart, &["--expect-version", "v1.0.0"]),
            (Command::ApplyAndRestart, &["--channel", "stable"]),
            (Command::ApplyAndRestart, &["stray"]),
            (Command::ApplyAndRestart, &["--no-ui", "--no-ui"]),
            (Command::ApplyAndRestart, &["--no-ui=1"]),
            (Command::ApplyAndRestart, &["--no-ui", "1"]),
            (Command::ApplyAndRestart, &["--background", "--background"]),
            (Command::ApplyAndRestart, &["--background=1"]),
            (Command::ApplyAndRestart, &["--background", "1"]),
            (Command::Check, &["--background"]),
            (Command::Download, &["--background"]),
            (Command::Startup, &["--background"]),
            (Command::Confirm, &["--background"]),
            (Command::Check, &["--no-ui"]),
            (Command::Download, &["--no-ui"]),
            (Command::Startup, &["--no-ui"]),
            (Command::Confirm, &["--no-ui"]),
        ];
        for (command, args) in bad {
            assert_eq!(parse(*command, &os(args)), Err(UsageError), "{args:?}");
        }
    }

    #[test]
    fn json_is_wanted_only_before_the_separator() {
        assert!(wants_json(&os(&["check", "--json"])));
        assert!(wants_json(&os(&["--json", "bogus"])));
        assert!(!wants_json(&os(&["startup", "--", "--json"])));
        assert!(!wants_json(&os(&["check"])));
    }
}
