//! The app-facing command line (C4, D42, M5-D11, M5-D12): `check`, `download`, `startup`,
//! `confirm` and `apply-and-restart`, run by any program as a child process. Each is a thin layer over the facade
//! ([`commands`]); [`execute`] is their one entry, and the only place that decides what is printed.
//!
//! Order of events, which the tests pin: the grammar is parsed first ([`args`]; a bad line is a
//! usage error with no lock, state read or request), then `--expect-schema` is checked, then the
//! tree is found, then the command runs. Whatever happens, exactly one final object ends the
//! output: a `result`, or an `error` of a closed kind with its exit code. Nothing printed holds an
//! argument value, a path, a URL, the health token or an error's own text.

pub mod args;
pub mod commands;
pub mod json;
pub mod progress;

use std::time::Duration;

use lunepack::{CancelToken, Installation, ProcessId, Version};

use self::args::Parsed;
use self::json::{Body, error_line, human_error, human_result, result_line};
use self::progress::{FinalLine, Output};
use crate::modes::{Adapters, Kind};

/// The one schema this build speaks (D28).
pub const SCHEMA: u64 = 1;
/// How long the process waits for its writer after the operation ends.
const DRAIN: Duration = Duration::from_secs(2);

/// The process `apply-and-restart` waits for, named by pid and start time when the runtime
/// started (C4: the parent by default, else `--wait-pid`), or the kind of error that says why it
/// cannot be waited for (`process`: pid 1, gone, a zombie, or unreadable).
pub type WaitTarget = Result<ProcessId, Kind>;

/// Runs a parsed command on `ad`, prints its output and returns the exit kind. `wait` is the
/// wait target of `apply-and-restart`, `None` for the other commands.
pub fn execute(ad: &Adapters, parsed: &Parsed, wait: Option<WaitTarget>) -> Kind {
    execute_with(ad, parsed, wait, || {
        (Box::new(std::io::stdout()), Box::new(std::io::stderr()))
    })
}

/// [`execute`] over chosen output streams.
pub fn execute_with(
    ad: &Adapters,
    parsed: &Parsed,
    wait: Option<WaitTarget>,
    streams: impl FnOnce() -> (
        Box<dyn std::io::Write + Send>,
        Box<dyn std::io::Write + Send>,
    ),
) -> Kind {
    let cancel = CancelToken::new();
    let (stdout, stderr) = streams();
    let output = Output::start(stdout, stderr, parsed.json, cancel.clone());
    let command = parsed.command.name();

    let (tree, outcome) = run_checked(ad, parsed, &output, &cancel, wait);
    let (line, mut kind) = match &outcome {
        Ok(body) => {
            let tree = tree.as_ref();
            let text = match (tree, parsed.json) {
                (Some(t), true) => result_line(command, t, body),
                (_, false) => human_result(command, body),
                // A result always has a tree: it ran from one.
                (None, true) => error_line(Some(command), None, Kind::Internal),
            };
            (
                FinalLine {
                    text,
                    is_error: false,
                },
                Kind::Ok,
            )
        }
        Err(kind) => {
            let text = if parsed.json {
                error_line(Some(command), tree.as_ref(), *kind)
            } else {
                human_error(Some(command), *kind)
            };
            (
                FinalLine {
                    text,
                    is_error: true,
                },
                *kind,
            )
        }
    };
    let finished = output.finish(line, DRAIN);
    // A result the caller could not read is reported as cancelled: its next run starts again
    // from what the facade kept.
    if finished.stdout_failed && kind == Kind::Ok {
        kind = Kind::Cancelled;
    }
    kind
}

/// The schema check, the discovery and the command: the tree's version (when found) and the
/// command's result.
fn run_checked(
    ad: &Adapters,
    parsed: &Parsed,
    output: &Output,
    cancel: &CancelToken,
    wait: Option<WaitTarget>,
) -> (Option<Version>, Result<Body, Kind>) {
    if parsed.expect_schema.is_some_and(|n| n != SCHEMA) {
        return (None, Err(Kind::SchemaMismatch));
    }
    let inst = match Installation::from_current_exe_with(commands::platform(&ad.platform)) {
        Ok(inst) => inst,
        Err(e) => return (None, Err(Kind::of(&e))),
    };
    let tree = inst.tree_version().clone();
    (
        Some(tree),
        commands::run(&inst, parsed, output, cancel, wait),
    )
}
