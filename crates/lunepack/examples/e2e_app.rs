//! The Rust app of the end-to-end suite (M5-D13), and a worked example of an app that updates
//! itself through the library.
//!
//! At every start it calls [`lunepack::startup`] first, then acts on a marker file in its own
//! tree, `e2e-flags` at the tree's root, one directive per line:
//!
//! - `crash-on-start`: exit 3 without confirming;
//! - `exit-without-confirm`: exit 0 without confirming;
//! - `slow-confirm <secs>`: sleep that long before confirming.
//!
//! Then it confirms its health. Two arguments serve the Windows suite (`scripts/e2e-windows.ps1`):
//! `--hold <secs>` keeps the process alive that long (writing `hold` first), so a running image
//! can be replaced or collected around it, and `--check <n>` runs the sibling runtime's
//! `check --json` `n` times with default `std::process::Command` flags and writes `check-run
//! <exit code>` after each, to see that the runtime opens no console of its own; `--aumid`
//! writes `aumid <id>` with the process's explicit app user model id (Windows; `aumid none` when
//! it has none or off Windows), which the suite compares with the Start-menu shortcut's. With
//! `--update` it checks the feed, downloads and stages what it
//! finds and hands it to the runtime with [`lunepack::apply_and_restart`], passing
//! `--after-update` as the restart argument; with `--no-ui` as well, the applier shows no
//! window ([`lunepack::UiChoice::Never`]).
//!
//! The per-machine suite (`scripts/e2e-windows-machine.ps1`, M10 step 19) adds three things.
//! `--stage-after <file>` (with `--update`) stops between the download and the stage and waits
//! until that file exists, so the suite can change what the download holds before the upload.
//! The environment variable `LUNEPACK_E2E_NO_CONFIRM`, set to the version of a tree, makes the app
//! of that tree exit without confirming exactly as the flag `exit-without-confirm` does, for the
//! runs of one process tree the suite starts it in (the flag is in the tree for every start). And, on Windows only,
//! `--service-probe <case>` talks to the install's update service with the core's protocol
//! client, on its own, to put what no library call would send in front of it:
//!
//! - `garbage`: 96 bytes of garbage in place of the hello (the connection must be closed), then a
//!   hello and a `status` (the service keeps serving);
//! - `oversize`: a hello, then a frame header of 2 MiB (closed), then a hello and a `status`;
//! - `wrong-token`: `confirm` and `rollback` of the pending version with a token that is not its
//!   own (both must answer `token_mismatch`), then a `status` that shows the same attempts;
//! - `status`: the `status` answer;
//! - `stage-docs <dir>`: `stage_begin` with the documents in `<dir>`, which the suite assembles
//!   (`root-<n>.json` files in numeric order, `keys.json`, `feed.json`, `manifest.json`): the
//!   service's answer, as one word.
//!
//! A probe writes `probe <case> <word> ...` lines; versions, closed words and counts only.
//!
//! The harness names two files in the environment. `LUNEPACK_E2E_OUT` gets one line per outcome,
//! `<tree version> <outcome>`: versions and outcomes only, so the suite can compare runs of
//! different apps. `LUNEPACK_E2E_DETAIL` gets facts that differ by app (the executable's real
//! path). Neither is written when its variable is unset.
//!
//! A failure prints nothing and writes `<version> error <stage>` to the outcome file.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use lunepack::{
    ApplyOptions, CancelToken, ConfirmOutcome, DownloadOptions, Installation, LifecycleEvent,
    StartupAction, blocking,
};

const OUT_VAR: &str = "LUNEPACK_E2E_OUT";
const DETAIL_VAR: &str = "LUNEPACK_E2E_DETAIL";
const FLAGS_FILE: &str = "e2e-flags";
const AFTER_UPDATE: &str = "--after-update";

/// Appends one line to the file `var` names (one `write`, so concurrent processes interleave
/// whole lines).
fn note(var: &str, line: &str) {
    let Some(path) = std::env::var_os(var) else {
        return;
    };
    let mut line = line.to_owned();
    line.push('\n');
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = file.write_all(line.as_bytes());
    }
}

/// What the marker file asks for.
#[derive(Default)]
struct Flags {
    crash: bool,
    exit_without_confirm: bool,
    slow_confirm: Option<u64>,
    /// `hold <secs>`: stay alive that long after confirming (macOS rows read `ps` meanwhile).
    hold: Option<u64>,
}

fn read_flags(tree: &Path) -> Flags {
    let mut flags = Flags::default();
    // A macOS bundle keeps the marker under `Contents/Resources` (a file at the bundle's root
    // would break a signature's seal).
    let text = std::fs::read_to_string(tree.join(FLAGS_FILE))
        .or_else(|_| std::fs::read_to_string(tree.join("Contents/Resources").join(FLAGS_FILE)));
    let Ok(text) = text else {
        return flags;
    };
    for line in text.lines() {
        let mut words = line.split_whitespace();
        match (words.next(), words.next()) {
            (Some("crash-on-start"), None) => flags.crash = true,
            (Some("exit-without-confirm"), None) => flags.exit_without_confirm = true,
            (Some("slow-confirm"), Some(secs)) => flags.slow_confirm = secs.parse().ok(),
            (Some("hold"), Some(secs)) => flags.hold = secs.parse().ok(),
            _ => {}
        }
    }
    flags
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let started = lunepack::startup();
    let Ok(inst) = Installation::from_current_exe() else {
        note(OUT_VAR, "- error locate");
        return ExitCode::from(1);
    };
    let version = inst.tree_version().to_string();
    let out = |line: &str| note(OUT_VAR, &format!("{version} {line}"));
    let Ok(startup) = started else {
        out("error startup");
        return ExitCode::from(1);
    };
    if let Ok(exe) = std::env::current_exe() {
        note(DETAIL_VAR, &format!("{version} exe {}", exe.display()));
    }
    out("start");
    if args.iter().any(|a| a == AFTER_UPDATE) {
        out("arg after-update");
    }
    for event in &startup.events {
        match event {
            LifecycleEvent::Installed { .. } => out("event installed"),
            LifecycleEvent::FirstRun { .. } => out("event first_run"),
            LifecycleEvent::Updated { from, .. } => out(&format!("event updated {from}")),
        }
    }
    if startup.action == StartupAction::Exit {
        out("exit rolled-back");
        return ExitCode::SUCCESS;
    }

    let flags = read_flags(inst.tree_root());
    if flags.crash {
        out("crash");
        return ExitCode::from(3);
    }
    let no_confirm_here = std::env::var("LUNEPACK_E2E_NO_CONFIRM").is_ok_and(|v| v == version);
    if flags.exit_without_confirm || no_confirm_here {
        out("exit-without-confirm");
        return ExitCode::SUCCESS;
    }
    if let Some(secs) = flags.slow_confirm {
        out("slow-confirm");
        std::thread::sleep(Duration::from_secs(secs));
    }
    match lunepack::confirm_healthy() {
        Ok(ConfirmOutcome::Confirmed) => out("confirmed"),
        Ok(ConfirmOutcome::NothingPending) => out("nothing-pending"),
        Err(lunepack::Error::TokenMismatch) => {
            out("error token-mismatch");
            return ExitCode::from(1);
        }
        Err(_) => {
            out("error confirm");
            return ExitCode::from(1);
        }
    }

    // The macOS rows compare this with `ps` (the token must never be in an argv): it is noted
    // only when the row asks for it, and goes to the detail file, never to the outcome file.
    if std::env::var_os("LUNEPACK_E2E_NOTE_TOKEN").is_some() {
        let token = std::env::var("LUNEPACK_HEALTH_TOKEN").unwrap_or_default();
        note(DETAIL_VAR, &format!("{version} token {token}"));
    }
    if let Some(secs) = flags.hold {
        out("hold");
        std::thread::sleep(Duration::from_secs(secs));
    }
    if let Some(secs) = arg_value(&args, "--hold") {
        out("hold");
        std::thread::sleep(Duration::from_secs(secs));
    }
    if args.iter().any(|a| a == "--aumid") {
        out(&format!("aumid {}", process_aumid()));
    }
    if let Some(runs) = arg_value(&args, "--check") {
        check_runs(&inst, runs, &out);
    }
    if let Some(case) = arg_text(&args, "--service-probe") {
        return service_probe(&inst, &case, &args, &out);
    }
    if args.iter().any(|a| a == "--update") {
        let no_ui = args.iter().any(|a| a == "--no-ui");
        let background = args.iter().any(|a| a == "--background");
        let stage_after = arg_text(&args, "--stage-after").map(std::path::PathBuf::from);
        return match update(&inst, no_ui, background, stage_after.as_deref()) {
            Ok(line) => {
                out(&line);
                ExitCode::SUCCESS
            }
            Err(stage) => {
                out(&format!("error {stage}"));
                ExitCode::from(1)
            }
        };
    }
    ExitCode::SUCCESS
}

/// This process's explicit app user model id (set by [`lunepack::startup`]), `none` when it has
/// none; `error` when the system cannot say.
#[cfg(windows)]
fn process_aumid() -> String {
    match lunepack_os_windows::process_aumid() {
        Ok(Some(id)) => id,
        Ok(None) => "none".to_owned(),
        Err(_) => "error".to_owned(),
    }
}

/// Only Windows has an app user model id.
#[cfg(not(windows))]
fn process_aumid() -> String {
    "none".to_owned()
}

/// The text that follows `flag` among `args`.
fn arg_text(args: &[OsString], flag: &str) -> Option<String> {
    let at = args.iter().position(|a| a == flag)?;
    args.get(at + 1)?.to_str().map(str::to_owned)
}

/// The number that follows `flag` among `args`.
fn arg_value(args: &[OsString], flag: &str) -> Option<u64> {
    let at = args.iter().position(|a| a == flag)?;
    args.get(at + 1)?.to_str()?.parse().ok()
}

/// Runs the runtime beside the entry `runs` times with `check --json`, all default process flags
/// (so a runtime that was a console program would open a console of its own when this app has
/// none; the suite starts it with no console), and writes each exit code.
fn check_runs(inst: &Installation, runs: u64, out: &dyn Fn(&str)) {
    let name = if cfg!(windows) {
        "lunepack-runtime.exe"
    } else {
        "lunepack-runtime"
    };
    let Some(dir) = inst.entry_path().parent().map(Path::to_path_buf) else {
        out("error check-run");
        return;
    };
    // The control of the Windows suite's console check: a console program started the same way
    // by an app that has no console (a ping, a console program) gets a console host of its own, which the suite's sampler
    // must see (else it proves nothing about the runtime).
    #[cfg(windows)]
    let control = std::process::Command::new("ping.exe")
        .args(["-n", "4", "127.0.0.1"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok();
    for _ in 0..runs {
        let code = std::process::Command::new(dir.join(name))
            .args(["check", "--json"])
            .output()
            .ok()
            .and_then(|output| output.status.code());
        out(&format!(
            "check-run {}",
            code.map_or_else(|| "none".to_owned(), |c| c.to_string())
        ));
    }
    #[cfg(windows)]
    if let Some(mut control) = control {
        let _ = control.wait();
    }
}

/// Check, download, stage and hand over. Returns the last outcome line; the earlier ones are
/// written on the way.
fn update(
    inst: &Installation,
    no_ui: bool,
    background: bool,
    stage_after: Option<&Path>,
) -> Result<String, &'static str> {
    let version = inst.tree_version().to_string();
    let out = |line: &str| note(OUT_VAR, &format!("{version} {line}"));
    let builder = inst.updater_builder().map_err(|_| "builder")?;
    let updater = blocking::Updater::from(builder.build().map_err(|_| "builder")?);
    let cancel = CancelToken::new();
    let Some(info) = updater.check(&cancel).map_err(|_| "check")? else {
        return Ok("check none".to_owned());
    };
    out(&format!("check {}", info.version()));
    let downloaded = updater
        .download(&info, DownloadOptions::default(), &cancel)
        .map_err(|_| "download")?;
    if let Some(file) = stage_after {
        // The suite changes what the download holds, then creates this file.
        out("downloaded");
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        while !file.exists() {
            if std::time::Instant::now() > deadline {
                return Err("stage-wait");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    let staged = updater.stage(downloaded, &cancel).map_err(|_| "stage")?;
    out(&format!("staged {}", staged.version()));
    lunepack::apply_and_restart(ApplyOptions {
        expect_version: Some(staged.version().clone()),
        wait_for: None,
        restart_args: vec![OsString::from(AFTER_UPDATE)],
        ui: if no_ui {
            lunepack::UiChoice::Never
        } else {
            lunepack::UiChoice::Auto
        },
        background,
    })
    .map_err(|_| "apply")?;
    Ok("apply-scheduled".to_owned())
}

// ---- the service probe (Windows) ------------------------------------------------------------

/// Only Windows has an update service.
#[cfg(not(windows))]
fn service_probe(_: &Installation, _: &str, _: &[OsString], out: &dyn Fn(&str)) -> ExitCode {
    out("probe unsupported");
    ExitCode::from(1)
}

/// What a probe says of a failed request: the service's own word, or the kind of failure.
#[cfg(windows)]
fn failure_word(e: &lunepack_core::ServiceError) -> String {
    use lunepack_core::ServiceError;
    match e {
        ServiceError::Answered {
            code,
            class: Some(class),
        } => format!("{} {}", code.as_str(), class.as_str()),
        ServiceError::Answered { code, class: None } => code.as_str().to_owned(),
        ServiceError::Closed => "closed".to_owned(),
        ServiceError::Timeout => "timeout".to_owned(),
        ServiceError::Io(_) => "io".to_owned(),
        _ => "other".to_owned(),
    }
}

/// Probes the service of the running install (see the head of this file).
#[cfg(windows)]
fn service_probe(
    inst: &Installation,
    case: &str,
    args: &[OsString],
    out: &dyn Fn(&str),
) -> ExitCode {
    use lunepack_core::service::{
        ClientSession, ClientTimeouts, DocumentKind, OutgoingDocument, StageBegun, Token,
    };
    use lunepack_core::{Channel, ServiceConnector as _};
    use std::io::{Read as _, Write as _};

    let connector = lunepack_os_windows::WindowsConnector::new();
    let timeouts = ClientTimeouts {
        hello: Some(Duration::from_secs(15)),
        answer: Some(Duration::from_secs(60)),
    };
    let app = inst.app_id().clone();
    let session = || -> Result<_, String> {
        let io = connector
            .connect(&app)
            .map_err(|_| "connect-failed".to_owned())?;
        ClientSession::connect(io, app.clone(), timeouts).map_err(|e| failure_word(&e))
    };
    // A `status` on a fresh connection: the service still serves.
    let serving = || -> String {
        match session().and_then(|mut s| s.status().map_err(|e| failure_word(&e))) {
            Ok(_) => "serving".to_owned(),
            Err(word) => format!("not-serving {word}"),
        }
    };
    // Whether the service ends a connection whose peer sent `bytes` (after `io`'s hello, if any):
    // a read answers an error frame and then ends, or ends at once.
    let ends = |io: &mut Box<dyn lunepack_core::service::Duplex>| -> bool {
        let _ = io.set_read_deadline(Some(Duration::from_secs(20)));
        let mut buf = [0u8; 4096];
        for _ in 0..16 {
            match io.read(&mut buf) {
                Ok(0) | Err(_) => return true,
                Ok(_) => {}
            }
        }
        false
    };
    match case {
        "garbage" => {
            let Ok(mut io) = connector.connect(&app) else {
                out("probe garbage connect-failed");
                return ExitCode::from(1);
            };
            let _ = io.write_all(&[0xFF; 96]);
            let _ = io.flush();
            out(&format!("probe garbage closed={}", ends(&mut io)));
            drop(io);
            out(&format!("probe garbage {}", serving()));
        }
        "oversize" => {
            match session() {
                Ok(s) => {
                    let mut io = s.into_inner();
                    // A frame of kind `message` whose length says 2 MiB; no body follows.
                    let mut head = Vec::new();
                    head.extend_from_slice(&(((2u32 << 20) + 1).to_le_bytes()));
                    head.push(lunepack_core::service::KIND_MESSAGE);
                    let _ = io.write_all(&head);
                    let _ = io.flush();
                    out(&format!("probe oversize closed={}", ends(&mut io)));
                }
                Err(word) => out(&format!("probe oversize hello-failed {word}")),
            }
            out(&format!("probe oversize {}", serving()));
        }
        "wrong-token" => {
            let mut s = match session() {
                Ok(s) => s,
                Err(word) => {
                    out(&format!("probe wrong-token hello-failed {word}"));
                    return ExitCode::from(1);
                }
            };
            let before = s.status().ok();
            let Some(pending) = before.as_ref().and_then(|b| b.pending.as_ref()) else {
                out("probe wrong-token nothing-pending");
                return ExitCode::from(1);
            };
            let version = pending.version.clone();
            let attempts = pending.attempts;
            let wrong = Token::from_bytes([0x5A; 32]);
            let confirm = match s.confirm(&version, &wrong) {
                Ok(_) => "accepted".to_owned(),
                Err(e) => failure_word(&e),
            };
            out(&format!("probe wrong-token confirm {confirm}"));
            let rollback = match s.rollback(&version, &wrong) {
                Ok(_) => "accepted".to_owned(),
                Err(e) => failure_word(&e),
            };
            out(&format!("probe wrong-token rollback {rollback}"));
            // The same connection is still good after an answered error.
            match s.status() {
                Ok(after) => {
                    let same = after
                        .pending
                        .as_ref()
                        .is_some_and(|p| p.version == version && p.attempts == attempts);
                    out(&format!("probe wrong-token still-pending={same}"));
                }
                Err(e) => out(&format!("probe wrong-token status {}", failure_word(&e))),
            }
        }
        "status" => match session().and_then(|mut s| s.status().map_err(|e| failure_word(&e))) {
            Ok(st) => out(&format!(
                "probe status current={} pending={} staged={} service={} disabled={}",
                st.current,
                st.pending.as_ref().map_or_else(
                    || "none".to_owned(),
                    |p| format!("{}/{}", p.version, p.attempts)
                ),
                st.staged
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), ToString::to_string),
                st.service,
                st.self_update_disabled
            )),
            Err(word) => {
                out(&format!("probe status {word}"));
                return ExitCode::from(1);
            }
        },
        "stage-docs" => {
            let Some(dir) = arg_text(args, "--docs").map(std::path::PathBuf::from) else {
                out("probe stage-docs usage");
                return ExitCode::from(1);
            };
            let read = |name: &str| std::fs::read(dir.join(name)).ok();
            let mut roots: Vec<(u64, Vec<u8>)> = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for e in entries.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if let Some(n) = name
                        .strip_prefix("root-")
                        .and_then(|r| r.strip_suffix(".json"))
                        .and_then(|n| n.parse::<u64>().ok())
                        && let Ok(bytes) = std::fs::read(e.path())
                    {
                        roots.push((n, bytes));
                    }
                }
            }
            roots.sort_by_key(|(n, _)| *n);
            let (Some(keys), Some(feed), Some(manifest)) =
                (read("keys.json"), read("feed.json"), read("manifest.json"))
            else {
                out("probe stage-docs missing-documents");
                return ExitCode::from(1);
            };
            let mut docs: Vec<OutgoingDocument<'_>> = roots
                .iter()
                .map(|(_, bytes)| OutgoingDocument {
                    kind: DocumentKind::Root,
                    bytes,
                })
                .collect();
            for (kind, bytes) in [
                (DocumentKind::Keys, &keys),
                (DocumentKind::Feed, &feed),
                (DocumentKind::Manifest, &manifest),
            ] {
                docs.push(OutgoingDocument { kind, bytes });
            }
            let Ok(channel) = Channel::parse("stable") else {
                return ExitCode::from(1);
            };
            let word = match session() {
                Ok(mut s) => match s.stage_begin(&channel, &docs) {
                    Ok(StageBegun::Ready(v)) => format!("ready {v}"),
                    Ok(StageBegun::NoUpdate) => "no-update".to_owned(),
                    Err(e) => format!("refused {}", failure_word(&e)),
                },
                Err(word) => format!("hello-failed {word}"),
            };
            out(&format!("probe stage-docs {word}"));
        }
        _ => {
            out("probe unknown-case");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}
