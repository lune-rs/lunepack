//! The runtime's UI host (M6 step 4) against a fake UI process, with real processes and pipes.
//!
//! Own `main` (see Cargo.toml): this test binary is also the fake UI (first argument `--engine`)
//! and, for `apply`, the app (`helper-app`). A case places a `lunepack-ui` wrapper script beside a
//! runtime; the script starts this binary as the UI with the behaviour the case names
//! (`LUNEPACK_FAKE_UI`, a comma list, below) and the directory it notes what it saw in. The fake UI
//! speaks the real frame codec of `lunepack_core::ui`.
//!
//! Two kinds of cases:
//!
//! - **host** cases drive `UiHost` itself (the source file compiled into this test) with lowered
//!   bounds: a UI that is absent, exits at once with each typed code, never says hello, says hello
//!   with another build id, writes garbage or an oversize frame, sends a choice for no prompt,
//!   stops reading or stops answering `Ping` at an open prompt, or stops reading while frames
//!   flow; and that the host never blocks and always ends in bounded time;
//! - **runtime** cases run the built `lunepack-runtime` (`install`, `uninstall`, `apply`) with the
//!   real bounds: a well-behaved UI choosing proceed, retry, finish with launch and reveal; a UI
//!   killed at the welcome or confirm prompt, mid-install or mid-apply; one that stops reading
//!   mid-run or hangs at the rolled-back prompt; `--silent`, `--no-ui`, `LUNEPACK_NO_UI` and no
//!   display. Each checks that the outcome and exit code are the headless run's (or `cancelled`
//!   at a prompt before any change), and the launched or relaunched app holds none of the UI's
//!   pipes.
//!
//! The cases run in parallel, each in its own directory. Linux and Windows (M7 step 10). On
//! Windows the fake UI is this binary hard-linked as `lunepack-ui.exe` with its script in a file
//! beside it (no shell wrapper), the host cases and the `apply` cases run, and the cases that need
//! a shell script app, procfs, or a data home a test can redirect (`install`, `uninstall`: the
//! data home on Windows is the shell's known folder) are listed in `LINUX_ONLY` with their reason;
//! the Windows E2E (step 13) covers them against a real install.
// The Linux-only cases stay compiled on Windows (their helpers are shared), so some are unused.
#![cfg_attr(windows, allow(dead_code, unused_imports))]

#[cfg(any(target_os = "linux", windows))]
#[allow(dead_code)]
#[path = "../src/events.rs"]
mod events;

#[cfg(any(target_os = "linux", windows))]
#[allow(dead_code, unused_imports)]
#[path = "../src/ui_host.rs"]
mod ui_host;

#[cfg(any(target_os = "linux", windows))]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--engine") => native::fake_ui(),
        Some(native::HELPER_ARG) => native::helper_app(),
        Some(native::SLEEP_ARG) => native::sleep(&args[1..]),
        _ => native::run_all(&args),
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn main() {
    println!("lunepack-runtime ui_host tests: Linux and Windows only, skipped");
}

#[cfg(any(target_os = "linux", windows))]
mod native {
    use std::io::{Read, Write};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Output, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use lunepack::{
        HEALTH_TOKEN_VAR, InstallMeta, Phase, Process, ProcessId, Progress, RelPath, Target,
        TrustedRoot, UpdateConfig, Version,
    };
    use lunepack_core::state::{InstallState, Scope, StagedRef, UserScope};
    use lunepack_core::ui::{
        self, ChoiceValue, Details, EngineMsg, Flow, Outcome, PromptKind, UiMsg,
    };
    use lunepack_core::{
        AppId, Channel, CodecId, EncodedFrame, Encoder, Hasher, LayoutScheme, PayloadKind,
        ReleaseLayout, Signer, U53, UserLayout, pack_file,
    };
    use lunepack_crypto::{Ed25519Signer, Ed25519Verifier, Sha256Hasher, generate_key_file};
    use lunepack_fs::StdFs;
    #[cfg(target_os = "linux")]
    use lunepack_os_linux::LinuxProcess as NativeProcess;
    #[cfg(windows)]
    use lunepack_os_windows::WindowsProcess as NativeProcess;
    use lunepack_testkit::{ChainFixture, FakeCodec, SUITE_APP_ID, SUITE_CHANNEL};

    use crate::events::{Event, Events, Sink, SinkFailed, to_json_line};
    use crate::ui_host::{self, Bounds, Start, UiHost, UiStop};

    pub const HELPER_ARG: &str = "helper-app";
    /// A helper mode of this binary: `sleep-for <seconds>`, a process to wait for.
    pub const SLEEP_ARG: &str = "sleep-for";
    /// The layout scheme of this OS (what the runtime's platform picks).
    #[cfg(windows)]
    const SCHEME: LayoutScheme = LayoutScheme::WINDOWS;
    #[cfg(not(windows))]
    const SCHEME: LayoutScheme = LayoutScheme::XDG;
    #[cfg(windows)]
    const RUNTIME_FILE: &str = "lunepack-runtime.exe";
    #[cfg(not(windows))]
    const RUNTIME_FILE: &str = "lunepack-runtime";

    /// An entry path as this OS names an executable (`bin/app` is `bin/app.exe` on Windows).
    fn exe(entry: &str) -> String {
        if cfg!(windows) {
            format!("{entry}.exe")
        } else {
            entry.to_owned()
        }
    }

    const FAKE_VAR: &str = "LUNEPACK_FAKE_UI";
    const OUT_VAR: &str = "LUNEPACK_FAKE_UI_OUT";
    const RUNTIME: &str = env!("CARGO_BIN_EXE_lunepack-runtime");
    const V100: &str = "1.0.0";
    const V110: &str = "1.1.0";
    const BIN: &str = "lp-ui-test";
    const DAY: u64 = 86_400;
    const INSTALL_ID: [u8; 16] = [3; 16];
    /// A bound on any one runtime run.
    const RUN_LIMIT: Duration = Duration::from_secs(90);

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const TARGET: Target = Target::LinuxAarch64;
    #[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
    const TARGET: Target = Target::LinuxX86_64;
    #[cfg(all(windows, target_arch = "aarch64"))]
    const TARGET: Target = Target::WindowsAarch64;
    #[cfg(all(windows, not(target_arch = "aarch64")))]
    const TARGET: Target = Target::WindowsX86_64;

    /// The cases (by name prefix) that need a Linux-only mechanism, each with why; they are
    /// skipped on Windows.
    #[cfg(windows)]
    const LINUX_ONLY: &[(&str, &str)] = &[
        (
            "install_",
            "the data home is the shell's known folder, which a test cannot redirect",
        ),
        (
            "uninstall_",
            "the data home is the shell's known folder; the uninstall hand-off is step 11",
        ),
    ];

    // ---- the fake UI ------------------------------------------------------------------------

    /// One fake UI's behaviour, from `LUNEPACK_FAKE_UI`: comma-separated directives.
    ///
    /// - `exit=N`: exit at once with N;
    /// - `nohello`: never send hello (keeps reading);
    /// - `build=X`: say hello with build id X;
    /// - `garbage`, `oversize`: write bytes that are not a frame, or a length over the cap,
    ///   instead of hello;
    /// - `stray`: after hello, send a choice for a prompt that is not open;
    /// - `nopong`: never answer `Ping`;
    /// - `stop@T`, `die@T`: at trigger T stop reading (sleep for good), or abort; T is `start`
    ///   (before reading anything), `hello`, `progress` (the first progress frame) or
    ///   `prompt:<Kind>`;
    /// - `answers=a+b+…`: the answers to the prompts in order (`proceed`, `cancel`, `finish`,
    ///   `launch`, `retry`, `close`, `ack`, `reveal0`; a `reveal0` is followed by the next answer
    ///   for the same prompt); past the list, the headless answer;
    /// - `delay=MS`: wait this long before answering a prompt (pings are answered meanwhile);
    /// - `fix=PATH`: remove PATH before answering `retry`;
    /// - `expect=PATH`: at each prompt, note whether a process runs with PATH as its executable.
    #[derive(Default)]
    struct Script {
        exit: Option<i32>,
        nohello: bool,
        build: Option<String>,
        garbage: bool,
        oversize: bool,
        stray: bool,
        nopong: bool,
        stop_at: Option<String>,
        die_at: Option<String>,
        answers: Vec<String>,
        delay: Duration,
        fix: Option<PathBuf>,
        expect: Option<PathBuf>,
    }

    /// A file beside this executable (the fake UI's script and notes directory when its
    /// environment cannot carry them: Windows has no wrapper script).
    fn beside(name: &str) -> Option<String> {
        let exe = std::env::current_exe().ok()?;
        std::fs::read_to_string(exe.parent()?.join(name)).ok()
    }

    fn script() -> Script {
        let text = std::env::var(FAKE_VAR)
            .ok()
            .or_else(|| beside("fake-ui.spec"))
            .unwrap_or_default();
        let mut s = Script::default();
        for item in text.split(',').filter(|i| !i.is_empty()) {
            let (key, value) = item.split_once('=').unwrap_or((item, ""));
            match key {
                "exit" => s.exit = Some(value.parse().expect("code")),
                "nohello" => s.nohello = true,
                "build" => s.build = Some(value.to_owned()),
                "garbage" => s.garbage = true,
                "oversize" => s.oversize = true,
                "stray" => s.stray = true,
                "nopong" => s.nopong = true,
                "delay" => s.delay = Duration::from_millis(value.parse().expect("ms")),
                "answers" => s.answers = value.split('+').map(str::to_owned).collect(),
                "fix" => s.fix = Some(PathBuf::from(value)),
                "expect" => s.expect = Some(PathBuf::from(value)),
                other => {
                    if let Some(t) = other.strip_prefix("stop@") {
                        s.stop_at = Some(t.to_owned());
                    } else if let Some(t) = other.strip_prefix("die@") {
                        s.die_at = Some(t.to_owned());
                    } else {
                        panic!("unknown fake UI directive");
                    }
                }
            }
        }
        s
    }

    fn note(line: &str) {
        let Some(out) = std::env::var_os(OUT_VAR).or_else(|| beside("fake-ui.out").map(Into::into))
        else {
            return;
        };
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(Path::new(&out).join("notes"))
            .expect("notes");
        f.write_all(format!("{line}\n").as_bytes()).expect("note");
    }

    #[cfg(target_os = "linux")]
    fn fd_target(fd: u32) -> String {
        std::fs::read_link(format!("/proc/self/fd/{fd}"))
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    }

    /// Windows has no descriptor table to read (the pipe checks are Linux only).
    #[cfg(windows)]
    fn fd_target(_fd: u32) -> String {
        String::new()
    }

    #[cfg(windows)]
    fn all_fds() -> String {
        String::new()
    }

    /// Every fd target of this process, space separated.
    #[cfg(target_os = "linux")]
    fn all_fds() -> String {
        let mut out = Vec::new();
        for entry in std::fs::read_dir("/proc/self/fd").expect("fds") {
            let path = entry.expect("fd").path();
            if let Ok(target) = std::fs::read_link(&path) {
                out.push(target.display().to_string());
            }
        }
        out.join(" ")
    }

    /// The UI dies abnormally: an abort on Linux; a plain nonzero exit on Windows (an abort there
    /// can raise the error-reporting dialog).
    fn die() -> ! {
        #[cfg(windows)]
        std::process::exit(3);
        #[cfg(not(windows))]
        std::process::abort();
    }

    fn hit(at: &Option<String>, trigger: &str) -> bool {
        at.as_deref() == Some(trigger)
    }

    fn sleep_for_good() -> ! {
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    fn answer_of(token: &str, kind: PromptKind, flow: Flow) -> ChoiceValue {
        match token {
            "proceed" => ChoiceValue::Proceed,
            "cancel" => ChoiceValue::Cancel,
            "finish" => ChoiceValue::Finish { launch: false },
            "launch" => ChoiceValue::Finish { launch: true },
            "retry" => ChoiceValue::Retry,
            "close" => ChoiceValue::Close,
            "ack" => ChoiceValue::Acknowledge,
            "reveal0" => ChoiceValue::Reveal { index: 0 },
            _ => ui_host::headless_answer(kind, flow),
        }
    }

    /// The fake UI: `lunepack-ui --engine` as the case's script says.
    pub fn fake_ui() {
        let s = script();
        if let Some(code) = s.exit {
            std::process::exit(code);
        }
        note(&format!("ui start pipes={} {}", fd_target(0), fd_target(1)));
        if hit(&s.stop_at, "start") {
            sleep_for_good();
        }
        let out = Arc::new(Mutex::new(std::io::stdout()));
        let send = {
            let out = Arc::clone(&out);
            move |msg: &UiMsg| {
                let mut o = out.lock().expect("out");
                let _ = ui::write_frame(&mut *o, msg);
            }
        };
        let raw = |bytes: &[u8]| {
            let mut o = out.lock().expect("out");
            let _ = o.write_all(bytes);
            let _ = o.flush();
        };
        if s.garbage {
            raw(b"this is not a frame at all, just text\n");
        }
        if s.oversize {
            let mut bytes = ((ui::MAX_FRAME as u32) + 1).to_le_bytes().to_vec();
            bytes.extend_from_slice(&[b'{'; 64]);
            raw(&bytes);
        }
        let mut input = std::io::stdin().lock();
        let mut flow = Flow::Install;
        let mut answers = s.answers.clone().into_iter();
        loop {
            let msg = match ui::read_frame::<_, EngineMsg>(&mut input) {
                Ok(msg) => msg,
                Err(_) => {
                    note("ui eof");
                    std::process::exit(13);
                }
            };
            match &msg {
                EngineMsg::Hello {
                    build_id, flow: f, ..
                } => {
                    flow = *f;
                    note(&format!("ui got hello {f:?}"));
                    if s.garbage || s.oversize || s.nohello {
                        continue;
                    }
                    let id = s.build.clone().unwrap_or_else(|| build_id.clone());
                    send(&UiMsg::Hello { build_id: id });
                    if s.stray {
                        send(&UiMsg::Choice {
                            id: 77,
                            value: ChoiceValue::Close,
                        });
                    }
                    if hit(&s.die_at, "hello") {
                        die();
                    }
                    if hit(&s.stop_at, "hello") {
                        sleep_for_good();
                    }
                }
                EngineMsg::Progress { .. } => {
                    if hit(&s.die_at, "progress") {
                        note("ui dies at progress");
                        die();
                    }
                    if hit(&s.stop_at, "progress") {
                        note("ui stops at progress");
                        sleep_for_good();
                    }
                }
                EngineMsg::Ping { n } => {
                    if !s.nopong {
                        send(&UiMsg::Pong { n: *n });
                    }
                }
                // A UI that never said hello answers nothing.
                EngineMsg::Prompt { .. } if s.garbage || s.oversize || s.nohello => {}
                EngineMsg::Prompt { id, kind } => {
                    if let Some(exe) = &s.expect {
                        note(&format!("ui sees expected running={}", runs(exe)));
                    }
                    note(&format!("ui got prompt {kind:?}"));
                    let trigger = format!("prompt:{kind:?}");
                    if hit(&s.die_at, &trigger) {
                        die();
                    }
                    if hit(&s.stop_at, &trigger) {
                        sleep_for_good();
                    }
                    let mut picked = Vec::new();
                    loop {
                        let token = answers.next().unwrap_or_default();
                        let value = answer_of(&token, *kind, flow);
                        picked.push(value);
                        if !matches!(value, ChoiceValue::Reveal { .. }) {
                            break;
                        }
                    }
                    let id = *id;
                    let delay = s.delay;
                    let fix = s.fix.clone();
                    let send = send.clone();
                    // From another thread, so pings are answered while the "user" reads.
                    std::thread::spawn(move || {
                        std::thread::sleep(delay);
                        for value in picked {
                            if value == ChoiceValue::Retry
                                && let Some(fix) = &fix
                            {
                                let _ = std::fs::remove_file(fix);
                            }
                            send(&UiMsg::Choice { id, value });
                            std::thread::sleep(Duration::from_millis(1100));
                        }
                    });
                }
                EngineMsg::Outcome(o) => note(&format!("ui got outcome {}", outcome_name(o))),
                EngineMsg::Close => {
                    note("ui got close");
                    std::process::exit(0);
                }
                EngineMsg::Step { .. } | EngineMsg::Cancellable(_) => {}
            }
        }
    }

    /// Whether the thing `expect=` names is true. Windows (no procfs): the text is a note the app
    /// writes when it starts, found in this run's notes.
    #[cfg(windows)]
    fn runs(what: &Path) -> bool {
        let out = std::env::var_os(OUT_VAR).or_else(|| beside("fake-ui.out").map(Into::into));
        out.and_then(|o| std::fs::read_to_string(Path::new(&o).join("notes")).ok())
            .is_some_and(|notes| notes.contains(&*what.to_string_lossy()))
    }

    /// Whether a process runs with `exe` as its executable.
    #[cfg(target_os = "linux")]
    fn runs(exe: &Path) -> bool {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return false;
        };
        entries.flatten().any(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
                && std::fs::read_link(e.path().join("exe")).is_ok_and(|t| t == exe)
        })
    }

    fn outcome_name(o: &Outcome) -> String {
        match o {
            Outcome::Installed => "Installed".into(),
            Outcome::Failed { code } => format!("Failed {code}"),
            Outcome::Cancelled => "Cancelled".into(),
            Outcome::Updated => "Updated".into(),
            Outcome::RolledBack { from, to } => format!("RolledBack {from} {to}"),
            Outcome::Uninstalled { leftovers } => format!("Uninstalled {}", leftovers.len()),
            Outcome::UninstallFailed { code } => format!("UninstallFailed {code}"),
        }
    }

    // ---- the app for `apply` ---------------------------------------------------------------

    /// A process that sleeps `<seconds>` (the wait target of a case).
    pub fn sleep(rest: &[String]) {
        let secs: f64 = rest.first().and_then(|s| s.parse().ok()).expect("seconds");
        std::thread::sleep(Duration::from_secs_f64(secs));
    }

    /// The app `apply` starts: notes its start and its fds, then confirms or crashes as its
    /// tree's marker says.
    pub fn helper_app() {
        let token = std::env::var_os(HEALTH_TOKEN_VAR);
        let inst = lunepack::Installation::from_current_exe().expect("installation");
        let v = inst.tree_version().to_string();
        note(&format!(
            "{v} start token={}",
            if token.is_some() { "yes" } else { "no" }
        ));
        note(&format!("{v} app-fds {}", all_fds()));
        let marker = std::fs::read_to_string(inst.tree_root().join("marker")).unwrap_or_default();
        let startup = lunepack::startup().expect("startup");
        if startup.action == lunepack::StartupAction::Exit {
            return;
        }
        match marker.trim() {
            "confirm" => {
                let got = lunepack::confirm_healthy();
                note(&format!("{v} confirm {}", got.is_ok()));
            }
            "crash" => std::process::exit(3),
            "linger" => std::thread::sleep(Duration::from_secs(5)),
            _ => {}
        }
    }

    // ---- the harness ------------------------------------------------------------------------

    type Case = fn();

    const TESTS: &[(&str, Case)] = &[
        (
            "host_absent_binary_is_headless",
            host_absent_binary_is_headless,
        ),
        (
            "host_exits_at_once_with_each_typed_code",
            host_exits_at_once_with_each_typed_code,
        ),
        (
            "host_never_sends_hello_times_out",
            host_never_sends_hello_times_out,
        ),
        (
            "host_wrong_build_id_is_refused",
            host_wrong_build_id_is_refused,
        ),
        (
            "host_garbage_is_a_protocol_stop",
            host_garbage_is_a_protocol_stop,
        ),
        (
            "host_oversize_frame_is_refused",
            host_oversize_frame_is_refused,
        ),
        (
            "host_a_choice_for_no_prompt_is_a_protocol_stop",
            host_a_choice_for_no_prompt_is_a_protocol_stop,
        ),
        (
            "host_stops_reading_at_each_pre_change_and_rolled_back_prompt",
            host_stops_reading_at_each_pre_change_and_rolled_back_prompt,
        ),
        (
            "host_alive_but_never_answers_ping",
            host_alive_but_never_answers_ping,
        ),
        (
            "host_a_user_reading_a_screen_is_not_a_hang",
            host_a_user_reading_a_screen_is_not_a_hang,
        ),
        (
            "host_stops_reading_while_frames_flow_never_blocks",
            host_stops_reading_while_frames_flow_never_blocks,
        ),
        (
            "host_one_write_in_progress_too_long_is_a_stall",
            host_one_write_in_progress_too_long_is_a_stall,
        ),
        (
            "host_close_is_bounded_with_a_hung_ui",
            host_close_is_bounded_with_a_hung_ui,
        ),
        (
            "host_killed_at_welcome_cancels",
            host_killed_at_welcome_cancels,
        ),
        (
            "install_well_behaved_proceeds_and_launches_without_ui_pipes",
            install_well_behaved_proceeds_and_launches_without_ui_pipes,
        ),
        (
            "install_retry_after_a_failure_installs",
            install_retry_after_a_failure_installs,
        ),
        (
            "install_ui_killed_at_welcome_cancels_and_changes_nothing",
            install_ui_killed_at_welcome_cancels_and_changes_nothing,
        ),
        (
            "install_ui_killed_mid_install_still_installs",
            install_ui_killed_mid_install_still_installs,
        ),
        (
            "install_ui_stops_reading_mid_install_still_installs",
            install_ui_stops_reading_mid_install_still_installs,
        ),
        (
            "install_silent_and_no_display_start_no_ui",
            install_silent_and_no_display_start_no_ui,
        ),
        (
            "uninstall_with_a_live_ui_from_the_tree_reveals_and_succeeds",
            uninstall_with_a_live_ui_from_the_tree_reveals_and_succeeds,
        ),
        (
            "uninstall_ui_killed_at_confirm_cancels",
            uninstall_ui_killed_at_confirm_cancels,
        ),
        (
            "apply_well_behaved_closes_and_the_app_holds_no_ui_pipe",
            apply_well_behaved_closes_and_the_app_holds_no_ui_pipe,
        ),
        (
            "apply_ui_killed_mid_apply_still_confirms",
            apply_ui_killed_mid_apply_still_confirms,
        ),
        (
            "apply_ui_stops_reading_mid_apply_still_confirms",
            apply_ui_stops_reading_mid_apply_still_confirms,
        ),
        (
            "apply_rollback_with_a_hung_ui_relaunches_first_and_ends",
            apply_rollback_with_a_hung_ui_relaunches_first_and_ends,
        ),
        (
            "apply_no_ui_and_policy_start_no_ui",
            apply_no_ui_and_policy_start_no_ui,
        ),
    ];

    pub fn run_all(args: &[String]) {
        let filter = args.iter().find(|a| !a.starts_with('-'));
        let (_wrapper_dir, base) = scratch("uiwrapper-");
        write_wrapper(&base);
        let failed = Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for (name, test) in TESTS {
                if filter.is_some_and(|f| !name.contains(f.as_str())) {
                    continue;
                }
                let failed = &failed;
                #[cfg(windows)]
                if let Some((_, why)) = LINUX_ONLY.iter().find(|(p, _)| name.starts_with(p)) {
                    println!("test {name} ... skipped on Windows ({why})");
                    continue;
                }
                scope.spawn(move || {
                    let started = Instant::now();
                    match std::panic::catch_unwind(test) {
                        Ok(()) => {
                            println!("test {name} ... ok ({} ms)", started.elapsed().as_millis())
                        }
                        Err(_) => {
                            println!("test {name} ... FAILED");
                            failed.lock().expect("failed").push(*name);
                        }
                    }
                });
            }
        });
        let failed = failed.into_inner().expect("failed");
        if !failed.is_empty() {
            println!("failed: {failed:?}");
            std::process::exit(1);
        }
    }

    fn scratch(prefix: &str) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .expect("tmp");
        let base = plain(std::fs::canonicalize(tmp.path()).expect("canonical"));
        (tmp, base)
    }

    /// `path` without Windows' `\\?\` prefix (a canonical path there).
    fn plain(path: PathBuf) -> PathBuf {
        let text = path.to_string_lossy().into_owned();
        match text.strip_prefix(r"\\?\") {
            Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
            _ => path,
        }
    }

    fn write_exec(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
        std::fs::write(path, text).expect("write");
        #[cfg(unix)]
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("mode");
    }

    /// The one wrapper script every `lunepack-ui` is a hard link of, written before any case
    /// runs: an executable written while another thread forks can fail to start (`ETXTBSY`,
    /// the fork holds it open for writing until it execs), so no case writes one.
    static WRAPPER: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

    fn write_wrapper(dir: &Path) {
        // Windows has no wrapper: the fake UI is this binary itself (see `place_ui`).
        #[cfg(windows)]
        {
            let _ = dir;
            WRAPPER
                .set(std::env::current_exe().expect("exe"))
                .expect("wrapper once");
        }
        #[cfg(not(windows))]
        write_unix_wrapper(dir);
    }

    #[cfg(not(windows))]
    fn write_unix_wrapper(dir: &Path) {
        let me = std::env::current_exe().expect("exe");
        let path = dir.join("fake-ui-wrapper");
        write_exec(
            &path,
            &format!(
                "#!/bin/sh\nd=$(dirname \"$0\")\n{FAKE_VAR}=$(cat \"$d/fake-ui.spec\") \
                 {OUT_VAR}=$(cat \"$d/fake-ui.out\") exec '{}' \"$@\"\n",
                me.display()
            ),
        );
        WRAPPER.set(path).expect("wrapper once");
    }

    /// `dir/lunepack-ui`: starts this binary as the fake UI with `spec`, noting into `out`.
    fn place_ui(dir: &Path, spec: &str, out: &Path) {
        std::fs::create_dir_all(dir).expect("dir");
        std::fs::write(dir.join("fake-ui.spec"), spec).expect("spec");
        std::fs::write(dir.join("fake-ui.out"), out.as_os_str().as_encoded_bytes()).expect("out");
        let wrapper = WRAPPER.get().expect("wrapper");
        let link = dir.join(ui_host::UI_FILE);
        if std::fs::hard_link(wrapper, &link).is_err() {
            std::fs::copy(wrapper, &link).expect("copy the wrapper");
        }
    }

    fn notes(out: &Path) -> String {
        std::fs::read_to_string(out.join("notes")).unwrap_or_default()
    }

    /// The UI pipes the fake UI noted (`pipe:[N]` targets).
    fn ui_pipes(out: &Path) -> Vec<String> {
        notes(out)
            .lines()
            .filter_map(|l| l.strip_prefix("ui start pipes="))
            .flat_map(|l| l.split(' ').map(str::to_owned).collect::<Vec<_>>())
            .collect()
    }

    #[cfg(windows)]
    fn assert_app_holds_no_ui_pipe(_out: &Path, _app_fds: &str) {
        // Linux only: Windows has no descriptor table to read; the E2E covers handle inheritance.
    }

    #[cfg(target_os = "linux")]
    fn assert_app_holds_no_ui_pipe(out: &Path, app_fds: &str) {
        let pipes = ui_pipes(out);
        assert_eq!(pipes.len(), 2, "the UI noted its pipes: {}", notes(out));
        assert!(pipes.iter().all(|p| p.starts_with("pipe:[")), "{pipes:?}");
        assert_ne!(pipes[0], pipes[1]);
        // The instrument: the matcher finds a pipe in a listing that holds it.
        assert!(app_fds_hold(&format!("x {} y", pipes[0]), &pipes));
        assert!(!app_fds_hold(app_fds, &pipes), "the app holds a UI pipe");
    }

    fn app_fds_hold(fds: &str, pipes: &[String]) -> bool {
        fds.split(' ').any(|t| pipes.iter().any(|p| p == t))
    }

    fn wait_until(limit: Duration, cond: impl Fn() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < limit {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        cond()
    }

    // ---- host cases ---------------------------------------------------------------------------

    /// Lowered bounds, still wide enough for a fake UI that starts slowly while the runtime
    /// cases run beside it.
    const FAST: Bounds = Bounds {
        hello: Duration::from_secs(10),
        stall: Duration::from_secs(1),
        ping_every: Duration::from_millis(300),
        pong_wait: Duration::from_secs(2),
        close_wait: Duration::from_secs(2),
        watch_tick: Duration::from_millis(50),
    };

    /// Collects the events as JSON lines.
    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<String>>>);

    impl Sink for Lines {
        fn name(&self) -> &'static str {
            "log"
        }

        fn deliver(&mut self, event: &Event) -> Result<(), SinkFailed> {
            self.0.lock().expect("lines").push(to_json_line(event));
            Ok(())
        }
    }

    struct HostLab {
        _tmp: tempfile::TempDir,
        dir: PathBuf,
        out: PathBuf,
        lines: Lines,
        bounds: Bounds,
    }

    impl HostLab {
        fn new(spec: Option<&str>) -> HostLab {
            let (tmp, base) = scratch("uihost-");
            let dir = base.join("bin");
            let out = base.join("out");
            std::fs::create_dir_all(&dir).expect("dir");
            std::fs::create_dir_all(&out).expect("out");
            if let Some(spec) = spec {
                place_ui(&dir, spec, &out);
            }
            HostLab {
                _tmp: tmp,
                dir,
                out,
                lines: Lines::default(),
                bounds: FAST,
            }
        }

        fn start(&self, flow: Flow) -> UiHost {
            self.start_with(flow, None)
        }

        fn start_with(&self, flow: Flow, icon: Option<Vec<u8>>) -> UiHost {
            let process: Arc<dyn Process> = Arc::new(NativeProcess::new());
            let env = |name: &str| (name == "DISPLAY").then(|| ":99".into());
            let mut app = ui_host::card("Host test", V100, None);
            app.icon_png = icon;
            UiHost::start_with(
                self.bounds,
                &Start {
                    process,
                    fs: &StdFs::new(),
                    runtime_exe: &self.dir.join("lunepack-runtime"),
                    env: &env,
                    quiet: false,
                },
                flow,
                app,
                Details {
                    location: None,
                    size_bytes: None,
                },
            )
        }

        fn events(&self, ui: &UiHost) -> Events {
            Events::new(Some(Box::new(self.lines.clone())), ui.sink())
        }

        fn lines(&self, events: Events) -> String {
            events.finish(Duration::from_secs(2));
            self.lines.0.lock().expect("lines").join("\n")
        }
    }

    fn welcome(ui: &UiHost, events: &Events) -> ChoiceValue {
        ui.prompt(PromptKind::Welcome, events, &mut |_| {})
    }

    fn stop_line(reason: &str) -> String {
        format!("\"code\":\"ui_stopped\",\"version\":null,\"reason\":\"{reason}\"")
    }

    fn host_absent_binary_is_headless() {
        let lab = HostLab::new(None);
        let ui = lab.start(Flow::Install);
        assert!(ui.child_id().is_none());
        let events = lab.events(&ui);
        let t = Instant::now();
        assert_eq!(welcome(&ui, &events), ChoiceValue::Proceed);
        assert!(t.elapsed() < Duration::from_millis(100));
        ui.close(&events);
        assert!(!lab.lines(events).contains("ui_stopped"));
    }

    fn host_exits_at_once_with_each_typed_code() {
        for (code, reason) in [
            (0, "exited"),
            (10, "exited"),
            (11, "exited"),
            (12, "protocol"),
            (13, "exited"),
            (14, "build_mismatch"),
            (1, "exited"),
        ] {
            let lab = HostLab::new(Some(&format!("exit={code}")));
            let ui = lab.start(Flow::Install);
            assert!(ui.child_id().is_some());
            let events = lab.events(&ui);
            let t = Instant::now();
            // Never said hello: the headless answer, not the lost one.
            assert_eq!(welcome(&ui, &events), ChoiceValue::Proceed, "exit {code}");
            assert!(
                t.elapsed() < FAST.hello + Duration::from_secs(1),
                "exit {code}"
            );
            assert_eq!(ui.stopped().map(|s| s.exit_code), Some(Some(code)));
            ui.close(&events);
            let lines = lab.lines(events);
            let want = format!("{},\"ui_exit_code\":{code}}}", stop_line(reason));
            assert_eq!(lines.matches("ui_stopped").count(), 1, "{lines}");
            assert!(lines.contains(&want), "exit {code}: {lines}");
        }
    }

    fn host_never_sends_hello_times_out() {
        let mut lab = HostLab::new(Some("nohello"));
        lab.bounds.hello = Duration::from_millis(2000);
        let ui = lab.start(Flow::Uninstall);
        let events = lab.events(&ui);
        let t = Instant::now();
        let got = ui.prompt(PromptKind::Confirm, &events, &mut |_| {});
        assert_eq!(got, ChoiceValue::Proceed);
        let took = t.elapsed();
        assert!(
            took >= lab.bounds.hello - Duration::from_millis(200),
            "{took:?}"
        );
        assert!(took < lab.bounds.hello + Duration::from_secs(1), "{took:?}");
        ui.close(&events);
        assert!(lab.lines(events).contains(&stop_line("hello_timeout")));
    }

    fn host_wrong_build_id_is_refused() {
        let lab = HostLab::new(Some("build=0.0.0+ui1.other"));
        let ui = lab.start(Flow::Install);
        let events = lab.events(&ui);
        assert_eq!(welcome(&ui, &events), ChoiceValue::Proceed);
        assert_eq!(ui.stopped().map(|s| s.reason), Some(UiStop::BuildMismatch));
        ui.close(&events);
        assert!(lab.lines(events).contains(&stop_line("build_mismatch")));
    }

    fn host_garbage_is_a_protocol_stop() {
        let lab = HostLab::new(Some("garbage"));
        let ui = lab.start(Flow::Install);
        let events = lab.events(&ui);
        assert_eq!(welcome(&ui, &events), ChoiceValue::Proceed);
        assert_eq!(ui.stopped().map(|s| s.reason), Some(UiStop::Protocol));
        ui.close(&events);
        let lines = lab.lines(events);
        assert!(lines.contains(&stop_line("protocol")), "{lines}");
        // Nothing of what the UI wrote reaches the log.
        assert!(!lines.contains("not a frame"));
    }

    fn host_oversize_frame_is_refused() {
        let lab = HostLab::new(Some("oversize"));
        let ui = lab.start(Flow::Install);
        let events = lab.events(&ui);
        let t = Instant::now();
        assert_eq!(welcome(&ui, &events), ChoiceValue::Proceed);
        assert!(t.elapsed() < FAST.hello);
        assert_eq!(ui.stopped().map(|s| s.reason), Some(UiStop::Protocol));
        ui.close(&events);
    }

    fn host_a_choice_for_no_prompt_is_a_protocol_stop() {
        let lab = HostLab::new(Some("stray"));
        let ui = lab.start(Flow::Install);
        let events = lab.events(&ui);
        assert!(wait_until(Duration::from_secs(3), || ui
            .stopped()
            .is_some()));
        assert_eq!(ui.stopped().map(|s| s.reason), Some(UiStop::Protocol));
        // Lost after its hello: the welcome prompt cancels.
        assert_eq!(welcome(&ui, &events), ChoiceValue::Cancel);
        ui.close(&events);
        assert!(lab.lines(events).contains(&stop_line("protocol")));
    }

    fn host_stops_reading_at_each_pre_change_and_rolled_back_prompt() {
        let bound = FAST.pong_wait + Duration::from_secs(1);
        for (flow, kind, want) in [
            (Flow::Install, PromptKind::Welcome, ChoiceValue::Cancel),
            (Flow::Uninstall, PromptKind::Confirm, ChoiceValue::Cancel),
            (
                Flow::Update,
                PromptKind::RolledBack,
                ChoiceValue::Acknowledge,
            ),
        ] {
            let lab = HostLab::new(Some(&format!("stop@prompt:{kind:?}")));
            let ui = lab.start(flow);
            let events = lab.events(&ui);
            if flow == Flow::Update {
                events.emit(&Event::phase(Phase::Confirm, None));
                assert!(wait_until(Duration::from_secs(2), || notes(&lab.out)
                    .contains("ui got hello")));
                ui.outcome(Outcome::RolledBack {
                    from: V110.into(),
                    to: V100.into(),
                });
            }
            let t = Instant::now();
            assert_eq!(ui.prompt(kind, &events, &mut |_| {}), want, "{kind:?}");
            assert!(t.elapsed() < bound, "{kind:?}: {:?}", t.elapsed());
            assert!(notes(&lab.out).contains(&format!("ui got prompt {kind:?}")));
            assert_eq!(ui.stopped().map(|s| s.reason), Some(UiStop::Hung));
            ui.close(&events);
            assert!(lab.lines(events).contains(&stop_line("hung")));
        }
    }

    fn host_alive_but_never_answers_ping() {
        let lab = HostLab::new(Some("nopong,delay=60000"));
        let ui = lab.start(Flow::Install);
        let events = lab.events(&ui);
        let t = Instant::now();
        let got = welcome(&ui, &events);
        let took = t.elapsed();
        assert_eq!(
            ui.stopped().map(|s| s.reason),
            Some(UiStop::Hung),
            "{got:?} {took:?} {}",
            notes(&lab.out)
        );
        assert_eq!(got, ChoiceValue::Cancel);
        assert!(took < FAST.pong_wait + Duration::from_secs(1), "{took:?}");
        ui.close(&events);
    }

    fn host_a_user_reading_a_screen_is_not_a_hang() {
        // The "user" answers after three pong bounds; a live UI keeps answering pings.
        let lab = HostLab::new(Some("answers=proceed,delay=6000"));
        let ui = lab.start(Flow::Install);
        let events = lab.events(&ui);
        let t = Instant::now();
        let got = welcome(&ui, &events);
        let took = t.elapsed();
        assert_eq!(ui.stopped(), None, "{took:?}");
        assert_eq!(got, ChoiceValue::Proceed);
        assert!(took >= Duration::from_millis(5800), "{took:?}");
        ui.close(&events);
        assert!(wait_until(Duration::from_secs(2), || notes(&lab.out)
            .contains("ui got close")));
        assert!(!lab.lines(events).contains("ui_stopped"));
    }

    fn host_stops_reading_while_frames_flow_never_blocks() {
        let lab = HostLab::new(Some("stop@hello"));
        let ui = lab.start(Flow::Update);
        let events = lab.events(&ui);
        assert!(wait_until(Duration::from_secs(3), || notes(&lab.out)
            .contains("ui got hello")));
        // Each emit and each direct frame returns at once, whether or not the UI reads.
        let t = Instant::now();
        let mut slowest = Duration::ZERO;
        for i in 0..3000 {
            let one = Instant::now();
            events.emit(&Event::Progress(Progress {
                phase: Phase::Wait,
                done: i,
                total: 3000,
                file: None,
            }));
            ui.steps(&[ui::StepItem::WaitApp]);
            slowest = slowest.max(one.elapsed());
        }
        // The one emit that finds the queue full stops the UI, which ends the child: on Windows a
        // window-less child gets WM_CLOSE and then the kill after the grace (100 ms), so that
        // call may take the grace on top (bounded; the real UI has windows and closes at once).
        let bound = Duration::from_millis(if cfg!(windows) { 300 } else { 100 });
        assert!(slowest < bound, "{slowest:?}");
        assert!(wait_until(FAST.stall + Duration::from_secs(2), || ui
            .stopped()
            .is_some()));
        assert!(t.elapsed() < FAST.stall + Duration::from_secs(3));
        assert_eq!(ui.stopped().map(|s| s.reason), Some(UiStop::Stalled));
        // The outcome and the rolled-back prompt resolve at once.
        ui.outcome(Outcome::Updated);
        let t = Instant::now();
        assert_eq!(
            ui.prompt(PromptKind::RolledBack, &events, &mut |_| {}),
            ChoiceValue::Acknowledge
        );
        assert!(t.elapsed() < Duration::from_millis(100));
        ui.close(&events);
        let lines = lab.lines(events);
        assert_eq!(lines.matches("ui_stopped").count(), 1, "{lines}");
        assert!(lines.contains(&stop_line("stalled")));
    }

    fn host_one_write_in_progress_too_long_is_a_stall() {
        // A hello with the largest icon is far over a pipe's buffer, and the UI reads nothing.
        let lab = HostLab::new(Some("stop@start"));
        let icon = vec![0x89u8; ui::MAX_ICON_BYTES];
        let t = Instant::now();
        let ui = lab.start_with(Flow::Install, Some(icon));
        // The start spawns the UI and returns; it does not wait for the write. On Windows the
        // first launch of a fresh executable can take a second under real-time scanning.
        let start_bound = Duration::from_millis(if cfg!(windows) { 3000 } else { 500 });
        assert!(t.elapsed() < start_bound, "start waited");
        let events = lab.events(&ui);
        assert!(wait_until(FAST.stall + Duration::from_secs(1), || ui
            .stopped()
            .is_some()));
        assert_eq!(ui.stopped().map(|s| s.reason), Some(UiStop::Stalled));
        assert!(t.elapsed() < FAST.hello, "a stall, not the hello timeout");
        assert_eq!(welcome(&ui, &events), ChoiceValue::Proceed);
        ui.close(&events);
    }

    fn host_close_is_bounded_with_a_hung_ui() {
        let lab = HostLab::new(Some("stop@hello"));
        let ui = lab.start(Flow::Update);
        let events = lab.events(&ui);
        assert!(wait_until(Duration::from_secs(3), || notes(&lab.out)
            .contains("ui got hello")));
        ui.outcome(Outcome::Updated);
        let t = Instant::now();
        ui.close(&events);
        assert!(t.elapsed() < FAST.close_wait + Duration::from_secs(1));
        lab.lines(events);
    }

    fn host_killed_at_welcome_cancels() {
        let lab = HostLab::new(Some("die@prompt:Welcome"));
        let ui = lab.start(Flow::Install);
        let events = lab.events(&ui);
        assert_eq!(welcome(&ui, &events), ChoiceValue::Cancel);
        assert_eq!(ui.stopped().map(|s| s.reason), Some(UiStop::Exited));
        ui.close(&events);
        assert!(lab.lines(events).contains(&stop_line("exited")));
    }

    // ---- runtime cases: install and uninstall ----------------------------------------------------

    fn app_id() -> AppId {
        AppId::parse(SUITE_APP_ID).expect("app id")
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs()
    }

    fn u53(v: u64) -> U53 {
        U53::new(v).expect("u53")
    }

    /// Every frame stored: fast, and the runtime's real decoder reads stored frames.
    struct StoreOnly;

    impl Encoder for StoreOnly {
        fn encode(&self, codec: CodecId, _: &[u8]) -> Result<EncodedFrame, lunepack_core::Error> {
            Err(lunepack_core::error::CodecError::Unsupported(codec).into())
        }

        fn encode_memory(&self, _: CodecId, input_len: u64) -> u64 {
            input_len
        }
    }

    fn write_file(path: &Path, bytes: &[u8], exec: bool) {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
        std::fs::write(path, bytes).expect("write");
        #[cfg(unix)]
        {
            let mode = if exec { 0o755 } else { 0o644 };
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("mode");
        }
        #[cfg(not(unix))]
        let _ = exec;
    }

    /// One install case: a release of 1.0.0 on a `file:` feed, its bootstrap tree, an empty home.
    struct InstallLab {
        _tmp: tempfile::TempDir,
        base: PathBuf,
        home: PathBuf,
        data: PathBuf,
        root: PathBuf,
        out: PathBuf,
        boot: PathBuf,
    }

    impl InstallLab {
        fn new() -> InstallLab {
            let (tmp, base) = scratch("uiinstall-");
            let home = base.join("home");
            let out = base.join("out");
            for d in [&home, &out] {
                std::fs::create_dir_all(d).expect("dirs");
            }
            let data = home.join(".local/share");
            let lab = InstallLab {
                _tmp: tmp,
                boot: base.join("boot").join(V100),
                root: data.join(SUITE_APP_ID),
                base,
                home,
                data,
                out,
            };
            lab.publish();
            // The fake opener the uninstall's reveal finds on PATH.
            write_exec(
                &lab.base.join("fakebin/xdg-open"),
                &format!(
                    "#!/bin/sh\necho \"open $1\" >> '{}/notes'\n",
                    lab.out.display()
                ),
            );
            lab
        }

        /// The app: notes that it ran, its fds and whether it had a token.
        fn tree_files(&self) -> Vec<(String, Vec<u8>, bool)> {
            let out = self.out.display();
            let script = format!(
                "#!/bin/sh\nfds=''\nfor f in /proc/$$/fd/*; do fds=\"$fds $(readlink \"$f\")\"; done\n\
                 echo \"app-fds$fds\" >> '{out}/notes'\n\
                 echo \"app token=${{{HEALTH_TOKEN_VAR}:+yes}}\" >> '{out}/notes'\n\
                 echo app-ran >> '{out}/notes'\n"
            );
            vec![
                ("bin/app".to_owned(), script.into_bytes(), true),
                (
                    "bin/lunepack-runtime".to_owned(),
                    std::fs::read(RUNTIME).expect("runtime"),
                    true,
                ),
            ]
        }

        fn publish(&self) {
            let keys = tempfile::tempdir().expect("keys");
            let signers: Vec<Ed25519Signer> = (0..2)
                .map(|i| {
                    let key = generate_key_file(&keys.path().join(format!("k{i}"))).expect("key");
                    Ed25519Signer::from_key_file(&key.path).expect("load key")
                })
                .collect();
            let sign = |seed: u8, message: &[u8]| {
                let signer = &signers[usize::from(seed)];
                (
                    signer.public_key(),
                    signer.sign(message).expect("sign with a fresh key"),
                )
            };
            let mut small_order = [0u8; 32];
            small_order[0] = 1;
            let fx = ChainFixture {
                hasher: &Sha256Hasher,
                verifier: &Ed25519Verifier,
                sign: &sign,
                invalid_key: small_order,
            };
            let t = now();
            let root = TrustedRoot::from_parts(
                app_id(),
                1,
                1,
                &[fx.public_key(0)],
                &Sha256Hasher,
                &Ed25519Verifier,
            )
            .expect("root");
            let release = self.base.join("release");
            let feed = format!("file://{}/", release.display());
            let meta = InstallMeta {
                entry: RelPath::parse("bin/app").expect("entry"),
                name: "UI install test".to_owned(),
                comment: None,
                icon: None,
                categories: Vec::new(),
                bin: Some(BIN.to_owned()),
                terminal: false,
                publisher: None,
                file_types: Vec::new(),
                url_schemes: Vec::new(),
                autostart: false,
            };
            let config = UpdateConfig::new(
                &root,
                Version::parse(V100).expect("version"),
                TARGET,
                &feed,
                Channel::parse(SUITE_CHANNEL).expect("channel"),
                60,
                meta,
            )
            .expect("config")
            .to_bytes()
            .expect("config bytes");

            let mut files = self.tree_files();
            files.push(("lunepack-update.json".to_owned(), config, false));
            let mut layout = ReleaseLayout::new(app_id(), V100, TARGET).expect("layout");
            for (path, bytes, exec) in &files {
                let packed = pack_file(bytes, &StoreOnly, &FakeCodec::new(), &Sha256Hasher)
                    .expect("pack file");
                layout
                    .add_file(RelPath::parse(path).expect("path"), *exec, &packed)
                    .expect("add file");
                // Linked, not written: see `WRAPPER`.
                if path == "bin/lunepack-runtime" {
                    place(Path::new(RUNTIME), &self.boot.join(path));
                } else {
                    write_file(&self.boot.join(path), bytes, *exec);
                }
            }
            let (doc, pack) = layout.finish(t - 3600, &Sha256Hasher).expect("finish");
            let manifest = fx.envelope(PayloadKind::Manifest, &doc.to_payload(), &[1]);
            let mut ks = fx.keyset_document(1, 1, None, 1, &[1]);
            ks.keys = vec![fx.release_key(1, t - DAY, t + 1000 * DAY)];
            let ks_bytes = fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);
            let rel = fx.release(V100, &[(TARGET, &manifest)], None);
            let mut feed_doc = fx.feed_document(1, Some(t + 30 * DAY), vec![rel]);
            feed_doc.issued = u53(t - 3600);
            let feed_bytes = fx.envelope(PayloadKind::Feed, &feed_doc.to_payload(), &[1]);
            let target = TARGET.as_str();
            for (name, bytes) in [
                ("keys.json".to_owned(), ks_bytes),
                (format!("feed-{SUITE_CHANNEL}.json"), feed_bytes),
                (format!("{V100}/{target}.manifest.json"), manifest),
                (format!("{V100}/{target}.pack"), pack),
            ] {
                write_file(&release.join(name), &bytes, false);
            }
        }

        fn installed_bin(&self) -> PathBuf {
            self.root.join("versions").join(V100).join("bin")
        }

        fn desktop_entry(&self) -> PathBuf {
            self.data
                .join("applications")
                .join(format!("{SUITE_APP_ID}.desktop"))
        }

        fn bin_link(&self) -> PathBuf {
            self.home.join(".local/bin").join(BIN)
        }

        fn command(&self, runtime: &Path, args: &[&str]) -> Command {
            let mut cmd = Command::new(runtime);
            cmd.args(args)
                .env_clear()
                .env("HOME", &self.home)
                .env(
                    "PATH",
                    format!("{}:/usr/bin:/bin", self.base.join("fakebin").display()),
                )
                .env("DISPLAY", ":99")
                .current_dir(&self.base)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            cmd
        }

        fn run(&self, runtime: &Path, args: &[&str]) -> Run {
            self.run_cmd(self.command(runtime, args))
        }

        fn run_cmd(&self, mut cmd: Command) -> Run {
            let started = Instant::now();
            let child = cmd.spawn().expect("runtime");
            let out = finish(child);
            Run::of(out, started.elapsed())
        }

        fn install(&self, args: &[&str]) -> Run {
            let mut all = vec!["install"];
            all.extend_from_slice(args);
            self.run(&self.boot.join("bin/lunepack-runtime"), &all)
        }

        fn record(&self) -> Option<InstallState> {
            UserScope {
                dir: self.root.join("state"),
                app_id: app_id(),
            }
            .load(&StdFs::new(), &Sha256Hasher)
            .ok()
            .and_then(|l| l.record)
        }

        fn notes(&self) -> String {
            notes(&self.out)
        }
    }

    struct Run {
        code: i32,
        stdout: String,
        stderr: String,
        took: Duration,
    }

    impl std::fmt::Debug for Run {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "exit {} in {:?} stdout {:?} stderr {:?}",
                self.code, self.took, self.stdout, self.stderr
            )
        }
    }

    impl Run {
        fn of(out: Output, took: Duration) -> Run {
            Run {
                code: out.status.code().unwrap_or(-1),
                stdout: String::from_utf8(out.stdout).expect("utf-8 stdout"),
                stderr: String::from_utf8(out.stderr).expect("utf-8 stderr"),
                took,
            }
        }

        fn line(&self) -> &str {
            let lines: Vec<&str> = self.stdout.lines().collect();
            assert_eq!(lines.len(), 1, "one stdout line: {self:?}");
            lines[0]
        }
    }

    /// Waits for `child` (at most [`RUN_LIMIT`], then kills it and fails), reading its stdout
    /// and stderr meanwhile so a full pipe never holds it up.
    fn finish(mut child: Child) -> Output {
        fn drain(stream: Option<impl Read + Send + 'static>) -> std::thread::JoinHandle<Vec<u8>> {
            std::thread::spawn(move || {
                let mut all = Vec::new();
                if let Some(mut s) = stream {
                    let _ = s.read_to_end(&mut all);
                }
                all
            })
        }
        let stdout = drain(child.stdout.take());
        let stderr = drain(child.stderr.take());
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait") {
                break status;
            }
            if start.elapsed() > RUN_LIMIT {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the runtime ran too long");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        Output {
            status,
            stdout: stdout.join().expect("stdout"),
            stderr: stderr.join().expect("stderr"),
        }
    }

    fn installed_line() -> String {
        format!(
            "{{\"schema\":1,\"type\":\"result\",\"command\":\"install\",\"tree_version\":\"{V100}\",\"outcome\":\"installed\",\"version\":\"{V100}\"}}"
        )
    }

    fn cancelled_line(command: &str) -> String {
        format!(
            "{{\"schema\":1,\"type\":\"error\",\"command\":\"{command}\",\"tree_version\":\"{V100}\",\"kind\":\"cancelled\",\"exit_code\":5}}"
        )
    }

    fn assert_installed(lab: &InstallLab, run: &Run) {
        assert_eq!(run.code, 0, "{run:?}");
        assert_eq!(run.line(), installed_line());
        let record = lab.record().expect("record");
        assert_eq!(record.current.expect("current").version.to_string(), V100);
        assert!(lab.desktop_entry().exists());
    }

    fn install_well_behaved_proceeds_and_launches_without_ui_pipes() {
        let lab = InstallLab::new();
        place_ui(&lab.boot.join("bin"), "answers=proceed+launch", &lab.out);
        let run = lab.install(&[]);
        assert_installed(&lab, &run);
        assert!(!run.stderr.contains("ui_stopped"), "{run:?}");
        assert!(wait_until(Duration::from_secs(5), || lab
            .notes()
            .contains("app-ran")));
        let notes = lab.notes();
        let order = [
            "ui got hello Install",
            "ui got prompt Welcome",
            "ui got outcome Installed",
            "ui got prompt Done",
            "ui got close",
        ];
        let mut at = 0;
        for want in order {
            let found = notes[at..]
                .find(want)
                .unwrap_or_else(|| panic!("{want}: {notes}"));
            at += found + want.len();
        }
        assert!(
            notes.contains("app token=\n"),
            "the app got a token: {notes}"
        );
        let fds = notes
            .lines()
            .find_map(|l| l.strip_prefix("app-fds"))
            .expect("app fds");
        assert_app_holds_no_ui_pipe(&lab.out, fds);
    }

    fn install_retry_after_a_failure_installs() {
        let lab = InstallLab::new();
        write_file(&lab.bin_link(), b"someone else's tool\n", true);
        place_ui(
            &lab.boot.join("bin"),
            &format!(
                "answers=proceed+retry+finish,fix={}",
                lab.bin_link().display()
            ),
            &lab.out,
        );
        let run = lab.install(&[]);
        assert_installed(&lab, &run);
        let notes = lab.notes();
        assert!(notes.contains("ui got outcome Failed 24"), "{notes}");
        assert!(notes.contains("ui got outcome Installed"), "{notes}");
        assert!(!notes.contains("app-ran"), "finish without launch launched");
    }

    fn install_ui_killed_at_welcome_cancels_and_changes_nothing() {
        let lab = InstallLab::new();
        place_ui(&lab.boot.join("bin"), "die@prompt:Welcome", &lab.out);
        let run = lab.install(&[]);
        assert_eq!(run.code, 5, "{run:?}");
        assert_eq!(run.line(), cancelled_line("install"));
        assert!(run.stderr.contains("\"code\":\"ui_stopped\""), "{run:?}");
        assert!(!lab.root.exists(), "R was created");
        assert!(!lab.desktop_entry().exists());
        assert!(!lab.bin_link().exists());
    }

    fn install_ui_killed_mid_install_still_installs() {
        let lab = InstallLab::new();
        place_ui(
            &lab.boot.join("bin"),
            "answers=proceed+launch,die@progress",
            &lab.out,
        );
        let run = lab.install(&[]);
        assert_installed(&lab, &run);
        assert!(lab.notes().contains("ui dies at progress"));
        assert!(run.stderr.contains("\"code\":\"ui_stopped\""), "{run:?}");
        // A launch is only ever chosen in the UI; a lost UI chooses none.
        std::thread::sleep(Duration::from_millis(300));
        assert!(!lab.notes().contains("app-ran"));
    }

    fn install_ui_stops_reading_mid_install_still_installs() {
        let lab = InstallLab::new();
        place_ui(
            &lab.boot.join("bin"),
            "answers=proceed+launch,stop@progress",
            &lab.out,
        );
        let run = lab.install(&[]);
        assert_installed(&lab, &run);
        assert!(lab.notes().contains("ui stops at progress"));
        // Found at the done prompt at the latest: no pong within the hang bound.
        assert!(run.took < Duration::from_secs(30), "{run:?}");
        assert!(run.stderr.contains("\"code\":\"ui_stopped\""), "{run:?}");
        assert!(!lab.notes().contains("app-ran"));
    }

    fn install_silent_and_no_display_start_no_ui() {
        let lab = InstallLab::new();
        place_ui(&lab.boot.join("bin"), "answers=proceed+launch", &lab.out);
        let run = lab.install(&["--silent"]);
        assert_installed(&lab, &run);
        // The same install again, without a display and with the policy variable: refused as
        // installed, and still no UI.
        let runtime = lab.boot.join("bin/lunepack-runtime");
        let mut no_display = lab.command(&runtime, &["install"]);
        no_display.env_remove("DISPLAY");
        assert_eq!(lab.run_cmd(no_display).code, 23);
        let mut policy = lab.command(&runtime, &["install"]);
        policy.env("LUNEPACK_NO_UI", "1");
        assert_eq!(lab.run_cmd(policy).code, 23);
        assert!(!lab.notes().contains("ui start"), "{}", lab.notes());
        assert!(!lab.notes().contains("app-ran"));
        let twice = lab.install(&["--silent", "--silent"]);
        assert_eq!(twice.code, 2);
    }

    fn uninstall_with_a_live_ui_from_the_tree_reveals_and_succeeds() {
        let lab = InstallLab::new();
        assert_installed(&lab, &lab.install(&["--silent"]));
        // A desktop file that is not lunepack's at the entry's name: kept and listed.
        std::fs::remove_file(lab.desktop_entry()).expect("remove");
        write_file(
            &lab.desktop_entry(),
            b"[Desktop Entry]\nName=Other\n",
            false,
        );
        place_ui(
            &lab.installed_bin(),
            "answers=proceed+reveal0+close",
            &lab.out,
        );
        let run = lab.run(
            &lab.installed_bin().join("lunepack-runtime"),
            &["uninstall"],
        );
        assert_eq!(run.code, 0, "{run:?}");
        assert!(
            run.line()
                .contains("\"outcome\":\"uninstalled_with_leftovers\""),
            "{run:?}"
        );
        assert!(!run.stderr.contains("ui_stopped"), "{run:?}");
        assert!(!lab.root.exists(), "R is still there");
        let notes = lab.notes();
        assert!(notes.contains("ui got outcome Uninstalled 1"), "{notes}");
        let applications = lab.data.join("applications");
        assert!(
            wait_until(Duration::from_secs(5), || lab
                .notes()
                .contains(&format!("open {}\n", applications.display()))),
            "{}",
            lab.notes()
        );
        assert!(lab.notes().contains("ui got close"));
        // Nothing printed names a path.
        let base = lab.base.display().to_string();
        assert!(!run.stdout.contains(&base) && !run.stderr.contains(&base));
    }

    fn uninstall_ui_killed_at_confirm_cancels() {
        let lab = InstallLab::new();
        assert_installed(&lab, &lab.install(&["--silent"]));
        let before = lab.record();
        place_ui(&lab.installed_bin(), "die@prompt:Confirm", &lab.out);
        let run = lab.run(
            &lab.installed_bin().join("lunepack-runtime"),
            &["uninstall"],
        );
        assert_eq!(run.code, 5, "{run:?}");
        assert_eq!(run.line(), cancelled_line("uninstall"));
        assert_eq!(lab.record(), before);
        assert!(lab.desktop_entry().exists());
        assert!(lab.bin_link().exists());
    }

    // ---- runtime cases: apply -------------------------------------------------------------------

    fn version(text: &str) -> Version {
        Version::parse(text).expect("version")
    }

    /// Places `from` at `to`: a hard link when possible, else a copy.
    fn place(from: &Path, to: &Path) {
        std::fs::create_dir_all(to.parent().expect("parent")).expect("dirs");
        if std::fs::hard_link(from, to).is_err() {
            std::fs::copy(from, to).expect("copy");
        }
    }

    struct ApplyLab {
        _tmp: tempfile::TempDir,
        home: PathBuf,
        data: PathBuf,
        root: PathBuf,
        out: PathBuf,
    }

    impl ApplyLab {
        /// 1.0.0 (marker `linger`: it runs five seconds) installed, 1.1.0 (marker `marker`)
        /// staged, the fake UI with `spec` beside 1.0.0's runtime.
        fn new(marker: &str, spec: &str) -> ApplyLab {
            let (tmp, base) = scratch("uiapply-");
            let home = base.join("home");
            let data = home.join(".local/share");
            let root = data.join(app_id().as_str());
            let out = base.join("out");
            for d in [&home, &data, &root, &out] {
                std::fs::create_dir_all(d).expect("dirs");
            }
            let lab = ApplyLab {
                _tmp: tmp,
                home,
                data,
                root,
                out,
            };
            lab.tree(V100, "linger");
            lab.tree(V110, marker);
            // Linux: the app's executable, which a process must be running from; Windows (no
            // procfs): the note the relaunched 1.0.0 writes when it starts.
            let expect = if cfg!(windows) {
                "1.0.0 start token=no".to_owned()
            } else {
                lab.tree_dir(V100).join("bin/app").display().to_string()
            };
            let spec = spec.replace("@expect@", &expect);
            place_ui(&lab.tree_dir(V100).join("bin"), &spec, &lab.out);
            let fs = StdFs::new();
            let store = UserScope {
                dir: lab.layout().state_dir(),
                app_id: app_id(),
            };
            let loaded = store.load(&fs, &Sha256Hasher).expect("load");
            let next = InstallState::new(1, app_id(), Scope::User, INSTALL_ID, TARGET)
                .install(version(V100), 10, TARGET, INSTALL_ID)
                .set_staged(Some((
                    StagedRef::new(version(V110), TARGET, Sha256Hasher.sha256(b"1.1.0")),
                    20,
                )));
            store
                .commit(&fs, &loaded, &next, &Sha256Hasher)
                .expect("commit");
            lab
        }

        fn layout(&self) -> UserLayout {
            UserLayout::from_root(self.root.clone(), SCHEME)
        }

        fn tree_dir(&self, v: &str) -> PathBuf {
            self.layout().versions_dir().join(v)
        }

        fn tree(&self, v: &str, marker: &str) {
            let dir = self.tree_dir(v);
            let mut cfg = lunepack_testkit::sample_update_config();
            cfg.version = version(v);
            cfg.target = TARGET;
            cfg.health_timeout_secs = 10;
            cfg.install = InstallMeta {
                entry: RelPath::parse(&exe("bin/app")).expect("entry"),
                name: format!("UI apply test {v}"),
                comment: None,
                icon: None,
                categories: Vec::new(),
                bin: None,
                terminal: false,
                publisher: None,
                file_types: Vec::new(),
                url_schemes: Vec::new(),
                autostart: false,
            };
            write_file(
                &dir.join("lunepack-update.json"),
                &cfg.to_bytes().expect("config bytes"),
                false,
            );
            place(
                &std::env::current_exe().expect("exe"),
                &dir.join(exe("bin/app")),
            );
            place(Path::new(RUNTIME), &dir.join("bin").join(RUNTIME_FILE));
            std::fs::write(dir.join("marker"), marker).expect("marker");
        }

        fn command(&self, extra: &[&str]) -> Command {
            let target = wait_target();
            let mut cmd = Command::new(self.tree_dir(V100).join("bin").join(RUNTIME_FILE));
            cmd.args([
                "apply",
                "--wait-pid",
                &target.pid.to_string(),
                "--wait-start",
                &target.start_ticks.to_string(),
                "--version",
                V110,
            ])
            .args(extra)
            .args(["--", HELPER_ARG]);
            // Linux: a cleared environment, with a display so a UI is wanted. Windows: the
            // inherited one (the system needs its variables), minus what would change the run.
            #[cfg(not(windows))]
            cmd.env_clear()
                .env("HOME", &self.home)
                .env("XDG_DATA_HOME", &self.data)
                .env("PATH", "/usr/bin:/bin")
                .env("DISPLAY", ":99");
            #[cfg(windows)]
            cmd.env_remove("LUNEPACK_NO_UI")
                .env_remove(HEALTH_TOKEN_VAR);
            cmd.env(OUT_VAR, &self.out)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            cmd
        }

        fn run(&self, cmd: Command) -> Run {
            let started = Instant::now();
            let out = finish(cmd.into_child());
            Run::of(out, started.elapsed())
        }

        fn notes(&self) -> String {
            notes(&self.out)
        }

        fn log(&self) -> String {
            std::fs::read_to_string(self.layout().logs_dir().join("runtime.log"))
                .unwrap_or_default()
        }

        fn current(&self) -> Version {
            UserScope {
                dir: self.layout().state_dir(),
                app_id: app_id(),
            }
            .load(&StdFs::new(), &Sha256Hasher)
            .expect("load")
            .record
            .expect("record")
            .current
            .expect("current")
            .version
        }
    }

    trait IntoChild {
        fn into_child(self) -> Child;
    }

    impl IntoChild for Command {
        fn into_child(mut self) -> Child {
            self.spawn().expect("runtime")
        }
    }

    /// A short-lived process to wait for (reaped by a thread), and its id.
    fn wait_target() -> ProcessId {
        let mut child = Command::new(std::env::current_exe().expect("exe"))
            .args([SLEEP_ARG, "0.3"])
            .spawn()
            .expect("sleep");
        let id = NativeProcess::new()
            .process_id(child.id())
            .expect("probe")
            .expect("running");
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        id
    }

    fn apply_well_behaved_closes_and_the_app_holds_no_ui_pipe() {
        let lab = ApplyLab::new("confirm", "");
        let run = lab.run(lab.command(&[]));
        assert_eq!(run.code, 0, "{run:?}");
        assert_eq!(lab.current(), version(V110));
        let notes = lab.notes();
        assert!(notes.contains("ui got hello Update"), "{notes}");
        assert!(notes.contains("ui got outcome Updated"), "{notes}");
        assert!(notes.contains("ui got close"), "{notes}");
        assert!(notes.contains("1.1.0 start token=yes"), "{notes}");
        assert!(!lab.log().contains("ui_stopped"), "{}", lab.log());
        let fds = notes
            .lines()
            .find_map(|l| l.strip_prefix("1.1.0 app-fds "))
            .expect("app fds");
        assert_app_holds_no_ui_pipe(&lab.out, fds);
        // The token is in no note of the UI: its environment never held it.
        assert!(!notes.contains(HEALTH_TOKEN_VAR));
    }

    fn apply_ui_killed_mid_apply_still_confirms() {
        let lab = ApplyLab::new("confirm", "die@progress");
        let run = lab.run(lab.command(&[]));
        assert_eq!(run.code, 0, "{run:?}");
        assert_eq!(lab.current(), version(V110));
        assert!(lab.notes().contains("ui dies at progress"));
        assert!(
            lab.log().contains("\"code\":\"ui_stopped\""),
            "{}",
            lab.log()
        );
    }

    fn apply_ui_stops_reading_mid_apply_still_confirms() {
        let lab = ApplyLab::new("confirm", "stop@progress");
        let run = lab.run(lab.command(&[]));
        assert_eq!(run.code, 0, "{run:?}");
        assert_eq!(lab.current(), version(V110));
        // The close bound, then the kill.
        assert!(run.took < Duration::from_secs(20), "{run:?}");
    }

    fn apply_rollback_with_a_hung_ui_relaunches_first_and_ends() {
        let lab = ApplyLab::new("crash", "expect=@expect@,stop@prompt:RolledBack");
        let run = lab.run(lab.command(&[]));
        assert_eq!(run.code, 20, "{run:?}");
        assert_eq!(lab.current(), version(V100));
        let notes = lab.notes();
        assert!(notes.contains("1.0.0 start token=no"), "{notes}");
        // When the prompt reached the UI, 1.0.0 was already running.
        assert!(
            notes.contains("ui sees expected running=true\nui got prompt RolledBack"),
            "{notes}"
        );
        assert!(
            notes.contains("ui got outcome RolledBack 1.1.0 1.0.0"),
            "{notes}"
        );
        let fds = notes
            .lines()
            .find_map(|l| l.strip_prefix("1.0.0 app-fds "))
            .expect("1.0.0 app fds");
        assert_app_holds_no_ui_pipe(&lab.out, fds);
        // Found hung by the pings, within the bounds: a ping at once, a pong bound of 15 s.
        assert!(run.took < Duration::from_secs(45), "{run:?}");
        assert!(lab.log().contains("\"reason\":\"hung\""), "{}", lab.log());
    }

    fn apply_no_ui_and_policy_start_no_ui() {
        let lab = ApplyLab::new("confirm", "");
        let run = lab.run(lab.command(&["--no-ui"]));
        assert_eq!(run.code, 0, "{run:?}");
        assert!(!lab.notes().contains("ui start"), "{}", lab.notes());
        // Windows has no display to be missing: only the policy variable.
        let policies: &[(&str, Option<&str>)] = if cfg!(windows) {
            &[("LUNEPACK_NO_UI", Some("1"))]
        } else {
            &[("LUNEPACK_NO_UI", Some("1")), ("DISPLAY", None)]
        };
        for (name, value) in policies.iter().copied() {
            let lab = ApplyLab::new("confirm", "");
            let mut cmd = lab.command(&[]);
            match value {
                Some(v) => cmd.env(name, v),
                None => cmd.env_remove(name),
            };
            let run = lab.run(cmd);
            assert_eq!(run.code, 0, "{name}: {run:?}");
            assert!(!lab.notes().contains("ui start"), "{name}: {}", lab.notes());
        }
        let twice = lab.run(lab.command(&["--no-ui", "--no-ui"]));
        assert_eq!(twice.code, 2);
    }
}
