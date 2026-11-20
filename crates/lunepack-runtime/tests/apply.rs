//! The runtime's `apply` mode with real processes (M5 step 8): commit, launch with a token,
//! supervision, confirmation, rollback, the wait target, the per-version configs (P3), GC and the
//! event sinks.
//!
//! Each case builds an install under a temporary data home: version trees written with the real
//! update-config writer, records with the core's real writer and transitions, and in each tree
//! this test binary as the app's entry and the built `lunepack-runtime` beside it (hard links
//! when the filesystem allows, else copies). Own `main` (see Cargo.toml): run as `helper-app`,
//! this binary is the app. It calls the real `lunepack::startup()` and `confirm_healthy()`, and
//! what it does next comes from a marker file in its own tree (confirm, crash, exit 0, sleep,
//! confirm late) or from its next argument. It notes what it saw in a file outside the install;
//! it notes whether it had a health token, never the token itself (one case saves the token to a
//! test-only file, to grep every output for it).
//!
//! The cases run one after another, on Linux, Windows and macOS (M8 step 6e). Everything that
//! depends on the OS's layout scheme (the trees' entry and config paths, where the live version
//! is after a swap, `R/current` or the live bundle `B`) comes from `tests/common`; a case that
//! needs a mechanism one OS lacks is skipped on it, by name and with its reason, in `SKIPPED`
//! below. The macOS cases of the old `apply_macos.rs` (a folder the user cannot write, a
//! translocated runtime) are here too, skipped elsewhere.

// The sink fan-out, compiled into this test so a UI-sink fake can be plugged in (the binary never
// constructs one in M5).
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod common;

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[allow(dead_code)]
#[path = "../src/events.rs"]
mod events;

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some(native::HELPER_ARG) {
        native::helper(&args[1..]);
        return;
    }
    if args.first().map(String::as_str) == Some(native::SLEEP_ARG) {
        native::sleep(&args[1..]);
        return;
    }
    native::run_all(&args);
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn main() {
    println!("lunepack-runtime apply tests: Linux, macOS and Windows only, skipped");
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod native {
    use std::ffi::OsString;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use lunepack::{
        ConfirmOutcome, HEALTH_TOKEN_VAR, InstallMeta, Installation, Phase, ProcessId, Progress,
        RelPath, StartupAction, UpdateConfig, Version,
    };
    use lunepack_core::state::{InstallState, Scope, StagedRef, UserScope};
    use lunepack_core::{Hasher, UserLayout};
    use lunepack_crypto::Sha256Hasher;
    #[cfg(target_os = "linux")]
    use lunepack_os_linux::LinuxProcess as NativeProcess;
    #[cfg(target_os = "macos")]
    use lunepack_os_macos::MacProcess as NativeProcess;
    #[cfg(windows)]
    use lunepack_os_windows::WindowsProcess as NativeProcess;
    use lunepack_testkit::sample_update_config;

    use crate::common::{
        self, ENTRY, ENTRY_DIR, OS_NAME, OTHER_ENTRY, RUNTIME_FILE, SCHEME, TARGET, exe,
    };
    use crate::events::{Event, Events, LogSink, Sink, SinkFailed};

    pub const HELPER_ARG: &str = "helper-app";
    /// A helper mode of this binary: `sleep-for <seconds>`, a process to wait for.
    pub const SLEEP_ARG: &str = "sleep-for";
    /// Where the helper writes its notes (set on the runtime, inherited by the apps it starts).
    const OUT_VAR: &str = "LUNEPACK_APPLY_TEST_OUT";
    const INSTALL_ID: [u8; 16] = [3; 16];
    const V090: &str = "0.9.0";
    const V100: &str = "1.0.0";
    const V110: &str = "1.1.0";
    /// A bound on any one runtime run in a case.
    const RUN_LIMIT: Duration = Duration::from_secs(60);

    /// The two cases of the macOS bundle layout (an apps folder the user cannot write, a
    /// translocated runtime), skipped on the other OSes.
    #[cfg(not(target_os = "macos"))]
    const MACOS_ONLY: &str = "the macOS bundle layout (exit 28 unsupported_location)";

    /// The cases an OS skips, each with why; `run_all` prints the reason.
    #[cfg(windows)]
    const SKIPPED: &[(&str, &str)] = &[
        (
            "the_wait_target_is_never_signalled",
            "waits on a shell script that traps POSIX signals",
        ),
        (
            "a_zombie_wait_target_counts_as_exited",
            "a zombie is a procfs state",
        ),
        (
            "the_entry_directory_may_change_between_versions",
            "reads the desktop entry and the command link the Linux integration writes",
        ),
        (
            "an_apps_folder_the_user_cannot_write_is_exit_28_and_the_app_comes_back",
            MACOS_ONLY,
        ),
        (
            "a_translocated_runtime_is_exit_28_before_anything_else",
            MACOS_ONLY,
        ),
        (
            "an_apply_from_a_bundle_the_user_moved_follows_it_and_updates_it_where_it_is",
            MACOS_ONLY,
        ),
    ];
    #[cfg(target_os = "linux")]
    const SKIPPED: &[(&str, &str)] = &[
        (
            "an_apps_folder_the_user_cannot_write_is_exit_28_and_the_app_comes_back",
            MACOS_ONLY,
        ),
        (
            "a_translocated_runtime_is_exit_28_before_anything_else",
            MACOS_ONLY,
        ),
        (
            "an_apply_from_a_bundle_the_user_moved_follows_it_and_updates_it_where_it_is",
            MACOS_ONLY,
        ),
    ];
    #[cfg(target_os = "macos")]
    const SKIPPED: &[(&str, &str)] = &[];

    type Case = fn(&Lab);

    const TESTS: &[(&str, Case)] = &[
        (
            "bad_argv_exits_2_and_does_nothing",
            bad_argv_exits_2_and_does_nothing,
        ),
        (
            "confirmed_then_gc_removes_older_than_previous",
            confirmed_then_gc_removes_older_than_previous,
        ),
        (
            "crash_rolls_back_marks_bad_and_relaunches_old_without_token",
            crash_rolls_back_marks_bad_and_relaunches_old_without_token,
        ),
        (
            "exit_0_then_a_second_process_confirms",
            exit_0_then_a_second_process_confirms,
        ),
        (
            "slow_confirm_is_terminated_and_rolled_back",
            slow_confirm_is_terminated_and_rolled_back,
        ),
        (
            "confirm_racing_the_timeout_has_one_outcome",
            confirm_racing_the_timeout_has_one_outcome,
        ),
        (
            "the_wait_target_is_never_signalled",
            the_wait_target_is_never_signalled,
        ),
        (
            "a_zombie_wait_target_counts_as_exited",
            a_zombie_wait_target_counts_as_exited,
        ),
        (
            "the_entry_directory_may_change_between_versions",
            the_entry_directory_may_change_between_versions,
        ),
        (
            "a_missing_new_config_changes_nothing",
            a_missing_new_config_changes_nothing,
        ),
        (
            "nothing_staged_relaunches_the_current_version",
            nothing_staged_relaunches_the_current_version,
        ),
        (
            "an_apply_another_applier_made_starts_nothing_more",
            an_apply_another_applier_made_starts_nothing_more,
        ),
        (
            "a_record_that_moved_on_starts_nothing_more",
            a_record_that_moved_on_starts_nothing_more,
        ),
        (
            "an_apply_another_applier_rolled_back_starts_nothing_more",
            an_apply_another_applier_rolled_back_starts_nothing_more,
        ),
        (
            "an_unconfirmed_version_that_exits_to_apply_starts_again",
            an_unconfirmed_version_that_exits_to_apply_starts_again,
        ),
        (
            "a_supervised_version_that_exits_to_apply_is_not_rolled_back",
            a_supervised_version_that_exits_to_apply_is_not_rolled_back,
        ),
        (
            "a_missing_previous_config_leaves_it_pending",
            a_missing_previous_config_leaves_it_pending,
        ),
        ("a_spawn_failure_rolls_back", a_spawn_failure_rolls_back),
        (
            "gc_keeps_a_tree_in_use_as_cwd",
            gc_keeps_a_tree_in_use_as_cwd,
        ),
        (
            "the_token_never_reaches_any_output",
            the_token_never_reaches_any_output,
        ),
        (
            "a_stuck_ui_sink_does_not_delay_and_is_dropped_once",
            a_stuck_ui_sink_does_not_delay_and_is_dropped_once,
        ),
        (
            "the_log_rotates_at_one_mebibyte",
            the_log_rotates_at_one_mebibyte,
        ),
        (
            "an_apps_folder_the_user_cannot_write_is_exit_28_and_the_app_comes_back",
            an_apps_folder_the_user_cannot_write_is_exit_28_and_the_app_comes_back,
        ),
        (
            "a_translocated_runtime_is_exit_28_before_anything_else",
            a_translocated_runtime_is_exit_28_before_anything_else,
        ),
        (
            "an_apply_from_a_bundle_the_user_moved_follows_it_and_updates_it_where_it_is",
            an_apply_from_a_bundle_the_user_moved_follows_it_and_updates_it_where_it_is,
        ),
    ];

    pub fn run_all(args: &[String]) {
        let filter = args.iter().find(|a| !a.starts_with('-'));
        let mut failed = 0;
        for (name, test) in TESTS {
            if filter.is_some_and(|f| !name.contains(f.as_str())) {
                continue;
            }
            if let Some((_, why)) = SKIPPED.iter().find(|(n, _)| n == name) {
                println!("test {name} ... skipped on {OS_NAME} ({why})");
                continue;
            }
            let lab = Lab::new();
            let started = Instant::now();
            let result = std::panic::catch_unwind(|| test(&lab));
            drop(lab);
            match result {
                Ok(()) => println!("test {name} ... ok ({} ms)", started.elapsed().as_millis()),
                Err(_) => {
                    println!("test {name} ... FAILED");
                    failed += 1;
                }
            }
        }
        if failed > 0 {
            std::process::exit(1);
        }
    }

    // ---- the helper app -----------------------------------------------------------------------

    fn note(line: &str) {
        let Some(out) = std::env::var_os(OUT_VAR) else {
            return;
        };
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(Path::new(&out).join("notes"))
            .expect("notes");
        f.write_all(format!("{line}\n").as_bytes()).expect("note");
    }

    /// The app: `helper-app [mode]`.
    pub fn helper(rest: &[String]) {
        let token = std::env::var_os(HEALTH_TOKEN_VAR);
        let inst = Installation::from_current_exe().expect("installation");
        let v = inst.tree_version().to_string();
        let exe = std::env::current_exe().expect("exe");
        let mode = match rest.first() {
            Some(mode) => mode.clone(),
            None => std::fs::read_to_string(inst.tree_root().join("marker"))
                .unwrap_or_default()
                .trim()
                .to_owned(),
        };
        note(&format!(
            "{v} start token={} exe={}",
            if token.is_some() { "yes" } else { "no" },
            exe.display()
        ));
        if let Some(token) = &token {
            // The whole command line, as bytes (the argument vector on Linux, the arguments
            // joined by a space elsewhere: the token is 64 hex digits, never split by one).
            let cmdline: Vec<u8> = std::env::args_os()
                .flat_map(|a| {
                    let mut bytes = a.as_encoded_bytes().to_vec();
                    bytes.push(b' ');
                    bytes
                })
                .collect();
            let needle = token.as_encoded_bytes();
            let in_argv = cmdline.windows(needle.len()).any(|w| w == needle);
            note(&format!("{v} argv-has-token={in_argv}"));
            if mode == "save-token" {
                let out = std::env::var_os(OUT_VAR).expect("out");
                std::fs::write(Path::new(&out).join("planted-token"), needle).expect("plant");
            }
        }
        #[cfg(target_os = "linux")]
        if mode == "report" {
            report_integration(&inst, &v);
        }
        let startup = lunepack::startup().expect("startup");
        let action = match startup.action {
            StartupAction::Continue => "continue",
            StartupAction::Exit => "exit",
        };
        note(&format!("{v} startup {action}"));
        if startup.action == StartupAction::Exit {
            return;
        }
        let confirm = |v: &str| {
            let got = match lunepack::confirm_healthy() {
                Ok(ConfirmOutcome::Confirmed) => "confirmed".to_owned(),
                Ok(ConfirmOutcome::NothingPending) => "nothing_pending".to_owned(),
                Err(e) => format!("error {e}"),
            };
            note(&format!("{v} confirm {got}"));
        };
        match mode.as_str() {
            "confirm" | "save-token" => confirm(&v),
            "crash" | "report" => std::process::exit(3),
            "sleep" => std::thread::sleep(Duration::from_secs(60)),
            other => {
                if let Some(ms) = other.strip_prefix("confirm-after-") {
                    let ms: u64 = ms.parse().expect("ms");
                    std::thread::sleep(Duration::from_millis(ms));
                    confirm(&v);
                }
                if let Some(ms) = other.strip_prefix("crash-after-") {
                    let ms: u64 = ms.parse().expect("ms");
                    std::thread::sleep(Duration::from_millis(ms));
                    std::process::exit(3);
                }
                // "exit0" and anything else: exit 0 without confirming.
            }
        }
    }

    /// A process that sleeps `<seconds>` (the wait target of a case).
    pub fn sleep(rest: &[String]) {
        let secs: f64 = rest.first().and_then(|s| s.parse().ok()).expect("seconds");
        std::thread::sleep(Duration::from_secs_f64(secs));
    }

    /// Notes where the command link and the desktop entry's `Exec` point.
    #[cfg(target_os = "linux")]
    fn report_integration(inst: &Installation, v: &str) {
        let home = PathBuf::from(std::env::var_os("HOME").expect("home"));
        let bin = inst.meta().bin.clone().expect("bin");
        let link = std::fs::read_link(home.join(".local/bin").join(bin))
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        note(&format!("{v} link={link}"));
        let data = PathBuf::from(std::env::var_os("XDG_DATA_HOME").expect("data home"));
        let entry = std::fs::read_to_string(
            data.join("applications")
                .join(format!("{}.desktop", inst.app_id().as_str())),
        )
        .unwrap_or_default();
        for line in entry.lines().filter(|l| l.starts_with("Exec=")) {
            note(&format!("{v} desktop {line}"));
        }
    }

    // ---- the lab ------------------------------------------------------------------------------

    struct Lab {
        _tmp: tempfile::TempDir,
        base: PathBuf,
        home: PathBuf,
        data: PathBuf,
        root: PathBuf,
        out: PathBuf,
    }

    fn version(text: &str) -> Version {
        Version::parse(text).expect("version")
    }

    fn sha(bytes: &[u8]) -> lunepack_core::Sha256Digest {
        Sha256Hasher.sha256(bytes)
    }

    fn now_ms() -> u64 {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_millis(),
        )
        .expect("ms")
    }

    impl Lab {
        fn new() -> Lab {
            let h = common::Home::new("apply-", sample_update_config().app_id.as_str(), None, true);
            let out = h.base.join("out");
            std::fs::create_dir_all(&out).expect("out");
            Lab {
                _tmp: h.tmp,
                base: h.base,
                home: h.home,
                data: h.data,
                root: h.root,
                out,
            }
        }

        fn layout(&self) -> UserLayout {
            UserLayout::from_root(self.root.clone(), SCHEME)
        }

        /// `R/versions/<v>`: where a tree is written, and where it is parked.
        fn tree_dir(&self, v: &str) -> PathBuf {
            self.layout().versions_dir().join(v)
        }

        /// Where the tree holding `v` is now: the live bundle on macOS once it holds `v`.
        fn tree_of(&self, v: &str) -> PathBuf {
            common::tree_of(&self.layout(), v)
        }

        /// The tree an app of `v` is started from.
        fn run_tree(&self, v: &str) -> PathBuf {
            common::run_tree(&self.layout(), v)
        }

        /// Where the live bundle goes when `R/bundle` does not exist yet (macOS).
        fn bundle_default(&self) -> PathBuf {
            self.home.join("Applications/Hello.app")
        }

        fn config(&self, v: &str, entry: &str, timeout: u64) -> UpdateConfig {
            let mut cfg = sample_update_config();
            cfg.version = version(v);
            cfg.target = TARGET;
            cfg.health_timeout_secs = timeout;
            cfg.install = InstallMeta {
                entry: RelPath::parse(entry).expect("entry"),
                name: format!("Apply test {v}"),
                comment: None,
                icon: None,
                categories: Vec::new(),
                bin: Some("lp-apply-test".to_owned()),
                terminal: false,
                publisher: None,
                file_types: Vec::new(),
                url_schemes: Vec::new(),
                autostart: false,
            };
            cfg
        }

        /// `R/versions/<v>`: the config (entry `entry`), this binary as the entry, the runtime
        /// beside it, and the marker.
        fn tree(&self, v: &str, entry: &str, marker: &str, timeout: u64) -> PathBuf {
            let dir = self.tree_dir(v);
            self.tree_at(&dir, v, entry, marker, timeout);
            dir
        }

        /// The tree of `v` at `dir`, wherever that is.
        fn tree_at(&self, dir: &Path, v: &str, entry: &str, marker: &str, timeout: u64) {
            std::fs::create_dir_all(dir).expect("dirs");
            let entry = exe(entry);
            let entry = entry.as_str();
            let cfg = self.config(v, entry, timeout);
            common::write_config(dir, &cfg.to_bytes().expect("config bytes"));
            common::place_app(dir, entry);
            std::fs::write(dir.join("marker"), marker).expect("marker");
        }

        fn store(&self) -> UserScope {
            UserScope {
                dir: self.layout().state_dir(),
                app_id: sample_update_config().app_id,
            }
        }

        fn commit(&self, next: impl FnOnce(Option<&InstallState>) -> InstallState) {
            let fs = lunepack_fs::StdFs::new();
            let store = self.store();
            let loaded = store.load(&fs, &Sha256Hasher).expect("load");
            let next = next(loaded.record.as_ref());
            store
                .commit(&fs, &loaded, &next, &Sha256Hasher)
                .expect("commit");
        }

        fn record(&self) -> InstallState {
            self.store()
                .load(&lunepack_fs::StdFs::new(), &Sha256Hasher)
                .expect("load")
                .record
                .expect("record")
        }

        /// [`Lab::commit`], then the record's current version is the live one: on macOS its tree
        /// is moved to the live bundle and the pointer and identity are written (the core's
        /// writers); elsewhere the runtime projects it at its first start.
        fn commit_live(&self, next: impl FnOnce(Option<&InstallState>) -> InstallState) {
            self.commit(next);
            let current = self.record().current.expect("a current version").version;
            common::project(&self.layout(), &self.bundle_default(), &current.to_string());
        }

        /// 1.0.0 installed (live) and `staged` staged (bound), with the core's real writer.
        fn install(&self, staged: &str) {
            self.commit_live(|_| {
                let app = sample_update_config().app_id;
                InstallState::new(1, app, Scope::User, INSTALL_ID, TARGET)
                    .install(version(V100), 10, TARGET, INSTALL_ID)
                    .set_staged(Some((
                        StagedRef::new(version(staged), TARGET, sha(staged.as_bytes())),
                        20,
                    )))
            });
        }

        fn command(&self, program: &Path) -> Command {
            let mut cmd = Command::new(program);
            cmd.env("HOME", &self.home)
                .env("XDG_DATA_HOME", &self.data)
                .env(OUT_VAR, &self.out)
                .env_remove(HEALTH_TOKEN_VAR)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            common::quiet_ui(&mut cmd);
            cmd
        }

        /// Starts `from`'s runtime: `apply --wait-pid … --wait-start … --version v -- helper-app`.
        fn start_apply(&self, from: &str, entry_dir: &str, wait: ProcessId, v: &str) -> Child {
            self.start_apply_with(from, entry_dir, wait, v, &[HELPER_ARG])
        }

        /// [`Lab::start_apply`] with `restart` after `--` (`helper-app <mode>` overrides the
        /// started tree's marker).
        fn start_apply_with(
            &self,
            from: &str,
            entry_dir: &str,
            wait: ProcessId,
            v: &str,
            restart: &[&str],
        ) -> Child {
            let runtime = self.tree_of(from).join(entry_dir).join(RUNTIME_FILE);
            self.command(&runtime)
                .args([
                    "apply",
                    "--wait-pid",
                    &wait.pid.to_string(),
                    "--wait-start",
                    &wait.start_ticks.to_string(),
                    "--version",
                    v,
                    "--",
                ])
                .args(restart)
                .spawn()
                .expect("runtime")
        }

        /// Runs the apply to its end; returns its exit code and everything it printed.
        fn apply(&self, from: &str, wait: ProcessId, v: &str) -> (i32, Vec<u8>) {
            let child = self.start_apply(from, ENTRY_DIR, wait, v);
            finish(child)
        }

        fn notes(&self) -> String {
            std::fs::read_to_string(self.out.join("notes")).unwrap_or_default()
        }

        fn wait_note(&self, needle: &str, limit: Duration) -> bool {
            wait_until(limit, || self.notes().contains(needle))
        }

        fn log(&self) -> String {
            let logs = self.layout().logs_dir();
            let mut text = std::fs::read_to_string(logs.join("runtime.log.1")).unwrap_or_default();
            text.push_str(&std::fs::read_to_string(logs.join("runtime.log")).unwrap_or_default());
            text
        }

        /// The live version is `v`: `R/current` names it (Linux), the live bundle holds it and
        /// `R/current` does not exist (macOS), and the live tree's own config names `v`.
        fn assert_live(&self, v: &str) {
            common::assert_live(&self.layout(), v);
        }

        /// `R/versions/<v>` holds the tree of `v`.
        fn assert_parked(&self, v: &str) {
            common::assert_parked(&self.layout(), v);
        }
    }

    /// Waits for `child` (at most [`RUN_LIMIT`], then kills it and fails); its exit code and its
    /// stdout and stderr.
    fn finish(mut child: Child) -> (i32, Vec<u8>) {
        let start = Instant::now();
        loop {
            if child.try_wait().expect("wait").is_some() {
                break;
            }
            if start.elapsed() > RUN_LIMIT {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the runtime ran too long");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let out = child.wait_with_output().expect("output");
        let mut all = out.stdout;
        all.extend_from_slice(&out.stderr);
        (out.status.code().unwrap_or(-1), all)
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

    /// A process that runs for `secs` (reaped by a thread), and its id.
    fn target(secs: &str) -> ProcessId {
        let mut child = Command::new(std::env::current_exe().expect("exe"))
            .args([SLEEP_ARG, secs])
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

    fn assert_rolled_back(lab: &Lab) {
        let r = lab.record();
        assert_eq!(r.current.as_ref().expect("current").version, version(V100));
        assert!(r.pending.is_none(), "pending after rollback");
        assert!(r.health.is_none(), "health after rollback");
        assert!(r.bad.contains(&version(V110)), "1.1.0 not marked bad");
        lab.assert_live("1.0.0");
    }

    fn assert_confirmed(lab: &Lab) {
        let r = lab.record();
        assert_eq!(r.current.as_ref().expect("current").version, version(V110));
        assert_eq!(
            r.previous.as_ref().expect("previous").version,
            version(V100)
        );
        assert!(r.pending.is_none(), "still pending");
        assert!(r.health.is_none(), "health left");
        assert!(r.bad.is_empty(), "marked bad");
        lab.assert_live("1.1.0");
    }

    fn log_has(lab: &Lab, needle: &str) -> bool {
        lab.log().contains(needle)
    }

    /// The `time_ms` of the first log line holding `needle`.
    fn log_time(lab: &Lab, needle: &str) -> u64 {
        let log = lab.log();
        let line = log
            .lines()
            .find(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no log line with {needle}"));
        let at = line.rfind("\"time_ms\":").expect("time") + "\"time_ms\":".len();
        line[at..].trim_end_matches('}').parse().expect("time_ms")
    }

    // ---- the cases ------------------------------------------------------------------------------

    fn bad_argv_exits_2_and_does_nothing(lab: &Lab) {
        lab.tree(V100, ENTRY, "exit0", 5);
        lab.tree(V110, ENTRY, "confirm", 5);
        lab.install(V110);
        let before = lab.record();
        let runtime = lab.tree_of(V100).join(ENTRY_DIR).join(RUNTIME_FILE);
        for args in [
            vec![],
            vec!["apply"],
            vec!["apply", "--wait-pid", "1", "--wait-start", "2"],
            vec![
                "apply",
                "--wait-pid",
                "1",
                "--wait-pid",
                "1",
                "--wait-start",
                "2",
                "--version",
                V110,
            ],
            vec![
                "apply",
                "--wait-pid",
                "x/secret/path",
                "--wait-start",
                "2",
                "--version",
                V110,
            ],
            vec!["frobnicate", "--secret"],
        ] {
            let out = lab.command(&runtime).args(&args).output().expect("run");
            assert_eq!(out.status.code(), Some(2), "{args:?}");
            assert!(out.stdout.is_empty());
            assert_eq!(out.stderr, b"lunepack-runtime: usage error\n");
        }
        assert_eq!(lab.record(), before);
        assert!(
            !lab.layout().logs_dir().exists(),
            "a usage error wrote a log"
        );
        assert!(lab.notes().is_empty(), "a usage error started something");
    }

    fn confirmed_then_gc_removes_older_than_previous(lab: &Lab) {
        let old = lab.tree_dir(V090);
        std::fs::create_dir_all(old.join("bin")).expect("0.9.0");
        std::fs::write(old.join("bin/app"), b"old").expect("old file");
        // Not version trees: a non-canonical name, a symlink (Unix), a file.
        let versions = lab.layout().versions_dir();
        std::fs::create_dir_all(versions.join("v0.8.0")).expect("odd dir");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&old, versions.join("0.7.0")).expect("link");
        std::fs::write(versions.join("0.6.0"), b"file").expect("file");
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, ENTRY, "confirm", 30);
        lab.install(V110);
        let (code, output) = lab.apply(V100, target("0.2"), V110);
        assert_eq!(code, 0);
        assert_confirmed(lab);
        let notes = lab.notes();
        assert!(notes.contains("1.1.0 start token=yes"), "{notes}");
        assert!(notes.contains("1.1.0 confirm confirmed"), "{notes}");
        // The new version ran from where the layout runs a version from (the live bundle on
        // macOS), with the token in the environment and never in its arguments.
        let want_exe = common::join_rel(&lab.run_tree(V110), &exe(ENTRY));
        assert!(
            notes.contains(&format!("1.1.0 start token=yes exe={}", want_exe.display())),
            "want {}: {notes}",
            want_exe.display()
        );
        assert!(notes.contains("1.1.0 argv-has-token=false"), "{notes}");
        assert!(!old.exists(), "GC kept 0.9.0");
        // The kept trees stay: 1.1.0 live, 1.0.0 the previous version.
        lab.assert_parked(V100);
        assert!(lab.tree_of(V110).exists());
        assert!(
            !String::from_utf8_lossy(&output).contains("token"),
            "the output names the token"
        );
        assert!(versions.join("v0.8.0").exists());
        #[cfg(unix)]
        assert!(std::fs::symlink_metadata(versions.join("0.7.0")).is_ok());
        assert!(versions.join("0.6.0").exists());
        for phase in ["wait", "apply", "launch", "confirm"] {
            assert!(
                log_has(lab, &format!("\"phase\":\"{phase}\"")),
                "no {phase} phase"
            );
        }
        assert!(log_has(lab, "\"outcome\":\"confirmed\""));
        // The bin link and the desktop entry point through current (Linux).
        #[cfg(target_os = "linux")]
        {
            let link = std::fs::read_link(lab.home.join(".local/bin/lp-apply-test")).expect("link");
            assert_eq!(link, lab.root.join("current/bin/app"));
        }
    }

    fn crash_rolls_back_marks_bad_and_relaunches_old_without_token(lab: &Lab) {
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, ENTRY, "crash", 30);
        lab.install(V110);
        let (code, _) = lab.apply(V100, target("0.2"), V110);
        assert_eq!(code, 20);
        assert_rolled_back(lab);
        assert!(lab.notes().contains("1.1.0 start token=yes"));
        assert!(
            lab.wait_note("1.0.0 start token=no", Duration::from_secs(10)),
            "1.0.0 was not relaunched: {}",
            lab.notes()
        );
        assert!(!lab.notes().contains("1.0.0 start token=yes"));
        assert!(log_has(lab, "\"phase\":\"rollback\""));
        assert!(log_has(lab, "\"reason\":\"crashed\""));
        assert!(log_has(lab, "\"outcome\":\"rolled_back\""));
        // The bad tree is no longer kept (rolled back, it was parked under its version first).
        assert!(!lab.tree_dir(V110).exists(), "GC kept the bad tree");
    }

    fn exit_0_then_a_second_process_confirms(lab: &Lab) {
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, ENTRY, "exit0", 30);
        lab.install(V110);
        let runtime = lab.start_apply(V100, ENTRY_DIR, target("0.2"), V110);
        assert!(
            lab.wait_note("1.1.0 startup continue", Duration::from_secs(10)),
            "the first start did not run"
        );
        // The supervised child exited 0 without confirming; the apply is still waiting.
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            lab.record().pending.as_ref().map(|p| p.version.clone()),
            Some(version(V110))
        );
        let second = lab
            .command(&lab.tree_of(V110).join(exe(ENTRY)))
            .args([HELPER_ARG, "confirm"])
            .output()
            .expect("second");
        assert!(second.status.success());
        assert!(lab.notes().contains("1.1.0 start token=no"));
        assert!(lab.notes().contains("1.1.0 confirm confirmed"));
        let started = Instant::now();
        let (code, _) = finish(runtime);
        assert_eq!(code, 0);
        assert!(started.elapsed() < Duration::from_secs(5), "slow to notice");
        assert_confirmed(lab);
    }

    fn slow_confirm_is_terminated_and_rolled_back(lab: &Lab) {
        lab.tree(V100, ENTRY, "exit0", 5);
        lab.tree(V110, ENTRY, "confirm-after-8000", 5);
        lab.install(V110);
        let started = Instant::now();
        let (code, _) = lab.apply(V100, target("0.1"), V110);
        let took = started.elapsed();
        assert_eq!(code, 20);
        assert!(
            took >= Duration::from_secs(5),
            "rolled back early: {took:?}"
        );
        assert!(took < Duration::from_secs(12), "rolled back late: {took:?}");
        assert_rolled_back(lab);
        assert!(log_has(lab, "\"reason\":\"timeout\""));
        // The child was ended: it never got to confirm.
        std::thread::sleep(Duration::from_secs(4));
        assert!(!lab.notes().contains("1.1.0 confirm"), "{}", lab.notes());
    }

    fn confirm_racing_the_timeout_has_one_outcome(_: &Lab) {
        for offset in ["4950", "5000", "5050"] {
            let lab = &Lab::new();
            lab.tree(V100, ENTRY, "exit0", 5);
            lab.tree(V110, ENTRY, &format!("confirm-after-{offset}"), 5);
            lab.install(V110);
            let (code, _) = lab.apply(V100, target("0.1"), V110);
            // Let a confirm that was under way finish (or be ended).
            std::thread::sleep(Duration::from_millis(500));
            let notes = lab.notes();
            match code {
                0 => {
                    assert_confirmed(lab);
                    assert!(notes.contains("1.1.0 confirm confirmed"), "{notes}");
                }
                20 => {
                    assert_rolled_back(lab);
                    assert!(!notes.contains("1.1.0 confirm confirmed"), "{notes}");
                }
                other => panic!("exit {other} at {offset}"),
            }
            println!("  offset {offset} ms: exit {code}");
        }
    }

    fn the_wait_target_is_never_signalled(lab: &Lab) {
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, ENTRY, "confirm", 30);
        lab.install(V110);
        let done = lab.out.join("target-done");
        let script = format!(
            "trap '' HUP INT QUIT TERM USR1 USR2 PIPE ALRM; sleep 1.5; echo done > '{}'",
            done.display()
        );
        let mut child = Command::new("/bin/sh")
            .args(["-c", &script])
            .spawn()
            .expect("target");
        let id = NativeProcess::new()
            .process_id(child.id())
            .expect("probe")
            .expect("running");
        let runtime = lab.start_apply(V100, ENTRY_DIR, id, V110);
        let status = child.wait().expect("target wait");
        let exited_at = now_ms();
        assert!(status.success(), "the target was disturbed: {status:?}");
        assert!(done.exists(), "the target did not finish its own work");
        let (code, _) = finish(runtime);
        assert_eq!(code, 0);
        assert_confirmed(lab);
        // The commit came after the target's exit (50 ms of slack for the clock read).
        assert!(log_time(lab, "\"phase\":\"apply\"") + 50 >= exited_at);
    }

    fn a_zombie_wait_target_counts_as_exited(lab: &Lab) {
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, ENTRY, "confirm", 30);
        lab.install(V110);
        let mut zombie = Command::new("sleep").arg("0.2").spawn().expect("sleep");
        let id = NativeProcess::new()
            .process_id(zombie.id())
            .expect("probe")
            .expect("running");
        // Not reaped: it stays a zombie of this process.
        std::thread::sleep(Duration::from_millis(600));
        assert!(common::is_zombie(id.pid), "not a zombie");
        let (code, _) = lab.apply(V100, id, V110);
        assert_eq!(code, 0);
        let waited = log_time(lab, "\"phase\":\"apply\"") - log_time(lab, "\"phase\":\"wait\"");
        assert!(waited < 1000, "waited {waited} ms for a zombie");
        let _ = zombie.wait();
        assert_confirmed(lab);
    }

    fn the_entry_directory_may_change_between_versions(lab: &Lab) {
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, OTHER_ENTRY, "report", 30);
        lab.install(V110);
        let (code, _) = lab.apply(V100, target("0.1"), V110);
        assert_eq!(code, 20);
        let notes = lab.notes();
        let new_exe = common::join_rel(&lab.run_tree(V110), OTHER_ENTRY);
        assert!(
            notes.contains(&format!("1.1.0 start token=yes exe={}", new_exe.display())),
            "{notes}"
        );
        // The desktop entry and the command link point through `R/current` (Linux only).
        #[cfg(target_os = "linux")]
        let current = lab.root.join("current");
        #[cfg(target_os = "linux")]
        {
            assert!(
                notes.contains(&format!(
                    "1.1.0 link={}",
                    current.join(OTHER_ENTRY).display()
                )),
                "{notes}"
            );
            assert!(
                notes.contains(&format!(
                    "1.1.0 desktop Exec=\"{}\"",
                    current.join(OTHER_ENTRY).display()
                )),
                "{notes}"
            );
        }
        let old_exe = common::join_rel(&lab.run_tree(V100), ENTRY);
        assert!(
            lab.wait_note(
                &format!("1.0.0 start token=no exe={}", old_exe.display()),
                Duration::from_secs(10)
            ),
            "{}",
            lab.notes()
        );
        assert_rolled_back(lab);
        // The integration followed the rollback.
        #[cfg(target_os = "linux")]
        {
            let link = std::fs::read_link(lab.home.join(".local/bin/lp-apply-test")).expect("link");
            assert_eq!(link, current.join(ENTRY));
            let desktop = std::fs::read_to_string(lab.data.join("applications").join(format!(
                "{}.desktop",
                sample_update_config().app_id.as_str()
            )))
            .expect("desktop entry");
            assert!(desktop.contains(&format!("Exec=\"{}\"", current.join(ENTRY).display())));
        }
    }

    fn a_missing_new_config_changes_nothing(lab: &Lab) {
        lab.tree(V100, ENTRY, "exit0", 30);
        let new = lab.tree(V110, ENTRY, "confirm", 30);
        std::fs::remove_file(common::config_in(&new)).expect("remove config");
        lab.install(V110);
        let before = lab.record();
        let (code, _) = lab.apply(V100, target("0.1"), V110);
        assert_eq!(code, 14);
        assert_eq!(lab.record(), before);
        assert!(log_has(lab, "\"kind\":\"update_config\""));
        // The app exited for the apply: the current version starts again, without the token.
        assert!(
            lab.wait_note("1.0.0 startup continue", Duration::from_secs(10)),
            "1.0.0 was not relaunched: {}",
            lab.notes()
        );
        assert!(lab.notes().contains("1.0.0 start token=no"));
        // Its own startup reconciled `current`, to the version that is still current.
        lab.assert_live("1.0.0");
        assert!(!lab.notes().contains("1.1.0 start"), "1.1.0 was started");
        assert!(!lab.notes().contains("token=yes"));
    }

    fn nothing_staged_relaunches_the_current_version(lab: &Lab) {
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, ENTRY, "confirm", 30);
        lab.commit_live(|r| {
            let app = sample_update_config().app_id;
            assert!(r.is_none());
            InstallState::new(1, app, Scope::User, INSTALL_ID, TARGET).install(
                version(V100),
                10,
                TARGET,
                INSTALL_ID,
            )
        });
        let before = lab.record();
        let (code, _) = lab.apply(V100, target("0.1"), V110);
        assert_eq!(code, 12);
        assert_eq!(lab.record(), before);
        assert!(log_has(lab, "\"kind\":\"nothing_staged\""));
        assert!(
            lab.wait_note("1.0.0 start token=no", Duration::from_secs(10)),
            "1.0.0 was not relaunched: {}",
            lab.notes()
        );
        assert!(!lab.notes().contains("1.1.0 start"), "1.1.0 was started");
    }

    /// Long enough for a detached relaunch, had there been one, to note its start.
    const NO_START_WAIT: Duration = Duration::from_secs(3);

    /// F17: another applier for the same version (a second app instance, or `apply-and-restart`
    /// called twice) committed it first and launched it; this one is refused and starts nothing.
    fn an_apply_another_applier_made_starts_nothing_more(lab: &Lab) {
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, ENTRY, "confirm", 30);
        lab.install(V110);
        lab.commit(|r| {
            lunepack_core::apply(
                r.expect("record"),
                &version(V110),
                sha(b"the other applier"),
            )
            .expect("apply")
        });
        let before = lab.record();
        assert_eq!(
            before.pending.as_ref().map(|p| p.version.clone()),
            Some(version(V110))
        );
        let (code, _) = lab.apply(V100, target("0.1"), V110);
        assert_eq!(code, 12);
        assert_eq!(lab.record(), before);
        assert!(log_has(lab, "\"kind\":\"nothing_staged\""));
        assert!(
            !lab.wait_note(" start ", NO_START_WAIT),
            "an app was started: {}",
            lab.notes()
        );
        assert!(!log_has(lab, "relaunch_failed"));
    }

    /// F17: the record names another current version and nothing pending (the update was applied
    /// and confirmed elsewhere): the outgoing version is not started again.
    fn a_record_that_moved_on_starts_nothing_more(lab: &Lab) {
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, ENTRY, "confirm", 30);
        lab.install(V110);
        lab.commit(|r| {
            let applied =
                lunepack_core::apply(r.expect("record"), &version(V110), sha(b"elsewhere"))
                    .expect("apply");
            let (confirmed, _) =
                lunepack_core::confirm(&applied, &version(V110), lunepack_core::TokenCheck::Absent)
                    .expect("confirm");
            confirmed
        });
        let before = lab.record();
        assert!(before.pending.is_none());
        let (code, _) = lab.apply(V100, target("0.1"), V110);
        assert_eq!(code, 12);
        assert_eq!(lab.record(), before);
        assert!(
            !lab.wait_note(" start ", NO_START_WAIT),
            "an app was started: {}",
            lab.notes()
        );
    }

    /// F21: another applier for the same version (`apply-and-restart` called twice) applied it,
    /// the version crashed, and that applier rolled it back and started 1.0.0 again, all before
    /// this applier's commit window. The record is back where the app left it (1.0.0 current,
    /// nothing pending) except that 1.1.0 is bad: this applier is refused and starts nothing more.
    fn an_apply_another_applier_rolled_back_starts_nothing_more(lab: &Lab) {
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, ENTRY, "crash", 30);
        lab.install(V110);
        lab.commit(|r| {
            let applied = lunepack_core::apply(
                r.expect("record"),
                &version(V110),
                sha(b"the other applier"),
            )
            .expect("apply");
            lunepack_core::rollback(&applied, &version(V110)).expect("rollback")
        });
        let before = lab.record();
        assert_eq!(
            before.current.as_ref().map(|c| c.version.clone()),
            Some(version(V100))
        );
        assert!(before.pending.is_none() && before.staged.is_none());
        assert!(before.bad.contains(&version(V110)));
        let (code, _) = lab.apply(V100, target("0.1"), V110);
        assert_eq!(code, 12);
        assert_eq!(lab.record(), before);
        assert!(log_has(lab, "\"kind\":\"nothing_staged\""));
        assert!(
            !lab.wait_note(" start ", NO_START_WAIT),
            "an app was started: {}",
            lab.notes()
        );
        assert!(!log_has(lab, "relaunch_failed"));
    }

    /// `staged` staged (bound) in `record`, with the core's real writer.
    fn staging(record: &InstallState, staged: &str) -> InstallState {
        record.set_staged(Some((
            StagedRef::new(version(staged), TARGET, sha(staged.as_bytes())),
            30,
        )))
    }

    /// 0.9.0 installed and `staged` staged (bound).
    fn installed_090(staged: &str) -> InstallState {
        let app = sample_update_config().app_id;
        let record = InstallState::new(1, app, Scope::User, INSTALL_ID, TARGET).install(
            version(V090),
            10,
            TARGET,
            INSTALL_ID,
        );
        staging(&record, staged)
    }

    /// F19: the version that exited is itself pending its health check (it asked for the update
    /// before it confirmed, and no supervisor is left). The core refuses the apply while a version
    /// is pending; the record did not move on, so that version starts again without the token,
    /// and the start counts as an unconfirmed one.
    fn an_unconfirmed_version_that_exits_to_apply_starts_again(lab: &Lab) {
        lab.tree(V090, ENTRY, "exit0", 30);
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, ENTRY, "confirm", 30);
        let gone = sha(b"a supervisor that is gone");
        lab.commit_live(|_| {
            let pending =
                lunepack_core::apply(&installed_090(V100), &version(V100), gone).expect("apply");
            staging(&pending, V110)
        });
        let (code, _) = lab.apply(V100, target("0.1"), V110);
        // The core's refusal (a version is pending) is the facade's `Verify` error.
        assert_eq!(code, 7);
        assert!(log_has(lab, "\"kind\":\"verify\""));
        assert!(
            lab.wait_note("1.0.0 startup continue", Duration::from_secs(10)),
            "1.0.0 was not relaunched: {}",
            lab.notes()
        );
        let notes = lab.notes();
        assert!(notes.contains("1.0.0 start token=no"), "{notes}");
        assert!(!notes.contains("token=yes"), "{notes}");
        assert!(!notes.contains("1.1.0 start"), "1.1.0 was started: {notes}");
        // Nothing was applied; the relaunch counted one unconfirmed start of 1.0.0.
        let r = lab.record();
        assert_eq!(r.current.as_ref().expect("current").version, version(V100));
        assert_eq!(
            r.pending.as_ref().map(|p| (p.version.clone(), p.attempts)),
            Some((version(V100), 1))
        );
        assert_eq!(r.health.as_ref().map(|h| h.token_sha256), Some(gone));
        assert_eq!(
            r.staged.as_ref().map(|s| s.version.clone()),
            Some(version(V110))
        );
        assert!(r.bad.is_empty(), "marked bad");
        lab.assert_live("1.0.0");
    }

    /// F19 with the pending version's supervisor still running: started with its token, 1.0.0
    /// exits 0 for an apply before it confirms, and the apply is refused. Started again without
    /// the token, it confirms, so its supervisor ends confirmed instead of rolling a healthy
    /// version back at its timeout.
    fn a_supervised_version_that_exits_to_apply_is_not_rolled_back(lab: &Lab) {
        lab.tree(V090, ENTRY, "exit0", 30);
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, ENTRY, "confirm", 30);
        lab.commit_live(|_| installed_090(V100));
        let supervisor = lab.start_apply(V090, ENTRY_DIR, target("0.1"), V100);
        assert!(
            lab.wait_note("1.0.0 startup continue", Duration::from_secs(10)),
            "1.0.0 did not start: {}",
            lab.notes()
        );
        assert!(lab.notes().contains("1.0.0 start token=yes"));
        // 1.1.0 is staged meanwhile, and 1.0.0 asks for it before it confirms.
        lab.commit(|r| staging(r.expect("record"), V110));
        let applier = lab.start_apply_with(
            V100,
            ENTRY_DIR,
            target("0.1"),
            V110,
            &[HELPER_ARG, "confirm"],
        );
        let (code, _) = finish(applier);
        assert_eq!(code, 7);
        let (code, _) = finish(supervisor);
        assert_eq!(
            code,
            0,
            "the supervisor did not end confirmed: {}",
            lab.notes()
        );
        let notes = lab.notes();
        assert!(notes.contains("1.0.0 start token=no"), "{notes}");
        assert!(notes.contains("1.0.0 confirm confirmed"), "{notes}");
        assert!(!notes.contains("1.1.0 start"), "1.1.0 was started: {notes}");
        assert!(
            !notes.contains("0.9.0 start"),
            "0.9.0 was relaunched: {notes}"
        );
        assert!(log_has(lab, "\"outcome\":\"confirmed\""));
        assert!(!log_has(lab, "\"phase\":\"rollback\""));
        let r = lab.record();
        assert_eq!(r.current.as_ref().expect("current").version, version(V100));
        assert_eq!(
            r.previous.as_ref().expect("previous").version,
            version(V090)
        );
        assert!(r.pending.is_none(), "still pending");
        assert!(r.health.is_none(), "health left");
        assert!(r.bad.is_empty(), "marked bad");
        assert_eq!(
            r.staged.as_ref().map(|s| s.version.clone()),
            Some(version(V110))
        );
        lab.assert_live("1.0.0");
    }

    fn a_missing_previous_config_leaves_it_pending(lab: &Lab) {
        // When the previous version's config goes missing. Linux and Windows: while the applier
        // waits for its target. macOS: 1.0.0's tree is the live bundle until the swap, and a
        // bundle that holds no config is no bundle (the swap refuses it, exit 7, nothing
        // started), so it goes missing from the parked tree once 1.1.0 runs, the moment a
        // rollback reads it; 1.1.0 then crashes 1.5 s later.
        let macos = cfg!(target_os = "macos");
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(
            V110,
            ENTRY,
            if macos { "crash-after-1500" } else { "crash" },
            30,
        );
        lab.install(V110);
        let runtime = lab.start_apply(V100, ENTRY_DIR, target("1.5"), V110);
        if macos {
            assert!(
                lab.wait_note("1.1.0 startup continue", Duration::from_secs(10)),
                "1.1.0 did not start: {}",
                lab.notes()
            );
            lab.assert_parked(V100);
            std::fs::remove_file(common::config_in(&lab.tree_dir(V100))).expect("remove config");
        } else {
            assert!(
                wait_until(Duration::from_secs(5), || log_has(
                    lab,
                    "\"phase\":\"wait\""
                )),
                "no wait phase"
            );
            std::fs::remove_file(common::config_in(&lab.tree_of(V100))).expect("remove config");
        }
        let (code, _) = finish(runtime);
        assert_eq!(code, 22);
        let r = lab.record();
        assert_eq!(
            r.pending.as_ref().map(|p| p.version.clone()),
            Some(version(V110))
        );
        assert!(r.bad.is_empty());
        assert!(log_has(lab, "\"code\":\"rollback_unavailable\""));
        assert!(!lab.notes().contains("1.0.0 start"), "1.0.0 was relaunched");
    }

    fn a_spawn_failure_rolls_back(lab: &Lab) {
        lab.tree(V100, ENTRY, "exit0", 30);
        let new = lab.tree(V110, ENTRY, "confirm", 30);
        std::fs::remove_file(new.join(exe(ENTRY))).expect("remove entry");
        lab.install(V110);
        let (code, _) = lab.apply(V100, target("0.1"), V110);
        assert_eq!(code, 20);
        assert_rolled_back(lab);
        assert!(log_has(lab, "\"reason\":\"spawn_failed\""));
        assert!(lab.wait_note("1.0.0 start token=no", Duration::from_secs(10)));
    }

    fn gc_keeps_a_tree_in_use_as_cwd(lab: &Lab) {
        let old = lab.tree_dir(V090);
        std::fs::create_dir_all(&old).expect("0.9.0");
        // A process that uses the old tree: on Linux one whose working directory is in it, on
        // Windows (which scans image paths) a copy of the test binary running from it.
        #[cfg(not(windows))]
        let mut user = Command::new("sleep")
            .arg("30")
            .current_dir(&old)
            .spawn()
            .expect("sleep");
        #[cfg(windows)]
        let mut user = {
            let copy = old.join("user.exe");
            std::fs::copy(std::env::current_exe().expect("exe"), &copy).expect("copy");
            Command::new(&copy)
                .args([SLEEP_ARG, "30"])
                .spawn()
                .expect("user")
        };
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, ENTRY, "confirm", 30);
        lab.install(V110);
        let (code, _) = lab.apply(V100, target("0.1"), V110);
        let _ = user.kill();
        let _ = user.wait();
        assert_eq!(code, 0);
        assert!(old.exists(), "GC removed a tree in use");
        assert!(log_has(lab, "\"code\":\"gc_in_use\""));
    }

    fn the_token_never_reaches_any_output(lab: &Lab) {
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, ENTRY, "save-token", 30);
        lab.install(V110);
        let (code, printed) = lab.apply(V100, target("0.1"), V110);
        assert_eq!(code, 0);
        let token = std::fs::read(lab.out.join("planted-token")).expect("planted token");
        assert_eq!(token.len(), 64);
        assert!(
            token
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
            "not lowercase hex"
        );
        assert!(lab.notes().contains("1.1.0 argv-has-token=false"));
        let upper = token.to_ascii_uppercase();
        let raw: Vec<u8> = token
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).expect("hex"), 16).expect("hex"))
            .collect();
        let mut haystacks: Vec<(String, Vec<u8>)> = vec![("runtime output".into(), printed)];
        haystacks.push(("notes".into(), lab.notes().into_bytes()));
        let layout = lab.layout();
        for dir in [layout.logs_dir(), layout.state_dir()] {
            for entry in std::fs::read_dir(&dir).expect("dir") {
                let path = entry.expect("entry").path();
                if path.is_file() {
                    haystacks.push((
                        path.display().to_string(),
                        std::fs::read(&path).expect("read"),
                    ));
                }
            }
        }
        assert!(haystacks.len() >= 4, "too few files searched");
        for (name, bytes) in &haystacks {
            for needle in [&token, &upper, &raw] {
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle.as_slice()),
                    "the token is in {name}"
                );
            }
        }
        // The instrument finds what it looks for.
        let planted = [b"x".as_slice(), &token, b"y"].concat();
        assert!(planted.windows(token.len()).any(|w| w == token.as_slice()));
        assert_confirmed(lab);
    }

    /// A UI sink that never returns from its first event.
    struct Stuck;

    impl Sink for Stuck {
        fn name(&self) -> &'static str {
            "ui"
        }
        fn deliver(&mut self, _: &Event) -> Result<(), SinkFailed> {
            loop {
                std::thread::park();
            }
        }
    }

    /// A UI sink that fails at once.
    struct Broken;

    impl Sink for Broken {
        fn name(&self) -> &'static str {
            "ui"
        }
        fn deliver(&mut self, _: &Event) -> Result<(), SinkFailed> {
            Err(SinkFailed)
        }
    }

    fn a_stuck_ui_sink_does_not_delay_and_is_dropped_once(lab: &Lab) {
        let fs: Arc<dyn lunepack::Fs> = Arc::new(lunepack_fs::StdFs::new());
        let wait = Event::phase(Phase::Wait, Some(&version(V110)));
        for (name, ui) in [
            ("stuck", Box::new(Stuck) as Box<dyn Sink>),
            ("broken", Box::new(Broken) as Box<dyn Sink>),
        ] {
            let logs = lab.out.join(name);
            let events = Events::new(
                Some(Box::new(LogSink::new(Arc::clone(&fs), logs.clone()))),
                Some(ui),
            );
            let started = Instant::now();
            // Progress coalesces (latest wins), so a stuck sink's queue never fills with it.
            for i in 0..2000u64 {
                events.emit(&Event::Progress(Progress {
                    phase: Phase::Download,
                    done: i,
                    total: 2000,
                    file: None,
                }));
                if i % 50 == 0 {
                    events.emit(&wait);
                }
            }
            events.emit(&Event::phase(Phase::Apply, Some(&version(V110))));
            let emitted = started.elapsed();
            assert!(
                emitted < Duration::from_millis(500),
                "{name}: emit took {emitted:?}"
            );
            if name == "broken" {
                assert!(
                    wait_until(Duration::from_secs(2), || events.dropped() == vec!["ui"]),
                    "the broken sink was not dropped"
                );
                // Emits after the drop report it once.
                events.emit(&wait);
                events.emit(&wait);
            }
            let finishing = Instant::now();
            events.finish(Duration::from_secs(1));
            let took = finishing.elapsed();
            assert!(
                took < Duration::from_millis(2500),
                "{name}: finish took {took:?}"
            );
            let log = std::fs::read_to_string(logs.join("runtime.log")).expect("log");
            let dropped = usize::from(name == "broken");
            assert_eq!(
                log.matches("\"code\":\"sink_dropped\"").count(),
                dropped,
                "{name}"
            );
            assert!(
                log.contains("\"phase\":\"apply\""),
                "{name}: the log missed events"
            );
            let waits = 40 + 2 * dropped;
            assert_eq!(log.matches("\"phase\":\"wait\"").count(), waits, "{name}");
        }
        // A stuck sink whose queue fills with events that cannot coalesce is dropped, and emit
        // still never blocks.
        let events = Events::new(None, Some(Box::new(Stuck)));
        let started = Instant::now();
        for _ in 0..200 {
            events.emit(&wait);
        }
        assert!(started.elapsed() < Duration::from_millis(200));
        assert_eq!(events.dropped(), vec!["ui"]);
        events.finish(Duration::from_millis(100));
    }

    fn the_log_rotates_at_one_mebibyte(lab: &Lab) {
        let fs: Arc<dyn lunepack::Fs> = Arc::new(lunepack_fs::StdFs::new());
        let logs = lab.out.join("rotate");
        let mut sink = LogSink::new(fs, logs.clone());
        let event = Event::phase(Phase::Confirm, Some(&version(V110)));
        let mut written = 0usize;
        while written < 3 * 1024 * 1024 {
            sink.deliver(&event).expect("deliver");
            written += 100;
        }
        let new = std::fs::metadata(logs.join("runtime.log"))
            .expect("log")
            .len();
        let old = std::fs::metadata(logs.join("runtime.log.1"))
            .expect("old log")
            .len();
        assert!(new <= 1024 * 1024 && old <= 1024 * 1024, "{new} {old}");
        assert!(old > 1024 * 1024 - 200, "rotated early: {old}");
        let names: Vec<OsString> = std::fs::read_dir(&logs)
            .expect("dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
    }

    /// macOS: the apps folder the live bundle is in is not writable by the user. The apply is
    /// refused before anything moves (exit 28, `not_writable`), the record is as it was, and the
    /// app that exited for the apply comes back as the version it was.
    #[cfg(unix)]
    fn an_apps_folder_the_user_cannot_write_is_exit_28_and_the_app_comes_back(lab: &Lab) {
        use std::os::unix::fs::PermissionsExt;
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, ENTRY, "confirm", 30);
        lab.install(V110);
        let apps = lab.home.join("Applications");
        std::fs::set_permissions(&apps, std::fs::Permissions::from_mode(0o555)).expect("chmod");
        let before = lab.record();
        let (code, printed) = lab.apply(V100, target("0.3"), V110);
        // Restore, so the temporary directory can be removed.
        std::fs::set_permissions(&apps, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let is_root = Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0");
        if code != 28 && is_root {
            println!("note: running as root, the folder is writable to it; case not applicable");
            return;
        }
        // `apply` of an installed app writes its events to the install's log.
        let output = format!("{}{}", String::from_utf8_lossy(&printed), lab.log());
        assert_eq!(code, 28, "{output}");
        assert!(
            output.contains("\"kind\":\"unsupported_location\"")
                && output.contains("\"reason\":\"not_writable\""),
            "{output}"
        );
        assert_eq!(lab.record(), before, "nothing was committed");
        lab.assert_live(V100);
        lab.assert_parked(V110);
        // No path in the output.
        assert!(
            !output.contains(&lab.base.display().to_string()),
            "{output}"
        );
        // The app exited for this apply, so it comes back as the version it was.
        assert!(
            lab.wait_note("1.0.0 start token=no", Duration::from_secs(20)),
            "{}",
            lab.notes()
        );
    }

    #[cfg(not(unix))]
    fn an_apps_folder_the_user_cannot_write_is_exit_28_and_the_app_comes_back(_: &Lab) {
        unreachable!("skipped: {MACOS_ONLY}");
    }

    /// macOS (M8-D17): the user moved the app's bundle (a Finder move, the app having been
    /// started before it) and its `apply` runs from where it is now. The applier follows the move
    /// under the lock before it commits anything, so the new version is placed in the bundle the
    /// user kept and not at the path it was moved from.
    fn an_apply_from_a_bundle_the_user_moved_follows_it_and_updates_it_where_it_is(lab: &Lab) {
        lab.tree(V100, ENTRY, "exit0", 30);
        lab.tree(V110, ENTRY, "confirm", 30);
        lab.install(V110);
        let old = common::bundle_of(&lab.layout());
        let moved = lab.home.join("Documents/Hello.app");
        std::fs::create_dir_all(moved.parent().expect("parent")).expect("dirs");
        std::fs::rename(&old, &moved).expect("move");
        let wait = target("0.2");
        let runtime = moved.join(ENTRY_DIR).join(RUNTIME_FILE);
        let child = lab
            .command(&runtime)
            .args([
                "apply",
                "--wait-pid",
                &wait.pid.to_string(),
                "--wait-start",
                &wait.start_ticks.to_string(),
                "--version",
                V110,
                "--",
                HELPER_ARG,
            ])
            .spawn()
            .expect("runtime");
        let (code, printed) = finish(child);
        let output = format!("{}{}", String::from_utf8_lossy(&printed), lab.log());
        assert_eq!(code, 0, "{output}");
        // The bundle the user kept holds 1.1.0, the pointer names it, and nothing was put back
        // at the old path.
        assert_eq!(common::bundle_of(&lab.layout()), moved);
        lab.assert_live(V110);
        assert!(
            std::fs::symlink_metadata(&old).is_err(),
            "the new version was placed where the bundle was moved from"
        );
        lab.assert_parked(V100);
        assert!(
            lab.notes().contains(&format!(
                "1.1.0 start token=yes exe={}",
                common::join_rel(&moved, &exe(ENTRY)).display()
            )),
            "{}",
            lab.notes()
        );
    }

    /// macOS: the runtime of a copy of the app under an `AppTranslocation` folder, as Gatekeeper
    /// runs a quarantined app from, is refused first of all (exit 28, `translocated`), even by a
    /// plain `check`, and nothing is written.
    fn a_translocated_runtime_is_exit_28_before_anything_else(lab: &Lab) {
        let copy = lab.base.join("AppTranslocation/ID/d/Hello.app");
        lab.tree_at(&copy, V100, ENTRY, "exit0", 30);
        let runtime = copy.join(ENTRY_DIR).join(RUNTIME_FILE);
        let out = lab
            .command(&runtime)
            .args(["check", "--json"])
            .output()
            .expect("run");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.status.code(), Some(28), "{text}");
        assert!(
            text.contains("\"kind\":\"unsupported_location\"")
                && text.contains("\"reason\":\"translocated\""),
            "{text}"
        );
        assert!(!text.contains(&lab.base.display().to_string()), "{text}");
        // Nothing was written: `R` holds nothing.
        assert_eq!(
            std::fs::read_dir(&lab.root).expect("R").count(),
            0,
            "something was written under R"
        );
    }
}
