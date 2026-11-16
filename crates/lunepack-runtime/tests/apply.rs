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
//! The cases run one after another. Linux only.

// The sink fan-out, compiled into this test so a UI-sink fake can be plugged in (the binary never
// constructs one in M5).
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/events.rs"]
mod events;

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some(linux::HELPER_ARG) {
        linux::helper(&args[1..]);
        return;
    }
    linux::run_all(&args);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("lunepack-runtime apply tests: Linux only, skipped");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use lunepack::{
        ConfirmOutcome, HEALTH_TOKEN_VAR, InstallMeta, Installation, Phase, ProcessId, Progress,
        RelPath, StartupAction, Target, UpdateConfig, Version,
    };
    use lunepack_core::Hasher;
    use lunepack_core::state::{InstallState, Scope, StagedRef, UserScope};
    use lunepack_crypto::Sha256Hasher;
    use lunepack_os_linux::LinuxProcess;
    use lunepack_testkit::sample_update_config;

    use crate::events::{Event, Events, LogSink, Sink, SinkFailed};

    pub const HELPER_ARG: &str = "helper-app";
    /// Where the helper writes its notes (set on the runtime, inherited by the apps it starts).
    const OUT_VAR: &str = "LUNEPACK_APPLY_TEST_OUT";
    const RUNTIME: &str = env!("CARGO_BIN_EXE_lunepack-runtime");
    const INSTALL_ID: [u8; 16] = [3; 16];
    const V090: &str = "0.9.0";
    const V100: &str = "1.0.0";
    const V110: &str = "1.1.0";
    /// A bound on any one runtime run in a case.
    const RUN_LIMIT: Duration = Duration::from_secs(60);

    #[cfg(target_arch = "aarch64")]
    const TARGET: Target = Target::LinuxAarch64;
    #[cfg(not(target_arch = "aarch64"))]
    const TARGET: Target = Target::LinuxX86_64;

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
    ];

    pub fn run_all(args: &[String]) {
        let filter = args.iter().find(|a| !a.starts_with('-'));
        let mut failed = 0;
        for (name, test) in TESTS {
            if filter.is_some_and(|f| !name.contains(f.as_str())) {
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
        let exe = std::fs::read_link("/proc/self/exe").expect("exe");
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
            let cmdline = std::fs::read("/proc/self/cmdline").expect("cmdline");
            let needle = token.as_encoded_bytes();
            let in_argv = cmdline.windows(needle.len()).any(|w| w == needle);
            note(&format!("{v} argv-has-token={in_argv}"));
            if mode == "save-token" {
                let out = std::env::var_os(OUT_VAR).expect("out");
                std::fs::write(Path::new(&out).join("planted-token"), needle).expect("plant");
            }
        }
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
                // "exit0" and anything else: exit 0 without confirming.
            }
        }
    }

    /// Notes where the command link and the desktop entry's `Exec` point.
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

    /// Places `from` at `to`: a hard link when possible, else a copy.
    fn place(from: &Path, to: &Path) {
        std::fs::create_dir_all(to.parent().expect("parent")).expect("dirs");
        // Never copy over an existing link: that would write into the linked binary.
        assert!(std::fs::symlink_metadata(to).is_err(), "already placed");
        if std::fs::hard_link(from, to).is_err() {
            std::fs::copy(from, to).expect("copy");
        }
    }

    impl Lab {
        fn new() -> Lab {
            // Under the target directory: the binaries can be hard-linked from there.
            let tmp = tempfile::Builder::new()
                .prefix("apply-")
                .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
                .expect("tmp");
            let base = std::fs::canonicalize(tmp.path()).expect("canonical");
            let home = base.join("home");
            let data = home.join(".local/share");
            let app = sample_update_config().app_id;
            let root = data.join(app.as_str());
            let out = base.join("out");
            for d in [&home, &data, &root, &out] {
                std::fs::create_dir_all(d).expect("dirs");
            }
            Lab {
                _tmp: tmp,
                home,
                data,
                root,
                out,
            }
        }

        fn tree_dir(&self, v: &str) -> PathBuf {
            self.root.join("versions").join(v)
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
            };
            cfg
        }

        /// `R/versions/<v>`: the config (entry `entry`), this binary as the entry, the runtime
        /// beside it, and the marker.
        fn tree(&self, v: &str, entry: &str, marker: &str, timeout: u64) -> PathBuf {
            let dir = self.tree_dir(v);
            std::fs::create_dir_all(&dir).expect("dirs");
            let cfg = self.config(v, entry, timeout);
            std::fs::write(
                dir.join("lunepack-update.json"),
                cfg.to_bytes().expect("config bytes"),
            )
            .expect("config");
            let entry_path = dir.join(entry);
            place(&std::env::current_exe().expect("exe"), &entry_path);
            place(
                Path::new(RUNTIME),
                &entry_path.parent().expect("dir").join("lunepack-runtime"),
            );
            std::fs::write(dir.join("marker"), marker).expect("marker");
            dir
        }

        fn store(&self) -> UserScope {
            UserScope {
                dir: self.root.join("state"),
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

        /// 1.0.0 installed and `staged` staged (bound), with the core's real writer.
        fn install(&self, staged: &str) {
            self.commit(|_| {
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
            let runtime = self.tree_dir(from).join(entry_dir).join("lunepack-runtime");
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
            let child = self.start_apply(from, "bin", wait, v);
            finish(child)
        }

        fn notes(&self) -> String {
            std::fs::read_to_string(self.out.join("notes")).unwrap_or_default()
        }

        fn wait_note(&self, needle: &str, limit: Duration) -> bool {
            wait_until(limit, || self.notes().contains(needle))
        }

        fn log(&self) -> String {
            let logs = self.root.join("logs");
            let mut text = std::fs::read_to_string(logs.join("runtime.log.1")).unwrap_or_default();
            text.push_str(&std::fs::read_to_string(logs.join("runtime.log")).unwrap_or_default());
            text
        }

        fn current_link(&self) -> PathBuf {
            std::fs::read_link(self.root.join("current")).expect("current")
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
        let mut child = Command::new("sleep").arg(secs).spawn().expect("sleep");
        let id = LinuxProcess::new()
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
        assert_eq!(lab.current_link(), Path::new("versions/1.0.0"));
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
        assert_eq!(lab.current_link(), Path::new("versions/1.1.0"));
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
        lab.tree(V100, "bin/app", "exit0", 5);
        lab.tree(V110, "bin/app", "confirm", 5);
        lab.install(V110);
        let before = lab.record();
        let runtime = lab.tree_dir(V100).join("bin/lunepack-runtime");
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
        assert!(!lab.root.join("logs").exists(), "a usage error wrote a log");
        assert!(lab.notes().is_empty(), "a usage error started something");
    }

    fn confirmed_then_gc_removes_older_than_previous(lab: &Lab) {
        let old = lab.tree_dir(V090);
        std::fs::create_dir_all(old.join("bin")).expect("0.9.0");
        std::fs::write(old.join("bin/app"), b"old").expect("old file");
        // Not version trees: a non-canonical name, a symlink, a file.
        let versions = lab.root.join("versions");
        std::fs::create_dir_all(versions.join("v0.8.0")).expect("odd dir");
        std::os::unix::fs::symlink(&old, versions.join("0.7.0")).expect("link");
        std::fs::write(versions.join("0.6.0"), b"file").expect("file");
        lab.tree(V100, "bin/app", "exit0", 30);
        lab.tree(V110, "bin/app", "confirm", 30);
        lab.install(V110);
        let (code, _) = lab.apply(V100, target("0.2"), V110);
        assert_eq!(code, 0);
        assert_confirmed(lab);
        assert!(lab.notes().contains("1.1.0 start token=yes"));
        assert!(lab.notes().contains("1.1.0 confirm confirmed"));
        assert!(!old.exists(), "GC kept 0.9.0");
        assert!(lab.tree_dir(V100).exists() && lab.tree_dir(V110).exists());
        assert!(versions.join("v0.8.0").exists());
        assert!(std::fs::symlink_metadata(versions.join("0.7.0")).is_ok());
        assert!(versions.join("0.6.0").exists());
        for phase in ["wait", "apply", "launch", "confirm"] {
            assert!(
                log_has(lab, &format!("\"phase\":\"{phase}\"")),
                "no {phase} phase"
            );
        }
        assert!(log_has(lab, "\"outcome\":\"confirmed\""));
        // The bin link and the desktop entry point through current.
        let link = std::fs::read_link(lab.home.join(".local/bin/lp-apply-test")).expect("link");
        assert_eq!(link, lab.root.join("current/bin/app"));
    }

    fn crash_rolls_back_marks_bad_and_relaunches_old_without_token(lab: &Lab) {
        lab.tree(V100, "bin/app", "exit0", 30);
        lab.tree(V110, "bin/app", "crash", 30);
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
        // The bad tree is no longer kept.
        assert!(!lab.tree_dir(V110).exists(), "GC kept the bad tree");
    }

    fn exit_0_then_a_second_process_confirms(lab: &Lab) {
        lab.tree(V100, "bin/app", "exit0", 30);
        lab.tree(V110, "bin/app", "exit0", 30);
        lab.install(V110);
        let runtime = lab.start_apply(V100, "bin", target("0.2"), V110);
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
            .command(&lab.tree_dir(V110).join("bin/app"))
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
        lab.tree(V100, "bin/app", "exit0", 5);
        lab.tree(V110, "bin/app", "confirm-after-8000", 5);
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
            lab.tree(V100, "bin/app", "exit0", 5);
            lab.tree(V110, "bin/app", &format!("confirm-after-{offset}"), 5);
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
        lab.tree(V100, "bin/app", "exit0", 30);
        lab.tree(V110, "bin/app", "confirm", 30);
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
        let id = LinuxProcess::new()
            .process_id(child.id())
            .expect("probe")
            .expect("running");
        let runtime = lab.start_apply(V100, "bin", id, V110);
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
        lab.tree(V100, "bin/app", "exit0", 30);
        lab.tree(V110, "bin/app", "confirm", 30);
        lab.install(V110);
        let mut zombie = Command::new("sleep").arg("0.2").spawn().expect("sleep");
        let id = LinuxProcess::new()
            .process_id(zombie.id())
            .expect("probe")
            .expect("running");
        // Not reaped: it stays a zombie of this process.
        std::thread::sleep(Duration::from_millis(600));
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", id.pid)).expect("stat");
        assert!(stat.contains(") Z "), "not a zombie: {stat}");
        let (code, _) = lab.apply(V100, id, V110);
        assert_eq!(code, 0);
        let waited = log_time(lab, "\"phase\":\"apply\"") - log_time(lab, "\"phase\":\"wait\"");
        assert!(waited < 1000, "waited {waited} ms for a zombie");
        let _ = zombie.wait();
        assert_confirmed(lab);
    }

    fn the_entry_directory_may_change_between_versions(lab: &Lab) {
        lab.tree(V100, "bin/app", "exit0", 30);
        lab.tree(V110, "app", "report", 30);
        lab.install(V110);
        let (code, _) = lab.apply(V100, target("0.1"), V110);
        assert_eq!(code, 20);
        let notes = lab.notes();
        let new_exe = lab.tree_dir(V110).join("app");
        assert!(
            notes.contains(&format!("1.1.0 start token=yes exe={}", new_exe.display())),
            "{notes}"
        );
        let current = lab.root.join("current");
        assert!(
            notes.contains(&format!("1.1.0 link={}", current.join("app").display())),
            "{notes}"
        );
        assert!(
            notes.contains(&format!(
                "1.1.0 desktop Exec=\"{}\"",
                current.join("app").display()
            )),
            "{notes}"
        );
        let old_exe = lab.tree_dir(V100).join("bin/app");
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
        let link = std::fs::read_link(lab.home.join(".local/bin/lp-apply-test")).expect("link");
        assert_eq!(link, current.join("bin/app"));
        let desktop = std::fs::read_to_string(lab.data.join("applications").join(format!(
            "{}.desktop",
            sample_update_config().app_id.as_str()
        )))
        .expect("desktop entry");
        assert!(desktop.contains(&format!("Exec=\"{}\"", current.join("bin/app").display())));
    }

    fn a_missing_new_config_changes_nothing(lab: &Lab) {
        lab.tree(V100, "bin/app", "exit0", 30);
        let new = lab.tree(V110, "bin/app", "confirm", 30);
        std::fs::remove_file(new.join("lunepack-update.json")).expect("remove config");
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
        assert_eq!(lab.current_link(), Path::new("versions/1.0.0"));
        assert!(!lab.notes().contains("1.1.0 start"), "1.1.0 was started");
        assert!(!lab.notes().contains("token=yes"));
    }

    fn nothing_staged_relaunches_the_current_version(lab: &Lab) {
        lab.tree(V100, "bin/app", "exit0", 30);
        lab.tree(V110, "bin/app", "confirm", 30);
        lab.commit(|r| {
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
        lab.tree(V100, "bin/app", "exit0", 30);
        lab.tree(V110, "bin/app", "confirm", 30);
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
        lab.tree(V100, "bin/app", "exit0", 30);
        lab.tree(V110, "bin/app", "confirm", 30);
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
        lab.tree(V090, "bin/app", "exit0", 30);
        lab.tree(V100, "bin/app", "exit0", 30);
        lab.tree(V110, "bin/app", "confirm", 30);
        let gone = sha(b"a supervisor that is gone");
        lab.commit(|_| {
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
        assert_eq!(lab.current_link(), Path::new("versions/1.0.0"));
    }

    /// F19 with the pending version's supervisor still running: started with its token, 1.0.0
    /// exits 0 for an apply before it confirms, and the apply is refused. Started again without
    /// the token, it confirms, so its supervisor ends confirmed instead of rolling a healthy
    /// version back at its timeout.
    fn a_supervised_version_that_exits_to_apply_is_not_rolled_back(lab: &Lab) {
        lab.tree(V090, "bin/app", "exit0", 30);
        lab.tree(V100, "bin/app", "exit0", 30);
        lab.tree(V110, "bin/app", "confirm", 30);
        lab.commit(|_| installed_090(V100));
        let supervisor = lab.start_apply(V090, "bin", target("0.1"), V100);
        assert!(
            lab.wait_note("1.0.0 startup continue", Duration::from_secs(10)),
            "1.0.0 did not start: {}",
            lab.notes()
        );
        assert!(lab.notes().contains("1.0.0 start token=yes"));
        // 1.1.0 is staged meanwhile, and 1.0.0 asks for it before it confirms.
        lab.commit(|r| staging(r.expect("record"), V110));
        let applier =
            lab.start_apply_with(V100, "bin", target("0.1"), V110, &[HELPER_ARG, "confirm"]);
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
        assert_eq!(lab.current_link(), Path::new("versions/1.0.0"));
    }

    fn a_missing_previous_config_leaves_it_pending(lab: &Lab) {
        let old = lab.tree(V100, "bin/app", "exit0", 30);
        lab.tree(V110, "bin/app", "crash", 30);
        lab.install(V110);
        let runtime = lab.start_apply(V100, "bin", target("1.5"), V110);
        assert!(
            wait_until(Duration::from_secs(5), || log_has(
                lab,
                "\"phase\":\"wait\""
            )),
            "no wait phase"
        );
        std::fs::remove_file(old.join("lunepack-update.json")).expect("remove config");
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
        lab.tree(V100, "bin/app", "exit0", 30);
        let new = lab.tree(V110, "bin/app", "confirm", 30);
        std::fs::remove_file(new.join("bin/app")).expect("remove entry");
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
        let mut user = Command::new("sleep")
            .arg("30")
            .current_dir(&old)
            .spawn()
            .expect("sleep");
        lab.tree(V100, "bin/app", "exit0", 30);
        lab.tree(V110, "bin/app", "confirm", 30);
        lab.install(V110);
        let (code, _) = lab.apply(V100, target("0.1"), V110);
        let _ = user.kill();
        let _ = user.wait();
        assert_eq!(code, 0);
        assert!(old.exists(), "GC removed a tree in use");
        assert!(log_has(lab, "\"code\":\"gc_in_use\""));
    }

    fn the_token_never_reaches_any_output(lab: &Lab) {
        lab.tree(V100, "bin/app", "exit0", 30);
        lab.tree(V110, "bin/app", "save-token", 30);
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
        for dir in ["logs", "state"] {
            for entry in std::fs::read_dir(lab.root.join(dir)).expect("dir") {
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
}
