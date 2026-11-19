//! The runtime's `apply` on the macOS bundle layout with real processes (M8 step 6): the swap of
//! the live bundle, the launch from the bundle with the health token in the environment only,
//! the rollback that puts the previous bundle back and starts it from there, the refused places
//! (exit 28 with a closed `reason`) and GC under `R/versions`.
//!
//! Each case builds an install under a temporary home: bundles written with the real update-config
//! writer, the record with the core's writer, this test binary as the app's entry and the built
//! `lunepack-runtime` beside it. Own `main`: run as `helper-app`, this binary is the app; it calls
//! the real `lunepack::startup()` and `confirm_healthy()`, and what it does next comes from a
//! marker file in its own bundle. The cases run one after another.
//!
//! The Linux and Windows twins of these cases are `tests/apply.rs`, which builds the other layouts.

#[cfg(target_os = "macos")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some(native::HELPER_ARG) => native::helper(&args[1..]),
        Some(native::SLEEP_ARG) => native::sleep(&args[1..]),
        _ => native::run_all(&args),
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("lunepack-runtime macOS apply tests: macOS only, skipped");
}

#[cfg(target_os = "macos")]
mod native {
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use lunepack::{
        ConfirmOutcome, HEALTH_TOKEN_VAR, InstallMeta, Installation, ProcessId, RelPath,
        StartupAction, Target, UpdateConfig, Version,
    };
    use lunepack_core::state::{InstallState, Scope, StagedRef, UserScope};
    use lunepack_core::{
        Hasher, LayoutScheme, UserLayout, set_bundle_pointer, write_bundle_identity,
    };
    use lunepack_crypto::Sha256Hasher;
    use lunepack_os_macos::MacProcess;
    use lunepack_testkit::sample_update_config;

    pub const HELPER_ARG: &str = "helper-app";
    pub const SLEEP_ARG: &str = "sleep-for";
    const OUT_VAR: &str = "LUNEPACK_APPLY_TEST_OUT";
    const RUNTIME: &str = env!("CARGO_BIN_EXE_lunepack-runtime");
    const INSTALL_ID: [u8; 16] = [3; 16];
    const TARGET: Target = Target::MacosAarch64;
    const V090: &str = "0.9.0";
    const V100: &str = "1.0.0";
    const V110: &str = "1.1.0";
    const RUN_LIMIT: Duration = Duration::from_secs(60);

    type Case = fn(&Lab);

    const TESTS: &[(&str, Case)] = &[
        (
            "confirmed_swaps_the_bundle_launches_from_it_and_collects_old_trees",
            confirmed,
        ),
        (
            "a_crash_rolls_back_into_the_bundle_and_starts_the_previous_version_from_it",
            crash_rolls_back,
        ),
        (
            "an_apps_folder_the_user_cannot_write_is_exit_28_and_the_app_comes_back",
            not_writable_is_28,
        ),
        (
            "a_translocated_runtime_is_exit_28_before_anything_else",
            translocated_is_28,
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

    /// The app: `helper-app [mode]`; without a mode, the marker file of its own bundle.
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
            let needle = token.as_encoded_bytes();
            let in_argv = std::env::args_os().any(|a| {
                a.as_encoded_bytes()
                    .windows(needle.len())
                    .any(|w| w == needle)
            });
            note(&format!("{v} argv-has-token={in_argv}"));
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
        match mode.as_str() {
            "confirm" => {
                let got = match lunepack::confirm_healthy() {
                    Ok(ConfirmOutcome::Confirmed) => "confirmed".to_owned(),
                    Ok(ConfirmOutcome::NothingPending) => "nothing_pending".to_owned(),
                    Err(e) => format!("error {e}"),
                };
                note(&format!("{v} confirm {got}"));
            }
            "crash" => std::process::exit(3),
            // "exit0" and anything else: exit 0 without confirming.
            _ => {}
        }
    }

    /// A process that sleeps `<seconds>` (the wait target of a case).
    pub fn sleep(rest: &[String]) {
        let secs: f64 = rest.first().and_then(|s| s.parse().ok()).expect("seconds");
        std::thread::sleep(Duration::from_secs_f64(secs));
    }

    // ---- the lab ------------------------------------------------------------------------------

    struct Lab {
        _tmp: tempfile::TempDir,
        base: PathBuf,
        home: PathBuf,
        root: PathBuf,
        out: PathBuf,
    }

    fn version(text: &str) -> Version {
        Version::parse(text).expect("version")
    }

    fn sha(bytes: &[u8]) -> lunepack_core::Sha256Digest {
        Sha256Hasher.sha256(bytes)
    }

    /// Places `from` at `to`: a hard link when possible, else a copy.
    fn place(from: &Path, to: &Path) {
        std::fs::create_dir_all(to.parent().expect("parent")).expect("dirs");
        assert!(std::fs::symlink_metadata(to).is_err(), "already placed");
        if std::fs::hard_link(from, to).is_err() {
            std::fs::copy(from, to).expect("copy");
        }
    }

    impl Lab {
        fn new() -> Lab {
            let tmp = tempfile::Builder::new()
                .prefix("applymac-")
                .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
                .expect("tmp");
            let base = std::fs::canonicalize(tmp.path()).expect("canonical");
            let home = base.join("home");
            let data = home.join("Library/Application Support");
            let app = sample_update_config().app_id;
            let root = data.join(app.as_str());
            let out = base.join("out");
            for d in [&home.join("Applications"), &data, &out] {
                std::fs::create_dir_all(d).expect("dirs");
            }
            Lab {
                _tmp: tmp,
                base,
                home,
                root,
                out,
            }
        }

        fn layout(&self) -> UserLayout {
            UserLayout::from_root(self.root.clone(), LayoutScheme::MACOS)
        }

        fn bundle(&self) -> PathBuf {
            self.home.join("Applications/Hello.app")
        }

        fn version_dir(&self, v: &str) -> PathBuf {
            self.layout().versions_dir().join(v)
        }

        fn config(&self, v: &str) -> UpdateConfig {
            let mut cfg = sample_update_config();
            cfg.version = version(v);
            cfg.target = TARGET;
            cfg.health_timeout_secs = 30;
            cfg.install = InstallMeta {
                entry: RelPath::parse("Contents/MacOS/app").expect("entry"),
                name: format!("Apply test {v}"),
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
            cfg
        }

        /// A bundle at `dir` of version `v`: the config, this binary as the entry, the runtime
        /// beside it and the marker.
        fn tree(&self, dir: &Path, v: &str, marker: &str) {
            std::fs::create_dir_all(dir.join("Contents/Resources")).expect("dirs");
            std::fs::write(
                dir.join("Contents/Resources/lunepack-update.json"),
                self.config(v).to_bytes().expect("config bytes"),
            )
            .expect("config");
            place(
                &std::env::current_exe().expect("exe"),
                &dir.join("Contents/MacOS/app"),
            );
            place(
                Path::new(RUNTIME),
                &dir.join("Contents/MacOS/lunepack-runtime"),
            );
            std::fs::write(dir.join("marker"), marker).expect("marker");
        }

        fn store(&self) -> UserScope {
            UserScope {
                dir: self.layout().state_dir(),
                app_id: sample_update_config().app_id,
            }
        }

        fn record(&self) -> InstallState {
            self.store()
                .load(&lunepack_fs::StdFs::new(), &Sha256Hasher)
                .expect("load")
                .record
                .expect("record")
        }

        /// 1.0.0 live in the bundle (`old_marker`), 1.1.0 staged in `versions` (`new_marker`),
        /// the pointer and the identity, and the record.
        fn install(&self, old_marker: &str, new_marker: &str) {
            let fs = lunepack_fs::StdFs::new();
            let layout = self.layout();
            std::fs::create_dir_all(layout.versions_dir()).expect("versions");
            std::fs::create_dir_all(layout.state_dir()).expect("state");
            self.tree(&self.bundle(), V100, old_marker);
            self.tree(&self.version_dir(V110), V110, new_marker);
            set_bundle_pointer(&fs, &layout, &self.bundle()).expect("pointer");
            write_bundle_identity(&fs, &layout, &self.bundle()).expect("identity");
            let app = sample_update_config().app_id;
            let record = InstallState::new(1, app, Scope::User, INSTALL_ID, TARGET)
                .install(version(V100), 10, TARGET, INSTALL_ID)
                .set_staged(Some((
                    StagedRef::new(version(V110), TARGET, sha(V110.as_bytes())),
                    20,
                )));
            let store = self.store();
            let loaded = store.load(&fs, &Sha256Hasher).expect("load");
            store
                .commit(&fs, &loaded, &record, &Sha256Hasher)
                .expect("commit");
        }

        fn command(&self, program: &Path) -> Command {
            let mut cmd = Command::new(program);
            cmd.env("HOME", &self.home)
                .env(OUT_VAR, &self.out)
                .env("LUNEPACK_NO_UI", "1")
                .env_remove(HEALTH_TOKEN_VAR)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            cmd
        }

        /// Runs the bundle's runtime: `apply --wait-pid … --version v -- helper-app`; its exit
        /// code and everything it printed.
        fn apply(&self, wait: ProcessId, v: &str) -> (i32, String) {
            let runtime = self.bundle().join("Contents/MacOS/lunepack-runtime");
            let mut child = self
                .command(&runtime)
                .args([
                    "apply",
                    "--wait-pid",
                    &wait.pid.to_string(),
                    "--wait-start",
                    &wait.start_ticks.to_string(),
                    "--version",
                    v,
                    "--",
                    HELPER_ARG,
                ])
                .spawn()
                .expect("runtime");
            let start = Instant::now();
            while child.try_wait().expect("wait").is_none() {
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
            (
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&all).into_owned(),
            )
        }

        fn notes(&self) -> String {
            std::fs::read_to_string(self.out.join("notes")).unwrap_or_default()
        }

        fn wait_note(&self, needle: &str) -> bool {
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(20) {
                if self.notes().contains(needle) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            self.notes().contains(needle)
        }

        fn version_in(&self, dir: &Path) -> Option<String> {
            let bytes = std::fs::read(dir.join("Contents/Resources/lunepack-update.json")).ok()?;
            Some(UpdateConfig::parse(&bytes).ok()?.version.to_string())
        }
    }

    /// A process that runs for `secs` (reaped by a thread), and its id.
    fn target(secs: &str) -> ProcessId {
        let mut child = Command::new(std::env::current_exe().expect("exe"))
            .args([SLEEP_ARG, secs])
            .spawn()
            .expect("sleep");
        let id = MacProcess::new()
            .process_id(child.id())
            .expect("probe")
            .expect("running");
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        id
    }

    // ---- the cases ----------------------------------------------------------------------------

    fn confirmed(lab: &Lab) {
        lab.install("exit0", "confirm");
        // An older tree nothing references: GC removes it. A symlink and a file that merely look
        // like version names stay.
        let versions = lab.layout().versions_dir();
        lab.tree(&lab.version_dir(V090), V090, "exit0");
        std::os::unix::fs::symlink(lab.version_dir(V090), versions.join("0.7.0")).expect("link");
        std::fs::write(versions.join("0.6.0"), b"file").expect("file");

        let (code, output) = lab.apply(target("0.3"), V110);
        assert_eq!(code, 0, "{output}");
        let r = lab.record();
        assert_eq!(r.current.as_ref().expect("current").version, version(V110));
        assert_eq!(
            r.previous.as_ref().expect("previous").version,
            version(V100)
        );
        assert!(r.pending.is_none() && r.health.is_none() && r.bad.is_empty());
        // The bundle holds 1.1.0; 1.0.0 is parked; the staging tree is gone.
        assert_eq!(lab.version_in(&lab.bundle()).as_deref(), Some(V110));
        assert_eq!(
            lab.version_in(&lab.version_dir(V100)).as_deref(),
            Some(V100)
        );
        assert!(!lab.version_dir(V110).exists());
        for slot in [lab.layout().swap_slot(), lab.layout().out_slot()] {
            assert!(std::fs::symlink_metadata(slot).is_err(), "a slot is left");
        }
        // The new version ran from the bundle, with the token, never in argv.
        let notes = lab.notes();
        let want_exe = format!("exe={}", lab.bundle().join("Contents/MacOS/app").display());
        assert!(notes.contains("1.1.0 start token=yes"), "{notes}");
        assert!(notes.contains(&want_exe), "{notes}");
        assert!(notes.contains("1.1.0 argv-has-token=false"), "{notes}");
        assert!(notes.contains("1.1.0 confirm confirmed"), "{notes}");
        // GC: the unreferenced tree is gone, the look-alikes and the kept trees stay.
        assert!(!lab.version_dir(V090).exists(), "GC kept 0.9.0");
        assert!(std::fs::symlink_metadata(versions.join("0.7.0")).is_ok());
        assert!(versions.join("0.6.0").exists());
        assert!(lab.version_dir(V100).exists());
        assert!(
            !output.contains("token"),
            "output names the token: {output}"
        );
    }

    fn crash_rolls_back(lab: &Lab) {
        lab.install("exit0", "crash");
        let (code, output) = lab.apply(target("0.3"), V110);
        assert_eq!(code, 20, "{output}");
        let r = lab.record();
        assert_eq!(r.current.as_ref().expect("current").version, version(V100));
        assert!(r.pending.is_none() && r.health.is_none());
        assert!(r.bad.contains(&version(V110)));
        // 1.0.0 is back in the bundle and 1.1.0 is parked under its version.
        assert_eq!(lab.version_in(&lab.bundle()).as_deref(), Some(V100));
        assert_eq!(
            lab.version_in(&lab.version_dir(V110)).as_deref(),
            Some(V110)
        );
        // The previous version was started again from the bundle, without the token.
        let want = format!(
            "1.0.0 start token=no exe={}",
            lab.bundle().join("Contents/MacOS/app").display()
        );
        assert!(lab.wait_note(&want), "{}", lab.notes());
        assert!(lab.notes().contains("1.1.0 start token=yes"));
    }

    fn not_writable_is_28(lab: &Lab) {
        use std::os::unix::fs::PermissionsExt;
        lab.install("exit0", "confirm");
        let apps = lab.home.join("Applications");
        std::fs::set_permissions(&apps, std::fs::Permissions::from_mode(0o555)).expect("chmod");
        let before = lab.record();
        let (code, output) = lab.apply(target("0.3"), V110);
        // Restore, so the temporary directory can be removed.
        std::fs::set_permissions(&apps, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        if code != 28 && is_root() {
            println!("note: running as root, the folder is writable to it; case not applicable");
            return;
        }
        // `apply` of an installed app writes its events to the install's log.
        let log = std::fs::read_to_string(lab.layout().logs_dir().join("runtime.log"))
            .unwrap_or_default();
        let output = format!("{output}{log}");
        assert_eq!(code, 28, "{output}");
        assert!(
            output.contains("\"kind\":\"unsupported_location\"")
                && output.contains("\"reason\":\"not_writable\""),
            "{output}"
        );
        assert_eq!(lab.record(), before, "nothing was committed");
        assert_eq!(lab.version_in(&lab.bundle()).as_deref(), Some(V100));
        assert_eq!(
            lab.version_in(&lab.version_dir(V110)).as_deref(),
            Some(V110)
        );
        // No path in the output.
        assert!(
            !output.contains(&lab.base.display().to_string()),
            "{output}"
        );
        // The app exited for this apply, so it comes back as the version it was.
        assert!(lab.wait_note("1.0.0 start token=no"), "{}", lab.notes());
    }

    fn is_root() -> bool {
        Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
    }

    fn translocated_is_28(lab: &Lab) {
        // A copy of the app under an `AppTranslocation` folder, as Gatekeeper runs a quarantined
        // app from.
        let copy = lab.base.join("AppTranslocation/ID/d/Hello.app");
        lab.tree(&copy, V100, "exit0");
        let runtime = copy.join("Contents/MacOS/lunepack-runtime");
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
        // Nothing was written: no install state exists.
        assert!(!lab.root.exists());
    }
}
