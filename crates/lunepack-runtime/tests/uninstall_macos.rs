//! The runtime's `uninstall` on the macOS bundle layout with real processes (M8 step 6b, M8-D5,
//! M8-D15): the live bundle `B`, then the install root `R`, then the LaunchAgent when its `Label`
//! is ours; foreign items kept; tombstones of an earlier cut-off run removed; refused while an
//! instance runs (25) and from any tree that is not the one `R/bundle` names (26), with nothing
//! removed.
//!
//! Each case builds an install under a temporary home: bundles written with the real update-config
//! writer, the record with the core's writer, a copy of this test binary as the app's entry and the
//! built `lunepack-runtime` beside it. Own `main`: run as `sleep-for`, this binary is a running
//! instance of the app. The cases run one after another.

#[cfg(target_os = "macos")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some(native::SLEEP_ARG) => native::sleep(&args[1..]),
        _ => native::run_all(&args),
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("lunepack-runtime macOS uninstall tests: macOS only, skipped");
}

#[cfg(target_os = "macos")]
mod native {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use lunepack::{HEALTH_TOKEN_VAR, InstallMeta, RelPath, Target, UpdateConfig, Version};
    use lunepack_core::state::{InstallState, Scope, UserScope};
    use lunepack_core::{LayoutScheme, UserLayout, set_bundle_pointer, write_bundle_identity};
    use lunepack_crypto::Sha256Hasher;
    use lunepack_testkit::sample_update_config;

    pub const SLEEP_ARG: &str = "sleep-for";
    const RUNTIME: &str = env!("CARGO_BIN_EXE_lunepack-runtime");
    const INSTALL_ID: [u8; 16] = [5; 16];
    const TARGET: Target = Target::MacosAarch64;
    const V090: &str = "0.9.0";
    const V100: &str = "1.0.0";
    const RUN_LIMIT: Duration = Duration::from_secs(60);
    const TOMBSTONE_HEX: &str = "0123456789abcdef";

    type Case = fn(&Lab);

    const TESTS: &[(&str, Case)] = &[
        (
            "the_bundle_the_root_and_our_launch_agent_go_and_foreign_items_stay",
            removes_everything_ours,
        ),
        (
            "a_foreign_launch_agent_at_our_name_is_kept_and_reported",
            foreign_agent_is_kept,
        ),
        (
            "an_instance_running_from_the_bundle_or_a_version_tree_refuses_with_nothing_removed",
            refused_while_running,
        ),
        (
            "tombstones_of_an_earlier_cut_off_run_are_removed_without_following_links",
            tombstones_removed,
        ),
        (
            "a_tree_the_pointer_does_not_name_is_26_with_nothing_removed",
            not_the_pointer_is_26,
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

    /// A running instance: sleeps `<seconds>`.
    pub fn sleep(rest: &[String]) {
        let secs: f64 = rest.first().and_then(|s| s.parse().ok()).expect("seconds");
        std::thread::sleep(Duration::from_secs_f64(secs));
    }

    // ---- the lab ------------------------------------------------------------------------------

    struct Lab {
        _tmp: tempfile::TempDir,
        base: PathBuf,
        home: PathBuf,
        data: PathBuf,
        root: PathBuf,
    }

    fn version(text: &str) -> Version {
        Version::parse(text).expect("version")
    }

    impl Lab {
        fn new() -> Lab {
            // Not under the target directory: a Docker bind mount of the working tree makes its VM
            // process (the user's) hold descriptors on what the container looked at, and the
            // in-use scan counts that process (see `tests/common`'s `scratch`).
            let tmp = tempfile::Builder::new()
                .prefix("uninstmac-")
                .tempdir()
                .expect("tmp");
            let base = std::fs::canonicalize(tmp.path()).expect("canonical");
            let home = base.join("home");
            let data = home.join("Library/Application Support");
            let root = data.join(app_id());
            for d in [
                &home.join("Applications"),
                &home.join("Library/LaunchAgents"),
                &data,
            ] {
                std::fs::create_dir_all(d).expect("dirs");
            }
            Lab {
                _tmp: tmp,
                base,
                home,
                data,
                root,
            }
        }

        fn layout(&self) -> UserLayout {
            UserLayout::from_root(self.root.clone(), LayoutScheme::MACOS)
        }

        fn apps(&self) -> PathBuf {
            self.home.join("Applications")
        }

        fn bundle(&self) -> PathBuf {
            self.apps().join("Hello.app")
        }

        fn version_dir(&self, v: &str) -> PathBuf {
            self.layout().versions_dir().join(v)
        }

        fn agents(&self) -> PathBuf {
            self.home.join("Library/LaunchAgents")
        }

        fn our_agent(&self) -> PathBuf {
            self.agents().join(format!("{}.lunepack.plist", app_id()))
        }

        fn config(&self, v: &str) -> UpdateConfig {
            let mut cfg = sample_update_config();
            cfg.version = version(v);
            cfg.target = TARGET;
            cfg.install = InstallMeta {
                entry: RelPath::parse("Contents/MacOS/app").expect("entry"),
                name: "Hello".to_owned(),
                comment: None,
                icon: None,
                categories: Vec::new(),
                bin: None,
                terminal: false,
                publisher: None,
                file_types: Vec::new(),
                url_schemes: Vec::new(),
                autostart: true,
            };
            cfg
        }

        /// A bundle at `dir` of version `v`: the config, a copy of this binary as the entry (so
        /// the kernel names an instance by this path only) and the runtime beside it.
        fn tree(&self, dir: &Path, v: &str) {
            std::fs::create_dir_all(dir.join("Contents/Resources")).expect("dirs");
            std::fs::create_dir_all(dir.join("Contents/MacOS")).expect("dirs");
            std::fs::write(
                dir.join("Contents/Resources/lunepack-update.json"),
                self.config(v).to_bytes().expect("config bytes"),
            )
            .expect("config");
            std::fs::copy(
                std::env::current_exe().expect("exe"),
                dir.join("Contents/MacOS/app"),
            )
            .expect("entry");
            // A copy, never a hard link: the kernel names a hard-linked executable by whichever
            // of its paths it looked up last (see `tests/common`'s `place`).
            let runtime = dir.join("Contents/MacOS/lunepack-runtime");
            std::fs::copy(RUNTIME, &runtime).expect("runtime");
        }

        /// 1.0.0 live in the bundle, an old 0.9.0 tree in `versions`, the pointer, the identity,
        /// the record and our LaunchAgent.
        fn install(&self) {
            let fs = lunepack_fs::StdFs::new();
            let layout = self.layout();
            std::fs::create_dir_all(layout.versions_dir()).expect("versions");
            std::fs::create_dir_all(layout.state_dir()).expect("state");
            self.tree(&self.bundle(), V100);
            self.tree(&self.version_dir(V090), V090);
            set_bundle_pointer(&fs, &layout, &self.bundle()).expect("pointer");
            write_bundle_identity(&fs, &layout, &self.bundle()).expect("identity");
            let record = InstallState::new(
                1,
                sample_update_config().app_id,
                Scope::User,
                INSTALL_ID,
                TARGET,
            )
            .install(version(V100), 10, TARGET, INSTALL_ID);
            let store = UserScope {
                dir: layout.state_dir(),
                app_id: sample_update_config().app_id,
            };
            let loaded = store.load(&fs, &Sha256Hasher).expect("load");
            store
                .commit(&fs, &loaded, &record, &Sha256Hasher)
                .expect("commit");
            std::fs::write(self.our_agent(), plist(&format!("{}.lunepack", app_id())))
                .expect("agent");
        }

        /// Runs `<tree>`'s runtime: `uninstall --silent`; its exit code, stdout and stderr.
        fn uninstall(&self, tree: &Path) -> (i32, String, String) {
            let runtime = tree.join("Contents/MacOS/lunepack-runtime");
            let mut child = Command::new(&runtime)
                .args(["uninstall", "--silent"])
                .env("HOME", &self.home)
                .env("LUNEPACK_NO_UI", "1")
                .env_remove(HEALTH_TOKEN_VAR)
                .current_dir(&self.base)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
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
            (
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            )
        }

        /// Every path under the lab's base, not following a symlink.
        fn snapshot(&self) -> BTreeSet<PathBuf> {
            fn walk(dir: &Path, into: &mut BTreeSet<PathBuf>) {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    return;
                };
                for entry in entries {
                    let path = entry.expect("entry").path();
                    let is_dir = std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir());
                    into.insert(path.clone());
                    if is_dir {
                        walk(&path, into);
                    }
                }
            }
            let mut all = BTreeSet::new();
            walk(&self.base, &mut all);
            all
        }

        /// Fails when anything of `before` is gone.
        fn nothing_removed(&self, before: &BTreeSet<PathBuf>) {
            let after = self.snapshot();
            let gone: Vec<_> = before.difference(&after).collect();
            assert!(gone.is_empty(), "removed: {gone:?}");
        }

        /// The tombstones of this app id in `dir`.
        fn tombstones_in(&self, dir: &Path) -> Vec<String> {
            let prefix = format!(".{}.removing-", app_id());
            std::fs::read_dir(dir)
                .expect("dir")
                .filter_map(|e| e.ok()?.file_name().into_string().ok())
                .filter(|n| n.starts_with(&prefix))
                .collect()
        }

        /// A running instance from `tree`'s entry, once the kernel has it.
        fn instance(&self, tree: &Path) -> Running {
            let child = Command::new(tree.join("Contents/MacOS/app"))
                .args([SLEEP_ARG, "60"])
                .stdin(Stdio::null())
                .spawn()
                .expect("instance");
            let process = lunepack_os_macos::MacProcess::new();
            let start = Instant::now();
            while process.process_id(child.id()).ok().flatten().is_none() {
                assert!(start.elapsed() < Duration::from_secs(10), "not started");
                std::thread::sleep(Duration::from_millis(20));
            }
            // Its executable is read only once exec is done: wait for the path to be the entry's.
            std::thread::sleep(Duration::from_millis(200));
            Running(child)
        }
    }

    /// A process killed and reaped when dropped.
    struct Running(Child);

    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn app_id() -> String {
        sample_update_config().app_id.as_str().to_owned()
    }

    /// A LaunchAgent plist with `label`.
    fn plist(label: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n\
             \t<key>Label</key>\n\t<string>{label}</string>\n\t<key>RunAtLoad</key>\n\t<true/>\n\
             </dict>\n</plist>\n"
        )
    }

    fn exists(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }

    /// The final object is the one line on stdout, with `outcome`.
    fn assert_outcome(stdout: &str, outcome: &str) {
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(lines.len(), 1, "{stdout}");
        let line = lines[0];
        assert!(
            line.contains("\"type\":\"result\"")
                && line.contains("\"command\":\"uninstall\"")
                && line.contains(&format!("\"outcome\":\"{outcome}\"")),
            "{line}"
        );
    }

    fn assert_error(code: i32, stdout: &str, want_code: i32, want_kind: &str) {
        assert_eq!(code, want_code, "{stdout}");
        assert!(
            stdout.contains("\"type\":\"error\"")
                && stdout.contains(&format!("\"kind\":\"{want_kind}\"")),
            "{stdout}"
        );
    }

    // ---- the cases ----------------------------------------------------------------------------

    fn removes_everything_ours(lab: &Lab) {
        lab.install();
        // Foreign items: a file and another app next to `B`, another app's LaunchAgent, another
        // folder in the data home.
        let foreign_file = lab.apps().join("notes.txt");
        let other_app = lab.apps().join("Other.app");
        let other_agent = lab.agents().join("com.example.other.plist");
        let other_data = lab.data.join("com.example.other");
        std::fs::write(&foreign_file, b"mine").expect("file");
        std::fs::create_dir_all(other_app.join("Contents")).expect("app");
        std::fs::write(&other_agent, plist("com.example.other")).expect("agent");
        std::fs::create_dir_all(&other_data).expect("data");

        let (code, stdout, stderr) = lab.uninstall(&lab.bundle());
        assert_eq!(code, 0, "{stdout}{stderr}");
        assert_outcome(&stdout, "uninstalled");
        assert!(!exists(&lab.bundle()), "the bundle is left");
        assert!(!exists(&lab.root), "the install root is left");
        assert!(!exists(&lab.our_agent()), "our LaunchAgent is left");
        for kept in [&foreign_file, &other_app, &other_agent, &other_data] {
            assert!(exists(kept), "a foreign item went: {}", kept.display());
        }
        assert_eq!(
            std::fs::read(&foreign_file).expect("file"),
            b"mine",
            "the foreign file changed"
        );
        assert!(lab.tombstones_in(&lab.apps()).is_empty());
        assert!(lab.tombstones_in(&lab.data).is_empty());
        assert!(
            !stdout.contains(&lab.base.display().to_string()),
            "{stdout}"
        );
    }

    fn foreign_agent_is_kept(lab: &Lab) {
        lab.install();
        // Another program's file at our name: never ours to remove.
        let foreign = plist("com.example.someone-else");
        std::fs::write(lab.our_agent(), &foreign).expect("agent");
        let (code, stdout, stderr) = lab.uninstall(&lab.bundle());
        assert_eq!(code, 0, "{stdout}{stderr}");
        assert_outcome(&stdout, "uninstalled_with_leftovers");
        assert_eq!(
            std::fs::read_to_string(lab.our_agent()).expect("agent"),
            foreign,
            "the foreign LaunchAgent changed"
        );
        assert!(!exists(&lab.bundle()) && !exists(&lab.root));
    }

    fn refused_while_running(lab: &Lab) {
        lab.install();
        for tree in [lab.bundle(), lab.version_dir(V090)] {
            let running = lab.instance(&tree);
            let before = lab.snapshot();
            let (code, stdout, _) = lab.uninstall(&lab.bundle());
            assert_error(code, &stdout, 25, "in_use");
            lab.nothing_removed(&before);
            drop(running);
        }
        // Once nothing runs, the same uninstall goes through.
        let (code, stdout, stderr) = lab.uninstall(&lab.bundle());
        assert_eq!(code, 0, "{stdout}{stderr}");
        assert!(!exists(&lab.bundle()) && !exists(&lab.root));
    }

    fn tombstones_removed(lab: &Lab) {
        lab.install();
        let id = app_id();
        // What an earlier run left when cut off: a tombstone in each parent, one holding a link
        // to a file outside it; and look-alikes that are not tombstones.
        let outside = lab.base.join("outside.txt");
        std::fs::write(&outside, b"keep").expect("outside");
        let t_apps = lab.apps().join(format!(".{id}.removing-{TOMBSTONE_HEX}"));
        let t_data = lab.data.join(format!(".{id}.removing-{TOMBSTONE_HEX}"));
        for t in [&t_apps, &t_data] {
            std::fs::create_dir_all(t.join("Contents")).expect("tombstone");
            std::os::unix::fs::symlink(&outside, t.join("Contents/link")).expect("link");
        }
        let not_hex = lab.apps().join(format!(".{id}.removing-0123456789abcdeX"));
        let other_app = lab
            .data
            .join(format!(".com.example.other.removing-{TOMBSTONE_HEX}"));
        let a_file = lab.apps().join(format!(".{id}.removing-fedcba9876543210"));
        std::fs::create_dir_all(&not_hex).expect("look-alike");
        std::fs::create_dir_all(&other_app).expect("other");
        std::fs::write(&a_file, b"file").expect("file");

        let (code, stdout, stderr) = lab.uninstall(&lab.bundle());
        assert_eq!(code, 0, "{stdout}{stderr}");
        assert!(!exists(&t_apps) && !exists(&t_data), "a tombstone is left");
        assert_eq!(std::fs::read(&outside).expect("outside"), b"keep");
        for kept in [&not_hex, &other_app, &a_file] {
            assert!(exists(kept), "a look-alike went: {}", kept.display());
        }
    }

    fn not_the_pointer_is_26(lab: &Lab) {
        lab.install();
        // A tombstone of an earlier run stays too: nothing at all is removed before validation.
        let t_apps = lab
            .apps()
            .join(format!(".{}.removing-{TOMBSTONE_HEX}", app_id()));
        std::fs::create_dir_all(&t_apps).expect("tombstone");

        // The runtime of an old instance's tree in `R/versions`: installed, but not `B`.
        let before = lab.snapshot();
        let (code, stdout, _) = lab.uninstall(&lab.version_dir(V090));
        assert_error(code, &stdout, 26, "install_mismatch");
        lab.nothing_removed(&before);

        // A bundle moved on its volume (followed only at the app's next start): not `B` either.
        let moved = lab.apps().join("Moved.app");
        std::fs::rename(lab.bundle(), &moved).expect("move");
        let before = lab.snapshot();
        let (code, stdout, _) = lab.uninstall(&moved);
        assert_error(code, &stdout, 26, "install_mismatch");
        lab.nothing_removed(&before);
        assert!(exists(&lab.our_agent()));
    }
}
