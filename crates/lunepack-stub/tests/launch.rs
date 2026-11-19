//! The built stubs run for real against a fake install (M7-D7, launch contract v1).
//!
//! Own `main` (see Cargo.toml): this test binary is also the app (when it runs as `app.exe`) and
//! the runtime (as `lunepack-runtime.exe`) the stub starts. The app writes a report to the file
//! `LP_STUB_OUT` names: its own path, its command-line tail as the system holds it, the health
//! token it sees and its working directory; with `LP_STUB_STDIO` set it copies its standard input
//! to standard output and standard error; it exits with `LP_STUB_EXIT`. The runtime writes its
//! arguments. Records are written with the core's store writer and the real SHA-256 hasher; the
//! install root is a temporary folder whose name has a space. Windows only; the GUI stub's
//! failure path shows a message box, so failures are run through the console stub.

#[cfg(windows)]
fn main() {
    let exe = std::env::current_exe().expect("own path");
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase());
    match name.as_deref() {
        Some("app.exe") => cases::fake_app(),
        Some("lunepack-runtime.exe") => cases::fake_runtime(),
        _ => cases::run_all(),
    }
}

#[cfg(not(windows))]
fn main() {
    println!("lunepack-stub launch tests: Windows only, skipped");
}

#[cfg(windows)]
mod cases {
    use std::io::{Read as _, Write as _};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use lunepack_core::state::{commit, commit_raw_payload, load};
    use lunepack_core::{
        CurrentRef, InstallState, LayoutScheme, PendingRef, PreviousRef, RelPath, Scope, StubError,
        Target, UpdateConfig, UserLayout, Version,
    };
    use lunepack_crypto::Sha256Hasher;
    use lunepack_fs::StdFs;
    use lunepack_testkit::sample_update_config;

    const GUI: &str = env!("CARGO_BIN_EXE_lunepack-stub");
    const CONSOLE: &str = env!("CARGO_BIN_EXE_lunepack-stub-console");
    #[cfg(target_arch = "x86_64")]
    const TARGET: Target = Target::WindowsX86_64;
    #[cfg(target_arch = "aarch64")]
    const TARGET: Target = Target::WindowsAarch64;
    const LIMIT: Duration = Duration::from_secs(30);
    const TOKEN_VAR: &str = "LUNEPACK_HEALTH_TOKEN";
    /// The contract's argument round trip.
    const TAIL: &str = r#"a "b c" d\"e \\""#;

    // --- the helpers this binary turns into ---

    fn write_report(text: &str) {
        let out = PathBuf::from(std::env::var_os("LP_STUB_OUT").expect("LP_STUB_OUT"));
        let tmp = out.with_extension("tmp");
        std::fs::write(&tmp, text).expect("report");
        std::fs::rename(&tmp, &out).expect("report rename");
    }

    pub fn fake_app() {
        let line = lunepack_os_windows::raw_command_line().expect("command line");
        let tail = String::from_utf16(lunepack_stub::command_line_tail(&line)).expect("utf-16");
        let token = std::env::var(TOKEN_VAR).unwrap_or_else(|_| "-".to_owned());
        let exe = std::env::current_exe().expect("exe");
        let cwd = std::env::current_dir().expect("cwd");
        if std::env::var_os("LP_STUB_STDIO").is_some() {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input).expect("stdin");
            print!("out:{input}");
            eprint!("err:{input}");
            let _ = std::io::stdout().flush();
        }
        write_report(&format!(
            "exe={}\ntail={tail}\ntoken={token}\ncwd={}\n",
            exe.display(),
            cwd.display()
        ));
        let code: u32 = std::env::var("LP_STUB_EXIT")
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        std::process::exit(code as i32);
    }

    pub fn fake_runtime() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        write_report(&args.join("\n"));
    }

    // --- the fake install ---

    struct Lab {
        _tmp: tempfile::TempDir,
        dir: PathBuf,
        root: PathBuf,
    }

    struct Run {
        code: i32,
        stdout: String,
        stderr: String,
    }

    fn v(text: &str) -> Version {
        Version::parse(text).expect("version")
    }

    impl Lab {
        fn new() -> Lab {
            let tmp = tempfile::Builder::new()
                .prefix("stub-")
                .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
                .expect("tmp");
            let dir = std::fs::canonicalize(tmp.path()).expect("canonical");
            let dir = PathBuf::from(
                dir.to_string_lossy()
                    .strip_prefix(r"\\?\")
                    .expect("verbatim")
                    .to_owned(),
            );
            let root = dir.join("Stub Test App");
            std::fs::create_dir(&root).expect("root");
            std::fs::copy(GUI, root.join("app.exe")).expect("gui stub");
            std::fs::copy(CONSOLE, root.join("app-console.exe")).expect("console stub");
            Lab {
                _tmp: tmp,
                dir,
                root,
            }
        }

        fn layout(&self) -> UserLayout {
            UserLayout::from_root(self.root.clone(), LayoutScheme::WINDOWS)
        }

        fn config(&self, version: &str) -> UpdateConfig {
            let mut c = sample_update_config();
            c.install.entry = RelPath::parse("bin/app.exe").expect("entry");
            c.version = v(version);
            c.target = TARGET;
            c
        }

        /// The tree of `version`: the config, and this binary as the app and as the runtime.
        fn tree(&self, version: &str) -> PathBuf {
            let tree = self.layout().version_dir(&v(version));
            let bin = tree.join("bin");
            std::fs::create_dir_all(&bin).expect("tree");
            let me = std::env::current_exe().expect("test exe");
            std::fs::copy(&me, bin.join("app.exe")).expect("app");
            std::fs::copy(&me, bin.join("lunepack-runtime.exe")).expect("runtime");
            std::fs::write(
                tree.join("lunepack-update.json"),
                self.config(version).to_bytes().expect("config bytes"),
            )
            .expect("config");
            tree
        }

        fn record(&self, record: &InstallState) {
            let dir = self.layout().state_dir();
            std::fs::create_dir_all(&dir).expect("state");
            let fs = StdFs::new();
            let loaded =
                load::<InstallState>(&fs, &dir, &record.app_id, &Sha256Hasher).expect("load");
            commit(&fs, &dir, &loaded, record, &Sha256Hasher).expect("commit");
        }

        fn new_record(&self, current: &str) -> InstallState {
            let mut r = InstallState::new(
                1,
                sample_update_config().app_id,
                Scope::User,
                [5; 16],
                TARGET,
            );
            r.current = Some(CurrentRef {
                version: v(current),
                issued: 1,
            });
            r
        }

        /// An installed 1.0.0.
        fn installed() -> Lab {
            let lab = Lab::new();
            lab.tree("1.0.0");
            lab.record(&lab.new_record("1.0.0"));
            lab
        }

        fn out(&self) -> PathBuf {
            self.dir.join("report.txt")
        }

        fn stub(&self, console: bool) -> PathBuf {
            self.root.join(if console {
                "app-console.exe"
            } else {
                "app.exe"
            })
        }

        /// Runs a stub with `tail` as its raw command-line tail and waits for it.
        fn run(&self, console: bool, tail: &str, setup: impl FnOnce(&mut Command)) -> Run {
            let _ = std::fs::remove_file(self.out());
            let mut command = Command::new(self.stub(console));
            if !tail.is_empty() {
                std::os::windows::process::CommandExt::raw_arg(&mut command, tail);
            }
            command
                .env("LP_STUB_OUT", self.out())
                .env_remove(TOKEN_VAR)
                .env_remove("LP_STUB_STDIO")
                .env_remove("LP_STUB_EXIT")
                .current_dir(&self.dir)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            setup(&mut command);
            let mut child = command.spawn().expect("spawn the stub");
            let start = Instant::now();
            while child.try_wait().expect("wait").is_none() {
                if start.elapsed() > LIMIT {
                    let _ = child.kill();
                    panic!("the stub ran too long");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let out = child.wait_with_output().expect("output");
            Run {
                code: out.status.code().expect("exit code"),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            }
        }

        /// The report the app or the runtime wrote (waiting for it: the GUI stub does not wait).
        fn report(&self) -> String {
            let start = Instant::now();
            loop {
                if let Ok(text) = std::fs::read_to_string(self.out()) {
                    return text;
                }
                assert!(start.elapsed() < LIMIT, "no report");
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn field(&self, report: &str, key: &str) -> String {
            report
                .lines()
                .find_map(|l| l.strip_prefix(&format!("{key}=")))
                .unwrap_or_else(|| panic!("no {key} in the report"))
                .to_owned()
        }

        fn entry(&self, version: &str) -> PathBuf {
            self.layout()
                .version_dir(&v(version))
                .join("bin")
                .join("app.exe")
        }
    }

    // --- the cases ---

    /// The console stub starts the current entry with its tail byte for byte, its environment
    /// (the health token passes unchanged, and is not added when absent) and working directory,
    /// and the three standard handles; it exits with the app's code.
    fn console_launches_with_the_tail_environment_and_handles() {
        let lab = Lab::installed();
        let run = {
            let _ = std::fs::remove_file(lab.out());
            let mut command = Command::new(lab.stub(true));
            std::os::windows::process::CommandExt::raw_arg(&mut command, TAIL);
            command
                .env("LP_STUB_OUT", lab.out())
                .env("LP_STUB_STDIO", "1")
                .env(TOKEN_VAR, "tok-123")
                .env_remove("LP_STUB_EXIT")
                .current_dir(&lab.dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.spawn().expect("spawn");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(b"hello")
                .expect("write stdin");
            let out = child.wait_with_output().expect("output");
            Run {
                code: out.status.code().expect("code"),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            }
        };
        assert_eq!(run.code, 0, "{}", run.stderr);
        assert_eq!(run.stdout, "out:hello");
        assert_eq!(run.stderr, "err:hello");
        let report = lab.report();
        assert_eq!(lab.field(&report, "tail"), TAIL);
        assert_eq!(PathBuf::from(lab.field(&report, "exe")), lab.entry("1.0.0"));
        assert_eq!(lab.field(&report, "token"), "tok-123");
        assert_eq!(PathBuf::from(lab.field(&report, "cwd")), lab.dir);

        // No tail, no token: none is added.
        let run = lab.run(true, "", |_| {});
        assert_eq!(run.code, 0);
        let report = lab.report();
        assert_eq!(lab.field(&report, "tail"), "");
        assert_eq!(lab.field(&report, "token"), "-");
    }

    /// The console stub exits with the app's full 32-bit exit code.
    fn console_passes_on_the_full_exit_code() {
        let lab = Lab::installed();
        for code in [3u32, 255, 0xC000_0005] {
            let run = lab.run(true, "x", |c| {
                c.env("LP_STUB_EXIT", code.to_string());
            });
            assert_eq!(run.code as u32, code, "{}", run.stderr);
            lab.report();
        }
    }

    /// The GUI stub starts the app with the same tail and exits 0 without waiting for it.
    fn gui_starts_the_app_and_exits_0() {
        let lab = Lab::installed();
        let run = lab.run(false, TAIL, |c| {
            c.env("LP_STUB_EXIT", "3").env(TOKEN_VAR, "tok-456");
        });
        assert_eq!(run.code, 0, "{}", run.stderr);
        assert!(run.stdout.is_empty() && run.stderr.is_empty());
        let report = lab.report();
        assert_eq!(lab.field(&report, "tail"), TAIL);
        assert_eq!(PathBuf::from(lab.field(&report, "exe")), lab.entry("1.0.0"));
        assert_eq!(lab.field(&report, "token"), "tok-456");
    }

    /// The record's current version starts, never its pending or previous one.
    fn the_current_version_starts_even_while_pending() {
        let lab = Lab::new();
        lab.tree("1.0.0");
        lab.tree("2.0.0");
        let mut r = lab.new_record("2.0.0");
        r.pending = Some(PendingRef {
            version: v("2.0.0"),
            attempts: 0,
        });
        r.previous = Some(PreviousRef {
            version: v("1.0.0"),
        });
        lab.record(&r);
        for console in [true, false] {
            let run = lab.run(console, "", |_| {});
            assert_eq!(run.code, 0, "{}", run.stderr);
            let report = lab.report();
            assert_eq!(PathBuf::from(lab.field(&report, "exe")), lab.entry("2.0.0"));
        }
    }

    /// Each failure exits with its code and prints its fixed message, one line, no path.
    fn each_failure_has_its_code_and_fixed_message() {
        let check = |lab: &Lab, want: StubError| {
            let run = lab.run(true, "x", |_| {});
            assert_eq!(run.code, i32::from(want.code()), "{want:?}: {}", run.stderr);
            assert_eq!(run.stderr, format!("{}\n", want.message()), "{want:?}");
            assert!(run.stdout.is_empty());
            assert!(!lab.out().exists(), "{want:?}: the app ran");
        };
        // 90: no record.
        let lab = Lab::new();
        lab.tree("1.0.0");
        check(&lab, StubError::NotInstalled);
        // 91: a whole record the reader refuses.
        let lab = Lab::installed();
        commit_raw_payload(
            &StdFs::new(),
            &lab.layout().state_dir(),
            2,
            b"{\"seq\":2}",
            &Sha256Hasher,
        )
        .expect("raw record");
        check(&lab, StubError::State);
        // 92: the current version's config is missing.
        let lab = Lab::installed();
        std::fs::remove_file(
            lab.layout()
                .version_dir(&v("1.0.0"))
                .join("lunepack-update.json"),
        )
        .expect("remove config");
        check(&lab, StubError::Config);
        // 93: the entry is missing.
        let lab = Lab::installed();
        std::fs::remove_file(lab.entry("1.0.0")).expect("remove entry");
        check(&lab, StubError::Entry);
        // 94: the entry's directory is a junction (to a real copy of it).
        let lab = Lab::installed();
        let bin = lab.entry("1.0.0").parent().expect("bin").to_path_buf();
        let elsewhere = lab.dir.join("elsewhere");
        std::fs::rename(&bin, &elsewhere).expect("move bin");
        let made = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&bin)
            .arg(&elsewhere)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("mklink");
        assert!(made.success(), "mklink /J");
        check(&lab, StubError::Link);
        std::fs::remove_dir(&bin).expect("remove the junction");
        // 95: the entry is a regular file that does not start.
        let lab = Lab::installed();
        std::fs::write(lab.entry("1.0.0"), b"not a program").expect("entry");
        check(&lab, StubError::Launch);
    }

    /// Exactly `--lunepack-uninstall` [`/S` | `--silent`] starts the current version's runtime as
    /// `uninstall [--silent]` and exits 0; any other argument list goes to the app unchanged.
    fn the_reserved_argument_starts_the_runtime_uninstall() {
        let lab = Lab::installed();
        for console in [true, false] {
            for (tail, want) in [
                ("--lunepack-uninstall", "uninstall"),
                ("--lunepack-uninstall /S", "uninstall\n--silent"),
                ("--lunepack-uninstall --silent", "uninstall\n--silent"),
            ] {
                let run = lab.run(console, tail, |_| {});
                assert_eq!(run.code, 0, "{tail}: {}", run.stderr);
                assert_eq!(lab.report(), want, "{tail}");
            }
            for tail in ["--lunepack-uninstall x", "x --lunepack-uninstall"] {
                let run = lab.run(console, tail, |_| {});
                assert_eq!(run.code, 0, "{tail}: {}", run.stderr);
                let report = lab.report();
                assert_eq!(lab.field(&report, "tail"), tail);
            }
        }
        // A runtime that is missing is the entry error, and nothing starts.
        std::fs::remove_file(lab.entry("1.0.0").with_file_name("lunepack-runtime.exe"))
            .expect("remove runtime");
        let run = lab.run(true, "--lunepack-uninstall", |_| {});
        assert_eq!(run.code, i32::from(StubError::Entry.code()));
        assert!(!lab.out().exists());
    }

    /// The stub takes `R` from its own path and never from `R`'s name: a renamed install folder
    /// still launches.
    fn a_renamed_install_folder_still_launches() {
        let mut lab = Lab::installed();
        let renamed = lab.dir.join("Renamed Folder");
        std::fs::rename(&lab.root, &renamed).expect("rename");
        lab.root = renamed;
        let run = lab.run(true, "", |_| {});
        assert_eq!(run.code, 0, "{}", run.stderr);
        let report = lab.report();
        assert_eq!(PathBuf::from(lab.field(&report, "exe")), lab.entry("1.0.0"));
        assert!(!Path::new(&lab.field(&report, "exe")).starts_with(r"\\?\"));
    }

    pub fn run_all() {
        let cases: &[(&str, fn())] = &[
            (
                "console_launches_with_the_tail_environment_and_handles",
                console_launches_with_the_tail_environment_and_handles,
            ),
            (
                "console_passes_on_the_full_exit_code",
                console_passes_on_the_full_exit_code,
            ),
            (
                "gui_starts_the_app_and_exits_0",
                gui_starts_the_app_and_exits_0,
            ),
            (
                "the_current_version_starts_even_while_pending",
                the_current_version_starts_even_while_pending,
            ),
            (
                "each_failure_has_its_code_and_fixed_message",
                each_failure_has_its_code_and_fixed_message,
            ),
            (
                "the_reserved_argument_starts_the_runtime_uninstall",
                the_reserved_argument_starts_the_runtime_uninstall,
            ),
            (
                "a_renamed_install_folder_still_launches",
                a_renamed_install_folder_still_launches,
            ),
        ];
        let filter: Vec<String> = std::env::args()
            .skip(1)
            .filter(|a| !a.starts_with('-'))
            .collect();
        let mut failed = 0;
        let mut ran = 0;
        for (name, case) in cases {
            if !filter.is_empty() && !filter.iter().any(|f| name.contains(f.as_str())) {
                continue;
            }
            ran += 1;
            let ok = std::panic::catch_unwind(case).is_ok();
            println!("test {name} ... {}", if ok { "ok" } else { "FAILED" });
            if !ok {
                failed += 1;
            }
        }
        println!(
            "test result: {}. {} passed; {failed} failed",
            if failed == 0 { "ok" } else { "FAILED" },
            ran - failed
        );
        if failed > 0 {
            std::process::exit(101);
        }
    }
}
