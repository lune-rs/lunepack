//! The Service Control Manager side against the real system (M10 step 9): the connector's answers
//! for a service that is not there, the registrar's reads of a missing service, the dispatcher's
//! refusal outside the SCM, and the self-test's process (exit code, timeout and kill, environment,
//! working directory, inherited handles, a path with spaces).
//!
//! Own `main` (see Cargo.toml): this binary is also the program the self-test starts (its first
//! argument is `--self-test`, its behaviour comes from the file name it was copied to), and the
//! cases run one after another.
//!
//! The real registration (create, descriptor read-back, image quoting, replacement, removal, a
//! disabled service) needs an administrator and creates a service under a name of its own; it runs
//! only with `LUNEPACK_TEST_SCM_REAL=1` and says so when it does not. Starting the service as a
//! standard user is step 11's row.

#[cfg(not(windows))]
fn main() {
    println!("lunepack-os-windows scm tests: Windows only, skipped");
}

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--self-test") {
        std::process::exit(windows::child(&args));
    }
    if windows::is_service_copy() {
        std::process::exit(windows::service_main());
    }
    windows::run_all(&args);
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use std::os::windows::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use lunepack_core::{AppId, ConnectError, ServiceConnector, ServiceRegError, ServiceRegistrar};
    use lunepack_os_windows::{
        HostError, PipeAccess, PipeError, PipeServer, SID_ADMINISTRATORS, USERS_MASK,
        WindowsConnector, WindowsRegistrar, judge_service_descriptor, pipe_name, run_service,
    };
    use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Threading::{
        CreateEventW, OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };

    type TestFn = fn(&Path);

    const TESTS: &[(&str, TestFn)] = &[
        ("a_missing_service_is_not_installed", missing_service),
        (
            "a_missing_service_reads_as_none_and_removes_as_ok",
            registrar_missing,
        ),
        (
            "the_dispatcher_refuses_outside_the_scm",
            dispatcher_outside_scm,
        ),
        ("a_self_test_that_exits_zero_passes", self_test_pass),
        ("a_self_test_that_exits_nonzero_fails", self_test_fail),
        (
            "a_self_test_that_hangs_is_killed_at_the_limit",
            self_test_hang,
        ),
        (
            "a_self_test_runs_clean_in_a_folder_with_spaces",
            self_test_clean,
        ),
        ("a_relative_image_is_refused", self_test_relative),
        ("real_registration_round_trip", real_round_trip),
        ("real_service_runs_connects_and_stops", real_service),
    ];

    pub fn run_all(args: &[String]) {
        let filter = args.iter().find(|a| !a.starts_with('-'));
        let mut failed = 0;
        for (name, test) in TESTS {
            if filter.is_some_and(|f| !name.contains(f.as_str())) {
                continue;
            }
            let scratch = Scratch::new(name);
            let result = std::panic::catch_unwind(|| test(&scratch.0));
            drop(scratch);
            match result {
                Ok(()) => println!("test {name} ... ok"),
                Err(_) => {
                    println!("test {name} ... FAILED");
                    failed += 1;
                }
            }
        }
        if failed > 0 {
            println!("{failed} test(s) failed");
            std::process::exit(1);
        }
    }

    /// A scratch folder whose name has a space in it (so every path a test builds needs quoting),
    /// removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let dir =
                std::env::temp_dir().join(format!("lp scm {}-{}", std::process::id(), name.len()));
            assert!(!dir.exists(), "scratch is new");
            std::fs::create_dir_all(&dir).expect("create the scratch folder");
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn app(prefix: &str) -> AppId {
        AppId::parse(&format!("{prefix}-{}", std::process::id())).expect("a valid app id")
    }

    // ---- the child ------------------------------------------------------------------------

    /// What a copy of this binary does when it is started with `--self-test`, by its file name.
    pub fn child(args: &[String]) -> i32 {
        let exe = std::env::current_exe().expect("own path");
        let stem = exe
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let folder = exe.parent().expect("a folder").to_path_buf();
        match stem.as_str() {
            "scm-pass" => 0,
            "scm-fail" => 3,
            "scm-hang" => {
                std::fs::write(folder.join("pid.txt"), std::process::id().to_string())
                    .expect("write the pid");
                std::thread::sleep(Duration::from_secs(120));
                0
            }
            "scm-clean" => clean_child(args, &folder, false),
            "scm-control" => clean_child(args, &folder, true),
            _ => 99,
        }
    }

    /// Checks what the self-test promises (`control` = false) or, for the control run started by a
    /// plain `Command`, that this very check can see an inherited handle (`control` = true).
    fn clean_child(args: &[String], folder: &Path, control: bool) -> i32 {
        let mut report = String::new();
        let handles: Vec<usize> = std::fs::read_to_string(folder.join("handles.txt"))
            .unwrap_or_default()
            .split_whitespace()
            .filter_map(|v| v.parse().ok())
            .collect();
        let valid = handles
            .iter()
            .filter(|h| {
                let mut flags = 0u32;
                // SAFETY: `flags` is writable; an invalid handle value only makes the call fail.
                unsafe { GetHandleInformation(**h as HANDLE, &mut flags) != 0 }
            })
            .count();
        report.push_str(&format!("handles {} valid {valid}\n", handles.len()));
        let mut bad = handles.is_empty();
        if control {
            bad |= valid == 0;
        } else {
            bad |= valid != 0;
            let vars: Vec<String> = std::env::vars_os()
                .map(|(k, _)| k.to_string_lossy().to_ascii_lowercase())
                .collect();
            report.push_str(&format!("vars {vars:?}\n"));
            bad |= vars != ["systemroot"];
            let cwd = std::env::current_dir().expect("a working directory");
            report.push_str(&format!("cwd {}\n", cwd.display()));
            bad |= !same_folder(&cwd, folder);
            let own = std::env::args().collect::<Vec<_>>();
            report.push_str(&format!("args {own:?} / {args:?}\n"));
            bad |= own.len() != 2 || own[1] != "--self-test";
        }
        let _ = std::fs::write(
            folder.join(if control { "control.txt" } else { "report.txt" }),
            report,
        );
        i32::from(bad)
    }

    fn same_folder(a: &Path, b: &Path) -> bool {
        let strip = |p: &Path| {
            std::fs::canonicalize(p)
                .map(|p| {
                    p.to_string_lossy()
                        .trim_start_matches(r"\\?\")
                        .to_ascii_lowercase()
                })
                .ok()
        };
        strip(a).is_some() && strip(a) == strip(b)
    }

    /// A copy of this binary named `<name>.exe` inside `dir`.
    fn copy_as(dir: &Path, name: &str) -> PathBuf {
        let target = dir.join(format!("{name}.exe"));
        std::fs::copy(std::env::current_exe().expect("own path"), &target)
            .expect("copy the binary");
        target
    }

    // ---- the cases ------------------------------------------------------------------------

    fn missing_service(_: &Path) {
        match WindowsConnector::new().connect(&app("scm-absent")) {
            Err(ConnectError::NotInstalled) => {}
            Err(other) => panic!("expected NotInstalled, got {other:?}"),
            Ok(_) => panic!("expected NotInstalled, got a connection"),
        }
    }

    fn registrar_missing(dir: &Path) {
        let id = app("scm-absent");
        let registrar = WindowsRegistrar::new("Absent");
        assert_eq!(registrar.image(&id), Ok(None));
        assert_eq!(registrar.remove(&id), Ok(()));
        assert_eq!(
            registrar.set_image(&id, &dir.join("x.exe")),
            Err(ServiceRegError::NotRegistered)
        );
    }

    fn dispatcher_outside_scm(_: &Path) {
        assert_eq!(run_service("", |_| 0), Err(HostError::InvalidName));
        assert_eq!(run_service("a\0b", |_| 0), Err(HostError::InvalidName));
        // Outside the SCM the dispatcher cannot connect. A process may call it only once, so
        // this is the only call that reaches it (a later one is `InUse`).
        assert_eq!(run_service("scm-test", |_| 0), Err(HostError::NotAService));
    }

    fn self_test_pass(dir: &Path) {
        let image = copy_as(dir, "scm-pass");
        assert_eq!(WindowsRegistrar::new("T").self_test(&image), Ok(()));
    }

    fn self_test_fail(dir: &Path) {
        let image = copy_as(dir, "scm-fail");
        assert_eq!(
            WindowsRegistrar::new("T").self_test(&image),
            Err(ServiceRegError::SelfTestFailed)
        );
        // A file that is not there fails the same way.
        assert_eq!(
            WindowsRegistrar::new("T").self_test(&dir.join("missing.exe")),
            Err(ServiceRegError::SelfTestFailed)
        );
    }

    fn self_test_hang(dir: &Path) {
        let image = copy_as(dir, "scm-hang");
        let start = Instant::now();
        assert_eq!(
            WindowsRegistrar::new("T").self_test(&image),
            Err(ServiceRegError::SelfTestFailed)
        );
        let took = start.elapsed();
        assert!(
            took >= Duration::from_secs(9) && took < Duration::from_secs(20),
            "cut at the limit, took {took:?}"
        );
        let pid: u32 = std::fs::read_to_string(dir.join("pid.txt"))
            .expect("the hanging child ran")
            .trim()
            .parse()
            .expect("a pid");
        // SAFETY: opening a process for synchronize only; a handle of a gone process fails.
        let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
        if !process.is_null() {
            // SAFETY: `process` is an open handle with synchronize access.
            let waited = unsafe { WaitForSingleObject(process, 5_000) };
            assert_eq!(waited, 0, "the killed process ends");
        }
    }

    fn self_test_clean(dir: &Path) {
        // Inheritable handles this process holds: the test's own proof that a plain `Command`
        // hands them down (the control) and that the self-test does not.
        let handles: Vec<usize> = (0..64)
            .map(|_| {
                let attributes = SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: std::ptr::null_mut(),
                    bInheritHandle: 1,
                };
                // SAFETY: `attributes` is valid for the call; the event is unnamed.
                let h = unsafe { CreateEventW(&attributes, 1, 0, std::ptr::null()) };
                assert!(!h.is_null(), "create an inheritable event");
                h as usize
            })
            .collect();
        let list: Vec<String> = handles.iter().map(usize::to_string).collect();
        std::fs::write(dir.join("handles.txt"), list.join(" ")).expect("write the handle list");

        let control = copy_as(dir, "scm-control");
        let status = Command::new(&control)
            .arg("--self-test")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000)
            .status()
            .expect("start the control");
        let control_report = std::fs::read_to_string(dir.join("control.txt")).unwrap_or_default();
        assert!(
            status.success(),
            "the control sees an inherited handle (the instrument works): {control_report}"
        );

        let image = copy_as(dir, "scm-clean");
        let outcome = WindowsRegistrar::new("T").self_test(&image);
        let report = std::fs::read_to_string(dir.join("report.txt")).unwrap_or_default();
        assert_eq!(
            outcome,
            Ok(()),
            "the self-test child's own report:\n{report}"
        );
    }

    fn self_test_relative(_: &Path) {
        assert_eq!(
            WindowsRegistrar::new("T").self_test(Path::new(r"scm-pass.exe")),
            Err(ServiceRegError::SelfTestFailed)
        );
    }

    // ---- the real registration (administrator, opt in) ------------------------------------

    /// Removes the service on every exit path.
    struct Cleanup(AppId);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = WindowsRegistrar::new("T").remove(&self.0);
        }
    }

    fn sc(args: &[&str]) -> String {
        let root = std::env::var("SystemRoot").expect("SystemRoot");
        let out = Command::new(format!(r"{root}\System32\sc.exe"))
            .args(args)
            .output()
            .expect("run sc.exe");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn real_round_trip(dir: &Path) {
        if std::env::var("LUNEPACK_TEST_SCM_REAL").as_deref() != Ok("1") {
            println!(
                "  skipped: set LUNEPACK_TEST_SCM_REAL=1 as an administrator to register a real service"
            );
            return;
        }
        let id = app("scm-real");
        let name = format!("lunepack-{}", id.as_str());
        let _cleanup = Cleanup(id.clone());
        let registrar = WindowsRegistrar::new("Scm Real Test");
        let first = dir.join("one dir").join("lunepack-service.exe");
        let second = dir.join("two dir").join("lunepack-service.exe");

        registrar.register_new(&id, &first).expect("register");
        assert!(
            registrar.register_new(&id, &second).is_err(),
            "an existing service is an error for register_new"
        );
        assert_eq!(registrar.image(&id), Ok(Some(first.clone())));

        // The stored string: the absolute path in double quotes, nothing after it.
        let config = sc(&["qc", &name]);
        let quoted = format!("\"{}\"", first.display());
        assert!(
            config.contains(&format!("BINARY_PATH_NAME   : {quoted}\r\n")),
            "stored image: {config}"
        );
        assert!(
            config.contains("Scm Real Test Update Service"),
            "display name: {config}"
        );
        assert!(config.contains("DEMAND_START"), "start type: {config}");
        assert!(config.contains("WIN32_OWN_PROCESS"), "type: {config}");
        assert!(config.contains("LocalSystem"), "account: {config}");

        // The descriptor read back: owner Administrators, Users exactly start/status/read control,
        // nothing for a non-administrator that changes the service.
        let descriptor = registrar.descriptor(&id).expect("read the descriptor");
        println!("  descriptor: {descriptor:?}");
        assert_eq!(descriptor.owner, SID_ADMINISTRATORS);
        assert_eq!(judge_service_descriptor(&descriptor), Ok(()));
        let users: u32 = descriptor
            .entries
            .as_ref()
            .expect("a DACL")
            .iter()
            .filter(|a| a.sid == "S-1-5-32-545")
            .fold(0, |m, a| m | a.mask);
        assert_eq!(users, USERS_MASK);

        // set_image changes only the image path.
        registrar.set_image(&id, &second).expect("set_image");
        assert_eq!(registrar.image(&id), Ok(Some(second.clone())));
        let config = sc(&["qc", &name]);
        assert!(
            config.contains("DEMAND_START") && config.contains("LocalSystem"),
            "{config}"
        );
        assert_eq!(
            judge_service_descriptor(&registrar.descriptor(&id).expect("d")),
            Ok(())
        );

        // The core's `register` replaces.
        registrar.register(&id, &first).expect("replace");
        assert_eq!(registrar.image(&id), Ok(Some(first.clone())));
        assert_eq!(
            judge_service_descriptor(&registrar.descriptor(&id).expect("d")),
            Ok(())
        );

        // A start that fails (the file is not there) and a disabled service.
        match WindowsConnector::with_timeout(Duration::from_secs(5)).connect(&id) {
            Err(ConnectError::Failed(_) | ConnectError::FailedCode(..)) => {}
            Err(other) => panic!("expected Failed, got {other:?}"),
            Ok(_) => panic!("a connection to a service that cannot start"),
        }
        sc(&["config", &name, "start=", "disabled"]);
        match WindowsConnector::with_timeout(Duration::from_secs(5)).connect(&id) {
            Err(ConnectError::Disabled) => {}
            Err(other) => panic!("expected Disabled, got {other:?}"),
            Ok(_) => panic!("a connection to a disabled service"),
        }

        registrar.remove(&id).expect("remove");
        assert_eq!(registrar.image(&id), Ok(None));
        assert_eq!(registrar.remove(&id), Ok(()));
    }

    // ---- a real service made of a copy of this binary --------------------------------------

    /// Whether this process is the copy registered as the test service (named `scm-svc.exe`).
    pub fn is_service_copy() -> bool {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.file_stem().map(|s| s.to_ascii_lowercase()))
            .is_some_and(|s| s == "scm-svc")
    }

    /// The service body of the copy: it reads its app id from `appid.txt` beside it, serves the
    /// service pipe (owner LocalSystem, which it is), greets each client and lets go, and ends when
    /// the SCM asks it to stop.
    pub fn service_main() -> i32 {
        let folder = std::env::current_exe()
            .expect("own path")
            .parent()
            .expect("a folder")
            .to_path_buf();
        let Ok(id) = std::fs::read_to_string(folder.join("appid.txt")) else {
            return 2;
        };
        let name = format!("lunepack-{}", id.trim());
        let service_name = name.clone();
        let result = run_service(&service_name, move |control| {
            let Ok(mut server) = PipeServer::create(&name, &PipeAccess::Service) else {
                return 3;
            };
            let canceller = server.canceller();
            control.on_stop(move || canceller.cancel());
            let mut served = 0u32;
            while !control.stop_requested() {
                match server.accept(Some(Duration::from_secs(5))) {
                    Ok(()) => {
                        served += 1;
                        let _ = std::io::Write::write_all(
                            &mut server,
                            format!("hello {served}").as_bytes(),
                        );
                        server.disconnect();
                    }
                    Err(PipeError::Timeout) => {}
                    Err(PipeError::Cancelled) => break,
                    Err(_) => return 4,
                }
            }
            0
        });
        i32::from(result.is_err())
    }

    fn real_service(dir: &Path) {
        if std::env::var("LUNEPACK_TEST_SCM_REAL").as_deref() != Ok("1") {
            println!(
                "  skipped: set LUNEPACK_TEST_SCM_REAL=1 as an administrator to register a real service"
            );
            return;
        }
        let id = app("scm-svc");
        let _cleanup = Cleanup(id.clone());
        let image = copy_as(dir, "scm-svc");
        std::fs::write(dir.join("appid.txt"), id.as_str()).expect("write the app id");
        let registrar = WindowsRegistrar::new("Scm Service Test");
        registrar.register_new(&id, &image).expect("register");
        assert_eq!(pipe_name(&id), format!("lunepack-{}", id.as_str()));

        let connector = WindowsConnector::with_timeout(Duration::from_secs(20));
        for round in 1..=2u32 {
            let mut channel = match connector.connect(&id) {
                Ok(channel) => channel,
                Err(e) => panic!("round {round}: connect failed: {e:?}"),
            };
            let mut greeting = String::new();
            std::io::Read::read_to_string(&mut channel, &mut greeting).expect("read the greeting");
            assert_eq!(greeting, format!("hello {round}"));
        }

        // Stop and delete: the stop control reaches the body, which ends its blocked accept.
        let start = Instant::now();
        registrar.remove(&id).expect("remove");
        let took = start.elapsed();
        assert!(
            took < Duration::from_secs(10),
            "the service stopped promptly, took {took:?}"
        );
        assert_eq!(registrar.image(&id), Ok(None));
    }
}
