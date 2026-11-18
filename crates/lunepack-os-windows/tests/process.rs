//! `WindowsProcess` with real processes: the testkit's process suite plus the Windows cases (a
//! reused pid is not waited on, a wait wakes at once when the process ends, the parent's identity,
//! a detached child that outlives its parent and one started inside a job that forbids breakaway,
//! a polite close request, and the in-use scan for a copied executable, case, short names and a
//! sibling folder sharing a prefix). Own `main` (see Cargo.toml): this binary is also the helper
//! program (`helper/`), and the cases run one after another, so no case sees another case's
//! processes.

#[cfg(windows)]
mod helper;

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if helper::run(&args) {
        return;
    }
    windows::run_all(&args);
}

#[cfg(not(windows))]
fn main() {
    println!("lunepack-os-windows process tests: Windows only, skipped");
}

#[cfg(windows)]
mod windows {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use lunepack_core::{ChildStdio, ExitKind, Process, ProcessId, SpawnSpec, WaitOutcome};
    use lunepack_os_windows::WindowsProcess;
    use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, OpenProcess, PROCESS_TERMINATE, TerminateProcess,
    };

    type TestFn = fn(&Path);

    const TESTS: &[(&str, TestFn)] = &[
        ("the_process_suite_passes", process_suite),
        ("a_reused_pid_counts_as_exited", reused_pid),
        ("a_wait_wakes_when_the_process_ends", wait_wakes),
        ("the_parent_is_the_spawning_process", parent_is_spawner),
        ("an_exited_parent_is_none", parent_gone),
        ("a_detached_child_outlives_its_parent", detached_outlives),
        (
            "a_detached_spawn_works_in_a_job_that_forbids_breakaway",
            detached_in_job,
        ),
        ("terminate_asks_a_window_to_close_first", terminate_asks),
        (
            "a_copied_exe_running_from_a_tree_uses_it",
            in_use_copied_exe,
        ),
        (
            "a_short_name_for_the_tree_is_still_the_tree",
            in_use_short_name,
        ),
        (
            "a_sibling_started_after_a_piped_child_holds_none_of_its_pipes",
            sibling_holds_no_pipe,
        ),
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
            std::process::exit(1);
        }
    }

    /// A canonical scratch directory, removed afterwards.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!(
                "lunepack-os-windows-{}-{}-a-fairly-long-directory-name",
                std::process::id(),
                name
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).expect("create scratch");
            Scratch(std::fs::canonicalize(&dir).expect("canonicalize scratch"))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Kills and reaps a std child when the case ends, so a failed case leaves no process.
    struct Reap(std::process::Child);

    impl Drop for Reap {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    const LIMIT: Duration = Duration::from_secs(20);

    fn helper() -> PathBuf {
        std::env::current_exe().expect("current_exe")
    }

    fn os() -> WindowsProcess {
        WindowsProcess::new()
    }

    fn std_helper(program: &Path, args: &[&str]) -> Reap {
        Reap(
            Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .expect("start the helper"),
        )
    }

    fn wait_for_file(path: &Path) -> String {
        let deadline = Instant::now() + LIMIT;
        loop {
            if let Ok(text) = std::fs::read_to_string(path) {
                return text;
            }
            assert!(Instant::now() < deadline, "the file did not appear");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn read_pid_file(path: &Path) -> ProcessId {
        let text = wait_for_file(path);
        let mut it = text.split_whitespace();
        ProcessId {
            pid: it.next().unwrap().parse().unwrap(),
            start_ticks: it.next().unwrap().parse().unwrap(),
        }
    }

    /// Kills a process that is not this test's child (a detached one), after checking that `id`
    /// still names it, and waits until it counts as exited.
    #[allow(unsafe_code)]
    fn kill_detached(id: ProcessId) {
        if os().process_id(id.pid).unwrap() == Some(id) {
            // SAFETY: `OpenProcess` takes integers; the handle it returns is closed by
            // `TerminateProcess`'s caller below through `OwnedHandle`.
            let raw = unsafe { OpenProcess(PROCESS_TERMINATE, 0, id.pid) };
            assert!(!raw.is_null(), "open the detached process to end it");
            // SAFETY: `raw` is the non-null handle just opened and owned here.
            let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) };
            // SAFETY: the handle is live and has terminate access.
            let ok = unsafe {
                TerminateProcess(std::os::windows::io::AsRawHandle::as_raw_handle(&handle), 1)
            };
            assert_ne!(ok, 0, "terminate the detached process");
        }
        assert_eq!(
            os().wait_exit(&id, LIMIT).unwrap(),
            WaitOutcome::Exited,
            "the detached process did not end"
        );
    }

    use std::os::windows::io::FromRawHandle as _;

    fn process_suite(_: &Path) {
        lunepack_testkit::run_process_suite(&os(), &helper());
    }

    /// A pid whose start time is not the process's own is another process behind a reused pid: it
    /// is not waited on, whatever the process with that pid is doing.
    fn reused_pid(scratch: &Path) {
        let file = scratch.join("id");
        let _sleeper = std_helper(&helper(), &["pid-sleep", &file.to_string_lossy(), "600"]);
        let id = read_pid_file(&file);
        let started = Instant::now();
        assert_eq!(
            os().wait_exit(&id, Duration::from_millis(200)).unwrap(),
            WaitOutcome::TimedOut,
            "control: the real id is a running process"
        );
        assert!(started.elapsed() >= Duration::from_millis(150));
        for start_ticks in [id.start_ticks + 1, id.start_ticks - 1, 0, u64::MAX] {
            let started = Instant::now();
            let reused = ProcessId {
                pid: id.pid,
                start_ticks,
            };
            assert_eq!(
                os().wait_exit(&reused, Duration::from_secs(30)).unwrap(),
                WaitOutcome::Exited,
                "start {start_ticks}"
            );
            assert!(started.elapsed() < Duration::from_secs(5), "{start_ticks}");
        }
        assert_eq!(os().process_id(id.pid).unwrap(), Some(id));
    }

    /// The wait is on the process handle: it returns when the process ends, long before its
    /// timeout, and not before it ends.
    fn wait_wakes(_: &Path) {
        let mut child = std_helper(&helper(), &["sleep", "2"]);
        let id = os().process_id(child.0.id()).unwrap().expect("running");
        let started = Instant::now();
        assert_eq!(
            os().wait_exit(&id, Duration::from_secs(60)).unwrap(),
            WaitOutcome::Exited
        );
        let took = started.elapsed();
        assert!(took >= Duration::from_secs(1), "{took:?}");
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!(child.0.wait().unwrap().code(), Some(0));
    }

    fn parent_is_spawner(scratch: &Path) {
        let file = scratch.join("parent");
        let mut child = os()
            .spawn_child(&spec(
                &helper(),
                &["parent-report", &file.to_string_lossy(), "0"],
            ))
            .expect("spawn_child");
        let got = read_pid_file(&file);
        assert_eq!(
            got,
            os().current().unwrap(),
            "a child's parent is this process"
        );
        wait_exit_child(child.as_mut());
        // The same process, asked for its own parent: the test runner's, older than this one.
        if let Some(parent) = os().parent().unwrap() {
            assert!(parent.start_ticks <= os().current().unwrap().start_ticks);
            assert_ne!(parent.pid, std::process::id());
        }
    }

    /// A parent that has ended is no parent: the pid may be reused, and nothing is left to wait for.
    fn parent_gone(scratch: &Path) {
        let file = scratch.join("orphan");
        let mut spec = spec(&helper(), &["detach-then", "exit", "parent-report"]);
        spec.args.push(file.clone().into_os_string());
        spec.args.push("2".into());
        let mut first = os().spawn_child(&spec).expect("spawn_child");
        wait_exit_child(first.as_mut());
        drop(first);
        assert_eq!(wait_for_file(&file), "none\n", "the parent had ended");
    }

    fn wait_exit_child(child: &mut dyn lunepack_core::Child) {
        let deadline = Instant::now() + LIMIT;
        while child.try_wait().expect("try_wait").is_none() {
            assert!(Instant::now() < deadline, "the child did not end");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn spec(program: &Path, args: &[&str]) -> SpawnSpec {
        let mut spec = SpawnSpec::new(program);
        spec.args = args.iter().map(Into::into).collect();
        spec
    }

    /// A detached program survives the end of the process that started it, and has no parent to
    /// wait for once that has ended.
    fn detached_outlives(scratch: &Path) {
        let file = scratch.join("grandchild");
        let mut starter = spec(&helper(), &["detach-then", "exit", "pid-sleep"]);
        starter.args.push(file.clone().into_os_string());
        starter.args.push("30".into());
        let mut first = os().spawn_child(&starter).expect("spawn_child");
        wait_exit_child(first.as_mut());
        let id = read_pid_file(&file);
        assert_eq!(
            os().process_id(id.pid).unwrap(),
            Some(id),
            "the detached child outlives its starter"
        );
        assert_eq!(
            os().wait_exit(&id, Duration::from_millis(200)).unwrap(),
            WaitOutcome::TimedOut
        );
        kill_detached(id);
    }

    /// Inside a job that forbids breakaway, `CREATE_BREAKAWAY_FROM_JOB` fails (the control), and
    /// `spawn_detached` retries without it and still starts the program.
    fn detached_in_job(scratch: &Path) {
        let (control, file) = (scratch.join("control"), scratch.join("done"));
        let mut job_helper = os()
            .spawn_child(&spec(
                &helper(),
                &[
                    "in-job",
                    &control.to_string_lossy(),
                    &file.to_string_lossy(),
                ],
            ))
            .expect("spawn_child");
        assert_eq!(
            wait_for_file(&control),
            "denied\n",
            "INVALID: the job did not forbid breakaway, so the fallback was not exercised"
        );
        assert_eq!(wait_for_file(&file), "done");
        wait_exit_child(job_helper.as_mut());
    }

    /// A child with a window is asked to close first and ends on its own, well inside the grace
    /// period, with exit code 0 (not the forced 1).
    fn terminate_asks(scratch: &Path) {
        let ready = scratch.join("window-ready");
        let mut child = os()
            .spawn_child(&spec(&helper(), &["window", &ready.to_string_lossy()]))
            .expect("spawn_child");
        wait_for_file(&ready);
        let started = Instant::now();
        child.terminate(Duration::from_secs(15)).expect("terminate");
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "the close request was not honoured: {:?}",
            started.elapsed()
        );
        assert_eq!(child.try_wait().unwrap(), Some(ExitKind::Success));
    }

    fn copy_into(tree: &Path) -> PathBuf {
        std::fs::create_dir_all(tree).expect("create the tree");
        let copy = tree.join("app-copy.exe");
        std::fs::copy(helper(), &copy).expect("copy the helper into the tree");
        copy
    }

    fn in_use_copied_exe(scratch: &Path) {
        let tree = scratch.join("Tree Dir");
        let sibling = scratch.join("Tree Dir 2");
        let other = scratch.join("other");
        std::fs::create_dir(&sibling).unwrap();
        std::fs::create_dir(&other).unwrap();
        let copy = copy_into(&tree);
        assert!(
            !os().tree_in_use(&tree, &[]).unwrap(),
            "control: nothing runs from the tree yet"
        );
        let mut running = std_helper(&copy, &["sleep", "600"]);
        let id = os().process_id(running.0.id()).unwrap().expect("running");
        assert!(os().tree_in_use(&tree, &[]).unwrap(), "a copy runs from it");
        // The same directory in other spellings: another case, a trailing separator, a `.`.
        let upper = PathBuf::from(tree.to_string_lossy().to_uppercase());
        assert!(os().tree_in_use(&upper, &[]).unwrap(), "upper case");
        let lower = PathBuf::from(tree.to_string_lossy().to_lowercase());
        assert!(os().tree_in_use(&lower, &[]).unwrap(), "lower case");
        assert!(os().tree_in_use(&tree.join("."), &[]).unwrap(), "dot");
        // A parent directory contains it too; a sibling whose name starts the same does not.
        assert!(os().tree_in_use(scratch, &[]).unwrap(), "the parent");
        assert!(
            !os().tree_in_use(&sibling, &[]).unwrap(),
            "a sibling sharing a name prefix"
        );
        assert!(!os().tree_in_use(&other, &[]).unwrap(), "another directory");
        // Exclusion is by the whole id: a reused pid is another process.
        assert!(!os().tree_in_use(&tree, &[id]).unwrap(), "excluded");
        let wrong = ProcessId {
            pid: id.pid,
            start_ticks: id.start_ticks + 1,
        };
        assert!(
            os().tree_in_use(&tree, &[wrong]).unwrap(),
            "a different start time does not exclude"
        );
        // Ended: not in use, although the std handle to the ended process is still open.
        running.0.kill().unwrap();
        running.0.wait().unwrap();
        assert!(!os().tree_in_use(&tree, &[]).unwrap(), "the copy ended");
    }

    /// The tree named by its 8.3 short name is the same tree. (A volume without short names has
    /// nothing to test: the case says so and passes.)
    #[allow(unsafe_code)]
    fn in_use_short_name(scratch: &Path) {
        let tree = scratch.join("A Long Tree Directory Name");
        let copy = copy_into(&tree);
        let wide: Vec<u16> = tree.as_os_str().encode_wide().chain([0]).collect();
        let mut buf = vec![0u16; 1024];
        // SAFETY: `wide` is NUL-terminated and lives for the call; `buf` has the length stated.
        let n = unsafe { GetShortPathNameW(wide.as_ptr(), buf.as_mut_ptr(), 1024) } as usize;
        let short = PathBuf::from(std::ffi::OsString::from(String::from_utf16_lossy(
            &buf[..n],
        )));
        if n == 0 || short.file_name() == tree.file_name() {
            println!("  (no short names on this volume: nothing to test)");
            return;
        }
        let running = std_helper(&copy, &["sleep", "600"]);
        assert!(
            os().tree_in_use(&short, &[]).unwrap(),
            "the short name of the tree"
        );
        drop(running);
    }

    /// A process started after a piped child holds none of the child's pipe ends: the child sees
    /// the end of its input as soon as the parent drops its end, though the sibling still runs.
    fn sibling_holds_no_pipe(scratch: &Path) {
        let mut cat = os()
            .spawn_child(&{
                let mut s = spec(&helper(), &["cat"]);
                s.stdio = ChildStdio::Piped;
                s
            })
            .expect("spawn a piped child");
        let stdin = cat.take_stdin().expect("input");
        let ready = scratch.join("sibling");
        os().spawn_detached(&spec(
            &helper(),
            &[
                "detach-then",
                "exit",
                "pid-sleep",
                &ready.to_string_lossy(),
                "30",
            ],
        ))
        .expect("a sibling");
        let sibling = read_pid_file(&ready);
        let tail = std::thread::spawn(move || {
            drop(stdin);
        });
        tail.join().unwrap();
        let deadline = Instant::now() + LIMIT;
        while cat.try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "cat never saw its input end: a sibling holds the pipe"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        kill_detached(sibling);
    }
}
