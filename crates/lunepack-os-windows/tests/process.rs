//! `WindowsProcess` with real processes: the testkit's process suite plus the Windows cases (a
//! reused pid is not waited on, a wait wakes at once when the process ends, the parent's identity,
//! a detached child that outlives its parent and one started inside a job that forbids breakaway,
//! a polite close request, the in-use scan for a copied executable, case, short names and a
//! sibling folder sharing a prefix, and the premises of the strict in-use check M10-D20 rests on). Own `main` (see Cargo.toml): this binary is also the helper
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
    use std::io::Read as _;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::os::windows::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use lunepack_core::{ChildStdio, ExitKind, Process, ProcessId, SpawnSpec, WaitOutcome};
    use lunepack_os_windows::WindowsProcess;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetShortPathNameW,
    };
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
        (
            "a_detached_child_does_not_hold_the_parents_pipe",
            detached_not_on_parent_pipe,
        ),
        (
            "strict_a_running_exe_in_the_tree_is_in_use",
            strict_running_exe,
        ),
        (
            "strict_a_dll_loaded_by_an_outside_process_is_in_use",
            strict_loaded_dll,
        ),
        (
            "strict_a_working_directory_in_the_tree_is_in_use",
            strict_working_directory,
        ),
        (
            "strict_a_file_held_without_delete_sharing_is_in_use",
            strict_held_file,
        ),
        ("strict_a_read_only_file_is_in_use", strict_read_only),
        (
            "strict_a_junction_is_not_followed",
            strict_junction_not_followed,
        ),
        (
            "strict_changes_nothing_and_a_missing_tree_is_an_error",
            strict_changes_nothing,
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

    // ---- the premises of `tree_in_use_strict` (M10-D20) ---------------------------------------
    //
    // Each case proves a premise with a process or handle that is really there, and a control
    // after it is gone: the probe must answer `false` again, so the answer `true` came from the
    // thing under test and not from the instrument.

    fn strict(tree: &Path) -> bool {
        os().tree_in_use_strict(tree, &[])
            .expect("tree_in_use_strict")
    }

    /// The control: once what held the tree is gone, the check answers `false`. A process's image
    /// section is released as the process ends, so a short wait is allowed here and nowhere else.
    #[track_caller]
    fn strict_becomes_free(tree: &Path, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while strict(tree) {
            assert!(
                Instant::now() < deadline,
                "control: the tree is still in use after {what}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// A copy of a system executable inside `tree`, running with its input held open by the
    /// returned child.
    fn start_system_copy(tree: &Path) -> Reap {
        let exe = tree.join("cmd.exe");
        std::fs::copy(r"C:\Windows\System32\cmd.exe", &exe).expect("copy a system executable");
        Reap(
            Command::new(&exe)
                .arg("/q")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .expect("start the copy"),
        )
    }

    fn end(mut child: Reap) {
        child.0.kill().expect("kill");
        child.0.wait().expect("wait");
    }

    /// (1) A long-lived child started from a copy of a system exe inside the tree.
    fn strict_running_exe(scratch: &Path) {
        let tree = scratch.join("tree");
        std::fs::create_dir(&tree).unwrap();
        let mut child = start_system_copy(&tree);
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "INVALID: the program ended early"
        );
        assert!(strict(&tree), "a program runs from the tree");
        end(child);
        strict_becomes_free(&tree, "the program ended");
    }

    /// (2) A copy of a system DLL inside the tree, really loaded by a process whose own image is
    /// outside it: the scan cannot see it, the probe can.
    fn strict_loaded_dll(scratch: &Path) {
        let tree = scratch.join("tree");
        std::fs::create_dir(&tree).unwrap();
        let dll = tree.join("lp-premise.dll");
        std::fs::copy(r"C:\Windows\System32\version.dll", &dll).expect("copy a system library");
        assert!(!strict(&tree), "control: nothing uses the library yet");
        let ready = scratch.join("ready");
        let child = std_helper(
            &helper(),
            &[
                "load-dll",
                &dll.to_string_lossy(),
                &ready.to_string_lossy(),
                "600",
            ],
        );
        wait_for_file(&ready);
        assert!(
            !os().tree_in_use(&tree, &[]).unwrap(),
            "INVALID: the scan already sees the process, so the probe proves nothing"
        );
        assert!(strict(&tree), "a library of the tree is loaded");
        end(child);
        strict_becomes_free(&tree, "the process ended");
    }

    /// (3) A child whose image is outside the tree and whose working directory is inside it.
    fn strict_working_directory(scratch: &Path) {
        let tree = scratch.join("tree");
        let inner = tree.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        assert!(!strict(&tree), "control: nothing runs there yet");
        let child = Reap(
            Command::new(helper())
                .args(["sleep", "600"])
                .current_dir(&inner)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .expect("start the helper"),
        );
        assert!(
            !os().tree_in_use(&tree, &[]).unwrap(),
            "INVALID: the scan already sees the process, so the probe proves nothing"
        );
        assert!(strict(&tree), "a working directory lies in the tree");
        end(child);
        strict_becomes_free(&tree, "the process ended");
    }

    /// (4) A file of the tree held by another handle: share read only keeps the tree in use, full
    /// sharing does not.
    fn strict_held_file(scratch: &Path) {
        let tree = scratch.join("tree");
        std::fs::create_dir(&tree).unwrap();
        let file = tree.join("held.txt");
        std::fs::write(&file, b"x").unwrap();
        let hold = |share: u32| {
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(share)
                .open(&file)
                .expect("hold the file")
        };
        assert!(!strict(&tree), "control: nothing holds the file");
        let handle = hold(FILE_SHARE_READ);
        assert!(strict(&tree), "held with share read only");
        drop(handle);
        assert!(!strict(&tree), "control: released");
        let handle = hold(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        assert!(!strict(&tree), "held with full sharing");
        drop(handle);
    }

    /// (5) A file with the read-only attribute keeps its tree in use (fail toward keeping).
    fn strict_read_only(scratch: &Path) {
        let tree = scratch.join("tree");
        std::fs::create_dir(&tree).unwrap();
        let file = tree.join("ro.txt");
        std::fs::write(&file, b"x").unwrap();
        assert!(!strict(&tree), "control: a writable file");
        let mut perms = std::fs::metadata(&file).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&file, perms.clone()).unwrap();
        let answer = strict(&tree);
        // Windows only: clearing the attribute is the whole effect (the lint is about Unix).
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&file, perms).unwrap();
        assert!(answer, "a read-only file");
        assert!(!strict(&tree), "control: the attribute cleared");
    }

    /// (6) A junction inside the tree that points at a folder outside it, from which a child
    /// runs: the junction is opened itself, never followed.
    fn strict_junction_not_followed(scratch: &Path) {
        let tree = scratch.join("tree");
        let outside = scratch.join("outside");
        std::fs::create_dir(&tree).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let link = tree.join("link");
        let made = Command::new("cmd.exe")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .stdout(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .expect("run mklink");
        assert!(made.success(), "INVALID: the junction was not created");
        let copy = outside.join("app-copy.exe");
        std::fs::copy(helper(), &copy).unwrap();
        let child = std_helper(&copy, &["sleep", "600"]);
        assert!(
            strict(&outside),
            "control: a program runs from the folder the junction points at"
        );
        assert!(!strict(&tree), "the junction is not followed");
        end(child);
        // The junction goes first: `remove_dir_all` of the scratch must not reach the target.
        std::fs::remove_dir(&link).expect("remove the junction");
    }

    /// (7) The probe changes nothing: last-write times and attributes stay as they were. And a
    /// tree that does not exist is an error, never an answer.
    fn strict_changes_nothing(scratch: &Path) {
        let tree = scratch.join("tree");
        let inner = tree.join("a").join("b");
        std::fs::create_dir_all(&inner).unwrap();
        for file in [
            tree.join("one.txt"),
            tree.join("a").join("two.txt"),
            inner.join("three.txt"),
        ] {
            std::fs::write(file, b"data").unwrap();
        }
        let snapshot = || {
            let mut rows = Vec::new();
            let mut pending = vec![tree.clone()];
            while let Some(dir) = pending.pop() {
                for entry in std::fs::read_dir(&dir).unwrap() {
                    let path = entry.unwrap().path();
                    let meta = std::fs::symlink_metadata(&path).unwrap();
                    rows.push((
                        path.clone(),
                        meta.last_write_time(),
                        meta.file_attributes(),
                        meta.file_size(),
                    ));
                    if meta.is_dir() {
                        pending.push(path);
                    }
                }
            }
            rows.sort();
            rows
        };
        let before = snapshot();
        assert_eq!(before.len(), 5, "INVALID: the tree is not what was built");
        assert!(!strict(&tree), "nothing holds the tree");
        assert_eq!(snapshot(), before, "times, attributes and sizes unchanged");
        assert!(
            os().tree_in_use_strict(&scratch.join("missing"), &[])
                .is_err(),
            "a tree that does not exist is an error"
        );
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

    /// A program that reads another's output to its end (an app that runs `apply-and-restart`
    /// with a pipe on the runtime's output) sees the end as soon as that program exits, though
    /// the detached program it started still runs: the detached one inherits no pipe end.
    fn detached_not_on_parent_pipe(scratch: &Path) {
        let pid_file = scratch.join("pid");
        let mut parent = Reap(
            Command::new(helper())
                .args(["detach-then", "exit", "pid-sleep"])
                .arg(&pid_file)
                .arg("600")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .expect("spawn the parent"),
        );
        let mut out = parent.0.stdout.take().unwrap();
        let mut err = parent.0.stderr.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut sink = Vec::new();
            let a = out.read_to_end(&mut sink).is_ok();
            let b = err.read_to_end(&mut sink).is_ok();
            let _ = tx.send(a && b);
        });
        let started = Instant::now();
        let read = rx.recv_timeout(Duration::from_secs(10));
        let detached = read_pid_file(&pid_file);
        let took = started.elapsed();
        kill_detached(detached);
        assert_eq!(read, Ok(true), "the pipes did not reach end of file");
        assert!(took < Duration::from_secs(5), "reading took {took:?}");
        assert!(parent.0.wait().unwrap().success());
    }
}
