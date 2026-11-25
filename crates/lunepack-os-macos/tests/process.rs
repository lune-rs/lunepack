//! `MacProcess` with real processes: first the in-use premise (a tree moved by a swap is reported
//! under its new path by each of the three libproc sources), then the testkit's process suite and
//! the macOS cases (a reused pid, a zombie wait target, a detached child, the in-use scan for cwd
//! and open files, termination of a child that ignores SIGTERM). Own `main` (see Cargo.toml): this
//! binary is also the helper program (`helper/`), and the cases run one after another, so no case
//! sees another case's processes.

#[cfg(target_os = "macos")]
mod helper;

#[cfg(target_os = "macos")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if helper::run(&args) {
        return;
    }
    macos::run_all(&args);
}

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("lunepack-os-macos process tests: macOS only, skipped");
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io::Read;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use lunepack_core::{ExitKind, Process, ProcessId, SpawnSpec, WaitOutcome};
    use lunepack_os_macos::{MacProcess, libproc};

    type TestFn = fn(&Path);

    const TESTS: &[(&str, TestFn)] = &[
        // P5: these three come first. If any fails, GC and uninstall cannot trust the scan.
        (
            "a_swapped_tree_is_reported_under_its_new_path_by_the_exe_path",
            swap_exe_path,
        ),
        (
            "a_swapped_tree_is_reported_under_its_new_path_by_the_cwd",
            swap_cwd,
        ),
        (
            "a_swapped_tree_is_reported_under_its_new_path_by_the_open_files",
            swap_fds,
        ),
        (
            "an_instance_moved_by_a_swap_is_in_use_for_its_new_tree",
            swap_in_use,
        ),
        ("the_process_suite_passes", process_suite),
        ("an_id_carries_the_start_time_of_the_process", id_start_time),
        ("a_reused_pid_counts_as_exited", reused_pid),
        (
            "an_unreaped_zombie_counts_as_exited_and_holds_nothing",
            zombie_target,
        ),
        ("wait_exit_wakes_when_a_non_child_ends", wait_wakes_on_exit),
        (
            "a_detached_child_survives_a_hangup_of_the_parents_group",
            detached_survives_hangup,
        ),
        (
            "a_detached_child_does_not_hold_the_parents_pipe",
            detached_not_on_parent_pipe,
        ),
        ("a_process_with_its_cwd_in_the_tree_uses_it", in_use_cwd),
        ("a_process_with_an_open_file_in_the_tree_uses_it", in_use_fd),
        (
            "the_tree_is_matched_as_the_kernel_names_it",
            in_use_kernel_name,
        ),
        (
            "the_scan_names_its_tree_without_opening_it",
            tree_named_unopened,
        ),
        (
            "terminate_kills_a_child_that_ignores_sigterm",
            terminate_stubborn,
        ),
        // M8-D13: the background start through LaunchServices.
        (
            "a_background_app_is_identified_and_gets_the_token_by_its_environment_only",
            background_identified,
        ),
        ("a_background_app_gets_its_arguments", background_arguments),
        ("terminate_ends_a_background_app", background_terminate),
        (
            "a_background_start_of_a_missing_or_broken_bundle_fails",
            background_missing,
        ),
        (
            "an_info_plist_naming_another_executable_falls_back_to_a_child_start",
            background_fallback,
        ),
        (
            "a_running_instance_is_never_identified_as_the_new_one",
            background_second_instance,
        ),
        // M8-D19 (a): a process whose executable was deleted.
        (
            "deleted_exe_judged_by_cwd_and_files",
            deleted_exe_judged_by_cwd_and_files,
        ),
        (
            "deleted_exe_holding_a_file_in_the_tree",
            deleted_exe_holding_a_file_in_the_tree,
        ),
        // M8-D19 (b): last, alone, so its churn reaches no other case.
        ("churn_never_counts", churn_never_counts),
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
            static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _ = name;
            let dir =
                std::env::temp_dir().join(format!("lunepack-os-macos-{}-{n}", std::process::id()));
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
        std::fs::canonicalize(std::env::current_exe().expect("current_exe")).expect("canonicalize")
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

    #[allow(unsafe_code)]
    fn swap(a: &Path, b: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let ca = std::ffi::CString::new(a.as_os_str().as_bytes()).unwrap();
        let cb = std::ffi::CString::new(b.as_os_str().as_bytes()).unwrap();
        // SAFETY: both pointers are valid NUL-terminated strings that outlive the call.
        let rc = unsafe { libc::renamex_np(ca.as_ptr(), cb.as_ptr(), libc::RENAME_SWAP) };
        assert_eq!(rc, 0, "renamex_np: {}", std::io::Error::last_os_error());
    }

    /// A helper started from directory `a` with its working directory there and one file of `a`
    /// open, then `a` swapped with `b` (a second directory holding other content). Returns the
    /// scratch's two paths and the child.
    struct Swapped {
        a: PathBuf,
        b: PathBuf,
        pid: u32,
        _child: Reap,
    }

    fn start_and_swap(scratch: &Path) -> Swapped {
        let a = scratch.join("a");
        let b = scratch.join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        std::fs::write(a.join("data"), b"x").unwrap();
        std::fs::write(b.join("other"), b"y").unwrap();
        std::fs::copy(helper(), a.join("helper")).expect("copy the helper");
        let ready = scratch.join("ready");
        let child = Reap(
            Command::new(a.join("helper"))
                .arg("hold")
                .arg(a.join("data"))
                .arg(&ready)
                .arg("600")
                .current_dir(&a)
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn the helper"),
        );
        wait_for_file(&ready);
        let pid = child.0.id();
        // The instruments, before the swap: each source finds the process in `a`, so a source
        // that answered nothing would be caught here and not read as "not under a".
        assert_eq!(libproc::exe_path(pid).unwrap(), Some(a.join("helper")));
        assert_eq!(libproc::cwd_path(pid).unwrap(), Some(a.clone()));
        assert!(libproc::fd_paths(pid).unwrap().contains(&a.join("data")));
        swap(&a, &b);
        Swapped {
            a,
            b,
            pid,
            _child: child,
        }
    }

    fn swap_exe_path(scratch: &Path) {
        let s = start_and_swap(scratch);
        let exe = libproc::exe_path(s.pid).unwrap().expect("an exe path");
        assert_eq!(
            exe,
            s.b.join("helper"),
            "in use premise failed (exe path): {exe:?} is not under the tree's new path"
        );
        assert!(!exe.starts_with(&s.a));
    }

    fn swap_cwd(scratch: &Path) {
        let s = start_and_swap(scratch);
        let cwd = libproc::cwd_path(s.pid).unwrap().expect("a cwd");
        assert_eq!(
            cwd, s.b,
            "in use premise failed (cwd): {cwd:?} is not the tree's new path"
        );
    }

    fn swap_fds(scratch: &Path) {
        let s = start_and_swap(scratch);
        let fds = libproc::fd_paths(s.pid).unwrap();
        assert!(
            fds.contains(&s.b.join("data")),
            "in use premise failed (open files): {fds:?} lacks the file under the new path"
        );
        assert!(
            !fds.iter().any(|p| p.starts_with(&s.a)),
            "in use premise failed (open files): a path is still under the old path"
        );
    }

    fn os() -> MacProcess {
        MacProcess::new()
    }

    fn spec(program: &Path, args: &[&str]) -> SpawnSpec {
        let mut spec = SpawnSpec::new(program);
        spec.args = args.iter().map(Into::into).collect();
        spec
    }

    fn id_of(pid: u32) -> ProcessId {
        os().process_id(pid)
            .expect("process_id")
            .expect("the process runs")
    }

    #[allow(unsafe_code)]
    fn send(pid: i32, signal: i32) {
        // SAFETY: kill(2) takes two integers and touches no memory. Callers pass a pid (or a
        // negated process group id) of a process this test started and has just checked.
        let rc = unsafe { libc::kill(pid, signal) };
        assert_eq!(rc, 0, "kill({pid}, {signal})");
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
    fn kill_detached(id: ProcessId) {
        if os().process_id(id.pid).unwrap() == Some(id) {
            send(i32::try_from(id.pid).unwrap(), libc::SIGKILL);
        }
        assert_eq!(
            os().wait_exit(&id, LIMIT).unwrap(),
            WaitOutcome::Exited,
            "the detached process did not end"
        );
    }

    fn swap_in_use(scratch: &Path) {
        let s = start_and_swap(scratch);
        // The instance runs from the tree that now sits at `b`, not from the one now at `a`.
        assert!(os().tree_in_use(&s.b, &[]).unwrap(), "the new path");
        assert!(!os().tree_in_use(&s.a, &[]).unwrap(), "the old path");
        let id = id_of(s.pid);
        assert!(!os().tree_in_use(&s.b, &[id]).unwrap(), "excluded");
    }

    fn process_suite(_: &Path) {
        lunepack_testkit::run_process_suite(&os(), &helper());
    }

    fn id_start_time(_: &Path) {
        let me = os().current().unwrap();
        assert_eq!(me.pid, std::process::id());
        // The start time is in microseconds since the epoch: a recent moment, in the past.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        assert!(me.start_ticks <= now, "starts in the future");
        assert!(
            now - me.start_ticks < 24 * 3600 * 1_000_000,
            "over a day old"
        );
        assert_eq!(os().current().unwrap(), me, "stable");
        let parent = os().parent().unwrap().expect("a parent");
        assert_eq!(
            parent.pid,
            std::os::unix::process::parent_id(),
            "the parent's pid"
        );
        assert!(parent.start_ticks <= me.start_ticks);
    }

    fn reused_pid(_: &Path) {
        let me = os().current().unwrap();
        for start_ticks in [me.start_ticks + 1, me.start_ticks.wrapping_sub(1), 0] {
            let other = ProcessId {
                pid: me.pid,
                start_ticks,
            };
            let started = Instant::now();
            assert_eq!(
                os().wait_exit(&other, Duration::from_secs(30)).unwrap(),
                WaitOutcome::Exited,
                "a pid with another start time"
            );
            assert!(
                started.elapsed() < Duration::from_millis(500),
                "not at once"
            );
        }
        assert_eq!(
            os().wait_exit(&me, Duration::from_millis(150)).unwrap(),
            WaitOutcome::TimedOut,
            "the real id of a running process"
        );
    }

    /// The process state letters `ps` shows for `pid` (`Z` for a zombie); empty when it is gone.
    fn ps_state(pid: u32) -> String {
        let out = Command::new("/bin/ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .expect("ps");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    fn zombie_target(scratch: &Path) {
        let tree = scratch.join("tree");
        std::fs::create_dir(&tree).unwrap();
        // Started with std and not waited for until the end: it ends after a moment and then
        // stays a zombie.
        let child = Reap(
            Command::new(helper())
                .args(["sleep", "1"])
                .current_dir(&tree)
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn"),
        );
        let pid = child.0.id();
        let id = id_of(pid);
        assert!(os().tree_in_use(&tree, &[]).unwrap(), "while it runs");
        let deadline = Instant::now() + LIMIT;
        while !ps_state(pid).starts_with('Z') {
            assert!(
                Instant::now() < deadline,
                "the child did not become a zombie"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let started = Instant::now();
        assert_eq!(
            os().wait_exit(&id, Duration::from_secs(30)).unwrap(),
            WaitOutcome::Exited,
            "a zombie"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "wait_exit on a zombie took {:?}",
            started.elapsed()
        );
        assert_eq!(os().process_id(pid).unwrap(), None, "a zombie has no id");
        assert!(
            !os().tree_in_use(&tree, &[]).unwrap(),
            "a zombie whose cwd was the tree holds nothing"
        );
        // Still a zombie: the answers above were about an unreaped process.
        assert!(ps_state(pid).starts_with('Z'));
    }

    /// The kqueue watch wakes when a process that is not our child ends, long before the
    /// slice that makes it look again.
    fn wait_wakes_on_exit(scratch: &Path) {
        let pid_file = scratch.join("pid");
        let _parent = Reap(
            Command::new(helper())
                .args(["detach-then", "exit", "pid-sleep"])
                .arg(&pid_file)
                .arg("2")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
                .expect("spawn the parent"),
        );
        let detached = read_pid_file(&pid_file);
        let started = Instant::now();
        assert_eq!(
            os().wait_exit(&detached, Duration::from_secs(30)).unwrap(),
            WaitOutcome::Exited
        );
        let took = started.elapsed();
        assert!(took < Duration::from_secs(5), "took {took:?}");
        assert_eq!(os().process_id(detached.pid).unwrap(), None);
    }

    fn detached_survives_hangup(scratch: &Path) {
        let pid_file = scratch.join("pid");
        let mut parent = Reap(
            Command::new(helper())
                .args(["detach-then", "sleep", "pid-sleep"])
                .arg(&pid_file)
                .arg("600")
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
                .expect("spawn the parent"),
        );
        let detached = read_pid_file(&pid_file);
        let group = i32::try_from(parent.0.id()).unwrap();
        send(-group, libc::SIGHUP);
        let status = parent.0.wait().unwrap();
        assert_eq!(
            status.signal(),
            Some(libc::SIGHUP),
            "the parent got the hangup"
        );
        assert_eq!(
            os().wait_exit(&detached, Duration::from_millis(500))
                .unwrap(),
            WaitOutcome::TimedOut,
            "the detached child died with its parent's group"
        );
        kill_detached(detached);
    }

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

    fn in_use_cwd(scratch: &Path) {
        let tree = scratch.join("tree");
        std::fs::create_dir(&tree).unwrap();
        let mut child = Reap(
            Command::new(helper())
                .args(["sleep", "600"])
                .current_dir(&tree)
                .spawn()
                .unwrap(),
        );
        // The process exists once spawn returns; its cwd was set before exec.
        assert!(os().tree_in_use(&tree, &[]).unwrap(), "cwd in the tree");
        let id = id_of(child.0.id());
        assert!(!os().tree_in_use(&tree, &[id]).unwrap(), "excluded");
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(!os().tree_in_use(&tree, &[]).unwrap(), "after the exit");
    }

    fn in_use_fd(scratch: &Path) {
        let tree = scratch.join("tree");
        let other = scratch.join("other");
        std::fs::create_dir(&tree).unwrap();
        std::fs::create_dir(&other).unwrap();
        let file = tree.join("data");
        std::fs::write(&file, b"x").unwrap();
        let ready = scratch.join("ready");
        assert!(!os().tree_in_use(&tree, &[]).unwrap(), "before");
        let mut child = Reap(
            Command::new(helper())
                .arg("hold")
                .arg(&file)
                .arg(&ready)
                .arg("600")
                .current_dir(&other)
                .spawn()
                .unwrap(),
        );
        wait_for_file(&ready);
        assert!(
            os().tree_in_use(&tree, &[]).unwrap(),
            "an open file in the tree"
        );
        assert!(os().tree_in_use(&other, &[]).unwrap(), "the holder's cwd");
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(!os().tree_in_use(&tree, &[]).unwrap(), "after the exit");
    }

    /// The tree is asked for with a path spelled in another case (the default volume is case
    /// insensitive) and through a symlink: the answer is the same as for its own name.
    fn in_use_kernel_name(scratch: &Path) {
        let tree = scratch.join("Tree");
        std::fs::create_dir(&tree).unwrap();
        let _child = Reap(
            Command::new(helper())
                .args(["sleep", "600"])
                .current_dir(&tree)
                .spawn()
                .unwrap(),
        );
        let link = scratch.join("link");
        std::os::unix::fs::symlink(&tree, &link).unwrap();
        assert!(os().tree_in_use(&link, &[]).unwrap(), "through a symlink");
        let upper = scratch.join("TREE");
        if upper.exists() {
            assert!(
                os().tree_in_use(&upper, &[]).unwrap(),
                "the same directory spelled in another case"
            );
        } else {
            println!("note: the volume is case sensitive; the case spelling was not tested");
        }
    }

    /// The scan names its tree without a descriptor on it (M13 step 5): one it opened, even for an
    /// instant, is copied into a child another thread forks meanwhile and held there until the
    /// child's exec, and a scan that reaches the child first counts an unused tree in use. A tree
    /// this user may not open (mode 000) shows it: `kernel_path`, which opens, is refused, while
    /// the scan's name for it is the same path and the scan answers.
    fn tree_named_unopened(scratch: &Path) {
        let tree = scratch.join("Tree");
        std::fs::create_dir(&tree).unwrap();
        let opened = libproc::kernel_path(&tree).unwrap();
        assert_eq!(libproc::kernel_path_unopened(&tree).unwrap(), opened);
        let upper = scratch.join("TREE");
        if upper.exists() {
            assert_eq!(
                libproc::kernel_path_unopened(&upper).unwrap(),
                opened,
                "the same directory spelled in another case"
            );
        }
        let file = tree.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(
            libproc::kernel_path_unopened(&file).unwrap(),
            libproc::kernel_path(&file).unwrap()
        );
        assert_eq!(
            libproc::kernel_path_unopened(&scratch.join("missing"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tree, std::fs::Permissions::from_mode(0o000)).unwrap();
        let open = libproc::kernel_path(&tree).map(|_| ());
        let unopened = libproc::kernel_path_unopened(&tree);
        let in_use = os().tree_in_use(&tree, &[]);
        // Restored before any assertion, so the scratch can be removed.
        std::fs::set_permissions(&tree, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            open.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied,
            "the control: opening the tree is refused"
        );
        assert_eq!(unopened.unwrap(), opened);
        assert!(!in_use.unwrap(), "a tree nobody uses");
    }

    /// A copy of the helper at `<scratch>/exe/helper`, started with `args` in `cwd`, then deleted
    /// once it runs (`ready` exists: deleted any earlier, the copy is killed by the system as it
    /// pages its code in). Returns the copy's directory and the child.
    fn start_then_delete_exe(
        scratch: &Path,
        cwd: &Path,
        ready: &Path,
        args: &[&std::ffi::OsStr],
    ) -> (PathBuf, Reap) {
        let exe_dir = scratch.join("exe");
        std::fs::create_dir(&exe_dir).unwrap();
        let exe = exe_dir.join("helper");
        std::fs::copy(helper(), &exe).expect("copy the helper");
        let child = Reap(
            Command::new(&exe)
                .args(args)
                .current_dir(cwd)
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn the copy"),
        );
        let pid = child.0.id();
        wait_for_file(ready);
        // The instrument, before the delete: the executable path names the copy.
        assert_eq!(libproc::exe_path(pid).unwrap(), Some(exe.clone()));
        std::fs::remove_file(&exe).expect("delete the copy");
        // And after: the kernel has no path for it any more (ENOENT, M8-D19 (a)).
        let err = libproc::exe_path(pid).expect_err("a deleted executable has no path");
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT), "{err}");
        (exe_dir, child)
    }

    /// M8-D19 (a): a process in `sleep` (`pid-sleep`, which says when it runs) whose executable
    /// was deleted is judged by its working directory and open files.
    fn deleted_exe_judged_by_cwd_and_files(scratch: &Path) {
        let tree = scratch.join("tree");
        let cwd = scratch.join("cwd");
        std::fs::create_dir(&tree).unwrap();
        std::fs::create_dir(&cwd).unwrap();
        let ready = scratch.join("ready");
        let (exe_dir, _child) = start_then_delete_exe(
            scratch,
            &cwd,
            &ready,
            &["pid-sleep".as_ref(), ready.as_os_str(), "600".as_ref()],
        );
        assert!(
            !os().tree_in_use(&tree, &[]).unwrap(),
            "a deleted executable counted for an unrelated tree"
        );
        assert!(
            os().tree_in_use(&cwd, &[]).unwrap(),
            "its working directory"
        );
        assert!(
            !os().tree_in_use(&exe_dir, &[]).unwrap(),
            "the deleted executable's old directory"
        );
    }

    fn deleted_exe_holding_a_file_in_the_tree(scratch: &Path) {
        let tree = scratch.join("tree");
        let cwd = scratch.join("cwd");
        std::fs::create_dir(&tree).unwrap();
        std::fs::create_dir(&cwd).unwrap();
        let ready = scratch.join("ready");
        let held = tree.join("held");
        std::fs::write(&held, b"x").unwrap();
        let (_exe_dir, _child) = start_then_delete_exe(
            scratch,
            &cwd,
            &ready,
            &[
                "hold".as_ref(),
                held.as_os_str(),
                ready.as_os_str(),
                "600".as_ref(),
            ],
        );
        assert!(
            os().tree_in_use(&tree, &[]).unwrap(),
            "an open file in the tree"
        );
    }

    /// M8-D19 (b): processes of this user that start and end all through the scans never count
    /// for a tree nobody uses.
    fn churn_never_counts(scratch: &Path) {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        const SCANS: usize = 2_000;
        const THREADS: usize = 4;
        let tree = scratch.join("tree");
        std::fs::create_dir(&tree).unwrap();
        let stop = AtomicBool::new(false);
        let started = AtomicU64::new(0);
        let mut positives = 0;
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    while !stop.load(Ordering::Relaxed) {
                        let status = Command::new("/usr/bin/true")
                            .stdin(Stdio::null())
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .status()
                            .expect("start /usr/bin/true");
                        assert!(status.success());
                        started.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
            // The churn runs before the first scan.
            while started.load(Ordering::Relaxed) < THREADS as u64 {
                std::thread::yield_now();
            }
            for _ in 0..SCANS {
                if os().tree_in_use(&tree, &[]).unwrap() {
                    positives += 1;
                }
            }
            stop.store(true, Ordering::Relaxed);
        });
        let churned = started.load(Ordering::Relaxed);
        println!("note: {SCANS} scans, {churned} processes started meanwhile, {positives} in use");
        assert_eq!(positives, 0, "a tree nobody uses was in use");
    }

    fn terminate_stubborn(scratch: &Path) {
        let ready = scratch.join("ready");
        let mut child = os()
            .spawn_child(&spec(
                &helper(),
                &["sleep-ignore-term", "600", &ready.to_string_lossy()],
            ))
            .unwrap();
        wait_for_file(&ready);
        let started = Instant::now();
        child.terminate(Duration::from_millis(400)).unwrap();
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(400), "no grace: {took:?}");
        assert!(took < Duration::from_secs(5), "took {took:?}");
        assert_eq!(child.try_wait().unwrap(), Some(ExitKind::Signal(9)));
        assert_eq!(
            os().wait_exit(&child.id(), Duration::from_secs(5)).unwrap(),
            WaitOutcome::Exited
        );
    }

    // ---- background start (M8-D13) -------------------------------------------------------------

    const LSREGISTER: &str = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";
    const TOKEN_VAR: &str = "LUNEPACK_HEALTH_TOKEN";

    /// A temporary app bundle `<scratch>/<name>.app` whose executable `hello` is a copy of this
    /// helper (no Dock icon: `LSUIElement`). On drop every process running from it is killed and
    /// the bundle is unregistered from LaunchServices (`lsregister -u`).
    struct Bundle {
        path: PathBuf,
    }

    impl Bundle {
        fn new(scratch: &Path, name: &str, executable: &str) -> Bundle {
            static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = scratch.join(format!("{name}.app"));
            let macos = path.join("Contents/MacOS");
            std::fs::create_dir_all(&macos).unwrap();
            std::fs::copy(helper(), macos.join("hello")).expect("copy the helper");
            let plist = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>{executable}</string>
  <key>CFBundleIdentifier</key><string>dev.lunepack.test.background.p{}.n{n}</string>
  <key>CFBundleName</key><string>{name}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
"#,
                std::process::id()
            );
            std::fs::write(path.join("Contents/Info.plist"), plist).unwrap();
            Bundle { path }
        }

        fn entry(&self) -> PathBuf {
            self.path.join("Contents/MacOS/hello")
        }
    }

    /// The pids of processes whose executable lies in `bundle`.
    fn running_in(bundle: &Path) -> Vec<u32> {
        let bundle = libproc::kernel_path(bundle).unwrap_or_else(|_| bundle.to_path_buf());
        libproc::list_pids()
            .unwrap_or_default()
            .into_iter()
            .filter(|pid| {
                libproc::exe_path(*pid)
                    .ok()
                    .flatten()
                    .is_some_and(|p| p.starts_with(&bundle))
            })
            .collect()
    }

    impl Drop for Bundle {
        fn drop(&mut self) {
            for pid in running_in(&self.path) {
                let _ = Command::new("/bin/kill")
                    .args(["-9", &pid.to_string()])
                    .status();
            }
            let _ = Command::new(LSREGISTER)
                .arg("-u")
                .arg(&self.path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }

    /// Polls `child` until it is identified (its id is no longer `open`'s), within `LIMIT`.
    fn identified(child: &mut Box<dyn lunepack_core::Child>, open: ProcessId) -> ProcessId {
        let deadline = Instant::now() + LIMIT;
        loop {
            let _ = child.try_wait().unwrap();
            if child.id() != open {
                return child.id();
            }
            assert!(Instant::now() < deadline, "the app was not identified");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn exit_within(child: &mut Box<dyn lunepack_core::Child>) -> ExitKind {
        let deadline = Instant::now() + LIMIT;
        loop {
            if let Some(kind) = child.try_wait().unwrap() {
                return kind;
            }
            assert!(Instant::now() < deadline, "no exit seen");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn token() -> String {
        format!(
            "{:064x}",
            u128::from(std::process::id()) * 0x1234_5678_9abc_def1
        )
    }

    fn background_identified(scratch: &Path) {
        let bundle = Bundle::new(scratch, "Back", "hello");
        let out = scratch.join("env");
        let secret = token();
        let mut spec = spec(
            &bundle.entry(),
            &["env-sleep", &out.to_string_lossy(), "600", TOKEN_VAR],
        );
        spec.env_remove.push(TOKEN_VAR.into());
        spec.env_set.push((TOKEN_VAR.into(), secret.clone().into()));
        let mut child = os().spawn_app_background(&spec).expect("background start");
        let open = child.id();
        let app = identified(&mut child, open);
        // The app is a process of the entry, and not `open`.
        let exe = libproc::exe_path(app.pid).unwrap().expect("exe");
        assert_eq!(exe, libproc::kernel_path(&bundle.entry()).unwrap());
        assert_eq!(
            wait_for_file(&out),
            format!("{TOKEN_VAR}={secret}\n"),
            "the token reached the app"
        );
        // No command line of any process carries it (`open`'s included).
        let ps = Command::new("/bin/ps")
            .args(["-axww", "-o", "args="])
            .output()
            .expect("ps");
        let all = String::from_utf8_lossy(&ps.stdout);
        assert!(
            all.contains("/usr/bin/open -g -n -W"),
            "open was seen running"
        );
        assert!(!all.contains(&secret), "the token is on a command line");
        assert_eq!(child.try_wait().unwrap(), None, "still running");
        child.terminate(Duration::from_secs(5)).unwrap();
        assert_eq!(child.try_wait().unwrap(), Some(ExitKind::Unknown));
        assert!(running_in(&bundle.path).is_empty(), "the app is gone");
    }

    fn background_arguments(scratch: &Path) {
        let bundle = Bundle::new(scratch, "Args", "hello");
        let out = scratch.join("args");
        let mut child = os()
            .spawn_app_background(&spec(
                &bundle.entry(),
                &[
                    "args",
                    &out.to_string_lossy(),
                    "one",
                    "two words",
                    "--three",
                ],
            ))
            .expect("background start");
        assert_eq!(wait_for_file(&out), "one\ntwo words\n--three\n");
        assert_eq!(exit_within(&mut child), ExitKind::Unknown);
    }

    fn background_terminate(scratch: &Path) {
        let bundle = Bundle::new(scratch, "Stop", "hello");
        let out = scratch.join("pid");
        let mut child = os()
            .spawn_app_background(&spec(
                &bundle.entry(),
                &["pid-sleep", &out.to_string_lossy(), "600"],
            ))
            .expect("background start");
        let open = child.id();
        let app = identified(&mut child, open);
        let written = wait_for_file(&out);
        assert_eq!(
            written.split_whitespace().next(),
            Some(app.pid.to_string().as_str())
        );
        let started = Instant::now();
        child.terminate(Duration::from_secs(5)).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "SIGTERM sufficed"
        );
        assert_eq!(
            os().wait_exit(&app, Duration::from_secs(5)).unwrap(),
            WaitOutcome::Exited
        );
        assert_eq!(
            os().wait_exit(&open, Duration::from_secs(5)).unwrap(),
            WaitOutcome::Exited,
            "open is ended and reaped too"
        );
    }

    fn background_missing(scratch: &Path) {
        // No bundle at all: nothing to start (the runtime treats it as a failed launch).
        let gone = scratch.join("Gone.app/Contents/MacOS/hello");
        let got = os().spawn_app_background(&spec(&gone, &["exit", "0"]));
        assert!(got.is_err(), "a missing bundle started");
        // A bundle LaunchServices cannot start (its executable is not executable): `open` fails
        // before any app is seen, which is a failure, never an unknown exit.
        let bundle = Bundle::new(scratch, "Broken", "hello");
        std::fs::set_permissions(
            bundle.entry(),
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .unwrap();
        let mut child = os()
            .spawn_app_background(&spec(&bundle.entry(), &["exit", "0"]))
            .expect("the start itself");
        assert!(
            matches!(exit_within(&mut child), ExitKind::Failure(_)),
            "a launch that failed"
        );
    }

    fn background_fallback(scratch: &Path) {
        let bundle = Bundle::new(scratch, "Other", "something-else");
        let mut child = os()
            .spawn_app_background(&spec(&bundle.entry(), &["exit", "7"]))
            .expect("start");
        // A child start: the exit status is observable.
        assert_eq!(exit_within(&mut child), ExitKind::Failure(7));
    }

    fn background_second_instance(scratch: &Path) {
        let bundle = Bundle::new(scratch, "Twice", "hello");
        let first_ready = scratch.join("first");
        let first = Reap(
            Command::new(bundle.entry())
                .args(["pid-sleep", &first_ready.to_string_lossy(), "600"])
                .stdin(Stdio::null())
                .spawn()
                .expect("the first instance"),
        );
        wait_for_file(&first_ready);
        let out = scratch.join("second");
        let mut child = os()
            .spawn_app_background(&spec(
                &bundle.entry(),
                &["pid-sleep", &out.to_string_lossy(), "600"],
            ))
            .expect("background start");
        let open = child.id();
        let app = identified(&mut child, open);
        assert_ne!(app.pid, first.0.id(), "the running instance was taken");
        let written = wait_for_file(&out);
        assert_eq!(
            written.split_whitespace().next(),
            Some(app.pid.to_string().as_str())
        );
        child.terminate(Duration::from_secs(5)).unwrap();
        // The first instance was left alone.
        assert!(running_in(&bundle.path).contains(&first.0.id()));
    }
}
