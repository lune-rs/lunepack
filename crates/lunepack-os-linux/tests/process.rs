//! `LinuxProcess` with real processes: the testkit's process suite plus the Linux cases (a comm
//! with parentheses, a reused pid, a zombie wait target, a detached child and hangups and pipes,
//! the in-use scan for cwd, open files and shell scripts, and termination of a child that ignores
//! SIGTERM). Own `main` (see Cargo.toml): this binary is also the helper program (`helper/`), and
//! the cases run one after another, so no case sees another case's processes.
//!
//! Run in the gate's container too, where cargo is pid 1 and reaps nothing: a process orphaned
//! there stays a zombie, which the liveness rule counts as exited.

#[cfg(target_os = "linux")]
mod helper;

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if helper::run(&args) {
        return;
    }
    linux::run_all(&args);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("lunepack-os-linux process tests: Linux only, skipped");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Read;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use lunepack_core::{ExitKind, Process, ProcessId, SpawnSpec, WaitOutcome};
    use lunepack_os_linux::LinuxProcess;

    use crate::helper::stat_fields;

    type TestFn = fn(&Path);

    const TESTS: &[(&str, TestFn)] = &[
        ("the_process_suite_passes", process_suite),
        ("a_comm_with_parentheses_is_parsed", comm_with_parentheses),
        ("a_reused_pid_counts_as_exited", reused_pid),
        (
            "an_unreaped_zombie_counts_as_exited_and_holds_nothing",
            zombie_target,
        ),
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
        ("a_shell_script_from_the_tree_uses_it", in_use_scripts),
        (
            "a_process_whose_leader_exited_is_judged_by_its_live_threads",
            zombie_leader,
        ),
        (
            "a_non_dumpable_process_unrelated_to_the_tree_does_not_use_it",
            nodump_unrelated,
        ),
        (
            "a_non_dumpable_process_with_the_tree_in_its_command_line_uses_it",
            nodump_cmdline,
        ),
        (
            "terminate_kills_a_child_that_ignores_sigterm",
            terminate_stubborn,
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
            let dir = std::env::temp_dir()
                .join(format!("lunepack-os-linux-{}-{name}", std::process::id()));
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

    fn os() -> LinuxProcess {
        LinuxProcess::new()
    }

    fn spec(program: &Path, args: &[&str]) -> SpawnSpec {
        let mut spec = SpawnSpec::new(program);
        spec.args = args.iter().map(Into::into).collect();
        spec
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

    fn start_ticks(pid: u32) -> u64 {
        stat_fields(Some(pid))[22 - 3].parse().expect("start ticks")
    }

    #[allow(unsafe_code)]
    fn send(pid: i32, signal: i32) {
        // SAFETY: kill(2) takes two integers and touches no memory. Callers pass a pid (or a
        // negated process group id) of a process this test started and has just checked.
        let rc = unsafe { libc::kill(pid, signal) };
        assert_eq!(rc, 0, "kill({pid}, {signal})");
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

    fn process_suite(_: &Path) {
        lunepack_testkit::run_process_suite(&os(), &helper());
    }

    fn comm_with_parentheses(scratch: &Path) {
        let odd = scratch.join("a) (b");
        std::fs::copy(helper(), &odd).expect("copy the helper");
        let mut child = os()
            .spawn_child(&spec(&odd, &["sleep", "600"]))
            .expect("spawn");
        let id = child.id();
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", id.pid)).unwrap();
        assert!(stat.contains("(a) (b) "), "comm is not the file name");
        assert_eq!(os().process_id(id.pid).unwrap(), Some(id));
        assert_eq!(id.start_ticks, start_ticks(id.pid));
        assert_eq!(
            os().wait_exit(&id, Duration::from_millis(150)).unwrap(),
            WaitOutcome::TimedOut
        );
        child.terminate(Duration::from_secs(5)).unwrap();
        assert_eq!(
            os().wait_exit(&id, Duration::from_secs(5)).unwrap(),
            WaitOutcome::Exited
        );
    }

    fn reused_pid(_: &Path) {
        let me = os().current().unwrap();
        assert_eq!(me.start_ticks, start_ticks(me.pid));
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

    fn zombie_target(scratch: &Path) {
        let tree = scratch.join("tree");
        std::fs::create_dir(&tree).unwrap();
        // Started with std and never waited for until the end: it stays a zombie.
        let child = Reap(
            Command::new(helper())
                .args(["exit", "0"])
                .current_dir(&tree)
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn"),
        );
        let pid = child.0.id();
        let id = ProcessId {
            pid,
            start_ticks: start_ticks(pid),
        };
        let deadline = Instant::now() + LIMIT;
        while stat_fields(Some(pid))[0] != "Z" {
            assert!(
                Instant::now() < deadline,
                "the child did not become a zombie"
            );
            std::thread::sleep(Duration::from_millis(10));
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
        assert_eq!(stat_fields(Some(pid))[0], "Z");
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
        let fields = stat_fields(Some(detached.pid));
        assert_eq!(
            fields[6 - 3],
            detached.pid.to_string(),
            "not a session leader"
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
        let id = ProcessId {
            pid: child.0.id(),
            start_ticks: start_ticks(child.0.id()),
        };
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

    /// A process whose thread-group leader has ended while another thread runs: `/proc/<pid>/exe`
    /// and `cwd` are gone, so the scan reads the live thread instead (F9): its cwd in the tree is
    /// in use, an unrelated directory is not.
    fn zombie_leader(scratch: &Path) {
        let tree = scratch.join("tree");
        let other = scratch.join("other");
        std::fs::create_dir(&tree).unwrap();
        std::fs::create_dir(&other).unwrap();
        let ready = scratch.join("ready");
        let child = Reap(
            Command::new(helper())
                .arg("leader-exit")
                .arg(&ready)
                .arg("600")
                .current_dir(&tree)
                .spawn()
                .unwrap(),
        );
        wait_for_file(&ready);
        let pid = child.0.id();
        let deadline = Instant::now() + LIMIT;
        while stat_fields(Some(pid))[0] != "Z" {
            assert!(Instant::now() < deadline, "the leader did not end");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            std::fs::read_link(format!("/proc/{pid}/cwd")).is_err(),
            "the leader holds no cwd"
        );
        assert!(
            os().tree_in_use(&tree, &[]).unwrap(),
            "a live thread's cwd in the tree"
        );
        assert!(
            !os().tree_in_use(&other, &[]).unwrap(),
            "an unrelated tree is not in use"
        );
        drop(child);
        assert!(!os().tree_in_use(&tree, &[]).unwrap(), "after the exit");
    }

    fn shell(names: &[&str]) -> Option<PathBuf> {
        names.iter().map(PathBuf::from).find(|p| p.is_file())
    }

    fn in_use_scripts(scratch: &Path) {
        let tree = scratch.join("tree");
        let other = scratch.join("other");
        std::fs::create_dir(&tree).unwrap();
        std::fs::create_dir(&other).unwrap();
        let script = tree.join("app.sh");
        // printf and read are builtins: the shell itself runs it, and starts no other program.
        std::fs::write(&script, "printf x > \"$1\"\nread -r line\nexit 0\n").unwrap();
        let sh = shell(&["/bin/sh"]).expect("/bin/sh");
        let dash = shell(&["/usr/bin/dash", "/bin/dash"]).expect("dash is not installed");
        let mut shells = vec![("sh", sh), ("dash", dash)];
        if let Some(bash) = shell(&["/usr/bin/bash", "/bin/bash"]) {
            shells.push(("bash", bash));
        }
        for (name, program) in shells {
            let ready = scratch.join(format!("ready-{name}"));
            let mut child = Reap(
                Command::new(&program)
                    .arg(&script)
                    .arg(&ready)
                    .current_dir(&other)
                    .stdin(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
            wait_for_file(&ready);
            assert!(
                os().tree_in_use(&tree, &[]).unwrap(),
                "`{name} script.sh` from the tree"
            );
            drop(child.0.stdin.take());
            let status = child.0.wait().unwrap();
            assert!(status.success(), "{name}: {status:?}");
            assert!(
                !os().tree_in_use(&tree, &[]).unwrap(),
                "{name}: after the exit"
            );
        }
    }

    /// Starts `<program> nodump <ready> 600 <extra>...` and waits until it is non-dumpable.
    /// Without `CAP_SYS_PTRACE` its `exe` is then denied to this process (the gate's container
    /// and an unprivileged user); with it (root outside the gate) the case still holds, through
    /// the files, and says so.
    fn start_nodump(program: &Path, ready: &Path, extra: &[&Path], cwd: &Path) -> Reap {
        let mut command = Command::new(program);
        command.arg("nodump").arg(ready).arg("600");
        command.args(extra);
        let child = Reap(command.current_dir(cwd).spawn().expect("spawn nodump"));
        wait_for_file(ready);
        let exe = std::fs::read_link(format!("/proc/{}/exe", child.0.id()));
        match exe {
            Err(e) => assert_eq!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied,
                "the exe of a non-dumpable process: {e}"
            ),
            Ok(_) => println!("note: exe of a non-dumpable process is readable (CAP_SYS_PTRACE)"),
        }
        child
    }

    fn nodump_unrelated(scratch: &Path) {
        let tree = scratch.join("tree");
        let other = scratch.join("other");
        std::fs::create_dir(&tree).unwrap();
        std::fs::create_dir(&other).unwrap();
        let _nodump = start_nodump(&helper(), &scratch.join("ready"), &[&other], &other);
        assert!(
            !os().tree_in_use(&tree, &[]).unwrap(),
            "a non-dumpable process that has nothing to do with the tree"
        );
    }

    fn nodump_cmdline(scratch: &Path) {
        let tree = scratch.join("tree");
        let other = scratch.join("other");
        std::fs::create_dir_all(tree.join("bin")).unwrap();
        std::fs::create_dir(&other).unwrap();
        let app = tree.join("bin").join("app");
        std::fs::copy(helper(), &app).unwrap();
        let data = tree.join("data");
        std::fs::write(&data, b"x").unwrap();
        // `current` is a link to the tree, as in an install.
        let current = scratch.join("current");
        std::os::unix::fs::symlink(&tree, &current).unwrap();

        // (a) argv[0] under the tree.
        let ready = scratch.join("ready-a");
        let mut child = start_nodump(&app, &ready, &[], &other);
        assert!(os().tree_in_use(&tree, &[]).unwrap(), "argv[0] in the tree");
        let id = ProcessId {
            pid: child.0.id(),
            start_ticks: start_ticks(child.0.id()),
        };
        assert!(!os().tree_in_use(&tree, &[id]).unwrap(), "excluded");
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(!os().tree_in_use(&tree, &[]).unwrap(), "a: after the exit");

        // (b) argv[0] through the `current` link.
        let ready = scratch.join("ready-b");
        let mut child = start_nodump(&current.join("bin").join("app"), &ready, &[], &other);
        assert!(
            os().tree_in_use(&tree, &[]).unwrap(),
            "argv[0] through the current link"
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(!os().tree_in_use(&tree, &[]).unwrap(), "b: after the exit");

        // (c) an absolute argument in the tree, and (d) one through the link.
        for (name, arg) in [("c", data.clone()), ("d", current.join("data"))] {
            let ready = scratch.join(format!("ready-{name}"));
            let mut child = start_nodump(&helper(), &ready, &[&arg], &other);
            assert!(
                os().tree_in_use(&tree, &[]).unwrap(),
                "{name}: an absolute argument"
            );
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            assert!(
                !os().tree_in_use(&tree, &[]).unwrap(),
                "{name}: after the exit"
            );
        }

        // (e) an argument that is not there (any more) but lies in the tree.
        let ready = scratch.join("ready-e");
        let gone = current.join("deleted-file");
        let _child = start_nodump(&helper(), &ready, &[&gone], &other);
        assert!(
            os().tree_in_use(&tree, &[]).unwrap(),
            "e: an absolute argument naming a missing file in the tree"
        );
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
}
