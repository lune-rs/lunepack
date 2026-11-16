//! The helper program: this test binary run with a helper mode as its first argument. It speaks
//! the protocol of `lunepack_testkit::run_process_suite` plus three modes of this crate's tests:
//!
//! - `hold <file> <ready> <secs>`: opens `file`, creates `ready`, then sleeps with `file` open.
//! - `nodump <ready> <secs> [ignored...]`: sets `PR_SET_DUMPABLE` to 0 (so `/proc/<pid>/{exe,cwd,fd,
//!   maps}` are denied to its own user without `CAP_SYS_PTRACE`, like `(sd-pam)` or ssh-agent),
//!   creates `ready`, then sleeps. The extra arguments only appear in its command line.
//! - `pid-sleep <file> <secs>`: creates `file` holding `<pid> <start ticks>`, then sleeps.
//! - `leader-exit <ready> <secs>`: starts a thread that sleeps for `secs` and then exits the
//!   process, creates `ready`, then ends the main thread alone (`SYS_exit`), so the thread-group
//!   leader is a zombie while the other thread runs.
//! - `detach-then <exit|sleep> <mode> <arg>...`: starts this binary with `<mode> <arg>...` through
//!   `LinuxProcess::spawn_detached`, then exits 0 (`exit`) or sleeps for 600 s (`sleep`).
//!
//! - `cat`: copies its standard input to its standard output until end of file (the suite's mode).
//! - `fds <file> [<ready>]`: creates `file` holding one line per open descriptor, `<fd> <target>`
//!   (the target as `/proc/self/fd` reads it, `pipe:[inode]` for a pipe), and then, when `ready` is
//!   given, creates `ready` and sleeps 600 s.
//!
//! Every file is created atomically (`<file>.tmp`, then a rename).

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::Duration;

use lunepack_core::{Process, SpawnSpec};
use lunepack_os_linux::LinuxProcess;

const MODES: &[&str] = &[
    "exit",
    "sleep",
    "sleep-ignore-term",
    "write",
    "args",
    "env",
    "probe",
    "hold",
    "nodump",
    "pid-sleep",
    "leader-exit",
    "detach-then",
    "cat",
    "fds",
];

/// Runs the helper mode named by `args[0]` and never returns; `false` when `args` names no mode.
pub fn run(args: &[String]) -> bool {
    let Some(mode) = args.first() else {
        return false;
    };
    if !MODES.contains(&mode.as_str()) {
        return false;
    }
    let rest = &args[1..];
    match mode.as_str() {
        "exit" => std::process::exit(rest[0].parse().expect("exit code")),
        "sleep" => sleep(&rest[0]),
        "sleep-ignore-term" => {
            ignore_sigterm();
            create(Path::new(&rest[1]), "ready\n");
            sleep(&rest[0]);
        }
        "write" => create(Path::new(&rest[0]), &rest[1]),
        "args" => {
            let text: String = rest[1..].iter().map(|a| format!("{a}\n")).collect();
            create(Path::new(&rest[0]), &text);
        }
        "env" => {
            let text: String = rest[1..]
                .iter()
                .map(|name| match std::env::var_os(name) {
                    Some(v) => format!("{name}={}\n", v.to_string_lossy()),
                    None => format!("{name} unset\n"),
                })
                .collect();
            create(Path::new(&rest[0]), &text);
        }
        "probe" => {
            let fields = stat_fields(None);
            let leader = fields[6 - 3] == std::process::id().to_string();
            let mut text = String::from(if leader {
                "session leader\n"
            } else {
                "session member\n"
            });
            for (fd, name) in [(0, "stdin"), (1, "stdout"), (2, "stderr")] {
                let null = is_dev_null(&format!("/proc/self/fd/{fd}"));
                text.push_str(&format!("{name} {}\n", if null { "null" } else { "other" }));
            }
            create(Path::new(&rest[0]), &text);
        }
        "hold" => {
            let _file = std::fs::File::open(&rest[0]).expect("open the held file");
            create(Path::new(&rest[1]), "ready\n");
            sleep(&rest[2]);
        }
        "nodump" => {
            set_not_dumpable();
            create(Path::new(&rest[0]), "ready\n");
            sleep(&rest[1]);
        }
        "pid-sleep" => {
            let me = LinuxProcess::new().current().expect("current");
            create(
                Path::new(&rest[0]),
                &format!("{} {}\n", me.pid, me.start_ticks),
            );
            sleep(&rest[1]);
        }
        "leader-exit" => {
            let secs = rest[1].clone();
            std::thread::spawn(move || {
                sleep(&secs);
                std::process::exit(0);
            });
            create(Path::new(&rest[0]), "ready\n");
            exit_this_thread();
        }
        "cat" => {
            let mut input = std::io::stdin().lock();
            let mut output = std::io::stdout().lock();
            std::io::copy(&mut input, &mut output).expect("copy standard input to output");
            std::io::Write::flush(&mut output).expect("flush");
        }
        "fds" => {
            let mut text = String::new();
            for entry in std::fs::read_dir("/proc/self/fd").expect("read /proc/self/fd") {
                let entry = entry.expect("fd entry");
                let Ok(target) = std::fs::read_link(entry.path()) else {
                    continue;
                };
                text.push_str(&format!(
                    "{} {}\n",
                    entry.file_name().to_string_lossy(),
                    target.display()
                ));
            }
            create(Path::new(&rest[0]), &text);
            if let Some(ready) = rest.get(1) {
                create(Path::new(ready), "ready\n");
                sleep("600");
            }
        }
        "detach-then" => {
            let mut spec = SpawnSpec::new(std::env::current_exe().expect("current_exe"));
            spec.args = rest[1..].iter().map(Into::into).collect();
            LinuxProcess::new()
                .spawn_detached(&spec)
                .expect("spawn_detached");
            if rest[0] == "sleep" {
                sleep("600");
            }
        }
        _ => unreachable!(),
    }
    std::process::exit(0);
}

fn sleep(secs: &str) {
    std::thread::sleep(Duration::from_secs(secs.parse().expect("seconds")));
}

fn create(path: &Path, text: &str) {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    std::fs::write(&tmp, text).expect("write the helper's file");
    std::fs::rename(&tmp, path).expect("rename the helper's file");
}

fn is_dev_null(path: &str) -> bool {
    let (Ok(fd), Ok(null)) = (std::fs::metadata(path), std::fs::metadata("/dev/null")) else {
        return false;
    };
    fd.file_type().is_char_device() && fd.rdev() == null.rdev()
}

/// The fields of `/proc/<pid>/stat` (of this process for `None`) from field 3 on, counted after
/// the last `)`: index `n - 3` is field `n`.
pub fn stat_fields(pid: Option<u32>) -> Vec<String> {
    let path = match pid {
        Some(pid) => format!("/proc/{pid}/stat"),
        None => "/proc/self/stat".to_owned(),
    };
    let text = std::fs::read(path).expect("read stat");
    let close = text.iter().rposition(|&b| b == b')').expect("comm");
    String::from_utf8_lossy(&text[close + 2..])
        .trim_end()
        .split(' ')
        .map(str::to_owned)
        .collect()
}

#[allow(unsafe_code)]
fn ignore_sigterm() {
    // SAFETY: signal(2) with SIG_IGN installs no handler code; this process is single-threaded
    // here (the helper starts no thread), and nothing else in it relies on SIGTERM's disposition.
    let previous = unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
    assert_ne!(previous, libc::SIG_ERR, "ignore SIGTERM");
}

#[allow(unsafe_code)]
fn set_not_dumpable() {
    // SAFETY: prctl(2) PR_SET_DUMPABLE takes two integers and touches no memory; the three
    // unused arguments are zero as the call requires.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    assert_eq!(rc, 0, "prctl(PR_SET_DUMPABLE, 0)");
}

#[allow(unsafe_code)]
fn exit_this_thread() -> ! {
    // SAFETY: the raw exit(2) system call (not exit_group) ends only the calling thread and takes
    // one integer. Nothing on this thread's stack needs a destructor (the helper's arguments are
    // leaked with the process), and the other thread ends the process with exit_group later.
    unsafe { libc::syscall(libc::SYS_exit, 0) };
    unreachable!("SYS_exit returned");
}
