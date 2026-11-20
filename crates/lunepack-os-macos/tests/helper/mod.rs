//! The helper program: this test binary run with a helper mode as its first argument. It speaks
//! the protocol of `lunepack_testkit::run_process_suite` plus the modes of this crate's tests:
//!
//! - `hold <file> <ready> <secs>`: opens `file`, creates `ready`, then sleeps with `file` open.
//! - `pid-sleep <file> <secs>`: creates `file` holding `<pid> <start micros>`, then sleeps.
//! - `detach-then <exit|sleep> <mode> <arg>...`: starts this binary with `<mode> <arg>...` through
//!   `MacProcess::spawn_detached`, then exits 0 (`exit`) or sleeps for 600 s (`sleep`).
//! - `cat`: copies its standard input to its standard output until end of file.
//! - `env-sleep <file> <secs> <name>...`: as `env`, then sleeps (an app started in the
//!   background, M8-D13, that stays up to be identified).
//!
//! Every file is created atomically (`<file>.tmp`, then a rename).

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::Duration;

use lunepack_core::{Process, SpawnSpec};
use lunepack_os_macos::MacProcess;

const MODES: &[&str] = &[
    "exit",
    "sleep",
    "sleep-ignore-term",
    "write",
    "args",
    "env",
    "probe",
    "hold",
    "pid-sleep",
    "detach-then",
    "cat",
    "env-sleep",
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
            let leader = session_id() == i64::from(std::process::id());
            let mut text = String::from(if leader {
                "session leader\n"
            } else {
                "session member\n"
            });
            for (fd, name) in [(0, "stdin"), (1, "stdout"), (2, "stderr")] {
                let null = is_dev_null(fd);
                text.push_str(&format!("{name} {}\n", if null { "null" } else { "other" }));
            }
            create(Path::new(&rest[0]), &text);
        }
        "env-sleep" => {
            let text: String = rest[2..]
                .iter()
                .map(|name| match std::env::var_os(name) {
                    Some(v) => format!("{name}={}\n", v.to_string_lossy()),
                    None => format!("{name} unset\n"),
                })
                .collect();
            create(Path::new(&rest[0]), &text);
            sleep(&rest[1]);
        }
        "hold" => {
            let _file = std::fs::File::open(&rest[0]).expect("open the held file");
            create(Path::new(&rest[1]), "ready\n");
            sleep(&rest[2]);
        }
        "pid-sleep" => {
            let me = MacProcess::new().current().expect("current");
            create(
                Path::new(&rest[0]),
                &format!("{} {}\n", me.pid, me.start_ticks),
            );
            sleep(&rest[1]);
        }
        "cat" => {
            let mut input = std::io::stdin().lock();
            let mut output = std::io::stdout().lock();
            std::io::copy(&mut input, &mut output).expect("copy standard input to output");
            std::io::Write::flush(&mut output).expect("flush");
        }
        "detach-then" => {
            let mut spec = SpawnSpec::new(std::env::current_exe().expect("current_exe"));
            spec.args = rest[1..].iter().map(Into::into).collect();
            MacProcess::new()
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

/// Whether descriptor `fd` is the null device (a character device with `/dev/null`'s `rdev`).
#[allow(unsafe_code)]
fn is_dev_null(fd: i32) -> bool {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `st` is writable memory of the size of `struct stat`; `fstat` fills it when it
    // returns 0, and it is read only then.
    let rc = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if rc != 0 {
        return false;
    }
    // SAFETY: `fstat` returned 0, so the struct is initialised.
    let st = unsafe { st.assume_init() };
    let Ok(null) = std::fs::metadata("/dev/null") else {
        return false;
    };
    let is_char = (st.st_mode as u32 & libc::S_IFMT as u32) == libc::S_IFCHR as u32;
    is_char && st.st_rdev as u64 == null.rdev() && null.file_type().is_char_device()
}

#[allow(unsafe_code)]
fn session_id() -> i64 {
    // SAFETY: getsid(2) with 0 names the calling process; it takes one integer and touches no
    // memory.
    i64::from(unsafe { libc::getsid(0) })
}

#[allow(unsafe_code)]
fn ignore_sigterm() {
    // SAFETY: signal(2) with SIG_IGN installs no handler code; this process is single-threaded
    // here (the helper starts no thread), and nothing else in it relies on SIGTERM's disposition.
    let previous = unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
    assert_ne!(previous, libc::SIG_ERR, "ignore SIGTERM");
}
