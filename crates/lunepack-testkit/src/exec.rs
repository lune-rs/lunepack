//! Starting an executable a test has just written (M13 step 5).
//!
//! Linux refuses to `exec` a file that any process still holds open for writing (`ETXTBSY`). A test
//! that writes a script or copies a binary and starts it at once can hit that without any bug in
//! the code under test: the cases of a test binary run in parallel threads, and a thread that forks
//! while another has the file open for writing leaves a copy of that descriptor in its child until
//! the child's own `exec`, which can end after the writer closed the file. The copy is gone within
//! milliseconds, so the right answer is to try again, and only for that error: [`spawn`] does, for
//! a bounded time, and returns every other error, and the busy error itself once the time is up,
//! as it came.

use std::io;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// How long [`spawn`] keeps trying: far longer than a forked child takes to reach its `exec`, short
/// enough that a file that really stays open for writing fails the test and says why.
pub const BUSY_LIMIT: Duration = Duration::from_secs(20);

/// The pause between two tries.
const PAUSE: Duration = Duration::from_millis(2);

/// [`Command::spawn`], tried again while the program is busy for writing ([`BUSY_LIMIT`]).
pub fn spawn(cmd: &mut Command) -> io::Result<Child> {
    spawn_within(cmd, BUSY_LIMIT)
}

/// [`spawn`] with the time to keep trying given.
pub fn spawn_within(cmd: &mut Command, limit: Duration) -> io::Result<Child> {
    let started = Instant::now();
    loop {
        match cmd.spawn() {
            Err(e)
                if e.kind() == io::ErrorKind::ExecutableFileBusy && started.elapsed() < limit =>
            {
                std::thread::sleep(PAUSE);
            }
            other => return other,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    /// A fresh directory under the system's temporary one, removed when dropped (only this one).
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Scratch {
            static N: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "lunepack-exec-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            Scratch(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn script(dir: &Path) -> PathBuf {
        let path = dir.join("tool");
        fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn a_program_that_starts_is_started_once() {
        let dir = Scratch::new();
        let path = script(dir.path());
        let mut child = spawn(&mut Command::new(&path)).unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn other_errors_come_back_at_once() {
        let dir = Scratch::new();
        let started = Instant::now();
        let err = spawn(&mut Command::new(dir.path().join("missing"))).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// Linux only: a file open for writing cannot be executed.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_program_open_for_writing_is_started_once_it_is_closed() {
        let dir = Scratch::new();
        let path = script(dir.path());
        let writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert_eq!(
            Command::new(&path).spawn().unwrap_err().kind(),
            io::ErrorKind::ExecutableFileBusy,
            "the premise: the kernel refuses it while it is open for writing"
        );
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            drop(writer);
        });
        let started = Instant::now();
        let mut child = spawn(&mut Command::new(&path)).unwrap();
        assert!(child.wait().unwrap().success());
        assert!(started.elapsed() >= Duration::from_millis(100), "it waited");
        closer.join().unwrap();
    }

    /// Linux only: the busy error is returned as it is once the time is up.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_program_that_stays_open_for_writing_fails_after_the_limit() {
        let dir = Scratch::new();
        let path = script(dir.path());
        let _writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
        let started = Instant::now();
        let err = spawn_within(&mut Command::new(&path), Duration::from_millis(200)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ExecutableFileBusy);
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
