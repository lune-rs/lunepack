//! `ActivatedListener::from_systemd` with real sockets on descriptor 3 (M11-D3): this binary
//! starts itself as a child with the case's descriptor duplicated onto 3, as systemd passes it,
//! and the child reports what `from_systemd` answered. Own `main` (see Cargo.toml), so no other
//! test's descriptors meet descriptor 3.

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--child") {
        linux::child(&args[1..]);
        return;
    }
    linux::run_all();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("lunepack-os-linux activation tests: Linux only, skipped");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::TcpListener;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use lunepack_os_linux::{ActivatedListener, ActivationError};

    /// In the child: takes descriptor 3 for `expected` and prints the answer, then (when it was
    /// taken) whether a second take is refused and whether a client connects.
    pub fn child(args: &[String]) {
        let expected = PathBuf::from(&args[0]);
        match ActivatedListener::from_systemd(&expected) {
            Ok(listener) => {
                let again = ActivatedListener::from_systemd(&expected).err();
                let client = UnixStream::connect(&expected).is_ok();
                let accepted = listener.accept().is_ok();
                println!("ok again={again:?} client={client} accepted={accepted}");
            }
            Err(e) => println!("err {e:?}"),
        }
    }

    /// Runs this binary as the child with `fd` on descriptor 3 (`None`: descriptor 3 closed).
    fn run_child(fd: Option<RawFd>, expected: &Path) -> String {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.arg("--child").arg(expected);
        // SAFETY: the closure only calls `dup2`, `fcntl` and `close`, which are async-signal-safe, on
        // descriptors the parent owns and that stay open until the child has started.
        #[allow(unsafe_code)]
        unsafe {
            cmd.pre_exec(move || {
                match fd {
                    // `dup2` onto itself keeps close-on-exec: clear it then.
                    Some(3) => {
                        if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Some(fd) => {
                        if libc::dup2(fd, 3) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    None => {
                        libc::close(3);
                    }
                }
                Ok(())
            });
        }
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "the child failed: {out:?}");
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    fn err(e: ActivationError) -> String {
        format!("err {e:?}")
    }

    pub fn run_all() {
        let dir = std::env::temp_dir().join(format!("lunepack-activation-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let mut failed = 0;
        let mut check = |name: &str, got: String, want: &str| {
            if got == want {
                println!("test {name} ... ok");
            } else {
                println!("test {name} ... FAILED: got {got:?}, want {want:?}");
                failed += 1;
            }
        };

        let path = dir.join("service.sock");
        let listener = UnixListener::bind(&path).unwrap();
        check(
            "the_unit_socket_is_taken_once",
            run_child(Some(listener.as_raw_fd()), &path),
            "ok again=Some(Taken) client=true accepted=true",
        );
        check(
            "another_path_is_refused",
            run_child(Some(listener.as_raw_fd()), &dir.join("other.sock")),
            &err(ActivationError::WrongPath),
        );

        let (a, _b) = UnixStream::pair().unwrap();
        check(
            "a_socket_that_does_not_listen_is_refused",
            run_child(Some(a.as_raw_fd()), &path),
            &err(ActivationError::NotListening),
        );

        let dgram_path = dir.join("dgram.sock");
        let dgram = UnixDatagram::bind(&dgram_path).unwrap();
        check(
            "a_datagram_socket_is_refused",
            run_child(Some(dgram.as_raw_fd()), &dgram_path),
            &err(ActivationError::WrongKind),
        );

        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        check(
            "a_socket_that_is_not_unix_is_refused",
            run_child(Some(tcp.as_raw_fd()), &path),
            &err(ActivationError::WrongKind),
        );

        let file = std::fs::File::create(dir.join("plain")).unwrap();
        check(
            "a_file_is_refused",
            run_child(Some(file.as_raw_fd()), &path),
            &err(ActivationError::NotASocket),
        );
        check(
            "a_closed_descriptor_is_refused",
            run_child(None, &path),
            &err(ActivationError::NotASocket),
        );

        let _ = std::fs::remove_dir_all(&dir);
        if failed > 0 {
            std::process::exit(1);
        }
    }
}
