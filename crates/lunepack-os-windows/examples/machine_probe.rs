//! The acceptance probe of the per-machine adapters (M10 step 11): a small program that drives
//! the Windows adapters one operation at a time, so `scripts/ci/windows-machine-adapter-test.ps1`
//! can run each as the administrator and as a created standard user and compare what each saw.
//!
//! Every operation prints one result line and exits 0 whatever the outcome (a refusal is a result,
//! not a failure of the probe): `ok`, `err:<kind>` or `key=value` words; the script judges them.
//! A usage error exits 2. Nothing here reads the environment, and no operation prints a path the
//! caller did not pass in, except where the line says so.
//!
//! Run with no arguments by the service control manager it is the update service of the app named
//! in `app-id.txt` beside it: it serves the real `Service` pipe, answers the hello of each client
//! and writes `started-<its own file name>.txt` beside itself, so the script can tell which copy
//! of the binary the service started from. Run with `--self-test` it exits 0.
//!
//! Operations (`<class>` is `machine` or `admin`):
//!
//! - `standing`: `Standard`, `Admin` or `UacElevated`.
//! - `protect-make <dir> <class>` and `protect-check <dir> <class>`.
//! - `pipe-serve-elevation <name> <sid> <secs> <ready-file>`: serves an `Elevation` pipe for
//!   `sid`, prints `owner=<sid>`, creates the ready file, sends one line to the client.
//! - `pipe-read-elevation <name>`: connects expecting Administrators and reads to the end.
//! - `pipe-open-write <name>`: opens the pipe for writing (must be refused).
//! - `pipe-create-service <name>`: tries to create a `Service` pipe (a standard user is refused).
//! - `pipe-connect-service <name>`: connects expecting LocalSystem and runs the hello.
//! - `squat <name> <secs> <ready-file>`: creates a pipe of that name with a default descriptor
//!   (what a squatter would do), exactly as the service creates its own but without the
//!   first-instance flag, and holds it.
//! - `service-register <app id> <image>`, `service-image <app id>`, `service-set-image <app id>
//!   <image>`, `service-remove <app id>`, `service-self-test <image>`.
//! - `service-connect <app id>`: the connector (starts the service when it is not running), then
//!   the hello.
//! - `integration-write <root> <app id> <ext>` and `integration-remove <root> <app id> <ext>`:
//!   the all-users scope over the real `HKLM` and the common Start menu.
//! - `policy-read <app id>`.

#[cfg(not(windows))]
fn main() {
    println!("machine_probe: Windows only");
}

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = probe::run(&args);
    std::process::exit(code);
}

#[cfg(windows)]
mod probe {
    use std::io::{self, Read, Write};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use lunepack_core::{
        AppId, ClientSession, ConnectError, DirClass, Duplex, FileType, InstallMeta,
        IntegrationRequest, OsIntegration, PolicySource, Protect, STUB_FILE, Scope, ServerSession,
        ServiceConnector, ServiceRegistrar, Standing, Version,
    };
    use lunepack_core::{RelPath, service::ClientTimeouts};
    use lunepack_os_windows::{
        ExpectedOwner, PipeAccess, PipeClient, PipeError, PipeServer, RegistryPolicy, WinScope,
        WindowsConnector, WindowsIntegration, WindowsProtect, WindowsRegistrar,
        common_start_menu_programs, pipe_name, run_service, standing,
    };

    const USAGE: i32 = 2;
    const HELLO: Duration = Duration::from_secs(10);

    pub fn run(args: &[String]) -> i32 {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        match a.as_slice() {
            [] => service(),
            ["--self-test"] => 0,
            ["standing"] => {
                println!(
                    "{}",
                    match standing() {
                        Standing::Standard => "Standard",
                        Standing::Admin => "Admin",
                        Standing::UacElevated => "UacElevated",
                    }
                );
                0
            }
            ["protect-make", dir, class] => with_class(class, |c| {
                report(
                    WindowsProtect
                        .create_dir(Path::new(dir), c)
                        .map_err(|e| kind_of(&e)),
                )
            }),
            ["protect-check", dir, class] => with_class(class, |c| {
                report(
                    WindowsProtect
                        .check(Path::new(dir), c)
                        .map_err(|e| kind_of(&e)),
                )
            }),
            ["pipe-serve-elevation", name, sid, secs, ready] => {
                pipe_serve_elevation(name, sid, secs, ready)
            }
            ["pipe-read-elevation", name] => pipe_read_elevation(name),
            ["pipe-open-write", name] => pipe_open_write(name),
            ["pipe-create-service", name] => pipe_create_service(name),
            ["pipe-connect-service", name] => pipe_connect_service(name),
            ["squat", name, secs, ready] => squat(name, secs, ready),
            ["service-register", id, image] => with_app(id, |app| {
                report(
                    WindowsRegistrar::new("Lunepack Probe")
                        .register_new(&app, Path::new(image))
                        .map_err(|e| format!("{e:?}")),
                )
            }),
            ["service-image", id] => with_app(id, |app| {
                match WindowsRegistrar::new("Lunepack Probe").image(&app) {
                    Ok(Some(image)) => println!("image={}", image.display()),
                    Ok(None) => println!("image=none"),
                    Err(e) => println!("err:{e:?}"),
                }
                0
            }),
            ["service-set-image", id, image] => with_app(id, |app| {
                report(
                    WindowsRegistrar::new("Lunepack Probe")
                        .set_image(&app, Path::new(image))
                        .map_err(|e| format!("{e:?}")),
                )
            }),
            ["service-remove", id] => with_app(id, |app| {
                report(
                    WindowsRegistrar::new("Lunepack Probe")
                        .remove(&app)
                        .map_err(|e| format!("{e:?}")),
                )
            }),
            ["service-self-test", image] => report(
                WindowsRegistrar::new("Lunepack Probe")
                    .self_test(Path::new(image))
                    .map_err(|e| format!("{e:?}")),
            ),
            ["service-connect", id] => with_app(id, service_connect),
            ["integration-write", root, id, ext] => {
                integration(Path::new(root), id, ext, Direction::Write)
            }
            ["integration-remove", root, id, ext] => {
                integration(Path::new(root), id, ext, Direction::Remove)
            }
            ["policy-read", id] => with_app(id, |app| {
                let p = RegistryPolicy::new().read(&app);
                println!(
                    "self_update_disabled={} no_update_ui={}",
                    p.self_update_disabled, p.no_update_ui
                );
                0
            }),
            _ => {
                eprintln!("machine_probe: unknown operation or wrong arguments (see the header)");
                USAGE
            }
        }
    }

    /// Prints `ok` or `err:<kind>`; the exit code is 0 either way.
    fn report(result: Result<(), String>) -> i32 {
        match result {
            Ok(()) => println!("ok"),
            Err(kind) => println!("err:{kind}"),
        }
        0
    }

    /// The variant name of an error, never its text (which may name a path).
    fn kind_of(err: &lunepack_core::ProtectError) -> String {
        let text = format!("{err:?}");
        text.split(['(', ' ', '{'])
            .next()
            .unwrap_or("unknown")
            .to_owned()
    }

    fn with_class(class: &str, body: impl FnOnce(DirClass) -> i32) -> i32 {
        match class {
            "machine" => body(DirClass::MachineTree),
            "admin" => body(DirClass::AdminOnly),
            _ => USAGE,
        }
    }

    fn with_app(id: &str, body: impl FnOnce(AppId) -> i32) -> i32 {
        match AppId::parse(id) {
            Ok(app) => body(app),
            Err(_) => USAGE,
        }
    }

    fn create_file(path: &str, text: &str) {
        let tmp = format!("{path}.tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }

    // ---- pipes ---------------------------------------------------------------------------------

    fn pipe_serve_elevation(name: &str, sid: &str, secs: &str, ready: &str) -> i32 {
        let Ok(secs) = secs.parse::<u64>() else {
            return USAGE;
        };
        let access = PipeAccess::Elevation {
            sid: sid.to_owned(),
        };
        let mut server = match PipeServer::create(name, &access) {
            Ok(server) => server,
            Err(e) => {
                println!("err:{e:?}");
                return 0;
            }
        };
        match server.descriptor() {
            Ok(d) => println!("owner={}", d.owner),
            Err(e) => println!("err:descriptor {e:?}"),
        }
        create_file(ready, "ready\n");
        match server.accept(Some(Duration::from_secs(secs))) {
            Ok(()) => {
                let sent = server
                    .write_all(b"elevation-stream\n")
                    .and_then(|()| server.flush());
                println!("served={}", sent.is_ok());
                // The client reads before the server lets go: a disconnect drops unread bytes.
                std::thread::sleep(Duration::from_secs(3));
                server.disconnect();
            }
            Err(e) => println!("err:{e:?}"),
        }
        0
    }

    fn pipe_read_elevation(name: &str) -> i32 {
        match PipeClient::connect(name, ExpectedOwner::Administrators, Duration::from_secs(15)) {
            Ok(mut client) => {
                let mut text = String::new();
                match client.read_to_string(&mut text) {
                    Ok(_) => println!("read={}", text.trim()),
                    Err(e) => println!("err:read {:?}", e.kind()),
                }
            }
            Err(e) => println!("err:{e:?}"),
        }
        0
    }

    fn pipe_open_write(name: &str) -> i32 {
        let path = format!(r"\\.\pipe\{name}");
        match std::fs::OpenOptions::new().write(true).open(path) {
            Ok(_) => println!("opened"),
            Err(e) => println!("err:os {}", e.raw_os_error().unwrap_or(-1)),
        }
        0
    }

    fn pipe_create_service(name: &str) -> i32 {
        match PipeServer::create(name, &PipeAccess::Service) {
            Ok(server) => match server.descriptor() {
                Ok(d) => println!("created owner={}", d.owner),
                Err(e) => println!("created err:descriptor {e:?}"),
            },
            Err(e) => println!("err:{e:?}"),
        }
        0
    }

    fn pipe_connect_service(name: &str) -> i32 {
        match PipeClient::connect(name, ExpectedOwner::LocalSystem, Duration::from_secs(15)) {
            Ok(client) => {
                // The owner check passed: the pipe's owner is LocalSystem.
                println!("owner=LocalSystem");
                match hello(client, name) {
                    Ok(version) => println!("hello version={version}"),
                    Err(e) => println!("err:hello {e}"),
                }
            }
            Err(e) => println!("err:{e:?}"),
        }
        0
    }

    /// The hello of protocol version 1 over `io`. The app id is the pipe name without its
    /// `lunepack-` prefix (the pipe is `lunepack-<app id>`).
    fn hello<D: Duplex>(io: D, pipe: &str) -> Result<u32, String> {
        let id = pipe.strip_prefix("lunepack-").unwrap_or(pipe);
        let app = AppId::parse(id).map_err(|e| format!("{e:?}"))?;
        let timeouts = ClientTimeouts {
            hello: Some(HELLO),
            answer: Some(HELLO),
        };
        let session = ClientSession::connect(io, app, timeouts).map_err(|e| format!("{e:?}"))?;
        Ok(session.version())
    }

    #[allow(unsafe_code)]
    fn squat(name: &str, secs: &str, ready: &str) -> i32 {
        use std::ptr::null;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};
        use windows_sys::Win32::System::Pipes::{
            CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
            PIPE_WAIT,
        };
        let Ok(secs) = secs.parse::<u64>() else {
            return USAGE;
        };
        let path: Vec<u16> = format!(r"\\.\pipe\{name}")
            .encode_utf16()
            .chain([0])
            .collect();
        // SAFETY: `path` is a NUL-terminated `u16` buffer that outlives the call; the security
        // attributes are null (the default descriptor, owned by the caller). The parameters are
        // the service's own (one instance, byte mode, 64 KiB buffers) without the first-instance
        // flag, so a refusal is the existing pipe's descriptor, not a mismatch.
        let handle = unsafe {
            CreateNamedPipeW(
                path.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64 * 1024,
                64 * 1024,
                0,
                null(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            println!(
                "err:os {}",
                io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            );
            return 0;
        }
        println!("created");
        create_file(ready, "ready\n");
        std::thread::sleep(Duration::from_secs(secs));
        // The handle is left to the process's end, which closes it.
        0
    }

    // ---- the service -----------------------------------------------------------------------------

    /// A server lent to a session, so the session's end does not take the pipe with it.
    struct Lend<'a>(&'a mut PipeServer);

    impl Read for Lend<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for Lend<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl Duplex for Lend<'_> {
        fn set_read_deadline(&mut self, deadline: Option<Duration>) -> io::Result<()> {
            self.0.set_read_deadline(deadline)
        }
    }

    /// The service: the app id comes from `app-id.txt` beside the binary.
    fn service() -> i32 {
        let Ok(exe) = std::env::current_exe() else {
            return 2;
        };
        let Some(dir) = exe.parent().map(Path::to_path_buf) else {
            return 2;
        };
        let Some(app) = std::fs::read_to_string(dir.join("app-id.txt"))
            .ok()
            .and_then(|t| AppId::parse(t.trim()).ok())
        else {
            eprintln!(
                "machine_probe: not a service started by the control manager, or no app-id.txt"
            );
            return 2;
        };
        // The dispatcher gets the fixed name the real service host gives it (`lunepack-service`):
        // the control manager ignores the name of an own-process service, and this proves it on
        // every run of the acceptance script (the service is registered as `lunepack-<app id>`).
        let result = run_service("lunepack-service", move |control| {
            let marker = exe
                .file_name()
                .map(|n| format!("started-{}.txt", n.to_string_lossy()))
                .unwrap_or_else(|| "started.txt".to_owned());
            let _ = std::fs::write(dir.join(marker), b"started\n");
            let mut server = match PipeServer::create(&pipe_name(&app), &PipeAccess::Service) {
                Ok(server) => server,
                Err(_) => return 1,
            };
            let canceller = server.canceller();
            control.on_stop(move || canceller.cancel());
            while !control.stop_requested() {
                match server.accept(Some(Duration::from_secs(1))) {
                    Ok(()) => {
                        if let Ok(mut session) =
                            ServerSession::accept(Lend(&mut server), app.clone())
                        {
                            let _ = session.next_request();
                        }
                        server.disconnect();
                    }
                    Err(PipeError::Timeout) => {}
                    Err(PipeError::Cancelled) => break,
                    Err(_) => return 1,
                }
            }
            0
        });
        match result {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("machine_probe: {e}");
                2
            }
        }
    }

    fn service_connect(app: AppId) -> i32 {
        match WindowsConnector::new().connect(&app) {
            Ok(io) => match hello(io, &pipe_name(&app)) {
                Ok(version) => println!("hello version={version}"),
                Err(e) => println!("err:hello {e}"),
            },
            Err(e) => println!(
                "err:{}",
                match e {
                    ConnectError::NotInstalled => "NotInstalled".to_owned(),
                    ConnectError::Disabled => "Disabled".to_owned(),
                    ConnectError::Busy => "Busy".to_owned(),
                    ConnectError::WrongOwner => "WrongOwner".to_owned(),
                    other => format!("{other:?}"),
                }
            ),
        }
        0
    }

    // ---- the machine integration -----------------------------------------------------------------

    #[derive(Clone, Copy)]
    enum Direction {
        Write,
        Remove,
    }

    fn integration(root: &Path, id: &str, ext: &str, direction: Direction) -> i32 {
        let Ok(app) = AppId::parse(id) else {
            return USAGE;
        };
        let name = format!("Lunepack Probe {id}");
        let tree = root.join("app").join("1.0.0").join("bin");
        let staged = std::fs::create_dir_all(&tree)
            .and_then(|()| std::fs::create_dir_all(root.join(".lunepack").join("state")))
            .and_then(|()| std::fs::write(tree.join(STUB_FILE), b"the probe stub"));
        if staged.is_err() {
            println!("err:stage");
            return 0;
        }
        let request = IntegrationRequest {
            app_id: app,
            install_root: PathBuf::from(root),
            version: Version::parse("1.0.0").expect("version"),
            meta: InstallMeta {
                entry: RelPath::parse("bin/app.exe").expect("entry"),
                name: name.clone(),
                comment: None,
                icon: None,
                categories: Vec::new(),
                bin: None,
                terminal: false,
                publisher: Some("Lunepack Probe".to_owned()),
                file_types: vec![FileType {
                    ext: ext.to_owned(),
                    name: "Lunepack Probe File".to_owned(),
                    mime: "application/x-lunepack-probe".to_owned(),
                }],
                url_schemes: Vec::new(),
                autostart: true,
            },
            previous: None,
            stale_bins: Vec::new(),
        };
        let Some(w) = WindowsIntegration::current_user().with_machine(WinScope::machine()) else {
            println!("err:no machine scope");
            return 0;
        };
        let outcome = match direction {
            Direction::Write => w.apply(Scope::Machine, &request).map(|r| r.kept.len()),
            Direction::Remove => w.remove(Scope::Machine, &request).map(|r| r.kept.len()),
        };
        match outcome {
            Ok(kept) => {
                println!("ok kept={kept}");
                if let Ok(programs) = common_start_menu_programs() {
                    println!(
                        "shortcut={}",
                        programs.join(format!("{name}.lnk")).display()
                    );
                }
            }
            Err(e) => println!(
                "err:{}",
                format!("{e:?}").split(['(', ' ']).next().unwrap_or("")
            ),
        }
        0
    }
}
