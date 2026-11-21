//! The service binary's pieces that need no operating system (arguments, the location rule, the
//! log, the connection cap, the idle rule, what a self-test counts), the binary's behaviour when
//! it is run outside an install, and, on Windows, its PE hardening (the runtime's pattern).

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use lunepack_core::Duplex;
use lunepack_core::engine::EngineError;
use lunepack_core::service::ErrorCode;
use lunepack_service::args::{Mode, UsageError, parse};
use lunepack_service::location::{LocationError, display_name, locate, log_path};
use lunepack_service::logfile::{CAP, Level, Log};
use lunepack_service::session::{Capped, IDLE_EXIT, idle_exit, self_test_passes};
use lunepack_testkit::mem_duplex;

fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

// ---- the command line ----------------------------------------------------------------------------

#[test]
fn no_argument_is_the_service_and_one_flag_is_the_self_test() {
    assert_eq!(parse(&os(&[])), Ok(Mode::Service));
    assert_eq!(parse(&os(&["--self-test"])), Ok(Mode::SelfTest));
}

#[test]
fn anything_else_is_a_usage_error() {
    for args in [
        &["--self-test", "--self-test"][..],
        &["--self-test", "x"],
        &["self-test"],
        &["--selftest"],
        &["--SELF-TEST"],
        &["-h"],
        &["--help"],
        &[""],
        &["x"],
        &["--", "--self-test"],
    ] {
        assert_eq!(parse(&os(args)), Err(UsageError), "{args:?}");
    }
}

// ---- the location rule ---------------------------------------------------------------------------

fn image(root: &Path, version: &str) -> PathBuf {
    root.join(".lunepack")
        .join("machine")
        .join("service")
        .join(version)
        .join("lunepack-service.exe")
}

/// An absolute path that exists on no machine: the location rule reads names, never the disk.
fn base() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\")
    } else {
        PathBuf::from("/")
    }
}

fn pf() -> PathBuf {
    base().join("lunepack-service-test-pf")
}

#[test]
fn the_image_of_an_install_under_program_files_is_accepted() {
    let root = pf().join("Hello App");
    let located = locate(&image(&root, "1.2.3"), &pf()).expect("located");
    assert_eq!(located.layout.root(), root);
    assert_eq!(located.version.to_string(), "1.2.3");
    assert_eq!(display_name(&located.layout).as_deref(), Some("Hello App"));
    assert_eq!(
        log_path(&located.layout),
        root.join(".lunepack").join("logs").join("service.log")
    );
    // A pre-release and build metadata read as the version they are.
    let located = locate(&image(&root, "1.2.3-rc.1"), &pf()).expect("located");
    assert_eq!(located.version.to_string(), "1.2.3-rc.1");
    // Windows paths do not compare by case.
    let upper = PathBuf::from(pf().to_string_lossy().to_uppercase());
    assert!(locate(&image(&root, "1.2.3"), &upper).is_ok());
}

#[test]
fn an_image_that_is_not_in_the_service_folder_is_refused() {
    let root = pf().join("Hello App");
    let good = image(&root, "1.2.3");
    let refused = |p: &Path| locate(p, &pf());
    // Another file name, another folder name at each level, a version that is not canonical.
    let mut wrong_name = good.clone();
    wrong_name.set_file_name("lunepack-runtime.exe");
    assert_eq!(refused(&wrong_name), Err(LocationError::NotAServiceImage));
    for bad in [
        root.join(".lunepack")
            .join("machine")
            .join("service")
            .join("1.2.3")
            .join("sub")
            .join("lunepack-service.exe"),
        root.join(".lunepack")
            .join("machine")
            .join("other")
            .join("1.2.3")
            .join("lunepack-service.exe"),
        root.join(".lunepack")
            .join("state")
            .join("service")
            .join("1.2.3")
            .join("lunepack-service.exe"),
        root.join("app").join("lunepack-service.exe"),
        image(&root, "1.2"),
        image(&root, "01.2.3"),
        image(&root, "v1.2.3"),
        image(&root, "latest"),
    ] {
        assert_eq!(
            refused(&bad),
            Err(LocationError::NotAServiceImage),
            "{bad:?}"
        );
    }
    // Relative, or with dots in it: never trusted, whatever they resolve to.
    assert_eq!(
        refused(Path::new(
            ".lunepack/machine/service/1.2.3/lunepack-service.exe"
        )),
        Err(LocationError::NotAServiceImage)
    );
    let dotted = pf()
        .join("Hello App")
        .join("..")
        .join("Hello App")
        .join(".lunepack")
        .join("machine")
        .join("service")
        .join("1.2.3")
        .join("lunepack-service.exe");
    assert_eq!(refused(&dotted), Err(LocationError::NotAServiceImage));
}

#[test]
fn a_root_that_is_not_directly_under_program_files_is_refused() {
    let elsewhere = base().join("lunepack-service-test-other");
    let cases = [
        // Another parent.
        image(&elsewhere.join("Hello App"), "1.2.3"),
        // Deeper than a direct child (a folder a user could create).
        image(&pf().join("Vendor").join("Hello App"), "1.2.3"),
        // Program Files itself as the root.
        image(&pf(), "1.2.3"),
        // A name sharing a prefix with Program Files.
        image(
            &base().join("lunepack-service-test-pf2").join("Hello App"),
            "1.2.3",
        ),
    ];
    for case in cases {
        assert_eq!(
            locate(&case, &pf()),
            Err(LocationError::NotUnderProgramFiles),
            "{case:?}"
        );
    }
    // A relative known folder is not a known folder.
    assert_eq!(
        locate(&image(&pf().join("Hello App"), "1.2.3"), Path::new("pf")),
        Err(LocationError::NotUnderProgramFiles)
    );
}

// ---- the log -------------------------------------------------------------------------------------

fn fixed_time() -> u64 {
    1_700_000_000
}

#[test]
fn a_log_line_is_a_time_a_level_a_fixed_message_and_a_code() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("logs").join("service.log");
    let log = Log::new(path.clone(), fixed_time);
    log.info("the service starts");
    log.error("the engine did not open", 4);
    log.line(Level::Info, "no code", None);
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        text,
        "1700000000 INFO the service starts\n\
         1700000000 ERROR the engine did not open 4\n\
         1700000000 INFO no code\n"
    );
}

#[test]
fn the_log_is_capped_by_moving_the_full_file_aside() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("service.log");
    let log = Log::with_cap(path.clone(), fixed_time, 200);
    for _ in 0..40 {
        log.info("a line that fills the file");
    }
    let aside = dir.path().join("service.log.1");
    assert!(aside.exists(), "the full file was moved aside");
    let size = |p: &Path| std::fs::metadata(p).unwrap().len();
    assert!(
        size(&path) < 200 + 64 && size(&aside) < 200 + 64,
        "each stays near the cap"
    );
    // Only the two files: nothing grows without bound.
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert_eq!(CAP, 256 * 1024);
}

#[test]
fn a_log_that_cannot_be_written_does_not_fail_the_service() {
    // The parent is a file, so no directory can be made under it.
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("file");
    std::fs::write(&blocker, b"x").unwrap();
    let log = Log::new(blocker.join("logs").join("service.log"), fixed_time);
    log.info("dropped");
    log.error("dropped too", 1);
}

// ---- the connection cap and the idle rule --------------------------------------------------------

#[test]
fn a_capped_connection_stops_after_its_limit() {
    let (client, server) = mem_duplex();
    let mut client = client;
    let mut capped = Capped::new(server, Duration::from_millis(150));
    client.write_all(b"hello").unwrap();
    let mut buf = [0u8; 5];
    capped.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello");
    capped.write_all(b"back").unwrap();
    std::thread::sleep(Duration::from_millis(250));
    let err = capped.read(&mut buf).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    let err = capped.write(b"x").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    let err = capped
        .set_read_deadline(Some(Duration::from_secs(5)))
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}

#[test]
fn a_read_deadline_never_reaches_past_the_cap() {
    let (_client, server) = mem_duplex();
    let mut capped = Capped::new(server, Duration::from_millis(200));
    // A 30 s frame deadline is cut to what is left of the connection's life: the read returns
    // when the cap does, not when the frame deadline would.
    capped
        .set_read_deadline(Some(Duration::from_secs(30)))
        .unwrap();
    let started = Instant::now();
    let mut buf = [0u8; 1];
    let err = capped.read(&mut buf).unwrap_err();
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ),
        "{err:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    // No deadline at all is bounded by the cap too.
    let (_client, server) = mem_duplex();
    let mut capped = Capped::new(server, Duration::from_millis(200));
    capped.set_read_deadline(None).unwrap();
    let started = Instant::now();
    assert!(capped.read(&mut buf).is_err());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn the_service_is_idle_after_sixty_seconds_without_a_lease() {
    assert_eq!(IDLE_EXIT, Duration::from_secs(60));
    assert!(!idle_exit(Duration::from_secs(59), false));
    assert!(idle_exit(Duration::from_secs(60), false));
    assert!(idle_exit(Duration::from_secs(3600), false));
    assert!(
        !idle_exit(Duration::from_secs(3600), true),
        "a running lease keeps the service up"
    );
    assert!(!idle_exit(Duration::ZERO, false));
}

// ---- the self-test -------------------------------------------------------------------------------

fn refused(code: ErrorCode) -> Result<(), EngineError> {
    // An engine error as the engine makes it: through its answer, since its constructor is private.
    let answer = lunepack_core::service::Response::error(code);
    match answer {
        lunepack_core::service::Response::Error { code, class } => Err(EngineError { code, class }),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_self_test_passes_when_the_engine_opens_or_the_parent_holds_its_lock() {
    assert!(self_test_passes(&Ok(())));
    assert!(
        self_test_passes(&refused(ErrorCode::Busy)),
        "the registrar starts the binary while the engine that switches the service holds the lock"
    );
    for code in ErrorCode::ALL {
        if *code != ErrorCode::Busy {
            assert!(!self_test_passes(&refused(*code)), "{code:?}");
        }
    }
}

// ---- the binary ----------------------------------------------------------------------------------

const BINARY: &str = env!("CARGO_BIN_EXE_lunepack-service");

fn run(args: &[&str]) -> std::process::Output {
    Command::new(BINARY)
        .args(args)
        .env_clear()
        .output()
        .expect("run the service binary")
}

#[test]
fn the_binary_refuses_a_bad_command_line_with_two() {
    for args in [&["--bogus"][..], &["--self-test", "x"], &["x"]] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn the_binary_does_nothing_outside_an_install() {
    // `--self-test` and a bare start from a build folder: not an install's service folder.
    for args in [&["--self-test"][..], &[]] {
        let out = run(args);
        assert_ne!(out.status.code(), Some(0), "{args:?}");
        assert!(out.stdout.len() < 200, "at most one short line");
    }
}

#[cfg(windows)]
#[test]
fn outside_an_install_the_binary_exits_with_the_location_code() {
    for args in [&["--self-test"][..], &[]] {
        assert_eq!(run(args).status.code(), Some(3), "{args:?}");
    }
}

#[cfg(not(windows))]
#[test]
fn off_windows_the_binary_says_so_in_one_line() {
    let out = run(&["--self-test"]);
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text.lines().count(), 1, "{text}");
}

// ---- the crate's own source ----------------------------------------------------------------------

#[test]
fn the_source_names_no_impersonation_no_environment_and_no_unsafe() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        // The comments say what the service never does; the code never does it.
        let code: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for word in [
            "Impersonate",
            "ImpersonateNamedPipeClient",
            "RevertToSelf",
            "SetThreadToken",
            "env::var",
            "temp_dir",
            "current_dir",
            "home_dir",
            "unsafe",
            "Command::new",
            "LoadLibrary",
        ] {
            assert!(!code.contains(word), "{} names {word}", path.display());
        }
        seen += 1;
    }
    assert!(seen >= 7, "the scan saw the crate's files");
}

// ---- the PE image (Windows) ----------------------------------------------------------------------

/// The service's own PE image carries the Windows hardening (M7-D10), as the runtime's does
/// (`crates/lunepack-runtime/tests/pe_hardening.rs`): no C-runtime DLL import, no static
/// `advapi32.dll` import (it is delay-loaded), `DependentLoadFlags` of
/// `LOAD_LIBRARY_SEARCH_SYSTEM32`, an embedded manifest with `asInvoker` and `longPathAware`, and
/// the console subsystem. Empty off Windows; it reads the binary cargo built for this test, so it
/// fails when `.cargo/config.toml`'s `+crt-static` is overridden by a `RUSTFLAGS` variable.
#[cfg(windows)]
#[test]
fn the_service_image_is_hardened() {
    use lunepack_core::pe::{
        LOAD_LIBRARY_SEARCH_SYSTEM32, PeImage, SUBSYSTEM_CONSOLE, is_c_runtime,
        manifest_is_hardened,
    };
    use lunepack_core::{Target, check_service_image};

    #[cfg(target_arch = "x86_64")]
    const TARGET: Target = Target::WindowsX86_64;
    #[cfg(target_arch = "aarch64")]
    const TARGET: Target = Target::WindowsAarch64;

    let bytes = std::fs::read(BINARY).expect("read the service binary");
    let pe = PeImage::parse(&bytes).expect("the service binary reads as a PE image");
    let imports: Vec<&str> = pe.all_imports().collect();
    let crt: Vec<&&str> = imports.iter().filter(|n| is_c_runtime(n)).collect();
    assert!(
        crt.is_empty(),
        "C runtime imports: {crt:?} (all: {imports:?})"
    );
    assert!(!pe.imports.is_empty(), "the reader found no imports at all");
    assert!(
        !pe.imports
            .iter()
            .any(|n| n.eq_ignore_ascii_case("advapi32.dll")),
        "advapi32.dll is delay-loaded, not a static import: {:?}",
        pe.imports
    );
    assert!(
        pe.delay_imports
            .iter()
            .any(|n| n.eq_ignore_ascii_case("advapi32.dll")),
        "the delay-load of advapi32.dll took effect: {:?}",
        pe.delay_imports
    );
    assert_eq!(
        pe.dependent_load_flags,
        Some(LOAD_LIBRARY_SEARCH_SYSTEM32),
        "DependentLoadFlags"
    );
    assert_eq!(pe.headers.subsystem, SUBSYSTEM_CONSOLE, "a console binary");
    let manifest = pe.manifest.as_deref().expect("an embedded RT_MANIFEST");
    assert!(
        manifest_is_hardened(manifest),
        "the manifest requests asInvoker and sets longPathAware to true"
    );
    // The packager's own check (step 13 runs it on `--service`) accepts it.
    assert_eq!(check_service_image(&bytes, TARGET), Ok(()));
}
