//! The Linux and macOS host (M11 step 5): the location rule, the order of the host's first
//! actions (location, then the activated socket, then everything else), the timed accept, and the
//! rule that the binary reads no environment variable.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::io::Read;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use lunepack_core::{MachineScheme, endpoint};
use lunepack_service::args::Mode;
use lunepack_service::exit;
use lunepack_service::host_unix::{
    ACCEPT_SLICE, SCHEME, accept_within, machine_home, resolve_home, run_at,
};
use lunepack_service::location::{LocationError, locate_unix, root_app_id};

fn image(root: &Path, version: &str) -> PathBuf {
    root.join(".lunepack")
        .join("machine")
        .join("service")
        .join(version)
        .join("lunepack-service")
}

/// A machine home that exists on no machine: the location rule reads names, never the disk.
fn home() -> PathBuf {
    PathBuf::from("/lunepack-service-test-home")
}

fn scheme() -> MachineScheme {
    SCHEME
}

#[test]
fn this_os_has_a_fixed_machine_home_and_scheme() {
    let expected = if cfg!(target_os = "linux") {
        ("/opt", MachineScheme::LINUX)
    } else {
        (
            "/Library/Application Support/lunepack",
            MachineScheme::MACOS,
        )
    };
    assert_eq!(SCHEME, expected.1);
    assert_eq!(SCHEME.home, Some(expected.0));
}

#[test]
fn the_exact_shape_is_accepted() {
    let root = home().join("hello.app");
    let located = locate_unix(&image(&root, "1.2.3"), &home(), scheme()).expect("located");
    assert_eq!(located.layout.root(), root);
    assert_eq!(located.version.to_string(), "1.2.3");
    assert_eq!(
        root_app_id(&located.layout).map(|a| a.as_str().to_owned()),
        Some("hello.app".to_owned())
    );
    let located = locate_unix(&image(&root, "1.2.3-rc.1"), &home(), scheme()).expect("located");
    assert_eq!(located.version.to_string(), "1.2.3-rc.1");
}

#[test]
fn an_image_that_is_not_in_the_service_folder_is_refused() {
    let root = home().join("hello");
    let good = image(&root, "1.2.3");
    let refused = |p: &Path| locate_unix(p, &home(), scheme());
    // A copy in a temporary folder, the build folder, a user's folder.
    for copy in [
        "/tmp/lunepack-service",
        "/home/user/lunepack-service",
        "/Users/user/Downloads/lunepack-service",
    ] {
        assert_eq!(
            refused(Path::new(copy)),
            Err(LocationError::NotAServiceImage),
            "{copy}"
        );
    }
    // The right shape under the wrong parent.
    assert_eq!(
        refused(Path::new(
            "/tmp/x/.lunepack/machine/service/1.2.3/lunepack-service"
        )),
        Err(LocationError::NotUnderMachineHome)
    );
    // The Windows file name is not this OS's.
    let mut wrong_name = good.clone();
    wrong_name.set_file_name("lunepack-service.exe");
    assert_eq!(refused(&wrong_name), Err(LocationError::NotAServiceImage));
    // Another folder name at each level, or one level deeper.
    for bad in [
        root.join(".lunepack")
            .join("machine")
            .join("service")
            .join("1.2.3")
            .join("sub")
            .join("lunepack-service"),
        root.join(".lunepack")
            .join("machine")
            .join("other")
            .join("1.2.3")
            .join("lunepack-service"),
        root.join(".lunepack")
            .join("state")
            .join("service")
            .join("1.2.3")
            .join("lunepack-service"),
        root.join("app").join("lunepack-service"),
        // The stable link itself is not an image: the kernel never reports it.
        root.join(".lunepack")
            .join("machine")
            .join("lunepack-service"),
    ] {
        assert_eq!(
            refused(&bad),
            Err(LocationError::NotAServiceImage),
            "{bad:?}"
        );
    }
}

#[test]
fn a_version_directory_that_is_not_canonical_text_is_refused() {
    let root = home().join("hello");
    for version in ["1.2", "01.2.3", "v1.2.3", "latest", "1.2.3 ", "1.2.3+", ""] {
        assert_eq!(
            locate_unix(&image(&root, version), &home(), scheme()),
            Err(LocationError::NotAServiceImage),
            "{version:?}"
        );
    }
}

#[test]
fn a_path_with_dots_or_a_relative_one_is_refused_before_it_is_read() {
    let root = home().join("hello");
    let dotted = home()
        .join("hello")
        .join("..")
        .join("hello")
        .join(".lunepack")
        .join("machine")
        .join("service")
        .join("1.2.3")
        .join("lunepack-service");
    assert_eq!(
        locate_unix(&dotted, &home(), scheme()),
        Err(LocationError::NotAServiceImage)
    );
    // `.`, a doubled and a trailing separator: spellings the kernel never reports.
    for text in [
        "/lunepack-service-test-home/./hello/.lunepack/machine/service/1.2.3/lunepack-service",
        "/lunepack-service-test-home//hello/.lunepack/machine/service/1.2.3/lunepack-service",
        "/lunepack-service-test-home/hello/.lunepack/machine/service/1.2.3/lunepack-service/",
    ] {
        assert_eq!(
            locate_unix(Path::new(text), &home(), scheme()),
            Err(LocationError::NotAServiceImage),
            "{text}"
        );
    }
    assert_eq!(
        locate_unix(
            &image(&root, "1.2.3"),
            Path::new("/lunepack-service-test-home/"),
            scheme()
        ),
        Err(LocationError::NotUnderMachineHome)
    );
    assert_eq!(
        locate_unix(
            Path::new(".lunepack/machine/service/1.2.3/lunepack-service"),
            &home(),
            scheme()
        ),
        Err(LocationError::NotAServiceImage)
    );
    // The same for the home: never trusted when relative or dotted, whatever it resolves to.
    for bad_home in [
        Path::new("lunepack-service-test-home"),
        Path::new("/lunepack-service-test-home/../lunepack-service-test-home"),
    ] {
        assert_eq!(
            locate_unix(&image(&root, "1.2.3"), bad_home, scheme()),
            Err(LocationError::NotUnderMachineHome),
            "{bad_home:?}"
        );
    }
}

#[test]
fn a_root_that_is_not_directly_under_the_machine_home_is_refused() {
    let other = PathBuf::from("/lunepack-service-test-other");
    let cases = [
        // Another parent.
        image(&other.join("hello"), "1.2.3"),
        // Deeper than a direct child (a folder a user could create).
        image(&home().join("vendor").join("hello"), "1.2.3"),
        // The home itself as the root: its own parent is not the home.
        image(&home(), "1.2.3"),
        // A name sharing a prefix with the home.
        image(
            &PathBuf::from("/lunepack-service-test-home2").join("hello"),
            "1.2.3",
        ),
        // The same letters in another case: the comparison is exact.
        image(
            &PathBuf::from("/LUNEPACK-SERVICE-TEST-HOME").join("hello"),
            "1.2.3",
        ),
    ];
    for case in cases {
        assert_eq!(
            locate_unix(&case, &home(), scheme()),
            Err(LocationError::NotUnderMachineHome),
            "{case:?}"
        );
    }
}

#[test]
fn a_root_not_named_by_a_valid_app_id_is_refused() {
    for name in ["Hello App", "-", "a b", "..", "hello.", "con"] {
        let case = image(&home().join(name), "1.2.3");
        assert!(
            locate_unix(&case, &home(), scheme()).is_err(),
            "{name:?} must not be a service root"
        );
    }
}

// ---- the machine home ---------------------------------------------------------------------------

#[test]
fn the_machine_home_is_the_one_the_kernel_names() {
    let dir = tempfile::tempdir().unwrap();
    let resolved = resolve_home(dir.path()).unwrap();
    // The scratch folder lies behind a link on macOS (`/var` -> `/private/var`): the answer is the
    // resolved form, which is what the kernel reports for an image under it.
    #[cfg(target_os = "macos")]
    assert_eq!(
        resolved,
        lunepack_os_macos::libproc::kernel_path(dir.path()).unwrap(),
        "the same source the in-use scan compares against"
    );
    #[cfg(target_os = "linux")]
    assert_eq!(resolved, std::fs::canonicalize(dir.path()).unwrap());
    // A constant that does not exist, or cannot be read, is an error (the host exits 3).
    assert!(resolve_home(&dir.path().join("missing")).is_err());
}

#[test]
fn the_machine_home_constant_comes_from_the_scheme_not_the_environment() {
    // `machine_home` takes no argument and reads no variable: on a machine without the folder it
    // fails, on one with it, it is that folder.
    match machine_home() {
        Ok(path) => assert!(path.is_absolute()),
        Err(_) => assert!(!Path::new(SCHEME.home.unwrap()).exists()),
    }
}

// ---- the first actions of the host --------------------------------------------------------------

fn install_root(dir: &Path, app: &str) -> (PathBuf, PathBuf) {
    let root = dir.join(app);
    let image = image(&root, "1.0.0");
    (root, image)
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn a_copy_in_the_wrong_place_exits_with_the_location_code_and_does_nothing() {
    let scratch = tempfile::tempdir().unwrap();
    let home = scratch.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let elsewhere = scratch.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    for mode in [Mode::Service, Mode::SelfTest] {
        let (_, image) = install_root(&elsewhere, "hello");
        let mut err = Vec::new();
        assert_eq!(run_at(mode, &image, &home, &mut err), exit::LOCATION);
        assert!(err.is_empty(), "no output before the rule passes");
        assert!(entries(&home).is_empty(), "nothing was written");
        assert_eq!(entries(&elsewhere), Vec::<String>::new());
    }
}

#[test]
fn started_outside_the_init_system_it_says_so_once_and_does_nothing_else() {
    let scratch = tempfile::tempdir().unwrap();
    let home = scratch.path().to_path_buf();
    let (root, image) = install_root(&home, "hello");
    let mut err = Vec::new();
    assert_eq!(run_at(Mode::Service, &image, &home, &mut err), exit::USAGE);
    let text = String::from_utf8(err).unwrap();
    assert_eq!(text.lines().count(), 1, "{text:?}");
    // No log, no lock, no folder: the root was never touched (it does not even exist).
    assert!(!root.exists());
    assert!(entries(&home).is_empty());
}

#[test]
fn the_self_test_of_a_tree_without_a_record_fails_with_the_engine_code() {
    let scratch = tempfile::tempdir().unwrap();
    let home = scratch.path().to_path_buf();
    let (root, image) = install_root(&home, "hello");
    std::fs::create_dir(&root).unwrap();
    let mut err = Vec::new();
    assert_eq!(
        run_at(Mode::SelfTest, &image, &home, &mut err),
        exit::ENGINE
    );
    assert!(err.is_empty());
    // The check wrote nothing.
    assert_eq!(entries(&root), Vec::<String>::new());
}

#[test]
fn the_socket_the_unit_names_is_derived_from_the_app_id_alone() {
    // The host takes its listener for the app the root is named by.
    let app = lunepack_core::AppId::parse("hello").unwrap();
    assert!(
        endpoint::socket_path(lunepack_core::UnixOs::Linux, &app)
            .to_string_lossy()
            .ends_with("hello.sock")
    );
}

// ---- the timed accept ---------------------------------------------------------------------------

#[test]
fn accept_within_returns_none_after_its_slice_without_a_client() {
    let dir = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let started = Instant::now();
    let got = accept_within(&listener, Duration::from_millis(200)).unwrap();
    assert!(got.is_none());
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(180) && took < Duration::from_secs(5),
        "{took:?}"
    );
    assert_eq!(ACCEPT_SLICE, Duration::from_secs(1));
}

#[test]
fn accept_within_returns_a_blocking_stream_for_a_client() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = UnixStream::connect(&path).unwrap();
    let mut stream = accept_within(&listener, Duration::from_secs(5))
        .unwrap()
        .expect("a client");
    // A blocking stream waits for its read timeout; a non-blocking one fails at once.
    stream
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let started = Instant::now();
    let mut buf = [0u8; 1];
    let err = stream.read(&mut buf).unwrap_err();
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        "{err:?}"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(100),
        "{:?}",
        started.elapsed()
    );
    drop(client);
}

// ---- the binary ----------------------------------------------------------------------------------

#[test]
fn the_binary_reads_no_environment_but_its_arguments() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        // The Windows host asks the system for its own image path; it never runs here.
        if name == "host.rs" {
            continue;
        }
        for (n, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            // Every use of `std::env` or `env::`: only the one read of the command line, in main.
            for word in ["env::", "getenv", "environ"] {
                if line.contains(word) {
                    assert!(
                        name == "main.rs" && line.contains("env::args_os"),
                        "{name}:{} names {word}",
                        n + 1
                    );
                }
            }
        }
    }
}
