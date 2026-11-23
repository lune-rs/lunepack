//! The all-users install of a Windows setup (M10 step 16), the parts that need no administrator,
//! no service and no machine: the hidden mode's command line, which no ordinary runtime has, and
//! the source rules of `src/machine.rs`. The flows (the offer, the hand-off, the refusals, the
//! elevated mode over fakes) are unit tests of the crate's own modules; the real hand-off with a
//! standard user is the end-to-end suite's (step 19).

use std::path::PathBuf;
use std::process::{Command, Stdio};

const RUNTIME: &str = env!("CARGO_BIN_EXE_lunepack-runtime");
const ID: &str = "0123456789abcdef0123456789abcdef";
const SID: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(RUNTIME)
        .args(args)
        .env_remove("LUNEPACK_HEALTH_TOKEN")
        .env("LUNEPACK_NO_UI", "1")
        .stdin(Stdio::null())
        .output()
        .expect("run the runtime");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The ordinary runtime has no `machine-install` mode and no `--all-users` option: the one fixed
/// usage line and exit 2, whatever the arguments are, and nothing else is printed.
#[test]
fn machine_install_is_not_a_mode_of_an_ordinary_runtime() {
    let events = ["--events", ID, "--for-sid", SID];
    let mut cases: Vec<Vec<&str>> = vec![
        [&["machine-install"][..], &events[..]].concat(),
        vec!["machine-install"],
        vec!["--all-users"],
        vec!["--all-users", "--silent"],
        vec!["setup", "--all-users"],
        [
            &["machine-install", "--events", "short", "--for-sid"][..],
            &[SID][..],
        ]
        .concat(),
        [
            &["machine-install", "--events", ID, "--for-sid"][..],
            &["not-a-sid"][..],
        ]
        .concat(),
    ];
    cases.push(vec![
        "machine-install",
        "--events",
        ID,
        "--events",
        ID,
        "--for-sid",
        SID,
    ]);
    for args in cases {
        let (code, stdout, stderr) = run(&args);
        assert_eq!(code, 2, "{args:?}: {stderr}");
        assert_eq!(stdout, "", "{args:?}");
        assert_eq!(
            stderr.trim_end(),
            "lunepack-runtime: usage error",
            "{args:?}"
        );
        // Nothing the caller passed comes back.
        assert!(!stderr.contains(ID) && !stderr.contains(SID), "{args:?}");
    }
}

fn source(name: &str) -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "src", name].iter().collect();
    std::fs::read_to_string(&path).expect("read the module")
}

/// The module that runs elevated reads no environment variable, makes no temporary directory,
/// looks at no current directory, and has no per-user lookup and no known folder of a user (M10-D14,
/// M10-D15): the words are put together here so this file does not trip its own scan.
#[test]
fn machine_install_module_has_no_ambient_input_and_no_per_user_lookup() {
    let machine = source("machine.rs");
    // The module's own tests (after the marker) may name anything; the code before them may not.
    let code = machine
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .expect("code before the tests");
    let needles = [
        ["std::", "env"].concat(),
        ["env", "::var"].concat(),
        ["temp", "_dir"].concat(),
        ["current", "_dir"].concat(),
        ["env", "::args"].concat(),
        ["Local", "AppData"].concat(),
        ["local", "_app_data"].concat(),
        ["user", "_program_files"].concat(),
        ["data", "_home"].concat(),
        ["resolve_root", "("].concat(),
        ["Scope::", "User"].concat(),
        ["Installation", "::from"].concat(),
    ];
    for needle in &needles {
        assert!(
            !code.contains(needle.as_str()),
            "machine.rs mentions `{needle}`"
        );
    }
    // The instrument: the scan finds a needle in a module that has it.
    let setup = source("setup.rs");
    assert!(
        setup.contains(needles[10].as_str()) || setup.contains(needles[9].as_str()),
        "the scan's needles do not occur where the per-user lookup is"
    );
    // The hand-off's per-user check is made in `setup.rs` and passed in; `machine.rs` is handed it.
    assert!(code.contains("user_install_there"));
}

/// The relay module reads nothing from the environment either (it runs in both processes).
#[test]
fn machine_install_relay_has_no_ambient_input() {
    let relay = source("relay.rs");
    let code = relay
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .expect("code before the tests");
    for needle in [
        ["std::", "env"].concat(),
        ["temp", "_dir"].concat(),
        ["current", "_dir"].concat(),
    ] {
        assert!(
            !code.contains(needle.as_str()),
            "relay.rs mentions `{needle}`"
        );
    }
}

/// The body of the function `signature` opens in `main.rs`, up to its closing brace at column 0.
#[cfg(unix)]
fn function_of(text: &str, signature: &str) -> String {
    let from = text
        .find(signature)
        .unwrap_or_else(|| panic!("no `{signature}` in main.rs"));
    let rest = &text[from..];
    let end = rest.find("\n}\n").expect("the function's end");
    rest[..end].to_owned()
}

/// M11-D9: the root side of a Linux setup (the elevated `machine-install --events stdout` copy and
/// `--all-users` as root) reads no environment variable, no working directory and nothing under any
/// home, and starts no window; the per-user side, which does all of that, is the instrument.
#[cfg(unix)]
#[test]
fn the_root_side_of_a_linux_setup_has_no_ambient_input() {
    let main = source("main.rs");
    let needles = [
        ["std::", "env"].concat(),
        ["env", "::var"].concat(),
        ["temp", "_dir"].concat(),
        ["current", "_dir"].concat(),
        ["data", "_home("].concat(),
        ["ui", "_for("].concat(),
        ["UiHost", "::start"].concat(),
        ["ui_host::", "ui_wanted"].concat(),
        ["XdgEnv", "::from_process"].concat(),
        ["Platform", "::native"].concat(),
    ];
    for name in ["fn linux_machine_install_mode(", "fn linux_root_setup("] {
        let body = function_of(&main, name);
        for needle in &needles {
            assert!(
                !body.contains(needle.as_str()),
                "{name} mentions `{needle}`"
            );
        }
    }
    // The scan finds those words where they are used: in the user's side of the same setup.
    let user_side = function_of(&main, "fn linux_user_setup(");
    assert!(user_side.contains(needles[0].as_str()));
    assert!(user_side.contains(needles[4].as_str()));
    assert!(user_side.contains(needles[7].as_str()));
    // The root's image is the one open of `/proc/self/exe`.
    let entry = function_of(
        &main,
        "fn setup_mode(args: &[std::ffi::OsString]) -> Option<Kind> {\n    use lunepack::Process as _;\n\n    let process = lunepack_os_linux",
    );
    assert!(entry.contains("/proc/self/exe"));
}

/// The new pieces of the relay and the machine module that run in the elevated copy name no
/// ambient input either (the existing scans above cover the whole files; this names the Linux
/// adapters, which sit in `machine.rs` before its tests).
#[cfg(unix)]
#[test]
fn the_linux_adapters_of_the_machine_module_have_no_ambient_input() {
    let machine = source("machine.rs");
    let code = machine
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .expect("code before the tests");
    let linux = code
        .split("pub mod native_linux {")
        .nth(1)
        .expect("the Linux adapters");
    assert!(linux.contains("MachineScheme::LINUX"));
    for needle in [
        ["std::", "env"].concat(),
        ["env", "::var"].concat(),
        ["XdgEnv", "::from_process"].concat(),
        ["from_process", "_env"].concat(),
    ] {
        assert!(
            !linux.contains(needle.as_str()),
            "native_linux mentions `{needle}`"
        );
    }
}

/// The names of the functions of `text` (code before its tests) that call `needle`, other than the
/// one that defines it.
#[cfg(unix)]
fn callers_of(text: &str, needle: &str) -> Vec<String> {
    let code = text
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .expect("code before the tests");
    let mut found = Vec::new();
    let mut current = String::new();
    for line in code.lines() {
        let trimmed = line.trim_start();
        let is_signature = trimmed.starts_with("fn ")
            || trimmed.starts_with("pub fn ")
            || trimmed.starts_with("pub(crate) fn ");
        if is_signature {
            current = trimmed
                .split("fn ")
                .nth(1)
                .and_then(|rest| rest.split(['(', '<']).next())
                .unwrap_or_default()
                .to_owned();
            // The definition itself is no call.
            if current == needle.trim_end_matches('(') {
                continue;
            }
        }
        if line.contains(needle)
            && !trimmed.starts_with("//")
            && current != needle.trim_end_matches('(')
            && !found.contains(&current)
        {
            found.push(current.clone());
        }
    }
    found
}

/// M11-D9, P3: what is installed from the setup's own image is installed by exactly the two Linux
/// root modes (the elevated copy and `--all-users` as root, both of a process whose euid is 0) and,
/// in step 10, the macOS `--pkg` mode: no other function constructs that trust.
#[cfg(unix)]
#[test]
fn only_the_root_modes_install_from_the_own_image() {
    let machine = source("machine.rs");
    let main = source("main.rs");
    let setup = source("setup.rs");
    let modes = source("modes.rs");
    let relay = source("relay.rs");
    let ui_host = source("ui_host.rs");
    // The one constructor of the trust is called by the shared install and nothing else.
    assert_eq!(
        callers_of(&machine, "stage_payload_own_image("),
        ["install_all_own_image"]
    );
    for (name, text) in [
        ("main.rs", &main),
        ("setup.rs", &setup),
        ("modes.rs", &modes),
        ("relay.rs", &relay),
        ("ui_host.rs", &ui_host),
    ] {
        assert!(
            callers_of(text, "stage_payload_own_image(").is_empty(),
            "{name} constructs the own-image trust"
        );
    }
    // The shared install is called by the stdout mode and, in `main.rs`, by the root `--all-users`.
    assert_eq!(
        callers_of(&machine, "install_all_own_image("),
        ["run_stdout_mode"]
    );
    assert_eq!(
        callers_of(&main, "install_all_own_image("),
        ["linux_root_setup"]
    );
    assert!(callers_of(&setup, "install_all_own_image(").is_empty());
    // The instrument: the scan finds a call where there is one.
    let finishers = callers_of(&machine, "events.finish(");
    assert!(
        finishers.iter().any(|f| f == "run_mode")
            && finishers.iter().any(|f| f == "run_stdout_mode"),
        "{finishers:?}"
    );
}
