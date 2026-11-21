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
