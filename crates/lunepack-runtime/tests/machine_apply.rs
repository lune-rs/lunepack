//! Apply, supervise, repair and uninstall on machine installs (M10 step 18), the parts that need
//! no administrator, no service and no machine: the hidden modes' command lines, which no ordinary
//! runtime has off Windows and which refuse everything an ordinary run gives them on it, and the
//! source rules that keep the five commands away from the elevation port. The flows (apply over the
//! engine, the elevated modes over fakes, the standing matrix of `repair`) are unit tests of the
//! crate's own modules; the real cycle with a standard user is the end-to-end suite's (step 19).

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

/// The hidden modes do nothing for an ordinary run: off Windows they are not words of the grammar
/// (the one usage line), on Windows a runtime that is not an administrator's inside a machine tree
/// is a usage error too, and either way nothing is printed that names an argument.
#[test]
fn the_hidden_machine_modes_do_nothing_for_an_ordinary_run() {
    let events = ["--events", ID, "--for-sid", SID];
    let wait = ["--wait-pid", "4242", "--wait-start", "17"];
    let cases: Vec<Vec<&str>> = vec![
        [&["machine-repair"][..], &events[..]].concat(),
        [&["machine-uninstall"][..], &events[..]].concat(),
        [&["machine-uninstall"][..], &wait[..]].concat(),
        vec!["machine-repair"],
        vec!["machine-uninstall"],
        [
            &["machine-uninstall", "--install-root", "x"][..],
            &events[..],
        ]
        .concat(),
    ];
    for args in cases {
        let (code, stdout, stderr) = run(&args);
        assert_eq!(code, 2, "{args:?}: {stderr}");
        assert_eq!(stdout, "", "{args:?}");
        for value in [ID, SID, "4242", "x"] {
            assert!(!stderr.contains(value), "{args:?} echoed {value}");
        }
    }
}

fn source(name: &str) -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "src", name].iter().collect();
    std::fs::read_to_string(&path).expect("read the module")
}

/// The text of the item that starts at `name` in `code`: up to the next item at the same level.
fn item<'a>(code: &'a str, name: &str) -> &'a str {
    let at = code.find(name).unwrap_or_else(|| panic!("{name}"));
    let body = &code[at..];
    let end = body.find("\n}\n").map_or(body.len(), |n| n + 3);
    &body[..end]
}

/// Only `repair` receives the host that holds the elevation port: the other four commands are
/// functions that are never handed it (C4), and the apply module never names it.
#[test]
fn the_elevation_port_reaches_repair_and_nothing_else_of_the_commands() {
    let commands = source("cli/commands.rs");
    let code = commands
        .split("\n#[cfg(test)]")
        .next()
        .expect("code before the tests");
    for name in [
        "fn check(",
        "fn download(",
        "fn startup(",
        "fn confirm(",
        "fn apply_and_restart(",
    ] {
        let text = item(code, name);
        for word in ["Host", "host", "elevation", "Elevation", "run_elevated"] {
            assert!(!text.contains(word), "{name} mentions `{word}`");
        }
    }
    // `run` hands the host to `repair` and to no other command: besides its own parameter, the
    // one line that names it is the `Repair` arm.
    let run_fn = item(code, "pub fn run(");
    let naming: Vec<&str> = run_fn.lines().filter(|l| l.contains("host")).collect();
    assert_eq!(naming.len(), 2, "{naming:?}");
    assert!(naming[0].contains("host: Option<&Host"), "{naming:?}");
    assert!(naming[1].contains("Command::Repair"), "{naming:?}");
    // The instrument: `repair` is the one that has them.
    let repair = item(code, "fn repair(");
    assert!(repair.contains("host") && repair.contains("machine::repair"));
    // The apply module reaches the service and the policy only, never the elevation.
    let apply = source("apply.rs");
    let apply_code = apply
        .split("\n#[cfg(test)]")
        .next()
        .expect("code before the tests");
    for word in ["Elevation", "run_elevated", "elevation"] {
        assert!(!apply_code.contains(word), "apply.rs mentions `{word}`");
    }
}

/// The apply on a machine install writes nothing under `R` or the registry itself, and takes no
/// lock there: its writes are the user's log through the events sink, and every change is a request
/// to the service.
#[test]
fn the_machine_apply_has_no_write_of_its_own() {
    let apply = source("apply.rs");
    let code = apply
        .split("\n#[cfg(test)]")
        .next()
        .expect("code before the tests");
    let start = code
        .find("// ---- the machine install (M10 step 18)")
        .expect("the machine section");
    let machine = &code[start..];
    for word in [
        ".create_new(",
        ".create_dir_all(",
        ".rename(",
        ".remove_file(",
        ".remove_dir_all",
        ".truncate(",
        ".commit(",
        "try_lock",
        "lock_retry",
        "set_exec",
        ".symlink(",
        "reconcile(",
    ] {
        assert!(!machine.contains(word), "the machine apply calls `{word}`");
    }
    // The instrument: the per-user section above it has them.
    assert!(code[..start].contains(".commit(") && code[..start].contains("lock_retry"));
}
