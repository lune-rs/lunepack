//! The bounded tool runner (M9-D3) with real processes. Own `main` (see Cargo.toml): this binary
//! is also the helper program the cases start (`--helper <mode> ...`), and the cases run one after
//! another. It compiles `src/tool.rs` itself, which has no dependency on the rest of the crate.
//!
//! Every planted value is made at run time; no case prints an environment or a config.

// The binary uses part of this module; the cases here use the rest.
#[allow(dead_code)]
#[path = "../src/tool.rs"]
mod tool;

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use tool::{OUTPUT_CAP, STDERR_TAIL, ToolError, is_batch_script, run_captured, run_tool};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--helper") {
        helper(&args[1..]);
        return;
    }
    let filter = args.iter().find(|a| !a.starts_with('-'));
    let mut failed = 0;
    for (name, test) in TESTS {
        if filter.is_some_and(|f| !name.contains(f.as_str())) {
            continue;
        }
        let dir = std::env::temp_dir().join(format!("lunepack-tool-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch");
        let result = std::panic::catch_unwind(|| test(&dir));
        let _ = std::fs::remove_dir_all(&dir);
        match result {
            Ok(()) => println!("test {name} ... ok"),
            Err(_) => {
                println!("test {name} ... FAILED");
                failed += 1;
            }
        }
    }
    if failed > 0 {
        std::process::exit(1);
    }
}

// ---- the helper program ----------------------------------------------------------------------------

/// What the helper does, by its first argument. A crash is never simulated with an abort (repo
/// lesson 2026-11-20): a helper that must fail exits nonzero.
fn helper(args: &[String]) {
    let arg = |i: usize| args.get(i).map(String::as_str).unwrap_or("");
    match arg(0) {
        // Prints its second argument on stdout.
        "say" => print!("{}", arg(1)),
        // Prints its second argument on stderr and exits with status 3.
        "fail-with" => {
            eprint!("{}", arg(1));
            std::process::exit(3);
        }
        // Exits with status 3 and prints nothing.
        "fail-quiet" => std::process::exit(3),
        // Reads standard input to its end and prints how many bytes it held.
        "stdin-len" => {
            let mut n = 0;
            let mut buf = [0u8; 256];
            let mut stdin = std::io::stdin();
            while let Ok(read) = stdin.read(&mut buf) {
                if read == 0 {
                    break;
                }
                n += read;
            }
            print!("{n}");
        }
        // Writes N bytes to stdout and N to stderr.
        "flood" => {
            let n: usize = arg(1).parse().expect("byte count");
            let chunk = vec![b'z'; 64 * 1024];
            for stream in 0..2 {
                let mut left = n;
                while left > 0 {
                    let take = left.min(chunk.len());
                    let wrote = if stream == 0 {
                        std::io::stdout().write_all(&chunk[..take])
                    } else {
                        std::io::stderr().write_all(&chunk[..take])
                    };
                    if wrote.is_err() {
                        return;
                    }
                    left -= take;
                }
            }
        }
        // Writes A filler bytes, then its second argument, then exits 3, all on stderr.
        "fill-then" => {
            let fill: usize = arg(1).parse().expect("filler length");
            let mut err = std::io::stderr();
            let _ = err.write_all(&vec![b'a'; fill]);
            let _ = err.write_all(arg(2).as_bytes());
            let _ = err.write_all(&vec![b'b'; 10_000]);
            std::process::exit(3);
        }
        // Sleeps S milliseconds, then creates the file named by its third argument.
        "sleep-then-mark" => {
            let ms: u64 = arg(1).parse().expect("milliseconds");
            std::thread::sleep(Duration::from_millis(ms));
            std::fs::write(arg(2), b"ran").expect("write marker");
        }
        other => {
            eprintln!("unknown helper mode {other}");
            std::process::exit(64);
        }
    }
}

fn exe() -> OsString {
    std::env::current_exe()
        .expect("current exe")
        .into_os_string()
}

fn helper_argv(mode: &[&str]) -> Vec<OsString> {
    let mut argv = vec![exe(), OsString::from("--helper")];
    argv.extend(mode.iter().map(OsString::from));
    argv
}

/// A value no real output contains.
fn planted(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("planted-{tag}-{}-{nanos}", std::process::id())
}

// ---- the cases -------------------------------------------------------------------------------------

type TestFn = fn(&Path);

const TESTS: &[(&str, TestFn)] = &[
    ("a_success_returns_its_output", success_output),
    ("a_nonzero_exit_names_the_status", nonzero_exit),
    ("standard_input_is_null", stdin_is_null),
    ("output_is_capped_and_does_not_deadlock", output_capped),
    ("a_run_past_its_timeout_is_killed", timeout_kills),
    (
        "a_planted_env_value_is_redacted_from_stderr",
        redacts_stderr,
    ),
    (
        "a_value_cut_by_the_output_cap_is_not_shown",
        redacts_cut_value,
    ),
    ("the_tail_is_at_most_4_kib", tail_is_bounded),
    (
        "an_error_never_shows_the_argv_or_a_value",
        no_argv_in_errors,
    ),
    (
        "a_missing_program_names_only_its_file_name",
        missing_program,
    ),
    ("an_empty_argv_is_refused", empty_argv),
    ("batch_script_names_are_recognised", batch_names),
    #[cfg(windows)]
    ("a_batch_script_is_refused_before_it_runs", batch_refused),
];

fn success_output(_: &Path) {
    let out = run_tool(
        &helper_argv(&["say", "hello"]),
        Duration::from_secs(30),
        &[],
    )
    .unwrap();
    assert_eq!(out.stdout, b"hello");
    assert!(out.stderr.is_empty());
}

fn nonzero_exit(_: &Path) {
    let e = run_tool(
        &helper_argv(&["fail-with", "it broke"]),
        Duration::from_secs(30),
        &[],
    )
    .unwrap_err();
    let text = e.to_string();
    assert!(matches!(e, ToolError::Failed { .. }), "{text}");
    assert!(text.contains("it broke") && text.contains('3'), "{text}");
    // The status and the program's file name only: not the path of the program.
    let dir = Path::new(&exe()).parent().unwrap().display().to_string();
    assert!(!text.contains(&dir), "{text}");
}

fn stdin_is_null(_: &Path) {
    let started = Instant::now();
    let out = run_tool(&helper_argv(&["stdin-len"]), Duration::from_secs(30), &[]).unwrap();
    assert_eq!(out.stdout, b"0");
    assert!(started.elapsed() < Duration::from_secs(20));
}

fn output_capped(_: &Path) {
    // 10 MiB on each stream: more than any pipe holds, so a runner that did not drain both while
    // waiting would block the child until the timeout.
    let started = Instant::now();
    let c = run_captured(
        &helper_argv(&["flood", &(10 * 1024 * 1024).to_string()]),
        Duration::from_secs(60),
    )
    .unwrap();
    assert!(c.status.success());
    assert_eq!(c.stdout.len(), OUTPUT_CAP);
    assert_eq!(c.stderr.len(), OUTPUT_CAP);
    assert!(c.stdout_truncated && c.stderr_truncated);
    assert!(started.elapsed() < Duration::from_secs(50));
    // Under the cap nothing is marked truncated.
    let c = run_captured(&helper_argv(&["flood", "100"]), Duration::from_secs(30)).unwrap();
    assert_eq!((c.stdout.len(), c.stderr.len()), (100, 100));
    assert!(!c.stdout_truncated && !c.stderr_truncated);
}

fn timeout_kills(dir: &Path) {
    // The helper would create the marker after 2 s; killed at 200 ms it never does.
    let marker = dir.join("marker");
    let mut argv = helper_argv(&["sleep-then-mark", "2000"]);
    argv.push(marker.clone().into_os_string());
    let started = Instant::now();
    let e = run_tool(&argv, Duration::from_millis(200), &[]).unwrap_err();
    assert!(e.is_timeout(), "{e}");
    assert!(e.to_string().contains("timed out"), "{e}");
    assert!(started.elapsed() < Duration::from_secs(10));
    std::thread::sleep(Duration::from_millis(3500));
    assert!(!marker.exists(), "the child outlived its kill");
}

fn redacts_stderr(_: &Path) {
    let value = planted("a");
    let other = planted("b");
    let argv = helper_argv(&["fail-with", &format!("bad {value} and {other} end")]);
    let redact = vec![
        ("SIGN_ID".to_owned(), OsString::from(&value)),
        ("KEY_ID".to_owned(), OsString::from(&other)),
    ];
    let e = run_tool(&argv, Duration::from_secs(30), &redact).unwrap_err();
    let text = e.to_string();
    assert!(
        text.contains("<SIGN_ID>") && text.contains("<KEY_ID>"),
        "{text}"
    );
    assert!(
        !text.contains(&value) && !text.contains(&other),
        "a value is shown"
    );
    assert!(
        !format!("{e:?}").contains(&value),
        "a value is in the debug text"
    );
}

fn redacts_cut_value(_: &Path) {
    // The value straddles the 64 KiB cap, so the captured text ends in its first bytes.
    let value = planted("cut");
    let fill = OUTPUT_CAP - 8;
    let argv = helper_argv(&["fill-then", &fill.to_string(), &value]);
    let redact = vec![("SIGN_ID".to_owned(), OsString::from(&value))];
    let e = run_tool(&argv, Duration::from_secs(30), &redact).unwrap_err();
    let text = e.to_string();
    assert!(
        !text.contains(&value[..8]),
        "the start of a cut value is shown"
    );
}

fn tail_is_bounded(_: &Path) {
    let argv = helper_argv(&["fill-then", "20000", "X"]);
    let e = run_tool(&argv, Duration::from_secs(30), &[]).unwrap_err();
    let ToolError::Failed { stderr_tail, .. } = e else {
        panic!("not a failure");
    };
    assert!(stderr_tail.len() <= STDERR_TAIL, "{}", stderr_tail.len());
    // It is the tail, not the head.
    assert!(stderr_tail.ends_with('b'));
}

fn no_argv_in_errors(_: &Path) {
    // A value that went into argv through `{env:}` and another argument that did not.
    let value = planted("env");
    let arg = planted("arg");
    let mut argv = helper_argv(&["fail-quiet"]);
    argv.push(OsString::from(&value));
    argv.push(OsString::from(&arg));
    let redact = vec![("SIGN_ID".to_owned(), OsString::from(&value))];
    let e = run_tool(&argv, Duration::from_secs(30), &redact).unwrap_err();
    let shown = format!("{e} | {e:?}");
    assert!(
        !shown.contains(&value) && !shown.contains(&arg),
        "argv shown"
    );
    // The same for a timeout and a failed start.
    let mut slow = helper_argv(&["sleep-then-mark", "5000"]);
    slow.push(OsString::from(&value));
    let e = run_tool(&slow, Duration::from_millis(100), &redact).unwrap_err();
    let shown = format!("{e} | {e:?}");
    assert!(!shown.contains(&value), "argv shown after a timeout");
}

fn missing_program(dir: &Path) {
    let program = dir.join("no-such-tool-here");
    let e = run_tool(
        &[
            program.clone().into_os_string(),
            OsString::from("--secret-looking"),
        ],
        Duration::from_secs(5),
        &[],
    )
    .unwrap_err();
    let text = e.to_string();
    assert!(matches!(e, ToolError::Spawn { .. }), "{text}");
    assert!(text.contains("no-such-tool-here"), "{text}");
    assert!(!text.contains(&dir.display().to_string()), "{text}");
    assert!(!text.contains("--secret-looking"), "{text}");
}

fn empty_argv(_: &Path) {
    let e = run_tool(&[], Duration::from_secs(5), &[]).unwrap_err();
    assert!(matches!(e, ToolError::EmptyArgv));
}

fn batch_names(_: &Path) {
    for yes in [
        "x.bat",
        "x.BAT",
        "x.cmd",
        "x.Cmd",
        "x.cmd.",
        "x.cmd ",
        "x.bat. .",
        "C:\\tools\\sign.cmd",
        "/tools/sign.bat",
    ] {
        assert!(is_batch_script(yes.as_ref()), "{yes:?}");
    }
    for no in [
        "x.exe",
        "x",
        "signtool",
        "x.bat.exe",
        "cmd",
        "x.cmd.exe",
        "",
    ] {
        assert!(!is_batch_script(no.as_ref()), "{no:?}");
    }
}

/// A planted batch file that would write a marker is refused in every spelling Win32 would resolve
/// to it, and never runs.
#[cfg(windows)]
fn batch_refused(dir: &Path) {
    let marker = dir.join("marker");
    let script = dir.join("x.cmd");
    std::fs::write(&script, format!("@echo ran> \"{}\"\r\n", marker.display())).unwrap();
    let base = script.display().to_string();
    let bat = dir.join("x.BAT");
    std::fs::write(&bat, format!("@echo ran> \"{}\"\r\n", marker.display())).unwrap();
    for name in [
        base.clone(),
        format!("{base}."),
        format!("{base} "),
        bat.display().to_string(),
    ] {
        let e = run_tool(&[OsString::from(&name)], Duration::from_secs(10), &[]).unwrap_err();
        assert!(matches!(e, ToolError::BatchScript { .. }), "{e}");
    }
    assert!(!marker.exists(), "a batch file ran");
}
