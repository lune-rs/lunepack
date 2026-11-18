//! The binary's command line: without `--engine` it prints one usage line to stderr, writes nothing
//! to stdout and exits 2. (No test here opens a window.)

use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lunepack-ui"))
        .args(args)
        .output()
        .expect("the binary starts")
}

#[test]
fn no_arguments_is_a_usage_error() {
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "standard output carries frames only");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err.lines().count(), 1, "one usage line: {err}");
    assert!(err.starts_with("usage: lunepack-ui --engine"));
}

#[test]
fn any_other_arguments_are_a_usage_error() {
    for args in [
        &["--demo"][..],
        &["--engine", "extra"],
        &["install"],
        &["--engine=1"],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty());
    }
}
