//! Compiles the C example (`examples/c/example.c`) against the library this build made, with the
//! strictest warnings the toolchain has, and runs its self-test (M14 step 5). A machine with no C
//! compiler fails this test: the C ABI is only proved by a C caller.
//!
//! The library comes from the `deps` directory next to this test's executable (`cargo test` builds
//! the cdylib there before the tests run) and is found by listing it, never by an assumed name.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The target triple this crate was built for (`build.rs`).
const TARGET: &str = env!("LUNEPACK_FFI_TARGET");

/// The variables the example writes its protocol lines to; a run that does not want them clears them.
const LOG_VARIABLES: [&str; 2] = ["LUNEPACK_E2E_OUT", "LUNEPACK_E2E_DETAIL"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate sits two levels below the workspace root")
        .to_path_buf()
}

/// The library files in `deps`: the shared library, and on Windows its import library.
fn library_files() -> (PathBuf, Option<PathBuf>) {
    let deps = std::env::current_exe()
        .expect("current exe")
        .parent()
        .expect("deps directory")
        .to_path_buf();
    let names: Vec<(String, PathBuf)> = fs::read_dir(&deps)
        .expect("list deps")
        .map(|e| e.expect("entry").path())
        .filter_map(|p| Some((p.file_name()?.to_str()?.to_owned(), p)))
        .collect();
    let pick = |matches: &dyn Fn(&str) -> bool, what: &str| -> PathBuf {
        let found: Vec<&PathBuf> = names
            .iter()
            .filter(|(n, _)| matches(n))
            .map(|(_, p)| p)
            .collect();
        assert!(
            found.len() == 1,
            "expected exactly one {what} in {}, found {found:?}; entries named lunepack_ffi: {:?}",
            deps.display(),
            names
                .iter()
                .filter(|(n, _)| n.contains("lunepack_ffi"))
                .map(|(n, _)| n)
                .collect::<Vec<_>>()
        );
        found[0].clone()
    };
    if cfg!(windows) {
        let dll = pick(&|n| n == "lunepack_ffi.dll", "lunepack_ffi.dll");
        // `lunepack_ffi.dll.lib` for MSVC, whatever the toolchain calls it otherwise.
        let import = pick(
            &|n| n.starts_with("lunepack_ffi") && n.ends_with(".lib"),
            "import library (lunepack_ffi*.lib)",
        );
        (dll, Some(import))
    } else if cfg!(target_os = "macos") {
        (
            pick(&|n| n == "liblunepack_ffi.dylib", "liblunepack_ffi.dylib"),
            None,
        )
    } else {
        (
            pick(&|n| n == "liblunepack_ffi.so", "liblunepack_ffi.so"),
            None,
        )
    }
}

fn compiler() -> cc::Tool {
    cc::Build::new()
        .target(TARGET)
        .host(TARGET)
        .opt_level(0)
        .debug(false)
        .cargo_metadata(false)
        .cargo_warnings(false)
        .try_get_compiler()
        .unwrap_or_else(|e| panic!("no C compiler for {TARGET}: {e}"))
}

fn run(mut command: Command, what: &str) -> Output {
    let output = command
        .output()
        .unwrap_or_else(|e| panic!("{what}: cannot start {command:?}: {e}"));
    assert!(
        output.status.success(),
        "{what} failed ({}):\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// A scratch directory under cargo's target tmp dir, emptied first.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("c_example-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// Builds the example in `dir` beside a copy of the library; returns the executable.
fn build_example(dir: &Path) -> PathBuf {
    let root = workspace_root();
    let include = root.join("crates/lunepack-ffi/include");
    let source = root.join("examples/c/example.c");
    let (lib, import) = library_files();
    let lib_copy = dir.join(lib.file_name().expect("library name"));
    fs::copy(&lib, &lib_copy).expect("copy the library beside the executable");
    let tool = compiler();
    let mut cmd = tool.to_command();
    cmd.current_dir(dir);
    let exe;
    if tool.is_like_msvc() {
        exe = dir.join("example.exe");
        let import = import.expect("an import library on Windows");
        let import_copy = dir.join(import.file_name().expect("import name"));
        fs::copy(&import, &import_copy).expect("copy the import library");
        cmd.args(["/nologo", "/W4", "/WX"])
            .arg(format!("/I{}", include.display()))
            .arg(&source)
            .arg(format!("/Fe{}", exe.display()))
            .arg(format!("/Fo{}", dir.join("example.obj").display()))
            .arg("/link")
            .arg(&import_copy);
    } else {
        exe = dir.join("example");
        cmd.args(["-std=c99", "-Wall", "-Wextra", "-Werror"])
            .arg("-I")
            .arg(&include)
            .arg(&source)
            .arg("-o")
            .arg(&exe)
            .arg("-L")
            .arg(dir)
            .arg("-llunepack_ffi");
        if cfg!(target_os = "macos") {
            cmd.arg("-Wl,-rpath,@executable_path");
        } else {
            cmd.arg("-Wl,-rpath,$ORIGIN");
        }
    }
    run(cmd, "compiling examples/c/example.c as C");
    exe
}

/// The command that checks `source` as C++, warning-free, without linking.
fn cpp_check_command(tool: &cc::Tool, dir: &Path, include: &Path, source: &Path) -> Command {
    let mut cmd = tool.to_command();
    cmd.current_dir(dir);
    if tool.is_like_msvc() {
        cmd.args(["/nologo", "/W4", "/WX", "/TP", "/Zs", "/EHsc"])
            .arg(format!("/I{}", include.display()))
            .arg(source);
    } else {
        cmd.args(["-x", "c++", "-Wall", "-Wextra", "-Werror", "-fsyntax-only"])
            .arg("-I")
            .arg(include)
            .arg(source);
    }
    cmd
}

/// The example also compiles as C++ (the header's `extern "C"`), warning-free. A toolchain with a C
/// compiler and no C++ one (the gate's Docker image has gcc without g++) cannot say, and is told
/// so on stderr: the C build and the self-test, which are the ABI's proof, never skip.
fn check_as_cpp(dir: &Path) {
    let root = workspace_root();
    let include = root.join("crates/lunepack-ffi/include");
    let tool = compiler();
    let probe = dir.join("probe.cpp");
    fs::write(&probe, "int main() { return 0; }\n").expect("write the C++ probe");
    if cpp_check_command(&tool, dir, &include, &probe)
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        eprintln!(
            "SKIPPED: the C++ check of examples/c/example.c: the C compiler cannot compile C++"
        );
        return;
    }
    let source = root.join("examples/c/example.c");
    run(
        cpp_check_command(&tool, dir, &include, &source),
        "compiling examples/c/example.c as C++",
    );
}

/// A command for the example with no protocol variable set.
fn example_command(exe: &Path, dir: &Path) -> Command {
    let mut cmd = Command::new(exe);
    cmd.current_dir(dir);
    for variable in LOG_VARIABLES {
        cmd.env_remove(variable);
    }
    cmd
}

#[test]
fn the_c_example_compiles_warning_free_and_its_selftest_passes() {
    let dir = scratch("selftest");
    let exe = build_example(&dir);
    check_as_cpp(&dir);
    let mut cmd = example_command(&exe, &dir);
    cmd.arg("--selftest");
    let output = run(cmd, "the example's --selftest");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "selftest ok"
    );
}

/// Outside an install the app cannot start its updater: it writes the protocol's `error startup`
/// line (the tree version is not known yet, so `-`) and exits 1, as the shell and .NET apps do.
#[test]
fn outside_an_install_the_example_writes_the_error_startup_line() {
    let dir = scratch("protocol");
    let exe = build_example(&dir);
    let log = dir.join("out.log");
    let status = example_command(&exe, &dir)
        .arg("--update")
        .env("LUNEPACK_E2E_OUT", &log)
        .status()
        .expect("run the example");
    assert_eq!(status.code(), Some(1));
    assert_eq!(fs::read_to_string(&log).expect("log"), "- error startup\n");
}
