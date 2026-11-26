//! `build-example-c --out <dir> [--target <lunepack target id>]`: builds the C library
//! (`lunepack-ffi`, release) and the C example app (`examples/c/example.c`), and places the
//! executable `example` (`example.exe` on Windows) and the library beside it in `<dir>`, for the
//! end-to-end suites to pack as an app (M14). Nothing is written outside `<dir>` and `target/`.
//!
//! The C compiler is the one the `cc` crate finds for the target (`CC`, `CFLAGS` and the usual
//! variables apply); no compiler is an error, never a skip.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, anyhow, bail};

const USAGE: &str = "usage: build-example-c --out <dir> [--target <id>]";

/// The Rust target triple of each lunepack target id.
const TARGETS: &[(&str, &str)] = &[
    ("linux-x86_64", "x86_64-unknown-linux-gnu"),
    ("linux-aarch64", "aarch64-unknown-linux-gnu"),
    ("windows-x86_64", "x86_64-pc-windows-msvc"),
    ("macos-aarch64", "aarch64-apple-darwin"),
    ("macos-x86_64", "x86_64-apple-darwin"),
];

/// Runs the task.
pub fn main(args: impl IntoIterator<Item = String>) -> ExitCode {
    match parse(args).and_then(|(out, target)| run(&out, target.as_deref())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("build-example-c: error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn parse(args: impl IntoIterator<Item = String>) -> Result<(PathBuf, Option<String>)> {
    let mut args = args.into_iter();
    let mut out = None;
    let mut target = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => out = Some(args.next().ok_or_else(|| anyhow!("--out needs a value"))?),
            "--target" => {
                target = Some(
                    args.next()
                        .ok_or_else(|| anyhow!("--target needs a value"))?,
                );
            }
            other => bail!("unknown argument `{other}`; {USAGE}"),
        }
    }
    let out = out.ok_or_else(|| anyhow!("{USAGE}"))?;
    Ok((PathBuf::from(out), target))
}

/// The host's target triple, from `rustc -vV`.
fn host_triple() -> Result<String> {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc)
        .arg("-vV")
        .output()
        .context("cannot run rustc -vV")?;
    String::from_utf8(output.stdout)?
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("rustc -vV names no host"))
}

fn run(out: &Path, target_id: Option<&str>) -> Result<()> {
    let root = std::env::current_dir()?;
    if !root.join("examples/c/example.c").is_file() {
        bail!("run from the workspace root (examples/c/example.c not found)");
    }
    let host = host_triple()?;
    let (triple, cross) = match target_id {
        None => (host.clone(), false),
        Some(id) => {
            let triple = TARGETS
                .iter()
                .find(|(i, _)| *i == id)
                .map(|(_, t)| (*t).to_owned())
                .ok_or_else(|| {
                    anyhow!(
                        "unknown target `{id}`; targets: {}",
                        TARGETS
                            .iter()
                            .map(|(i, _)| *i)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })?;
            let cross = triple != host;
            (triple, cross)
        }
    };
    let windows = triple.contains("windows");
    let apple = triple.contains("apple");

    // The output directory must be absent or empty.
    if out.exists() {
        if !out.is_dir() || fs::read_dir(out)?.next().is_some() {
            bail!("{} exists and is not an empty directory", out.display());
        }
    } else {
        fs::create_dir_all(out).with_context(|| format!("cannot create {}", out.display()))?;
    }
    let out = fs::canonicalize(out)?;

    // The library, release.
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut build = Command::new(cargo);
    build.args(["build", "--release", "--locked", "-p", "lunepack-ffi"]);
    if cross {
        build.args(["--target", &triple]);
    }
    let status = build
        .current_dir(&root)
        .status()
        .context("cannot run cargo")?;
    if !status.success() {
        bail!("cargo build of lunepack-ffi failed ({status})");
    }
    let mut lib_dir = root.join("target");
    if cross {
        lib_dir.push(&triple);
    }
    lib_dir.push("release");
    let find = |matches: &dyn Fn(&str) -> bool, what: &str| -> Result<PathBuf> {
        let found: Vec<PathBuf> = fs::read_dir(&lib_dir)
            .with_context(|| format!("cannot list {}", lib_dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(matches))
            .collect();
        match found.as_slice() {
            [one] => Ok(one.clone()),
            _ => bail!(
                "expected exactly one {what} in {}, found {found:?}",
                lib_dir.display()
            ),
        }
    };
    let (lib, import) = if windows {
        (
            find(&|n| n == "lunepack_ffi.dll", "lunepack_ffi.dll")?,
            Some(find(
                &|n| n.starts_with("lunepack_ffi") && n.ends_with(".lib"),
                "import library (lunepack_ffi*.lib)",
            )?),
        )
    } else if apple {
        (
            find(&|n| n == "liblunepack_ffi.dylib", "liblunepack_ffi.dylib")?,
            None,
        )
    } else {
        (
            find(&|n| n == "liblunepack_ffi.so", "liblunepack_ffi.so")?,
            None,
        )
    };
    let place = |from: &Path| -> Result<PathBuf> {
        let to = out.join(from.file_name().expect("a file name"));
        fs::copy(from, &to).with_context(|| format!("cannot copy {}", from.display()))?;
        Ok(to)
    };
    place(&lib)?;
    let import = import.map(|i| place(&i)).transpose()?;

    // The example, with the toolchain `cc` finds for the target.
    let tool = cc::Build::new()
        .target(&triple)
        .host(&host)
        .opt_level(2)
        .debug(false)
        .cargo_metadata(false)
        .cargo_warnings(false)
        .try_get_compiler()
        .map_err(|e| anyhow!("no C compiler for {triple}: {e}"))?;
    let include = root.join("crates/lunepack-ffi/include");
    let source = root.join("examples/c/example.c");
    let mut cmd = tool.to_command();
    cmd.current_dir(&out);
    let exe = if windows {
        out.join("example.exe")
    } else {
        out.join("example")
    };
    if tool.is_like_msvc() {
        let import = import
            .as_ref()
            .ok_or_else(|| anyhow!("no import library"))?;
        cmd.args(["/nologo", "/W4", "/WX"])
            .arg(format!("/I{}", include.display()))
            .arg(&source)
            .arg(format!("/Fe{}", exe.display()))
            .arg(format!("/Fo{}", out.join("example.obj").display()))
            .arg("/link")
            .arg(import);
    } else {
        cmd.args(["-std=c99", "-Wall", "-Wextra", "-Werror"])
            .arg("-I")
            .arg(&include)
            .arg(&source)
            .arg("-o")
            .arg(&exe)
            .arg("-L")
            .arg(&out)
            .arg("-llunepack_ffi");
        cmd.arg(if apple {
            "-Wl,-rpath,@executable_path"
        } else {
            "-Wl,-rpath,$ORIGIN"
        });
    }
    let status = cmd
        .status()
        .with_context(|| format!("cannot start the C compiler {:?}", tool.path()))?;
    if !status.success() {
        bail!("compiling examples/c/example.c failed ({status})");
    }
    // MSVC leaves the object file and the copied import library in <dir>: the app needs the
    // executable and the DLL only.
    if windows {
        let _ = fs::remove_file(out.join("example.obj"));
        if let Some(import) = &import {
            let _ = fs::remove_file(import);
        }
    }
    println!(
        "build-example-c: wrote {} and {}",
        exe.display(),
        lib.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("the library")
    );
    Ok(())
}
