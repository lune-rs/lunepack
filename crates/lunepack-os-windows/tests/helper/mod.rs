//! The helper program: this test binary run with a helper mode as its first argument. It speaks
//! the protocol of `lunepack_testkit::run_process_suite` plus the modes of this crate's tests:
//!
//! - `pid-sleep <file> <secs>`: creates `file` holding `<pid> <start ticks>`, then sleeps.
//! - `detach-then <exit|sleep> <mode> <arg>...`: starts this binary with `<mode> <arg>...` through
//!   `WindowsProcess::spawn_detached`, then exits 0 (`exit`) or sleeps for 600 s (`sleep`).
//! - `parent-report <file> <secs>`: sleeps `secs`, then creates `file` holding `none` or
//!   `<pid> <start ticks>` as `WindowsProcess::parent` says.
//! - `in-job <control-file> <file>`: puts itself in a job object that forbids breakaway, records in
//!   `control-file` whether a raw spawn with `CREATE_BREAKAWAY_FROM_JOB` is refused there
//!   (`denied`, the premise of the test) or not (`allowed`), then starts `write <file> done`
//!   through `WindowsProcess::spawn_detached`, which must work anyway.
//! - `load-dll <dll> <ready> <secs>`: loads the library at `dll` with `LoadLibraryW` (a real load,
//!   not a data mapping), creates `ready`, then sleeps `secs` with the library still loaded.
//! - `window <ready>`: creates a hidden top-level window, creates `ready`, and exits 0 once the
//!   window is destroyed (a `WM_CLOSE` does that).
//!
//! Every file is created atomically (`<file>.tmp`, then a rename).

use std::os::windows::process::CommandExt as _;
use std::path::Path;
use std::time::Duration;

use lunepack_core::{Process, SpawnSpec};
use lunepack_os_windows::WindowsProcess;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_CHAR, GetFileType};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetConsoleProcessList, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, LoadLibraryW};
use windows_sys::Win32::System::Threading::{CREATE_BREAKAWAY_FROM_JOB, GetCurrentProcess};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DispatchMessageW, IsWindow, MSG, PM_REMOVE, PeekMessageW, WS_POPUP,
};

const MODES: &[&str] = &[
    "exit",
    "sleep",
    "sleep-ignore-term",
    "write",
    "args",
    "env",
    "probe",
    "cat",
    "pid-sleep",
    "detach-then",
    "parent-report",
    "in-job",
    "window",
    "load-dll",
];

/// Runs the helper mode named by `args[0]` and never returns; `false` when `args` names no mode.
pub fn run(args: &[String]) -> bool {
    let Some(mode) = args.first() else {
        return false;
    };
    if !MODES.contains(&mode.as_str()) {
        return false;
    }
    let rest = &args[1..];
    match mode.as_str() {
        "exit" => std::process::exit(rest[0].parse().expect("exit code")),
        "sleep" => sleep(&rest[0]),
        "sleep-ignore-term" => {
            // Windows has no signal to ignore: the helper only reports that it is up.
            create(Path::new(&rest[1]), "ready\n");
            sleep(&rest[0]);
        }
        "write" => create(Path::new(&rest[0]), &rest[1]),
        "args" => {
            let text: String = rest[1..].iter().map(|a| format!("{a}\n")).collect();
            create(Path::new(&rest[0]), &text);
        }
        "env" => {
            let text: String = rest[1..]
                .iter()
                .map(|name| match std::env::var_os(name) {
                    Some(v) => format!("{name}={}\n", v.to_string_lossy()),
                    None => format!("{name} unset\n"),
                })
                .collect();
            create(Path::new(&rest[0]), &text);
        }
        "probe" => {
            let mut text = String::from(if has_console() {
                "console\n"
            } else {
                "no console\n"
            });
            for (id, name) in [
                (STD_INPUT_HANDLE, "stdin"),
                (STD_OUTPUT_HANDLE, "stdout"),
                (STD_ERROR_HANDLE, "stderr"),
            ] {
                text.push_str(&format!(
                    "{name} {}\n",
                    if is_nul(id) { "null" } else { "other" }
                ));
            }
            create(Path::new(&rest[0]), &text);
        }
        "cat" => {
            let mut input = std::io::stdin().lock();
            let mut output = std::io::stdout().lock();
            std::io::copy(&mut input, &mut output).expect("copy standard input to output");
            std::io::Write::flush(&mut output).expect("flush");
        }
        "pid-sleep" => {
            let me = WindowsProcess::new().current().expect("current");
            create(
                Path::new(&rest[0]),
                &format!("{} {}\n", me.pid, me.start_ticks),
            );
            sleep(&rest[1]);
        }
        "detach-then" => {
            let mut spec = SpawnSpec::new(std::env::current_exe().expect("current_exe"));
            spec.args = rest[1..].iter().map(Into::into).collect();
            WindowsProcess::new()
                .spawn_detached(&spec)
                .expect("spawn_detached");
            if rest[0] == "sleep" {
                sleep("600");
            }
        }
        "parent-report" => {
            sleep(&rest[1]);
            let text = match WindowsProcess::new().parent().expect("parent") {
                Some(p) => format!("{} {}\n", p.pid, p.start_ticks),
                None => "none\n".to_owned(),
            };
            create(Path::new(&rest[0]), &text);
        }
        "in-job" => in_job(&rest[0], &rest[1]),
        "window" => window(Path::new(&rest[0])),
        "load-dll" => {
            load_dll(&rest[0]);
            create(Path::new(&rest[1]), "ready\n");
            sleep(&rest[2]);
        }
        _ => unreachable!(),
    }
    std::process::exit(0);
}

fn sleep(secs: &str) {
    std::thread::sleep(Duration::from_secs(secs.parse().expect("seconds")));
}

fn create(path: &Path, text: &str) {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    std::fs::write(&tmp, text).expect("write the helper's file");
    std::fs::rename(&tmp, path).expect("rename the helper's file");
}

#[allow(unsafe_code)]
fn has_console() -> bool {
    let mut list = [0u32; 2];
    // SAFETY: the buffer holds the two ids the call is told about; it returns how many processes
    // share the console, or 0 when this process has none.
    unsafe { GetConsoleProcessList(list.as_mut_ptr(), 2) > 0 }
}

/// Whether the standard handle `id` is the `NUL` device: a character device that is not a console.
#[allow(unsafe_code)]
fn is_nul(id: u32) -> bool {
    // SAFETY: `GetStdHandle` takes a constant and returns a handle (or null or invalid).
    let handle: HANDLE = unsafe { GetStdHandle(id) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return false;
    }
    let mut mode = 0u32;
    // SAFETY: `handle` came from `GetStdHandle` above; `mode` is a valid out pointer.
    let (kind, console) = unsafe {
        (
            GetFileType(handle),
            GetConsoleMode(handle, &raw mut mode) != 0,
        )
    };
    kind == FILE_TYPE_CHAR && !console
}

#[allow(unsafe_code)]
fn in_job(control: &str, file: &str) {
    // SAFETY: both arguments of `CreateJobObjectW` may be null (default security, no name).
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    assert!(!job.is_null(), "create a job");
    // SAFETY: `job` is the handle just created (leaked on purpose: the job lives as long as this
    // process); the pseudo handle of this process is valid for the call.
    let assigned = unsafe { AssignProcessToJobObject(job, GetCurrentProcess()) } != 0;
    // The premise: inside this job a breakaway is refused.
    let refused = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["exit", "0"])
        .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
        .spawn()
        .map(|mut c| {
            let _ = c.wait();
        })
        .err()
        .and_then(|e| e.raw_os_error())
        == Some(5);
    create(
        Path::new(control),
        match (assigned, refused) {
            (true, true) => "denied\n",
            (true, false) => "allowed\n",
            (false, _) => "no job\n",
        },
    );
    let mut spec = SpawnSpec::new(std::env::current_exe().expect("current_exe"));
    spec.args = vec!["write".into(), file.into(), "done".into()];
    WindowsProcess::new()
        .spawn_detached(&spec)
        .expect("spawn_detached inside a job that forbids breakaway");
}

#[allow(unsafe_code)]
fn window(ready: &Path) {
    let class: Vec<u16> = "STATIC\0".encode_utf16().collect();
    let title: Vec<u16> = "lunepack test\0".encode_utf16().collect();
    // SAFETY: both strings are NUL-terminated and outlive the call; `STATIC` is a system class,
    // the style is a plain popup (hidden: never shown), no parent, menu or creation data.
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_POPUP,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        )
    };
    assert!(!hwnd.is_null(), "create a window");
    create(ready, "ready\n");
    // SAFETY: `msg` is plain integers, for which all-zero is valid.
    let mut msg: MSG = unsafe { std::mem::zeroed() };
    // SAFETY: `hwnd` is a window of this thread; the message calls take this thread's queue.
    while unsafe { IsWindow(hwnd) } != 0 {
        // SAFETY: `msg` is a valid out pointer; a null window filters nothing.
        while unsafe { PeekMessageW(&raw mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) } != 0 {
            // SAFETY: `msg` was filled by `PeekMessageW`.
            unsafe { DispatchMessageW(&raw const msg) };
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[allow(unsafe_code)]
fn load_dll(path: &str) {
    let wide: Vec<u16> = path.encode_utf16().chain([0]).collect();
    // SAFETY: `wide` is NUL-terminated and outlives the call; the module handle is leaked on
    // purpose, so the library stays loaded for as long as this process runs.
    let module = unsafe { LoadLibraryW(wide.as_ptr()) };
    assert!(!module.is_null(), "load the library");
}
