//! [`WindowsProcess`]: the core's [`Process`] over `std::process` and the Win32 process APIs.
//!
//! - A process is `{pid, start_ticks}` with `start_ticks` its creation time (the 64-bit `FILETIME`
//!   of `GetProcessTimes`). A reused pid is always a younger process, so it never matches.
//! - Programs start through `std::process::Command` with an absolute path: no shell, no `PATH`
//!   lookup. `env_remove` is applied before `env_set`. A piped child gets anonymous pipes from
//!   `std`, whose parent ends are not inheritable; its error stream stays null.
//! - A detached program starts with `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP |
//!   CREATE_NO_WINDOW` and also `CREATE_BREAKAWAY_FROM_JOB`, so a job that kills its members on
//!   close (a CI runner, a launcher) does not take it along; when the job forbids breakaway the
//!   start is retried without that flag. Its streams are null.
//! - Waiting opens the pid, checks the creation time on that very handle, then waits on the
//!   handle: no polling, and no window between the check and the wait in which the pid could be
//!   reused.
//! - [`Child::terminate`] first asks (`WM_CLOSE` to the child's top-level windows; a child without
//!   a window cannot be asked), waits up to the grace period, then ends the process.
//! - `tree_in_use` compares the image path of every other process with the tree after
//!   canonicalising both, never by string prefix. It skips a process it cannot open, so it is not a
//!   removal guard; `tree_in_use_strict` is (M10-D20): the same scan, then a file-system probe that
//!   opens every file and directory of the tree the way a deletion would and treats any refusal as
//!   "in use".

use core::time::Duration;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStringExt as _;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle, RawHandle};
use std::os::windows::process::CommandExt as _;
use std::path::{Component, Path, PathBuf, Prefix};
use std::process::{Command, Stdio};
use std::time::Instant;

use lunepack_core::{
    Child, ChildStdio, Error, ExitKind, Process, ProcessError, ProcessErrorKind, ProcessId,
    SpawnSpec, WaitOutcome,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES, FILETIME, HWND,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA, SYNCHRONIZE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, DETACHED_PROCESS,
    GetCurrentProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW, WaitForSingleObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_CLOSE,
};

/// What a process handle is opened for: its creation time and image path, and waiting on it.
const ACCESS: u32 = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
/// The longest single wait handed to the OS: `INFINITE` is `u32::MAX`, so stay below it.
const MAX_WAIT_MS: u128 = 0xFFFF_FFFE;
/// How often [`Child::terminate`] looks at the child during the grace period.
const TERMINATE_POLL: Duration = Duration::from_millis(10);

/// The Windows [`Process`].
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsProcess {
    _private: (),
}

impl WindowsProcess {
    /// The process adapter.
    pub fn new() -> WindowsProcess {
        WindowsProcess { _private: () }
    }

    /// The id of the running process `pid` (its pid and creation time), or `None` when no such
    /// process runs (gone, or ended with its handle still held elsewhere). Used to name a wait
    /// target given only by its pid.
    pub fn process_id(&self, pid: u32) -> Result<Option<ProcessId>, Error> {
        let Ok(handle) = open_process(pid, ACCESS) else {
            return Ok(None);
        };
        if has_ended(&handle).map_err(|e| unreadable("process id", e))? {
            return Ok(None);
        }
        let start_ticks =
            creation_time(handle.as_raw_handle()).map_err(|e| unreadable("process id", e))?;
        Ok(Some(ProcessId { pid, start_ticks }))
    }
}

fn unreadable(op: &'static str, err: io::Error) -> Error {
    ProcessError::new(ProcessErrorKind::Unreadable, op)
        .caused_by(err)
        .into()
}

fn spawn_error(err: io::Error, program: &Path) -> Error {
    let kind = match err.kind() {
        io::ErrorKind::NotFound => ProcessErrorKind::NotFound,
        io::ErrorKind::PermissionDenied => ProcessErrorKind::PermissionDenied,
        io::ErrorKind::InvalidInput => ProcessErrorKind::InvalidRequest,
        _ => ProcessErrorKind::SpawnFailed,
    };
    ProcessError::new(kind, "spawn")
        .about(program)
        .caused_by(err)
        .into()
}

/// The command for `spec`: the error stream null, the others null or piped as the spec says.
fn command(spec: &SpawnSpec, flags: u32) -> Result<Command, Error> {
    if !spec.program.is_absolute() {
        return Err(ProcessError::new(ProcessErrorKind::InvalidRequest, "spawn")
            .about(&spec.program)
            .into());
    }
    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args);
    for name in &spec.env_remove {
        cmd.env_remove(name);
    }
    for (name, value) in &spec.env_set {
        cmd.env(name, value);
    }
    let piped = || match spec.stdio {
        ChildStdio::Piped => Stdio::piped(),
        _ => Stdio::null(),
    };
    cmd.stdin(piped()).stdout(piped()).stderr(Stdio::null());
    cmd.creation_flags(flags);
    Ok(cmd)
}

/// The sharing every probe open asks for: it conflicts with nothing a process holds except what
/// a deletion would conflict with.
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

/// Opens `path` as `OPEN_EXISTING` with `access`, full sharing and `flags`, and closes it at
/// once. Nothing is read, written, truncated or changed.
fn probe_open(path: &Path, access: u32, flags: u32) -> io::Result<()> {
    std::fs::OpenOptions::new()
        .access_mode(access)
        .share_mode(SHARE_ALL)
        .custom_flags(flags)
        .open(path)
        .map(drop)
}

/// Opens a directory or a reparse point (never followed) the way a deletion of it would.
fn probe_directory(path: &Path) -> io::Result<()> {
    probe_open(
        path,
        DELETE,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
}

/// Whether anything holds a file or directory of `tree` in a way that keeps it from being
/// deleted (M10-D20): an image mapped by any process, a working directory, a file or directory
/// held open without delete sharing, a read-only file. Every regular file is opened for
/// write-data and delete, every directory and reparse point (never followed or descended into)
/// for delete, all with full sharing and each closed before the next; the first open that fails,
/// for any reason, answers `true`. A failure to list or to read metadata is an error.
fn tree_files_held(tree: &Path) -> Result<bool, Error> {
    let tree = std::fs::canonicalize(tree).map_err(|e| ProcessError::from_io("in use", e))?;
    let held = |path: &Path, err: &io::Error| {
        tracing::debug!(
            code = ?err.raw_os_error(),
            leaf = ?path.file_name(),
            "a file of the tree cannot be opened for deletion: in use"
        );
        Ok(true)
    };
    if let Err(e) = probe_directory(&tree) {
        return held(&tree, &e);
    }
    let mut pending = vec![tree];
    while let Some(dir) = pending.pop() {
        // The listing is read in full first, so no listing handle is open while children are.
        let entries = std::fs::read_dir(&dir)
            .and_then(|it| {
                it.map(|e| e.map(|e| e.path()))
                    .collect::<io::Result<Vec<_>>>()
            })
            .map_err(|e| ProcessError::from_io("in use", e))?;
        for path in entries {
            let meta =
                std::fs::symlink_metadata(&path).map_err(|e| ProcessError::from_io("in use", e))?;
            let reparse = meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
            let opened = if reparse || meta.is_dir() {
                probe_directory(&path)
            } else {
                probe_open(
                    &path,
                    FILE_WRITE_DATA | DELETE,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                )
            };
            if let Err(e) = opened {
                return held(&path, &e);
            }
            if !reparse && meta.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(false)
}

// ---- the Win32 calls (every unsafe block of this module) --------------------------------------

#[allow(unsafe_code)]
fn open_process(pid: u32, access: u32) -> io::Result<OwnedHandle> {
    // SAFETY: `OpenProcess` takes three integers and returns a new handle or null.
    let raw = unsafe { OpenProcess(access, 0, pid) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a non-null handle this call just created and nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

/// The pseudo handle of this process (valid in this process only, never closed).
#[allow(unsafe_code)]
fn current_process() -> RawHandle {
    // SAFETY: `GetCurrentProcess` takes nothing and returns a constant pseudo handle.
    unsafe { GetCurrentProcess() }
}

/// The creation time of the process `handle` names (a `FILETIME` as a 64-bit number), which needs
/// `PROCESS_QUERY_LIMITED_INFORMATION`.
#[allow(unsafe_code)]
fn creation_time(handle: RawHandle) -> io::Result<u64> {
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: `handle` is a live process handle for the call (the caller owns it); the four out
    // pointers are distinct `FILETIME`s that live for the whole call.
    let ok = unsafe {
        GetProcessTimes(
            handle,
            &raw mut created,
            &raw mut exited,
            &raw mut kernel,
            &raw mut user,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// Whether the process behind `handle` has ended (the handle is signalled), without waiting.
#[allow(unsafe_code)]
fn has_ended(handle: &OwnedHandle) -> io::Result<bool> {
    // SAFETY: the handle is live for the call and was opened with `SYNCHRONIZE`; a zero timeout
    // makes this a poll.
    match unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Waits up to `timeout` for the process behind `handle` to end.
#[allow(unsafe_code)]
fn wait_handle(handle: &OwnedHandle, timeout: Duration) -> io::Result<WaitOutcome> {
    let deadline = Instant::now().checked_add(timeout);
    loop {
        let remaining = deadline.map(|d| d.saturating_duration_since(Instant::now()));
        // Rounded up, so a sub-millisecond timeout still waits.
        let wanted = remaining.map_or(MAX_WAIT_MS, |r| r.as_nanos().div_ceil(1_000_000));
        let ms = u32::try_from(wanted.min(MAX_WAIT_MS)).unwrap_or(u32::MAX - 1);
        // SAFETY: the handle is live for the call and was opened with `SYNCHRONIZE`; `ms` is
        // below `INFINITE`.
        match unsafe { WaitForSingleObject(handle.as_raw_handle(), ms) } {
            WAIT_OBJECT_0 => return Ok(WaitOutcome::Exited),
            // The whole remaining time has passed (a longer wait goes round again).
            WAIT_TIMEOUT if wanted <= MAX_WAIT_MS && remaining.is_some() => {
                return Ok(WaitOutcome::TimedOut);
            }
            WAIT_TIMEOUT => {}
            _ => return Err(io::Error::last_os_error()),
        }
    }
}

/// One row of a process snapshot.
struct Entry {
    pid: u32,
    parent: u32,
}

/// Every process the system lists right now.
#[allow(unsafe_code)]
fn snapshot() -> io::Result<Vec<Entry>> {
    // SAFETY: `CreateToolhelp32Snapshot` takes two integers and returns a handle or
    // `INVALID_HANDLE_VALUE`.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a valid handle this call just created and nothing else owns.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    // SAFETY: `PROCESSENTRY32W` is plain integers and arrays, for which all-zero is valid.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut out = Vec::new();
    // SAFETY: `handle` is a live snapshot handle; `entry` is a valid out pointer with `dwSize`
    // set, as the call requires.
    let mut more = unsafe { Process32FirstW(handle.as_raw_handle(), &raw mut entry) } != 0;
    if !more {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == i32::try_from(ERROR_NO_MORE_FILES).ok() {
            return Ok(out);
        }
        return Err(err);
    }
    while more {
        out.push(Entry {
            pid: entry.th32ProcessID,
            parent: entry.th32ParentProcessID,
        });
        // SAFETY: as for `Process32FirstW`.
        more = unsafe { Process32NextW(handle.as_raw_handle(), &raw mut entry) } != 0;
    }
    Ok(out)
}

/// The Win32-form image path of the process behind `handle`.
#[allow(unsafe_code)]
fn image_path(handle: RawHandle) -> io::Result<PathBuf> {
    let mut buf: Vec<u16> = vec![0; 1024];
    loop {
        let mut len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `handle` is a live process handle with query access; `buf` holds `len` units and
        // the call writes at most that many (and the terminator), setting `len` to the count
        // written without the terminator.
        let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &raw mut len) };
        if ok != 0 {
            return Ok(PathBuf::from(OsString::from_wide(&buf[..len as usize])));
        }
        let err = io::Error::last_os_error();
        let too_small = err.raw_os_error() == i32::try_from(ERROR_INSUFFICIENT_BUFFER).ok();
        if !too_small || buf.len() >= 65_536 {
            return Err(err);
        }
        buf = vec![0; buf.len() * 2];
    }
}

/// Posts `WM_CLOSE` to every top-level window of the process `pid`. Best effort.
#[allow(unsafe_code)]
fn ask_to_close(pid: u32) {
    unsafe extern "system" fn visit(window: HWND, target: isize) -> i32 {
        let mut owner = 0u32;
        // SAFETY: `window` is the handle `EnumWindows` passed in; `owner` is a valid out pointer.
        unsafe { GetWindowThreadProcessId(window, &raw mut owner) };
        // SAFETY: `target` is the address of the `u32` below, alive for the whole enumeration.
        if owner == unsafe { *(target as *const u32) } {
            // SAFETY: posting a message takes a window handle and integers; a window that has
            // gone meanwhile makes the call fail, which is ignored.
            unsafe { PostMessageW(window, WM_CLOSE, 0, 0) };
        }
        1
    }
    let target = pid;
    // SAFETY: `visit` has the callback signature; the `LPARAM` is the address of `target`, which
    // outlives the call (the enumeration is synchronous).
    unsafe { EnumWindows(Some(visit), (&raw const target) as isize) };
}

// ---- path comparison --------------------------------------------------------------------------

/// The components of `path` as a comparison key: the verbatim and the plain form of a drive or a
/// share are one, and every part is upper-cased (NTFS compares names without case).
fn key(path: &Path) -> Vec<String> {
    let upper = |s: &std::ffi::OsStr| s.to_string_lossy().to_uppercase();
    path.components()
        .map(|c| match c {
            Component::Prefix(p) => match p.kind() {
                Prefix::Disk(d) | Prefix::VerbatimDisk(d) => {
                    format!("{}:", char::from(d.to_ascii_uppercase()))
                }
                Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
                    format!("\\\\{}\\{}", upper(server), upper(share))
                }
                _ => upper(p.as_os_str()),
            },
            Component::RootDir => "\\".to_owned(),
            Component::CurDir => ".".to_owned(),
            Component::ParentDir => "..".to_owned(),
            Component::Normal(n) => upper(n),
        })
        .collect()
}

/// Whether `path` is `tree` or lies below it, by whole components and ignoring case and the
/// verbatim prefix. A path with `..` or `.` in it is never under anything (it is not canonical).
fn is_under(tree: &Path, path: &Path) -> bool {
    let (tree, path) = (key(tree), key(path));
    if path.iter().any(|c| c == ".." || c == ".") {
        return false;
    }
    path.len() >= tree.len() && path[..tree.len()] == tree[..]
}

/// The image path as the OS reports it, canonicalised when that works (long names, true case),
/// else as reported.
fn canonical_image(raw: PathBuf) -> PathBuf {
    std::fs::canonicalize(&raw).unwrap_or(raw)
}

// ---- the trait --------------------------------------------------------------------------------

impl Process for WindowsProcess {
    fn current_exe(&self) -> Result<PathBuf, Error> {
        let exe = std::env::current_exe().map_err(|e| unreadable("current exe", e))?;
        let exe = std::fs::canonicalize(exe).map_err(|e| unreadable("current exe", e))?;
        if !exe.is_absolute() {
            return Err(ProcessError::new(ProcessErrorKind::Unreadable, "current exe").into());
        }
        Ok(exe)
    }

    fn current(&self) -> Result<ProcessId, Error> {
        let start_ticks = creation_time(current_process()).map_err(|e| unreadable("current", e))?;
        Ok(ProcessId {
            pid: std::process::id(),
            start_ticks,
        })
    }

    fn parent(&self) -> Result<Option<ProcessId>, Error> {
        let me = std::process::id();
        let rows = snapshot().map_err(|e| unreadable("parent", e))?;
        let Some(ppid) = rows.iter().find(|e| e.pid == me).map(|e| e.parent) else {
            return Ok(None);
        };
        if ppid == 0 || ppid == me {
            return Ok(None);
        }
        // A parent that is gone, or that this process may not open, is no parent to wait for.
        let Ok(handle) = open_process(ppid, ACCESS) else {
            return Ok(None);
        };
        // An ended parent (its pid listed only because a handle to it is still open somewhere)
        // is no parent to wait for either.
        if has_ended(&handle).map_err(|e| unreadable("parent", e))? {
            return Ok(None);
        }
        let parent_start =
            creation_time(handle.as_raw_handle()).map_err(|e| unreadable("parent", e))?;
        let own_start = self.current()?.start_ticks;
        // A reused pid belongs to a process younger than this one; the real parent is older.
        if parent_start > own_start {
            return Ok(None);
        }
        Ok(Some(ProcessId {
            pid: ppid,
            start_ticks: parent_start,
        }))
    }

    fn spawn_detached(&self, spec: &SpawnSpec) -> Result<(), Error> {
        if spec.stdio != ChildStdio::Null {
            // Nobody would own the pipes of a program that outlives this process.
            return Err(ProcessError::new(ProcessErrorKind::InvalidRequest, "spawn")
                .about(&spec.program)
                .into());
        }
        let flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW;
        // The handle is dropped without waiting: the program outlives this process.
        match command(spec, flags | CREATE_BREAKAWAY_FROM_JOB)?.spawn() {
            Ok(child) => drop(child),
            // A job that does not allow breakaway refuses the flag with "access denied".
            Err(e) if e.raw_os_error() == i32::try_from(ERROR_ACCESS_DENIED).ok() => {
                command(spec, flags)?
                    .spawn()
                    .map(drop)
                    .map_err(|e| spawn_error(e, &spec.program))?;
            }
            Err(e) => return Err(spawn_error(e, &spec.program)),
        }
        Ok(())
    }

    fn spawn_child(&self, spec: &SpawnSpec) -> Result<Box<dyn Child>, Error> {
        let mut child = command(spec, CREATE_NO_WINDOW)?
            .spawn()
            .map_err(|e| spawn_error(e, &spec.program))?;
        let pid = child.id();
        // The std child owns a handle with query access, so the pid cannot have been reused.
        match creation_time(child.as_raw_handle()) {
            Ok(start_ticks) => {
                let stdin = child.stdin.take();
                let stdout = child.stdout.take();
                Ok(Box::new(WindowsChild {
                    child,
                    id: ProcessId { pid, start_ticks },
                    done: None,
                    stdin,
                    stdout,
                }))
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(unreadable("spawn", e))
            }
        }
    }

    fn wait_exit(&self, id: &ProcessId, timeout: Duration) -> Result<WaitOutcome, Error> {
        // A pid that cannot be opened is gone (or not ours to wait for): it counts as ended.
        let Ok(handle) = open_process(id.pid, ACCESS) else {
            return Ok(WaitOutcome::Exited);
        };
        // Checked on the handle that is then waited on, so the pid cannot change under us.
        let start = creation_time(handle.as_raw_handle()).map_err(|e| unreadable("wait", e))?;
        if start != id.start_ticks {
            return Ok(WaitOutcome::Exited);
        }
        wait_handle(&handle, timeout).map_err(|e| unreadable("wait", e))
    }

    /// Compares every other process's image with the tree. A process this one cannot open is
    /// skipped, and only a process's image is looked at (not its working directory or the DLLs it
    /// loaded), so this is no guard for a removal: that is [`Process::tree_in_use_strict`].
    ///
    /// The skip is deliberate (M13-D17) and differs from the trait's rule that a process that
    /// cannot be inspected counts as in use: the system's own processes cannot be opened by an
    /// ordinary user, so counting them would make every scan answer in use and stop collection on
    /// every Windows machine. It is safe because the OS refuses to delete a running image, which
    /// is what an unseen process under the tree would hold, and because the removals that matter
    /// (a machine install's) ask `tree_in_use_strict`, whose file-system probe finds what this
    /// scan cannot see.
    fn tree_in_use(&self, tree: &Path, exclude: &[ProcessId]) -> Result<bool, Error> {
        let tree = std::fs::canonicalize(tree).map_err(|e| ProcessError::from_io("in use", e))?;
        let me = std::process::id();
        let rows = snapshot().map_err(|e| unreadable("in use", e))?;
        for row in rows {
            if row.pid == me {
                continue;
            }
            // A process that cannot be opened is skipped: its image cannot be deleted while it
            // runs, so the OS keeps the tree safe even where this scan cannot see.
            let Ok(handle) = open_process(row.pid, ACCESS) else {
                continue;
            };
            // Listed but already ended (a handle elsewhere keeps the entry): not running from it.
            if has_ended(&handle).unwrap_or(true) {
                continue;
            }
            if exclude.iter().any(|x| x.pid == row.pid) {
                let start = creation_time(handle.as_raw_handle()).ok();
                // Another start time is another process behind a reused pid: not excluded.
                if start.is_none_or(|s| {
                    exclude
                        .iter()
                        .any(|x| x.pid == row.pid && x.start_ticks == s)
                }) {
                    continue;
                }
            }
            let Ok(image) = image_path(handle.as_raw_handle()) else {
                continue;
            };
            if is_under(&tree, &canonical_image(image)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The scan of `tree_in_use`, then the file-system probe: `true` when the scan says so, its
    /// error when it fails, otherwise whether any file or directory of the tree refuses to be
    /// opened for deletion. The probe sees what a rename does not (a running image, a DLL loaded
    /// by any process, inspectable or not) and what the scan does not (a working directory, a
    /// held file).
    fn tree_in_use_strict(&self, tree: &Path, exclude: &[ProcessId]) -> Result<bool, Error> {
        if self.tree_in_use(tree, exclude)? {
            return Ok(true);
        }
        tree_files_held(tree)
    }
}

/// A child started by [`WindowsProcess::spawn_child`].
struct WindowsChild {
    child: std::process::Child,
    id: ProcessId,
    done: Option<ExitKind>,
    /// The parent's end of the child's input pipe, until the caller takes it.
    stdin: Option<std::process::ChildStdin>,
    /// The parent's end of the child's output pipe, until the caller takes it.
    stdout: Option<std::process::ChildStdout>,
}

fn exit_kind(status: std::process::ExitStatus) -> ExitKind {
    // `code` is `Some` for every Windows exit; the exit code is a `u32` read as an `i32`.
    match status.code() {
        Some(0) => ExitKind::Success,
        Some(code) => ExitKind::Failure(code),
        None => ExitKind::Failure(-1),
    }
}

impl Child for WindowsChild {
    fn id(&self) -> ProcessId {
        self.id
    }

    fn try_wait(&mut self) -> Result<Option<ExitKind>, Error> {
        if self.done.is_none() {
            let status = self
                .child
                .try_wait()
                .map_err(|e| ProcessError::from_io("wait", e))?;
            self.done = status.map(exit_kind);
        }
        Ok(self.done)
    }

    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        self.stdin
            .take()
            .map(|p| Box::new(p) as Box<dyn Write + Send>)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        self.stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>)
    }

    fn terminate(&mut self, grace: Duration) -> Result<(), Error> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        // The std child still owns its handle, so the pid is still this child's.
        ask_to_close(self.id.pid);
        let deadline = Instant::now().checked_add(grace);
        loop {
            if self.try_wait()?.is_some() {
                return Ok(());
            }
            let remaining = match deadline {
                Some(deadline) => deadline.saturating_duration_since(Instant::now()),
                None => TERMINATE_POLL,
            };
            if remaining.is_zero() {
                break;
            }
            std::thread::sleep(remaining.min(TERMINATE_POLL));
        }
        // `TerminateProcess` through std (exit code 1), then reap it. A child that ended between
        // the last check and the kill makes the kill fail; the wait then reports its real exit.
        let _ = self.child.kill();
        let status = self
            .child
            .wait()
            .map_err(|e| ProcessError::from_io("terminate", e))?;
        self.done = Some(exit_kind(status));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_under_the_tree_is_found_by_whole_components_ignoring_case_and_verbatim() {
        let tree = Path::new(r"C:\Users\Me\App");
        assert!(is_under(tree, Path::new(r"C:\Users\Me\App\bin\a.exe")));
        assert!(is_under(tree, Path::new(r"c:\users\me\app\BIN\a.exe")));
        assert!(is_under(tree, Path::new(r"\\?\C:\Users\Me\App\a.exe")));
        assert!(is_under(
            Path::new(r"\\?\c:\users\me\app"),
            Path::new(r"C:\USERS\ME\APP\x")
        ));
        assert!(
            !is_under(tree, Path::new(r"C:\Users\Me\App2\a.exe")),
            "a sibling sharing a prefix"
        );
        assert!(!is_under(tree, Path::new(r"C:\Users\Me\Ap")));
        assert!(
            !is_under(tree, Path::new(r"D:\Users\Me\App\a.exe")),
            "another drive"
        );
        assert!(
            !is_under(tree, Path::new(r"C:\Users\Me\App\..\Other\a.exe")),
            "not canonical"
        );
        assert!(!is_under(
            tree,
            Path::new(r"\\server\share\Users\Me\App\a.exe")
        ));
    }
}
