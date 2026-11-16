//! Reading `/proc`: the `stat` line, the liveness rule and the in-use scan.
//!
//! Liveness (one rule for every place that asks whether a process still runs): a [`ProcessId`]
//! names a process that has **exited** when `/proc/<pid>` is gone, when its start time differs
//! (the pid was reused), or when it is a zombie or dead (state `Z` or `X`) with no thread of it
//! still running. A zombie holds no files and only waits for a reaper that may never come (a
//! container whose pid 1 does not reap), so it counts as exited.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use lunepack_core::ProcessId;

/// `PF_KTHREAD` in the `flags` field: a kernel thread, which has no executable and no files.
const PF_KTHREAD: u64 = 0x0020_0000;

/// How long a same-uid process whose files vanished during the in-use read is re-probed before
/// it counts as in use (fail closed), and the step between probes. The kernel drops a task's mm,
/// then its files and working directory, before it becomes a zombie; this covers that window.
const VANISH_BOUND: Duration = Duration::from_millis(200);
const VANISH_STEP: Duration = Duration::from_millis(10);

/// The fields of `/proc/<pid>/stat` this crate uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stat {
    /// Field 3, one character (`R`, `S`, `D`, `Z`, `X`, ...).
    pub state: u8,
    /// Field 9.
    pub flags: u64,
    /// Field 22, clock ticks since boot.
    pub start_ticks: u64,
}

/// Parses a `/proc/<pid>/stat` line. The comm field (2) is in parentheses and may itself hold
/// spaces and parentheses, so the fields are counted after the **last** `)`. Anything that does
/// not have the expected shape is `None`.
pub(crate) fn parse_stat(text: &[u8]) -> Option<Stat> {
    let open = text.iter().position(|&b| b == b'(')?;
    let close = text.iter().rposition(|&b| b == b')')?;
    if close < open || open == 0 {
        return None;
    }
    let pid = &text[..open];
    if pid.last() != Some(&b' ') || !all_digits(&pid[..pid.len() - 1]) {
        return None;
    }
    let rest = text[close + 1..]
        .strip_suffix(b"\n")
        .unwrap_or(&text[close + 1..]);
    let rest = rest.strip_prefix(b" ")?;
    // `rest` starts at field 3.
    let fields: Vec<&[u8]> = rest.split(|&b| b == b' ').collect();
    let state = match fields.first()? {
        [c] if c.is_ascii_alphabetic() => *c,
        _ => return None,
    };
    let flags = decimal(fields.get(9 - 3)?)?;
    let start_ticks = decimal(fields.get(22 - 3)?)?;
    Some(Stat {
        state,
        flags,
        start_ticks,
    })
}

fn all_digits(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(u8::is_ascii_digit)
}

/// A non-empty run of ASCII digits that fits a `u64` (no sign, no space).
fn decimal(s: &[u8]) -> Option<u64> {
    if !all_digits(s) {
        return None;
    }
    std::str::from_utf8(s).ok()?.parse().ok()
}

/// What `/proc` says about a pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Probe {
    /// No such process (or it was reaped while being read).
    Gone,
    /// A zombie or dead process with no running thread.
    Dead(Stat),
    /// Running (any state other than the above).
    Running(Stat),
}

fn proc_path(pid: u32, leaf: &str) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/{leaf}"))
}

/// An error that means the process has vanished: `ENOENT`, or `ESRCH` from a read of a process
/// that was reaped after the open.
fn vanished(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ESRCH)
}

/// Reads and parses `/proc/<pid>/stat` (`/proc/self/stat` for `None`).
pub(crate) fn read_stat(pid: Option<u32>) -> io::Result<Option<Stat>> {
    let path = match pid {
        Some(pid) => proc_path(pid, "stat"),
        None => PathBuf::from("/proc/self/stat"),
    };
    read_stat_at(&path)
}

/// Reads and parses the `stat` file at `path`; `None` when it has vanished.
fn read_stat_at(path: &Path) -> io::Result<Option<Stat>> {
    match fs::read(path) {
        Ok(text) => parse_stat(&text).map(Some).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "unexpected /proc stat line")
        }),
        Err(e) if vanished(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Classifies `pid` by the liveness rule.
pub(crate) fn probe(pid: u32) -> io::Result<Probe> {
    let Some(stat) = read_stat(Some(pid))? else {
        return Ok(Probe::Gone);
    };
    if !matches!(stat.state, b'Z' | b'X' | b'x') {
        return Ok(Probe::Running(stat));
    }
    // A thread-group leader that ended while other threads run shows as a zombie; the process
    // still runs (and holds its files) until the last thread ends.
    match fs::read_dir(proc_path(pid, "task")) {
        Ok(tasks) => {
            let mut others = 0usize;
            for task in tasks {
                let task = task?;
                if task.file_name() != OsStr::new(&pid.to_string()) {
                    others += 1;
                }
            }
            Ok(if others == 0 {
                Probe::Dead(stat)
            } else {
                Probe::Running(stat)
            })
        }
        Err(e) if vanished(&e) => Ok(Probe::Dead(stat)),
        Err(e) => Err(e),
    }
}

/// Whether the process `id` has exited, by the liveness rule.
pub(crate) fn has_exited(id: &ProcessId) -> io::Result<bool> {
    Ok(match probe(id.pid)? {
        Probe::Gone | Probe::Dead(_) => true,
        Probe::Running(stat) => stat.start_ticks != id.start_ticks,
    })
}

/// The in-use scan of [`Process::tree_in_use`](lunepack_core::Process::tree_in_use); `tree`
/// is canonical. Errors only when `/proc` itself cannot be listed or this process's own entry
/// cannot be read.
///
/// A same-uid process whose `exe`, `cwd`, `fd` or `maps` cannot be read because the kernel denies
/// it (`EACCES`/`EPERM`: a non-dumpable process, such as a systemd `(sd-pam)` or an ssh-agent,
/// which every desktop login and CI runner has) does not count as in use by that failure. What is
/// still readable, its command line, decides: in use when `argv[0]` or an absolute argument,
/// canonicalised, lies under the tree (M5-D9, user decision Q40).
///
/// A read that fails because the files vanished (`ENOENT`/`ESRCH`) means the process is exiting,
/// or its thread-group leader has ended while other threads run. Then the process's live threads
/// are read instead (`/proc/<pid>/task/<tid>/`), and the pid is re-probed for at most
/// [`VANISH_BOUND`]: it is skipped once it counts as exited, decided by its live threads when all
/// of them read cleanly, and otherwise counts as in use. Any other read error answers `true`
/// (fail closed). Gap: a non-dumpable process started by a relative path, or not from the tree's
/// path, is not seen.
pub(crate) fn tree_in_use(tree: &Path, exclude: &[ProcessId]) -> io::Result<bool> {
    let my_uid = fs::metadata("/proc/self")?.uid();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .filter(|n| all_digits(n.as_bytes()))
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        match fs::symlink_metadata(entry.path()) {
            Ok(meta) if meta.uid() != my_uid => continue,
            Ok(_) => {}
            Err(e) if vanished(&e) => continue,
            // Whose process this is cannot be told: fail closed.
            Err(_) => return Ok(true),
        }
        let stat = match probe(pid) {
            Ok(Probe::Running(stat)) => stat,
            Ok(Probe::Gone | Probe::Dead(_)) => continue,
            Err(_) => return Ok(true),
        };
        if stat.flags & PF_KTHREAD != 0 {
            continue;
        }
        let id = ProcessId {
            pid,
            start_ticks: stat.start_ticks,
        };
        if exclude.contains(&id) {
            continue;
        }
        match process_uses_tree(&id, tree) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(e) => {
                let used = if permission_denied(&e) {
                    cmdline_uses_tree(pid, tree)
                } else {
                    Err(e)
                };
                match used {
                    Ok(true) => return Ok(true),
                    Ok(false) => {}
                    // Unreadable: fine only if the process ended (or the pid was reused)
                    // meanwhile.
                    Err(_) => {
                        if !has_exited(&id).unwrap_or(false) {
                            return Ok(true);
                        }
                    }
                }
            }
        }
    }
    Ok(false)
}

/// The kernel refused the read (`EACCES` or `EPERM`), as opposed to a process that vanished or
/// any other failure.
fn permission_denied(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::PermissionDenied
        || matches!(err.raw_os_error(), Some(libc::EACCES | libc::EPERM))
}

/// For a process whose files cannot be inspected: whether `argv[0]` or an absolute argument of
/// `/proc/<pid>/cmdline` lies under `tree`, as written or after resolving symlinks (so a path
/// through `R/current` resolves into the version tree). A relative argument cannot be resolved
/// without the process's working directory and is not counted.
fn cmdline_uses_tree(pid: u32, tree: &Path) -> io::Result<bool> {
    let cmdline = fs::read(proc_path(pid, "cmdline"))?;
    Ok(cmdline
        .split(|&b| b == 0)
        .filter(|arg| arg.first() == Some(&b'/'))
        .map(|arg| Path::new(OsStr::from_bytes(arg)))
        .any(|arg| under(arg, tree) || resolve(arg).is_some_and(|p| under(&p, tree))))
}

/// `path` with symlinks resolved; when it does not exist (any more), its parent resolved with the
/// last component re-appended.
fn resolve(path: &Path) -> Option<PathBuf> {
    fs::canonicalize(path).ok().or_else(|| {
        let parent = fs::canonicalize(path.parent()?).ok()?;
        Some(parent.join(path.file_name()?))
    })
}

/// Whether the process `id` uses `tree` ([`uses_tree`] over `/proc/<pid>`), riding out files that
/// vanish under the read. On a vanished-kind error the process is either exiting or a zombie
/// leader with live threads: within [`VANISH_BOUND`], it is `false` once `id` counts as exited,
/// and the answer of its live threads once every one of them reads cleanly; past the bound the
/// vanished error is returned, which the caller counts as in use. Any other error is returned at
/// once.
fn process_uses_tree(id: &ProcessId, tree: &Path) -> io::Result<bool> {
    let deadline = Instant::now() + VANISH_BOUND;
    loop {
        let err = match uses_tree(&PathBuf::from(format!("/proc/{}", id.pid)), tree) {
            Ok(used) => return Ok(used),
            Err(e) if vanished(&e) => e,
            Err(e) => return Err(e),
        };
        if has_exited(id)? {
            return Ok(false);
        }
        match threads_use_tree(id.pid, tree) {
            Ok(Some(used)) => return Ok(used),
            Ok(None) => {}
            Err(e) if vanished(&e) => {}
            Err(e) => return Err(e),
        }
        if Instant::now() >= deadline {
            return Err(err);
        }
        std::thread::sleep(VANISH_STEP);
    }
}

/// [`uses_tree`] over each live thread of `pid` (`/proc/<pid>/task/<tid>/`; threads may have
/// unshared their working directory or descriptor table, so each is read). A thread that is a
/// zombie or gone holds nothing and is skipped. `Some(true)` as soon as one thread uses the tree;
/// `Some(false)` when at least one live thread was read and every live thread read cleanly;
/// `None` when a thread's files vanished too (it is exiting) or no live thread was found, so the
/// caller re-probes. Any other error is returned.
fn threads_use_tree(pid: u32, tree: &Path) -> io::Result<Option<bool>> {
    let mut settled = false;
    let mut unsettled = false;
    for task in fs::read_dir(proc_path(pid, "task"))? {
        let task = task?;
        let dir = task.path();
        match read_stat_at(&dir.join("stat"))? {
            None => continue,
            Some(stat) if matches!(stat.state, b'Z' | b'X' | b'x') => continue,
            Some(_) => {}
        }
        match uses_tree(&dir, tree) {
            Ok(true) => return Ok(Some(true)),
            Ok(false) => settled = true,
            Err(e) if vanished(&e) => unsettled = true,
            Err(e) => return Err(e),
        }
    }
    Ok((settled && !unsettled).then_some(false))
}

/// Whether the process or thread whose `/proc` directory is `dir` has its executable, working
/// directory, an open file or a mapped file under `tree`. Any read error is returned (the caller
/// decides); a descriptor closed between the listing and its read is skipped.
fn uses_tree(dir: &Path, tree: &Path) -> io::Result<bool> {
    for leaf in ["exe", "cwd"] {
        if under(&fs::read_link(dir.join(leaf))?, tree) {
            return Ok(true);
        }
    }
    for fd in fs::read_dir(dir.join("fd"))? {
        let fd = fd?;
        match fs::read_link(fd.path()) {
            Ok(target) => {
                if under(&target, tree) {
                    return Ok(true);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    let maps = fs::read(dir.join("maps"))?;
    Ok(maps
        .split(|&b| b == b'\n')
        .filter_map(maps_path)
        .any(|p| under(p, tree)))
}

/// The path of one `maps` line (`address perms offset dev inode   path`), if it names a file.
fn maps_path(line: &[u8]) -> Option<&Path> {
    let path = line.splitn(6, |&b| b == b' ').nth(5)?;
    let start = path.iter().position(|&b| b != b' ')?;
    let path = &path[start..];
    (path.first() == Some(&b'/')).then(|| Path::new(OsStr::from_bytes(path)))
}

/// Whether `path` (as the kernel shows it) lies under `tree`, component-wise. The kernel appends
/// ` (deleted)` to a file that was unlinked; both the shown path and the path without that suffix
/// are tried, so a file that merely ends with those characters is not missed.
pub(crate) fn under(path: &Path, tree: &Path) -> bool {
    if path.starts_with(tree) {
        return true;
    }
    path.as_os_str()
        .as_bytes()
        .strip_suffix(b" (deleted)")
        .is_some_and(|p| Path::new(OsStr::from_bytes(p)).starts_with(tree))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(comm: &str, state: &str, start: &str) -> Vec<u8> {
        // Fields 3..=22 with flags (9) = 4194560 and start (22) as given.
        let mut fields: Vec<String> = (3..=52).map(|n| n.to_string()).collect();
        fields[0] = state.to_owned();
        fields[9 - 3] = "4194560".to_owned();
        fields[22 - 3] = start.to_owned();
        format!("1234 ({comm}) {}\n", fields.join(" ")).into_bytes()
    }

    #[test]
    fn the_fields_are_counted_after_the_last_parenthesis() {
        for comm in ["app", "a) (b", ") (", "x) S 1 2 (y", "", "sp ace", "((("] {
            let stat = parse_stat(&line(comm, "S", "987654321")).expect(comm);
            assert_eq!(stat.state, b'S', "{comm}");
            assert_eq!(stat.start_ticks, 987_654_321, "{comm}");
            assert_eq!(stat.flags, 4_194_560, "{comm}");
        }
        let stat = parse_stat(&line("z", "Z", "1")).unwrap();
        assert_eq!(stat.state, b'Z');
        assert_eq!(
            parse_stat(&line("m", "R", &u64::MAX.to_string()))
                .unwrap()
                .start_ticks,
            u64::MAX
        );
    }

    #[test]
    fn anything_else_is_refused() {
        let max_plus_one = "18446744073709551616";
        for bad in [
            line("a", "S", max_plus_one),
            line("a", "S", "+5"),
            line("a", "S", "-5"),
            line("a", "S", ""),
            line("a", "S", "12a"),
            line("a", "SS", "5"),
            line("a", "", "5"),
            line("a", "1", "5"),
            b"1234 (a) S 1 2 3".to_vec(),
            b"1234 a S".to_vec(),
            b"(a) S".to_vec(),
            b"x1 (a) S".to_vec(),
            b"".to_vec(),
            b"1234 )a( S 1".to_vec(),
        ] {
            assert_eq!(
                parse_stat(&bad),
                None,
                "{:?}",
                String::from_utf8_lossy(&bad)
            );
        }
        // Two spaces in a row shift the fields, so field 22 is not a number any more.
        let mut doubled = line("a", "S", "5");
        let at = doubled.iter().position(|&b| b == b')').unwrap() + 1;
        doubled.insert(at, b' ');
        assert_eq!(parse_stat(&doubled), None);
    }

    #[test]
    fn maps_lines_yield_file_paths_only() {
        assert_eq!(
            maps_path(b"7f00-7f01 r-xp 00000000 08:01 1234                       /opt/a b/lib.so"),
            Some(Path::new("/opt/a b/lib.so"))
        );
        assert_eq!(
            maps_path(b"7f00-7f01 r--p 00000000 08:01 1234   /t/x (deleted)"),
            Some(Path::new("/t/x (deleted)"))
        );
        assert_eq!(maps_path(b"7f00-7f01 rw-p 00000000 00:00 0 "), None);
        assert_eq!(
            maps_path(b"7f00-7f01 rw-p 00000000 00:00 0                          [heap]"),
            None
        );
        assert_eq!(maps_path(b""), None);
    }

    #[test]
    fn under_is_component_wise_and_strips_deleted() {
        let tree = Path::new("/r/versions/1.0.0");
        assert!(under(Path::new("/r/versions/1.0.0"), tree));
        assert!(under(Path::new("/r/versions/1.0.0/bin/app"), tree));
        assert!(under(Path::new("/r/versions/1.0.0/app (deleted)"), tree));
        assert!(under(Path::new("/r/versions/1.0.0 (deleted)"), tree));
        assert!(!under(Path::new("/r/versions/1.0.0x/app"), tree));
        assert!(!under(Path::new("/r/versions/1.0"), tree));
        assert!(!under(Path::new("/r/versions/1.0.0x (deleted)"), tree));
    }
}
