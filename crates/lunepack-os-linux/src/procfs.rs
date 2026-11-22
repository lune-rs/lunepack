//! Reading `/proc`: the `stat` line, the liveness rule and the in-use scan.
//!
//! Liveness (one rule for every place that asks whether a process still runs): a [`ProcessId`]
//! names a process that has **exited** when `/proc/<pid>` is gone, when its start time differs
//! (the pid was reused), or when it is a zombie or dead (state `Z` or `X`) with no thread of it
//! still running. A zombie holds no files and only waits for a reaper that may never come (a
//! container whose pid 1 does not reap), so it counts as exited.

use std::ffi::{OsStr, OsString};
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

/// The reads of `/proc` the scan makes. [`RealProc`] reads the kernel's; the tests script the
/// answers (another uid's process, a refused read, a process that vanishes) under a made-up root.
pub(crate) trait ProcFs {
    /// The names in the directory `path`; an entry that fails to read is an error.
    fn names(&self, path: &Path) -> io::Result<Vec<OsString>>;
    /// The bytes of the file `path`.
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    /// The target of the link `path`.
    fn read_link(&self, path: &Path) -> io::Result<PathBuf>;
    /// The owner of `path`, not following a final link.
    fn owner(&self, path: &Path) -> io::Result<u32>;
    /// The owner of `path`, following links (`/proc/self`).
    fn owner_followed(&self, path: &Path) -> io::Result<u32>;
}

/// The kernel's `/proc`.
pub(crate) struct RealProc;

impl ProcFs for RealProc {
    fn names(&self, path: &Path) -> io::Result<Vec<OsString>> {
        fs::read_dir(path)?
            .map(|e| e.map(|e| e.file_name()))
            .collect()
    }
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }
    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        fs::read_link(path)
    }
    fn owner(&self, path: &Path) -> io::Result<u32> {
        fs::symlink_metadata(path).map(|m| m.uid())
    }
    fn owner_followed(&self, path: &Path) -> io::Result<u32> {
        fs::metadata(path).map(|m| m.uid())
    }
}

/// The kernel's `/proc`.
const PROC: &str = "/proc";

/// An error that means the process has vanished: `ENOENT`, or `ESRCH` from a read of a process
/// that was reaped after the open.
fn vanished(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ESRCH)
}

/// Reads and parses `/proc/<pid>/stat` (`/proc/self/stat` for `None`).
pub(crate) fn read_stat(pid: Option<u32>) -> io::Result<Option<Stat>> {
    let path = match pid {
        Some(pid) => Path::new(PROC).join(pid.to_string()).join("stat"),
        None => PathBuf::from("/proc/self/stat"),
    };
    read_stat_at(&RealProc, &path)
}

/// Reads and parses the `stat` file at `path`; `None` when it has vanished.
fn read_stat_at(p: &dyn ProcFs, path: &Path) -> io::Result<Option<Stat>> {
    match p.read(path) {
        Ok(text) => parse_stat(&text).map(Some).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "unexpected /proc stat line")
        }),
        Err(e) if vanished(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Classifies `pid` by the liveness rule.
pub(crate) fn probe(pid: u32) -> io::Result<Probe> {
    probe_in(&RealProc, Path::new(PROC), pid)
}

/// [`probe`] over the `/proc` at `root`.
fn probe_in(p: &dyn ProcFs, root: &Path, pid: u32) -> io::Result<Probe> {
    let dir = root.join(pid.to_string());
    let Some(stat) = read_stat_at(p, &dir.join("stat"))? else {
        return Ok(Probe::Gone);
    };
    if !matches!(stat.state, b'Z' | b'X' | b'x') {
        return Ok(Probe::Running(stat));
    }
    // A thread-group leader that ended while other threads run shows as a zombie; the process
    // still runs (and holds its files) until the last thread ends.
    match p.names(&dir.join("task")) {
        Ok(tasks) => {
            let own = pid.to_string();
            let others = tasks.iter().filter(|t| *t != OsStr::new(&own)).count();
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
    has_exited_in(&RealProc, Path::new(PROC), id)
}

fn has_exited_in(p: &dyn ProcFs, root: &Path, id: &ProcessId) -> io::Result<bool> {
    Ok(match probe_in(p, root, id.pid)? {
        Probe::Gone | Probe::Dead(_) => true,
        Probe::Running(stat) => stat.start_ticks != id.start_ticks,
    })
}

/// The in-use scan of [`Process::tree_in_use`](lunepack_core::Process::tree_in_use); `tree`
/// is canonical. Only this user's processes are looked at ([`scan`] with this process's uid).
pub(crate) fn tree_in_use(tree: &Path, exclude: &[ProcessId]) -> io::Result<bool> {
    let my_uid = RealProc.owner_followed(Path::new("/proc/self"))?;
    scan(&RealProc, Path::new(PROC), tree, exclude, Some(my_uid))
}

/// The in-use scan of [`Process::tree_in_use_strict`](lunepack_core::Process::tree_in_use_strict)
/// (M11-D13 as restated): [`scan`] over every user's processes, with exactly the per-user scan's
/// rules otherwise.
pub(crate) fn tree_in_use_strict(tree: &Path, exclude: &[ProcessId]) -> io::Result<bool> {
    scan(&RealProc, Path::new(PROC), tree, exclude, None)
}

/// The in-use scan over the `/proc` at `root`: the processes of `only_uid` (every process for
/// `None`). Errors only when `/proc` itself cannot be listed.
///
/// A process whose `exe`, `cwd`, `fd` or `maps` cannot be read because the kernel denies it
/// (`EACCES`/`EPERM`: a non-dumpable process, such as a systemd `(sd-pam)` or an ssh-agent,
/// which every desktop login and CI runner has) does not count as in use by that failure. What is
/// still readable, its command line, decides: in use when `argv[0]` or an absolute argument,
/// canonicalised, lies under the tree (M5-D9, user decision Q40).
///
/// A read that fails because the files vanished (`ENOENT`/`ESRCH`) means the process is exiting,
/// or its thread-group leader has ended while other threads run. Then the process's live threads
/// are read instead (`/proc/<pid>/task/<tid>/`), and the pid is re-probed for at most
/// [`VANISH_BOUND`]: it is skipped once it counts as exited, decided by its live threads when all
/// of them read cleanly, and otherwise counts as in use. Kernel threads are skipped. Any other
/// read error answers `true` (fail closed). Gap: a non-dumpable process started by a relative
/// path, or not from the tree's path, is not seen.
pub(crate) fn scan(
    p: &dyn ProcFs,
    root: &Path,
    tree: &Path,
    exclude: &[ProcessId],
    only_uid: Option<u32>,
) -> io::Result<bool> {
    for name in p.names(root)? {
        let Some(pid) = name
            .to_str()
            .filter(|n| all_digits(n.as_bytes()))
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        match p.owner(&root.join(&name)) {
            Ok(uid) if only_uid.is_some_and(|only| only != uid) => continue,
            Ok(_) => {}
            Err(e) if vanished(&e) => continue,
            // Whose process this is cannot be told: fail closed.
            Err(_) => return Ok(true),
        }
        let stat = match probe_in(p, root, pid) {
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
        match process_uses_tree(p, root, &id, tree) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(e) => {
                let used = if permission_denied(&e) {
                    cmdline_uses_tree(p, root, pid, tree)
                } else {
                    Err(e)
                };
                match used {
                    Ok(true) => return Ok(true),
                    Ok(false) => {}
                    // Unreadable: fine only if the process ended (or the pid was reused)
                    // meanwhile.
                    Err(_) => {
                        if !has_exited_in(p, root, &id).unwrap_or(false) {
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
fn cmdline_uses_tree(p: &dyn ProcFs, root: &Path, pid: u32, tree: &Path) -> io::Result<bool> {
    let cmdline = p.read(&root.join(pid.to_string()).join("cmdline"))?;
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
fn process_uses_tree(p: &dyn ProcFs, root: &Path, id: &ProcessId, tree: &Path) -> io::Result<bool> {
    let deadline = Instant::now() + VANISH_BOUND;
    loop {
        let err = match uses_tree(p, &root.join(id.pid.to_string()), tree) {
            Ok(used) => return Ok(used),
            Err(e) if vanished(&e) => e,
            Err(e) => return Err(e),
        };
        if has_exited_in(p, root, id)? {
            return Ok(false);
        }
        match threads_use_tree(p, root, id.pid, tree) {
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
fn threads_use_tree(
    p: &dyn ProcFs,
    root: &Path,
    pid: u32,
    tree: &Path,
) -> io::Result<Option<bool>> {
    let mut settled = false;
    let mut unsettled = false;
    let tasks = root.join(pid.to_string()).join("task");
    for task in p.names(&tasks)? {
        let dir = tasks.join(task);
        match read_stat_at(p, &dir.join("stat"))? {
            None => continue,
            Some(stat) if matches!(stat.state, b'Z' | b'X' | b'x') => continue,
            Some(_) => {}
        }
        match uses_tree(p, &dir, tree) {
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
fn uses_tree(p: &dyn ProcFs, dir: &Path, tree: &Path) -> io::Result<bool> {
    for leaf in ["exe", "cwd"] {
        if under(&p.read_link(&dir.join(leaf))?, tree) {
            return Ok(true);
        }
    }
    let fds = dir.join("fd");
    for fd in p.names(&fds)? {
        match p.read_link(&fds.join(fd)) {
            Ok(target) => {
                if under(&target, tree) {
                    return Ok(true);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    let maps = p.read(&dir.join("maps"))?;
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

    // ---- the scan over a scripted `/proc` (M11-D13) ------------------------------------------

    use std::cell::RefCell;
    use std::collections::{HashMap, VecDeque};

    /// One scripted answer.
    #[derive(Clone)]
    enum Answer {
        Names(Vec<String>),
        Bytes(Vec<u8>),
        Link(PathBuf),
        Uid(u32),
        Errno(i32),
    }

    /// A `/proc` whose every read is scripted: each path answers its queue in order, the last
    /// answer repeating; an unscripted path is `ENOENT`.
    #[derive(Default)]
    struct FakeProc {
        answers: RefCell<HashMap<PathBuf, VecDeque<Answer>>>,
    }

    impl FakeProc {
        fn set(&self, path: impl Into<PathBuf>, answers: Vec<Answer>) {
            self.answers
                .borrow_mut()
                .insert(path.into(), answers.into_iter().collect());
        }

        fn next(&self, path: &Path) -> Answer {
            let mut all = self.answers.borrow_mut();
            match all.get_mut(path) {
                Some(q) if q.len() > 1 => q.pop_front().unwrap(),
                Some(q) => q.front().cloned().unwrap(),
                None => Answer::Errno(libc::ENOENT),
            }
        }

        fn err(errno: i32) -> io::Error {
            io::Error::from_raw_os_error(errno)
        }
    }

    impl ProcFs for FakeProc {
        fn names(&self, path: &Path) -> io::Result<Vec<OsString>> {
            match self.next(path) {
                Answer::Names(n) => Ok(n.into_iter().map(OsString::from).collect()),
                Answer::Errno(e) => Err(FakeProc::err(e)),
                _ => Err(FakeProc::err(libc::ENOTDIR)),
            }
        }
        fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
            match self.next(path) {
                Answer::Bytes(b) => Ok(b),
                Answer::Errno(e) => Err(FakeProc::err(e)),
                _ => Err(FakeProc::err(libc::EISDIR)),
            }
        }
        fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
            match self.next(path) {
                Answer::Link(l) => Ok(l),
                Answer::Errno(e) => Err(FakeProc::err(e)),
                _ => Err(FakeProc::err(libc::EINVAL)),
            }
        }
        fn owner(&self, path: &Path) -> io::Result<u32> {
            match self.next(&path.join("#owner")) {
                Answer::Uid(u) => Ok(u),
                Answer::Errno(e) => Err(FakeProc::err(e)),
                _ => Err(FakeProc::err(libc::EIO)),
            }
        }
        fn owner_followed(&self, path: &Path) -> io::Result<u32> {
            self.owner(path)
        }
    }

    const ROOT: &str = "/fakeproc";
    const TREE: &str = "/lunepack-test-tree/app/1.0.0";
    const ME: u32 = 501;
    const OTHER: u32 = 1000;

    fn stat_line(pid: u32, state: &str, flags: u64) -> Vec<u8> {
        let mut fields: Vec<String> = (3..=52).map(|n| n.to_string()).collect();
        fields[0] = state.to_owned();
        fields[9 - 3] = flags.to_string();
        fields[22 - 3] = "777".to_owned();
        format!("{pid} (p) {}\n", fields.join(" ")).into_bytes()
    }

    /// A running process of `uid` whose files are `exe`, `cwd`, no descriptor and empty maps.
    fn process(f: &FakeProc, pid: u32, uid: u32, exe: Answer, cmdline: &[u8]) {
        let dir = Path::new(ROOT).join(pid.to_string());
        f.set(dir.join("#owner"), vec![Answer::Uid(uid)]);
        f.set(
            dir.join("stat"),
            vec![Answer::Bytes(stat_line(pid, "S", 0))],
        );
        f.set(dir.join("exe"), vec![exe]);
        f.set(dir.join("cwd"), vec![Answer::Link(PathBuf::from("/"))]);
        f.set(dir.join("fd"), vec![Answer::Names(Vec::new())]);
        f.set(dir.join("maps"), vec![Answer::Bytes(Vec::new())]);
        f.set(dir.join("cmdline"), vec![Answer::Bytes(cmdline.to_vec())]);
    }

    fn listing(f: &FakeProc, pids: &[u32]) {
        let mut names: Vec<String> = pids.iter().map(u32::to_string).collect();
        names.push("self".to_owned());
        f.set(ROOT, vec![Answer::Names(names)]);
    }

    fn strict(f: &FakeProc) -> bool {
        scan(f, Path::new(ROOT), Path::new(TREE), &[], None).unwrap()
    }

    fn per_user(f: &FakeProc) -> bool {
        scan(f, Path::new(ROOT), Path::new(TREE), &[], Some(ME)).unwrap()
    }

    fn in_tree(rel: &str) -> PathBuf {
        Path::new(TREE).join(rel)
    }

    #[test]
    fn another_users_process_in_the_tree_is_in_use_only_for_the_strict_scan() {
        let f = FakeProc::default();
        listing(&f, &[10]);
        process(&f, 10, OTHER, Answer::Link(in_tree("bin/app")), b"");
        assert!(strict(&f), "the strict scan sees every user");
        assert!(!per_user(&f), "the per-user scan skips other uids");
        // The same process of this user is in use for both.
        process(&f, 10, ME, Answer::Link(in_tree("bin/app")), b"");
        assert!(per_user(&f));
        assert!(strict(&f));
    }

    #[test]
    fn a_refused_process_of_another_user_is_judged_by_its_command_line() {
        for leaf in ["exe", "cwd", "fd", "maps"] {
            let f = FakeProc::default();
            listing(&f, &[11]);
            process(
                &f,
                11,
                OTHER,
                Answer::Link(PathBuf::from("/usr/bin/x")),
                b"/usr/bin/agent\0-d\0",
            );
            let path = Path::new(ROOT).join("11").join(leaf);
            f.set(path.clone(), vec![Answer::Errno(libc::EACCES)]);
            assert!(
                !strict(&f),
                "{leaf}: argv outside the tree is not in use (Q40)"
            );
            process(
                &f,
                11,
                OTHER,
                Answer::Link(PathBuf::from("/usr/bin/x")),
                format!("{TREE}/bin/app\0--x\0").as_bytes(),
            );
            f.set(path, vec![Answer::Errno(libc::EPERM)]);
            assert!(strict(&f), "{leaf}: argv[0] in the tree is in use");
        }
    }

    #[test]
    fn a_vanishing_process_of_another_user_follows_f9() {
        let f = FakeProc::default();
        listing(&f, &[12]);
        process(&f, 12, OTHER, Answer::Errno(libc::ENOENT), b"");
        // Running at the listing, gone at the re-probe: skipped.
        f.set(
            Path::new(ROOT).join("12/stat"),
            vec![
                Answer::Bytes(stat_line(12, "S", 0)),
                Answer::Errno(libc::ENOENT),
            ],
        );
        assert!(!strict(&f));
        // Still running, its files vanished and no thread readable past the bound: in use.
        let f = FakeProc::default();
        listing(&f, &[12]);
        process(&f, 12, OTHER, Answer::Errno(libc::ENOENT), b"");
        f.set(
            Path::new(ROOT).join("12/task"),
            vec![Answer::Names(Vec::new())],
        );
        assert!(strict(&f), "fails closed past the bound");
    }

    #[test]
    fn kernel_threads_are_skipped() {
        let f = FakeProc::default();
        listing(&f, &[2]);
        process(&f, 2, 0, Answer::Errno(libc::ENOENT), b"");
        f.set(
            Path::new(ROOT).join("2/stat"),
            vec![Answer::Bytes(stat_line(2, "S", PF_KTHREAD))],
        );
        assert!(!strict(&f));
    }

    #[test]
    fn any_other_unreadable_read_is_in_use() {
        // An owner that cannot be read.
        let f = FakeProc::default();
        listing(&f, &[13]);
        process(
            &f,
            13,
            OTHER,
            Answer::Link(PathBuf::from("/usr/bin/x")),
            b"",
        );
        f.set(
            Path::new(ROOT).join("13/#owner"),
            vec![Answer::Errno(libc::EIO)],
        );
        assert!(strict(&f));
        // A descriptor table that fails with anything but a refusal or a vanishing.
        let f = FakeProc::default();
        listing(&f, &[13]);
        process(
            &f,
            13,
            OTHER,
            Answer::Link(PathBuf::from("/usr/bin/x")),
            b"",
        );
        f.set(
            Path::new(ROOT).join("13/fd"),
            vec![Answer::Errno(libc::EIO)],
        );
        assert!(strict(&f));
        // Nothing in the tree anywhere: not in use.
        let f = FakeProc::default();
        listing(&f, &[13, 14]);
        process(
            &f,
            13,
            OTHER,
            Answer::Link(PathBuf::from("/usr/bin/x")),
            b"",
        );
        process(&f, 14, ME, Answer::Link(PathBuf::from("/usr/bin/y")), b"");
        assert!(!strict(&f));
        // An unlisted /proc is an error, not an answer.
        let f = FakeProc::default();
        f.set(ROOT, vec![Answer::Errno(libc::EACCES)]);
        assert!(scan(&f, Path::new(ROOT), Path::new(TREE), &[], None).is_err());
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
