//! The runtime's private directories under the user's temp dir (Windows, M7-D5, M7-D13): the
//! uninstaller's copy (`lunepack-uninstall-<16 hex>`) and a setup's UI (`lunepack-setup-ui-<16
//! hex>`).
//!
//! Each is created new (never an existing path) directly under the temp dir, with a marker file
//! written create-new: one line of strict JSON naming the app id and the process identity (pid and
//! start time) of the run that made it. A run that ends removes its own directory when it can; one
//! it cannot remove (a running image) stays until a later lunepack run of any app removes it with
//! [`clear_stale`]: only a real directory named exactly `<prefix><16 lowercase hex>`, holding a
//! regular marker file whose bytes are exactly a marker, whose process no longer runs and from which
//! no process runs. Anything else under the temp dir is never touched.

#![cfg_attr(not(windows), allow(dead_code))]

use std::io::Write as _;
use std::path::{Path, PathBuf};

use lunepack::{FileKind, Fs, ProcessId, Rng};

/// The prefix of an uninstaller's copy (M7-D5).
pub const UNINSTALL_PREFIX: &str = "lunepack-uninstall-";
/// The prefix of a setup's UI directory (M7-D13).
pub const SETUP_UI_PREFIX: &str = "lunepack-setup-ui-";
/// The marker file inside either.
pub const MARKER_FILE: &str = "lunepack-marker.json";
/// The longest marker read.
const MARKER_CAP: u64 = 256;
/// The random bytes of a directory's name (16 hex digits).
const RANDOM_BYTES: usize = 8;

/// What a marker names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    /// The app id (FORMAT.md 10.6 text).
    pub app_id: String,
    /// The process that made the directory.
    pub owner: ProcessId,
}

impl Marker {
    /// The marker's bytes: `{"app_id":"<id>","pid":<u32>,"start":<u64>}` and a newline.
    pub fn to_text(&self) -> String {
        format!(
            "{{\"app_id\":\"{}\",\"pid\":{},\"start\":{}}}\n",
            self.app_id, self.owner.pid, self.owner.start_ticks
        )
    }

    /// Parses a marker strictly: only the exact bytes [`Marker::to_text`] writes for a valid app
    /// id (no other member, order, spacing, escape or number form).
    pub fn parse(bytes: &[u8]) -> Option<Marker> {
        let text = std::str::from_utf8(bytes).ok()?;
        let rest = text.strip_prefix("{\"app_id\":\"")?;
        let (app_id, rest) = rest.split_once('"')?;
        let rest = rest.strip_prefix(",\"pid\":")?;
        let (pid, rest) = rest.split_once(',')?;
        let rest = rest.strip_prefix("\"start\":")?;
        let start = rest.strip_suffix("}\n")?;
        lunepack::AppId::parse(app_id).ok()?;
        let marker = Marker {
            app_id: app_id.to_owned(),
            owner: ProcessId {
                pid: plain_number(pid)?,
                start_ticks: plain_number(start)?,
            },
        };
        (marker.to_text() == text).then_some(marker)
    }
}

/// A decimal number of ASCII digits with no sign and no leading zero (but `0`).
fn plain_number<T: std::str::FromStr>(text: &str) -> Option<T> {
    let plain = !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    plain.then(|| text.parse().ok()).flatten()
}

/// Whether `name` is `prefix` followed by exactly 16 lowercase hex digits.
pub fn is_dir_name(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(|hex| {
        hex.len() == RANDOM_BYTES * 2
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The user's temp dir (`GetTempPath2W` on Windows: `TMP`, `TEMP`, ...), canonical; `None` when
/// it cannot be resolved.
pub fn temp_home() -> Option<PathBuf> {
    std::fs::canonicalize(std::env::temp_dir()).ok()
}

/// Creates `<temp>\<prefix><16 hex>` new (an existing path is an error, nothing is followed) and
/// writes its marker create-new. A directory made before a failure is removed.
pub fn create(
    fs: &dyn Fs,
    rng: &dyn Rng,
    temp: &Path,
    prefix: &str,
    marker: &Marker,
) -> std::io::Result<PathBuf> {
    let mut random = [0u8; RANDOM_BYTES];
    rng.fill(&mut random).map_err(std::io::Error::other)?;
    let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let dir = temp.join(format!("{prefix}{name}"));
    // `create_dir` of a new name: fails on anything already there.
    std::fs::create_dir(&dir)?;
    let written = write_new(&dir.join(MARKER_FILE), marker.to_text().as_bytes());
    if let Err(e) = written {
        let _ = fs.remove_dir_all_nofollow(&dir);
        return Err(e);
    }
    Ok(dir)
}

/// Writes `bytes` to the new file `path` (create-new) and syncs it.
pub fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// The marker of the real directory `dir`: a regular file read with a cap, parsed strictly.
pub fn read_marker(fs: &dyn Fs, dir: &Path) -> Option<Marker> {
    let path = dir.join(MARKER_FILE);
    match fs.symlink_metadata(&path) {
        Ok(Some(meta)) if meta.kind == FileKind::File => {}
        _ => return None,
    }
    Marker::parse(&fs.read_capped(&path, MARKER_CAP).ok()?)
}

/// Whether process `pid` started at `start` runs. A process that cannot be read counts as running.
pub type Alive<'a> = &'a dyn Fn(u32, u64) -> bool;
/// Whether any process runs from (or holds its image in) a directory. An error counts as yes.
pub type InUse<'a> = &'a dyn Fn(&Path) -> bool;

/// Removes earlier runs' directories under `temp` (see the module text); returns how many went.
/// Best effort: anything that cannot be read or removed is kept.
pub fn clear_stale(fs: &dyn Fs, temp: &Path, alive: Alive<'_>, in_use: InUse<'_>) -> usize {
    let Ok(entries) = fs.list_dir(temp) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries {
        let Some(name) = entry.name.to_str() else {
            continue;
        };
        if !(is_dir_name(name, UNINSTALL_PREFIX) || is_dir_name(name, SETUP_UI_PREFIX)) {
            continue;
        }
        let dir = temp.join(name);
        // Checked again here, not followed: a reparse point or a file is never a directory of ours.
        match fs.symlink_metadata(&dir) {
            Ok(Some(meta)) if meta.kind == FileKind::Dir => {}
            _ => continue,
        }
        let Some(marker) = read_marker(fs, &dir) else {
            continue;
        };
        if alive(marker.owner.pid, marker.owner.start_ticks) || in_use(&dir) {
            continue;
        }
        if fs.remove_dir_all_nofollow(&dir).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(app: &str, pid: u32, start: u64) -> Marker {
        Marker {
            app_id: app.to_owned(),
            owner: ProcessId {
                pid,
                start_ticks: start,
            },
        }
    }

    #[test]
    fn a_marker_reads_back_and_only_its_exact_bytes_parse() {
        let m = marker("org.example.app", 42, 133_000_000_000);
        assert_eq!(
            m.to_text(),
            "{\"app_id\":\"org.example.app\",\"pid\":42,\"start\":133000000000}\n"
        );
        assert_eq!(Marker::parse(m.to_text().as_bytes()), Some(m));
        for bad in [
            "",
            "{\"app_id\":\"org.example.app\",\"pid\":42,\"start\":1}",
            "{\"app_id\":\"org.example.app\",\"pid\":42,\"start\":1}\n\n",
            "{\"app_id\":\"org.example.app\",\"pid\":42,\"start\":1} \n",
            "{ \"app_id\":\"org.example.app\",\"pid\":42,\"start\":1}\n",
            "{\"pid\":42,\"app_id\":\"org.example.app\",\"start\":1}\n",
            "{\"app_id\":\"org.example.app\",\"pid\":042,\"start\":1}\n",
            "{\"app_id\":\"org.example.app\",\"pid\":-1,\"start\":1}\n",
            "{\"app_id\":\"org.example.app\",\"pid\":4294967296,\"start\":1}\n",
            "{\"app_id\":\"org.example.app\",\"pid\":1,\"start\":1,\"x\":1}\n",
            "{\"app_id\":\"Org.Example\",\"pid\":1,\"start\":1}\n",
            "{\"app_id\":\"a\\\"b\",\"pid\":1,\"start\":1}\n",
            "{\"app_id\":\"\",\"pid\":1,\"start\":1}\n",
        ] {
            assert_eq!(Marker::parse(bad.as_bytes()), None, "{bad:?}");
        }
    }

    #[test]
    fn only_a_prefix_and_sixteen_lowercase_hex_digits_name_a_directory() {
        assert!(is_dir_name(
            "lunepack-uninstall-0123456789abcdef",
            UNINSTALL_PREFIX
        ));
        assert!(is_dir_name(
            "lunepack-setup-ui-ffffffffffffffff",
            SETUP_UI_PREFIX
        ));
        for bad in [
            "lunepack-uninstall-0123456789ABCDEF",
            "lunepack-uninstall-0123456789abcde",
            "lunepack-uninstall-0123456789abcdef0",
            "lunepack-uninstall-0123456789abcdeg",
            "lunepack-uninstall-",
            "Lunepack-uninstall-0123456789abcdef",
            "xlunepack-uninstall-0123456789abcdef",
            "lunepack-setup-ui-0123456789abcdef",
        ] {
            assert!(!is_dir_name(bad, UNINSTALL_PREFIX), "{bad}");
        }
    }

    struct Seq(std::sync::atomic::AtomicU8);

    impl Rng for Seq {
        fn fill(&self, buf: &mut [u8]) -> Result<(), lunepack_core::Error> {
            let n = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            buf.fill(n);
            Ok(())
        }
    }

    #[test]
    fn the_cleanup_removes_only_dead_unused_marked_directories_of_the_exact_names() {
        let tmp = tempfile::tempdir().expect("tmp");
        let temp = tmp.path();
        let fs = lunepack_fs::StdFs::new();
        let rng = Seq(std::sync::atomic::AtomicU8::new(1));
        let dead = create(&fs, &rng, temp, UNINSTALL_PREFIX, &marker("org.a", 7, 1)).expect("dir");
        let live = create(&fs, &rng, temp, SETUP_UI_PREFIX, &marker("org.b", 8, 2)).expect("dir");
        let used = create(&fs, &rng, temp, UNINSTALL_PREFIX, &marker("org.c", 7, 1)).expect("dir");
        std::fs::write(dead.join("payload"), b"x").expect("payload");
        // Same random bytes again: the name exists, so creation fails and nothing is reused.
        let again = create(
            &fs,
            &Seq(std::sync::atomic::AtomicU8::new(1)),
            temp,
            UNINSTALL_PREFIX,
            &marker("org.a", 9, 9),
        );
        assert!(again.is_err());
        assert_eq!(read_marker(&fs, &dead), Some(marker("org.a", 7, 1)));

        let keep = |name: &str, marker: Option<&str>| {
            let d = temp.join(name);
            std::fs::create_dir(&d).expect("dir");
            if let Some(m) = marker {
                std::fs::write(d.join(MARKER_FILE), m).expect("marker");
            }
            d
        };
        let dead_text = marker("org.a", 7, 1).to_text();
        let kept = [
            keep("lunepack-uninstall-aaaaaaaaaaaaaaaa", None),
            // Upper case (distinct letters: the test's filesystem may ignore case).
            keep("lunepack-uninstall-ABCDEF0123456789", Some(&dead_text)),
            keep("lunepack-uninstall-bbbbbbbbbbbbbbb", Some(&dead_text)),
            keep("lunepack-other-cccccccccccccccc", Some(&dead_text)),
            keep(
                "lunepack-setup-ui-dddddddddddddddd",
                Some("{\"app_id\":\"org.a\",\"pid\":7,\"start\":1} \n"),
            ),
        ];
        // A file with a directory's name, and a marker that is a directory.
        std::fs::write(temp.join("lunepack-uninstall-eeeeeeeeeeeeeeee"), &dead_text).expect("f");
        let dir_marker = keep("lunepack-uninstall-ffffffffffffffff", None);
        std::fs::create_dir(dir_marker.join(MARKER_FILE)).expect("dir marker");

        let alive = |pid: u32, start: u64| (pid, start) == (8, 2);
        let used_dir = used.clone();
        let in_use = move |dir: &Path| dir == used_dir;
        assert_eq!(clear_stale(&fs, temp, &alive, &in_use), 1);
        assert!(!dead.exists(), "the dead run's directory was kept");
        for d in kept.iter().chain([&live, &used, &dir_marker]) {
            assert!(d.is_dir(), "{d:?} was removed");
        }
        assert!(temp.join("lunepack-uninstall-eeeeeeeeeeeeeeee").is_file());
    }
}
