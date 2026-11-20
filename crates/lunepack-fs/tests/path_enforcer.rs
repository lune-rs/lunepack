//! Differential test of the core path rules (FORMAT.md 10.1, 10.2) against the real filesystem of
//! the host (APFS on macOS, ext4 or tmpfs on Linux, NTFS on Windows).
//!
//! Accepted names must round-trip exactly and never alias each other. Rejected colliding pairs are
//! created only to show what the filesystem does; an over-reject never fails the test. Device names
//! are never created (opening `COM1` on Windows can hang).

#![cfg(any(target_os = "macos", target_os = "linux", windows))]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::Path;

use lunepack_core::path::{EntryKind, RelPath, validate_path, validate_tree};
use lunepack_core::target::Target;

#[cfg(target_os = "macos")]
const HOST: (&str, Target) = ("macOS (APFS)", Target::MacosAarch64);
#[cfg(target_os = "linux")]
const HOST: (&str, Target) = ("Linux", Target::LinuxX86_64);
#[cfg(windows)]
const HOST: (&str, Target) = ("Windows (NTFS)", Target::WindowsX86_64);

/// Paths the rules accept; together they form one valid tree.
fn accepted_corpus() -> Vec<String> {
    let mut corpus: Vec<String> = [
        "bin/app",
        "Contents/MacOS/App",
        "a b/c.d.e",
        "ünïcode/文件",
        "CONSOLE",
        "nul1.txt",
        "com10",
        "COM¹x",
        "Straße",
        "café.txt",
        "日本語.txt",
        "emoji 😀",
        ".hidden",
        "a.b c",
        "ǆ",
        "x~y",
        "Ωmega",
        "İstanbul",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    corpus.push("a".repeat(255));
    corpus.push(format!("{}a", "é".repeat(127)));
    corpus
}

/// The corpus as tree entries: every proper prefix a directory, every corpus path a file.
fn entries(corpus: &[String]) -> BTreeMap<String, bool /* is_dir */> {
    let mut out = BTreeMap::new();
    for p in corpus {
        let comps: Vec<&str> = p.split('/').collect();
        for i in 1..comps.len() {
            out.insert(comps[..i].join("/"), true);
        }
        out.insert(p.clone(), false);
    }
    out
}

fn create_new_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(content)
}

/// Names in `dir` exactly as `read_dir` reports them.
fn listed(dir: &Path) -> BTreeSet<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let name = e.unwrap().file_name();
            name.into_string()
                .unwrap_or_else(|n| panic!("non-Unicode name read back: {n:?}"))
        })
        .collect()
}

#[test]
fn accepted_names_round_trip_and_never_alias() {
    let corpus = accepted_corpus();
    let tree = entries(&corpus);
    let paths: Vec<(RelPath, bool)> = tree
        .iter()
        .map(|(p, is_dir)| {
            let rel = validate_path(p).unwrap_or_else(|e| panic!("{p:?} rejected: {e}"));
            (rel, *is_dir)
        })
        .collect();
    validate_tree(
        paths.iter().map(|(p, is_dir)| {
            (
                p,
                if *is_dir {
                    EntryKind::Dir
                } else {
                    EntryKind::File
                },
            )
        }),
        HOST.1,
    )
    .expect("the corpus is one valid tree");

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // `create_new` and `create_dir` fail if the name already resolves to an entry, so an alias
    // between two accepted names shows up as `AlreadyExists` here.
    for (p, is_dir) in &tree {
        let full = root.join(p);
        let made = if *is_dir {
            fs::create_dir(&full)
        } else {
            create_new_file(&full, p.as_bytes())
        };
        made.unwrap_or_else(|e| panic!("{}: creating {p:?} failed: {e}", HOST.0));
    }

    // Every directory lists exactly the expected names, byte for byte.
    let mut children: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    children.insert(String::new(), BTreeSet::new());
    for (p, is_dir) in &tree {
        let (parent, name) = p.rsplit_once('/').unwrap_or(("", p));
        children
            .entry(parent.to_owned())
            .or_default()
            .insert(name.to_owned());
        if *is_dir {
            children.entry(p.clone()).or_default();
        }
    }
    for (dir, want) in &children {
        let got = listed(&root.join(dir));
        assert_eq!(&got, want, "{}: listing of {dir:?}", HOST.0);
    }
    // Every file still holds its own path: nothing was overwritten through an alias.
    for (p, is_dir) in &tree {
        if !is_dir {
            assert_eq!(fs::read(root.join(p)).unwrap(), p.as_bytes(), "{p:?}");
        }
    }
}

/// Pairs the rules reject because they can collide on some filesystem. The second name of each
/// pair is rejected by the path rules or the pair by the tree rules.
const COLLIDING: &[(&str, &str)] = &[
    ("A", "a"),
    ("Straße", "STRASSE"),
    ("k", "\u{212A}"), // KELVIN SIGN: not NFC, folds to `k`
    ("é", "e\u{301}"), // NFC and NFD: APFS treats them as one name
    ("ẞ", "ß"),        // capital sharp s: APFS folds it to ss
    ("ẞ", "ss"),
    ("ß", "ss"),
    ("Ω", "\u{2126}"),                    // OHM SIGN: not NFC
    ("x", "x."),                          // Win32 strips a trailing dot
    ("y", "y "),                          // and a trailing space
    ("longfilename.txt", "LONGFI~1.TXT"), // an 8.3 short name where NTFS makes them
];

fn pair_rejected(a: &str, b: &str) -> bool {
    let (Ok(pa), Ok(pb)) = (validate_path(a), validate_path(b)) else {
        return true;
    };
    validate_tree([(&pa, EntryKind::File), (&pb, EntryKind::File)], HOST.1).is_err()
}

#[test]
fn colliding_pairs_are_rejected_and_their_collisions_are_shown() {
    let tmp = tempfile::tempdir().unwrap();
    for (i, (a, b)) in COLLIDING.iter().enumerate() {
        validate_path(a).unwrap_or_else(|e| panic!("{a:?} should be accepted: {e}"));
        assert!(pair_rejected(a, b), "{a:?} and {b:?} should be rejected");

        // Demonstration only: whatever the filesystem does here, the rules already said no.
        let dir = tmp.path().join(i.to_string());
        fs::create_dir(&dir).unwrap();
        create_new_file(&dir.join(a), b"a").unwrap();
        let outcome = match create_new_file(&dir.join(b), b"b") {
            Ok(()) => format!("distinct ({} entries)", listed(&dir).len()),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => "aliases".to_owned(),
            Err(e) => format!("refused: {e}"),
        };
        eprintln!("{}: {a:?} / {b:?}: {outcome}", HOST.0);
    }
}

// ---- links through links (FORMAT.md 10.2, M8-D20): the lexical model against the kernel ----

/// splitmix64: a fixed, dependency-free generator, so every run sees the same trees.
#[cfg(unix)]
struct Rng(u64);

#[cfg(unix)]
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[cfg(unix)]
#[derive(Debug, Clone)]
enum GenKind {
    Dir,
    File,
    Link(String),
}

/// Entry names; link targets also use their upper-case spellings, `.` and `..`.
#[cfg(unix)]
const NAMES: [&str; 3] = ["a", "b", "c"];
#[cfg(unix)]
const TARGET_PARTS: [&str; 8] = ["a", "b", "c", "A", "B", "C", ".", ".."];

/// One small tree: depth at most 3, each name absent, a file, a directory (listed or implied by
/// its children) or a link whose target has 1 to 4 components.
#[cfg(unix)]
fn gen_tree(rng: &mut Rng) -> Vec<(String, GenKind)> {
    fn dir(rng: &mut Rng, prefix: &str, depth: usize, out: &mut Vec<(String, GenKind)>) {
        for name in NAMES {
            let path = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            match rng.below(10) {
                0..=2 => {}
                3 => out.push((path, GenKind::File)),
                4..=5 if depth < 3 => {
                    let listed = rng.below(4) != 0;
                    let before = out.len();
                    dir(rng, &path, depth + 1, out);
                    if listed || out.len() == before {
                        out.push((path, GenKind::Dir));
                    }
                }
                _ => {
                    let parts = 1 + rng.below(4) as usize;
                    let target: Vec<&str> = (0..parts)
                        .map(|_| TARGET_PARTS[rng.below(TARGET_PARTS.len() as u64) as usize])
                        .collect();
                    out.push((path, GenKind::Link(target.join("/"))));
                }
            }
        }
    }
    let mut out = Vec::new();
    dir(rng, "", 1, &mut out);
    out
}

#[cfg(unix)]
fn judge(entries: &[(String, GenKind)]) -> Result<(), lunepack_core::path::TreeError> {
    let paths: Vec<RelPath> = entries
        .iter()
        .map(|(p, _)| validate_path(p).unwrap_or_else(|e| panic!("{p:?}: {e}")))
        .collect();
    validate_tree(
        paths.iter().zip(entries).map(|(p, (_, k))| {
            let kind = match k {
                GenKind::Dir => EntryKind::Dir,
                GenKind::File => EntryKind::File,
                GenKind::Link(t) => EntryKind::Symlink { target: t },
            };
            (p, kind)
        }),
        HOST.1,
    )
}

/// Every name of the target alphabet, nested as directories to depth 3, under `dir`. Where the
/// filesystem folds case (APFS), the lower-case spelling serves both.
#[cfg(unix)]
fn plant_decoys(dir: &Path, depth: usize) {
    if depth == 0 {
        return;
    }
    for name in ["a", "b", "c", "A", "B", "C"] {
        let path = dir.join(name);
        match fs::create_dir(&path) {
            Ok(()) => plant_decoys(&path, depth - 1),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(e) => panic!("decoy {}: {e}", path.display()),
        }
    }
}

#[cfg(unix)]
fn materialise(root: &Path, entries: &[(String, GenKind)]) {
    for (p, kind) in entries {
        let full = root.join(p);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        match kind {
            GenKind::Dir => fs::create_dir_all(&full).unwrap(),
            GenKind::File => create_new_file(&full, b"f").unwrap(),
            GenKind::Link(t) => std::os::unix::fs::symlink(t, &full).unwrap(),
        }
    }
}

/// Where the component walker ended.
#[cfg(unix)]
#[derive(Debug)]
enum Walk {
    /// Resolved to this existing object inside the root.
    Inside(std::path::PathBuf),
    /// Stopped where the kernel stops: ENOENT or ENOTDIR.
    Stopped,
    /// A step left the root (the path need not exist).
    Escaped(std::path::PathBuf),
    /// More than 40 links followed.
    Loop,
}

/// Resolves `rel` under `root` one component at a time, following every link (final included),
/// applying `..` to the physical path already resolved.
#[cfg(unix)]
fn walk(root: &Path, rel: &str) -> Walk {
    use std::collections::VecDeque;
    let mut queue: VecDeque<String> = rel.split('/').map(str::to_owned).collect();
    let mut cur = root.to_path_buf();
    let mut cur_is_dir = true;
    let mut followed = 0;
    while let Some(comp) = queue.pop_front() {
        if !cur_is_dir {
            return Walk::Stopped; // ENOTDIR: a component after a non-directory
        }
        match comp.as_str() {
            "." => {}
            ".." => {
                cur.pop();
                if !cur.starts_with(root) {
                    return Walk::Escaped(cur);
                }
            }
            name => {
                let next = cur.join(name);
                match fs::symlink_metadata(&next) {
                    Err(e) if e.kind() == ErrorKind::NotFound => return Walk::Stopped,
                    Err(e) if e.raw_os_error() == Some(libc_enotdir()) => return Walk::Stopped,
                    Err(e) => panic!("walk {}: {e}", next.display()),
                    Ok(md) if md.file_type().is_symlink() => {
                        followed += 1;
                        if followed > 40 {
                            return Walk::Loop;
                        }
                        let target = fs::read_link(&next).unwrap();
                        let target = target.to_str().unwrap();
                        assert!(!target.starts_with('/'), "absolute target {target:?}");
                        for part in target.split('/').rev() {
                            queue.push_front(part.to_owned());
                        }
                    }
                    Ok(md) => {
                        cur = next;
                        cur_is_dir = md.is_dir();
                    }
                }
            }
        }
    }
    Walk::Inside(cur)
}

#[cfg(unix)]
fn libc_enotdir() -> i32 {
    20 // ENOTDIR on macOS and Linux
}
#[cfg(unix)]
const ENOENT: i32 = 2;
#[cfg(unix)]
const ELOOP: i32 = if cfg!(target_os = "macos") { 62 } else { 40 };

#[test]
#[cfg(unix)]
fn accepted_links_never_leave_the_tree_on_the_host() {
    const TREES: usize = 10_000;
    let tmp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(tmp.path()).unwrap();
    plant_decoys(&base, 3);
    let mut parent = base.clone();
    for level in ["u1", "u2", "u3"] {
        parent = parent.join(level);
        fs::create_dir(&parent).unwrap();
        plant_decoys(&parent, 3);
    }
    let root = parent.join("root");

    let mut rng = Rng(0x4C55_4E45_5041_434B);
    let (mut accepted, mut links_checked) = (0usize, 0usize);
    let mut rejected: BTreeMap<String, usize> = BTreeMap::new();
    let mut rejected_that_escape = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for n in 0..TREES {
        let entries = gen_tree(&mut rng);
        let verdict = judge(&entries);
        if let Err(e) = &verdict {
            let kind = match e {
                lunepack_core::path::TreeError::LinkTarget { source, .. } => {
                    format!("{source:?}").split('(').next().unwrap().to_owned()
                }
                other => format!("{other:?}").split(' ').next().unwrap().to_owned(),
            };
            *rejected.entry(kind).or_default() += 1;
        }
        if fs::symlink_metadata(&root).is_ok() {
            fs::remove_dir_all(&root).unwrap();
        }
        fs::create_dir(&root).unwrap();
        materialise(&root, &entries);
        if verdict.is_err() {
            // Over-rejects are allowed: only count the rejected trees that do escape.
            let escapes = entries.iter().any(|(p, k)| {
                matches!(k, GenKind::Link(_)) && matches!(walk(&root, p), Walk::Escaped(_))
            });
            rejected_that_escape += usize::from(escapes);
            continue;
        }
        accepted += 1;
        for (p, kind) in &entries {
            let GenKind::Link(target) = kind else {
                continue;
            };
            links_checked += 1;
            let what = format!("tree {n} {entries:?}: link {p:?} -> {target:?}");
            // The kernel's verdict is `stat`'s; `canonicalize` (realpath) names where it led.
            // macOS's realpath(3) accepts `file/.` where the kernel says ENOTDIR, so it is not
            // the verdict, but whatever it returns must still lie inside.
            let full = root.join(p);
            if let Ok(k) = fs::canonicalize(&full)
                && !k.starts_with(&root)
            {
                failures.push(format!(
                    "{what}: realpath resolved outside: {}",
                    k.display()
                ));
            }
            let kernel = fs::metadata(&full).and_then(|_| fs::canonicalize(&full));
            let walker = walk(&root, p);
            match (&kernel, &walker) {
                (_, Walk::Escaped(at)) => {
                    failures.push(format!("{what}: walker left the root at {}", at.display()))
                }
                (_, Walk::Loop) => failures.push(format!("{what}: walker met a loop")),
                (Ok(k), _) if !k.starts_with(&root) => {
                    failures.push(format!("{what}: kernel resolved outside: {}", k.display()))
                }
                (Ok(k), Walk::Inside(w)) => {
                    let w = fs::canonicalize(w).unwrap();
                    if &w != k {
                        failures.push(format!(
                            "{what}: kernel {} and walker {} disagree",
                            k.display(),
                            w.display()
                        ));
                    }
                }
                (Ok(k), Walk::Stopped) => failures.push(format!(
                    "{what}: kernel resolved {} where the walker stopped",
                    k.display()
                )),
                (Err(e), _) if e.raw_os_error() == Some(ELOOP) => {
                    failures.push(format!("{what}: kernel ELOOP"))
                }
                (Err(e), Walk::Stopped) if matches!(e.raw_os_error(), Some(c) if c == ENOENT || c == libc_enotdir()) =>
                    {}
                (Err(e), w) => failures.push(format!("{what}: kernel {e}, walker {w:?}")),
            }
        }
    }
    eprintln!(
        "{}: {TREES} trees, {accepted} accepted ({links_checked} links resolved), rejected \
         {rejected:?}, of which {rejected_that_escape} do escape physically",
        HOST.0
    );
    assert!(accepted >= 1_000, "too few accepted trees to mean anything");
    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
    for f in &failures {
        let kind = [
            "walker left the root",
            "walker met a loop",
            "resolved outside",
            "ELOOP",
        ]
        .into_iter()
        .find(|k| f.contains(k))
        .unwrap_or("disagreement");
        *by_kind.entry(kind).or_default() += 1;
    }
    if let Some(first) = failures.iter().find(|f| f.contains("left the root")) {
        eprintln!("first escape: {first}");
    }
    assert!(
        failures.is_empty(),
        "{} accepted links misbehave ({by_kind:?}), first: {}",
        failures.len(),
        failures.first().unwrap()
    );
}
