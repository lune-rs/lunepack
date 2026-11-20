//! Entry paths and trees (FORMAT.md 10.1 and 10.2): one validator for the writer and every reader
//! (C1).
//!
//! Two layers, both pure: [`validate_path`] holds the rules for one string, [`validate_tree`] the
//! rules that only hold for the entry set of one manifest (case-fold collisions, nothing under a
//! non-directory, symlink targets). Several rules over-reject on purpose: they fail closed against
//! the Win32 path normaliser, NTFS, APFS and Linux at once.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Bound;

use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::{Serialize, Serializer};
use unicode_normalization::{UnicodeNormalization, is_nfc};

use crate::error::Untrusted;
use crate::target::Target;

/// Longest path, and longest symlink target, in UTF-8 bytes.
pub const MAX_PATH_BYTES: usize = 1024;
/// Most components in a path.
pub const MAX_PATH_DEPTH: usize = 32;
/// Longest component in UTF-8 bytes (the conservative bound for NTFS, APFS and ext4).
pub const MAX_COMPONENT_BYTES: usize = 255;
/// Most symlink entries followed while resolving one symlink's target (FORMAT.md 10.2): the sum,
/// over every symlink entry the resolution steps onto, of one plus that entry's own count. Far
/// below the kernels' own limits (32 on macOS, 40 on Linux), so an accepted link never meets
/// `ELOOP`.
pub const MAX_LINK_HOPS: usize = 8;

/// Characters Windows refuses in a name; `:` also rules out drive letters and NTFS streams.
const WINDOWS_RESERVED: &[char] = &['<', '>', ':', '"', '|', '?', '*'];
/// Characters whose look-alikes must not appear after NFKC (best-fit and compatibility mappings).
const NFKC_FORBIDDEN: &[char] = &['/', '\\', ':', '*', '?', '"', '<', '>', '|'];

/// Why a path (or a symlink target) was rejected. Untrusted text never appears unescaped or longer
/// than [`Untrusted::MAX_CHARS`] in the message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PathError {
    /// The path is empty.
    #[error("empty path")]
    Empty,
    /// Over [`MAX_PATH_BYTES`].
    #[error("path is {len} bytes, over the {MAX_PATH_BYTES} byte cap")]
    TooLong {
        /// Length in bytes.
        len: usize,
    },
    /// More than [`MAX_PATH_DEPTH`] components.
    #[error("path has more than {MAX_PATH_DEPTH} components")]
    TooDeep,
    /// Not in Unicode NFC.
    #[error("path is not in Unicode NFC")]
    NotNfc,
    /// Starts with `/`.
    #[error("path is absolute")]
    Absolute,
    /// A forbidden character: `\`, NUL, a C0 control, DEL or one of `< > : " | ? *`.
    #[error("forbidden character {ch:?} at byte {offset}")]
    ForbiddenChar {
        /// The character.
        ch: char,
        /// Its byte offset in the path.
        offset: usize,
    },
    /// An empty component (`a//b`, a trailing `/`).
    #[error("component {index} is empty")]
    EmptyComponent {
        /// Zero-based component index.
        index: usize,
    },
    /// Over [`MAX_COMPONENT_BYTES`].
    #[error("component {index} is {len} bytes, over the {MAX_COMPONENT_BYTES} byte cap")]
    ComponentTooLong {
        /// Zero-based component index.
        index: usize,
        /// Length in bytes.
        len: usize,
    },
    /// A `.` or `..` component.
    #[error("component {index} is `.` or `..`")]
    DotComponent {
        /// Zero-based component index.
        index: usize,
    },
    /// A component ends with `.` or a space (Win32 strips them).
    #[error("component {index} ends with a dot or a space")]
    TrailingDotOrSpace {
        /// Zero-based component index.
        index: usize,
    },
    /// A component is a Windows device name.
    #[error("component {index} is a Windows device name")]
    DeviceName {
        /// Zero-based component index.
        index: usize,
    },
    /// A component contains `~` followed by an ASCII digit (an 8.3 short-name look-alike).
    #[error("component {index} looks like an 8.3 short name")]
    ShortNameLike {
        /// Zero-based component index.
        index: usize,
    },
    /// A component's NFKC form holds a forbidden character or is `.` or `..`.
    #[error("component {index} has a compatibility form that is forbidden")]
    CompatibilityForm {
        /// Zero-based component index.
        index: usize,
    },
}

/// A path that passed [`validate_path`]: relative, `/`-separated, NFC.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelPath(String);

impl RelPath {
    /// Validates `text` ([`validate_path`]).
    pub fn parse(text: &str) -> Result<Self, PathError> {
        validate_path(text)
    }

    /// The path text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The components, in order.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// The case-fold key of FORMAT.md 10.2: `NFC(lowercase(uppercase(p)))`.
    pub fn fold_key(&self) -> String {
        fold_key(&self.0)
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelPath({:?})", self.0)
    }
}

impl Serialize for RelPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RelPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PathVisitor;
        impl Visitor<'_> for PathVisitor {
            type Value = RelPath;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a relative entry path")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                validate_path(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(PathVisitor)
    }
}

/// Validates one entry path against every rule of FORMAT.md 10.1.
pub fn validate_path(text: &str) -> Result<RelPath, PathError> {
    if text.is_empty() {
        return Err(PathError::Empty);
    }
    if text.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong { len: text.len() });
    }
    // Characters first: they are meaningful before splitting (`\` is a separator on Windows).
    for (offset, ch) in text.char_indices() {
        if ch == '\\' || ch < ' ' || ch == '\u{7f}' || WINDOWS_RESERVED.contains(&ch) {
            return Err(PathError::ForbiddenChar { ch, offset });
        }
    }
    if !is_nfc(text) {
        return Err(PathError::NotNfc);
    }
    if text.starts_with('/') {
        return Err(PathError::Absolute);
    }
    if text.split('/').count() > MAX_PATH_DEPTH {
        return Err(PathError::TooDeep);
    }
    for (index, comp) in text.split('/').enumerate() {
        validate_component(comp, index)?;
    }
    Ok(RelPath(text.to_owned()))
}

/// The per-component rules; `index` only labels the error. Characters were checked by the caller.
fn validate_component(comp: &str, index: usize) -> Result<(), PathError> {
    if comp.is_empty() {
        return Err(PathError::EmptyComponent { index });
    }
    if comp.len() > MAX_COMPONENT_BYTES {
        return Err(PathError::ComponentTooLong {
            index,
            len: comp.len(),
        });
    }
    if comp == "." || comp == ".." {
        return Err(PathError::DotComponent { index });
    }
    if comp.ends_with('.') || comp.ends_with(' ') {
        return Err(PathError::TrailingDotOrSpace { index });
    }
    if is_device_name(comp) {
        return Err(PathError::DeviceName { index });
    }
    if comp
        .as_bytes()
        .windows(2)
        .any(|w| w[0] == b'~' && w[1].is_ascii_digit())
    {
        return Err(PathError::ShortNameLike { index });
    }
    let compat: String = comp.nfkc().collect();
    if compat == "." || compat == ".." || compat.contains(NFKC_FORBIDDEN) {
        return Err(PathError::CompatibilityForm { index });
    }
    Ok(())
}

/// Whether `name` is a Windows device name in any case, with or without an extension and with or
/// without spaces before the extension (`con`, `Con.txt`, `CON .txt`, `lpt¹.log`). Names that
/// only start with one (`CONSOLE`, `nul1.txt`, `com10`) are not.
pub(crate) fn is_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let Some(rest) = upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
    else {
        return false;
    };
    let mut chars = rest.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => c.is_ascii_digit() || matches!(c, '\u{b9}' | '\u{b2}' | '\u{b3}'),
        _ => false,
    }
}

/// The fold of FORMAT.md 10.2: `NFC(lowercase(uppercase(text)))` with Unicode full case mapping,
/// applied until the string stops changing. One pass is not a fixed point for U+1E9E (it gives
/// `ß`, and `ß` gives `ss`), and `ẞ`, `ß` and `ss` are one name on a case-insensitive filesystem,
/// so the fold repeats until stable (it is idempotent: `fold_key(fold_key(x)) == fold_key(x)`).
/// Case mapping never produces or removes `/`, and `/` is neither cased nor case-ignorable, so the
/// key of a path is the keys of its components joined by `/`.
pub fn fold_key(text: &str) -> String {
    let mut key: String = text.to_uppercase().to_lowercase().nfc().collect();
    loop {
        let next: String = key.to_uppercase().to_lowercase().nfc().collect();
        if next == key {
            return key;
        }
        key = next;
    }
}

/// The kind of one manifest entry, as [`validate_tree`] needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind<'a> {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symlink with its target text.
    Symlink {
        /// The link text, checked by the tree rules.
        target: &'a str,
    },
}

/// Why a symlink target was rejected (FORMAT.md 10.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LinkTargetError {
    /// The target is empty.
    #[error("empty target")]
    Empty,
    /// Over [`MAX_PATH_BYTES`].
    #[error("target is {len} bytes, over the {MAX_PATH_BYTES} byte cap")]
    TooLong {
        /// Length in bytes.
        len: usize,
    },
    /// Not in Unicode NFC.
    #[error("target is not in Unicode NFC")]
    NotNfc,
    /// `\`, NUL, a C0 control or DEL.
    #[error("forbidden character {ch:?} at byte {offset}")]
    ForbiddenChar {
        /// The character.
        ch: char,
        /// Its byte offset in the target.
        offset: usize,
    },
    /// Starts with `/`.
    #[error("target is absolute")]
    Absolute,
    /// An empty component.
    #[error("target has an empty component")]
    EmptyComponent,
    /// Resolution from the link's parent leaves the tree.
    #[error("target leaves the tree")]
    Escapes,
    /// A symlink entry followed in a non-final position does not end on a directory (it ends on a
    /// file, or on a name with no entry). Names that symlink.
    #[error("target passes through the symlink {0}, which does not end on a directory")]
    HopNotDirectory(Untrusted),
    /// The resolution steps onto a symlink entry whose own resolution is in progress. Names that
    /// symlink.
    #[error("target loops through the symlink {0}")]
    Cycle(Untrusted),
    /// The resolution follows more than [`MAX_LINK_HOPS`] symlink entries.
    #[error("target follows more than {MAX_LINK_HOPS} symlinks")]
    TooManyHops,
}

/// Why an entry set was rejected (FORMAT.md 10.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TreeError {
    /// Two entries have the same case-fold key.
    #[error("{first} and {second} collide when case is folded")]
    Collision {
        /// The earlier entry.
        first: Untrusted,
        /// The later entry.
        second: Untrusted,
    },
    /// An entry lies under a `file` or `symlink` entry.
    #[error("{path} lies under the non-directory {parent}")]
    UnderNonDirectory {
        /// The file or symlink entry.
        parent: Untrusted,
        /// The entry under it.
        path: Untrusted,
    },
    /// A symlink in a manifest for a Windows target.
    #[error("symlink {0} in a Windows manifest")]
    SymlinkOnWindows(Untrusted),
    /// A symlink target broke a rule.
    #[error("symlink {path}: {source}")]
    LinkTarget {
        /// The symlink entry.
        path: Untrusted,
        /// The broken rule.
        #[source]
        source: LinkTargetError,
    },
}

/// Validates the entry set of one manifest for `target` (FORMAT.md 10.2): no two entries with equal
/// fold keys, nothing under a `file` or `symlink` entry, no symlink on a Windows target, and every
/// symlink target stays inside the tree.
///
/// A target is resolved from the link's parent on a stack of fold keys: `.` stays, `..` pops (and
/// leaving the root is [`LinkTargetError::Escapes`]), any other name is pushed and looked up by fold
/// key. A name that is a symlink entry, in any position, is a hop: its own target is resolved by the
/// same rule and the stack becomes where it led, so a later `..` pops that place. A hop that is
/// not the last component must end on a directory: the root, a `dir` entry or an implied parent
/// directory ([`LinkTargetError::HopNotDirectory`]). The link's own end may be anything inside,
/// a name with no entry included. A hop into a link whose resolution is in progress is
/// [`LinkTargetError::Cycle`], and more than [`MAX_LINK_HOPS`] hops is
/// [`LinkTargetError::TooManyHops`] (a long cycle may be reported as that first). Which link the
/// first error names follows the entry order; the verdict does not.
///
/// Cost: one fold key and one ordered-map insert per entry, one range lookup per non-directory
/// entry, and, when there are symlinks, one node per entry in a component tree. Each symlink's
/// target is resolved at most once (memoised; only results that do not depend on the depth they
/// were reached at are kept), with one map lookup per target component: `O(n log n)` in the entry
/// count plus the targets' bytes. Recursion is at most `MAX_LINK_HOPS + 1` frames deep.
pub fn validate_tree<'a, I>(entries: I, target: Target) -> Result<(), TreeError>
where
    I: IntoIterator<Item = (&'a RelPath, EntryKind<'a>)>,
{
    // fold key -> (entry path, kind)
    let mut by_key: BTreeMap<String, (&RelPath, EntryKind<'_>)> = BTreeMap::new();
    let mut links: Vec<(&RelPath, &str)> = Vec::new();
    for (path, kind) in entries {
        if let EntryKind::Symlink { target: link } = kind {
            if target.is_windows() {
                return Err(TreeError::SymlinkOnWindows(untrusted(path)));
            }
            links.push((path, link));
        }
        if let Some((first, _)) = by_key.insert(path.fold_key(), (path, kind)) {
            return Err(TreeError::Collision {
                first: untrusted(first),
                second: untrusted(path),
            });
        }
    }
    // Nothing under a non-directory: the keys under `k` are exactly those starting with `k/`, and
    // they sort contiguously from `k/`, so the first key at or after `k/` decides.
    for (key, (parent, kind)) in &by_key {
        if matches!(kind, EntryKind::Dir) {
            continue;
        }
        let prefix = format!("{key}/");
        let next = by_key
            .range::<str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded))
            .next();
        if let Some((under, (path, _))) = next
            && under.starts_with(&prefix)
        {
            return Err(TreeError::UnderNonDirectory {
                parent: untrusted(parent),
                path: untrusted(path),
            });
        }
    }
    if links.is_empty() {
        return Ok(());
    }
    // Every target's text first, so a hop never walks a target that breaks a text rule.
    for (path, link) in &links {
        check_link_text(link).map_err(|source| TreeError::LinkTarget {
            path: untrusted(path),
            source,
        })?;
    }
    let mut resolver = Resolver::new(&by_key);
    for (path, _) in links {
        let node = resolver.node_of(&path.fold_key());
        resolver
            .resolve(node, 0)
            .map_err(|source| TreeError::LinkTarget {
                path: untrusted(path),
                source,
            })?;
    }
    Ok(())
}

/// The text rules of one symlink target (FORMAT.md 10.2), before any resolution.
fn check_link_text(link: &str) -> Result<(), LinkTargetError> {
    if link.is_empty() {
        return Err(LinkTargetError::Empty);
    }
    if link.len() > MAX_PATH_BYTES {
        return Err(LinkTargetError::TooLong { len: link.len() });
    }
    for (offset, ch) in link.char_indices() {
        if ch == '\\' || ch < ' ' || ch == '\u{7f}' {
            return Err(LinkTargetError::ForbiddenChar { ch, offset });
        }
    }
    if !is_nfc(link) {
        return Err(LinkTargetError::NotNfc);
    }
    if link.starts_with('/') {
        return Err(LinkTargetError::Absolute);
    }
    if link.split('/').any(str::is_empty) {
        return Err(LinkTargetError::EmptyComponent);
    }
    Ok(())
}

/// The root of the component tree.
const ROOT: usize = 0;

/// One node of the component tree: the root, an entry, or an implied parent directory.
struct Node<'a> {
    parent: usize,
    /// Children by the fold key of their last component.
    children: BTreeMap<String, usize>,
    /// The entry at this node; `None` for the root and implied directories (both directories).
    entry: Option<(&'a RelPath, EntryKind<'a>)>,
}

/// Where a resolution stands: a node of the component tree, then `missing` more components that
/// name no entry (nothing exists under a missing name, so their spelling no longer matters).
#[derive(Debug, Clone, Copy)]
struct Resolved {
    node: usize,
    missing: usize,
    /// Symlink entries followed, counted as [`MAX_LINK_HOPS`] says.
    hops: usize,
}

enum Memo {
    Unseen,
    InProgress,
    Done(Result<Resolved, LinkTargetError>),
}

/// Resolves symlink targets over the component tree of one entry set, each at most once.
struct Resolver<'a> {
    nodes: Vec<Node<'a>>,
    /// Indexed by node; only symlink nodes ever leave `Unseen`.
    memo: Vec<Memo>,
}

impl<'a> Resolver<'a> {
    fn new(by_key: &BTreeMap<String, (&'a RelPath, EntryKind<'a>)>) -> Self {
        let mut nodes = vec![Node {
            parent: ROOT,
            children: BTreeMap::new(),
            entry: None,
        }];
        for (key, entry) in by_key {
            let mut at = ROOT;
            for comp in key.split('/') {
                at = match nodes[at].children.get(comp) {
                    Some(&child) => child,
                    None => {
                        let child = nodes.len();
                        nodes.push(Node {
                            parent: at,
                            children: BTreeMap::new(),
                            entry: None,
                        });
                        nodes[at].children.insert(comp.to_owned(), child);
                        child
                    }
                };
            }
            nodes[at].entry = Some(*entry);
        }
        let memo = nodes.iter().map(|_| Memo::Unseen).collect();
        Resolver { nodes, memo }
    }

    /// The node of an entry's fold key (every entry has one).
    fn node_of(&self, key: &str) -> usize {
        key.split('/').fold(ROOT, |at, comp| {
            *self.nodes[at]
                .children
                .get(comp)
                .expect("every entry has a node")
        })
    }

    fn is_dir(&self, at: &Resolved) -> bool {
        at.missing == 0 && matches!(self.nodes[at.node].entry, None | Some((_, EntryKind::Dir)))
    }

    /// Resolves the symlink at `link`, reached through `depth` nested hops.
    fn resolve(&mut self, link: usize, depth: usize) -> Result<Resolved, LinkTargetError> {
        match &self.memo[link] {
            Memo::Done(result) => return result.clone(),
            Memo::InProgress => return Err(LinkTargetError::Cycle(self.name(link))),
            Memo::Unseen => {}
        }
        // Each nested frame is one hop of the outermost link, so a depth past the bound means
        // that link's count is past it too.
        if depth > MAX_LINK_HOPS {
            return Err(LinkTargetError::TooManyHops);
        }
        self.memo[link] = Memo::InProgress;
        let result = self.walk(link, depth);
        // `TooManyHops` can depend on the depth this link was reached at: never kept.
        self.memo[link] = match &result {
            Err(LinkTargetError::TooManyHops) => Memo::Unseen,
            other => Memo::Done(other.clone()),
        };
        result
    }

    fn walk(&mut self, link: usize, depth: usize) -> Result<Resolved, LinkTargetError> {
        let Some((_, EntryKind::Symlink { target })) = self.nodes[link].entry else {
            unreachable!("only symlink entries are resolved");
        };
        let mut at = Resolved {
            node: self.nodes[link].parent,
            missing: 0,
            hops: 0,
        };
        let comps: Vec<&str> = target.split('/').collect();
        let last = comps.len() - 1;
        for (i, comp) in comps.into_iter().enumerate() {
            match comp {
                // `.` names the directory the resolution is in, so it stays there. Pushing it as
                // a name would let `./..` pop it and hide one level of escape.
                "." => {}
                ".." => {
                    if at.missing > 0 {
                        at.missing -= 1;
                    } else if at.node == ROOT {
                        return Err(LinkTargetError::Escapes);
                    } else {
                        at.node = self.nodes[at.node].parent;
                    }
                }
                name => {
                    if at.missing > 0 {
                        at.missing += 1;
                        continue;
                    }
                    let Some(&child) = self.nodes[at.node].children.get(fold_key(name).as_str())
                    else {
                        at.missing = 1;
                        continue;
                    };
                    if !matches!(
                        self.nodes[child].entry,
                        Some((_, EntryKind::Symlink { .. }))
                    ) {
                        at.node = child;
                        continue;
                    }
                    let hop = self.resolve(child, depth + 1)?;
                    let hops = at.hops + 1 + hop.hops;
                    if hops > MAX_LINK_HOPS {
                        return Err(LinkTargetError::TooManyHops);
                    }
                    if i < last && !self.is_dir(&hop) {
                        return Err(LinkTargetError::HopNotDirectory(self.name(child)));
                    }
                    at = Resolved { hops, ..hop };
                }
            }
        }
        Ok(at)
    }

    fn name(&self, node: usize) -> Untrusted {
        match self.nodes[node].entry {
            Some((path, _)) => untrusted(path),
            None => Untrusted::new(""),
        }
    }
}

fn untrusted(path: &RelPath) -> Untrusted {
    Untrusted::new(path.as_str())
}
