//! The publisher-continuity check's fake and contract suite (M9, C7).
//!
//! [`FakePublisherCheck`] answers from a script and records what it was asked. The suite
//! ([`run_publisher_suite`]) is what each adapter runs against its real check: on a platform that can
//! make signed trees it asks a [`PublisherFixtures`] provider for same-publisher, other-publisher,
//! unsigned and tampered trees and asserts the closed outcomes of M9-D9; on a platform with no check
//! it asserts [`PublisherError::NotApplicable`] for everything. [`MarkerPublisher`] is a tiny
//! file-based model of a signed tree that is both a check and a provider, so the suite has a
//! subject that passes and the suite's own sensitivity can be shown.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use lunepack_core::{PublisherCheck, PublisherError, RelPath, SignedTree};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A [`PublisherCheck`] that gives its scripted results in order and records every call. When the
/// script is spent it answers [`PublisherError::Os`], which every policy treats as a local fault,
/// never as an approval.
#[derive(Debug, Default)]
pub struct FakePublisherCheck {
    script: Mutex<VecDeque<Result<bool, PublisherError>>>,
    calls: Mutex<Vec<(SignedTree, SignedTree)>>,
}

impl FakePublisherCheck {
    /// A fake that answers `script`, one result per call.
    pub fn new(script: impl IntoIterator<Item = Result<bool, PublisherError>>) -> Self {
        FakePublisherCheck {
            script: Mutex::new(script.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// The `(installed, candidate)` pairs asked so far.
    pub fn calls(&self) -> Vec<(SignedTree, SignedTree)> {
        lock(&self.calls).clone()
    }
}

impl PublisherCheck for FakePublisherCheck {
    fn same_publisher(
        &self,
        installed: &SignedTree,
        candidate: &SignedTree,
    ) -> Result<bool, PublisherError> {
        lock(&self.calls).push((installed.clone(), candidate.clone()));
        lock(&self.script)
            .pop_front()
            .unwrap_or(Err(PublisherError::Os))
    }
}

/// Makes trees for the suite. A method returns `None` when this platform cannot make that kind of
/// tree (no signing tool, no way to alter a signature), and the cases that need it are skipped
/// with a printed reason, never silently.
pub trait PublisherFixtures {
    /// A tree under `dir` signed by the publisher named `publisher` (`"a"` or `"b"`; two names are
    /// two identities). Every call with the same name is the same identity.
    fn signed(&self, dir: &Path, publisher: &str) -> Option<SignedTree>;
    /// A tree under `dir` with no signature.
    fn unsigned(&self, dir: &Path) -> Option<SignedTree>;
    /// A tree signed by publisher `a` whose signature no longer verifies (a signed byte altered).
    fn tampered(&self, dir: &Path) -> Option<SignedTree>;
}

/// What an adapter's suite run expects.
pub enum PublisherSuite<'a> {
    /// A platform with no check: every pair, whatever the trees, is `NotApplicable`.
    NotApplicable,
    /// A platform with a check, and the trees to ask it about.
    Signed(&'a dyn PublisherFixtures),
}

/// Runs the publisher contract suite against `check`, with scratch directories under `scratch`
/// (an existing, empty directory; nothing outside it is touched). Panics on a violation.
///
/// For [`PublisherSuite::Signed`]: same publisher is `Ok(true)`; another publisher is `Ok(false)`
/// both ways; an unsigned installed tree is `InstalledUnsigned`, an unsigned candidate
/// `CandidateUnsigned`, a tampered installed tree `InstalledInvalid`, a tampered candidate
/// `CandidateInvalid`; with both trees bad the installed tree's finding wins (it is examined
/// first); no error text carries a path; the check is repeatable.
pub fn run_publisher_suite(check: &dyn PublisherCheck, suite: PublisherSuite<'_>, scratch: &Path) {
    match suite {
        PublisherSuite::NotApplicable => not_applicable(check, scratch),
        PublisherSuite::Signed(fixtures) => signed(check, fixtures, scratch),
    }
}

fn not_applicable(check: &dyn PublisherCheck, scratch: &Path) {
    let entry = RelPath::parse("bin/app").expect("a path");
    let tree = |name: &str| SignedTree {
        root: scratch.join(name),
        entry: entry.clone(),
    };
    // Trees that do not exist, and the same tree twice: the answer does not depend on either.
    for (a, b) in [("one", "two"), ("one", "one")] {
        assert_eq!(
            check.same_publisher(&tree(a), &tree(b)),
            Err(PublisherError::NotApplicable),
            "a platform with no check answers not_applicable"
        );
    }
}

fn skip(what: &str) {
    eprintln!("skipped: the publisher suite cannot make {what} on this platform");
}

/// A fresh directory `name` under `scratch`.
fn dir(scratch: &Path, name: &str) -> std::path::PathBuf {
    let path = scratch.join(name);
    fs::create_dir(&path).unwrap_or_else(|e| panic!("cannot create the suite's {name} dir: {e}"));
    path
}

fn signed(check: &dyn PublisherCheck, fixtures: &dyn PublisherFixtures, scratch: &Path) {
    let mut n = 0;
    let mut next = |what: &str| {
        n += 1;
        dir(scratch, &format!("{n}-{what}"))
    };
    let ask = |installed: &SignedTree, candidate: &SignedTree| {
        let first = check.same_publisher(installed, candidate);
        // The same question has the same answer.
        assert_eq!(
            first,
            check.same_publisher(installed, candidate),
            "repeatable"
        );
        if let Err(e) = first {
            let shown = format!("{e} {e:?}");
            let root = scratch.to_string_lossy();
            assert!(
                !shown.contains(root.as_ref()) && !shown.contains('/') && !shown.contains('\\'),
                "an error carries a path: {shown}"
            );
        }
        first
    };

    let (Some(a1), Some(a2)) = (
        fixtures.signed(&next("a-installed"), "a"),
        fixtures.signed(&next("a-candidate"), "a"),
    ) else {
        // Without even a signed tree there is nothing the suite can say.
        skip("a signed tree");
        return;
    };
    assert_eq!(ask(&a1, &a2), Ok(true), "same publisher");
    assert_eq!(ask(&a2, &a1), Ok(true), "same publisher, the other way");
    assert_eq!(ask(&a1, &a1), Ok(true), "a tree against itself");

    match fixtures.signed(&next("b-candidate"), "b") {
        Some(b) => {
            assert_eq!(ask(&a1, &b), Ok(false), "another publisher");
            assert_eq!(ask(&b, &a1), Ok(false), "another publisher, the other way");
        }
        None => skip("a second identity"),
    }

    match fixtures.unsigned(&next("unsigned")) {
        Some(u) => {
            assert_eq!(ask(&u, &a1), Err(PublisherError::InstalledUnsigned));
            assert_eq!(ask(&a1, &u), Err(PublisherError::CandidateUnsigned));
            let u2 = fixtures
                .unsigned(&next("unsigned-2"))
                .expect("a second one");
            assert_eq!(
                ask(&u, &u2),
                Err(PublisherError::InstalledUnsigned),
                "the installed tree is examined first"
            );
        }
        None => skip("an unsigned tree"),
    }

    match fixtures.tampered(&next("tampered")) {
        Some(t) => {
            assert_eq!(ask(&t, &a1), Err(PublisherError::InstalledInvalid));
            assert_eq!(ask(&a1, &t), Err(PublisherError::CandidateInvalid));
        }
        None => skip("a tampered tree"),
    }
}

// ---- a file-based model of a signed tree ----------------------------------------------------------

/// The seal file of a [`MarkerPublisher`] tree.
const SEAL: &str = "SEAL";
/// The entry's path in the trees [`MarkerPublisher`] makes.
const ENTRY: &str = "bin/app";

/// A small model of a signed tree, for testing the suite and the policy plumbing without an
/// operating system: the seal file `SEAL` holds `publisher=<name>;sum=<checksum of the entry>`. A
/// tree with no seal is unsigned; a seal whose sum does not match the entry is invalid; any other
/// read failure is [`PublisherError::Os`]. It is deliberately not any real signature scheme.
#[derive(Debug, Default, Clone, Copy)]
pub struct MarkerPublisher;

fn sum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn seal_for(publisher: &str, entry: &[u8]) -> String {
    format!("publisher={publisher};sum={:016x}", sum(entry))
}

fn make_tree(dir: &Path, seal: Option<String>, entry: &[u8]) -> SignedTree {
    let at = dir.join(ENTRY);
    fs::create_dir_all(at.parent().expect("a parent")).expect("create the tree");
    fs::write(&at, entry).expect("write the entry");
    if let Some(seal) = seal {
        fs::write(dir.join(SEAL), seal).expect("write the seal");
    }
    SignedTree {
        root: dir.to_path_buf(),
        entry: RelPath::parse(ENTRY).expect("a path"),
    }
}

impl PublisherFixtures for MarkerPublisher {
    fn signed(&self, dir: &Path, publisher: &str) -> Option<SignedTree> {
        let entry = format!("entry bytes of {}", dir.display());
        Some(make_tree(
            dir,
            Some(seal_for(publisher, entry.as_bytes())),
            entry.as_bytes(),
        ))
    }

    fn unsigned(&self, dir: &Path) -> Option<SignedTree> {
        Some(make_tree(dir, None, b"unsigned entry"))
    }

    fn tampered(&self, dir: &Path) -> Option<SignedTree> {
        let tree = self.signed(dir, "a")?;
        fs::write(dir.join(ENTRY), b"altered after signing").expect("alter the entry");
        Some(tree)
    }
}

/// The publisher a tree is sealed by: `Unsigned`, `Invalid` or the name.
fn seal_of(
    tree: &SignedTree,
    invalid: PublisherError,
    unsigned: PublisherError,
) -> Result<String, PublisherError> {
    let seal = match fs::read_to_string(tree.root.join(SEAL)) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(unsigned),
        Err(_) => return Err(PublisherError::Os),
    };
    let entry = fs::read(tree.root.join(tree.entry.as_str())).map_err(|_| PublisherError::Os)?;
    let Some((publisher, rest)) = seal
        .strip_prefix("publisher=")
        .and_then(|t| t.split_once(';'))
    else {
        return Err(invalid);
    };
    if rest != format!("sum={:016x}", sum(&entry)) {
        return Err(invalid);
    }
    Ok(publisher.to_owned())
}

impl PublisherCheck for MarkerPublisher {
    fn same_publisher(
        &self,
        installed: &SignedTree,
        candidate: &SignedTree,
    ) -> Result<bool, PublisherError> {
        let a = seal_of(
            installed,
            PublisherError::InstalledInvalid,
            PublisherError::InstalledUnsigned,
        )?;
        let b = seal_of(
            candidate,
            PublisherError::CandidateInvalid,
            PublisherError::CandidateUnsigned,
        )?;
        Ok(a == b)
    }
}
