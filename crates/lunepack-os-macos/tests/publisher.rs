//! `MacPublisherCheck` against real bundles signed with the host's `codesign` (M9-D7, M9-R1-D2).
//!
//! Always run: ad-hoc and unsigned trees (no identity is needed), which also pin the Security
//! status values the check depends on. Run when a throwaway identity is given (the macOS CI job
//! of M9 step 9, or a developer who sets the variables): two identities in a temporary keychain that is never this machine's login keychain or search list, named by
//! `LUNEPACK_TEST_KEYCHAIN` (a path), `LUNEPACK_TEST_IDENTITY_A` and `LUNEPACK_TEST_IDENTITY_B`
//! (certificate names or hashes: not secrets). Without them the identity rows are skipped with
//! their names printed, never silently.
//!
//! No tree is executed; every tree lives under a scratch directory removed at the end.
#![cfg(target_os = "macos")]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use lunepack_core::{PublisherCheck, PublisherError, RelPath, SignedTree};
use lunepack_os_macos::MacPublisherCheck;
use lunepack_testkit::{PublisherFixtures, PublisherSuite, run_publisher_suite};

const CODESIGN: &str = "/usr/bin/codesign";

fn ask(installed: &SignedTree, candidate: &SignedTree) -> Result<bool, PublisherError> {
    MacPublisherCheck.same_publisher(installed, candidate)
}

fn run(program: &str, args: &[&str], path: &Path) {
    let out = Command::new(program)
        .args(args)
        .arg(path)
        .output()
        .expect("start the tool");
    assert!(
        out.status.success(),
        "{program} {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// How a tree is signed.
#[derive(Clone)]
enum How<'a> {
    Unsigned,
    AdHoc,
    Identity(&'a Identity),
}

/// A throwaway identity in a temporary keychain.
struct Identity {
    keychain: PathBuf,
    name: String,
}

fn identities() -> Option<(Identity, Identity)> {
    let keychain = PathBuf::from(std::env::var_os("LUNEPACK_TEST_KEYCHAIN")?);
    let a = std::env::var("LUNEPACK_TEST_IDENTITY_A").ok()?;
    let b = std::env::var("LUNEPACK_TEST_IDENTITY_B").ok()?;
    Some((
        Identity {
            keychain: keychain.clone(),
            name: a,
        },
        Identity { keychain, name: b },
    ))
}

struct Lab {
    root: PathBuf,
    /// An unsigned Mach-O every tree is made from (a copy of the test binary).
    binary: Vec<u8>,
    next: std::cell::Cell<u32>,
}

impl Lab {
    fn new(tag: &str) -> Lab {
        let root =
            std::env::temp_dir().join(format!("lunepack-mac-pub-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let copy = root.join("base");
        fs::copy(std::env::current_exe().unwrap(), &copy).unwrap();
        run(CODESIGN, &["--remove-signature"], &copy);
        let binary = fs::read(&copy).unwrap();
        fs::remove_file(&copy).unwrap();
        Lab {
            root,
            binary,
            next: std::cell::Cell::new(0),
        }
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.next.set(self.next.get() + 1);
        self.root.join(format!("{}-{name}", self.next.get()))
    }

    /// A bundle with an entry and a nested Mach-O, signed `how` (nested first).
    fn tree(&self, name: &str, how: &How<'_>) -> SignedTree {
        let root = self.dir(name);
        self.build(&root, how)
    }

    fn build(&self, root: &Path, how: &How<'_>) -> SignedTree {
        for (rel, mode) in [
            ("Contents/MacOS/app", 0o755),
            ("Contents/Frameworks/libx.dylib", 0o755),
        ] {
            let at = root.join(rel);
            fs::create_dir_all(at.parent().unwrap()).unwrap();
            fs::write(&at, &self.binary).unwrap();
            fs::set_permissions(&at, fs::Permissions::from_mode(mode)).unwrap();
        }
        fs::write(
            root.join("Contents/Info.plist"),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <plist version=\"1.0\"><dict>\
             <key>CFBundleExecutable</key><string>app</string>\
             <key>CFBundleIdentifier</key><string>org.example.publisher-test</string>\
             <key>CFBundlePackageType</key><string>APPL</string>\
             </dict></plist>\n",
        )
        .unwrap();
        let nested = root.join("Contents/Frameworks/libx.dylib");
        match how {
            How::Unsigned => {}
            How::AdHoc => {
                run(CODESIGN, &["--force", "--sign", "-"], &nested);
                run(CODESIGN, &["--force", "--sign", "-"], root);
            }
            How::Identity(id) => {
                for path in [&nested, root] {
                    let out = Command::new(CODESIGN)
                        .args(["--force", "--sign", &id.name, "--keychain"])
                        .arg(&id.keychain)
                        .arg(path)
                        .output()
                        .expect("start codesign");
                    assert!(
                        out.status.success(),
                        "codesign with the test identity failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
            }
        }
        SignedTree {
            root: root.to_path_buf(),
            entry: RelPath::parse("Contents/MacOS/app").unwrap(),
        }
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        // A mode-000 directory a test left cannot be listed; restore it first.
        let _ = Command::new("/bin/chmod")
            .args(["-R", "u+rwx"])
            .arg(&self.root)
            .output();
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Flips one byte of the nested Mach-O after it was signed.
fn tamper_nested(tree: &SignedTree) {
    let at = tree.root.join("Contents/Frameworks/libx.dylib");
    let mut bytes = fs::read(&at).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    fs::write(at, bytes).unwrap();
}

/// The facts the status table rests on: what Security answers for a real unsigned, ad-hoc and
/// tampered bundle, and for a missing one. If Apple changes any of them this fails first.
#[test]
fn the_status_values_are_what_security_answers_for_real_bundles() {
    let lab = Lab::new("status");
    let unsigned = lab.tree("unsigned", &How::Unsigned);
    let adhoc = lab.tree("adhoc", &How::AdHoc);
    let tampered = lab.tree("tampered", &How::AdHoc);
    tamper_nested(&tampered);
    let missing = SignedTree {
        root: lab.root.join("no-such-bundle"),
        entry: RelPath::parse("Contents/MacOS/app").unwrap(),
    };
    let as_installed = |t: &SignedTree| ask(t, &adhoc);
    assert_eq!(
        as_installed(&unsigned),
        Err(PublisherError::InstalledUnsigned)
    );
    assert_eq!(as_installed(&adhoc), Err(PublisherError::InstalledUnsigned));
    // Validity is judged before the ad-hoc flag: a damaged ad-hoc bundle is invalid, not "unsigned".
    assert_eq!(
        as_installed(&tampered),
        Err(PublisherError::InstalledInvalid)
    );
    assert_eq!(as_installed(&missing), Err(PublisherError::Os));
}

/// A tree that cannot be read is a local fault, never a verdict about its signature.
#[test]
fn an_unreadable_or_removed_tree_is_a_local_fault() {
    let lab = Lab::new("unreadable");
    let adhoc = lab.tree("adhoc", &How::AdHoc);
    let other = lab.tree("other", &How::AdHoc);
    // Mode 000 on the bundle's `Contents`: Security cannot read what it must seal-check.
    fs::set_permissions(
        adhoc.root.join("Contents"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    let result = ask(&adhoc, &other);
    fs::set_permissions(
        adhoc.root.join("Contents"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert_eq!(result, Err(PublisherError::Os));
    // Removed between staging and the check.
    fs::remove_dir_all(&other.root).unwrap();
    assert_eq!(ask(&adhoc, &other), Err(PublisherError::InstalledUnsigned));
    assert_eq!(ask(&other, &adhoc), Err(PublisherError::Os));
}

/// The fixtures of the contract suite: identity `a` and `b` are the two throwaway identities.
struct MacFixtures<'a> {
    lab: &'a Lab,
    a: &'a Identity,
    b: &'a Identity,
}

impl PublisherFixtures for MacFixtures<'_> {
    fn signed(&self, dir: &Path, publisher: &str) -> Option<SignedTree> {
        let id = if publisher == "a" { self.a } else { self.b };
        Some(self.lab.build(dir, &How::Identity(id)))
    }

    fn unsigned(&self, dir: &Path) -> Option<SignedTree> {
        Some(self.lab.build(dir, &How::Unsigned))
    }

    fn tampered(&self, dir: &Path) -> Option<SignedTree> {
        let tree = self.lab.build(dir, &How::Identity(self.a));
        tamper_nested(&tree);
        Some(tree)
    }
}

/// The rows that need a signing identity. Skipped, with the reason printed, without one.
#[test]
fn identities_give_the_closed_outcomes() {
    let Some((a, b)) = identities() else {
        eprintln!(
            "skipped: identity rows (LUNEPACK_TEST_KEYCHAIN, LUNEPACK_TEST_IDENTITY_A and \
             LUNEPACK_TEST_IDENTITY_B name a temporary keychain and two identities): same \
             certificate, two certificates, ad-hoc candidate, unsigned candidate, tampered \
             candidate, removed candidate, the contract suite"
        );
        return;
    };
    let lab = Lab::new("identities");
    let sign = |name: &str, id: &Identity| lab.tree(name, &How::Identity(id));
    let installed = sign("installed-a", &a);

    // Same certificate, two builds (a different nested file, so the signatures differ).
    let rebuilt = sign("rebuilt-a", &a);
    fs::write(rebuilt.root.join("Contents/Resources-extra"), b"x").ok();
    assert_eq!(ask(&installed, &rebuilt), Ok(true), "same certificate");
    // Two certificates.
    let other = sign("candidate-b", &b);
    assert_eq!(ask(&installed, &other), Ok(false), "two certificates");
    // An ad-hoc candidate beside a signed installed tree has no publisher.
    let adhoc = lab.tree("candidate-adhoc", &How::AdHoc);
    assert_eq!(
        ask(&installed, &adhoc),
        Err(PublisherError::CandidateUnsigned)
    );
    let unsigned = lab.tree("candidate-unsigned", &How::Unsigned);
    assert_eq!(
        ask(&installed, &unsigned),
        Err(PublisherError::CandidateUnsigned)
    );
    // One nested Mach-O modified after signing: invalid, not "different", not a local fault.
    let tampered = sign("candidate-tampered", &a);
    tamper_nested(&tampered);
    assert_eq!(
        ask(&installed, &tampered),
        Err(PublisherError::CandidateInvalid)
    );
    // An ad-hoc tampered candidate is invalid too: validity is judged first.
    let adhoc_tampered = lab.tree("candidate-adhoc-tampered", &How::AdHoc);
    tamper_nested(&adhoc_tampered);
    assert_eq!(
        ask(&installed, &adhoc_tampered),
        Err(PublisherError::CandidateInvalid)
    );
    // Removed, or unreadable, between staging and the check: a local fault.
    let gone = sign("candidate-gone", &a);
    fs::remove_dir_all(&gone.root).unwrap();
    assert_eq!(ask(&installed, &gone), Err(PublisherError::Os));
    let locked = sign("candidate-locked", &a);
    let contents = locked.root.join("Contents");
    fs::set_permissions(&contents, fs::Permissions::from_mode(0o000)).unwrap();
    let result = ask(&installed, &locked);
    fs::set_permissions(&contents, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(result, Err(PublisherError::Os));
    // The installed tree itself, tampered or removed.
    assert_eq!(
        ask(&tampered, &installed),
        Err(PublisherError::InstalledInvalid)
    );
    assert_eq!(ask(&gone, &installed), Err(PublisherError::Os));

    let dir = lab.dir("suite");
    fs::create_dir_all(&dir).unwrap();
    run_publisher_suite(
        &MacPublisherCheck,
        PublisherSuite::Signed(&MacFixtures {
            lab: &lab,
            a: &a,
            b: &b,
        }),
        &dir,
    );
}

/// A real signature by a real identity, no key made here: Apple's own apps. The same app twice is
/// the same publisher (its designated requirement is satisfied by itself); another Apple app does
/// not satisfy it, which is "different", not "invalid". The bundles are read-only and never run.
#[test]
fn system_apps_give_true_and_false() {
    let app = |name: &str| SignedTree {
        root: PathBuf::from(format!("/System/Applications/{name}.app")),
        entry: RelPath::parse("Contents/MacOS/x").unwrap(),
    };
    let (calc, notes) = (app("Calculator"), app("Notes"));
    if !calc.root.is_dir() || !notes.root.is_dir() {
        eprintln!("skipped: system apps row (Calculator or Notes is not installed)");
        return;
    }
    assert_eq!(ask(&calc, &calc), Ok(true), "an app against itself");
    assert_eq!(
        ask(&calc, &notes),
        Ok(false),
        "another app of the same vendor"
    );
    assert_eq!(ask(&notes, &calc), Ok(false));
}

/// A nested Mach-O whose signature was removed after the bundle was signed, and one removed from a
/// bundle sealed without it: both are judged invalid, not a local fault.
#[test]
fn a_nested_file_that_lost_its_signature_is_invalid() {
    let lab = Lab::new("nested");
    let adhoc = lab.tree("adhoc", &How::AdHoc);
    let stripped = lab.tree("stripped", &How::AdHoc);
    run(
        CODESIGN,
        &["--remove-signature"],
        &stripped.root.join("Contents/Frameworks/libx.dylib"),
    );
    assert_eq!(
        ask(&stripped, &adhoc),
        Err(PublisherError::InstalledInvalid)
    );
}
