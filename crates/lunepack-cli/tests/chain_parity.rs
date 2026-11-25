//! `lunepack verify` and a first-install client read a release directory's trust chain the same way
//! (M13 step 4, C2): the CLI runs the core's `RootWalk` and `KeysChain`, as the client does, so for
//! the same trusted root, clock reading and directory the two verdicts are equal. A table of release
//! directories is checked by the binary (`verify --at`) and by the facade's blocking `check` over a
//! `file:` feed, and each verdict is also pinned, so a row cannot pass by both sides failing for a
//! reason nobody meant.
//!
//! The directories are made by the binary (keys, `init`, `pack`, `feed add`, `keys rotate-root`) and
//! then edited with the core writers; every key is generated at test time.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;

use common::*;
use lunepack::{CancelToken, Layout, UpdaterBuilder, blocking};
use lunepack_core::digest::U53;
use lunepack_core::state::{InstallState, Scope, UserScope};
use lunepack_core::{
    AppId, Channel, Hasher, KeyEntry, PayloadKind, PublicKey, ReleaseKeyEntry, RootDocument,
    Signer, Target, TrustedRoot, Version, next_key_set, rotate_root, sign_envelope,
};
use lunepack_crypto::{Ed25519Signer, Ed25519Verifier, Sha256Hasher};
use lunepack_testkit::{FakeClock, MemFs, exe_headers};

const APP: &str = "org.example.hello";
const T0: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const TWO_YEARS: u64 = 63_072_000;
const WIN: &str = "windows-x86_64";
/// The most root rotations a walk takes (`lunepack_core::MAX_ROOT_STEPS`).
const CAP: u64 = lunepack_core::MAX_ROOT_STEPS;

#[derive(Clone)]
struct Key {
    path: PathBuf,
    public: String,
}

fn s(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

fn hex32(text: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

fn spec(k: &Key) -> String {
    format!("file:{}", s(&k.path))
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dest);
        } else {
            fs::copy(e.path(), dest).unwrap();
        }
    }
}

/// One publisher: its own config, state file and keys, and a release directory made by the binary:
/// `keys.json` for the first release key, 1.0.0 of `windows-x86_64` and a `stable` feed.
struct Lab {
    dir: tempfile::TempDir,
    config: PathBuf,
    release_dir: PathBuf,
    /// The compiled-in root key; clients start from it.
    root: Key,
    /// The key of the latest root, which signs the next rotation.
    current: Key,
    release: Key,
    secrets: Vec<Vec<u8>>,
}

impl Lab {
    /// `feed_days`: `--expires-after-days` of the feed, when set.
    fn new(feed_days: Option<u64>) -> Lab {
        let dir = tempfile::tempdir().unwrap();
        let mut lab = Lab {
            config: dir.path().join("lunepack.toml"),
            release_dir: dir.path().join("rel"),
            root: Key {
                path: PathBuf::new(),
                public: String::new(),
            },
            current: Key {
                path: PathBuf::new(),
                public: String::new(),
            },
            release: Key {
                path: PathBuf::new(),
                public: String::new(),
            },
            secrets: Vec::new(),
            dir,
        };
        lab.root = lab.new_key("root");
        lab.current = lab.root.clone();
        lab.release = lab.new_key("release");
        let root_public = lab.root.public.clone();
        assert_ok(
            &lab.run(&["init", "--app-id", APP, "--root-key", &root_public], T0),
            "init",
        );
        fs::create_dir(&lab.release_dir).unwrap();
        let (rel, root, release) = (
            lab.release_dir.clone(),
            spec(&lab.root),
            lab.release.clone(),
        );
        assert_ok(
            &lab.run(
                &[
                    "keys",
                    "set",
                    "--release-dir",
                    s(&rel),
                    "--release-key",
                    &release.public,
                    "--sign",
                    &root,
                ],
                T0,
            ),
            "keys set",
        );
        let input = lab.dir.path().join("input");
        fs::create_dir(&input).unwrap();
        fs::write(input.join("MyApp.exe"), exe_headers::pe(0x8664, 48 * 1024)).unwrap();
        fs::write(input.join("README.txt"), b"hello hello hello\n".repeat(100)).unwrap();
        let signer = spec(&release);
        assert_ok(
            &lab.run(
                &[
                    "pack",
                    "--input",
                    s(&input),
                    "--version",
                    "1.0.0",
                    "--target",
                    WIN,
                    "--release-dir",
                    s(&rel),
                    "--sign",
                    &signer,
                ],
                T0,
            ),
            "pack",
        );
        let days = feed_days.map(|d| d.to_string());
        let mut args = vec![
            "feed",
            "add",
            "--release-dir",
            s(&rel),
            "--channel",
            "stable",
            "--version",
            "1.0.0",
            "--sign",
            &signer,
        ];
        if let Some(d) = &days {
            args.extend_from_slice(&["--expires-after-days", d]);
        }
        assert_ok(&lab.run(&args, T0), "feed add");
        lab
    }

    fn new_key(&mut self, name: &str) -> Key {
        let base = self.dir.path().join(name);
        let out = run(&["keys", "gen", s(&base)], &[]);
        assert_ok(&out, "keys gen");
        let path = base.with_extension("key");
        self.secrets.push(fs::read(&path).unwrap());
        Key {
            path,
            public: field(&stdout(&out), "public:"),
        }
    }

    /// `lunepack --config <config> <args>` with the clock at `epoch`; the output is scanned for
    /// every secret generated so far.
    fn run(&self, args: &[&str], epoch: u64) -> Output {
        let mut full = vec!["--config", s(&self.config)];
        full.extend_from_slice(args);
        let out = run(&full, &[("SOURCE_DATE_EPOCH", &epoch.to_string())]);
        let refs: Vec<&[u8]> = self.secrets.iter().map(Vec::as_slice).collect();
        assert_no_secrets(&out, &refs);
        out
    }

    /// The compiled-in root of the config: what a client of this app starts from.
    fn trusted_root(&self) -> TrustedRoot {
        TrustedRoot::from_parts(
            AppId::parse(APP).unwrap(),
            1,
            1,
            &[hex32(&self.root.public)],
            &Sha256Hasher,
            &Ed25519Verifier,
        )
        .unwrap()
    }

    /// `keys rotate-root` from the current root key to a new one (generated here).
    fn rotate(&mut self, name: &str, epoch: u64) -> Key {
        let new = self.new_key(name);
        let (rel, old) = (self.release_dir.clone(), spec(&self.current));
        let out = self.run(
            &[
                "keys",
                "rotate-root",
                "--release-dir",
                s(&rel),
                "--new-root-key",
                &new.public,
                "--new-threshold",
                "1",
                "--sign",
                &old,
                "--sign-new",
                &spec(&new),
            ],
            epoch,
        );
        assert_ok(&out, "rotate-root");
        self.current = new.clone();
        new
    }
}

// ---- the two verdicts -------------------------------------------------------------------------

/// `lunepack verify <dir> --at <at>` against `lab`'s config: the exit status and stderr.
fn cli_verdict(lab: &Lab, dir: &Path, at: u64) -> (bool, String) {
    let out = lab.run(&["verify", s(dir), "--at", &at.to_string()], at);
    (out.status.success(), stderr(&out))
}

/// The facade's blocking `check` over a `file:` feed in `dir`, as a client with this root, no
/// floors and a clock at `at`: an install record of 0.9.0 with nothing raised.
fn client_verdict(root: TrustedRoot, dir: &Path, at: u64) -> bool {
    let fs = MemFs::new();
    let app = AppId::parse(APP).unwrap();
    let target = Target::parse(WIN).unwrap();
    let id = [7u8; 16];
    let record = InstallState::new(1, app.clone(), Scope::User, id, target).install(
        Version::parse("0.9.0").unwrap(),
        T0 - 30 * DAY,
        target,
        id,
    );
    let store = UserScope {
        dir: PathBuf::from("/user/state"),
        app_id: app.clone(),
    };
    let loaded = store.load(&fs, &Sha256Hasher).expect("load");
    store
        .commit(&fs, &loaded, &record, &Sha256Hasher)
        .expect("commit");
    let layout = Layout::User {
        state_dir: PathBuf::from("/user/state"),
        cache_dir: PathBuf::from("/user/cache"),
        versions_dir: PathBuf::from("/user/versions"),
        current_tree: None,
    };
    let feed = dir.join("feed-stable.json");
    let url = if cfg!(windows) {
        format!("file:///{}", feed.display().to_string().replace('\\', "/"))
    } else {
        format!("file://{}", feed.display())
    };
    let updater = UpdaterBuilder::new(app, root, &url, Channel::parse("stable").unwrap(), layout)
        .fs(Arc::new(fs))
        .clock(Arc::new(FakeClock::new(at)))
        .workers(2)
        .build()
        .expect("build the updater");
    blocking::Updater::from(updater)
        .check(&CancelToken::default())
        .is_ok()
}

/// Both verdicts for `dir`; panics when they differ. Returns the shared one and the CLI's stderr.
fn parity(label: &str, lab: &Lab, dir: &Path, at: u64) -> (bool, String) {
    let (cli, err) = cli_verdict(lab, dir, at);
    let client = client_verdict(lab.trusted_root(), dir, at);
    assert_eq!(
        cli, client,
        "{label}: `lunepack verify` says {cli}, a first-install client says {client} (stderr: {err})"
    );
    (cli, err)
}

/// One row: both verdicts equal and `expect`, and when refused the CLI names `names`.
fn row(label: &str, lab: &Lab, dir: &Path, at: u64, expect: bool, names: Option<&str>) {
    let (verdict, err) = parity(label, lab, dir, at);
    assert_eq!(
        verdict, expect,
        "{label}: expected {expect} (stderr: {err})"
    );
    if let Some(name) = names {
        assert!(
            err.contains(name),
            "{label}: stderr does not name {name}: {err}"
        );
    }
}

// ---- documents written with the core writers ---------------------------------------------------

fn key_entry(public: [u8; 32]) -> KeyEntry {
    KeyEntry {
        id: Sha256Hasher.sha256(&public),
        alg: "ed25519".to_owned(),
        public: PublicKey::from_bytes(public),
    }
}

fn signer(key: &Key) -> Ed25519Signer {
    Ed25519Signer::from_key_file(&key.path).expect("the key file")
}

/// A `keys.json` for `app`, signed by `root_key` as the root of `root_version`, listing `release`.
fn keys_json(app: &AppId, root_version: u64, root_key: &Key, release: &Key) -> Vec<u8> {
    let public = hex32(&release.public);
    let entry = ReleaseKeyEntry {
        id: Sha256Hasher.sha256(&public),
        alg: "ed25519".to_owned(),
        public: PublicKey::from_bytes(public),
        not_before: U53::new(T0).unwrap(),
        not_after: U53::new(T0 + TWO_YEARS).unwrap(),
    };
    let doc = next_key_set(
        None,
        root_version,
        app,
        vec![entry],
        1,
        None,
        &Sha256Hasher,
        &Ed25519Verifier,
    )
    .unwrap();
    let signer = signer(root_key);
    let refs: [&dyn Signer; 1] = [&signer];
    sign_envelope(
        PayloadKind::Keys,
        &doc.to_payload(),
        &refs,
        &Sha256Hasher,
        &Ed25519Verifier,
    )
    .unwrap()
}

/// `root-2.json` to `root-<1 + steps>.json`, each rotating to the same key (so the one key signs
/// every step), and a `keys.json` signed under the last of them.
fn long_chain(lab: &Lab, dir: &Path, steps: u64) {
    let app = AppId::parse(APP).unwrap();
    let root_signer = signer(&lab.root);
    let refs: [&dyn Signer; 1] = [&root_signer];
    let mut doc = RootDocument {
        format: U53::new(1).unwrap(),
        kind: "root".to_owned(),
        critical: Vec::new(),
        app_id: app.clone(),
        version: U53::new(1).unwrap(),
        threshold: U53::new(1).unwrap(),
        keys: vec![key_entry(hex32(&lab.root.public))],
    };
    for _ in 0..steps {
        doc = rotate_root(&doc, 1, doc.keys.clone()).unwrap();
        let bytes = sign_envelope(
            PayloadKind::Root,
            &doc.to_payload(),
            &refs,
            &Sha256Hasher,
            &Ed25519Verifier,
        )
        .unwrap();
        fs::write(dir.join(format!("root-{}.json", doc.version.get())), bytes).unwrap();
    }
    fs::write(
        dir.join("keys.json"),
        keys_json(&app, doc.version.get(), &lab.root, &lab.release),
    )
    .unwrap();
}

// ---- the table ---------------------------------------------------------------------------------

const AT: u64 = T0 + 3600;

/// The instrument: a directory the binary and the client both accept, and the same one with its
/// `keys.json` removed, which both refuse (so the comparison can fail and can pass).
#[test]
fn the_comparison_can_pass_and_can_fail() {
    let lab = Lab::new(None);
    row("valid", &lab, &lab.release_dir, AT, true, None);
    let broken = lab.dir.path().join("broken");
    copy_dir(&lab.release_dir, &broken);
    fs::remove_file(broken.join("keys.json")).unwrap();
    row("no keys.json", &lab, &broken, AT, false, Some("keys.json"));
}

#[test]
fn a_rotated_root_is_accepted_by_both() {
    let mut lab = Lab::new(None);
    lab.rotate("root2", T0 + 10);
    assert!(lab.release_dir.join("root-2.json").is_file());
    row("rotated root", &lab, &lab.release_dir, AT, true, None);
    // A second rotation, and the walk follows both.
    lab.rotate("root3", T0 + 20);
    assert!(lab.release_dir.join("root-3.json").is_file());
    row("rotated twice", &lab, &lab.release_dir, AT, true, None);
}

#[test]
fn a_root_file_that_does_not_verify_is_refused_by_both() {
    let mut lab = Lab::new(None);
    lab.rotate("root2", T0 + 10);
    let rel = lab.release_dir.clone();
    // One flipped byte in the middle of root-2.json.
    let flipped = lab.dir.path().join("flipped");
    copy_dir(&rel, &flipped);
    let mut bytes = fs::read(flipped.join("root-2.json")).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 1;
    fs::write(flipped.join("root-2.json"), bytes).unwrap();
    row(
        "flipped root",
        &lab,
        &flipped,
        AT,
        false,
        Some("root-2.json"),
    );
    // Garbage in its place.
    let garbage = lab.dir.path().join("garbage");
    copy_dir(&rel, &garbage);
    fs::write(garbage.join("root-2.json"), b"not a root document").unwrap();
    row(
        "garbage root",
        &lab,
        &garbage,
        AT,
        false,
        Some("root-2.json"),
    );
    // A root file the first root never signed, over a keys.json that still verifies under root 1.
    let mut other = Lab::new(None);
    other.rotate("root2", T0 + 10);
    let stranger = lab.dir.path().join("stranger");
    let fresh = Lab::new(None);
    copy_dir(&fresh.release_dir, &stranger);
    fs::copy(
        other.release_dir.join("root-2.json"),
        stranger.join("root-2.json"),
    )
    .unwrap();
    let (cli, err) = cli_verdict(&fresh, &stranger, AT);
    assert!(!cli, "a root file signed by another root is refused: {err}");
    assert!(err.contains("root-2.json"), "{err}");
    assert_eq!(client_verdict(fresh.trusted_root(), &stranger, AT), cli);
}

#[test]
fn a_gap_in_the_root_files_ends_the_walk_for_both() {
    let mut lab = Lab::new(None);
    lab.rotate("root2", T0 + 10);
    lab.rotate("root3", T0 + 20);
    // keys.json is under root 3; without root-2.json the walk stops at root 1 and cannot verify it.
    let gap = lab.dir.path().join("gap");
    copy_dir(&lab.release_dir, &gap);
    fs::remove_file(gap.join("root-2.json")).unwrap();
    row(
        "gap under a rotated key set",
        &lab,
        &gap,
        AT,
        false,
        Some("keys.json"),
    );
    // A root file beyond the gap is never read: keys.json under root 1 still verifies.
    let fresh = Lab::new(None);
    let beyond = fresh.dir.path().join("beyond");
    copy_dir(&fresh.release_dir, &beyond);
    fs::copy(
        lab.release_dir.join("root-3.json"),
        beyond.join("root-3.json"),
    )
    .unwrap();
    row(
        "root-3.json without root-2.json",
        &fresh,
        &beyond,
        AT,
        true,
        None,
    );
}

#[test]
fn more_root_steps_than_the_cap_are_refused_by_both() {
    let lab = Lab::new(None);
    // Exactly the cap of rotations: the walk reaches the last root and keys.json verifies.
    let at_cap = lab.dir.path().join("at-cap");
    copy_dir(&lab.release_dir, &at_cap);
    long_chain(&lab, &at_cap, CAP);
    row("1024 rotations", &lab, &at_cap, AT, true, None);
    // One more: the walk stops one root short of keys.json's, which names the root it was signed under.
    let over = lab.dir.path().join("over-cap");
    copy_dir(&lab.release_dir, &over);
    long_chain(&lab, &over, CAP + 1);
    row("1025 rotations", &lab, &over, AT, false, Some("keys.json"));
}

#[test]
fn a_key_set_for_another_app_is_refused_by_both() {
    let lab = Lab::new(None);
    let other = lab.dir.path().join("other-app");
    copy_dir(&lab.release_dir, &other);
    let app = AppId::parse("org.example.other").unwrap();
    fs::write(
        other.join("keys.json"),
        keys_json(&app, 1, &lab.root, &lab.release),
    )
    .unwrap();
    row(
        "keys.json of another app",
        &lab,
        &other,
        AT,
        false,
        Some("keys.json"),
    );
}

#[test]
fn an_expired_feed_is_refused_by_both() {
    let lab = Lab::new(Some(1));
    row(
        "feed within its expiry",
        &lab,
        &lab.release_dir,
        T0 + DAY / 2,
        true,
        None,
    );
    row(
        "expired feed",
        &lab,
        &lab.release_dir,
        T0 + 3 * DAY,
        false,
        Some("feed-stable.json"),
    );
}

#[test]
fn a_feed_signed_by_a_revoked_key_is_refused_by_both() {
    let mut lab = Lab::new(None);
    let second = lab.new_key("release2");
    let (rel, root) = (lab.release_dir.clone(), spec(&lab.root));
    // Keeping the first key: the feed still verifies.
    let mut kept = Lab::new(None);
    let extra = kept.new_key("release2");
    let kept_dir = kept.release_dir.clone();
    let args = [
        "keys",
        "set",
        "--release-dir",
        s(&kept_dir),
        "--release-key",
        &kept.release.public,
        "--release-key",
        &extra.public,
        "--sign",
        &spec(&kept.root),
    ];
    assert_ok(&kept.run(&args, T0 + 10), "keys set with both keys");
    row(
        "a key added, the old one kept",
        &kept,
        &kept_dir,
        AT,
        true,
        None,
    );
    // Revoking it: the feed is signed by a key that is no longer in keys.json.
    let out = lab.run(
        &[
            "keys",
            "set",
            "--release-dir",
            s(&rel),
            "--release-key",
            &second.public,
            "--sign",
            &root,
            "--allow-unverifiable-feeds",
        ],
        T0 + 10,
    );
    assert_ok(&out, "keys set without the first key");
    row(
        "feed signed by a revoked key",
        &lab,
        &rel,
        AT,
        false,
        Some("feed-stable.json"),
    );
}
