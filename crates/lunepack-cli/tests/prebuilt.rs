//! `prebuilt list`, `check`, `sign` and `verify` through the built binary. `list` is run in the
//! state this CLI ships with; the other states are decided by a function that takes the key sets
//! and the two list files as parameters, and its tests (`src/prebuilt.rs`, `src/cmd_prebuilt.rs`)
//! build keys, lists and envelopes at test time.
//!
//! `sign` and `verify` run here under `--trusted-key`, with keys made by `keys gen` in a temporary
//! directory at test time (under a file extension of their own). Every command's output is scanned
//! for every secret made so far, in every form `common::assert_no_secrets` knows.

mod common;

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::*;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use lunepack_core::Hasher;
use lunepack_crypto::Sha256Hasher;
use serde_json::Value;

const KNOWN: [&str; 6] = [
    "no-key",
    "none",
    "pinned",
    "rehearsal",
    "other-version",
    "inconsistent",
];

#[test]
fn prebuilt_list_shows_the_shipped_state() {
    let out = run(&["prebuilt", "list"], &[]);
    assert_ok(&out, "prebuilt list");
    let text = stdout(&out);
    let state = field(&text, "state:");
    // The committed constants and files: no-key until the key ceremony, none or pinned after it.
    assert!(
        ["no-key", "none", "pinned"].contains(&state.as_str()),
        "{text}"
    );
    if state == "no-key" {
        assert!(
            text.contains("key sets: none (no project key has been published)"),
            "{text}"
        );
        assert!(!text.contains("binary:"), "{text}");
    }
}

#[test]
fn prebuilt_list_json_is_one_stable_object() {
    let out = run(&["prebuilt", "list", "--json"], &[]);
    assert_ok(&out, "prebuilt list --json");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
    let obj = v.as_object().expect("an object");
    for member in ["state", "reason", "roots", "list", "binaries"] {
        assert!(obj.contains_key(member), "no {member}: {v}");
    }
    assert!(KNOWN.contains(&v["state"].as_str().unwrap()), "{v}");
    assert!(v["roots"].is_array() && v["binaries"].is_array(), "{v}");
    if v["state"] == "no-key" {
        assert_eq!(v["roots"], serde_json::json!([]));
        assert_eq!(v["binaries"], serde_json::json!([]));
        assert!(v["list"].is_null(), "{v}");
    }
    for root in v["roots"].as_array().unwrap() {
        for key in root["keys"].as_array().unwrap() {
            assert_eq!(key["public"].as_str().unwrap().len(), 64, "{v}");
            assert_eq!(key["id"].as_str().unwrap().len(), 64, "{v}");
        }
    }
}

#[test]
fn prebuilt_list_target_must_be_a_target_id() {
    let out = run(&["prebuilt", "list", "--target", "linux-x86_64"], &[]);
    assert_ok(&out, "a known target");
    let out = run(&["prebuilt", "list", "--target", "plan9-mips"], &[]);
    let err = assert_fails(&out, 1, "an unknown target");
    assert!(err.contains("--target"), "{err}");
}

// ---- check, sign, verify ---------------------------------------------------------------------------

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const KEY_VAR: &str = "LUNEPACK_TEST_PROJECT_KEY";
const RUNTIME: &[u8] = b"a runtime's bytes";
const UI: &[u8] = b"a ui's bytes, a little longer";

struct Key {
    path: PathBuf,
    public: String,
    id: String,
    /// The key file's text, for the variable of an `env:` signer.
    text: String,
}

struct World {
    dir: tempfile::TempDir,
    secrets: RefCell<Vec<Vec<u8>>>,
}

fn p(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

impl World {
    fn new() -> World {
        World {
            dir: tempfile::tempdir().unwrap(),
            secrets: RefCell::new(Vec::new()),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Runs the binary and scans its output for every secret made so far, and for the values of
    /// the environment it was given.
    fn cmd(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let output = run(args, env);
        let secrets = self.secrets.borrow();
        let refs: Vec<&[u8]> = secrets.iter().map(Vec::as_slice).collect();
        assert_no_secrets(&output, &refs);
        let env_values: Vec<&[u8]> = env.iter().map(|(_, v)| v.as_bytes()).collect();
        assert_no_secrets(&output, &env_values);
        output
    }

    fn new_key(&self, name: &str) -> Key {
        let path = self.path(&format!("{name}.lpk"));
        let out = self.cmd(&["keys", "gen", p(&path)], &[]);
        assert_ok(&out, "keys gen");
        let text = stdout(&out);
        let body = fs::read_to_string(&path).unwrap();
        let seed = SigningKey::from_pkcs8_pem(&body).unwrap().to_bytes();
        {
            let mut secrets = self.secrets.borrow_mut();
            secrets.push(body.clone().into_bytes());
            secrets.push(seed.to_vec());
        }
        Key {
            path,
            public: field(&text, "public:"),
            id: field(&text, "id:"),
            text: body,
        }
    }

    /// Writes a list file (the payload of FORMAT.md 21) with one row per `(kind, target, bytes)`.
    fn list(
        &self,
        name: &str,
        version: &str,
        rehearsal: bool,
        rows: &[(&str, &str, &[u8])],
    ) -> PathBuf {
        let rows: Vec<String> = rows
            .iter()
            .map(|(kind, target, bytes)| {
                format!(
                    r#"{{"kind":"{kind}","target":"{target}","size":{},"sha256":"{}"}}"#,
                    bytes.len(),
                    Sha256Hasher.sha256(bytes).to_hex()
                )
            })
            .collect();
        let text = format!(
            r#"{{"format":1,"kind":"prebuilt","critical":[],"version":"{version}","source_commit":"{COMMIT}","rehearsal":{rehearsal},"binaries":[{}]}}"#,
            rows.join(",")
        );
        let path = self.path(name);
        fs::write(&path, text).unwrap();
        path
    }

    fn release_list(&self, name: &str) -> PathBuf {
        self.list(
            name,
            VERSION,
            false,
            &[
                ("runtime", "linux-x86_64", RUNTIME),
                ("ui", "windows-x86_64", UI),
            ],
        )
    }

    /// `lunepack --config <a file that does not exist> prebuilt sign ...`, signing with `specs`
    /// and checking under `trusted` (and `threshold`).
    fn sign(
        &self,
        list: &Path,
        out: &Path,
        specs: &[&str],
        trusted: &[&Key],
        threshold: Option<&str>,
        env: &[(&str, &str)],
    ) -> Output {
        let missing = self.path("no-such-config.toml");
        let mut args = vec![
            "--config",
            p(&missing),
            "prebuilt",
            "sign",
            "--list",
            p(list),
            "--out",
            p(out),
        ];
        for s in specs {
            args.extend_from_slice(&["--sign", s]);
        }
        for k in trusted {
            args.extend_from_slice(&["--trusted-key", &k.public]);
        }
        if let Some(t) = threshold {
            args.extend_from_slice(&["--threshold", t]);
        }
        self.cmd(&args, env)
    }

    fn verify(&self, list: &Path, sig: &Path, trusted: &[&Key], extra: &[&str]) -> Output {
        let mut args = vec!["prebuilt", "verify", "--list", p(list), "--sig", p(sig)];
        for k in trusted {
            args.extend_from_slice(&["--trusted-key", &k.public]);
        }
        args.extend_from_slice(extra);
        self.cmd(&args, &[])
    }

    /// A list signed by `key` (through `file:`), and its envelope.
    fn signed(&self, name: &str, list: &Path, key: &Key) -> PathBuf {
        let out = self.path(name);
        let spec = format!("file:{}", p(&key.path));
        let res = self.sign(list, &out, &[&spec], &[key], None, &[]);
        assert_ok(&res, "sign");
        out
    }
}

fn json(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).expect("one JSON object")
}

fn asset(kind: &str, target: &str) -> String {
    let exe = if target.starts_with("windows") {
        ".exe"
    } else {
        ""
    };
    format!("lunepack-{kind}-{VERSION}-{target}{exe}")
}

#[test]
fn sign_through_env_then_verify() {
    // The instrument first: the secret scan fires on every form it claims to look for.
    self_check_secret_scan();
    let w = World::new();
    let k = w.new_key("project");
    let list = w.release_list("prebuilt.json");
    let out = w.path("prebuilt.sig.json");
    // The key travels only in the child's environment, and the config does not exist.
    let spec = format!("env:{KEY_VAR}");
    let res = w.sign(&list, &out, &[&spec], &[&k], None, &[(KEY_VAR, &k.text)]);
    assert_ok(&res, "sign through env:");
    let text = stdout(&res);
    assert!(text.contains("envelope written:"), "{text}");
    assert!(
        text.contains("verified under a key given on the command line, not a built-in one"),
        "{text}"
    );
    assert!(text.contains(&k.id), "{text}");
    assert!(out.is_file());

    let res = w.verify(&list, &out, &[&k], &[]);
    assert_ok(&res, "verify");
    let text = stdout(&res);
    assert!(
        text.contains("verified under a key given on the command line"),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "list: version {VERSION}, source commit {COMMIT}, rehearsal false"
        )),
        "{text}"
    );

    let res = w.verify(&list, &out, &[&k], &["--json"]);
    assert_ok(&res, "verify --json");
    let v = json(&res);
    assert_eq!(v["version"], VERSION);
    assert_eq!(v["source_commit"], COMMIT);
    assert_eq!(v["rehearsal"], false);
    assert_eq!(v["key_set"]["source"], "command-line");
    assert_eq!(v["key_set"]["retired"], false);
    assert_eq!(v["key_set"]["threshold"], 1);
    assert_eq!(v["key_set"]["keys"][0]["id"], k.id.as_str());
    assert_eq!(
        v["binaries"][0]["asset"],
        asset("runtime", "linux-x86_64").as_str()
    );
    assert_eq!(
        v["binaries"][1]["asset"],
        asset("ui", "windows-x86_64").as_str()
    );
    assert!(v["files"].is_null());
}

#[test]
fn sign_through_a_key_file_and_never_over_an_existing_file() {
    let w = World::new();
    let k = w.new_key("project");
    let list = w.release_list("prebuilt.json");
    let out = w.signed("prebuilt.sig.json", &list, &k);
    assert_ok(&w.verify(&list, &out, &[&k], &[]), "verify");

    let before = fs::read(&out).unwrap();
    let spec = format!("file:{}", p(&k.path));
    let res = w.sign(&list, &out, &[&spec], &[&k], None, &[]);
    let err = assert_fails(&res, 1, "sign over an existing file");
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(fs::read(&out).unwrap(), before);
}

#[test]
fn a_signer_that_is_not_the_trusted_key_writes_nothing_and_names_the_ids() {
    let w = World::new();
    let trusted = w.new_key("trusted");
    let other = w.new_key("other");
    let list = w.release_list("prebuilt.json");
    let out = w.path("prebuilt.sig.json");
    let spec = format!("file:{}", p(&other.path));
    let res = w.sign(&list, &out, &[&spec], &[&trusted], None, &[]);
    let err = assert_fails(&res, 1, "a signer outside the key set");
    assert!(!out.exists(), "nothing is written");
    assert!(err.contains("nothing was written"), "{err}");
    assert!(err.contains(&trusted.id), "the expected id: {err}");
    assert!(err.contains(&other.id), "the signer's id: {err}");

    // The same through env:, where a secret that holds the wrong key fails closed.
    let spec = format!("env:{KEY_VAR}");
    let res = w.sign(
        &list,
        &out,
        &[&spec],
        &[&trusted],
        None,
        &[(KEY_VAR, &other.text)],
    );
    let err = assert_fails(&res, 1, "a secret that holds the wrong key");
    assert!(!out.exists());
    assert!(err.contains(&other.id), "{err}");
}

#[test]
fn a_threshold_of_two_needs_two_signers() {
    let w = World::new();
    let (a, b) = (w.new_key("a"), w.new_key("b"));
    let list = w.release_list("prebuilt.json");
    let (spec_a, spec_b) = (
        format!("file:{}", p(&a.path)),
        format!("file:{}", p(&b.path)),
    );

    let out = w.path("one.sig.json");
    let res = w.sign(&list, &out, &[&spec_a], &[&a, &b], Some("2"), &[]);
    assert_fails(&res, 1, "one signer of a threshold of two");
    assert!(!out.exists());

    let out = w.path("two.sig.json");
    let res = w.sign(&list, &out, &[&spec_a, &spec_b], &[&a, &b], Some("2"), &[]);
    assert_ok(&res, "two signers");
    assert_ok(
        &w.verify(&list, &out, &[&a, &b], &["--threshold", "2"]),
        "verify at 2",
    );
    // A threshold of 1 of the two also accepts an envelope with both signatures.
    assert_ok(
        &w.verify(&list, &out, &[&a, &b], &["--threshold", "1"]),
        "verify at 1",
    );

    // Two keys without a threshold, and a threshold without a key, are refused.
    let res = w.sign(
        &list,
        &w.path("x.sig.json"),
        &[&spec_a, &spec_b],
        &[&a, &b],
        None,
        &[],
    );
    let err = assert_fails(&res, 1, "two keys, no threshold");
    assert!(err.contains("--threshold is required"), "{err}");
    let err = assert_fails(
        &w.verify(&list, &out, &[&a, &b], &[]),
        1,
        "verify without a threshold",
    );
    assert!(err.contains("--threshold is required"), "{err}");
    let err = assert_fails(
        &w.verify(&list, &out, &[], &["--threshold", "1"]),
        1,
        "a threshold alone",
    );
    assert!(err.contains("--threshold"), "{err}");
}

#[test]
fn a_list_of_another_version_is_not_signed_but_is_checked() {
    let w = World::new();
    let k = w.new_key("project");
    let list = w.list(
        "other.json",
        "9.9.9",
        false,
        &[("runtime", "linux-x86_64", RUNTIME)],
    );
    let out = w.path("other.sig.json");
    let spec = format!("file:{}", p(&k.path));
    let res = w.sign(&list, &out, &[&spec], &[&k], None, &[]);
    let err = assert_fails(&res, 1, "a list of another version");
    assert!(err.contains("version 9.9.9"), "{err}");
    assert!(!out.exists());
    // `check` reads any list the parser accepts.
    let res = w.cmd(&["prebuilt", "check", "--list", p(&list)], &[]);
    assert_ok(&res, "check");
    assert!(
        stdout(&res).contains("list: version 9.9.9"),
        "{}",
        stdout(&res)
    );
}

#[test]
fn an_edited_list_or_envelope_is_refused() {
    let w = World::new();
    let k = w.new_key("project");
    let list = w.release_list("prebuilt.json");
    let sig = w.signed("prebuilt.sig.json", &list, &k);

    // The list edited after signing: a trailing newline, and one changed byte.
    let mut bytes = fs::read(&list).unwrap();
    bytes.push(b'\n');
    let longer = w.path("longer.json");
    fs::write(&longer, &bytes).unwrap();
    let err = assert_fails(
        &w.verify(&longer, &sig, &[&k], &[]),
        1,
        "a trailing newline",
    );
    assert!(err.contains("not the envelope's payload"), "{err}");
    let mut bytes = fs::read(&list).unwrap();
    let at = bytes.iter().position(|b| *b == b'1').unwrap();
    bytes[at] = b'2';
    let changed = w.path("changed.json");
    fs::write(&changed, &bytes).unwrap();
    assert_fails(&w.verify(&changed, &sig, &[&k], &[]), 1, "a changed byte");

    // The envelope edited: one byte of the document.
    let mut doc = fs::read(&sig).unwrap();
    let last = doc.len() - 3;
    doc[last] ^= 1;
    let broken = w.path("broken.sig.json");
    fs::write(&broken, &doc).unwrap();
    assert_fails(
        &w.verify(&list, &broken, &[&k], &[]),
        1,
        "a changed envelope",
    );

    // Another key: the same envelope does not verify under it.
    let other = w.new_key("other");
    let err = assert_fails(&w.verify(&list, &sig, &[&other], &[]), 1, "another key");
    assert!(err.contains("does not verify"), "{err}");
}

#[test]
fn a_rehearsal_list_needs_the_flag_and_is_labelled() {
    let w = World::new();
    let k = w.new_key("project");
    let list = w.list(
        "rehearsal.json",
        VERSION,
        true,
        &[("runtime", "linux-x86_64", RUNTIME)],
    );
    let sig = w.signed("rehearsal.sig.json", &list, &k);

    let err = assert_fails(&w.verify(&list, &sig, &[&k], &[]), 1, "a rehearsal list");
    assert!(err.contains("rehearsal list"), "{err}");
    let res = w.verify(&list, &sig, &[&k], &["--allow-rehearsal"]);
    assert_ok(&res, "a rehearsal list, allowed");
    assert!(stdout(&res).contains("rehearsal true"), "{}", stdout(&res));
    let res = w.verify(&list, &sig, &[&k], &["--allow-rehearsal", "--json"]);
    assert_eq!(json(&res)["rehearsal"], true);
}

/// A directory with the files of `release_list`: `runtime` (Linux) and `ui` (Windows).
fn download(w: &World, name: &str) -> PathBuf {
    let dir = w.path(name);
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join(asset("runtime", "linux-x86_64")), RUNTIME).unwrap();
    fs::write(dir.join(asset("ui", "windows-x86_64")), UI).unwrap();
    dir
}

#[test]
fn dir_checks_files_against_the_rows() {
    let w = World::new();
    let k = w.new_key("project");
    let list = w.release_list("prebuilt.json");
    let sig = w.signed("prebuilt.sig.json", &list, &k);

    // A good set, with and without --all; files that are not lunepack binaries of this version
    // (a checksum list, a CLI download, the notices) are ignored.
    let dir = download(&w, "good");
    fs::write(dir.join("SHA256SUMS"), b"x").unwrap();
    fs::write(
        dir.join(format!("lunepack-cli-{VERSION}-linux-x86_64")),
        b"x",
    )
    .unwrap();
    fs::write(dir.join("lunepack-NOTICES.txt"), b"x").unwrap();
    let res = w.verify(&list, &sig, &[&k], &["--dir", p(&dir), "--all"]);
    assert_ok(&res, "a good set");
    assert!(
        stdout(&res).contains("files: 2 checked, every row present"),
        "{}",
        stdout(&res)
    );
    let res = w.verify(&list, &sig, &[&k], &["--dir", p(&dir), "--json"]);
    let v = json(&res);
    assert_eq!(v["files"]["checked"].as_array().unwrap().len(), 2, "{v}");
    assert_eq!(v["files"]["all"], false);

    // One byte changed, and one byte longer.
    let dir = download(&w, "changed");
    let mut bytes = RUNTIME.to_vec();
    bytes[0] ^= 1;
    fs::write(dir.join(asset("runtime", "linux-x86_64")), &bytes).unwrap();
    let err = assert_fails(
        &w.verify(&list, &sig, &[&k], &["--dir", p(&dir)]),
        1,
        "a changed byte",
    );
    assert!(err.contains("SHA-256"), "{err}");
    let dir = download(&w, "longer");
    fs::write(dir.join(asset("ui", "windows-x86_64")), [UI, b"!"].concat()).unwrap();
    let err = assert_fails(
        &w.verify(&list, &sig, &[&k], &["--dir", p(&dir)]),
        1,
        "a longer file",
    );
    assert!(err.contains("bytes, the list says"), "{err}");

    // A lunepack binary of the version that no row names: another kind, another target.
    for extra in [
        asset("service", "linux-x86_64"),
        asset("runtime", "linux-aarch64"),
    ] {
        let dir = download(&w, &format!("extra-{extra}"));
        fs::write(dir.join(&extra), b"x").unwrap();
        let err = assert_fails(
            &w.verify(&list, &sig, &[&k], &["--dir", p(&dir)]),
            1,
            "an extra binary",
        );
        assert!(err.contains(&extra) && err.contains("no row"), "{err}");
    }

    // A missing row: fine without --all, an error with it. No matching file at all: an error.
    let dir = download(&w, "missing");
    fs::remove_file(dir.join(asset("ui", "windows-x86_64"))).unwrap();
    assert_ok(
        &w.verify(&list, &sig, &[&k], &["--dir", p(&dir)]),
        "one row present",
    );
    let err = assert_fails(
        &w.verify(&list, &sig, &[&k], &["--dir", p(&dir), "--all"]),
        1,
        "a missing row",
    );
    assert!(
        err.contains(&asset("ui", "windows-x86_64")) && err.contains("not in the directory"),
        "{err}"
    );
    let empty = w.path("empty");
    fs::create_dir(&empty).unwrap();
    fs::write(empty.join("README"), b"x").unwrap();
    let err = assert_fails(
        &w.verify(&list, &sig, &[&k], &["--dir", p(&empty)]),
        1,
        "no matching file",
    );
    assert!(err.contains("no file in the directory"), "{err}");
    assert_fails(
        &w.verify(&list, &sig, &[&k], &["--dir", p(&w.path("absent"))]),
        1,
        "no directory",
    );
}

#[cfg(unix)]
#[test]
fn dir_never_follows_a_link() {
    let w = World::new();
    let k = w.new_key("project");
    let list = w.release_list("prebuilt.json");
    let sig = w.signed("prebuilt.sig.json", &list, &k);
    let dir = download(&w, "links");
    let target = w.path("elsewhere");
    fs::write(&target, RUNTIME).unwrap();
    let name = dir.join(asset("runtime", "linux-x86_64"));
    fs::remove_file(&name).unwrap();
    std::os::unix::fs::symlink(&target, &name).unwrap();
    let err = assert_fails(
        &w.verify(&list, &sig, &[&k], &["--dir", p(&dir)]),
        1,
        "a link",
    );
    assert!(err.contains("not a regular file"), "{err}");
}

/// Whether this build has a project key built in (after the key ceremony it has).
fn has_builtin_key() -> bool {
    let out = run(&["prebuilt", "list", "--json"], &[]);
    assert_ok(&out, "prebuilt list --json");
    !json(&out)["roots"].as_array().unwrap().is_empty()
}

#[test]
fn sign_and_verify_with_no_key_at_all_are_refused() {
    let w = World::new();
    let k = w.new_key("project");
    let list = w.release_list("prebuilt.json");
    let sig = w.signed("prebuilt.sig.json", &list, &k);
    let out = w.path("none.sig.json");
    let spec = format!("file:{}", p(&k.path));
    let res = w.sign(&list, &out, &[&spec], &[], None, &[]);
    let verify = w.verify(&list, &sig, &[], &[]);
    if has_builtin_key() {
        // After the key ceremony: the key made at test time is not the built-in one.
        assert_fails(&res, 1, "a signer that is not the built-in key");
        assert_fails(&verify, 1, "an envelope not signed by the built-in key");
    } else {
        // The shipped state of M13.
        let err = assert_fails(&res, 1, "sign with no key");
        assert!(
            err.contains("this CLI has no project key built in"),
            "{err}"
        );
        let err = assert_fails(&verify, 1, "verify with no key");
        assert!(
            err.contains("this CLI has no project key built in"),
            "{err}"
        );
        let err = assert_fails(
            &w.verify(&list, &sig, &[], &["--root-version", "1"]),
            1,
            "verify under a built-in set that does not exist",
        );
        assert!(err.contains("no project key built in"), "{err}");
    }
    assert!(!out.exists(), "nothing is written");
}

#[test]
fn the_trust_flags_obey_their_rules() {
    let w = World::new();
    let k = w.new_key("project");
    let list = w.release_list("prebuilt.json");
    let sig = w.signed("prebuilt.sig.json", &list, &k);

    // --trusted-key is exactly 64 lowercase hex.
    for bad in [
        k.public.to_uppercase(),
        k.public[..63].to_owned(),
        format!("{}0", k.public),
    ] {
        let res = w.cmd(
            &[
                "prebuilt",
                "verify",
                "--list",
                p(&list),
                "--sig",
                p(&sig),
                "--trusted-key",
                &bad,
            ],
            &[],
        );
        let err = assert_fails(&res, 1, "a malformed key");
        assert!(err.contains("--trusted-key"), "{err}");
    }
    // --trusted-key and --root-version do not mix.
    let err = assert_fails(
        &w.verify(&list, &sig, &[&k], &["--root-version", "1"]),
        1,
        "both flags",
    );
    assert!(err.contains("cannot be used together"), "{err}");
    // --root-version exists only on `verify`, and --all needs --dir: usage errors.
    let spec = format!("file:{}", p(&k.path));
    let other_out = w.path("o.sig.json");
    let res = w.cmd(
        &[
            "prebuilt",
            "sign",
            "--list",
            p(&list),
            "--out",
            p(&other_out),
            "--sign",
            &spec,
            "--root-version",
            "1",
        ],
        &[],
    );
    assert_fails(&res, 2, "--root-version on sign");
    assert_fails(
        &w.verify(&list, &sig, &[&k], &["--all"]),
        2,
        "--all without --dir",
    );
    // 17 keys are too many.
    let mut args = vec![
        "prebuilt",
        "verify",
        "--list",
        p(&list),
        "--sig",
        p(&sig),
        "--threshold",
        "1",
    ];
    for _ in 0..17 {
        args.extend_from_slice(&["--trusted-key", &k.public]);
    }
    assert_fails(&w.cmd(&args, &[]), 1, "17 keys");
}

#[test]
fn check_prints_what_the_parser_read() {
    let w = World::new();
    let list = w.release_list("prebuilt.json");
    let res = w.cmd(&["prebuilt", "check", "--list", p(&list)], &[]);
    assert_ok(&res, "check");
    let text = stdout(&res);
    assert!(
        text.contains(&format!(
            "list: version {VERSION}, source commit {COMMIT}, rehearsal false"
        )),
        "{text}"
    );
    assert!(
        text.contains(&format!("asset {}", asset("ui", "windows-x86_64"))),
        "{text}"
    );

    let res = w.cmd(&["prebuilt", "check", "--list", p(&list), "--json"], &[]);
    assert_ok(&res, "check --json");
    let v = json(&res);
    assert_eq!(v["version"], VERSION);
    assert_eq!(v["source_commit"], COMMIT);
    assert_eq!(v["rehearsal"], false);
    let rows = v["binaries"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["kind"], "runtime");
    assert_eq!(rows[0]["size"], RUNTIME.len());
    assert_eq!(
        rows[0]["sha256"],
        Sha256Hasher.sha256(RUNTIME).to_hex().as_str()
    );
    assert_eq!(rows[1]["asset"], asset("ui", "windows-x86_64").as_str());
}

#[test]
fn check_refuses_what_the_parser_refuses() {
    let w = World::new();
    let good = fs::read_to_string(w.release_list("good.json")).unwrap();
    let cases: Vec<(&str, String)> = vec![
        ("not json", "not json".to_owned()),
        ("empty", String::new()),
        // A duplicate member that a lenient reader would take as valid (FORMAT 3.1).
        (
            "a duplicated member",
            good.replacen(
                r#""rehearsal":false,"#,
                r#""rehearsal":true,"rehearsal":false,"#,
                1,
            ),
        ),
        (
            "rehearsal as a string",
            good.replacen(r#""rehearsal":false"#, r#""rehearsal":"false""#, 1),
        ),
        (
            "a missing rehearsal",
            good.replacen(r#""rehearsal":false,"#, "", 1),
        ),
        ("a short commit", good.replacen(COMMIT, &COMMIT[..39], 1)),
        ("trailing data", format!("{good}{good}")),
        ("a byte-order mark", format!("\u{feff}{good}")),
        ("over the cap", format!("{good}{}", " ".repeat(70_000))),
    ];
    for (what, text) in cases {
        let path = w.path("case.json");
        fs::write(&path, text).unwrap();
        let res = w.cmd(&["prebuilt", "check", "--list", p(&path)], &[]);
        let err = assert_fails(&res, 1, what);
        assert!(err.contains("not accepted"), "{what}: {err}");
        assert!(res.stdout.is_empty(), "{what}: nothing on stdout");
    }
    let err = assert_fails(
        &w.cmd(
            &["prebuilt", "check", "--list", p(&w.path("absent.json"))],
            &[],
        ),
        1,
        "a missing file",
    );
    assert!(err.contains("cannot read"), "{err}");
}

#[test]
fn fetch_in_a_state_that_is_not_pinned_is_refused_and_makes_nothing() {
    // The shipped state is `no-key`; after the key ceremony it is `none`, and after a release's pin
    // commit `pinned`, where `fetch` would use the network and is not run here.
    let state = {
        let out = run(&["prebuilt", "list", "--json"], &[]);
        assert_ok(&out, "prebuilt list --json");
        json(&out)["state"].as_str().unwrap().to_owned()
    };
    if state == "pinned" {
        return;
    }
    let w = World::new();
    let out_dir = w.path("fetched");
    for args in [
        vec!["--target", "linux-x86_64"],
        // The state wins over a base URL that would be refused, and over a good one.
        vec![
            "--target",
            "linux-x86_64",
            "--base-url",
            "ftp://example.com/",
        ],
        vec![
            "--target",
            "linux-x86_64",
            "--base-url",
            "file:///nonexistent/",
        ],
        vec!["--target", "plan9-mips", "--kind", "firmware"],
    ] {
        let mut full = vec!["prebuilt", "fetch", "--out", p(&out_dir)];
        full.extend_from_slice(&args);
        let res = w.cmd(&full, &[]);
        let err = assert_fails(&res, 1, "fetch in a refused state");
        assert!(err.contains(&format!("the state {state}")), "{err}");
        assert_eq!(err.trim_end().lines().count(), 1, "one line: {err}");
        assert!(res.stdout.is_empty());
        assert!(!out_dir.exists(), "--out is not made");
    }
}
