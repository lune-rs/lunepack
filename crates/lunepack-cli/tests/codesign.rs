//! The OS sign stage of `pack` (M9 step 3), through the real binary: C2's order (assemble, place,
//! sign, hash), the signed-form checks, notarize and staple, the signed-input skip, the written
//! publisher policy and the output hygiene of a failing tool.
//!
//! Three kinds of rows. The fake-signer rows (Unix) run `sh` scripts as the developer's tools: each
//! logs what it was asked to sign and rewrites the item into a form the signed-form checks accept,
//! so they prove the order and what the hash stage sees without any real identity. The real rows
//! run the host's own tools with throwaway identities generated at test time: `codesign` ad hoc on
//! macOS, `signtool` with a self-signed certificate on Windows. No secret, key file or credential
//! is created, read or printed.

// The macOS and Linux fixtures are unused on Windows, and the other way round.
#![cfg_attr(not(unix), allow(dead_code))]

mod common;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::*;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::digest::U53;
use lunepack_core::{
    AppId, ArtifactRef, Channel, Clock, ClockReading, Hasher, PayloadKind, ReleaseDoc,
    RollbackFloor, Signer, Target, TrustedRoot, VerifiedEntry, VerifiedKeySet, VerifiedManifest,
    decode_verified, next_feed, sign_envelope, verify_feed, verify_key_set, verify_manifest,
};
use lunepack_crypto::{Ed25519Signer, Ed25519Verifier, Sha256Hasher};
use lunepack_testkit::exe_headers::{self, PeSpec};

const APP: &str = "org.example.hello";
const T0: u64 = 1_800_000_000;
const WORK_PREFIX: &str = "lunepack-pack-";

struct At(u64);

impl Clock for At {
    fn now_unix_secs(&self) -> u64 {
        self.0
    }
}

struct Key {
    path: PathBuf,
    public: String,
}

fn s(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

fn hex(text: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

/// A config with one root key and one release key, and release dirs whose `keys.json` lists it.
struct World {
    dir: tempfile::TempDir,
    config: PathBuf,
    /// The config as `init` wrote it; `set_config` appends to this.
    base: String,
    tmp: PathBuf,
    root: Key,
    release: Key,
    secrets: RefCell<Vec<Vec<u8>>>,
}

impl World {
    fn new() -> World {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join("tmp");
        fs::create_dir(&tmp).unwrap();
        let mut w = World {
            config: dir.path().join("lunepack.toml"),
            base: String::new(),
            tmp,
            root: Key {
                path: PathBuf::new(),
                public: String::new(),
            },
            release: Key {
                path: PathBuf::new(),
                public: String::new(),
            },
            secrets: RefCell::new(Vec::new()),
            dir,
        };
        w.root = w.new_key("root");
        w.release = w.new_key("release0");
        let out = w.run(
            &["init", "--app-id", APP, "--root-key", &w.root.public],
            &[],
        );
        assert_ok(&out, "init");
        w.base = fs::read_to_string(&w.config).unwrap();
        w
    }

    /// The config becomes `init`'s text plus `extra`.
    fn set_config(&self, extra: &str) {
        fs::write(&self.config, format!("{}{extra}", self.base)).unwrap();
    }

    fn cmd(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let output = run(args, env);
        let secrets = self.secrets.borrow();
        let refs: Vec<&[u8]> = secrets.iter().map(Vec::as_slice).collect();
        assert_no_secrets(&output, &refs);
        output
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut full = vec!["--config", s(&self.config)];
        full.extend_from_slice(args);
        self.cmd(&full, env)
    }

    fn new_key(&self, name: &str) -> Key {
        let base = self.dir.path().join(name);
        let out = self.cmd(&["keys", "gen", s(&base)], &[]);
        assert_ok(&out, "keys gen");
        let path = base.with_extension("key");
        let pem = fs::read_to_string(&path).unwrap();
        let seed = SigningKey::from_pkcs8_pem(&pem).unwrap().to_bytes();
        let mut secrets = self.secrets.borrow_mut();
        secrets.push(pem.into_bytes());
        secrets.push(seed.to_vec());
        Key {
            path,
            public: field(&stdout(&out), "public:"),
        }
    }

    /// A release dir named `name` with `keys.json` written at `T0`, and its own publisher state.
    fn release_dir(&self, name: &str) -> PathBuf {
        let dir = self.dir.path().join(name);
        fs::create_dir(&dir).unwrap();
        let publisher = self.dir.path().join(format!("{name}.publisher"));
        fs::create_dir(&publisher).unwrap();
        let config = publisher.join("lunepack.toml");
        fs::write(&config, &self.base).unwrap();
        let root = format!("file:{}", s(&self.root.path));
        let out = self.cmd(
            &[
                "--config",
                s(&config),
                "keys",
                "set",
                "--release-dir",
                s(&dir),
                "--threshold",
                "1",
                "--release-key",
                &self.release.public,
                "--sign",
                &root,
            ],
            &[("SOURCE_DATE_EPOCH", &T0.to_string())],
        );
        assert_ok(&out, "keys set");
        dir
    }

    /// `pack` of `input` as `target` into `dir`, with `extra` arguments and environment.
    fn pack(
        &self,
        input: &Path,
        dir: &Path,
        target: &str,
        extra: &[&str],
        env: &[(&str, &str)],
    ) -> Output {
        let signer = format!("file:{}", s(&self.release.path));
        let mut args = vec![
            "pack",
            "--input",
            s(input),
            "--version",
            "1.0.0",
            "--target",
            target,
            "--release-dir",
            s(dir),
            "--sign",
            &signer,
        ];
        args.extend_from_slice(extra);
        let epoch = T0.to_string();
        let tmp = s(&self.tmp).to_owned();
        let mut full_env = vec![
            ("SOURCE_DATE_EPOCH", epoch.as_str()),
            ("TMPDIR", tmp.as_str()),
            ("TMP", tmp.as_str()),
            ("TEMP", tmp.as_str()),
        ];
        full_env.extend_from_slice(env);
        self.run(&args, &full_env)
    }

    fn work_dirs(&self) -> usize {
        fs::read_dir(&self.tmp)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(WORK_PREFIX)
            })
            .count()
    }

    fn keys(&self, release_dir: &Path) -> VerifiedKeySet {
        let root = TrustedRoot::from_parts(
            AppId::parse(APP).unwrap(),
            1,
            1,
            &[hex(&self.root.public)],
            &Sha256Hasher,
            &Ed25519Verifier,
        )
        .unwrap();
        verify_key_set(
            &root,
            &fs::read(release_dir.join("keys.json")).unwrap(),
            &RollbackFloor::default(),
            &ClockReading::read(&At(T0), None),
            &Sha256Hasher,
            &Ed25519Verifier,
        )
        .expect("keys.json verifies")
    }

    /// Reads a release the way a client does: the manifest, and every file decoded and checked
    /// against the manifest's SHA-256.
    fn verify(
        &self,
        release_dir: &Path,
        target: Target,
    ) -> (VerifiedManifest, BTreeMap<String, Vec<u8>>) {
        let keys = self.keys(release_dir);
        let base = release_dir.join("1.0.0");
        let manifest = fs::read(base.join(format!("{}.manifest.json", target.as_str()))).unwrap();
        let pack = fs::read(base.join(format!("{}.pack", target.as_str()))).unwrap();
        let app = AppId::parse(APP).unwrap();
        let channel = Channel::parse("stable").unwrap();
        let release = ReleaseDoc {
            version: "1.0.0".to_owned(),
            targets: BTreeMap::from([(
                target.as_str().to_owned(),
                ArtifactRef {
                    path: format!("1.0.0/{}.manifest.json", target.as_str()),
                    size: U53::new(manifest.len() as u64).unwrap(),
                    sha256: Sha256Hasher.sha256(&manifest),
                },
            )]),
            rollout: None,
        };
        let feed = next_feed(None, &app, &channel, T0, vec![release], None).unwrap();
        let signer = Ed25519Signer::from_key_file(&self.release.path).unwrap();
        let refs: [&dyn Signer; 1] = [&signer];
        let feed_bytes = sign_envelope(
            PayloadKind::Feed,
            &feed.to_payload(),
            &refs,
            &Sha256Hasher,
            &Ed25519Verifier,
        )
        .unwrap();
        let feed = verify_feed(
            &keys,
            &feed_bytes,
            &app,
            &channel,
            &RollbackFloor::default(),
            &ClockReading::read(&At(T0), None),
            &Ed25519Verifier,
        )
        .unwrap();
        let entry = feed.target_entry(0, target).unwrap();
        let verified = verify_manifest(&keys, &entry, &manifest, &Sha256Hasher, &Ed25519Verifier)
            .expect("the manifest verifies");
        verified.pack().check_bytes(&pack, &Sha256Hasher).unwrap();
        let mut files = BTreeMap::new();
        for e in verified.entries() {
            if let VerifiedEntry::File { path, frame, .. } = e {
                let mut out = Vec::new();
                if let Some(f) = frame {
                    let start = f.offset() as usize;
                    let bytes = &pack[start..start + f.length() as usize];
                    decode_verified(f, bytes, &Sha256Hasher, &LzmaCodec, &mut out)
                        .expect("the frame decodes");
                }
                files.insert(path.as_str().to_owned(), out);
            }
        }
        (verified, files)
    }
}

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// Everything a pack's stdout and stderr say, for substring checks.
fn said(out: &Output) -> String {
    format!("{}\n{}", stdout(out), stderr(out))
}

/// The signed form of a Windows image: a PE32+ with a certificate table at its end.
fn signed_pe() -> Vec<u8> {
    let mut spec = PeSpec::hardened(2);
    let at = exe_headers::pe_image(0x8664, &spec).len().div_ceil(8) * 8;
    spec.security_dir = Some((at as u32, 32));
    let mut bytes = exe_headers::pe_image(0x8664, &spec);
    bytes.resize(at, 0);
    bytes.extend_from_slice(&[0x5A; 32]);
    bytes
}

fn unsigned_pe() -> Vec<u8> {
    exe_headers::pe_image(0x8664, &PeSpec::hardened(2))
}

const ARM64: u32 = 0x0100_000C;

/// The signed form of a thin arm64 Mach-O: one `LC_CODE_SIGNATURE` whose data lies in the file.
fn signed_macho() -> Vec<u8> {
    let mut b = Vec::new();
    for word in [0xFEED_FACF, ARM64, 0, 2, 1, 16, 0, 0] {
        b.extend_from_slice(&word.to_le_bytes());
    }
    for word in [0x1du32, 16, 64, 16] {
        b.extend_from_slice(&word.to_le_bytes());
    }
    b.resize(80, 0xAA);
    b
}

fn unsigned_macho(len: usize) -> Vec<u8> {
    exe_headers::macho(ARM64, false, len)
}

/// `[update]` and `[install]` of a macOS app named Hello, plus `extra` inside `[update]`.
fn mac_toml(extra_update: &str) -> String {
    format!(
        "\n[update]\nfeed = \"https://updates.example.com/hello\"\n{extra_update}\n\
         [install]\nentry = \"Contents/MacOS/Hello\"\nname = \"Hello\"\n"
    )
}

/// TOML for a template: a literal string per element (no escapes, so Windows paths pass).
fn tpl(parts: &[&str]) -> String {
    let items: Vec<String> = parts.iter().map(|p| format!("'{p}'")).collect();
    format!("[{}]", items.join(", "))
}

#[cfg(unix)]
mod fake {
    use super::*;

    /// The helper programs of one world: `sh` scripts that log and rewrite, in `tools/`.
    pub struct Tools {
        pub dir: PathBuf,
        pub log: PathBuf,
        pub zip_copy: PathBuf,
    }

    impl Tools {
        pub fn new(w: &World) -> Tools {
            let dir = w.dir.path().join("tools");
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("signed.macho"), signed_macho()).unwrap();
            fs::write(dir.join("signed.pe"), signed_pe()).unwrap();
            Tools {
                log: dir.join("log"),
                zip_copy: dir.join("notarize.zip"),
                dir,
            }
        }

        /// Writes `<name>.sh` running `body`, with `$LOG` and `$TOOLS` set; returns its path.
        pub fn script(&self, name: &str, body: &str) -> String {
            let path = self.dir.join(format!("{name}.sh"));
            let text = format!(
                "#!/bin/sh\nLOG='{}'\nTOOLS='{}'\n{body}\n",
                self.log.display(),
                self.dir.display()
            );
            fs::write(&path, text).unwrap();
            path.to_str().unwrap().to_owned()
        }

        /// A template running script `name` with the given trailing elements.
        pub fn template(&self, name: &str, body: &str, args: &[&str]) -> String {
            let script = self.script(name, body);
            let mut parts = vec!["/bin/sh", script.as_str()];
            parts.extend_from_slice(args);
            tpl(&parts)
        }

        /// The log's lines as `(key, path under the tree)`; the tree root is `""`.
        pub fn log(&self) -> Vec<(String, String)> {
            let text = fs::read_to_string(&self.log).unwrap_or_default();
            text.lines()
                .map(|line| {
                    let (key, path) = line.split_once('|').unwrap_or((line, ""));
                    let rel = ["/tree.app", "/tree"]
                        .iter()
                        .find_map(|marker| path.split_once(marker).map(|(_, rest)| rest))
                        .map_or(path, |rest| rest.trim_start_matches('/'));
                    (key.to_owned(), rel.to_owned())
                })
                .collect()
        }

        /// The `[codesign.macos]` section of fake signers: loose Mach-O files are replaced by
        /// [`signed_macho`], bundles get a `_CodeSignature/CodeResources`, staple writes a ticket.
        pub fn macos_section(&self, with_notarize: bool) -> String {
            self.macos_section_with(with_notarize, &[])
        }

        /// Like [`Tools::macos_section`], with the script body and trailing arguments of some keys
        /// replaced: `(key, body, args)`.
        pub fn macos_section_with(
            &self,
            with_notarize: bool,
            over: &[(&str, &str, &[&str])],
        ) -> String {
            let make = |key: &str, body: &str, args: &[&str]| match over
                .iter()
                .find(|(k, ..)| *k == key)
            {
                Some((_, b, a)) => self.template(key, b, a),
                None => self.template(key, body, args),
            };
            let bundle_body = |key: &str| {
                format!(
                    "echo \"{key}|$1\" >> \"$LOG\"; mkdir -p \"$1/Contents/_CodeSignature\"; \
                     echo seal > \"$1/Contents/_CodeSignature/CodeResources\""
                )
            };
            let sign = make(
                "sign",
                "echo \"sign|$1\" >> \"$LOG\"; cp \"$TOOLS/signed.macho\" \"$1\"",
                &["{path}"],
            );
            let sign_bundle = make("sign_bundle", &bundle_body("sign_bundle"), &["{path}"]);
            let sign_outer = make("sign_outer", &bundle_body("sign_outer"), &["{path}"]);
            let verify = make("verify", "echo \"verify|$1\" >> \"$LOG\"", &["{path}"]);
            let mut text = format!(
                "\n[codesign.macos]\nsign = {sign}\nsign_bundle = {sign_bundle}\n\
                 sign_outer = {sign_outer}\nverify = {verify}\n"
            );
            if with_notarize {
                let notarize = make(
                    "notarize",
                    "echo \"notarize|$1\" >> \"$LOG\"; cp \"$2\" \"$TOOLS/notarize.zip\"",
                    &["{bundle}", "{zip}"],
                );
                let staple = make(
                    "staple",
                    "echo \"staple|$1\" >> \"$LOG\"; \
                     if [ -e \"$(dirname \"$1\")/lunepack-notarize.zip\" ]; then echo zip-present >> \"$LOG\"; fi; \
                     echo ticket > \"$1/Contents/CodeResources\"",
                    &["{path}"],
                );
                text.push_str(&format!("notarize = {notarize}\nstaple = {staple}\n"));
            }
            text
        }
    }

    /// A bundle input: `Info.plist`, the entry, a framework with `Versions/Current` links, a loose
    /// library and a non-Mach-O helper.
    pub fn mac_app(root: &Path) {
        write(root, "Contents/Info.plist", b"<plist/>");
        write(root, "Contents/MacOS/Hello", &unsigned_macho(20_000));
        set_mode(&root.join("Contents/MacOS/Hello"), 0o755);
        write(root, "Contents/Resources/readme.txt", b"read me\n");
        let fw = "Contents/Frameworks/Foo.framework";
        write(
            root,
            &format!("{fw}/Versions/A/Foo"),
            &unsigned_macho(9_000),
        );
        set_mode(&root.join(format!("{fw}/Versions/A/Foo")), 0o755);
        write(
            root,
            &format!("{fw}/Versions/A/Resources/Info.plist"),
            b"<plist/>",
        );
        std::os::unix::fs::symlink("A", root.join(format!("{fw}/Versions/Current"))).unwrap();
        std::os::unix::fs::symlink("Versions/Current/Foo", root.join(format!("{fw}/Foo"))).unwrap();
        write(
            root,
            "Contents/Frameworks/libx.dylib",
            &unsigned_macho(5_000),
        );
        write(root, "Contents/Helpers/Updater", b"#!/bin/sh\n");
        set_mode(&root.join("Contents/Helpers/Updater"), 0o755);
    }

    /// The runtime and UI files given to `--runtime` and `--ui`.
    pub fn mac_bins(w: &World) -> (PathBuf, PathBuf) {
        let (runtime, ui) = (w.dir.path().join("runtime"), w.dir.path().join("ui"));
        fs::write(&runtime, unsigned_macho(4_096)).unwrap();
        fs::write(&ui, unsigned_macho(6_000)).unwrap();
        (runtime, ui)
    }

    pub fn pack_mac(w: &World, input: &Path, dir: &Path, bins: &(PathBuf, PathBuf)) -> Output {
        w.pack(
            input,
            dir,
            "macos-aarch64",
            &["--runtime", s(&bins.0), "--ui", s(&bins.1)],
            &[],
        )
    }

    const HELPER: &str = "Contents/Helpers/lunepack-update.app";

    pub fn mac_world(notarize: bool) -> (World, Tools, PathBuf, tempfile::TempDir) {
        let w = World::new();
        let tools = Tools::new(&w);
        w.set_config(&format!(
            "{}{}",
            mac_toml(""),
            tools.macos_section(notarize)
        ));
        let dir = w.release_dir("rel");
        let input = tempfile::tempdir().unwrap();
        mac_app(input.path());
        (w, tools, dir, input)
    }

    /// C2's order: the plan inner to outer, the right template per kind, `verify` after the outer
    /// bundle, then notarize and staple; and the hash stage sees the post-sign bytes.
    #[test]
    fn macos_items_are_signed_inner_to_outer_and_hashed_after_signing() {
        let (w, tools, dir, input) = mac_world(true);
        let bins = mac_bins(&w);
        let out = pack_mac(&w, input.path(), &dir, &bins);
        assert_ok(&out, "macos pack with fake signers");
        let fw = "Contents/Frameworks/Foo.framework";
        let helper_ui = format!("{HELPER}/Contents/MacOS/lunepack-ui");
        let expected: Vec<(&str, String)> = vec![
            ("sign", format!("{fw}/Versions/A/Foo")),
            ("sign_bundle", fw.to_owned()),
            ("sign", helper_ui.clone()),
            ("sign_bundle", HELPER.to_owned()),
            ("sign", "Contents/Frameworks/libx.dylib".to_owned()),
            ("sign", "Contents/MacOS/lunepack-runtime".to_owned()),
            ("sign_outer", String::new()),
            ("verify", String::new()),
            ("notarize", String::new()),
            ("staple", String::new()),
        ];
        let log = tools.log();
        let got: Vec<(&str, &str)> = log.iter().map(|(k, p)| (k.as_str(), p.as_str())).collect();
        let want: Vec<(&str, &str)> = expected.iter().map(|(k, p)| (*k, p.as_str())).collect();
        assert_eq!(got, want, "the order the tools ran in");
        assert!(
            !log.iter().any(|(k, _)| k == "zip-present"),
            "the zip is gone before staple"
        );
        assert_eq!(w.work_dirs(), 0);

        // The hash stage saw the signed bytes, the entry (the bundle's main executable) was
        // left to the outer bundle, and the ticket stapler wrote is in the manifest.
        let (m, files) = w.verify(&dir, Target::MacosAarch64);
        let signed = signed_macho();
        for path in [
            format!("{fw}/Versions/A/Foo"),
            helper_ui,
            "Contents/Frameworks/libx.dylib".to_owned(),
            "Contents/MacOS/lunepack-runtime".to_owned(),
        ] {
            assert_eq!(files[&path], signed, "{path}");
        }
        assert_eq!(files["Contents/MacOS/Hello"], unsigned_macho(20_000));
        assert_eq!(files["Contents/_CodeSignature/CodeResources"], b"seal\n");
        assert_eq!(files["Contents/CodeResources"], b"ticket\n");
        assert!(
            m.entries()
                .iter()
                .any(|e| e.path().as_str() == "Contents/CodeResources"),
            "the ticket is in the manifest"
        );
        // The notarization zip held the tree under `<name>.app`, and did not outlive the call.
        let zip = fs::read(&tools.zip_copy).unwrap();
        assert!(zip.starts_with(b"PK\x03\x04"));
        for name in [
            "Hello.app/Contents/MacOS/Hello",
            "Hello.app/Contents/_CodeSignature/CodeResources",
            "Hello.app/Contents/Frameworks/Foo.framework/Versions/Current",
        ] {
            assert!(
                zip.windows(name.len()).any(|w| w == name.as_bytes()),
                "{name} is in the zip"
            );
        }
        let text = stdout(&out);
        assert!(text.contains("code-sign: 7 item(s)"), "{text}");
        assert!(
            text.contains("code-sign: Contents/MacOS/lunepack-runtime"),
            "{text}"
        );
    }

    /// M9-D6 / M9-R1-D1: the policy a pack writes into the update configuration.
    #[test]
    fn the_publisher_policy_is_written_by_the_default_rule() {
        let policy_of = |files: &BTreeMap<String, Vec<u8>>| {
            let bytes = &files["Contents/Resources/lunepack-update.json"];
            (
                lunepack_core::UpdateConfig::parse(bytes)
                    .unwrap()
                    .publisher_check,
                String::from_utf8_lossy(bytes).contains("publisher_check"),
            )
        };
        let bins_for = |w: &World| mac_bins(w);
        let pack_with = |config_extra: &str, update_extra: &str| {
            let w = World::new();
            let tools = Tools::new(&w);
            w.set_config(&format!(
                "{}{}",
                mac_toml(update_extra),
                config_extra.replace("@MAC@", &tools.macos_section(false))
            ));
            let dir = w.release_dir("rel");
            let input = tempfile::tempdir().unwrap();
            mac_app(input.path());
            let out = pack_mac(&w, input.path(), &dir, &bins_for(&w));
            assert_ok(&out, "pack");
            let (_, files) = w.verify(&dir, Target::MacosAarch64);
            policy_of(&files)
        };
        use lunepack_core::PublisherPolicy::{Enforce, Off, Warn};
        // OS signing configured for the target: enforce, written.
        assert_eq!(pack_with("@MAC@", ""), (Enforce, true));
        // An explicit value wins.
        assert_eq!(
            pack_with("@MAC@", "publisher_check = \"warn\"\n"),
            (Warn, true)
        );
        assert_eq!(
            pack_with("@MAC@", "publisher_check = \"off\"\n"),
            (Off, false)
        );
        // No section for this target (the other OS's is ignored): off, and not written.
        assert_eq!(
            pack_with("\n[codesign.windows]\nsign = ['x', '{path}']\n", ""),
            (Off, false)
        );
        assert_eq!(pack_with("", ""), (Off, false));
    }

    /// A template that exits 0 and changes nothing, or signs another file, fails the pack naming
    /// the item and the template's key, and nothing reaches the release.
    #[test]
    fn a_tool_that_leaves_the_item_unsigned_fails_the_pack() {
        let first = "Contents/Frameworks/Foo.framework/Versions/A/Foo";
        let fw = "Contents/Frameworks/Foo.framework";
        let path: &[&str] = &["{path}"];
        let cases: [(&str, &str, &str, &str); 4] = [
            ("sign", "sign changes nothing", "exit 0", first),
            (
                "sign",
                "sign signs another file",
                "cp \"$TOOLS/signed.macho\" \"$1.other\"",
                first,
            ),
            ("sign_bundle", "a bundle left unsigned", "exit 0", fw),
            (
                "sign_outer",
                "the outer bundle left unsigned",
                "exit 0",
                "Hello.app",
            ),
        ];
        for (key, what, body, item) in cases {
            let (w, tools, dir, input) = mac_world(false);
            w.set_config(&format!(
                "{}{}",
                mac_toml(""),
                tools.macos_section_with(false, &[(key, body, path)])
            ));
            let out = pack_mac(&w, input.path(), &dir, &mac_bins(&w));
            let err = assert_fails(&out, 1, what);
            assert!(
                err.contains(&format!("code-sign: {item} is not signed after {key}")),
                "{what}: {err:?}"
            );
            assert!(!dir.join("1.0.0").exists(), "{what}: nothing is written");
            assert_eq!(w.work_dirs(), 0, "{what}");
        }
    }

    /// A staple that writes no ticket fails the pack.
    #[test]
    fn a_staple_that_writes_no_ticket_fails_the_pack() {
        let (w, tools, dir, input) = mac_world(true);
        w.set_config(&format!(
            "{}{}",
            mac_toml(""),
            tools.macos_section_with(true, &[("staple", "exit 0", &["{path}"])])
        ));
        let out = pack_mac(&w, input.path(), &dir, &mac_bins(&w));
        let err = assert_fails(&out, 1, "no ticket");
        assert!(err.contains("staple left no ticket"), "{err:?}");
        assert!(!dir.join("1.0.0").exists());
        assert_eq!(w.work_dirs(), 0, "the zip and the work dir are gone");
    }

    /// M8-D8: a signed input bundle runs no template, and packs as it would without OS signing.
    #[test]
    fn a_signed_input_bundle_runs_no_template() {
        let (w, tools, dir, input) = mac_world(true);
        let bins = mac_bins(&w);
        // Both configs write the same policy, so the same bytes are placed.
        let off = "publisher_check = \"off\"\n";
        let with_signing = format!("{}{}", mac_toml(off), tools.macos_section(true));
        w.set_config(&with_signing);
        let assembled = w.dir.path().join("assembled");
        let out = w.run(
            &[
                "pack",
                "--input",
                s(input.path()),
                "--version",
                "1.0.0",
                "--target",
                "macos-aarch64",
                "--runtime",
                s(&bins.0),
                "--ui",
                s(&bins.1),
                "--assemble",
                s(&assembled),
            ],
            &[("SOURCE_DATE_EPOCH", &T0.to_string())],
        );
        assert_ok(&out, "assemble");
        assert!(tools.log().is_empty(), "assemble signs nothing");
        // "Sign" it as a developer would: the seal directory.
        write(&assembled, "Contents/_CodeSignature/CodeResources", b"seal");

        let out = pack_mac(&w, &assembled, &dir, &bins);
        assert_ok(&out, "pack of the signed bundle");
        assert!(
            stdout(&out).contains("already signed; left unchanged"),
            "{}",
            stdout(&out)
        );
        assert!(tools.log().is_empty(), "no template ran: {:?}", tools.log());
        let (_, with) = w.verify(&dir, Target::MacosAarch64);
        assert_eq!(with["Contents/_CodeSignature/CodeResources"], b"seal");

        // The same pack without any `[codesign.*]` gives the same files and the same pack bytes.
        w.set_config(&mac_toml(off));
        let plain_dir = w.release_dir("plain");
        assert_ok(&pack_mac(&w, &assembled, &plain_dir, &bins), "plain pack");
        let (_, plain) = w.verify(&plain_dir, Target::MacosAarch64);
        assert_eq!(with, plain);
        assert_eq!(
            fs::read(dir.join("1.0.0/macos-aarch64.pack")).unwrap(),
            fs::read(plain_dir.join("1.0.0/macos-aarch64.pack")).unwrap()
        );
    }

    /// A macOS pack needs `[update]` for OS signing: the bundle's main executable is its entry.
    #[test]
    fn macos_signing_needs_update() {
        let w = World::new();
        let tools = Tools::new(&w);
        w.set_config(&tools.macos_section(false));
        let dir = w.release_dir("rel");
        let input = tempfile::tempdir().unwrap();
        mac_app(input.path());
        let out = w.pack(input.path(), &dir, "macos-aarch64", &[], &[]);
        let err = assert_fails(&out, 1, "no [update]");
        assert!(err.contains("[codesign.macos] needs [update]"), "{err:?}");
        assert!(tools.log().is_empty());
    }

    /// M9-D3: a failing tool's output reaches the user only through the runner: no argv, and the
    /// call's `{env:}` values replaced by their names. A variable that is unset stops the pack
    /// before any tool runs.
    #[test]
    fn a_failing_tool_prints_no_argv_and_no_env_value() {
        let (w, tools, dir, input) = mac_world(false);
        let planted = format!("planted-identity-{}", std::process::id());
        w.set_config(&format!(
            "{}{}",
            mac_toml(""),
            tools.macos_section_with(
                false,
                &[(
                    "sign",
                    "echo \"identity $1 rejected\" >&2; exit 1",
                    &["{env:SIGN_ID}", "{path}"],
                )]
            )
        ));
        let bins = mac_bins(&w);
        let signer = format!("file:{}", s(&w.release.path));
        let args = [
            "pack",
            "--input",
            s(input.path()),
            "--version",
            "1.0.0",
            "--target",
            "macos-aarch64",
            "--release-dir",
            s(&dir),
            "--sign",
            &signer,
            "--runtime",
            s(&bins.0),
            "--ui",
            s(&bins.1),
        ];
        // Unset: refused naming the variable, before anything ran.
        let out = w.run(&args, &[("SOURCE_DATE_EPOCH", &T0.to_string())]);
        let err = assert_fails(&out, 1, "an unset variable");
        assert!(err.contains("SIGN_ID") && err.contains("unset"), "{err:?}");
        assert!(tools.log().is_empty());
        // Set: the tool fails; its message shows the name in place of the value.
        let out = w.run(
            &args,
            &[
                ("SOURCE_DATE_EPOCH", &T0.to_string()),
                ("SIGN_ID", &planted),
            ],
        );
        let err = assert_fails(&out, 1, "a failing tool");
        assert!(err.contains("sign failed"), "{err:?}");
        assert!(err.contains("identity <SIGN_ID> rejected"), "{err:?}");
        let all = said(&out);
        assert!(!all.contains(&planted), "an env value is shown");
        assert!(
            !all.contains(&tools.dir.display().to_string()),
            "the argv (the script's path) is shown"
        );
        assert!(!dir.join("1.0.0").exists());
    }

    /// Windows target through fake signers: only PE files without a certificate table are signed,
    /// deepest first; a signed PE and a non-PE `.exe` are left byte for byte; `verify` follows each.
    #[test]
    fn windows_unsigned_pe_files_are_signed_and_the_rest_left_alone() {
        let w = World::new();
        let tools = Tools::new(&w);
        let sign = tools.template(
            "sign",
            "echo \"sign|$1\" >> \"$LOG\"; cp \"$TOOLS/signed.pe\" \"$1\"",
            &["{path}"],
        );
        let verify = tools.template("verify", "echo \"verify|$1\" >> \"$LOG\"", &["{path}"]);
        w.set_config(&format!(
            "\n[codesign.windows]\nsign = {sign}\nverify = {verify}\n"
        ));
        let dir = w.release_dir("rel");
        let input = tempfile::tempdir().unwrap();
        write(input.path(), "bin/app.exe", &unsigned_pe());
        write(input.path(), "bin/deep/lib.dll", &unsigned_pe());
        write(input.path(), "third-party.dll", &signed_pe());
        write(input.path(), "fake.exe", b"MZ, but not a PE image");
        write(input.path(), "readme.txt", b"text");
        let out = w.pack(input.path(), &dir, "windows-x86_64", &[], &[]);
        assert_ok(&out, "windows pack with fake signers");
        let got = tools.log();
        let got: Vec<(&str, &str)> = got.iter().map(|(k, p)| (k.as_str(), p.as_str())).collect();
        assert_eq!(
            got,
            [
                ("sign", "bin/deep/lib.dll"),
                ("verify", "bin/deep/lib.dll"),
                ("sign", "bin/app.exe"),
                ("verify", "bin/app.exe"),
            ]
        );
        let (_, files) = w.verify(&dir, Target::WindowsX86_64);
        assert_eq!(files["bin/app.exe"], signed_pe());
        assert_eq!(files["bin/deep/lib.dll"], signed_pe());
        assert_eq!(files["third-party.dll"], signed_pe());
        assert_eq!(files["fake.exe"], b"MZ, but not a PE image");
        // Linux has nothing to sign: a `[codesign.windows]` section is ignored for it.
        let out = w.pack(
            input.path(),
            &w.release_dir("linux"),
            "linux-x86_64",
            &[],
            &[],
        );
        assert_ok(&out, "linux pack");
        assert_eq!(tools.log().len(), 4, "no tool ran for linux");
    }

    /// M10-D7: the placed update service is an unsigned PE of the tree, so the OS sign stage signs
    /// it and verifies it like the runtime, the stub and the entry; the sign stage runs after the
    /// placement and before the hash.
    #[test]
    fn windows_service_is_signed_like_the_other_pes() {
        let w = World::new();
        let tools = Tools::new(&w);
        let sign = tools.template(
            "sign",
            "echo \"sign|$1\" >> \"$LOG\"; cp \"$TOOLS/signed.pe\" \"$1\"",
            &["{path}"],
        );
        let verify = tools.template("verify", "echo \"verify|$1\" >> \"$LOG\"", &["{path}"]);
        w.set_config(&format!(
            "\n[update]\nfeed = \"https://updates.example.com/hello\"\n\n\
             [install]\nentry = \"bin/app.exe\"\nname = \"Hello\"\n\n\
             [codesign.windows]\nsign = {sign}\nverify = {verify}\n"
        ));
        let input = tempfile::tempdir().unwrap();
        write(input.path(), "bin/app.exe", &unsigned_pe());
        let runtime = w.dir.path().join("runtime.exe");
        fs::write(&runtime, unsigned_pe()).unwrap();
        let stub = w.dir.path().join("stub.exe");
        fs::write(&stub, unsigned_pe()).unwrap();
        let service = w.dir.path().join("service.exe");
        fs::write(
            &service,
            exe_headers::pe_image(0x8664, &PeSpec::hardened(3)),
        )
        .unwrap();
        let dir = w.release_dir("rel");
        let out = w.pack(
            input.path(),
            &dir,
            "windows-x86_64",
            &[
                "--runtime",
                s(&runtime),
                "--stub",
                s(&stub),
                "--service",
                s(&service),
            ],
            &[],
        );
        assert_ok(&out, "windows pack with --service and fake signers");
        let got = tools.log();
        for key in ["sign", "verify"] {
            assert!(
                got.iter()
                    .any(|(k, p)| k == key && p == "bin/lunepack-service.exe"),
                "{key} of the service: {got:?}"
            );
        }
        let (_, files) = w.verify(&dir, Target::WindowsX86_64);
        assert_eq!(files["bin/lunepack-service.exe"], signed_pe());
    }
}

#[cfg(target_os = "macos")]
mod real_macos {
    use super::*;
    use std::process::Command;

    const CODESIGN: &str = "/usr/bin/codesign";

    fn target() -> (&'static str, Target, u32) {
        if cfg!(target_arch = "aarch64") {
            ("macos-aarch64", Target::MacosAarch64, 0x0100_000C)
        } else {
            ("macos-x86_64", Target::MacosX86_64, 0x0100_0007)
        }
    }

    /// A real, runnable Mach-O for this host with its signature removed (the test binary).
    fn unsigned_real(dir: &Path, name: &str) -> Vec<u8> {
        let path = dir.join(name);
        fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        let out = Command::new(CODESIGN)
            .arg("--remove-signature")
            .arg(&path)
            .output()
            .expect("start codesign");
        assert!(
            out.status.success(),
            "codesign --remove-signature failed ({})",
            out.status
        );
        let bytes = fs::read(&path).unwrap();
        // The premise of every case below: the file is a Mach-O the check calls unsigned.
        assert!(!lunepack_core::macho_slices_signed(&bytes), "still signed");
        bytes
    }

    fn plist(executable: &str, id: &str, kind: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\
             <key>CFBundleExecutable</key><string>{executable}</string>\
             <key>CFBundleIdentifier</key><string>{id}</string>\
             <key>CFBundleName</key><string>{executable}</string>\
             <key>CFBundlePackageType</key><string>{kind}</string>\
             </dict></plist>\n"
        )
    }

    fn exec_write(root: &Path, rel: &str, bytes: &[u8]) {
        write(root, rel, bytes);
        set_mode(&root.join(rel), 0o755);
    }

    /// The bundle input: real unsigned Mach-O files for the entry and a framework.
    fn app(root: &Path, scratch: &Path) {
        write(
            root,
            "Contents/Info.plist",
            plist("Hello", "org.example.hello", "APPL").as_bytes(),
        );
        exec_write(
            root,
            "Contents/MacOS/Hello",
            &unsigned_real(scratch, "hello"),
        );
        write(root, "Contents/Resources/readme.txt", b"read me\n");
        let fw = "Contents/Frameworks/Foo.framework";
        exec_write(
            root,
            &format!("{fw}/Versions/A/Foo"),
            &unsigned_real(scratch, "foo"),
        );
        write(
            root,
            &format!("{fw}/Versions/A/Resources/Info.plist"),
            plist("Foo", "org.example.foo", "FMWK").as_bytes(),
        );
        use std::os::unix::fs::symlink;
        symlink("A", root.join(format!("{fw}/Versions/Current"))).unwrap();
        symlink("Versions/Current/Foo", root.join(format!("{fw}/Foo"))).unwrap();
        symlink(
            "Versions/Current/Resources",
            root.join(format!("{fw}/Resources")),
        )
        .unwrap();
    }

    /// Writes the pack's tree to `dest` as a bundle: directories, files with their exec bit and
    /// links, as an install would stage it.
    fn stage(m: &VerifiedManifest, files: &BTreeMap<String, Vec<u8>>, dest: &Path) {
        fs::create_dir_all(dest).unwrap();
        for e in m.entries() {
            let at = dest.join(e.path().as_str());
            match e {
                VerifiedEntry::Dir { .. } => fs::create_dir_all(&at).unwrap(),
                VerifiedEntry::File { path, exec, .. } => {
                    fs::create_dir_all(at.parent().unwrap()).unwrap();
                    fs::write(&at, &files[path.as_str()]).unwrap();
                    set_mode(&at, if *exec { 0o755 } else { 0o644 });
                }
                VerifiedEntry::Symlink { target, .. } => {
                    fs::create_dir_all(at.parent().unwrap()).unwrap();
                    std::os::unix::fs::symlink(target, &at).unwrap();
                }
            }
        }
    }

    fn codesign_verify(bundle: &Path) -> Output {
        Command::new(CODESIGN)
            .args(["--verify", "--deep", "--strict"])
            .arg(bundle)
            .output()
            .expect("start codesign")
    }

    /// Real `/usr/bin/codesign`, ad hoc: an unsigned app with the runtime, the helper app and a
    /// nested framework packs, and the bundle staged from the pack passes `codesign --verify
    /// --deep --strict`. The same verify on a tree with one nested Mach-O unsigned fails, which
    /// is the check that the verify can tell. A second pack runs the real `stapler validate` on
    /// the path the templates get and shows it is accepted as a bundle.
    #[test]
    fn a_real_ad_hoc_signed_bundle_verifies() {
        let (target_id, target, _) = target();
        let w = World::new();
        let scratch = tempfile::tempdir().unwrap();
        let sign = tpl(&[CODESIGN, "--force", "--sign", "-", "{path}"]);
        let verify = tpl(&[CODESIGN, "--verify", "--deep", "--strict", "{path}"]);
        w.set_config(&format!(
            "{}\n[codesign.macos]\nsign = {sign}\nverify = {verify}\n",
            mac_toml("")
        ));
        let dir = w.release_dir("rel");
        let input = tempfile::tempdir().unwrap();
        app(input.path(), scratch.path());
        let runtime = scratch.path().join("runtime-bin");
        let ui = scratch.path().join("ui-bin");
        fs::write(&runtime, unsigned_real(scratch.path(), "rt")).unwrap();
        fs::write(&ui, unsigned_real(scratch.path(), "ui")).unwrap();
        let extra = ["--runtime", s(&runtime), "--ui", s(&ui)];
        let out = w.pack(input.path(), &dir, target_id, &extra, &[]);
        assert_ok(&out, "pack with real codesign");
        assert!(
            stdout(&out).contains("code-sign: Contents/Frameworks/Foo.framework"),
            "{}",
            stdout(&out)
        );

        let (m, files) = w.verify(&dir, target);
        let staged = scratch.path().join("staged").join("Hello.app");
        stage(&m, &files, &staged);
        let ok = codesign_verify(&staged);
        assert!(
            ok.status.success(),
            "the staged bundle does not verify: {}",
            stderr(&ok)
        );
        // Every Mach-O of the pack is in its signed form.
        for path in [
            "Contents/MacOS/Hello",
            "Contents/MacOS/lunepack-runtime",
            "Contents/Frameworks/Foo.framework/Versions/A/Foo",
            "Contents/Helpers/lunepack-update.app/Contents/MacOS/lunepack-ui",
        ] {
            assert!(
                lunepack_core::macho_slices_signed(&files[path]),
                "{path} is unsigned in the pack"
            );
        }

        // The instrument: the same tree with one nested Mach-O unsigned does not verify.
        let broken = scratch.path().join("broken").join("Hello.app");
        stage(&m, &files, &broken);
        let nested = broken.join("Contents/Frameworks/Foo.framework/Versions/A/Foo");
        let st = Command::new(CODESIGN)
            .arg("--remove-signature")
            .arg(&nested)
            .status()
            .unwrap();
        assert!(st.success());
        assert!(
            !codesign_verify(&broken).status.success(),
            "the verify cannot tell a bundle with an unsigned nested file"
        );

        // `xcrun stapler validate` on the path a template gets: the bundle is accepted (it says
        // there is no ticket, instead of refusing the path).
        let report = scratch.path().join("stapler.txt");
        let probe = scratch.path().join("probe.sh");
        fs::write(
            &probe,
            format!(
                "#!/bin/sh\n/usr/bin/xcrun stapler validate \"$1\" > '{0}' 2>&1\necho \"exit=$?\" >> '{0}'\nexit 0\n",
                report.display()
            ),
        )
        .unwrap();
        w.set_config(&format!(
            "{}\n[codesign.macos]\nsign = {sign}\nverify = {}\n",
            mac_toml(""),
            tpl(&["/bin/sh", s(&probe), "{path}"])
        ));
        let again = w.release_dir("again");
        let out = w.pack(input.path(), &again, target_id, &extra, &[]);
        assert_ok(&out, "pack with the stapler probe");
        let said = fs::read_to_string(&report).unwrap();
        assert!(
            said.contains("does not have a ticket stapled"),
            "stapler validate on the work tree said: {said:?}"
        );
        eprintln!(
            "stapler validate on <work>/tree.app: {}",
            said.lines().last().unwrap_or("")
        );
    }
}

#[cfg(windows)]
mod real_windows {
    use super::*;
    use std::process::Command;

    fn signtool() -> Option<PathBuf> {
        let kits = PathBuf::from(std::env::var_os("ProgramFiles(x86)")?)
            .join("Windows Kits")
            .join("10")
            .join("bin");
        let mut found: Vec<PathBuf> = fs::read_dir(kits)
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.path().join("x64").join("signtool.exe"))
            .filter(|p| p.is_file())
            .collect();
        found.sort();
        found.pop()
    }

    fn powershell(script: &str) -> Option<String> {
        let out = Command::new("powershell")
            // Windows PowerShell 5.1 under a PowerShell 7 parent (CI's `pwsh` steps) inherits a
            // module path that puts 7's modules first; it then has no `Cert:` drive. Without the
            // variable it builds its own default.
            .env_remove("PSModulePath")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }

    /// A throwaway self-signed code-signing certificate in the current user's store, removed on
    /// drop. Its thumbprint is not a secret.
    struct Cert(String);

    impl Cert {
        fn new() -> Option<Cert> {
            let subject = format!("CN=lunepack-test-{}", std::process::id());
            let thumb = powershell(&format!(
                "(New-SelfSignedCertificate -Type CodeSigningCert -Subject '{subject}' \
                 -CertStoreLocation Cert:\\CurrentUser\\My -NotAfter (Get-Date).AddDays(1)).Thumbprint"
            ))?;
            (thumb.len() == 40).then_some(Cert(thumb))
        }
    }

    impl Drop for Cert {
        fn drop(&mut self) {
            let _ = powershell(&format!(
                "Remove-Item -Path Cert:\\CurrentUser\\My\\{} -Force",
                self.0
            ));
        }
    }

    /// Real `signtool` with a throwaway certificate: every previously unsigned PE of the packed
    /// tree has a certificate table, a PE signed before is byte for byte what it was.
    #[test]
    fn real_signtool_signs_every_unsigned_pe() {
        let Some(signtool) = signtool() else {
            eprintln!("skipped: no signtool.exe under Windows Kits\\10\\bin");
            return;
        };
        let Some(cert) = Cert::new() else {
            eprintln!("skipped: cannot create a self-signed certificate (PowerShell)");
            return;
        };
        let w = World::new();
        let sign = tpl(&[
            s(&signtool),
            "sign",
            "/fd",
            "sha256",
            "/sha1",
            "{env:LUNEPACK_TEST_THUMB}",
            "/s",
            "My",
            "{path}",
        ]);
        w.set_config(&format!("\n[codesign.windows]\nsign = {sign}\n"));
        let dir = w.release_dir("rel");
        let input = tempfile::tempdir().unwrap();
        write(input.path(), "bin/app.exe", &unsigned_pe());
        write(input.path(), "bin/deep/lib.dll", &unsigned_pe());
        write(input.path(), "readme.txt", b"text");
        // A PE the developer signed before: sign a copy with the same tool, keep its bytes.
        let pre = input.path().join("third-party.dll");
        fs::write(&pre, unsigned_pe()).unwrap();
        let st = Command::new(&signtool)
            .args(["sign", "/fd", "sha256", "/sha1", &cert.0, "/s", "My"])
            .arg(&pre)
            .output()
            .unwrap();
        assert!(st.status.success(), "signtool could not sign the fixture");
        let pre_bytes = fs::read(&pre).unwrap();
        assert!(lunepack_core::pe_is_signed(
            &pre_bytes,
            pre_bytes.len() as u64
        ));

        let out = w.pack(
            input.path(),
            &dir,
            "windows-x86_64",
            &[],
            &[("LUNEPACK_TEST_THUMB", &cert.0)],
        );
        assert_ok(&out, "windows pack with real signtool");
        let (_, files) = w.verify(&dir, Target::WindowsX86_64);
        for path in ["bin/app.exe", "bin/deep/lib.dll"] {
            let bytes = &files[path];
            assert!(
                lunepack_core::pe_is_signed(bytes, bytes.len() as u64),
                "{path} has no certificate table"
            );
        }
        assert_eq!(files["third-party.dll"], pre_bytes, "a signed PE changed");
        assert_eq!(files["readme.txt"], b"text");
        // `signtool verify /pa` needs the certificate trusted; it is only trusted on a job that
        // imported it (CI). Here it must at least read the signature (a trust failure is not a
        // missing-signature failure).
        let dest = w.dir.path().join("check");
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("app.exe"), &files["bin/app.exe"]).unwrap();
        let v = Command::new(&signtool)
            .args(["verify", "/pa"])
            .arg(dest.join("app.exe"))
            .output()
            .unwrap();
        let text =
            String::from_utf8_lossy(&v.stdout).into_owned() + &String::from_utf8_lossy(&v.stderr);
        assert!(
            v.status.success() || !text.contains("No signature found"),
            "signtool finds no signature in the packed file"
        );
    }

    /// `lunepack setup` signs the finished `Setup.exe` with `sign_installer` (real `signtool`) and
    /// reads it back as signed: the trailer is found before the certificate table (M7-D11).
    #[test]
    fn real_signtool_signs_setup_exe_and_it_reads_back() {
        let Some(signtool) = signtool() else {
            eprintln!("skipped: no signtool.exe under Windows Kits\\10\\bin");
            return;
        };
        let Some(cert) = Cert::new() else {
            eprintln!("skipped: cannot create a self-signed certificate (PowerShell)");
            return;
        };
        let w = World::new();
        let update = "\n[update]\nfeed = \"https://updates.example.com/hello\"\n\
                      [install]\nentry = \"bin/app.exe\"\nname = \"Hello\"\n";
        w.set_config(update);
        let dir = w.release_dir("rel");
        let input = tempfile::tempdir().unwrap();
        write(input.path(), "bin/app.exe", &unsigned_pe());
        let pe = w.dir.path().join("runtime.exe");
        fs::write(&pe, unsigned_pe()).unwrap();
        let out = w.pack(
            input.path(),
            &dir,
            "windows-x86_64",
            &["--runtime", s(&pe), "--stub", s(&pe)],
            &[],
        );
        assert_ok(&out, "windows pack");

        let sign = tpl(&[
            s(&signtool),
            "sign",
            "/fd",
            "sha256",
            "/sha1",
            "{env:LUNEPACK_TEST_THUMB}",
            "/s",
            "My",
            "{path}",
        ]);
        w.set_config(&format!(
            "{update}\n[codesign.windows]\nsign = {sign}\nsign_installer = {sign}\n"
        ));
        let setup = w.dir.path().join("Hello-Setup.exe");
        let at = (T0 + 3600).to_string();
        let out = w.run(
            &[
                "setup",
                s(&dir),
                "--version",
                "1.0.0",
                "--target",
                "windows-x86_64",
                "--out",
                s(&setup),
                "--at",
                &at,
            ],
            &[("LUNEPACK_TEST_THUMB", &cert.0)],
        );
        assert_ok(&out, "setup with real signtool");
        let bytes = fs::read(&setup).unwrap();
        assert!(
            lunepack_core::pe_is_signed(&bytes, bytes.len() as u64),
            "Setup.exe has no certificate table"
        );
        assert!(
            stdout(&out).contains("code-sign: Hello-Setup.exe"),
            "{}",
            stdout(&out)
        );
    }
}
