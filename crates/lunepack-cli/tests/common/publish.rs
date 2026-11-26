//! The fixture of the publish tests: signing material made at test time by the binary, a config
//! with `[publish]`, a `--store-dir` as `publish init` leaves it, and release directories packed
//! the way `fetch` and `pack` leave them. Every run's output is scanned for the made-up secrets.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::common::*;

pub const APP: &str = "org.example.hello";
pub const P: &str = "hello";

pub fn s(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

pub fn target() -> &'static str {
    if cfg!(windows) {
        "windows-x86_64"
    } else {
        "linux-x86_64"
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A text that differs per run and per call, for made-up credentials.
pub fn made_up(tag: &str, len: usize) -> String {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut out = String::from(tag);
    let mut x = seed ^ (std::process::id() as u128) << 64;
    while out.len() < len {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push(char::from(
            b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[(x >> 59) as usize % 32],
        ));
    }
    out
}

/// Every file under `dir` with its bytes, by relative path.
pub fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    pub fn walk(base: &Path, at: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(listing) = fs::read_dir(at) else {
            return;
        };
        for entry in listing {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub pack_config: PathBuf,
    pub release_signer: PathBuf,
    /// The root key file and its public key (hex).
    pub root: PathBuf,
    pub root_public: String,
    pub epoch: String,
    pub secrets: Vec<Vec<u8>>,
}

impl Fixture {
    /// Runs the binary with `SOURCE_DATE_EPOCH` set to the fixture's epoch (the pack and keys
    /// jobs; the publishing commands refuse it).
    pub fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut env = env.to_vec();
        env.push(("SOURCE_DATE_EPOCH", &self.epoch));
        self.run_plain(args, &env)
    }

    /// Runs the binary without `SOURCE_DATE_EPOCH`, as the publishing commands run.
    pub fn run_plain(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let out = run(args, env);
        let secrets: Vec<&[u8]> = self.secrets.iter().map(Vec::as_slice).collect();
        assert_no_secrets(&out, &secrets);
        out
    }

    pub fn generate(&mut self, name: &str) -> (PathBuf, String) {
        let base = self.dir.path().join(name);
        let out = self.run(&["keys", "gen", s(&base)], &[]);
        assert_ok(&out, "keys gen");
        let path = base.with_extension("key");
        self.secrets.push(fs::read(&path).unwrap());
        (path, field(&stdout(&out), "public:"))
    }

    /// Keys, the config `pack` runs under, `keys.json` and the publisher's state file, with every
    /// document issued at `epoch`.
    pub fn new(epoch: u64) -> (Fixture, PathBuf) {
        let mut f = Fixture {
            pack_config: PathBuf::new(),
            release_signer: PathBuf::new(),
            root: PathBuf::new(),
            root_public: String::new(),
            epoch: epoch.to_string(),
            secrets: Vec::new(),
            dir: tempfile::tempdir().unwrap(),
        };
        let (root, root_public) = f.generate("root");
        let (release, release_public) = f.generate("release");
        f.release_signer = release;
        f.root = root.clone();
        f.root_public = root_public.clone();
        f.pack_config = f.dir.path().join("lunepack.toml");
        let out = f.run(
            &[
                "--config",
                s(&f.pack_config),
                "init",
                "--app-id",
                APP,
                "--root-key",
                &root_public,
            ],
            &[],
        );
        assert_ok(&out, "init");
        let origin = f.dir.path().join("origin");
        fs::create_dir(&origin).unwrap();
        let root_sign = format!("file:{}", s(&root));
        let out = f.run(
            &[
                "--config",
                s(&f.pack_config),
                "keys",
                "set",
                "--release-dir",
                s(&origin),
                "--threshold",
                "1",
                "--release-key",
                &release_public,
                "--sign",
                &root_sign,
            ],
            &[],
        );
        assert_ok(&out, "keys set");
        (f, origin)
    }

    /// The app's config: the root, `[update]`, `[install]` and `[publish]` with `store`.
    pub fn config(&self, store: &str) -> PathBuf {
        self.config_keeping(store, 1)
    }

    /// Like [`Fixture::config`], keeping `keep` releases per channel.
    pub fn config_keeping(&self, store: &str, keep: u32) -> PathBuf {
        let mut text = fs::read_to_string(&self.pack_config).unwrap();
        text.push_str(&format!(
            "\n[update]\nfeed = \"https://updates.example.com/hello/\"\n\n[install]\nentry = \"bin/app\"\nname = \"Hello\"\n\n\
             [publish]\nprefix = \"{P}\"\n{store}\naccess_key_env = \"HELLO_STORE_KEY\"\nsecret_key_env = \"HELLO_STORE_SECRET\"\n\
             public_bucket = \"hello-public\"\nprivate_bucket = \"hello-private\"\nkeep = {keep}\n"
        ));
        let path = self
            .dir
            .path()
            .join(format!("app-{}-{keep}.toml", text.len()));
        fs::write(&path, text).unwrap();
        path
    }

    pub fn r2_config(&self) -> PathBuf {
        self.r2_config_keeping(1)
    }

    pub fn r2_config_keeping(&self, keep: u32) -> PathBuf {
        self.config_keeping(
            "store = \"r2\"\naccount_id_env = \"HELLO_R2_ACCOUNT_ID\"",
            keep,
        )
    }

    pub fn state(&self) -> Vec<u8> {
        fs::read(self.dir.path().join("lunepack-state.json")).unwrap()
    }

    /// A `--store-dir` with `keys.json` and the state file, as `publish init` leaves them.
    pub fn store_dir(&self, origin: &Path) -> PathBuf {
        let store = self.dir.path().join("store");
        let public = store.join("public").join(P);
        let private = store.join("private").join(P);
        fs::create_dir_all(&public).unwrap();
        fs::create_dir_all(&private).unwrap();
        fs::copy(origin.join("keys.json"), public.join("keys.json")).unwrap();
        fs::write(private.join("lunepack-state.json"), self.state()).unwrap();
        store
    }

    /// A release directory with the public bucket's documents (what `fetch` would write), with
    /// `version` packed into it.
    pub fn release_dir(
        &self,
        name: &str,
        public: &BTreeMap<String, Vec<u8>>,
        version: &str,
    ) -> PathBuf {
        let rd = self.dir.path().join(name);
        for (rel, bytes) in public {
            let path = rd.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        fs::create_dir_all(&rd).unwrap();
        let input = self.dir.path().join(format!("input-{version}"));
        fs::create_dir_all(input.join("bin")).unwrap();
        fs::write(
            input.join("bin/app"),
            format!("app {version}\n").repeat(300),
        )
        .unwrap();
        let sign = format!("file:{}", s(&self.release_signer));
        let out = self.run(
            &[
                "--config",
                s(&self.pack_config),
                "pack",
                "--input",
                s(&input),
                "--version",
                version,
                "--target",
                target(),
                "--release-dir",
                s(&rd),
                "--sign",
                &sign,
            ],
            &[],
        );
        assert_ok(&out, "pack");
        rd
    }

    pub fn push(
        &self,
        config: &Path,
        rd: &Path,
        version: &str,
        extra: &[&str],
        env: &[(&str, &str)],
    ) -> Output {
        let sign = format!("file:{}", s(&self.release_signer));
        let mut args = vec![
            "--config",
            s(config),
            "publish",
            "push",
            "--release-dir",
            s(rd),
            "--version",
            version,
            "--sign",
            &sign,
        ];
        args.extend_from_slice(extra);
        self.run_plain(&args, env)
    }
}

pub fn public_of(store: &Path) -> BTreeMap<String, Vec<u8>> {
    tree(&store.join("public").join(P))
}
