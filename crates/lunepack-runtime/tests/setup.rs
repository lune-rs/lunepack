//! A Linux setup file (M6 step 7) run for real: the built `lunepack-runtime` with a signed payload
//! and a trailer appended (FORMAT.md 14), in a temporary home.
//!
//! Own `main` (see Cargo.toml): this test binary is also the fake UI (first argument `--engine`).
//! The release packs a `lunepack-ui` wrapper script that notes the directory it runs from and its
//! mode, then starts this binary as the UI; the fake UI says hello with the engine's build id,
//! answers every `Ping`, and answers the prompts as `LUNEPACK_SETUP_FAKE_UI` says (`cancel`,
//! `proceed`, `launch`). Documents are signed with Ed25519 keys generated at test time (never
//! written into the repo); every frame is stored. Linux only.

#[cfg(target_os = "linux")]
fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--engine") => linux::fake_ui(),
        _ => linux::run_all(),
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("lunepack-runtime setup tests: Linux only, skipped");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Output, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use lunepack::{InstallMeta, RelPath, Target, TrustedRoot, UpdateConfig, Version};
    use lunepack_core::setup::{PART_ALIGN, SetupPart, SetupTrailer, TRAILER_SIZE};
    use lunepack_core::state::{InstallState, UserScope};
    use lunepack_core::ui::{self, ChoiceValue, EngineMsg, PromptKind, UiMsg};
    use lunepack_core::{
        AppId, Channel, CodecId, EncodedFrame, Encoder, PayloadKind, ReleaseLayout, Signer,
        pack_file,
    };
    use lunepack_crypto::{Ed25519Signer, Ed25519Verifier, Sha256Hasher, generate_key_file};
    use lunepack_fs::StdFs;
    use lunepack_testkit::{ChainFixture, FakeCodec, SUITE_APP_ID, SUITE_CHANNEL};

    const RUNTIME: &str = env!("CARGO_BIN_EXE_lunepack-runtime");
    const FAKE_VAR: &str = "LUNEPACK_SETUP_FAKE_UI";
    const OUT_VAR: &str = "LUNEPACK_SETUP_TEST_OUT";
    const V100: &str = "1.0.0";
    const BIN: &str = "lp-setup-test";
    const DAY: u64 = 86_400;
    const RUN_LIMIT: Duration = Duration::from_secs(120);

    #[cfg(target_arch = "aarch64")]
    const TARGET: Target = Target::LinuxAarch64;
    #[cfg(not(target_arch = "aarch64"))]
    const TARGET: Target = Target::LinuxX86_64;
    #[cfg(target_arch = "aarch64")]
    const OTHER_TARGET: Target = Target::LinuxX86_64;
    #[cfg(not(target_arch = "aarch64"))]
    const OTHER_TARGET: Target = Target::LinuxAarch64;

    const EXIT_OK: i32 = 0;
    const EXIT_USAGE: i32 = 2;
    const EXIT_CANCELLED: i32 = 5;
    const EXIT_VERIFY: i32 = 7;
    const EXIT_ALREADY_INSTALLED: i32 = 23;

    // ---- the fake UI ------------------------------------------------------------------------

    fn note(name: &str, text: &str) {
        if let Some(out) = std::env::var_os(OUT_VAR) {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(Path::new(&out).join(name))
                .expect("note");
            f.write_all(text.as_bytes()).expect("note");
        }
    }

    /// `lunepack-ui --engine`: hello, pongs, and the prompts answered as the case says.
    pub fn fake_ui() {
        let script = std::env::var(FAKE_VAR).unwrap_or_default();
        let mut input = std::io::stdin().lock();
        let mut out = std::io::stdout().lock();
        loop {
            let Ok(msg) = ui::read_frame::<_, EngineMsg>(&mut input) else {
                std::process::exit(0);
            };
            let reply = match msg {
                EngineMsg::Hello { build_id, app, .. } => {
                    note(
                        "ui-hello",
                        &format!("{} {}\n", app.name, app.publisher.unwrap_or_default()),
                    );
                    Some(UiMsg::Hello { build_id })
                }
                EngineMsg::Ping { n } => Some(UiMsg::Pong { n }),
                EngineMsg::Prompt { id, kind } => {
                    note("ui-prompts", &format!("{kind:?}\n"));
                    let value = match (kind, script.as_str()) {
                        (PromptKind::Welcome, "cancel") => ChoiceValue::Cancel,
                        (PromptKind::Welcome, _) => ChoiceValue::Proceed,
                        (PromptKind::Done, "launch") => ChoiceValue::Finish { launch: true },
                        (PromptKind::Done, _) => ChoiceValue::Finish { launch: false },
                        _ => ChoiceValue::Close,
                    };
                    Some(UiMsg::Choice { id, value })
                }
                _ => None,
            };
            if let Some(reply) = reply {
                let _ = ui::write_frame(&mut out, &reply);
            }
        }
    }

    // ---- the release and the setup file -----------------------------------------------------

    struct StoreOnly;

    impl Encoder for StoreOnly {
        fn encode(&self, codec: CodecId, _: &[u8]) -> Result<EncodedFrame, lunepack_core::Error> {
            Err(lunepack_core::error::CodecError::Unsupported(codec).into())
        }

        fn encode_memory(&self, _: CodecId, input_len: u64) -> u64 {
            input_len
        }
    }

    fn app_id() -> AppId {
        AppId::parse(SUITE_APP_ID).expect("app id")
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs()
    }

    /// How a case's setup file differs from a good one.
    #[derive(Default, Clone, Copy)]
    struct Twist {
        /// The config names a root other than the one the trailer and the key set use.
        config_root_other: bool,
    }

    struct Lab {
        _tmp: tempfile::TempDir,
        base: PathBuf,
        home: PathBuf,
        root: PathBuf,
        out: PathBuf,
        setup: PathBuf,
    }

    impl Lab {
        fn new(twist: Twist) -> Lab {
            let tmp = tempfile::Builder::new()
                .prefix("setup-")
                .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
                .expect("tmp");
            let base = std::fs::canonicalize(tmp.path()).expect("canonical");
            let home = base.join("home");
            let out = base.join("out");
            for d in [&home, &out] {
                std::fs::create_dir_all(d).expect("dirs");
            }
            let lab = Lab {
                _tmp: tmp,
                root: home.join(".local/share").join(SUITE_APP_ID),
                setup: base.join(format!("{SUITE_APP_ID}-{V100}-{}-setup", TARGET.as_str())),
                base,
                home,
                out,
            };
            let bytes = lab.build(twist);
            lab.write_setup(&bytes);
            lab
        }

        fn build(&self, twist: Twist) -> Vec<u8> {
            let keys = tempfile::tempdir().expect("keys");
            let signers: Vec<Ed25519Signer> = (0..3)
                .map(|i| {
                    let key = generate_key_file(&keys.path().join(format!("k{i}"))).expect("key");
                    Ed25519Signer::from_key_file(&key.path).expect("load key")
                })
                .collect();
            let sign = |seed: u8, message: &[u8]| {
                let signer = &signers[usize::from(seed)];
                (signer.public_key(), signer.sign(message).expect("sign"))
            };
            let mut small_order = [0u8; 32];
            small_order[0] = 1;
            let fx = ChainFixture {
                hasher: &Sha256Hasher,
                verifier: &Ed25519Verifier,
                sign: &sign,
                invalid_key: small_order,
            };
            let t = now();
            let root_of = |seed: u8| {
                TrustedRoot::from_parts(
                    app_id(),
                    1,
                    1,
                    &[fx.public_key(seed)],
                    &Sha256Hasher,
                    &Ed25519Verifier,
                )
                .expect("root")
            };
            let root = root_of(0);
            let config_root = if twist.config_root_other {
                root_of(2)
            } else {
                root.clone()
            };
            let meta = InstallMeta {
                entry: RelPath::parse("bin/app").expect("entry"),
                name: "Setup test".to_owned(),
                comment: None,
                icon: None,
                categories: Vec::new(),
                bin: Some(BIN.to_owned()),
                terminal: false,
                publisher: Some("Example Org".to_owned()),
            };
            let config = UpdateConfig::new(
                &config_root,
                Version::parse(V100).expect("version"),
                TARGET,
                "https://updates.example.invalid/",
                Channel::parse(SUITE_CHANNEL).expect("channel"),
                60,
                meta,
            )
            .expect("config")
            .to_bytes()
            .expect("config bytes");
            let runtime = std::fs::read(RUNTIME).expect("runtime");
            let me = std::env::current_exe().expect("test exe");
            let app = format!("#!/bin/sh\n: > \"${OUT_VAR}/app-ran\"\n");
            let ui = format!(
                "#!/bin/sh\nd=$(dirname \"$0\")\nprintf '%s\\n' \"$d\" >> \"${OUT_VAR}/ui-dir\"\n\
                 stat -c %a \"$d\" >> \"${OUT_VAR}/ui-mode\"\nexec '{}' --engine\n",
                me.display()
            );
            let files: Vec<(&str, Vec<u8>, bool)> = vec![
                ("bin/app", app.into_bytes(), true),
                ("bin/lunepack-runtime", runtime.clone(), true),
                ("bin/lunepack-ui", ui.into_bytes(), true),
                ("share/readme.txt", b"read me\n".repeat(20), false),
                ("lunepack-update.json", config, false),
            ];
            let mut layout = ReleaseLayout::new(app_id(), V100, TARGET).expect("layout");
            for (path, bytes, exec) in &files {
                let packed = pack_file(bytes, &StoreOnly, &FakeCodec::new(), &Sha256Hasher)
                    .expect("pack file");
                layout
                    .add_file(RelPath::parse(path).expect("path"), *exec, &packed)
                    .expect("add file");
            }
            let (doc, pack) = layout.finish(t - 3600, &Sha256Hasher).expect("finish");
            let manifest = fx.envelope(PayloadKind::Manifest, &doc.to_payload(), &[1]);
            let mut ks = fx.keyset_document(1, 1, None, 1, &[1]);
            ks.keys = vec![fx.release_key(1, t - DAY, t + 1000 * DAY)];
            let ks_bytes = fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);

            let mut bytes = runtime;
            let mut place = |part: &[u8]| {
                while !(bytes.len() as u64).is_multiple_of(PART_ALIGN) {
                    bytes.push(0);
                }
                let p = SetupPart {
                    offset: bytes.len() as u64,
                    length: part.len() as u64,
                };
                bytes.extend_from_slice(part);
                p
            };
            let keys_part = place(&ks_bytes);
            let manifest_part = place(&manifest);
            let pack_part = place(&pack);
            let trailer = SetupTrailer {
                root,
                version: Version::parse(V100).expect("version"),
                target: TARGET,
                keys: keys_part,
                manifest: manifest_part,
                pack: pack_part,
            };
            bytes.extend_from_slice(&trailer.encode().expect("trailer"));
            bytes
        }

        fn write_setup(&self, bytes: &[u8]) {
            let _ = std::fs::remove_file(&self.setup);
            std::fs::write(&self.setup, bytes).expect("setup");
            std::fs::set_permissions(&self.setup, std::fs::Permissions::from_mode(0o755))
                .expect("mode");
        }

        fn bytes(&self) -> Vec<u8> {
            std::fs::read(&self.setup).expect("setup")
        }

        fn trailer(&self) -> SetupTrailer {
            let bytes = self.bytes();
            SetupTrailer::parse(
                &bytes[bytes.len() - TRAILER_SIZE as usize..],
                bytes.len() as u64,
                &Sha256Hasher,
                &Ed25519Verifier,
            )
            .expect("trailer")
        }

        /// Replaces the trailer with `t`, the rest of the file kept.
        fn retrailer(&self, t: &SetupTrailer) {
            let mut bytes = self.bytes();
            bytes.truncate(bytes.len() - TRAILER_SIZE as usize);
            bytes.extend_from_slice(&t.encode().expect("trailer"));
            self.write_setup(&bytes);
        }

        fn app_cache(&self) -> PathBuf {
            self.home.join(".cache").join(SUITE_APP_ID)
        }

        fn run(&self, args: &[&str], ui: Option<&str>) -> Run {
            let mut cmd = Command::new(&self.setup);
            cmd.args(args)
                .env("HOME", &self.home)
                .env_remove("XDG_DATA_HOME")
                .env_remove("XDG_CACHE_HOME")
                .env_remove("LUNEPACK_HEALTH_TOKEN")
                .env_remove("LUNEPACK_NO_UI")
                .env_remove("WAYLAND_DISPLAY")
                .env(OUT_VAR, &self.out)
                .current_dir(&self.base)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            match ui {
                Some(script) => {
                    cmd.env("DISPLAY", ":lunepack-test").env(FAKE_VAR, script);
                }
                None => {
                    cmd.env_remove("DISPLAY");
                }
            }
            Run::of(finish(cmd.spawn().expect("setup")))
        }

        fn record(&self) -> Option<InstallState> {
            UserScope {
                dir: self.root.join("state"),
                app_id: app_id(),
            }
            .load(&StdFs::new(), &Sha256Hasher)
            .ok()
            .and_then(|l| l.record)
        }

        fn noted(&self, name: &str) -> String {
            std::fs::read_to_string(self.out.join(name)).unwrap_or_default()
        }

        fn ui_dirs_left(&self) -> Vec<String> {
            std::fs::read_dir(self.app_cache())
                .map(|it| {
                    it.map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                        .filter(|n| n.starts_with("setup-ui-"))
                        .collect()
                })
                .unwrap_or_default()
        }

        fn assert_installed(&self) {
            let rec = self.record().expect("record");
            assert_eq!(
                rec.current.expect("current").version.to_string(),
                V100,
                "current"
            );
            assert!(
                self.root
                    .join("versions")
                    .join(V100)
                    .join("bin/app")
                    .is_file()
            );
            assert!(
                self.home
                    .join(".local/share/applications")
                    .join(format!("{SUITE_APP_ID}.desktop"))
                    .is_file()
            );
        }

        fn assert_nothing_installed(&self) {
            assert!(
                std::fs::symlink_metadata(&self.root).is_err(),
                "the install root exists"
            );
            assert!(self.ui_dirs_left().is_empty(), "a UI directory was left");
        }
    }

    struct Run {
        code: i32,
        stdout: String,
        stderr: String,
    }

    impl std::fmt::Debug for Run {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "exit {} stdout {:?} stderr {:?}",
                self.code, self.stdout, self.stderr
            )
        }
    }

    impl Run {
        fn of(out: Output) -> Run {
            Run {
                code: out.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            }
        }

        fn assert_no_path(&self, lab: &Lab) {
            let base = lab.base.display().to_string();
            assert!(
                !self.stdout.contains(&base) && !self.stderr.contains(&base),
                "a path was printed: {self:?}"
            );
        }
    }

    fn finish(mut child: Child) -> Output {
        let start = Instant::now();
        while child.try_wait().expect("wait").is_none() {
            if start.elapsed() > RUN_LIMIT {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the setup ran too long");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        child.wait_with_output().expect("output")
    }

    fn wait_for(path: &Path) -> bool {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            if path.exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    // ---- cases ------------------------------------------------------------------------------

    fn silent_installs_with_no_ui() {
        let lab = Lab::new(Twist::default());
        let run = lab.run(&["--silent"], Some("proceed"));
        assert_eq!(run.code, EXIT_OK, "{run:?}");
        assert!(
            run.stdout.contains("\"command\":\"setup\"")
                && run.stdout.contains("\"outcome\":\"installed\""),
            "{run:?}"
        );
        lab.assert_installed();
        assert!(lab.noted("ui-dir").is_empty(), "a UI was started");
        assert!(lab.ui_dirs_left().is_empty());
        assert!(!lab.out.join("app-ran").exists());
        run.assert_no_path(&lab);
        // An existing install.
        let again = lab.run(&["--silent"], None);
        assert_eq!(again.code, EXIT_ALREADY_INSTALLED, "{again:?}");
    }

    fn no_display_installs_with_no_ui() {
        let lab = Lab::new(Twist::default());
        let run = lab.run(&[], None);
        assert_eq!(run.code, EXIT_OK, "{run:?}");
        lab.assert_installed();
        assert!(lab.noted("ui-dir").is_empty(), "a UI was started");
        assert!(lab.ui_dirs_left().is_empty());
    }

    fn a_ui_proceeds_and_launches_and_its_directory_goes() {
        let lab = Lab::new(Twist::default());
        let run = lab.run(&[], Some("launch"));
        assert_eq!(run.code, EXIT_OK, "{run:?}");
        lab.assert_installed();
        assert_eq!(lab.noted("ui-hello"), "Setup test Example Org\n");
        assert_eq!(lab.noted("ui-prompts"), "Welcome\nDone\n");
        let dir = lab.noted("ui-dir");
        let dir = Path::new(dir.trim());
        assert_eq!(dir.parent(), Some(lab.app_cache().as_path()), "{dir:?}");
        assert!(
            dir.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("setup-ui-"))
        );
        assert_eq!(lab.noted("ui-mode").trim(), "700");
        assert!(!dir.exists(), "the UI directory was left");
        assert!(
            wait_for(&lab.out.join("app-ran")),
            "the app was not launched"
        );
        run.assert_no_path(&lab);
    }

    fn a_ui_cancel_at_welcome_changes_nothing() {
        let lab = Lab::new(Twist::default());
        let run = lab.run(&[], Some("cancel"));
        assert_eq!(run.code, EXIT_CANCELLED, "{run:?}");
        assert_eq!(lab.noted("ui-prompts"), "Welcome\n");
        assert!(!lab.noted("ui-dir").is_empty(), "the UI did not run");
        lab.assert_nothing_installed();
        // The cache directory holds nothing of the run.
        let left: Vec<_> = std::fs::read_dir(lab.app_cache())
            .expect("app cache")
            .collect();
        assert!(left.is_empty(), "{} entries left", left.len());
    }

    fn stale_ui_directories_go_only_with_a_dead_owners_marker() {
        let lab = Lab::new(Twist::default());
        let cache = lab.app_cache();
        let make = |name: &str, marker: Option<String>| {
            let d = cache.join(name);
            std::fs::create_dir_all(&d).expect("dir");
            std::fs::write(d.join("payload"), b"x").expect("file");
            if let Some(m) = marker {
                std::fs::write(d.join("lunepack-setup-ui"), m).expect("marker");
            }
            d
        };
        let dead = make(
            "setup-ui-dead",
            Some(format!("lunepack setup ui {SUITE_APP_ID} 4194000 1\n")),
        );
        let unmarked = make("setup-ui-unmarked", None);
        let other_app = make(
            "setup-ui-other",
            Some("lunepack setup ui org.example.other 4194000 1\n".to_owned()),
        );
        let me = lunepack_os_linux::LinuxProcess::new()
            .process_id(std::process::id())
            .expect("me")
            .expect("me");
        let live = make(
            "setup-ui-live",
            Some(format!(
                "lunepack setup ui {SUITE_APP_ID} {} {}\n",
                me.pid, me.start_ticks
            )),
        );
        let not_ours = make("keep-me", None);
        let run = lab.run(&[], Some("proceed"));
        assert_eq!(run.code, EXIT_OK, "{run:?}");
        assert!(!dead.exists(), "a dead run's directory was kept");
        for kept in [&unmarked, &other_app, &live, &not_ours] {
            assert!(kept.join("payload").exists(), "{kept:?} was removed");
        }
    }

    fn a_tampered_byte_in_each_part_is_refused() {
        let lab = Lab::new(Twist::default());
        let good = lab.bytes();
        let t = lab.trailer();
        for (name, p) in [("keys", t.keys), ("manifest", t.manifest), ("pack", t.pack)] {
            let mut b = good.clone();
            b[(p.offset + p.length / 2) as usize] ^= 0x01;
            lab.write_setup(&b);
            let run = lab.run(&["--silent"], None);
            assert_eq!(run.code, EXIT_VERIFY, "{name}: {run:?}");
            lab.assert_nothing_installed();
        }
    }

    fn malformed_truncated_overlapping_and_mislabelled_files_are_refused() {
        let lab = Lab::new(Twist::default());
        let good = lab.bytes();
        let t = lab.trailer();
        // A payload byte short, the trailer kept: its parts no longer fit.
        let mut cut = good[..good.len() - TRAILER_SIZE as usize - 1].to_vec();
        cut.extend_from_slice(&good[good.len() - TRAILER_SIZE as usize..]);
        lab.write_setup(&cut);
        let run = lab.run(&[], None);
        assert_eq!(run.code, EXIT_VERIFY, "truncated: {run:?}");
        assert!(run.stdout.contains("\"kind\":\"verify\""), "{run:?}");
        lab.assert_nothing_installed();
        // The magic kept, a malformed byte before it: never an ordinary run.
        let mut bad = good.clone();
        let at = bad.len() - 20;
        bad[at] ^= 0xff;
        lab.write_setup(&bad);
        let run = lab.run(&["install"], None);
        assert_eq!(run.code, EXIT_VERIFY, "malformed: {run:?}");
        // Cut through the trailer: no magic, so the ordinary runtime, whose grammar refuses an
        // empty command line.
        lab.write_setup(&good[..good.len() - 1]);
        let run = lab.run(&[], None);
        assert_eq!(run.code, EXIT_USAGE, "no trailer: {run:?}");
        lab.assert_nothing_installed();

        lab.write_setup(&good);
        // Overlapping parts.
        let mut over = t.clone();
        over.manifest.offset = t.keys.offset + 8;
        lab.retrailer(&over);
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_VERIFY, "overlap: {run:?}");
        // Another target than the manifest's.
        let mut wrong = t.clone();
        wrong.target = OTHER_TARGET;
        lab.retrailer(&wrong);
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_VERIFY, "target: {run:?}");
        // Another version.
        let mut other = t.clone();
        other.version = Version::parse("1.0.0+b").expect("version");
        lab.retrailer(&other);
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_VERIFY, "version: {run:?}");
        lab.assert_nothing_installed();
    }

    fn a_trailer_root_other_than_the_configs_is_refused() {
        let lab = Lab::new(Twist {
            config_root_other: true,
        });
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_VERIFY, "{run:?}");
        lab.assert_nothing_installed();
    }

    fn arguments_other_than_silent_are_a_usage_error() {
        let lab = Lab::new(Twist::default());
        for args in [
            &["install"][..],
            &["--silent", "--silent"],
            &["--silent=1"],
            &["--no-ui"],
        ] {
            let run = lab.run(args, None);
            assert_eq!(run.code, EXIT_USAGE, "{args:?}: {run:?}");
            assert_eq!(run.stderr.trim(), "lunepack-runtime: usage error");
        }
        lab.assert_nothing_installed();
    }

    pub fn run_all() {
        let cases: &[(&str, fn())] = &[
            ("silent_installs_with_no_ui", silent_installs_with_no_ui),
            (
                "no_display_installs_with_no_ui",
                no_display_installs_with_no_ui,
            ),
            (
                "a_ui_proceeds_and_launches_and_its_directory_goes",
                a_ui_proceeds_and_launches_and_its_directory_goes,
            ),
            (
                "a_ui_cancel_at_welcome_changes_nothing",
                a_ui_cancel_at_welcome_changes_nothing,
            ),
            (
                "stale_ui_directories_go_only_with_a_dead_owners_marker",
                stale_ui_directories_go_only_with_a_dead_owners_marker,
            ),
            (
                "a_tampered_byte_in_each_part_is_refused",
                a_tampered_byte_in_each_part_is_refused,
            ),
            (
                "malformed_truncated_overlapping_and_mislabelled_files_are_refused",
                malformed_truncated_overlapping_and_mislabelled_files_are_refused,
            ),
            (
                "a_trailer_root_other_than_the_configs_is_refused",
                a_trailer_root_other_than_the_configs_is_refused,
            ),
            (
                "arguments_other_than_silent_are_a_usage_error",
                arguments_other_than_silent_are_a_usage_error,
            ),
        ];
        let filter: Vec<String> = std::env::args()
            .skip(1)
            .filter(|a| !a.starts_with('-'))
            .collect();
        let mut failed = 0;
        let mut ran = 0;
        for (name, case) in cases {
            if !filter.is_empty() && !filter.iter().any(|f| name.contains(f.as_str())) {
                continue;
            }
            ran += 1;
            let ok = std::panic::catch_unwind(case).is_ok();
            println!("test {name} ... {}", if ok { "ok" } else { "FAILED" });
            if !ok {
                failed += 1;
            }
        }
        println!(
            "test result: {}. {} passed; {failed} failed",
            if failed == 0 { "ok" } else { "FAILED" },
            ran - failed
        );
        if failed > 0 {
            std::process::exit(101);
        }
    }
}
