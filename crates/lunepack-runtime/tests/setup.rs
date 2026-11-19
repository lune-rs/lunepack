//! A setup file (M6 step 7, M7 step 11) run for real: the built `lunepack-runtime` with a signed
//! payload and a trailer appended (FORMAT.md 14).
//!
//! Own `main` (see Cargo.toml): this test binary is also the fake UI (first argument `--engine`)
//! and, on Windows, the app (when it runs as `app.exe`). On Linux the release packs a `lunepack-ui`
//! wrapper script that notes the directory it runs from and its mode, then starts this binary as
//! the UI; on Windows it packs a copy of this binary as `lunepack-ui.exe`, which notes its own
//! directory. The fake UI says hello with the engine's build id, answers every `Ping`, and answers
//! the prompts as `LUNEPACK_SETUP_FAKE_UI` says (`cancel`, `proceed`, `launch`). Documents are
//! signed with Ed25519 keys generated at test time (never written into the repo); every frame is
//! stored.
//!
//! Linux runs in a temporary home. Windows has no data-home redirect: each case installs into the
//! real per-user program files folder under a unique test app id and display name, and removes
//! what it created (the install folders, the Start-menu shortcut, the uninstall entry, its temp
//! directories) when it ends.
//!
//! macOS (M8 step 8) runs in a temporary home too. Its installer is an app, not one file: the
//! cases build `Install <name>.app` with the built runtime in `Contents/MacOS`, a `lunepack-ui`
//! wrapper script beside it (it starts this binary as the UI, as on Linux) and the payload file
//! (FORMAT.md 14 without the runtime part) in `Contents/Resources`; the "setup file" of a case is
//! that payload file. The installer UI that is the runtime's parent (`--ui-stdio`) is this binary
//! with the first argument `--fake-installer-ui`. The cases that are about a trailer appended to
//! the runtime, or about the UI read out of the pack, are skipped there by name.

mod common;

#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn main() {
    #[cfg(windows)]
    if std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.eq_ignore_ascii_case("app.exe")))
        == Some(true)
    {
        return cases::fake_app();
    }
    match std::env::args().nth(1).as_deref() {
        Some("--engine") => cases::fake_ui(),
        #[cfg(target_os = "macos")]
        Some("--fake-installer-ui") => cases::fake_installer_ui(),
        _ => cases::run_all(),
    }
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
fn main() {
    println!("lunepack-runtime setup tests: Linux, Windows and macOS only, skipped");
}

#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
mod cases {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Output, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use lunepack::{InstallMeta, RelPath, Target, TrustedRoot, UpdateConfig, Version};
    use lunepack_core::setup::{PART_ALIGN, SetupPart, SetupTrailer, TRAILER_SIZE};
    use lunepack_core::state::{InstallState, UserScope};
    use lunepack_core::ui::{self, ChoiceValue, EngineMsg, PromptKind, UiMsg};
    use lunepack_core::{
        AppId, Channel, CodecId, EncodedFrame, Encoder, LayoutScheme, PayloadKind, ReleaseLayout,
        Signer, UserLayout, pack_file,
    };
    use lunepack_crypto::{Ed25519Signer, Ed25519Verifier, Sha256Hasher, generate_key_file};
    use lunepack_fs::StdFs;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use lunepack_testkit::SUITE_APP_ID;

    use crate::common;
    use lunepack_testkit::{ChainFixture, FakeCodec, SUITE_CHANNEL};

    const RUNTIME: &str = env!("CARGO_BIN_EXE_lunepack-runtime");
    const FAKE_VAR: &str = "LUNEPACK_SETUP_FAKE_UI";
    const OUT_VAR: &str = "LUNEPACK_SETUP_TEST_OUT";
    const V100: &str = "1.0.0";
    const BIN: &str = "lp-setup-test";
    const DAY: u64 = 86_400;
    const RUN_LIMIT: Duration = Duration::from_secs(120);

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const TARGET: Target = Target::LinuxAarch64;
    #[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
    const TARGET: Target = Target::LinuxX86_64;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const OTHER_TARGET: Target = Target::LinuxX86_64;
    #[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
    const OTHER_TARGET: Target = Target::LinuxAarch64;
    #[cfg(all(windows, target_arch = "aarch64"))]
    const TARGET: Target = Target::WindowsAarch64;
    #[cfg(all(windows, not(target_arch = "aarch64")))]
    const TARGET: Target = Target::WindowsX86_64;
    #[cfg(all(windows, target_arch = "aarch64"))]
    const OTHER_TARGET: Target = Target::WindowsX86_64;
    #[cfg(all(windows, not(target_arch = "aarch64")))]
    const OTHER_TARGET: Target = Target::WindowsAarch64;
    #[cfg(target_os = "macos")]
    const TARGET: Target = common::TARGET;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    const OTHER_TARGET: Target = Target::MacosX86_64;
    #[cfg(all(target_os = "macos", not(target_arch = "aarch64")))]
    const OTHER_TARGET: Target = Target::MacosAarch64;

    /// The layout scheme and the tree's file names of this OS.
    #[cfg(target_os = "linux")]
    const SCHEME: LayoutScheme = LayoutScheme::XDG;
    #[cfg(windows)]
    const SCHEME: LayoutScheme = LayoutScheme::WINDOWS;
    #[cfg(target_os = "macos")]
    const SCHEME: LayoutScheme = common::SCHEME;
    #[cfg(target_os = "macos")]
    const APP_FILE: &str = common::APP_PATH;
    #[cfg(target_os = "macos")]
    const RUNTIME_FILE: &str = common::RUNTIME_PATH;
    /// The release's UI: the update window's helper app inside the bundle (M8-D6).
    #[cfg(target_os = "macos")]
    const UI_FILE: &str = lunepack_core::update_config::MACOS_HELPER_UI;
    /// The installer app's payload file and its runtime and UI (M8-D7), inside the installer.
    #[cfg(target_os = "macos")]
    const PAYLOAD_FILE: &str = lunepack_core::update_config::MACOS_INSTALLER_PAYLOAD;
    #[cfg(target_os = "macos")]
    const INSTALLER_RUNTIME: &str = "Contents/MacOS/lunepack-runtime";
    #[cfg(target_os = "macos")]
    const INSTALLER_UI: &str = "Contents/MacOS/lunepack-ui";
    /// Why a case does not run on macOS.
    #[cfg(target_os = "macos")]
    const NOT_ON_MACOS: &str = "the macOS installer is a bundle with a payload file (step 8)";
    /// The cases about a trailer appended to the runtime, or about the UI read out of the pack,
    /// with the reason they do not run on macOS. Each has a macOS counterpart below.
    #[cfg(target_os = "macos")]
    const SKIPPED_ON_MACOS: &[&str] = &[
        "a_ui_proceeds_and_launches_and_its_directory_goes",
        "malformed_truncated_overlapping_and_mislabelled_files_are_refused",
    ];
    #[cfg(target_os = "linux")]
    const APP_FILE: &str = "bin/app";
    #[cfg(windows)]
    const APP_FILE: &str = "bin/app.exe";
    #[cfg(target_os = "linux")]
    const RUNTIME_FILE: &str = "bin/lunepack-runtime";
    #[cfg(windows)]
    const RUNTIME_FILE: &str = "bin/lunepack-runtime.exe";
    #[cfg(target_os = "linux")]
    const UI_FILE: &str = "bin/lunepack-ui";
    #[cfg(windows)]
    const UI_FILE: &str = "bin/lunepack-ui.exe";
    /// The launcher stub the Windows integration places at `R` (any regular file will do here).
    #[cfg(windows)]
    const STUB_FILE: &str = "bin/lunepack-stub.exe";
    /// The Windows uninstall entries' parent key under `HKEY_CURRENT_USER`.
    #[cfg(windows)]
    const UNINSTALL_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall";
    /// The marker file of a runtime directory under the temp dir.
    #[cfg(windows)]
    const MARKER: &str = "lunepack-marker.json";

    const EXIT_OK: i32 = 0;
    const EXIT_USAGE: i32 = 2;
    const EXIT_CANCELLED: i32 = 5;
    const EXIT_VERIFY: i32 = 7;
    const EXIT_ALREADY_INSTALLED: i32 = 23;
    #[cfg(target_os = "macos")]
    const EXIT_UNSUPPORTED_LOCATION: i32 = 28;

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

    /// The app on Windows (this binary as `app.exe`): notes that it ran.
    #[cfg(windows)]
    pub fn fake_app() {
        note("app-ran", "");
    }

    /// `lunepack-ui --engine`: hello, pongs, and the prompts answered as the case says. On
    /// Windows it notes its own directory first (the Linux wrapper script does that there).
    pub fn fake_ui() {
        #[cfg(windows)]
        if let Some(dir) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
        {
            note("ui-dir", &format!("{}\n", dir.display()));
        }
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

    /// A tag nobody else uses: 8 hex digits from the OS randomness (short: `<name> (<app id>)` must stay within 64 units).
    #[cfg(windows)]
    fn unique() -> String {
        use lunepack::Rng as _;
        let mut b = [0u8; 4];
        lunepack_crypto::OsRng.fill(&mut b).expect("random");
        b.iter().map(|x| format!("{x:02x}")).collect()
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
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        home: PathBuf,
        /// The data home: `$HOME/.local/share` (Linux), the per-user program files folder
        /// (Windows, canonical), `$HOME/Library/Application Support` (macOS).
        #[cfg_attr(target_os = "linux", allow(dead_code))]
        data_home: PathBuf,
        /// macOS: the installer app, `Install <name>.app`.
        #[cfg(target_os = "macos")]
        installer: PathBuf,
        root: PathBuf,
        out: PathBuf,
        setup: PathBuf,
        app_id: String,
        name: String,
        signers: Vec<Ed25519Signer>,
        /// Windows: the display names a case used (their shortcuts and folders are removed).
        #[cfg(windows)]
        names: std::cell::RefCell<Vec<String>>,
        /// Windows: other paths a case made outside its temporary directory (removed at the end,
        /// also after a failure).
        #[cfg(windows)]
        extra: std::cell::RefCell<Vec<PathBuf>>,
    }

    impl Lab {
        fn new(twist: Twist) -> Lab {
            #[cfg(not(target_os = "macos"))]
            let (tmp, base) = {
                let tmp = tempfile::Builder::new()
                    .prefix("setup-")
                    .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
                    .expect("tmp");
                let base = std::fs::canonicalize(tmp.path()).expect("canonical");
                (tmp, base)
            };
            // A home with `~/Applications` and the data home, under the system's temporary
            // directory (`common::scratch`).
            #[cfg(target_os = "macos")]
            let common::Home {
                tmp,
                base,
                home,
                data,
                root,
            } = common::Home::new("setup-", SUITE_APP_ID, None, false);
            let out = base.join("out");
            std::fs::create_dir_all(&out).expect("dirs");
            let keys = tempfile::tempdir().expect("keys");
            let signers: Vec<Ed25519Signer> = (0..3)
                .map(|i| {
                    let key = generate_key_file(&keys.path().join(format!("k{i}"))).expect("key");
                    Ed25519Signer::from_key_file(&key.path).expect("load key")
                })
                .collect();
            #[cfg(target_os = "linux")]
            let lab = {
                let home = base.join("home");
                std::fs::create_dir_all(&home).expect("home");
                let data_home = home.join(".local/share");
                Lab {
                    root: data_home.join(SUITE_APP_ID),
                    setup: base.join(format!("{SUITE_APP_ID}-{V100}-{}-setup", TARGET.as_str())),
                    _tmp: tmp,
                    base,
                    home,
                    data_home,
                    out,
                    app_id: SUITE_APP_ID.to_owned(),
                    name: "Setup test".to_owned(),
                    signers,
                }
            };
            #[cfg(windows)]
            let lab = {
                let tag = unique();
                let dir = lunepack_os_windows::user_program_files().expect("program files");
                std::fs::create_dir_all(&dir).expect("program files");
                let data_home = std::fs::canonicalize(&dir).expect("canonical");
                let app_id = format!("org.lunepack-test.s{tag}");
                let name = format!("LP Setup {tag}");
                Lab {
                    root: data_home.join(&name),
                    setup: base.join(format!("{app_id}-{V100}-{}-setup.exe", TARGET.as_str())),
                    _tmp: tmp,
                    base,
                    data_home,
                    out,
                    names: std::cell::RefCell::new(Vec::new()),
                    extra: std::cell::RefCell::new(Vec::new()),
                    app_id,
                    name,
                    signers,
                }
            };
            #[cfg(target_os = "macos")]
            let lab = {
                let installer = base.join("Install Setup test.app");
                Lab {
                    setup: common::join_rel(&installer, PAYLOAD_FILE),
                    installer,
                    _tmp: tmp,
                    base,
                    home,
                    data_home: data,
                    root,
                    out,
                    app_id: SUITE_APP_ID.to_owned(),
                    name: "Setup test".to_owned(),
                    signers,
                }
            };
            let name = lab.name.clone();
            let bytes = lab.build(twist, &name);
            #[cfg(target_os = "macos")]
            lab.make_installer();
            lab.write_setup(&bytes);
            lab
        }

        /// macOS: the installer app around the payload file: the built runtime and, beside it,
        /// a `lunepack-ui` that notes its directory and starts this binary as the UI.
        #[cfg(target_os = "macos")]
        fn make_installer(&self) {
            let runtime = common::join_rel(&self.installer, INSTALLER_RUNTIME);
            common::place(Path::new(RUNTIME), &runtime);
            let me = std::env::current_exe().expect("test exe");
            let ui = format!(
                "#!/bin/sh\nd=$(dirname \"$0\")\nprintf '%s\\n' \"$d\" >> \"${OUT_VAR}/ui-dir\"\n\
                 exec '{}' --engine\n",
                me.display()
            );
            let ui_path = common::join_rel(&self.installer, INSTALLER_UI);
            std::fs::write(&ui_path, ui).expect("ui");
            std::fs::set_permissions(&ui_path, std::fs::Permissions::from_mode(0o755))
                .expect("mode");
            std::fs::create_dir_all(self.setup.parent().expect("resources")).expect("resources");
        }

        /// macOS: the installer's runtime.
        #[cfg(target_os = "macos")]
        fn installer_runtime(&self) -> PathBuf {
            common::join_rel(&self.installer, INSTALLER_RUNTIME)
        }

        /// macOS: the live bundle a first install makes, `~/Applications/<name>.app`.
        #[cfg(target_os = "macos")]
        fn bundle(&self) -> PathBuf {
            self.home
                .join("Applications")
                .join(format!("{}.app", self.name))
        }

        fn app_id(&self) -> AppId {
            AppId::parse(&self.app_id).expect("app id")
        }

        fn build(&self, twist: Twist, name: &str) -> Vec<u8> {
            #[cfg(windows)]
            self.names.borrow_mut().push(name.to_owned());
            let signers = &self.signers;
            let app_id = || self.app_id();
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
                entry: RelPath::parse(APP_FILE).expect("entry"),
                name: name.to_owned(),
                comment: None,
                icon: None,
                categories: Vec::new(),
                bin: Some(BIN.to_owned()),
                terminal: false,
                publisher: Some("Example Org".to_owned()),
                file_types: Vec::new(),
                url_schemes: Vec::new(),
                // macOS: the LaunchAgent is the integration a rerun can repair (M8-D12).
                autostart: cfg!(target_os = "macos"),
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
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let (app, ui) = (
                format!("#!/bin/sh\n: > \"${OUT_VAR}/app-ran\"\n").into_bytes(),
                format!(
                    "#!/bin/sh\nd=$(dirname \"$0\")\nprintf '%s\\n' \"$d\" >> \"${OUT_VAR}/ui-dir\"\n\
                     stat -c %a \"$d\" >> \"${OUT_VAR}/ui-mode\"\nexec '{}' --engine\n",
                    me.display()
                )
                .into_bytes(),
            );
            // This binary is the app (by its name) and the UI (by `--engine`).
            #[cfg(windows)]
            let (app, ui) = {
                let bytes = std::fs::read(&me).expect("test exe");
                (bytes.clone(), bytes)
            };
            #[allow(unused_mut)]
            let mut files: Vec<(&str, Vec<u8>, bool)> = vec![
                (APP_FILE, app, true),
                (RUNTIME_FILE, runtime.clone(), true),
                (UI_FILE, ui, true),
                (common::README_PATH, b"read me\n".repeat(20), false),
                (common::CONFIG_PATH, config, false),
            ];
            #[cfg(windows)]
            files.push((STUB_FILE, b"lunepack test stub".to_vec(), true));
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
            ks.app_id = app_id();
            ks.keys = vec![fx.release_key(1, t - DAY, t + 1000 * DAY)];
            let ks_bytes = fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);

            // The setup file is the runtime with the payload after it; the macOS payload file is
            // the payload alone, its parts from offset 0.
            #[cfg(not(target_os = "macos"))]
            let mut bytes = runtime;
            #[cfg(target_os = "macos")]
            let mut bytes = {
                drop(runtime);
                Vec::new()
            };
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
            // As `lunepack setup` writes it: the trailer starts 8-aligned (F5).
            while !(bytes.len() as u64).is_multiple_of(PART_ALIGN) {
                bytes.push(0);
            }
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
            #[cfg(unix)]
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

        #[cfg(target_os = "linux")]
        fn app_cache(&self) -> PathBuf {
            self.home.join(".cache").join(SUITE_APP_ID)
        }

        /// Runs the setup file with `args`; `ui` is the fake UI's script, `None` for no UI at
        /// all (no display on Linux, `LUNEPACK_NO_UI` on Windows).
        fn run(&self, args: &[&str], ui: Option<&str>) -> Run {
            #[cfg(target_os = "macos")]
            return self.run_program(&self.installer_runtime(), args, ui);
            #[cfg(not(target_os = "macos"))]
            self.run_program(&self.setup, args, ui)
        }

        fn run_program(&self, program: &Path, args: &[&str], ui: Option<&str>) -> Run {
            let mut cmd = Command::new(program);
            cmd.args(args)
                .env_remove("LUNEPACK_HEALTH_TOKEN")
                .env_remove("LUNEPACK_NO_UI")
                .env(OUT_VAR, &self.out)
                .current_dir(&self.base)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            #[cfg(target_os = "linux")]
            {
                cmd.env("HOME", &self.home)
                    .env_remove("XDG_DATA_HOME")
                    .env_remove("XDG_CACHE_HOME")
                    .env_remove("WAYLAND_DISPLAY");
                match ui {
                    Some(script) => {
                        cmd.env("DISPLAY", ":lunepack-test").env(FAKE_VAR, script);
                    }
                    None => {
                        cmd.env_remove("DISPLAY");
                    }
                }
            }
            #[cfg(target_os = "macos")]
            cmd.env("HOME", &self.home);
            // macOS: `LUNEPACK_NO_UI` also keeps a native notice off the screen.
            #[cfg(any(windows, target_os = "macos"))]
            match ui {
                Some(script) => {
                    cmd.env(FAKE_VAR, script);
                }
                None => {
                    cmd.env("LUNEPACK_NO_UI", "1");
                }
            }
            Run::of(finish(cmd.spawn().expect("setup")))
        }

        #[cfg(windows)]
        fn layout(&self) -> UserLayout {
            UserLayout::from_root(self.root.clone(), SCHEME)
        }

        fn record_at(&self, root: &Path) -> Option<InstallState> {
            UserScope {
                dir: UserLayout::from_root(root.to_path_buf(), SCHEME).state_dir(),
                app_id: self.app_id(),
            }
            .load(&StdFs::new(), &Sha256Hasher)
            .ok()
            .and_then(|l| l.record)
        }

        fn noted(&self, name: &str) -> String {
            std::fs::read_to_string(self.out.join(name)).unwrap_or_default()
        }

        #[cfg(target_os = "linux")]
        fn ui_dirs_left(&self) -> Vec<String> {
            std::fs::read_dir(self.app_cache())
                .map(|it| {
                    it.map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                        .filter(|n| n.starts_with("setup-ui-"))
                        .collect()
                })
                .unwrap_or_default()
        }

        /// macOS: the installer reads no UI out of the pack, so it makes no UI directory.
        #[cfg(target_os = "macos")]
        fn ui_dirs_left(&self) -> Vec<String> {
            Vec::new()
        }

        /// Windows: this case's UI directories under the temp dir (their marker names its app).
        #[cfg(windows)]
        fn ui_dirs_left(&self) -> Vec<String> {
            let mine = format!("{{\"app_id\":\"{}\",", self.app_id);
            std::fs::read_dir(temp_home())
                .map(|it| {
                    it.filter_map(|e| {
                        let e = e.ok()?;
                        let name = e.file_name().to_string_lossy().into_owned();
                        let marker = std::fs::read_to_string(e.path().join(MARKER)).ok()?;
                        (name.starts_with("lunepack-setup-ui-") && marker.starts_with(&mine))
                            .then_some(name)
                    })
                    .collect()
                })
                .unwrap_or_default()
        }

        fn assert_installed(&self) {
            self.assert_installed_at(&self.root, &self.name);
        }

        fn assert_installed_at(&self, root: &Path, name: &str) {
            let rec = self.record_at(root).expect("record");
            assert_eq!(
                rec.current.expect("current").version.to_string(),
                V100,
                "current"
            );
            let layout = UserLayout::from_root(root.to_path_buf(), SCHEME);
            #[cfg(not(target_os = "macos"))]
            let tree = layout.version_dir(&Version::parse(V100).expect("version"));
            // macOS: the live bundle in `~/Applications`, named after the app, holds the version.
            #[cfg(target_os = "macos")]
            let tree = {
                let bundle = self.home.join("Applications").join(format!("{name}.app"));
                assert_eq!(common::bundle_of(&layout), bundle, "the pointer");
                common::assert_live(&layout, V100);
                bundle
            };
            assert!(common::join_rel(&tree, APP_FILE).is_file(), "the entry");
            #[cfg(target_os = "linux")]
            {
                let _ = name;
                assert!(
                    self.home
                        .join(".local/share/applications")
                        .join(format!("{SUITE_APP_ID}.desktop"))
                        .is_file()
                );
            }
            #[cfg(target_os = "macos")]
            assert!(self.launch_agent().is_file(), "the LaunchAgent");
            #[cfg(windows)]
            {
                assert!(root.join("app.exe").is_file(), "the stub");
                assert!(shortcut(name).is_file(), "the Start-menu shortcut");
                assert!(reg_key_exists(&self.app_id), "the uninstall entry");
            }
        }

        fn assert_nothing_installed(&self) {
            assert!(
                std::fs::symlink_metadata(&self.root).is_err(),
                "the install root exists"
            );
            assert!(self.ui_dirs_left().is_empty(), "a UI directory was left");
            #[cfg(target_os = "macos")]
            assert_eq!(
                visible(&self.home.join("Applications")),
                Vec::<String>::new(),
                "something was placed in the apps folder"
            );
        }

        /// macOS: the autostart LaunchAgent of the app (M8-D12).
        #[cfg(target_os = "macos")]
        fn launch_agent(&self) -> PathBuf {
            self.home
                .join("Library/LaunchAgents")
                .join(format!("{}.lunepack.plist", self.app_id))
        }
    }

    /// The names in `dir` that do not start with a dot (a volume's own `.fseventsd` and the like
    /// are not ours), sorted; none when `dir` cannot be read.
    #[cfg(target_os = "macos")]
    fn visible(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|it| {
                it.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| !n.starts_with('.'))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// Windows: everything a case may have made outside its temporary directory goes: the install
    /// folders of every display name it used (and their `<name> (<app id>)` fallbacks), their
    /// Start-menu shortcuts, the uninstall entry, and its UI directories under the temp dir. A
    /// launched app may still be running from the install for a moment: removal is retried.
    #[cfg(windows)]
    impl Drop for Lab {
        fn drop(&mut self) {
            let names = self.names.borrow().clone();
            for name in &names {
                for dir in [
                    self.data_home.join(name),
                    self.data_home.join(format!("{name} ({})", self.app_id)),
                ] {
                    // Only a folder this case's app owns (or an empty one) is removed.
                    let ours = self.record_at(&dir).is_some()
                        || std::fs::read_dir(&dir).is_ok_and(|mut d| d.next().is_none());
                    if ours {
                        remove_retrying(&dir);
                    }
                }
                let _ = std::fs::remove_file(shortcut(name));
            }
            delete_reg_key(&self.app_id);
            for path in self.extra.borrow().iter() {
                remove_retrying(path);
            }
            for dir in self.ui_dirs_left() {
                remove_retrying(&temp_home().join(dir));
            }
        }
    }

    /// Windows: removes the directory `dir`, retrying for a few seconds while a process still
    /// holds an image in it.
    #[cfg(windows)]
    fn remove_retrying(dir: &Path) {
        let start = Instant::now();
        while std::fs::symlink_metadata(dir).is_ok() && start.elapsed() < Duration::from_secs(15) {
            if std::fs::remove_dir_all(dir).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Windows: the user's temp dir, canonical (where the runtime makes its directories).
    #[cfg(windows)]
    fn temp_home() -> PathBuf {
        std::fs::canonicalize(std::env::temp_dir()).expect("temp dir")
    }

    /// Windows: the Start-menu shortcut of display name `name`.
    #[cfg(windows)]
    fn shortcut(name: &str) -> PathBuf {
        lunepack_os_windows::start_menu_programs()
            .expect("programs")
            .join(format!("{name}.lnk"))
    }

    /// Windows: whether the uninstall entry of `app_id` exists.
    #[cfg(windows)]
    fn reg_key_exists(app_id: &str) -> bool {
        Command::new("reg")
            .args(["query", &format!("{UNINSTALL_KEY}\\{app_id}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Windows: removes the uninstall entry of `app_id` (a test app id only).
    #[cfg(windows)]
    fn delete_reg_key(app_id: &str) {
        assert!(
            app_id.starts_with("org.lunepack-test."),
            "not a test app id"
        );
        let _ = Command::new("reg")
            .args(["delete", &format!("{UNINSTALL_KEY}\\{app_id}"), "/f"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    /// A path's text without Windows' `\\?\` prefix, lower case on Windows (for comparisons).
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    fn plain(path: &Path) -> String {
        let text = path.to_string_lossy().into_owned();
        let text = text
            .strip_prefix(r"\\?\")
            .map(str::to_owned)
            .unwrap_or(text);
        if cfg!(windows) {
            text.to_lowercase()
        } else {
            text
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
            let texts = [plain(&lab.base), plain(&lab.root), plain(&lab.data_home)];
            let (out, err) = if cfg!(windows) {
                (self.stdout.to_lowercase(), self.stderr.to_lowercase())
            } else {
                (self.stdout.clone(), self.stderr.clone())
            };
            for text in texts {
                assert!(
                    !out.contains(&text) && !err.contains(&text),
                    "a path was printed: {self:?}"
                );
            }
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
        assert_eq!(lab.noted("ui-hello"), format!("{} Example Org\n", lab.name));
        assert_eq!(lab.noted("ui-prompts"), "Welcome\nDone\n");
        let dir = lab.noted("ui-dir");
        let dir = Path::new(dir.trim());
        #[cfg(target_os = "linux")]
        {
            assert_eq!(dir.parent(), Some(lab.app_cache().as_path()), "{dir:?}");
            assert!(
                dir.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("setup-ui-"))
            );
            assert_eq!(lab.noted("ui-mode").trim(), "700");
        }
        // M7-D13: directly under the temp dir, named `lunepack-setup-ui-<16 hex>`.
        #[cfg(windows)]
        {
            assert_eq!(
                dir.parent().map(plain),
                Some(plain(&temp_home())),
                "{dir:?}"
            );
            let name = dir
                .file_name()
                .expect("name")
                .to_string_lossy()
                .into_owned();
            let hex = name.strip_prefix("lunepack-setup-ui-").expect("prefix");
            assert!(
                hex.len() == 16
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "{name}"
            );
        }
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
        #[cfg(target_os = "linux")]
        {
            let left: Vec<_> = std::fs::read_dir(lab.app_cache())
                .expect("app cache")
                .collect();
            assert!(left.is_empty(), "{} entries left", left.len());
        }
    }

    #[cfg(target_os = "linux")]
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
        // A payload byte short (the pack's last, and the alignment padding after it), the trailer
        // kept: its parts no longer fit.
        let mut cut = good[..(t.pack.offset + t.pack.length - 1) as usize].to_vec();
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
            &["/s"],
            &["/S", "/S"],
            &["/S", "--silent"],
            #[cfg(target_os = "macos")]
            &["--ui-stdio", "--silent"],
            #[cfg(target_os = "macos")]
            &["--silent", "--ui-stdio"],
            #[cfg(target_os = "macos")]
            &["--ui-stdio", "--ui-stdio"],
            #[cfg(target_os = "macos")]
            &["--ui-stdio=1"],
        ] {
            let run = lab.run(args, None);
            assert_eq!(run.code, EXIT_USAGE, "{args:?}: {run:?}");
            assert_eq!(run.stderr.trim(), "lunepack-runtime: usage error");
        }
        lab.assert_nothing_installed();
    }

    // ---- Windows cases (M7 step 11) ------------------------------------------------------------

    /// `/S` is `--silent`: no UI process starts (the fake UI never notes its directory).
    #[cfg(windows)]
    fn slash_s_installs_silently_with_no_ui() {
        let lab = Lab::new(Twist::default());
        let run = lab.run(&["/S"], Some("proceed"));
        assert_eq!(run.code, EXIT_OK, "{run:?}");
        lab.assert_installed();
        assert!(lab.noted("ui-dir").is_empty(), "a UI was started");
        assert!(lab.ui_dirs_left().is_empty());
        run.assert_no_path(&lab);
    }

    /// F14: a malformed setup file run with arguments it does not accept, as a script passing
    /// another installer's flag would, exits 7 at once with `LUNEPACK_NO_UI` unset: no modal
    /// notice waits for a click (it would hang this run until `RUN_LIMIT`).
    #[cfg(windows)]
    fn a_malformed_setup_with_unknown_arguments_exits_without_a_notice() {
        let lab = Lab::new(Twist::default());
        let mut bad = lab.bytes();
        let at = bad.len() - 20;
        bad[at] ^= 0xff;
        lab.write_setup(&bad);
        for args in [&["--no-such-option"][..], &["/quiet"], &["/S", "/S"]] {
            let start = Instant::now();
            let run = lab.run(args, Some("proceed"));
            assert_eq!(run.code, EXIT_VERIFY, "{args:?}: {run:?}");
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "{args:?}: the run waited"
            );
            assert!(lab.noted("ui-dir").is_empty(), "a UI was started");
        }
        lab.assert_nothing_installed();
    }

    /// M7-D5: the installed runtime's `uninstall /S` hands off to its temp copy and exits 0; the
    /// copy removes the install, the stub, the Start-menu shortcut and the uninstall entry. `/S`
    /// is `--silent`: the UI beside the runtime (this binary) never starts.
    #[cfg(windows)]
    fn an_install_uninstalls_silently_through_the_hand_off() {
        let lab = Lab::new(Twist::default());
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_OK, "{run:?}");
        lab.assert_installed();
        let runtime = lab
            .layout()
            .version_dir(&Version::parse(V100).expect("version"))
            .join(RUNTIME_FILE);
        let run = lab.run_program(&runtime, &["uninstall", "/S"], Some("proceed"));
        assert_eq!(run.code, EXIT_OK, "{run:?}");
        assert!(run.stdout.is_empty(), "{run:?}");
        let start = Instant::now();
        while lab.root.exists() && start.elapsed() < RUN_LIMIT {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!lab.root.exists(), "the install root is still there");
        assert!(!shortcut(&lab.name).exists(), "the shortcut is still there");
        assert!(
            !reg_key_exists(&lab.app_id),
            "the uninstall entry is still there"
        );
        assert!(lab.noted("ui-dir").is_empty(), "a UI was started");
    }

    /// The offset of the security directory entry of the PE image `bytes`.
    #[cfg(windows)]
    fn security_entry(bytes: &[u8]) -> usize {
        let lfanew = u32::from_le_bytes(bytes[0x3c..0x40].try_into().expect("e_lfanew")) as usize;
        let opt = lfanew + 4 + 20;
        let magic = u16::from_le_bytes(bytes[opt..opt + 2].try_into().expect("magic"));
        let dirs = opt + if magic == 0x10b { 96 } else { 112 };
        dirs + 4 * 8
    }

    /// Points the security directory of `bytes` at `offset`, `size`.
    #[cfg(windows)]
    fn set_security(bytes: &mut [u8], offset: u64, size: u64) {
        let at = security_entry(bytes);
        bytes[at..at + 4].copy_from_slice(&(offset as u32).to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&(size as u32).to_le_bytes());
    }

    #[cfg(windows)]
    fn pad8(bytes: &mut Vec<u8>) {
        while !bytes.len().is_multiple_of(8) {
            bytes.push(0);
        }
    }

    /// A stand-in certificate table of `len` bytes (a `WIN_CERTIFICATE` header and filler).
    #[cfg(windows)]
    fn cert_table(len: usize) -> Vec<u8> {
        let mut t = vec![0u8; len];
        t[0..4].copy_from_slice(&(len as u32).to_le_bytes());
        t[4..6].copy_from_slice(&0x0200u16.to_le_bytes());
        t[6..8].copy_from_slice(&2u16.to_le_bytes());
        for (i, b) in t.iter_mut().enumerate().skip(8) {
            *b = (i % 251) as u8;
        }
        t
    }

    /// M7-D11 as amended (P4): a runtime with no trailer magic runs its command line whatever its
    /// certificate table looks like: well-formed at the end, not at the end, misaligned.
    #[cfg(windows)]
    fn an_ordinary_runtime_with_any_certificate_table_runs_normally() {
        let lab = Lab::new(Twist::default());
        let runtime = std::fs::read(RUNTIME).expect("runtime");
        let run_copy = |name: &str, bytes: &[u8]| {
            let path = lab.base.join(name);
            std::fs::write(&path, bytes).expect("copy");
            lab.run_program(&path, &["check", "--json"], None)
        };
        let control = run_copy("plain.exe", &runtime);
        assert_ne!(control.code, EXIT_VERIFY, "{control:?}");
        // Well-formed: padded to 8, the table at the end.
        let mut signed = runtime.clone();
        pad8(&mut signed);
        let at = signed.len() as u64;
        set_security(&mut signed, at, 1024);
        signed.extend(cert_table(1024));
        // Not at the end: bytes after the table.
        let mut not_at_end = signed.clone();
        not_at_end.extend_from_slice(&[0u8; 16]);
        // Misaligned: the table one byte after an 8-aligned end.
        let mut odd = runtime.clone();
        pad8(&mut odd);
        odd.push(0);
        let at = odd.len() as u64;
        set_security(&mut odd, at, 1024);
        odd.extend(cert_table(1024));
        for (name, bytes) in [
            ("signed.exe", &signed),
            ("not-at-end.exe", &not_at_end),
            ("odd.exe", &odd),
        ] {
            let run = run_copy(name, bytes);
            assert_eq!(
                (run.code, &run.stdout),
                (control.code, &control.stdout),
                "{name}: {run:?}"
            );
        }
    }

    /// The setup file signed the way signtool lays it out: the trailer ends 8-aligned, the
    /// certificate table follows it to the end of the file.
    #[cfg(windows)]
    fn signed_setup(lab: &Lab) -> Vec<u8> {
        let mut bytes = lab.bytes();
        // The writer ends the file on a multiple of 8, so signtool's padding before the table is
        // none (F5); nothing is inserted before the trailer here.
        assert!(
            bytes.len().is_multiple_of(8),
            "the setup writer must end the file 8-aligned"
        );
        let at = bytes.len() as u64;
        set_security(&mut bytes, at, 1024);
        bytes.extend(cert_table(1024));
        bytes
    }

    /// A setup file with its trailer before a certificate table installs; one byte appended
    /// after the table is refused (`verify`, exit 7) with nothing installed.
    #[cfg(windows)]
    fn a_signed_setup_installs_and_a_byte_after_its_table_is_refused() {
        let lab = Lab::new(Twist::default());
        let signed = signed_setup(&lab);
        let mut extra = signed.clone();
        extra.push(0);
        lab.write_setup(&extra);
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_VERIFY, "byte after the table: {run:?}");
        assert!(run.stdout.contains("\"kind\":\"verify\""), "{run:?}");
        lab.assert_nothing_installed();
        lab.write_setup(&signed);
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_OK, "signed: {run:?}");
        lab.assert_installed();
        run.assert_no_path(&lab);
    }

    /// M7-D17 (a): a non-empty folder that is not this app's install, named like the app, is left
    /// byte-identical; the install goes to `<name> (<app id>)`.
    #[cfg(windows)]
    fn a_foreign_folder_with_the_apps_name_is_left_alone() {
        let lab = Lab::new(Twist::default());
        let foreign = lab.root.clone();
        std::fs::create_dir(&foreign).expect("foreign folder");
        lab.extra.borrow_mut().push(foreign.clone());
        std::fs::write(foreign.join("notes.txt"), b"someone else's file\n").expect("file");
        std::fs::create_dir(foreign.join("sub")).expect("sub");
        let before = listing(&foreign);
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_OK, "{run:?}");
        let fallback = lab.data_home.join(format!("{} ({})", lab.name, lab.app_id));
        lab.assert_installed_at(&fallback, &lab.name);
        assert_eq!(listing(&foreign), before, "the foreign folder changed");
        run.assert_no_path(&lab);
    }

    /// Every file under `dir` with its bytes, sorted (directories as names).
    #[cfg(windows)]
    fn listing(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type().expect("type").is_dir() {
                out.push((format!("{name}/"), Vec::new()));
                for (sub, bytes) in listing(&entry.path()) {
                    out.push((format!("{name}/{sub}"), bytes));
                }
            } else {
                out.push((name, std::fs::read(entry.path()).expect("read")));
            }
        }
        out.sort();
        out
    }

    /// M7-D16: a setup of the same app id under another display name finds the existing install
    /// by its record and makes no folder of the new name (the install is already there: exit 23).
    #[cfg(windows)]
    fn a_rerun_under_another_display_name_uses_the_existing_folder() {
        let lab = Lab::new(Twist::default());
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_OK, "{run:?}");
        let renamed = format!("{} Renamed", lab.name);
        let bytes = lab.build(Twist::default(), &renamed);
        lab.write_setup(&bytes);
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_ALREADY_INSTALLED, "{run:?}");
        assert!(
            std::fs::symlink_metadata(lab.data_home.join(&renamed)).is_err(),
            "a folder of the new name was made"
        );
        lab.assert_installed();
    }

    /// M7-D8: a rerun on an installed app applies the integration again and still answers
    /// "already installed" (exit 23). A launcher stub (Windows) or a desktop entry (Linux) a cut-off
    /// run or the user lost is back after it, and the install's record is untouched.
    fn a_rerun_repairs_a_missing_entry() {
        let lab = Lab::new(Twist::default());
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_OK, "{run:?}");
        let before = lab.record_at(&lab.root).expect("record");
        #[cfg(windows)]
        let (entry, wanted) = (lab.root.join("app.exe"), b"lunepack test stub".to_vec());
        #[cfg(target_os = "linux")]
        let entry = lab
            .home
            .join(".local/share/applications")
            .join(format!("{SUITE_APP_ID}.desktop"));
        #[cfg(target_os = "macos")]
        let entry = lab.launch_agent();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let wanted = std::fs::read(&entry).expect("the entry");
        std::fs::remove_file(&entry).expect("remove the entry");
        let again = lab.run(&["--silent"], None);
        assert_eq!(again.code, EXIT_ALREADY_INSTALLED, "{again:?}");
        assert_eq!(
            std::fs::read(&entry).expect("the entry is back after the rerun"),
            wanted
        );
        assert_eq!(lab.record_at(&lab.root).expect("record"), before);
        lab.assert_installed();
    }

    /// M7-D5, M7-D13: a later run removes a stale directory under the temp dir (its owner gone,
    /// of any app) and keeps one whose owner runs, one with no marker and one of another name.
    #[cfg(windows)]
    fn stale_temp_directories_go_only_with_a_dead_owners_marker() {
        use lunepack::Rng as _;
        let lab = Lab::new(Twist::default());
        let temp = temp_home();
        let me = lunepack_os_windows::WindowsProcess::new()
            .process_id(std::process::id())
            .expect("me")
            .expect("me");
        let make = |prefix: &str, marker: Option<String>| {
            let mut b = [0u8; 8];
            lunepack_crypto::OsRng.fill(&mut b).expect("random");
            let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
            let d = temp.join(format!("{prefix}{hex}"));
            std::fs::create_dir(&d).expect("dir");
            lab.extra.borrow_mut().push(d.clone());
            std::fs::write(d.join("payload"), b"x").expect("file");
            if let Some(m) = marker {
                std::fs::write(d.join(MARKER), m).expect("marker");
            }
            d
        };
        // A pid no process has (Windows pids are multiples of 4).
        let dead_marker =
            |app: &str| format!("{{\"app_id\":\"{app}\",\"pid\":4294967291,\"start\":1}}\n");
        let dead = make("lunepack-setup-ui-", Some(dead_marker(&lab.app_id)));
        let dead_other = make(
            "lunepack-uninstall-",
            Some(dead_marker("org.example.other")),
        );
        let unmarked = make("lunepack-setup-ui-", None);
        let live = make(
            "lunepack-uninstall-",
            Some(format!(
                "{{\"app_id\":\"{}\",\"pid\":{},\"start\":{}}}\n",
                lab.app_id, me.pid, me.start_ticks
            )),
        );
        let not_ours = make("lunepack-other-", Some(dead_marker(&lab.app_id)));
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_OK, "{run:?}");
        assert!(!dead.exists(), "a dead run's directory was kept");
        assert!(
            !dead_other.exists(),
            "another app's dead directory was kept"
        );
        for kept in [&unmarked, &live, &not_ours] {
            assert!(kept.join("payload").exists(), "{kept:?} was removed");
        }
    }

    // ---- macOS cases (M8 step 8) ---------------------------------------------------------------

    /// The installer UI that is the runtime's parent (`--fake-installer-ui <engine> <script>`):
    /// starts the installer's runtime with `--ui-stdio` (stderr to `engine-stderr` in the out
    /// directory, its pid to `engine-pid`), says hello, answers every `Ping`, notes the prompts and
    /// answers them (`launch`: finish with a launch; `die`: exits with code 9 on the first frame
    /// after the welcome was answered, mid-install, without a word), then on `Close` waits for the
    /// runtime and notes its exit code (`engine-exit`) and how many bytes its standard output
    /// carried after `Close` (`after-close`). Every frame the runtime writes on its standard
    /// output must be a valid frame; anything else ends this UI with code 12.
    #[cfg(target_os = "macos")]
    pub fn fake_installer_ui() {
        let args: Vec<String> = std::env::args().collect();
        let (engine, script) = (&args[2], args[3].as_str());
        let out = PathBuf::from(std::env::var_os(OUT_VAR).expect("out"));
        let stderr = std::fs::File::create(out.join("engine-stderr")).expect("stderr");
        let mut child = Command::new(engine)
            .arg("--ui-stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .expect("engine");
        note("engine-pid", &child.id().to_string());
        let mut to_engine = child.stdin.take().expect("stdin");
        let mut from_engine = child.stdout.take().expect("stdout");
        let mut welcomed = false;
        loop {
            let msg = match ui::read_frame::<_, EngineMsg>(&mut from_engine) {
                Ok(msg) => msg,
                Err(ui::ProtocolError::Closed) => break,
                Err(_) => std::process::exit(12),
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
                    let value = match kind {
                        PromptKind::Welcome => {
                            welcomed = true;
                            ChoiceValue::Proceed
                        }
                        PromptKind::Done => ChoiceValue::Finish {
                            launch: script == "launch",
                        },
                        _ => ChoiceValue::Close,
                    };
                    Some(UiMsg::Choice { id, value })
                }
                EngineMsg::Close => {
                    note("ui-closed", "");
                    break;
                }
                _ if welcomed && script == "die" => std::process::exit(9),
                _ => None,
            };
            if let Some(reply) = reply {
                let _ = ui::write_frame(&mut to_engine, &reply);
            }
        }
        // After `Close` the runtime's standard output carries nothing more (its result goes to
        // standard error).
        let mut rest = Vec::new();
        let _ = std::io::Read::read_to_end(&mut from_engine, &mut rest);
        note("after-close", &rest.len().to_string());
        drop(to_engine);
        let status = child.wait().expect("engine");
        note(
            "engine-exit",
            &status.code().map_or("signal".to_owned(), |c| c.to_string()),
        );
    }

    /// macOS: runs the fake installer UI over the installer's runtime with `script`; returns its
    /// run (the runtime's final line is in `engine-stderr`).
    #[cfg(target_os = "macos")]
    fn run_ui_parent(lab: &Lab, script: &str) -> Run {
        let me = std::env::current_exe().expect("test exe");
        let engine = lab.installer_runtime();
        let engine = engine.to_str().expect("utf-8");
        // `None`: `LUNEPACK_NO_UI` keeps a native notice away; the parent UI is used anyway.
        lab.run_program(&me, &["--fake-installer-ui", engine, script], None)
    }

    /// macOS: waits until the process `pid` (a runtime whose parent is gone) has ended.
    #[cfg(target_os = "macos")]
    fn wait_gone(pid: u32) {
        let start = Instant::now();
        while lunepack_os_macos::MacProcess::new()
            .process_id(pid)
            .expect("probe")
            .is_some()
        {
            assert!(start.elapsed() < RUN_LIMIT, "the runtime did not end");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// M8-D7: the installer app's UI is the runtime's parent (`--ui-stdio`): the frames go over
    /// the runtime's own standard streams, which carry nothing else; the install, the done prompt
    /// and the launch go as with a UI child, and the result goes to standard error only.
    #[cfg(target_os = "macos")]
    fn the_installer_ui_drives_the_install_over_its_runtimes_streams() {
        let lab = Lab::new(Twist::default());
        let run = run_ui_parent(&lab, "launch");
        assert_eq!(run.code, EXIT_OK, "{run:?}");
        assert!(lab.out.join("ui-closed").exists(), "no Close: {run:?}");
        assert_eq!(lab.noted("engine-exit"), "0");
        assert_eq!(lab.noted("after-close"), "0", "bytes after Close on stdout");
        assert_eq!(lab.noted("ui-hello"), format!("{} Example Org\n", lab.name));
        assert_eq!(lab.noted("ui-prompts"), "Welcome\nDone\n");
        let stderr = lab.noted("engine-stderr");
        assert!(
            stderr.contains("\"command\":\"setup\"")
                && stderr.contains("\"outcome\":\"installed\""),
            "{stderr}"
        );
        lab.assert_installed();
        assert!(
            wait_for(&lab.out.join("app-ran")),
            "the app was not launched"
        );
        assert!(lab.noted("ui-dir").is_empty(), "a UI child was started");
    }

    /// The UI parent dies mid-install: the runtime cannot stop it and is not stopped by it; it
    /// finishes headless with the same outcome (installed, exit 0).
    #[cfg(target_os = "macos")]
    fn a_ui_parent_that_dies_mid_install_leaves_the_same_outcome() {
        let lab = Lab::new(Twist::default());
        let run = run_ui_parent(&lab, "die");
        assert_eq!(run.code, 9, "{run:?}");
        let pid: u32 = lab.noted("engine-pid").trim().parse().expect("pid");
        wait_gone(pid);
        assert_eq!(lab.noted("ui-prompts"), "Welcome\n");
        let stderr = lab.noted("engine-stderr");
        assert!(stderr.contains("\"outcome\":\"installed\""), "{stderr}");
        lab.assert_installed();
        assert!(!lab.out.join("app-ran").exists(), "the app was launched");
    }

    /// The payload file cut, flipped, lengthened or not a regular file: a payload that does not
    /// verify is exit 7 with nothing written; a link or a directory in its place is no installer
    /// (the ordinary runtime, whose grammar refuses an empty command line).
    #[cfg(target_os = "macos")]
    fn a_payload_cut_flipped_or_misplaced_is_refused() {
        let lab = Lab::new(Twist::default());
        let good = lab.bytes();
        let t = lab.trailer();
        let len = good.len();
        let trailer_at = len - TRAILER_SIZE as usize;
        let cut_pack = {
            let mut b = good[..(t.pack.offset + t.pack.length - 1) as usize].to_vec();
            b.extend_from_slice(&good[trailer_at..]);
            b
        };
        let flip = |at: usize| {
            let mut b = good.clone();
            b[at] ^= 0x01;
            b
        };
        let mut longer = good.clone();
        longer.extend_from_slice(&[0u8; 8]);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("one byte short", good[..len - 1].to_vec()),
            ("eight bytes short", good[..len - 8].to_vec()),
            ("the trailer alone", good[trailer_at..].to_vec()),
            ("the pack cut", cut_pack),
            ("eight bytes after the trailer", longer),
            ("the magic", flip(len - 1)),
            ("the trailer body", flip(trailer_at + 10)),
            ("the footer", flip(len - 40)),
            (
                "the key set",
                flip((t.keys.offset + t.keys.length / 2) as usize),
            ),
        ];
        for (name, bytes) in cases {
            lab.write_setup(&bytes);
            let run = lab.run(&["--silent"], None);
            assert_eq!(run.code, EXIT_VERIFY, "{name}: {run:?}");
            assert!(
                run.stdout.contains("\"kind\":\"verify\""),
                "{name}: {run:?}"
            );
            lab.assert_nothing_installed();
        }
        // A malformed payload with an argument the installer does not take is still exit 7.
        lab.write_setup(&flip(len - 1));
        let run = lab.run(&["install"], None);
        assert_eq!(run.code, EXIT_VERIFY, "{run:?}");
        // Not a regular file: a link to a good payload, then a directory.
        let elsewhere = lab.base.join("payload-elsewhere");
        std::fs::write(&elsewhere, &good).expect("payload");
        std::fs::remove_file(&lab.setup).expect("remove");
        std::os::unix::fs::symlink(&elsewhere, &lab.setup).expect("link");
        let run = lab.run(&[], None);
        assert_eq!(run.code, EXIT_USAGE, "link: {run:?}");
        std::fs::remove_file(&lab.setup).expect("remove");
        std::fs::create_dir(&lab.setup).expect("dir");
        let run = lab.run(&[], None);
        assert_eq!(run.code, EXIT_USAGE, "directory: {run:?}");
        lab.assert_nothing_installed();
    }

    /// macOS: runs `program` with `args`, which must succeed.
    #[cfg(target_os = "macos")]
    fn sh(program: &str, args: &[&std::ffi::OsStr]) {
        let out = Command::new(program).args(args).output().expect(program);
        assert!(
            out.status.success(),
            "{program}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A disk image attached at a mount point of the case, detached when dropped.
    #[cfg(target_os = "macos")]
    struct Mounted(PathBuf);

    #[cfg(target_os = "macos")]
    impl Mounted {
        fn attach(image: &Path, at: &Path, read_only: bool) -> Mounted {
            let mut args: Vec<&std::ffi::OsStr> = vec![
                "attach".as_ref(),
                "-nobrowse".as_ref(),
                "-noautoopen".as_ref(),
                "-mountpoint".as_ref(),
                at.as_os_str(),
            ];
            if read_only {
                args.push("-readonly".as_ref());
            }
            args.push(image.as_os_str());
            sh("/usr/bin/hdiutil", &args);
            Mounted(at.to_path_buf())
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for Mounted {
        fn drop(&mut self) {
            for force in [false, true] {
                let mut cmd = Command::new("/usr/bin/hdiutil");
                cmd.arg("detach");
                if force {
                    cmd.arg("-force");
                }
                let detached = cmd
                    .arg(&self.0)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success());
                if detached {
                    return;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }

    /// M8-D4 (Revision 1): only the target's place is judged. An installer run from a read-only
    /// disk image (as from the `.dmg`) installs.
    #[cfg(target_os = "macos")]
    fn a_setup_run_from_a_read_only_mount_installs() {
        let lab = Lab::new(Twist::default());
        let src = lab.base.join("dmg-src");
        std::fs::create_dir(&src).expect("src");
        let copy = src.join(lab.installer.file_name().expect("name"));
        sh(
            "/usr/bin/ditto",
            &[lab.installer.as_os_str(), copy.as_os_str()],
        );
        let image = lab.base.join("installer.dmg");
        sh(
            "/usr/bin/hdiutil",
            &[
                "create".as_ref(),
                "-quiet".as_ref(),
                "-srcfolder".as_ref(),
                src.as_os_str(),
                "-format".as_ref(),
                "UDRO".as_ref(),
                "-volname".as_ref(),
                "LP Setup Test".as_ref(),
                image.as_os_str(),
            ],
        );
        let at = lab.base.join("mnt");
        std::fs::create_dir(&at).expect("mount point");
        let _mounted = Mounted::attach(&image, &at, true);
        let runtime = common::join_rel(
            &at.join(lab.installer.file_name().expect("name")),
            INSTALLER_RUNTIME,
        );
        assert!(
            std::fs::write(at.join("probe"), b"x").is_err(),
            "the image is writable"
        );
        let run = lab.run_program(&runtime, &["--silent"], None);
        assert_eq!(run.code, EXIT_OK, "{run:?}");
        lab.assert_installed();
        run.assert_no_path(&lab);
    }

    /// M8-D16: the live bundle went to the Trash; a setup installs anew into a fresh bundle, with
    /// a new install id and the floors kept (raised here through the core's writers first).
    #[cfg(target_os = "macos")]
    fn a_setup_over_an_orphaned_install_installs_and_keeps_the_floors() {
        use lunepack_core::state::Floors;

        let lab = Lab::new(Twist::default());
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_OK, "{run:?}");
        let fs = StdFs::new();
        let store = UserScope {
            dir: UserLayout::from_root(lab.root.clone(), SCHEME).state_dir(),
            app_id: lab.app_id(),
        };
        let loaded = store.load(&fs, &Sha256Hasher).expect("load");
        let record = loaded.record.clone().expect("record");
        let raised = record.raise_floors(&Floors {
            root: None,
            keyset_version: record.floors.keyset_version + 5,
            feed_seq: [(Channel::parse(SUITE_CHANNEL).expect("channel"), 42)].into(),
        });
        let raised = store
            .commit(&fs, &loaded, &raised, &Sha256Hasher)
            .expect("commit");
        // Dragged to the Trash.
        let trash = lab.home.join(".Trash");
        std::fs::create_dir(&trash).expect("trash");
        let trashed = trash.join(lab.bundle().file_name().expect("name"));
        std::fs::rename(lab.bundle(), &trashed).expect("trash the bundle");
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_OK, "{run:?}");
        assert!(run.stdout.contains("\"outcome\":\"installed\""), "{run:?}");
        lab.assert_installed();
        let after = lab.record_at(&lab.root).expect("record");
        assert_ne!(after.install_id, raised.install_id, "the install id");
        assert_eq!(after.floors, raised.floors, "the floors");
        assert!(
            common::join_rel(&trashed, APP_FILE).is_file(),
            "the trashed copy was touched"
        );
    }

    /// M8-D4: an apps folder on another volume than `R` is exit 28 `other_volume`, with nothing
    /// written: no bundle, no install root.
    #[cfg(target_os = "macos")]
    fn a_setup_whose_apps_folder_is_on_another_volume_is_28() {
        let lab = Lab::new(Twist::default());
        let image = lab.base.join("apps.dmg");
        sh(
            "/usr/bin/hdiutil",
            &[
                "create".as_ref(),
                "-quiet".as_ref(),
                "-size".as_ref(),
                "8m".as_ref(),
                "-fs".as_ref(),
                "HFS+".as_ref(),
                "-volname".as_ref(),
                "LP Apps".as_ref(),
                image.as_os_str(),
            ],
        );
        let apps = lab.home.join("Applications");
        let _mounted = Mounted::attach(&image, &apps, false);
        let before = visible(&apps);
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_UNSUPPORTED_LOCATION, "{run:?}");
        assert!(
            run.stdout.contains("\"reason\":\"other_volume\""),
            "{run:?}"
        );
        assert_eq!(visible(&apps), before, "the apps folder changed");
        assert!(
            std::fs::symlink_metadata(&lab.root).is_err(),
            "the install root exists"
        );
    }

    /// Restores a folder's mode when dropped.
    #[cfg(target_os = "macos")]
    struct Mode(PathBuf, u32);

    #[cfg(target_os = "macos")]
    impl Drop for Mode {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(self.1));
        }
    }

    /// M8-D4: an apps folder the user cannot write is exit 28 `not_writable`, nothing written.
    #[cfg(target_os = "macos")]
    fn a_setup_whose_apps_folder_is_not_writable_is_28() {
        let lab = Lab::new(Twist::default());
        let apps = lab.home.join("Applications");
        let _restore = Mode(apps.clone(), 0o700);
        std::fs::set_permissions(&apps, std::fs::Permissions::from_mode(0o500)).expect("chmod");
        let run = lab.run(&["--silent"], None);
        assert_eq!(run.code, EXIT_UNSUPPORTED_LOCATION, "{run:?}");
        assert!(
            run.stdout.contains("\"reason\":\"not_writable\""),
            "{run:?}"
        );
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
            #[cfg(target_os = "linux")]
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
            #[cfg(windows)]
            (
                "slash_s_installs_silently_with_no_ui",
                slash_s_installs_silently_with_no_ui,
            ),
            #[cfg(windows)]
            (
                "a_malformed_setup_with_unknown_arguments_exits_without_a_notice",
                a_malformed_setup_with_unknown_arguments_exits_without_a_notice,
            ),
            #[cfg(windows)]
            (
                "an_install_uninstalls_silently_through_the_hand_off",
                an_install_uninstalls_silently_through_the_hand_off,
            ),
            #[cfg(windows)]
            (
                "an_ordinary_runtime_with_any_certificate_table_runs_normally",
                an_ordinary_runtime_with_any_certificate_table_runs_normally,
            ),
            #[cfg(windows)]
            (
                "a_signed_setup_installs_and_a_byte_after_its_table_is_refused",
                a_signed_setup_installs_and_a_byte_after_its_table_is_refused,
            ),
            #[cfg(windows)]
            (
                "a_foreign_folder_with_the_apps_name_is_left_alone",
                a_foreign_folder_with_the_apps_name_is_left_alone,
            ),
            #[cfg(windows)]
            (
                "a_rerun_under_another_display_name_uses_the_existing_folder",
                a_rerun_under_another_display_name_uses_the_existing_folder,
            ),
            (
                "a_rerun_repairs_a_missing_entry",
                a_rerun_repairs_a_missing_entry,
            ),
            #[cfg(windows)]
            (
                "stale_temp_directories_go_only_with_a_dead_owners_marker",
                stale_temp_directories_go_only_with_a_dead_owners_marker,
            ),
            #[cfg(target_os = "macos")]
            (
                "the_installer_ui_drives_the_install_over_its_runtimes_streams",
                the_installer_ui_drives_the_install_over_its_runtimes_streams,
            ),
            #[cfg(target_os = "macos")]
            (
                "a_ui_parent_that_dies_mid_install_leaves_the_same_outcome",
                a_ui_parent_that_dies_mid_install_leaves_the_same_outcome,
            ),
            #[cfg(target_os = "macos")]
            (
                "a_payload_cut_flipped_or_misplaced_is_refused",
                a_payload_cut_flipped_or_misplaced_is_refused,
            ),
            #[cfg(target_os = "macos")]
            (
                "a_setup_run_from_a_read_only_mount_installs",
                a_setup_run_from_a_read_only_mount_installs,
            ),
            #[cfg(target_os = "macos")]
            (
                "a_setup_over_an_orphaned_install_installs_and_keeps_the_floors",
                a_setup_over_an_orphaned_install_installs_and_keeps_the_floors,
            ),
            #[cfg(target_os = "macos")]
            (
                "a_setup_whose_apps_folder_is_on_another_volume_is_28",
                a_setup_whose_apps_folder_is_on_another_volume_is_28,
            ),
            #[cfg(target_os = "macos")]
            (
                "a_setup_whose_apps_folder_is_not_writable_is_28",
                a_setup_whose_apps_folder_is_not_writable_is_28,
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
            #[cfg(target_os = "macos")]
            if SKIPPED_ON_MACOS.contains(name) {
                println!(
                    "test {name} ... skipped on {} ({NOT_ON_MACOS})",
                    common::OS_NAME
                );
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
