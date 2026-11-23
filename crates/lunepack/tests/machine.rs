//! M10 step 17: the facade on a per-machine install (C8): detection, check and download as the
//! user, stage through the update service, startup and confirm through `attempt` and `confirm`,
//! and the lifecycle events of this user's `last_run`.
//!
//! The service is the core's real engine on the memory filesystem, reached through the testkit's
//! in-memory duplex (one server thread per connection). The facade's own filesystem is a wrapper in
//! which `R` is read-only: every write it attempts under `R` is recorded, and no test ends with one.

mod common;

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use common::{World, app_id, channel, version};
use lunepack::{
    ApplyOptions, ConfirmOutcome, DownloadOptions, Error, Installation, LifecycleEvent, Platform,
    ServiceReason, StartupAction, apply_and_restart_for, block_on, confirm_for, startup_for,
};
use lunepack_core::engine::{Engine, Ports, protected_dirs, serve};
use lunepack_core::service::{
    AttemptAnswer, ClientSession, ClientTimeouts, ServerHello, ServerSession,
};
use lunepack_core::state::{InstallCounters, InstallState, MachineScope, MachineStore, Scope};
use lunepack_core::{
    CodecId, ConnectError, DirEntryInfo, Floors, Fs, FsError, FsErrorKind, InstallMeta,
    LayoutScheme, LockGuard, MachineLayout, MachinePolicy, Meta, ReadAt, RelPath, RootParts,
    SERVICE_FILE, TrustedRoot, UPDATE_CONFIG_FILE, UpdateConfig,
};
use lunepack_testkit::{
    FakeClock, FakeCodec, FakeConnector, FakeHasher, FakeIntegration, FakePolicy, FakeProcess,
    FakeProtect, FakePublisherCheck, FakeRegistrar, FakeRng, FakeVerifier, MemFs, PackBuilder,
    SUITE_T0, abs_path, mem_duplex,
};

const V100: &str = "1.0.0";
const V110: &str = "1.1.0";
const FEED: &str = "https://fake.invalid/";
const MACHINE_INSTALL_ID: [u8; 16] = [9; 16];

// ---- the facade's filesystem: `R` is read-only ---------------------------------------------------

/// A [`MemFs`] that refuses, and records, every write under `root`.
struct ReadOnlyUnder {
    inner: MemFs,
    root: PathBuf,
    attempts: Arc<Mutex<Vec<String>>>,
}

impl ReadOnlyUnder {
    fn deny(&self, op: &'static str, path: &Path) -> Result<(), FsError> {
        if path.starts_with(&self.root) {
            self.attempts.lock().unwrap().push(op.to_string());
            return Err(FsError::new(FsErrorKind::Other, path, None));
        }
        Ok(())
    }
}

macro_rules! guarded {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $ret:ty => $op:literal [$($path:ident),*];)*) => {
        $(fn $name(&self, $($arg: $ty),*) -> $ret {
            $(self.deny($op, $path)?;)*
            self.inner.$name($($arg),*)
        })*
    };
}

impl Fs for ReadOnlyUnder {
    guarded! {
        create_new(path: &Path) -> Result<Box<dyn lunepack_core::FileWrite>, FsError> => "create_new" [path];
        open_append(path: &Path) -> Result<Box<dyn lunepack_core::FileWrite>, FsError> => "open_append" [path];
        truncate(path: &Path, len: u64) -> Result<(), FsError> => "truncate" [path];
        rename(from: &Path, to: &Path) -> Result<(), FsError> => "rename" [from, to];
        remove_file(path: &Path) -> Result<(), FsError> => "remove_file" [path];
        remove_dir_all_nofollow(path: &Path) -> Result<(), FsError> => "remove_dir_all" [path];
        create_dir_all(path: &Path) -> Result<(), FsError> => "create_dir_all" [path];
        sync_dir(path: &Path) -> Result<(), FsError> => "sync_dir" [path];
        copy_file(from: &Path, to_new: &Path) -> Result<(), FsError> => "copy_file" [to_new];
        set_exec(path: &Path, exec: bool) -> Result<(), FsError> => "set_exec" [path];
        symlink(target: &str, link_path: &Path) -> Result<(), FsError> => "symlink" [link_path];
        replace_symlink(target: &str, link: &Path) -> Result<(), FsError> => "replace_symlink" [link];
        try_lock(path: &Path) -> Result<Option<Box<dyn LockGuard>>, FsError> => "try_lock" [path];
    }

    fn read_capped(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError> {
        self.inner.read_capped(path, max)
    }
    fn open_read(&self, path: &Path) -> Result<Box<dyn ReadAt>, FsError> {
        self.inner.open_read(path)
    }
    fn list_dir(&self, path: &Path) -> Result<Vec<DirEntryInfo>, FsError> {
        self.inner.list_dir(path)
    }
    fn symlink_metadata(&self, path: &Path) -> Result<Option<Meta>, FsError> {
        self.inner.symlink_metadata(path)
    }
    fn read_link(&self, path: &Path) -> Result<String, FsError> {
        self.inner.read_link(path)
    }
}

// ---- the machine and its service -----------------------------------------------------------------

/// Everything the engine runs on.
struct Host {
    fs: MemFs,
    protect: FakeProtect,
    policy: FakePolicy,
    integration: FakeIntegration,
    publisher: FakePublisherCheck,
    registrar: FakeRegistrar,
    process: FakeProcess,
    rng: FakeRng,
    clock: FakeClock,
    codec: Arc<dyn lunepack_core::Codec>,
    root: PathBuf,
    monotonic: AtomicU64,
    connects: AtomicUsize,
}

impl Host {
    fn ports(&self) -> Ports<'_> {
        Ports {
            fs: &self.fs,
            codec: &*self.codec,
            hasher: &FakeHasher,
            verifier: &FakeVerifier,
            clock: &self.clock,
            rng: &self.rng,
            integration: &self.integration,
            publisher: &self.publisher,
            protect: &self.protect,
            policy: &self.policy,
            registrar: &self.registrar,
            process: &self.process,
            scheme: lunepack_core::MachineScheme::WINDOWS,
        }
    }

    fn store(&self) -> MachineStore {
        MachineStore {
            dir: MachineLayout::new(&self.root).state_dir(),
            app_id: app_id(),
        }
    }

    fn record(&self) -> InstallState {
        self.store()
            .load(&self.fs, &FakeHasher)
            .expect("load")
            .record
            .expect("record")
    }

    fn advance(&self, secs: u64) {
        self.monotonic.fetch_add(secs, Ordering::SeqCst);
    }
}

fn meta() -> InstallMeta {
    InstallMeta {
        entry: RelPath::parse("app.exe").expect("entry"),
        name: "Hello".into(),
        comment: None,
        icon: None,
        categories: Vec::new(),
        bin: None,
        terminal: false,
        publisher: None,
        file_types: Vec::new(),
        url_schemes: Vec::new(),
        autostart: false,
    }
}

fn config_for(root: &TrustedRoot, v: &str) -> UpdateConfig {
    UpdateConfig::new(
        root,
        version(v),
        common::TARGET,
        FEED,
        channel(),
        60,
        meta(),
    )
    .expect("config")
}

/// The files of a release of the machine install: the entry (changes), a file that never changes,
/// the service binary and the update config.
fn release_pack(world: &World, v: &str) -> PackBuilder {
    let mut pack = PackBuilder::new();
    pack.file(
        &FakeHasher,
        "app.exe",
        format!("entry of {v}").repeat(20).as_bytes(),
        CodecId::Lzma2,
    )
    .file(
        &FakeHasher,
        "readme.txt",
        b"unchanged readme".repeat(8).as_slice(),
        CodecId::Lzma2,
    )
    .file(
        &FakeHasher,
        SERVICE_FILE,
        format!("service of {v}").as_bytes(),
        CodecId::Lzma2,
    )
    .file(
        &FakeHasher,
        UPDATE_CONFIG_FILE,
        &config_for(&world.root(), v)
            .to_bytes()
            .expect("config bytes"),
        CodecId::Stored,
    );
    pack
}

/// One machine install of 1.0.0 with its service, a user's home, and the facade's way in.
struct Rig {
    world: World,
    host: Arc<Host>,
    home: PathBuf,
    local: PathBuf,
    attempts: Arc<Mutex<Vec<String>>>,
    facade_process: FakeProcess,
    facade_integration: FakeIntegration,
    /// The service's accept queue.
    server: Mutex<mpsc::Sender<(lunepack_testkit::MemDuplex, lunepack_core::AppId)>>,
    /// Incompressible release files, real LZMA frames and patches (M12-D6).
    noise: bool,
}

/// The release files of `v`: compressible ones, or (`noise`) incompressible ones edited a little
/// from release to release, so a delta patch is far shorter than its frame.
fn release_files(world: &World, v: &str, noise: bool) -> Vec<(&'static str, Vec<u8>)> {
    let config = config_for(&world.root(), v)
        .to_bytes()
        .expect("config bytes");
    if !noise {
        return vec![
            ("app.exe", format!("entry of {v}").repeat(20).into_bytes()),
            ("readme.txt", b"unchanged readme".repeat(8)),
            (SERVICE_FILE, format!("service of {v}").into_bytes()),
            (UPDATE_CONFIG_FILE, config),
        ];
    }
    let edits = if v == V100 { 0 } else { 1 };
    let edited = |mut bytes: Vec<u8>| {
        for k in 0..edits * 4 {
            let at = bytes.len() / 5 * (k + 1);
            bytes[at] ^= 0x5A;
        }
        bytes
    };
    vec![
        ("app.exe", edited(common::noise(30_000, 1))),
        ("readme.txt", b"unchanged readme".repeat(8)),
        (SERVICE_FILE, edited(common::noise(20_000, 2))),
        (UPDATE_CONFIG_FILE, config),
    ]
}

impl Rig {
    fn new() -> Rig {
        Rig::with(2, false)
    }

    /// A rig whose service speaks protocol versions `1..=server_max`, with `noise` release files.
    fn with(server_max: u32, noise: bool) -> Rig {
        let world = World::new();
        let fs = world.fs.clone();
        let home = abs_path("/pf");
        let root = home.join("Hello");
        let host = Arc::new(Host {
            protect: FakeProtect::new(&fs),
            policy: FakePolicy::new(),
            integration: FakeIntegration::new(),
            publisher: FakePublisherCheck::new([]),
            registrar: FakeRegistrar::new(),
            process: FakeProcess::new(root.join("app/1.0.0/app.exe")),
            rng: FakeRng::new(7),
            clock: FakeClock::new(SUITE_T0 + 3600),
            codec: if noise {
                Arc::new(lunepack_codec_lzma::LzmaCodec)
            } else {
                Arc::new(FakeCodec::new())
            },
            root: root.clone(),
            monotonic: AtomicU64::new(1000),
            connects: AtomicUsize::new(0),
            fs: fs.clone(),
        });
        for (dir, class) in protected_dirs(&root) {
            fs.create_dir_all(&dir).expect("dirs");
            host.protect.mark(&dir, class);
        }
        let (tx, rx) = mpsc::channel();
        let rig = Rig {
            server: Mutex::new(tx),
            world,
            host,
            home,
            local: abs_path("/local"),
            attempts: Arc::new(Mutex::new(Vec::new())),
            facade_process: FakeProcess::new("/unused"),
            facade_integration: FakeIntegration::new(),
            noise,
        };
        rig.write_tree(V100);
        let store = rig.host.store();
        let loaded = store.load(&fs, &FakeHasher).expect("load");
        let first = InstallState::new(
            1,
            app_id(),
            Scope::Machine,
            MACHINE_INSTALL_ID,
            common::TARGET,
        )
        .install(version(V100), SUITE_T0, common::TARGET, MACHINE_INSTALL_ID)
        .raise_floors(&Floors {
            root: Some(RootParts::from_trusted(&rig.world.root())),
            ..Floors::default()
        });
        store
            .commit(&fs, &loaded, &first, &FakeHasher)
            .expect("commit");
        let host = Arc::clone(&rig.host);
        thread::spawn(move || {
            let mut engine: Option<Engine<'_>> = None;
            for (io, app) in rx {
                let Ok(session) = ServerSession::accept_range(io, app, 1, server_max) else {
                    continue;
                };
                if engine.is_none() {
                    engine = Engine::open(host.ports(), &host.root).ok();
                }
                let Some(engine) = engine.as_mut() else {
                    continue;
                };
                let now = || Duration::from_secs(host.monotonic.load(Ordering::SeqCst));
                let _ = serve(session, engine, &now);
            }
        });
        rig
    }

    fn root(&self) -> PathBuf {
        self.host.root.clone()
    }

    fn write_tree(&self, v: &str) {
        let dir = self.root().join("app").join(v);
        self.world.fs.create_dir_all(&dir).expect("dir");
        for (name, bytes) in release_files(&self.world, v, self.noise) {
            let mut w = self.world.fs.create_new(&dir.join(name)).expect("create");
            w.write_all(&bytes).expect("write");
            w.sync().expect("sync");
        }
    }

    /// Publishes `v` as feed `seq`, laid out by the real writer with real LZMA frames and one delta
    /// from `from` (a patch for every file that changed); returns the delta file's name.
    fn publish_with_delta(&self, seq: u64, v: &str, from: &str) -> String {
        use lunepack_core::{PayloadKind, ReleaseLayout, encode_patch_checked, pack_file};
        let codec = lunepack_codec_lzma::LzmaCodec;
        let old = release_files(&self.world, from, true);
        let mut layout = ReleaseLayout::new(app_id(), v, common::TARGET).expect("layout");
        let mut patches = Vec::new();
        for (name, bytes) in release_files(&self.world, v, true) {
            let rel = RelPath::parse(name).expect("path");
            let packed = pack_file(&bytes, &codec, &codec, &FakeHasher).expect("pack");
            layout.add_file(rel.clone(), false, &packed).expect("add");
            let base = &old.iter().find(|(n, _)| *n == name).expect("base").1;
            if *base != bytes {
                let patch = encode_patch_checked(
                    &rel,
                    CodecId::Lzma2,
                    base,
                    &bytes,
                    &codec,
                    &codec,
                    &FakeHasher,
                )
                .expect("patch");
                patches.push((rel, patch));
            }
        }
        layout.add_delta(from, patches).expect("delta");
        let release = layout
            .finish_release(SUITE_T0, &FakeHasher)
            .expect("finish");
        let w = &self.world;
        let manifest =
            w.fx.envelope(PayloadKind::Manifest, &release.manifest.to_payload(), &[1]);
        w.origin.put(&common::manifest_path(v), manifest.clone());
        w.origin.put(&common::pack_path(v), release.pack.clone());
        let delta = release.deltas[0].path.clone();
        w.origin.put(&delta, release.deltas[0].bytes.clone());
        let doc = w.fx.release(v, &[(common::TARGET, &manifest)], None);
        w.publish_feed(seq, vec![doc]);
        delta
    }

    /// The connector of this machine's service. One engine serves every connection, as the
    /// service's host loop does, so its in-memory supervision lease outlives a connection.
    fn connector(&self) -> FakeConnector {
        let tx = self.server.lock().unwrap().clone();
        let host = Arc::clone(&self.host);
        FakeConnector::new(move |app| {
            host.connects.fetch_add(1, Ordering::SeqCst);
            let (client, server) = mem_duplex();
            tx.send((server, app.clone())).expect("the service thread");
            Ok(Box::new(client))
        })
    }

    /// The facade's platform for `user`'s local data folder.
    fn platform_for(
        &self,
        user: &str,
        token: Option<OsString>,
        connector: Arc<dyn lunepack::ServiceConnector>,
    ) -> Platform {
        let fs = ReadOnlyUnder {
            inner: self.world.fs.clone(),
            root: self.root(),
            attempts: Arc::clone(&self.attempts),
        };
        Platform::native()
            .with_fs(Arc::new(fs))
            .with_hasher(Arc::new(FakeHasher))
            .with_verifier(Arc::new(FakeVerifier))
            .with_process(Arc::new(self.facade_process.clone()))
            .with_integration(Arc::new(self.facade_integration.clone()))
            .with_rng(Arc::new(FakeRng::new(9)))
            .with_health_token(token)
            .with_layout_scheme(LayoutScheme::WINDOWS)
            .with_machine_home(self.home.clone())
            .with_local_data(self.local.join(user))
            .with_service_connector(connector)
            .with_policy_source(Arc::new(self.host.policy.clone()))
            .with_busy_wait(Duration::from_millis(300))
    }

    fn platform(&self, token: Option<OsString>) -> Platform {
        self.platform_for("alice", token, Arc::new(self.connector()))
    }

    fn open_with(&self, v: &str, platform: Platform) -> Installation {
        let exe = self.root().join("app").join(v).join("app.exe");
        Installation::from_exe_with(&exe, platform).expect("installation")
    }

    fn open(&self, v: &str, token: Option<OsString>) -> Installation {
        self.open_with(v, self.platform(token))
    }

    fn updater(&self, inst: &Installation) -> lunepack::Updater {
        self.updater_with(inst, lunepack::FetchPolicy::default())
    }

    fn updater_with(
        &self,
        inst: &Installation,
        policy: lunepack::FetchPolicy,
    ) -> lunepack::Updater {
        inst.updater_builder()
            .expect("builder")
            .transport(Arc::clone(&self.world.transport))
            .codec(Arc::clone(&self.host.codec))
            .clock(Arc::clone(&self.world.clock) as Arc<dyn lunepack_core::Clock>)
            .fetch_policy(policy)
            .workers(2)
            .build()
            .expect("build")
    }

    /// Publishes `v` as feed `seq`, with the machine's release files.
    fn publish(&self, seq: u64, v: &str) -> PackBuilder {
        let pack = release_pack(&self.world, v);
        self.world.publish_pack(seq, v, &pack);
        pack
    }

    /// A session of the runtime's double: `apply` of the staged version.
    fn apply(&self, v: &str) -> lunepack_core::service::Token {
        let connector = self.connector();
        let io = lunepack_core::ServiceConnector::connect(&connector, &app_id()).expect("connect");
        let mut session = ClientSession::connect(
            io,
            app_id(),
            ClientTimeouts {
                hello: Some(Duration::from_secs(10)),
                answer: Some(Duration::from_secs(30)),
            },
        )
        .expect("hello");
        session.apply(&version(v)).expect("apply")
    }

    fn user_counters(&self, user: &str) -> Option<InstallCounters> {
        let record = self.host.record();
        let scope = MachineScope {
            machine_dir: MachineLayout::new(&self.root()).state_dir(),
            user_dir: self
                .local
                .join(user)
                .join("lunepack")
                .join(app_id().as_str())
                .join("state"),
            app_id: app_id(),
        };
        scope
            .load_counters(&self.world.fs, &record, &FakeHasher)
            .expect("counters")
            .record
    }

    /// No test ends with a write the facade attempted under `R`.
    fn assert_read_only(&self) {
        assert_eq!(
            *self.attempts.lock().unwrap(),
            Vec::<String>::new(),
            "the facade wrote under R"
        );
    }
}

fn token_hex(token: &lunepack_core::service::Token) -> OsString {
    OsString::from(token.to_hex())
}

fn check_and_download(
    rig: &Rig,
    updater: &lunepack::Updater,
) -> (lunepack::UpdateInfo, lunepack::Downloaded) {
    let info = block_on(updater.check())
        .expect("check")
        .expect("an update");
    let downloaded =
        block_on(updater.download(&info, DownloadOptions::default())).expect("download");
    let _ = rig;
    (info, downloaded)
}

// ---- detection -----------------------------------------------------------------------------------

#[test]
fn a_tree_in_the_machine_home_with_a_machine_record_is_a_machine_install() {
    let rig = Rig::new();
    let inst = rig.open(V100, None);
    assert!(inst.is_machine() && inst.is_installed());
    assert!(inst.layout().is_none(), "no per-user layout");
    assert_eq!(
        inst.machine_layout().map(|l| l.root().to_path_buf()),
        Some(rig.root())
    );
    assert_eq!(
        inst.user_home(),
        Some(
            rig.local
                .join("alice")
                .join("lunepack")
                .join(app_id().as_str())
                .as_path()
        )
    );
    // The updater runs on the machine layout, with this user's cache.
    let _ = rig.updater(&inst);
    rig.assert_read_only();
}

#[test]
fn a_machine_record_anywhere_else_a_user_record_here_or_another_app_is_not_a_machine_install() {
    // Wrong parent: the machine home is somewhere else.
    let rig = Rig::new();
    let platform = rig.platform(None).with_machine_home(abs_path("/elsewhere"));
    let exe = rig.root().join("app").join(V100).join("app.exe");
    let got = Installation::from_exe_with(&exe, platform);
    // It resolves as a per-user tree would, and the user store refuses a machine record.
    assert!(matches!(got, Err(Error::State(_))), "{:?}", got.err());

    // A user record directly in the machine home: a user install.
    let rig = Rig::new();
    let other = rig.home.join("Other");
    let layout = lunepack_core::UserLayout::from_root(other.clone(), LayoutScheme::WINDOWS);
    let dir = layout.version_dir(&version(V100));
    let cfg = config_for(&rig.world.root(), V100);
    rig.world.fs.create_dir_all(&dir).expect("dir");
    for (name, bytes) in [
        ("app.exe", b"entry".to_vec()),
        (UPDATE_CONFIG_FILE, cfg.to_bytes().expect("bytes")),
    ] {
        let mut w = rig.world.fs.create_new(&dir.join(name)).expect("create");
        w.write_all(&bytes).expect("write");
    }
    let store = lunepack_core::state::UserScope {
        dir: layout.state_dir(),
        app_id: app_id(),
    };
    rig.world
        .fs
        .create_dir_all(&layout.state_dir())
        .expect("state");
    let loaded = store.load(&rig.world.fs, &FakeHasher).expect("load");
    let record = InstallState::new(1, app_id(), Scope::User, [3; 16], common::TARGET).install(
        version(V100),
        SUITE_T0,
        common::TARGET,
        [3; 16],
    );
    store
        .commit(&rig.world.fs, &loaded, &record, &FakeHasher)
        .expect("commit");
    let inst = Installation::from_exe_with(&dir.join("app.exe"), rig.platform(None)).expect("user");
    assert!(!inst.is_machine() && inst.layout().is_some());

    // Another app's machine record in the machine home: the machine store refuses it, and the
    // user path then refuses the record.
    let rig = Rig::new();
    let other_app = lunepack_core::AppId::parse("org.other.app").expect("app");
    let cfg_other = UpdateConfig::new(
        &rig.world.root(),
        version(V100),
        common::TARGET,
        FEED,
        channel(),
        60,
        meta(),
    )
    .expect("config");
    let mut cfg_other = cfg_other;
    cfg_other.app_id = other_app.clone();
    let root2 = rig.home.join("Hello2");
    let dir2 = root2.join("app").join(V100);
    rig.world.fs.create_dir_all(&dir2).expect("dir");
    let mut w = rig
        .world
        .fs
        .create_new(&dir2.join("app.exe"))
        .expect("create");
    w.write_all(b"x").expect("write");
    let mut w = rig
        .world
        .fs
        .create_new(&dir2.join(UPDATE_CONFIG_FILE))
        .expect("create");
    w.write_all(&cfg_other.to_bytes().expect("bytes"))
        .expect("write");
    // The state of another app id under the same root.
    let state2 = MachineLayout::new(&root2).state_dir();
    rig.world.fs.create_dir_all(&state2).expect("state");
    let store = MachineStore {
        dir: state2,
        app_id: app_id(),
    };
    let loaded = store.load(&rig.world.fs, &FakeHasher).expect("load");
    let rec = InstallState::new(1, app_id(), Scope::Machine, [5; 16], common::TARGET).install(
        version(V100),
        SUITE_T0,
        common::TARGET,
        [5; 16],
    );
    store
        .commit(&rig.world.fs, &loaded, &rec, &FakeHasher)
        .expect("commit");
    let got = Installation::from_exe_with(&dir2.join("app.exe"), rig.platform(None));
    assert!(
        !matches!(&got, Ok(inst) if inst.is_machine()),
        "{:?}",
        got.as_ref().err()
    );
}

// ---- the whole cycle -----------------------------------------------------------------------------

#[test]
fn check_download_stage_apply_startup_confirm_over_the_service() {
    let rig = Rig::new();
    // The user starts 1.0.0: a first run, once.
    let inst = rig.open(V100, None);
    let first = startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(first.action, StartupAction::Continue);
    assert!(!first.pending);
    assert_eq!(
        first.events,
        vec![LifecycleEvent::FirstRun {
            version: version(V100)
        }]
    );
    let again = startup_for(&rig.open(V100, None), Vec::new()).expect("startup");
    assert!(again.events.is_empty(), "delivered once");

    // check and download run as the user; the user's counters rise, the machine record does not.
    rig.publish(2, V110);
    let updater = rig.updater(&inst);
    let (info, downloaded) = check_and_download(&rig, &updater);
    assert_eq!(info.version(), &version(V110));
    assert_eq!(rig.host.record().floors.feed_seq.get(&channel()), None);
    assert_eq!(
        rig.user_counters("alice")
            .expect("counters")
            .floors
            .feed_seq
            .get(&channel()),
        Some(&2)
    );

    // stage goes to the service, which verifies the same bytes and builds the tree.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let downloaded = downloaded.with_options(DownloadOptions {
        progress: Some(Box::new(move |p| sink.lock().unwrap().push(p.phase))),
        cancel: None,
    });
    let staged = block_on(updater.stage(downloaded)).expect("stage");
    assert!(
        seen.lock().unwrap().contains(&lunepack::Phase::Stage),
        "the service's progress reaches the callback"
    );
    assert_eq!(staged.version(), &version(V110));
    assert_eq!(staged.tree(), rig.root().join("app").join(V110));
    assert_eq!(
        updater.staged().expect("staged").expect("some").version(),
        &version(V110)
    );
    let record = rig.host.record();
    assert_eq!(
        record.staged.as_ref().map(|s| s.version.clone()),
        Some(version(V110))
    );
    assert_eq!(
        record.floors.feed_seq.get(&channel()),
        Some(&2),
        "the engine raised it"
    );

    // apply_and_restart starts the runtime as today (the test double of the runtime then applies).
    let scheduled = apply_and_restart_for(&inst, ApplyOptions::default()).expect("apply");
    assert_eq!(scheduled.version(), &version(V110));
    let spawns = rig.facade_process.spawns();
    assert_eq!(spawns.len(), 1);
    assert_eq!(spawns[0].args[0], "apply");
    let token = rig.apply(V110);
    assert!(rig.host.record().pending.is_some());

    // The new version starts supervised, with its token, and confirms.
    let new = rig.open(V110, Some(token_hex(&token)));
    let started = startup_for(&new, Vec::new()).expect("startup");
    assert_eq!(started.action, StartupAction::Continue);
    assert!(started.pending, "still waiting for its health check");
    assert_eq!(
        started.events,
        vec![
            LifecycleEvent::Updated {
                from: version(V100),
                to: version(V110)
            },
            LifecycleEvent::FirstRun {
                version: version(V110)
            },
        ]
    );
    assert_eq!(
        confirm_for(&new).expect("confirm"),
        ConfirmOutcome::Confirmed
    );
    let record = rig.host.record();
    assert!(record.pending.is_none() && record.health.is_none());
    assert_eq!(record.current.expect("current").version, version(V110));
    // Confirmed once: nothing pending now.
    assert_eq!(
        confirm_for(&rig.open(V110, Some(token_hex(&token)))).expect("again"),
        ConfirmOutcome::NothingPending
    );
    rig.assert_read_only();
}

#[test]
fn a_file_the_service_cannot_place_is_fetched_and_the_stage_commits_again() {
    let rig = Rig::new();
    rig.publish(2, V110);
    let inst = rig.open(V100, None);
    // Range requests only, so the unchanged file has no frame and no pack is held.
    let updater = rig.updater_with(
        &inst,
        lunepack::FetchPolicy {
            gap: 0,
            full_ratio: 100,
            max_runs: 64,
        },
    );
    let (_, downloaded) = check_and_download(&rig, &updater);
    // The unchanged file changed under the machine tree after the user's scan found it equal: the
    // service's own scan finds no source for it, and answers `need_fetch`.
    let readme = rig.root().join("app").join(V100).join("readme.txt");
    rig.world.fs.remove_file(&readme).expect("remove");
    let mut w = rig.world.fs.create_new(&readme).expect("create");
    w.write_all(b"edited by an administrator").expect("write");
    let before = rig.world.origin.requests().len();
    let staged = block_on(updater.stage(downloaded)).expect("stage after need_fetch");
    assert!(
        rig.world.origin.requests().len() > before,
        "the missing file was fetched from the feed's origin"
    );
    assert_eq!(staged.version(), &version(V110));
    assert!(
        rig.host
            .fs
            .symlink_metadata(&staged.tree().join("readme.txt"))
            .expect("meta")
            .is_some()
    );
    rig.assert_read_only();
}

/// The frame entries of the user's download cache under `dir` (files named by a SHA-256 in a
/// `frames` directory), found by walking it.
fn cached_frames(fs: &MemFs, dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(at) = stack.pop() {
        let Ok(entries) = fs.list_dir(&at) else {
            continue;
        };
        for e in entries {
            let path = at.join(&e.name);
            match e.kind {
                lunepack_core::FileKind::Dir => stack.push(path),
                lunepack_core::FileKind::File
                    if at.file_name().is_some_and(|n| n == "frames")
                        && e.name.to_str().is_some_and(|n| {
                            n.len() == 64 && n.bytes().all(|b| b.is_ascii_hexdigit())
                        }) =>
                {
                    found.push(path);
                }
                _ => {}
            }
        }
    }
    found.sort();
    found
}

/// F2: a frame in the user's cache that is damaged (the right size, other bytes) is refused by the
/// service; the facade drops it from the cache, fetches it again and the stage commits.
#[test]
fn a_damaged_frame_in_the_cache_is_dropped_and_fetched_again() {
    let rig = Rig::new();
    rig.publish(2, V110);
    let inst = rig.open(V100, None);
    // Range requests only: the changed files come as frames.
    let updater = rig.updater_with(
        &inst,
        lunepack::FetchPolicy {
            gap: 0,
            full_ratio: 100,
            max_runs: 64,
        },
    );
    let (_, downloaded) = check_and_download(&rig, &updater);
    let frames = cached_frames(&rig.world.fs, &rig.local.join("alice"));
    let damaged = frames.first().expect("a cached frame").clone();
    let mut bytes = rig
        .world
        .fs
        .read_capped(&damaged, 1 << 20)
        .expect("read the frame");
    bytes[0] ^= 0xff;
    rig.world.fs.remove_file(&damaged).expect("remove");
    let mut w = rig.world.fs.create_new(&damaged).expect("create");
    w.write_all(&bytes).expect("write");
    drop(w);

    let before = rig.world.origin.requests().len();
    let staged = block_on(updater.stage(downloaded)).expect("stage after the refusal");
    assert_eq!(staged.version(), &version(V110));
    assert!(
        rig.world.origin.requests().len() > before,
        "the refused frame was fetched again from the feed's origin"
    );
    assert_eq!(
        rig.host.record().staged.as_ref().map(|s| s.version.clone()),
        Some(version(V110))
    );
    rig.assert_read_only();
}

/// F2's bound: a service that refuses every object as damaged and always answers `need_fetch` is
/// committed to at most three times, then the stage fails as exhausted.
#[test]
fn a_service_that_refuses_every_object_ends_within_three_commits() {
    use lunepack_core::service::{ErrorCode, Request, Response};
    let rig = Rig::new();
    rig.publish(2, V110);
    let commits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&commits);
    let refusing = Arc::new(FakeConnector::new(move |app| {
        let (client, server) = mem_duplex();
        let (app, counted) = (app.clone(), Arc::clone(&counted));
        thread::spawn(move || {
            let Ok(mut session) = ServerSession::accept(server, app) else {
                return;
            };
            while let Ok(Some(request)) = session.next_request() {
                let answer = match request {
                    Request::StageBegin { documents, .. } => {
                        let size = documents.iter().map(|d| d.bytes).sum();
                        if session.read_data(size, &mut std::io::sink()).is_err() {
                            return;
                        }
                        Response::StageReady {
                            version: version(V110),
                        }
                    }
                    Request::Put { size, .. } => {
                        if session.read_data(size, &mut std::io::sink()).is_err() {
                            return;
                        }
                        Response::error(ErrorCode::HashMismatch)
                    }
                    Request::StageCommit => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        Response::NeedFetch {
                            paths: vec![RelPath::parse("app.exe").expect("path")],
                            more: false,
                        }
                    }
                    _ => return,
                };
                if session.reply(&answer).is_err() {
                    return;
                }
            }
        });
        Ok(Box::new(client))
    }));
    let platform = rig.platform_for("alice", None, refusing);
    let inst = rig.open_with(V100, platform);
    let updater = rig.updater(&inst);
    let (_, downloaded) = check_and_download(&rig, &updater);
    let result = block_on(updater.stage(downloaded));
    assert!(
        matches!(result, Err(Error::NeedFetchExhausted(_))),
        "{result:?}"
    );
    assert_eq!(commits.load(Ordering::SeqCst), 3);
    rig.assert_read_only();
}

// ---- policy --------------------------------------------------------------------------------------

#[test]
fn disabled_self_update_is_reported_before_any_request() {
    let rig = Rig::new();
    rig.publish(2, V110);
    let inst = rig.open(V100, None);
    let updater = rig.updater(&inst);
    let (info, downloaded) = check_and_download(&rig, &updater);
    rig.world.origin.clear_requests();
    let connects = rig.host.connects.load(Ordering::SeqCst);
    rig.host.policy.set(MachinePolicy {
        self_update_disabled: true,
        no_update_ui: false,
    });
    assert!(matches!(
        block_on(updater.check()),
        Err(Error::DisabledByPolicy)
    ));
    assert!(matches!(
        block_on(updater.download(&info, DownloadOptions::default())),
        Err(Error::DisabledByPolicy)
    ));
    assert!(matches!(
        block_on(updater.stage(downloaded)),
        Err(Error::DisabledByPolicy)
    ));
    assert!(matches!(
        apply_and_restart_for(&inst, ApplyOptions::default()),
        Err(Error::DisabledByPolicy)
    ));
    assert!(rig.world.origin.requests().is_empty(), "no request");
    assert_eq!(
        rig.host.connects.load(Ordering::SeqCst),
        connects,
        "no connection"
    );
    // The policy is the administrator's: off again, the same update stages.
    rig.host.policy.set(MachinePolicy::default());
    let (_, downloaded) = check_and_download(&rig, &updater);
    block_on(updater.stage(downloaded)).expect("stage");
    rig.assert_read_only();
}

// ---- the connector's errors ----------------------------------------------------------------------

#[test]
fn each_way_the_service_cannot_be_reached_is_a_typed_error() {
    let rig = Rig::new();
    rig.publish(2, V110);
    let inst = rig.open(V100, None);
    let updater = rig.updater(&inst);
    let (_, downloaded) = check_and_download(&rig, &updater);
    // One download per stage: a stage consumes its `Downloaded`.
    type Expect = Box<dyn Fn(&Error) -> bool>;
    let mut cases: Vec<(ConnectError, Expect)> = vec![
        (
            ConnectError::NotInstalled,
            Box::new(|e| {
                matches!(
                    e,
                    Error::ServiceUnavailable {
                        reason: ServiceReason::NotInstalled
                    }
                )
            }),
        ),
        (
            ConnectError::Disabled,
            Box::new(|e| {
                matches!(
                    e,
                    Error::ServiceUnavailable {
                        reason: ServiceReason::Disabled
                    }
                )
            }),
        ),
        (
            ConnectError::WrongOwner,
            Box::new(|e| {
                matches!(
                    e,
                    Error::ServiceUnavailable {
                        reason: ServiceReason::Untrusted
                    }
                )
            }),
        ),
        (
            ConnectError::Failed("start"),
            Box::new(|e| {
                matches!(
                    e,
                    Error::ServiceUnavailable {
                        reason: ServiceReason::StartFailed
                    }
                )
            }),
        ),
        (ConnectError::Busy, Box::new(|e| matches!(e, Error::Busy))),
    ];
    let mut downloaded = Some(downloaded);
    for (error, expect) in cases.drain(..) {
        let platform = rig.platform_for("alice", None, Arc::new(FakeConnector::failing(error)));
        let inst = rig.open_with(V100, platform);
        let updater = rig.updater(&inst);
        let d = match downloaded.take() {
            Some(d) => d,
            None => check_and_download(&rig, &updater).1,
        };
        let got = block_on(updater.stage(d)).expect_err("no service");
        assert!(expect(&got), "{error:?} gave {got:?}");
    }
    // A service that speaks only other protocol versions.
    let unsupported = FakeConnector::new(|_| {
        let (client, mut server) = mem_duplex();
        thread::spawn(move || {
            let _ = lunepack_core::service::read_frame(&mut server);
            let body = ServerHello::Unsupported { min: 7, max: 9 }
                .encode()
                .expect("hello");
            let _ = lunepack_core::service::write_frame(
                &mut server,
                lunepack_core::service::KIND_MESSAGE,
                &body,
            );
        });
        Ok(Box::new(client))
    });
    let platform = rig.platform_for("alice", None, Arc::new(unsupported));
    let inst = rig.open_with(V100, platform);
    let updater = rig.updater(&inst);
    let (_, d) = check_and_download(&rig, &updater);
    assert!(matches!(
        block_on(updater.stage(d)),
        Err(Error::ServiceUnsupported)
    ));
    rig.assert_read_only();
}

#[test]
fn a_stage_without_a_connector_is_still_machine_scope() {
    // The library never writes a machine install itself: a layout with no way to reach a service
    // keeps the old answer.
    let rig = Rig::new();
    rig.publish(2, V110);
    let inst = rig.open(V100, None);
    let layout_only = lunepack::UpdaterBuilder::new(
        app_id(),
        rig.world.root(),
        "https://fake.invalid/",
        channel(),
        lunepack::Layout::Machine {
            machine_state_dir: MachineLayout::new(&rig.root()).state_dir(),
            user_state_dir: rig.local.join("alice/state"),
            cache_dir: rig.local.join("alice/cache"),
            versions_dir: Some(MachineLayout::new(&rig.root()).app_dir()),
            current_tree: None,
        },
    )
    .transport(Arc::clone(&rig.world.transport))
    .fs(Arc::new(rig.world.fs.clone()))
    .hasher(Arc::new(FakeHasher))
    .verifier(Arc::new(FakeVerifier))
    .codec(Arc::new(FakeCodec::new()))
    .clock(Arc::clone(&rig.world.clock) as Arc<dyn lunepack_core::Clock>)
    .build()
    .expect("build");
    let info = block_on(layout_only.check())
        .expect("check")
        .expect("update");
    let d = block_on(layout_only.download(&info, DownloadOptions::default())).expect("download");
    assert!(matches!(
        block_on(layout_only.stage(d)),
        Err(Error::MachineScope)
    ));
    drop(inst);
}

// ---- startup: attempt ----------------------------------------------------------------------------

/// 1.1.0 staged and applied; returns the token the runtime's double got.
fn applied(rig: &Rig) -> lunepack_core::service::Token {
    rig.publish(2, V110);
    let inst = rig.open(V100, None);
    let updater = rig.updater(&inst);
    let (_, d) = check_and_download(rig, &updater);
    block_on(updater.stage(d)).expect("stage");
    rig.apply(V110)
}

#[test]
fn a_start_under_the_appliers_lease_is_supervised_and_counts_nothing() {
    let rig = Rig::new();
    let _token = applied(&rig);
    let attempts = rig.host.record().pending.as_ref().map(|p| p.attempts);
    let started = startup_for(&rig.open(V110, None), Vec::new()).expect("startup");
    assert_eq!(started.action, StartupAction::Continue);
    assert!(started.pending);
    assert_eq!(
        rig.host.record().pending.as_ref().map(|p| p.attempts),
        attempts
    );
    rig.assert_read_only();
}

#[test]
fn a_start_after_the_lease_is_counted_and_its_token_confirms() {
    let rig = Rig::new();
    let _lost = applied(&rig);
    rig.host.advance(10_000);
    let inst = rig.open(V110, None);
    let started = startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(started.action, StartupAction::Continue);
    assert!(started.pending);
    assert_eq!(
        rig.host.record().pending.as_ref().map(|p| p.attempts),
        Some(1)
    );
    // The same process confirms with the token it was issued.
    assert_eq!(
        confirm_for(&inst).expect("confirm"),
        ConfirmOutcome::Confirmed
    );
    assert!(rig.host.record().pending.is_none());
    rig.assert_read_only();
}

#[test]
fn the_fourth_start_rolls_back_and_starts_the_launcher_without_the_token() {
    let rig = Rig::new();
    let _lost = applied(&rig);
    for n in 1..=3u64 {
        rig.host.advance(10_000);
        let started = startup_for(&rig.open(V110, None), Vec::new()).expect("startup");
        assert_eq!(started.action, StartupAction::Continue, "attempt {n}");
        assert_eq!(
            rig.host.record().pending.as_ref().map(|p| p.attempts),
            Some(n)
        );
    }
    rig.host.advance(10_000);
    let args = vec![OsString::from("--open"), OsString::from("file")];
    let started = startup_for(&rig.open(V110, None), args.clone()).expect("startup");
    assert_eq!(started.action, StartupAction::Exit);
    assert!(started.events.is_empty() && !started.pending);
    let record = rig.host.record();
    assert_eq!(
        record.current.as_ref().map(|c| c.version.clone()),
        Some(version(V100))
    );
    assert!(record.bad.contains(&version(V110)));
    let spawns = rig.facade_process.spawns();
    let spawn = spawns.last().expect("the launcher was started");
    assert!(spawn.detached);
    assert_eq!(spawn.program, rig.root().join("app.exe"));
    assert_eq!(spawn.args, args);
    assert!(
        spawn
            .env_remove
            .iter()
            .any(|v| v == lunepack::HEALTH_TOKEN_VAR)
    );
    rig.assert_read_only();
}

/// A service whose `attempt` answers `answer`; any other request is refused.
fn scripted(answer: AttemptAnswer) -> Arc<dyn lunepack::ServiceConnector> {
    Arc::new(FakeConnector::new(move |app| {
        let (client, server) = mem_duplex();
        let (app, answer) = (app.clone(), answer.clone());
        thread::spawn(move || {
            let Ok(mut session) = ServerSession::accept(server, app) else {
                return;
            };
            while let Ok(Some(_request)) = session.next_request() {
                let _ = session.reply(&lunepack_core::service::Response::Attempt(answer.clone()));
            }
        });
        Ok(Box::new(client))
    }))
}

#[test]
fn a_version_the_service_says_is_not_pending_starts_normally() {
    let rig = Rig::new();
    let _ = applied(&rig);
    let platform = rig.platform_for("alice", None, scripted(AttemptAnswer::NotPending));
    let inst = rig.open_with(V110, platform);
    let started = startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(started.action, StartupAction::Continue);
    assert!(!started.pending || rig.host.record().pending.is_some());
}

#[test]
fn a_service_that_cannot_be_reached_never_stops_the_app_from_starting() {
    let rig = Rig::new();
    let _ = applied(&rig);
    for connector in [
        Arc::new(FakeConnector::failing(ConnectError::NotInstalled))
            as Arc<dyn lunepack::ServiceConnector>,
        Arc::new(FakeConnector::failing(ConnectError::Disabled)),
        Arc::new(FakeConnector::failing(ConnectError::WrongOwner)),
        Arc::new(FakeConnector::failing(ConnectError::Busy)),
    ] {
        let platform = rig.platform_for("alice", None, connector);
        let started = startup_for(&rig.open_with(V110, platform), Vec::new()).expect("startup");
        assert_eq!(started.action, StartupAction::Continue);
        assert!(started.pending);
    }
    rig.assert_read_only();
}

#[test]
fn a_service_that_never_answers_delays_the_start_by_the_bounded_wait_only() {
    let rig = Rig::new();
    let _ = applied(&rig);
    let hang = Arc::new(FakeConnector::new(|_| {
        thread::sleep(Duration::from_secs(3));
        Err(ConnectError::NotInstalled)
    }));
    let platform = rig
        .platform_for("alice", None, hang)
        .with_service_wait(Duration::from_millis(200));
    let start = std::time::Instant::now();
    let started = startup_for(&rig.open_with(V110, platform), Vec::new()).expect("startup");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(started.action, StartupAction::Continue);
    assert!(started.pending);
    rig.assert_read_only();
}

/// F3: an `attempt` the service answers only after the bounded wait still gives this process its
/// token. The start goes on without it; the token that comes later confirms, and no further start
/// is counted for it.
#[test]
fn an_attempt_answered_after_the_wait_still_gives_the_process_its_token() {
    let rig = Rig::new();
    let _lost = applied(&rig);
    rig.host.advance(10_000);
    let inner = rig.connector();
    let slow = Arc::new(FakeConnector::new(move |app| {
        thread::sleep(Duration::from_millis(600));
        lunepack_core::ServiceConnector::connect(&inner, app)
    }));
    let platform = rig
        .platform_for("alice", None, slow)
        .with_service_wait(Duration::from_millis(100));
    let inst = rig.open_with(V110, platform);
    let started = startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(started.action, StartupAction::Continue);
    assert!(
        started.pending,
        "the start did not wait for the late answer"
    );
    // The late answer arrives: the start is counted once and its token confirms. Until the
    // helper thread has kept it, `confirm` finds the start's lease (supervised) and does nothing.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let outcome = confirm_for(&inst).expect("confirm");
        if outcome == ConfirmOutcome::Confirmed {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the late token never reached the process"
        );
        thread::sleep(Duration::from_millis(50));
    }
    let record = rig.host.record();
    assert!(record.pending.is_none());
    assert_eq!(record.current.expect("current").version, version(V110));
    assert!(!record.bad.contains(&version(V110)));
    rig.assert_read_only();
}

// ---- confirm -------------------------------------------------------------------------------------

#[test]
fn a_token_that_is_not_the_versions_falls_back_to_one_attempt() {
    let rig = Rig::new();
    let _applier_token = applied(&rig);
    let wrong = lunepack_core::service::Token::from_bytes([0x42; 32]);
    // Under the applier's lease the attempt is supervised: nothing to do, nothing changed.
    let inst = rig.open(V110, Some(token_hex(&wrong)));
    assert_eq!(
        confirm_for(&inst).expect("confirm"),
        ConfirmOutcome::NothingPending
    );
    assert!(rig.host.record().pending.is_some());
    // After the lease the attempt is counted and its token confirms.
    rig.host.advance(10_000);
    let inst = rig.open(V110, Some(token_hex(&wrong)));
    assert_eq!(
        confirm_for(&inst).expect("confirm"),
        ConfirmOutcome::Confirmed
    );
    assert!(rig.host.record().pending.is_none());
    // A token that is not 64 hex digits is refused before any request.
    let connects = rig.host.connects.load(Ordering::SeqCst);
    let inst = rig.open(V110, Some(OsString::from("not a token")));
    assert!(matches!(confirm_for(&inst), Err(Error::TokenMismatch)));
    assert_eq!(rig.host.connects.load(Ordering::SeqCst), connects);
    rig.assert_read_only();
}

#[test]
fn confirm_with_no_token_and_nothing_pending_makes_no_request() {
    let rig = Rig::new();
    let connects = rig.host.connects.load(Ordering::SeqCst);
    assert_eq!(
        confirm_for(&rig.open(V100, None)).expect("confirm"),
        ConfirmOutcome::NothingPending
    );
    assert_eq!(rig.host.connects.load(Ordering::SeqCst), connects);
}

// ---- events --------------------------------------------------------------------------------------

#[test]
fn events_follow_this_users_last_run_and_come_once() {
    let rig = Rig::new();
    // A first run of 1.0.0; the record is read-only to the user and no event is queued in it.
    assert!(rig.host.record().lifecycle.is_none());
    let events = |user: &str, v: &str| {
        let platform = rig.platform_for(user, None, Arc::new(rig.connector()));
        startup_for(&rig.open_with(v, platform), Vec::new())
            .expect("startup")
            .events
    };
    let first = |v: &str| LifecycleEvent::FirstRun {
        version: version(v),
    };
    assert_eq!(events("alice", V100), vec![first(V100)]);
    assert!(events("alice", V100).is_empty());
    // Another user is a first run of their own.
    assert_eq!(events("bob", V100), vec![first(V100)]);
    assert_eq!(
        rig.user_counters("bob").and_then(|c| c.last_run),
        Some(version(V100))
    );
    // An update, for the user who ran the old one: updated, then first run. Not for a user who
    // never ran 1.0.0.
    let _ = applied(&rig);
    rig.host.advance(10_000);
    let inst = rig.open(V110, None);
    startup_for(&inst, Vec::new()).expect("alice starts 1.1.0");
    assert_eq!(
        confirm_for(&inst).expect("confirm"),
        ConfirmOutcome::Confirmed
    );
    assert_eq!(
        rig.user_counters("alice").and_then(|c| c.last_run),
        Some(version(V110))
    );
    let carol = events("carol", V110);
    assert_eq!(carol, vec![first(V110)]);
    let bob = events("bob", V110);
    assert_eq!(
        bob,
        vec![
            LifecycleEvent::Updated {
                from: version(V100),
                to: version(V110)
            },
            first(V110)
        ]
    );
    // A rollback: alice ran 1.1.0 and now runs 1.0.0 again: nothing is delivered, and the next
    // update is announced again.
    assert!(events("alice", V100).is_empty());
    assert_eq!(
        rig.user_counters("alice").and_then(|c| c.last_run),
        Some(version(V100))
    );
    assert_eq!(
        events("alice", V110),
        vec![
            LifecycleEvent::Updated {
                from: version(V100),
                to: version(V110)
            },
            first(V110)
        ]
    );
    // `installed` is never delivered on a machine install.
    assert!(
        !events("dave", V110)
            .iter()
            .any(|e| matches!(e, LifecycleEvent::Installed { .. }))
    );
    rig.assert_read_only();
}

// ---- the instruments and cancel ------------------------------------------------------------------

/// The control of `assert_read_only`: a write under `R` through the facade's filesystem is refused
/// and recorded, a write elsewhere is not.
#[test]
fn the_read_only_filesystem_records_and_refuses_a_write_under_r() {
    let rig = Rig::new();
    let fs = ReadOnlyUnder {
        inner: rig.world.fs.clone(),
        root: rig.root(),
        attempts: Arc::clone(&rig.attempts),
    };
    let under = rig.root().join("app").join("x.txt");
    assert!(fs.create_new(&under).is_err());
    assert_eq!(rig.attempts.lock().unwrap().len(), 1);
    assert!(fs.create_dir_all(&rig.local.join("alice/state")).is_ok());
    assert_eq!(rig.attempts.lock().unwrap().len(), 1);
    rig.attempts.lock().unwrap().clear();
}

#[test]
fn a_cancelled_stage_makes_no_connection() {
    let rig = Rig::new();
    rig.publish(2, V110);
    let inst = rig.open(V100, None);
    let updater = rig.updater(&inst);
    let (_, downloaded) = check_and_download(&rig, &updater);
    let cancel = lunepack_core::CancelToken::new();
    cancel.cancel();
    let downloaded = downloaded.with_options(DownloadOptions {
        progress: None,
        cancel: Some(cancel),
    });
    let connects = rig.host.connects.load(Ordering::SeqCst);
    assert!(matches!(
        block_on(updater.stage(downloaded)),
        Err(Error::Cancelled)
    ));
    assert_eq!(rig.host.connects.load(Ordering::SeqCst), connects);
    assert!(rig.host.record().staged.is_none());
    rig.assert_read_only();
}

// ---- delta patches over the service (M12-D6) ------------------------------------------------------

/// The request names under the fake origin since `from`, with their `Range` headers.
fn requests_since(rig: &Rig, from: usize) -> Vec<(String, Option<String>)> {
    rig.world.origin.requests()[from..]
        .iter()
        .map(|r| {
            (
                r.url
                    .strip_prefix(lunepack_testkit::FAKE_BASE_URL)
                    .unwrap_or(&r.url)
                    .trim_start_matches('/')
                    .to_owned(),
                r.range_header.clone(),
            )
        })
        .collect()
}

fn assert_staged_files(rig: &Rig, tree: &Path, v: &str) {
    for (name, bytes) in release_files(&rig.world, v, true) {
        assert_eq!(
            rig.host
                .fs
                .read_capped(&tree.join(name), 1 << 20)
                .expect("read"),
            bytes,
            "{name}"
        );
    }
}

/// A version-2 service takes the patches: the download fetches the delta file and no frame of the
/// pack, the stage uploads the patches, and the engine rebuilds the files from its own tree.
#[test]
fn a_version_2_service_stages_from_uploaded_patches() {
    let rig = Rig::with(2, true);
    let delta = rig.publish_with_delta(2, V110, V100);
    let inst = rig.open(V100, None);
    let updater = rig.updater(&inst);
    let before = rig.world.origin.requests().len();
    let (_, downloaded) = check_and_download(&rig, &updater);
    let staged = block_on(updater.stage(downloaded)).expect("stage");
    let reqs = requests_since(&rig, before);
    assert!(reqs.iter().any(|(n, _)| *n == delta), "{reqs:?}");
    assert!(
        reqs.iter().all(|(n, _)| *n != common::pack_path(V110)),
        "no frame of the patched files: {reqs:?}"
    );
    assert_eq!(staged.version(), &version(V110));
    assert_staged_files(&rig, staged.tree(), V110);
    rig.assert_read_only();
}

/// A version-1 service takes no patch: before its first commit the client fetches the frames of
/// the patched files by Range, and the update completes.
#[test]
fn a_version_1_service_gets_frames_fetched_before_the_first_commit() {
    let rig = Rig::with(1, true);
    let delta = rig.publish_with_delta(2, V110, V100);
    let inst = rig.open(V100, None);
    let updater = rig.updater(&inst);
    let (_, downloaded) = check_and_download(&rig, &updater);
    let before = rig.world.origin.requests().len();
    let connects = rig.host.connects.load(Ordering::SeqCst);
    let staged = block_on(updater.stage(downloaded)).expect("stage");
    let reqs = requests_since(&rig, before);
    assert!(reqs.iter().all(|(n, _)| *n != delta), "{reqs:?}");
    assert!(
        reqs.iter().any(|(n, _)| *n == common::pack_path(V110)),
        "the patched files' frames: {reqs:?}"
    );
    assert_eq!(
        rig.host.connects.load(Ordering::SeqCst) - connects,
        2,
        "one connection learns the version, one stages"
    );
    assert_eq!(staged.version(), &version(V110));
    assert_staged_files(&rig, staged.tree(), V110);
    rig.assert_read_only();
}
