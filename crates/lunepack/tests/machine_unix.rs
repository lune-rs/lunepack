//! M11 step 11: the facade on a per-machine install on Linux (`R = /opt/<app id>`, `R/current`) and
//! macOS (`R = /Library/Application Support/lunepack/<app id>`, the bundle in `/Applications`):
//! detection by location and record (never by an argument, an environment variable or a plist
//! value), the per-user home `<data home>/.lunepack/<app id>`, and `stage`, `attempt` and `confirm`
//! through the connector.
//!
//! The service is the core's real engine on the memory filesystem under the OS's machine scheme,
//! reached through the testkit's in-memory duplex. Both unix schemes run on any host: the facade
//! takes the scheme from the platform, and the machine home is a path in the memory filesystem.

mod common;

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use common::{World, app_id, channel, version};
use lunepack::{
    ConfirmOutcome, DownloadOptions, Error, Installation, LifecycleEvent, Platform, StartupAction,
    block_on, confirm_for, startup_for,
};
use lunepack_core::engine::{Engine, InstallRequest, Ports, install, serve};
use lunepack_core::service::{ClientSession, ClientTimeouts, ServerSession, Token};
use lunepack_core::setup::VerifiedSetup;
use lunepack_core::state::{InstallState, MachineScope, MachineStore, Scope};
use lunepack_core::{
    CodecId, Fs, InstallMeta, IntegrationError, IntegrationReport, IntegrationRequest,
    LayoutScheme, MachineLayout, MachineScheme, OsIntegration, PayloadKind, RelPath, Target,
    UpdateConfig, machine_user_home, verify_payload_manifest,
};
use lunepack_testkit::{
    FakeClock, FakeCodec, FakeConnector, FakeHasher, FakeIntegration, FakePolicy, FakeProcess,
    FakeProtect, FakePublisherCheck, FakeRegistrar, FakeRng, FakeVerifier, MemFs, MemPlace,
    PackBuilder, SUITE_T0, abs_path, mem_duplex,
};

const V100: &str = "1.0.0";
const V110: &str = "1.1.0";
const FEED: &str = "https://fake.invalid/";

/// What differs between the two unix machine installs.
#[derive(Clone, Copy)]
struct Os {
    name: &'static str,
    scheme: MachineScheme,
    per_user: LayoutScheme,
    target: Target,
    entry: &'static str,
    service: &'static str,
    config: &'static str,
    home: &'static str,
    data_home: &'static str,
}

const LINUX: Os = Os {
    name: "linux",
    scheme: MachineScheme::LINUX,
    per_user: LayoutScheme::XDG,
    target: Target::LinuxX86_64,
    entry: "bin/app",
    service: "bin/lunepack-service",
    config: "lunepack-update.json",
    home: "/opt",
    data_home: "/home/alice/.local/share",
};

const MACOS: Os = Os {
    name: "macos",
    scheme: MachineScheme::MACOS,
    per_user: LayoutScheme::MACOS,
    target: Target::MacosAarch64,
    entry: "Contents/MacOS/app",
    service: "Contents/MacOS/lunepack-service",
    config: "Contents/Resources/lunepack-update.json",
    home: "/Library/Application Support/lunepack",
    data_home: "/Users/alice/Library/Application Support",
};

const BOTH: [Os; 2] = [LINUX, MACOS];

fn is_mac(os: Os) -> bool {
    os.target.is_macos()
}

fn meta(os: Os) -> InstallMeta {
    InstallMeta {
        entry: RelPath::parse(os.entry).expect("entry"),
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

fn config_for(world: &World, os: Os, v: &str) -> UpdateConfig {
    UpdateConfig::new(
        &world.root(),
        version(v),
        os.target,
        FEED,
        channel(),
        60,
        meta(os),
    )
    .expect("config")
}

/// The release files of `v`: the entry (changes), the service, the update config.
fn release_pack(world: &World, os: Os, v: &str) -> PackBuilder {
    let mut pack = PackBuilder::new();
    pack.file(
        &FakeHasher,
        os.entry,
        format!("entry of {v}").repeat(20).as_bytes(),
        CodecId::Lzma2,
    )
    .file(
        &FakeHasher,
        os.service,
        format!("service of {v}").as_bytes(),
        CodecId::Lzma2,
    )
    .file(
        &FakeHasher,
        os.config,
        &config_for(world, os, v).to_bytes().expect("config bytes"),
        CodecId::Stored,
    );
    pack
}

/// The signed manifest of `pack` as the world's release key signs it.
fn manifest_bytes(world: &World, os: Os, v: &str, pack: &PackBuilder) -> Vec<u8> {
    world.fx.envelope(
        PayloadKind::Manifest,
        &world.fx.manifest_document(v, os.target, pack).to_payload(),
        &[1],
    )
}

/// The service's integration: the fake has none for the machine scope, and the system-wide files
/// are the adapters' own tests' business (steps 3 and 4), so every call is accepted.
struct MachineIntegration;

impl OsIntegration for MachineIntegration {
    fn check(&self, _: Scope, _: &IntegrationRequest) -> Result<(), IntegrationError> {
        Ok(())
    }

    fn apply(
        &self,
        _: Scope,
        _: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        Ok(IntegrationReport::default())
    }

    fn remove(
        &self,
        _: Scope,
        _: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        Ok(IntegrationReport::default())
    }
}

/// Everything the engine runs on.
struct Host {
    os: Os,
    fs: MemFs,
    protect: FakeProtect,
    policy: FakePolicy,
    integration: MachineIntegration,
    publisher: FakePublisherCheck,
    registrar: FakeRegistrar,
    process: FakeProcess,
    rng: FakeRng,
    clock: FakeClock,
    codec: FakeCodec,
    monotonic: AtomicU64,
}

impl Host {
    fn home(&self) -> PathBuf {
        abs_path(self.os.home)
    }

    fn root(&self) -> PathBuf {
        self.home().join(app_id().as_str())
    }

    fn ports(&self) -> Ports<'_> {
        Ports {
            fs: &self.fs,
            codec: &self.codec,
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
            scheme: self.os.scheme,
        }
    }

    fn record(&self) -> InstallState {
        MachineStore {
            dir: MachineLayout::with_scheme(&self.root(), self.os.scheme).state_dir(),
            app_id: app_id(),
        }
        .load(&self.fs, &FakeHasher)
        .expect("load")
        .record
        .expect("record")
    }
}

/// One machine install of 1.0.0 made by the engine's first install, and the facade's way in.
struct Rig {
    os: Os,
    world: World,
    host: Arc<Host>,
    facade_process: FakeProcess,
    server: Mutex<mpsc::Sender<(lunepack_testkit::MemDuplex, lunepack_core::AppId)>>,
}

impl Rig {
    fn new(os: Os) -> Rig {
        let world = World::new();
        let fs = world.fs.clone();
        for dir in [abs_path(os.home), abs_path("/Applications")] {
            fs.create_dir_all(&dir).expect("dirs");
            // Durable, as the system's folders are.
            let mut at = Some(dir.as_path());
            while let Some(d) = at {
                fs.sync_dir(d).expect("sync");
                at = d.parent();
            }
        }
        let host = Arc::new(Host {
            os,
            protect: FakeProtect::new(&MemFs::new()).with_fs(&fs),
            policy: FakePolicy::new(),
            integration: MachineIntegration,
            publisher: FakePublisherCheck::new([]),
            registrar: FakeRegistrar::new(),
            process: FakeProcess::new(abs_path("/Applications/Hello.app/Contents/MacOS/app")),
            rng: FakeRng::new(7),
            clock: FakeClock::new(SUITE_T0 + 3600),
            codec: FakeCodec::new(),
            monotonic: AtomicU64::new(1000),
            fs: fs.clone(),
        });
        // The first install: the payload the setup copied, verified under the world's keys.
        let pack = release_pack(&world, os, V100);
        let (_, keys) = world.fx.verified_chain(&[1], 1);
        let manifest = verify_payload_manifest(
            &keys,
            (&version(V100), os.target),
            &manifest_bytes(&world, os, V100, &pack),
            SUITE_T0,
            &FakeHasher,
            &FakeVerifier,
        )
        .expect("manifest");
        let setup = VerifiedSetup {
            manifest,
            config: config_for(&world, os, V100),
        };
        let dir = host.home().join(".hello-setup");
        fs.create_dir_all(&dir).expect("payload dir");
        let mut w = fs.create_new(&dir.join("pack")).expect("pack");
        w.write_all(&pack.bytes).expect("write");
        w.sync().expect("sync");
        fs.sync_dir(&dir).expect("sync");
        let apps = abs_path("/Applications");
        install(
            host.ports(),
            &InstallRequest {
                machine_home: &host.home(),
                display_name: "Hello",
                setup: &setup,
                keyset_version: 1,
                payload_dir: &dir,
                pack: &dir.join("pack"),
                apps_dir: is_mac(os).then_some(apps.as_path()),
            },
        )
        .expect("the engine's first install");

        let (tx, rx) = mpsc::channel();
        let serving = Arc::clone(&host);
        thread::spawn(move || {
            let mut engine: Option<Engine<'_>> = None;
            for (io, app) in rx {
                let Ok(session) = ServerSession::accept(io, app) else {
                    continue;
                };
                if engine.is_none() {
                    engine = Engine::open(serving.ports(), &serving.root()).ok();
                }
                let Some(engine) = engine.as_mut() else {
                    continue;
                };
                let now = || Duration::from_secs(serving.monotonic.load(Ordering::SeqCst));
                let _ = serve(session, engine, &now);
            }
        });
        Rig {
            os,
            world,
            host,
            facade_process: FakeProcess::new("/unused"),
            server: Mutex::new(tx),
        }
    }

    fn root(&self) -> PathBuf {
        self.host.root()
    }

    /// The bundle of a macOS install: the live bundle `R/bundle` names.
    fn bundle(&self) -> PathBuf {
        abs_path("/Applications/Hello.app")
    }

    /// Where the running executable of `v` is: on Linux `R/app/<v>`, on macOS the live bundle for
    /// the current version and `R/app/<v>` for a version a swap parked.
    fn exe(&self, v: &str, live: bool) -> PathBuf {
        let tree = if is_mac(self.os) && live {
            self.bundle()
        } else {
            self.root().join("app").join(v)
        };
        let mut path = tree;
        for part in self.os.entry.split('/') {
            path.push(part);
        }
        path
    }

    fn connector(&self) -> FakeConnector {
        let tx = self.server.lock().unwrap().clone();
        FakeConnector::new(move |app| {
            let (client, server) = mem_duplex();
            tx.send((server, app.clone())).expect("the service thread");
            Ok(Box::new(client))
        })
    }

    fn platform(&self, token: Option<OsString>) -> Platform {
        Platform::native()
            .with_fs(Arc::new(self.world.fs.clone()))
            .with_hasher(Arc::new(FakeHasher))
            .with_verifier(Arc::new(FakeVerifier))
            .with_process(Arc::new(self.facade_process.clone()))
            .with_integration(Arc::new(FakeIntegration::new()))
            .with_rng(Arc::new(FakeRng::new(9)))
            .with_health_token(token)
            .with_layout_scheme(self.os.per_user)
            .with_machine_scheme(self.os.scheme)
            .with_machine_home(self.host.home())
            .with_data_home(abs_path(self.os.data_home))
            .with_home(abs_path(if is_mac(self.os) {
                "/Users/alice"
            } else {
                "/home/alice"
            }))
            .with_service_connector(Arc::new(self.connector()))
            .with_policy_source(Arc::new(self.host.policy.clone()))
            .with_busy_wait(Duration::from_millis(300))
    }

    fn open(&self, exe: &Path, token: Option<OsString>) -> Installation {
        Installation::from_exe_with(exe, self.platform(token)).expect("installation")
    }

    fn updater(&self, inst: &Installation) -> lunepack::Updater {
        inst.updater_builder()
            .expect("builder")
            .transport(Arc::clone(&self.world.transport))
            .codec(Arc::new(FakeCodec::new()))
            .clock(Arc::clone(&self.world.clock) as Arc<dyn lunepack_core::Clock>)
            .workers(2)
            .build()
            .expect("build")
    }

    /// Publishes `v` as feed `seq`.
    fn publish(&self, seq: u64, v: &str) {
        let pack = release_pack(&self.world, self.os, v);
        let manifest = manifest_bytes(&self.world, self.os, v, &pack);
        let target = self.os.target.as_str();
        self.world
            .origin
            .put(&format!("{v}/{target}.manifest.json"), manifest.clone());
        self.world
            .origin
            .put(&format!("{v}/{target}.pack"), pack.bytes.clone());
        let release = self
            .world
            .fx
            .release(v, &[(self.os.target, &manifest)], None);
        self.world.publish_feed(seq, vec![release]);
    }

    /// A session of the runtime's double: `apply` of the staged version.
    fn apply(&self, v: &str) -> Token {
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
}

// ---- detection -----------------------------------------------------------------------------------

#[test]
fn a_tree_of_the_machine_home_with_a_machine_record_is_a_machine_install_on_both_oses() {
    for os in BOTH {
        let rig = Rig::new(os);
        let inst = rig.open(&rig.exe(V100, true), None);
        assert!(inst.is_machine() && inst.is_installed(), "{}", os.name);
        assert!(inst.layout().is_none(), "{}: no per-user layout", os.name);
        assert_eq!(
            inst.machine_layout().map(|l| l.root().to_path_buf()),
            Some(rig.root()),
            "{}",
            os.name
        );
        assert_eq!(
            inst.machine_layout().map(MachineLayout::scheme),
            Some(os.scheme),
            "{}",
            os.name
        );
        // M11-D10: `<data home>/.lunepack/<app id>`, never `<dir>/lunepack/<app id>`.
        assert_eq!(
            inst.user_home(),
            Some(machine_user_home(&abs_path(os.data_home), &app_id()).as_path()),
            "{}",
            os.name
        );
        assert!(
            inst.user_home()
                .is_some_and(|h| h.ends_with(format!(".lunepack/{}", app_id().as_str()))),
            "{}",
            os.name
        );
        // The updater runs on the machine layout (no write under R: nothing is created here).
        let _ = rig.updater(&inst);
    }
}

#[test]
fn a_machine_record_anywhere_else_or_none_is_not_a_machine_install_on_linux() {
    // The tree of a machine install, the machine home somewhere else.
    let rig = Rig::new(LINUX);
    let platform = rig.platform(None).with_machine_home(abs_path("/srv"));
    let got = Installation::from_exe_with(&rig.exe(V100, false), platform);
    assert!(
        !matches!(&got, Ok(inst) if inst.is_machine()),
        "a machine record outside the machine home: {:?}",
        got.as_ref().err()
    );
    // A tree in the machine home with no record at all (another app's folder).
    let rig = Rig::new(LINUX);
    let other = abs_path("/opt/org.other.app");
    let dir = other.join("app").join(V100);
    let cfg = config_for(&rig.world, LINUX, V100);
    rig.world.fs.create_dir_all(&dir.join("bin")).expect("dir");
    for (name, bytes) in [
        ("bin/app", b"entry".to_vec()),
        ("lunepack-update.json", cfg.to_bytes().expect("bytes")),
    ] {
        let mut w = rig.world.fs.create_new(&dir.join(name)).expect("create");
        w.write_all(&bytes).expect("write");
    }
    let got = Installation::from_exe_with(&dir.join("bin/app"), rig.platform(None));
    assert!(
        !matches!(&got, Ok(inst) if inst.is_machine()),
        "no record: {:?}",
        got.as_ref().err()
    );
    // A user record in a machine-shaped folder: the machine store refuses it.
    let rig = Rig::new(LINUX);
    let root = abs_path("/opt/org.user.app");
    let dir = root.join("app").join(V100);
    rig.world.fs.create_dir_all(&dir.join("bin")).expect("dir");
    for (name, bytes) in [
        ("bin/app", b"entry".to_vec()),
        ("lunepack-update.json", cfg.to_bytes().expect("bytes")),
    ] {
        let mut w = rig.world.fs.create_new(&dir.join(name)).expect("create");
        w.write_all(&bytes).expect("write");
    }
    let layout = MachineLayout::with_scheme(&root, MachineScheme::LINUX);
    rig.world
        .fs
        .create_dir_all(&layout.state_dir())
        .expect("state");
    let store = lunepack_core::state::UserScope {
        dir: layout.state_dir(),
        app_id: app_id(),
    };
    let loaded = store.load(&rig.world.fs, &FakeHasher).expect("load");
    let record = InstallState::new(1, app_id(), Scope::User, [3; 16], LINUX.target).install(
        version(V100),
        SUITE_T0,
        LINUX.target,
        [3; 16],
    );
    store
        .commit(&rig.world.fs, &loaded, &record, &FakeHasher)
        .expect("commit");
    let got = Installation::from_exe_with(&dir.join("bin/app"), rig.platform(None));
    assert!(
        !matches!(&got, Ok(inst) if inst.is_machine()),
        "a user record: {:?}",
        got.as_ref().err()
    );
}

#[test]
fn a_macos_bundle_is_a_machine_install_when_it_is_the_live_bundle_or_a_parked_old_tree() {
    let rig = Rig::new(MACOS);
    // The live bundle `R/bundle` names.
    let live = rig.open(&rig.exe(V100, true), None);
    assert!(live.is_machine() && !live.adoptable() && !live.moved());
    assert_eq!(
        live.machine_layout().map(|l| l.root().to_path_buf()),
        Some(rig.root())
    );

    // After an update the old tree is parked in `R/app/<old>` (FORMAT 17.2 step 2) and is still
    // the install's: the old instance a user may still be running.
    rig.publish(2, V110);
    let updater = rig.updater(&live);
    let info = block_on(updater.check()).expect("check").expect("update");
    let downloaded =
        block_on(updater.download(&info, DownloadOptions::default())).expect("download");
    block_on(updater.stage(downloaded)).expect("stage");
    let token = rig.apply(V110);
    let parked_exe = rig.exe(V100, false);
    assert!(
        rig.world
            .fs
            .symlink_metadata(&parked_exe)
            .expect("lstat")
            .is_some(),
        "the swap parked the old tree: {}",
        parked_exe.display()
    );
    let old = rig.open(&parked_exe, None);
    assert!(old.is_machine(), "the parked old tree");
    assert_eq!(old.tree_version(), &version(V100));
    // The new live bundle holds 1.1.0.
    let new = rig.open(&rig.exe(V110, true), Some(OsString::from(token.to_hex())));
    assert!(new.is_machine());
    assert_eq!(new.tree_version(), &version(V110));
}

#[test]
fn a_bundle_that_is_neither_the_live_one_nor_a_parked_tree_is_not_a_machine_install() {
    let rig = Rig::new(MACOS);
    // A copy of the app next to the live bundle (a root-owned bundle of another name, or the user's
    // own copy): same config, no pointer to it, not a parked tree.
    let copy = abs_path("/Applications/Hello copy.app");
    let cfg = config_for(&rig.world, MACOS, V100);
    for (name, bytes) in [
        ("Contents/MacOS/app", b"entry".to_vec()),
        (
            "Contents/Resources/lunepack-update.json",
            cfg.to_bytes().expect("bytes"),
        ),
    ] {
        let at = copy.join(name);
        rig.world
            .fs
            .create_dir_all(at.parent().expect("parent"))
            .expect("dir");
        let mut w = rig.world.fs.create_new(&at).expect("create");
        w.write_all(&bytes).expect("write");
    }
    let got = Installation::from_exe_with(&copy.join("Contents/MacOS/app"), rig.platform(None));
    assert!(
        !matches!(&got, Ok(inst) if inst.is_machine()),
        "a copy that no pointer names: {:?}",
        got.as_ref().err()
    );
    // A root-owned copy that is neither stays a machine scope the user cannot update (exit 17):
    // never a machine install of this app, never adopted.
    rig.world.fs.set_place(
        &copy,
        MemPlace {
            owned_by_caller: false,
            owned_by_root: true,
            ..MemPlace::default()
        },
    );
    rig.publish(1, V100);
    let inst = Installation::from_exe_with(&copy.join("Contents/MacOS/app"), rig.platform(None))
        .expect("installation");
    assert!(!inst.is_machine());
    let got = block_on(rig.updater(&inst).check());
    assert!(matches!(got, Err(Error::MachineScope)), "{got:?}");
    // No machine record: a bundle of an app that has none (the machine home is empty).
    let empty = Rig::new(MACOS);
    let platform = empty
        .platform(None)
        .with_machine_home(abs_path("/Library/elsewhere"));
    let got = Installation::from_exe_with(&empty.exe(V100, true), platform);
    assert!(
        !matches!(&got, Ok(inst) if inst.is_machine()),
        "the machine home does not hold R: {:?}",
        got.as_ref().err()
    );
}

// ---- the whole cycle through the connector -------------------------------------------------------

#[test]
fn check_download_stage_apply_startup_confirm_over_the_service_on_both_oses() {
    for os in BOTH {
        let rig = Rig::new(os);
        let inst = rig.open(&rig.exe(V100, true), None);
        let first = startup_for(&inst, Vec::new()).expect("startup");
        assert_eq!(first.action, StartupAction::Continue, "{}", os.name);
        assert!(!first.pending, "{}", os.name);
        assert_eq!(
            first.events,
            vec![LifecycleEvent::FirstRun {
                version: version(V100)
            }],
            "{}",
            os.name
        );

        // check and download run as the user: the counters rise in the user's home, not in R.
        rig.publish(2, V110);
        let updater = rig.updater(&inst);
        let info = block_on(updater.check())
            .expect("check")
            .expect("an update");
        assert_eq!(info.version(), &version(V110), "{}", os.name);
        let downloaded =
            block_on(updater.download(&info, DownloadOptions::default())).expect("download");
        assert_eq!(
            rig.host.record().floors.feed_seq.get(&channel()),
            None,
            "{}: the machine record is the service's",
            os.name
        );
        let counters = MachineScope {
            machine_dir: MachineLayout::with_scheme(&rig.root(), os.scheme).state_dir(),
            user_dir: machine_user_home(&abs_path(os.data_home), &app_id()).join("state"),
            app_id: app_id(),
        }
        .load_counters(&rig.world.fs, &rig.host.record(), &FakeHasher)
        .expect("counters")
        .record
        .expect("this user's counters");
        assert_eq!(
            counters.floors.feed_seq.get(&channel()),
            Some(&2),
            "{}",
            os.name
        );

        // stage goes to the service through the connector.
        let staged = block_on(updater.stage(downloaded)).expect("stage");
        assert_eq!(staged.version(), &version(V110), "{}", os.name);
        assert_eq!(
            rig.host.record().staged.as_ref().map(|s| s.version.clone()),
            Some(version(V110)),
            "{}",
            os.name
        );

        // The runtime's double applies; the engine projects the new version.
        let token = rig.apply(V110);
        assert!(rig.host.record().pending.is_some(), "{}", os.name);

        // attempt: the new version starts supervised with its token; confirm.
        let new = rig.open(&rig.exe(V110, true), Some(OsString::from(token.to_hex())));
        let started = startup_for(&new, Vec::new()).expect("startup");
        assert_eq!(started.action, StartupAction::Continue, "{}", os.name);
        assert!(started.pending, "{}: waiting for the health check", os.name);
        assert_eq!(
            confirm_for(&new).expect("confirm"),
            ConfirmOutcome::Confirmed,
            "{}",
            os.name
        );
        let record = rig.host.record();
        assert!(
            record.pending.is_none() && record.health.is_none(),
            "{}",
            os.name
        );
        assert_eq!(
            record.current.expect("current").version,
            version(V110),
            "{}",
            os.name
        );
        // Confirmed once.
        assert_eq!(
            confirm_for(&rig.open(&rig.exe(V110, true), Some(OsString::from(token.to_hex()))))
                .expect("again"),
            ConfirmOutcome::NothingPending,
            "{}",
            os.name
        );
    }
}
