//! M10 step 6: the engine's first install, service switch, reconcile, GC, repair and uninstall,
//! over the fakes; and the machine layout helpers.

use std::path::{Path, PathBuf};
use std::time::Duration;

use lunepack_core::engine::{Engine, InstallRequest, MachineOpError, Ports, install};
use lunepack_core::service::{CommitOutcome, ConfirmAnswer, ObjectKind, Token};
use lunepack_core::setup::VerifiedSetup;
use lunepack_core::{
    AppId, Channel, CodecId, DirClass, Fs, Hasher, InstallMeta, InstallState, MachineLayout,
    MachineStore, PayloadKind, RelPath, RootChoice, SERVICE_FILE, Scope, Target,
    UPDATE_CONFIG_FILE, UpdateConfig, Version, verify_payload_manifest,
};
use lunepack_testkit::{
    ChainFixture, FakeClock, FakeCodec, FakeHasher, FakeMachineIntegration, FakePolicy,
    FakeProcess, FakeProtect, FakePublisherCheck, FakeRegistrar, FakeRng, FakeVerifier, FaultFs,
    MemFs, PackBuilder, SUITE_APP_ID, SUITE_T0, abs_path,
};

const TARGET: Target = Target::WindowsX86_64;

fn v(t: &str) -> Version {
    Version::parse(t).unwrap()
}

fn app() -> AppId {
    AppId::parse(SUITE_APP_ID).unwrap()
}

fn fx() -> ChainFixture<'static> {
    ChainFixture::fake()
}

fn meta() -> InstallMeta {
    InstallMeta {
        entry: RelPath::parse("app.exe").unwrap(),
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

fn config_bytes(version: &str) -> Vec<u8> {
    UpdateConfig::new(
        &fx().trusted_root(1, 1, &[0]),
        v(version),
        TARGET,
        "https://updates.example.org/hello/",
        Channel::parse("stable").unwrap(),
        60,
        meta(),
    )
    .unwrap()
    .to_bytes()
    .unwrap()
}

fn pack_of(version: &str, service: bool) -> PackBuilder {
    let fx = fx();
    let mut pack = PackBuilder::new();
    pack.file(
        fx.hasher,
        "app.exe",
        format!("entry of {version}").as_bytes(),
        CodecId::Lzma2,
    );
    if service {
        pack.file(
            fx.hasher,
            SERVICE_FILE,
            format!("service of {version}").as_bytes(),
            CodecId::Lzma2,
        );
    }
    pack.file(
        fx.hasher,
        UPDATE_CONFIG_FILE,
        &config_bytes(version),
        CodecId::Stored,
    );
    pack
}

fn manifest_bytes(version: &str, pack: &PackBuilder) -> Vec<u8> {
    let fx = fx();
    fx.envelope(
        PayloadKind::Manifest,
        &fx.manifest_document(version, TARGET, pack).to_payload(),
        &[5],
    )
}

/// A verified setup payload of `version` and its pack.
fn payload(version: &str, service: bool) -> (VerifiedSetup, PackBuilder) {
    let fx = fx();
    let pack = pack_of(version, service);
    let (_, keys) = fx.verified_chain(&[5], 1);
    let manifest = verify_payload_manifest(
        &keys,
        (&v(version), TARGET),
        &manifest_bytes(version, &pack),
        SUITE_T0,
        &FakeHasher,
        &FakeVerifier,
    )
    .unwrap();
    let config = UpdateConfig::parse(&config_bytes(version)).unwrap();
    (VerifiedSetup { manifest, config }, pack)
}

/// The signed documents of an update to `version` (feed seq `seq`).
struct Update {
    keys: Vec<u8>,
    feed: Vec<u8>,
    manifest: Vec<u8>,
    pack: PackBuilder,
}

fn update(version: &str, seq: u64) -> Update {
    let fx = fx();
    let pack = pack_of(version, true);
    let manifest = manifest_bytes(version, &pack);
    let keys = fx.envelope(
        PayloadKind::Keys,
        &fx.keyset_document(1, 1, None, 1, &[5]).to_payload(),
        &[0],
    );
    let feed = fx.envelope(
        PayloadKind::Feed,
        &fx.feed_document(
            seq,
            None,
            vec![fx.release(version, &[(TARGET, &manifest)], None)],
        )
        .to_payload(),
        &[5],
    );
    Update {
        keys,
        feed,
        manifest,
        pack,
    }
}

/// A machine home with every port faked.
struct Host {
    mem: MemFs,
    fs: FaultFs,
    protect: FakeProtect,
    policy: FakePolicy,
    integration: FakeMachineIntegration,
    publisher: FakePublisherCheck,
    registrar: FakeRegistrar,
    process: FakeProcess,
    rng: FakeRng,
    clock: FakeClock,
    codec: FakeCodec,
    home: PathBuf,
}

impl Host {
    fn new() -> Host {
        let mem = MemFs::new();
        let home = abs_path("/pf");
        mem.create_dir_all(&home).unwrap();
        Host {
            fs: FaultFs::new(&mem),
            protect: FakeProtect::new(&mem),
            policy: FakePolicy::new(),
            integration: FakeMachineIntegration::new(),
            publisher: FakePublisherCheck::new([]),
            registrar: FakeRegistrar::new(),
            process: FakeProcess::new(abs_path("/pf/Hello/app/1.0.0/app.exe")),
            rng: FakeRng::new(11),
            clock: FakeClock::new(SUITE_T0 + 3600),
            codec: FakeCodec::new(),
            home,
            mem,
        }
    }

    fn ports(&self) -> Ports<'_> {
        self.ports_with(&self.rng)
    }

    fn ports_with<'a>(&'a self, rng: &'a FakeRng) -> Ports<'a> {
        Ports {
            fs: &self.fs,
            codec: &self.codec,
            hasher: &FakeHasher,
            verifier: &FakeVerifier,
            clock: &self.clock,
            rng,
            integration: &self.integration,
            publisher: &self.publisher,
            protect: &self.protect,
            policy: &self.policy,
            registrar: &self.registrar,
            process: &self.process,
        }
    }

    fn root(&self) -> PathBuf {
        self.home.join("Hello")
    }

    fn layout(&self) -> MachineLayout {
        MachineLayout::new(&self.root())
    }

    fn payload_dir(&self) -> PathBuf {
        self.home.join(".hello-setup")
    }

    /// Copies `pack` into the admin-only payload folder, as the host does.
    fn stage_payload(&self, pack: &PackBuilder) -> PathBuf {
        let dir = self.payload_dir();
        if !self.exists(&dir) {
            self.mem.create_dir_all(&dir).unwrap();
        }
        let path = dir.join("pack");
        if self.exists(&path) {
            self.mem.remove_file(&path).unwrap();
        }
        self.write(&path, &pack.bytes);
        path
    }

    fn write(&self, path: &Path, bytes: &[u8]) {
        let mut w = self.mem.create_new(path).unwrap();
        std::io::Write::write_all(&mut w, bytes).unwrap();
        w.sync().unwrap();
    }

    fn exists(&self, p: &Path) -> bool {
        self.mem.symlink_metadata(p).unwrap().is_some()
    }

    fn install_with(
        &self,
        ports: Ports<'_>,
        version: &str,
        service: bool,
    ) -> Result<PathBuf, MachineOpError> {
        let (setup, pack) = payload(version, service);
        let pack_path = self.stage_payload(&pack);
        install(
            ports,
            &InstallRequest {
                machine_home: &self.home,
                display_name: "Hello",
                setup: &setup,
                keyset_version: 1,
                payload_dir: &self.payload_dir(),
                pack: &pack_path,
            },
        )
        .map(|i| i.root)
    }

    fn install(&self, version: &str) -> Result<PathBuf, MachineOpError> {
        self.install_with(self.ports(), version, true)
    }

    fn record(&self) -> InstallState {
        MachineStore {
            dir: self.layout().state_dir(),
            app_id: app(),
        }
        .load(&self.mem, &FakeHasher)
        .unwrap()
        .record
        .unwrap()
    }

    fn engine(&self) -> Engine<'_> {
        Engine::open(self.ports(), &self.root()).expect("open")
    }

    fn registered(&self) -> Option<PathBuf> {
        lunepack_core::ServiceRegistrar::image(&self.registrar, &app()).unwrap()
    }
}

/// Stages `version` through the engine's own operations with the pack.
fn stage(engine: &mut Engine<'_>, u: &Update) {
    let mut session = engine
        .stage_begin(
            &Channel::parse("stable").unwrap(),
            &[],
            &u.keys,
            &u.feed,
            &u.manifest,
        )
        .unwrap()
        .expect("an update");
    let sha = FakeHasher.sha256(&u.pack.bytes);
    engine
        .put_check(&session, ObjectKind::Pack, &sha, u.pack.bytes.len() as u64)
        .unwrap();
    let mut w = engine
        .put_open(&session, &sha, u.pack.bytes.len() as u64)
        .unwrap();
    std::io::Write::write_all(&mut w, &u.pack.bytes).unwrap();
    engine.put_finish(&mut session, &sha, w).unwrap();
    assert!(matches!(
        engine.stage_commit(&mut session, &mut |_, _| {}).unwrap(),
        CommitOutcome::Staged(_)
    ));
}

/// Stages, applies and confirms `version`.
fn update_to(engine: &mut Engine<'_>, version: &str, seq: u64) -> ConfirmAnswer {
    stage(engine, &update(version, seq));
    let token: Token = engine.apply(&v(version), Duration::from_secs(1)).unwrap();
    engine.confirm(&v(version), &token).unwrap()
}

// ---- the first install ---------------------------------------------------------------------------

#[test]
fn the_first_install_in_order() {
    let h = Host::new();
    let root = h.install("1.0.0").unwrap();
    assert_eq!(root, h.root());
    let l = h.layout();
    let created: Vec<(PathBuf, DirClass)> = h.protect.created();
    assert_eq!(
        created,
        vec![
            (l.root().to_path_buf(), DirClass::MachineTree),
            (l.app_dir(), DirClass::MachineTree),
            (l.lunepack_dir(), DirClass::MachineTree),
            (l.state_dir(), DirClass::MachineTree),
            (l.machine_dir(), DirClass::AdminOnly),
            (l.service_dir(), DirClass::AdminOnly),
            (l.service_version_dir(&v("1.0.0")), DirClass::AdminOnly),
        ]
    );
    let rec = h.record();
    assert_eq!(rec.scope, Scope::Machine);
    assert_eq!(rec.current.as_ref().unwrap().version, v("1.0.0"));
    assert_eq!(rec.floors.keyset_version, 1);
    assert_eq!(
        rec.floors.root.as_ref().unwrap().version,
        1,
        "the setup's root"
    );
    let ops: Vec<&str> = h.integration.calls().iter().map(|c| c.0).collect();
    assert_eq!(ops, ["check", "apply"]);
    assert!(h.integration.calls().iter().all(|c| c.1 == Scope::Machine));
    let image = l.service_image(&v("1.0.0"));
    assert!(h.exists(&image));
    assert_eq!(h.registrar.self_tests(), vec![image.clone()]);
    assert_eq!(h.registered(), Some(image));
    assert!(!h.exists(&h.payload_dir()), "the payload copy is removed");
    assert!(h.exists(&l.version_dir(&v("1.0.0")).join("app.exe")));
    // The engine opens over it.
    let engine = h.engine();
    assert_eq!(engine.status().unwrap().service, v("1.0.0"));
}

#[test]
fn already_installed() {
    let h = Host::new();
    h.install("1.0.0").unwrap();
    assert_eq!(h.install("1.0.0"), Err(MachineOpError::AlreadyInstalled));
    assert_eq!(h.record().current.unwrap().version, v("1.0.0"));
}

#[test]
fn a_release_without_the_service_binary_is_per_user_only() {
    let h = Host::new();
    assert_eq!(
        h.install_with(h.ports(), "1.0.0", false),
        Err(MachineOpError::PerMachineUnavailable)
    );
    assert!(!h.exists(&h.root()), "nothing was created");
    assert!(h.protect.created().is_empty());
    assert!(!h.exists(&h.payload_dir()));
}

#[test]
fn a_taken_folder_is_folder_taken() {
    let h = Host::new();
    for name in ["Hello", "Hello (org.example.hello)"] {
        let dir = h.home.join(name);
        h.mem.create_dir_all(&dir).unwrap();
        h.write(&dir.join("foreign.txt"), b"x");
    }
    assert_eq!(h.install("1.0.0"), Err(MachineOpError::FolderTaken));
    assert!(h.exists(&h.home.join("Hello").join("foreign.txt")));
}

/// Asserts that a failed install left nothing: no root (or the pre-existing one empty), no
/// registration, no applied integration, no payload copy.
fn assert_clean(h: &Host, root_existed: bool) {
    if root_existed {
        assert!(h.mem.list_dir(&h.root()).unwrap().is_empty());
    } else {
        assert!(!h.exists(&h.root()), "the root this run created is gone");
    }
    assert_eq!(h.registered(), None);
    assert!(!h.integration.is_applied());
    assert!(!h.exists(&h.payload_dir()));
}

#[test]
fn every_failure_point_cleans_up() {
    type Inject = fn(&Host);
    let cases: Vec<(&str, Inject, MachineOpError)> = vec![
        (
            "(3) a protected directory",
            |h| h.protect.fail_create(&h.layout().machine_dir()),
            MachineOpError::NotProtected,
        ),
        (
            "(4) the first record",
            |h| h.fs.fail_create_in(&h.layout().state_dir()),
            MachineOpError::Failed("write the first record"),
        ),
        (
            "(6) the integration check",
            |h| h.integration.fail("check"),
            MachineOpError::Integration,
        ),
        (
            "(6) the integration apply",
            |h| h.integration.fail("apply"),
            MachineOpError::Integration,
        ),
        (
            "(7) the service folder",
            |h| h.protect.fail_create(&h.layout().service_dir()),
            MachineOpError::NotProtected,
        ),
        (
            "(7) the self-test",
            |h| {
                h.registrar
                    .fail_self_test(&h.layout().service_image(&v("1.0.0")))
            },
            MachineOpError::SelfTest,
        ),
        (
            "(7) the registration",
            |h| h.registrar.fail_register(true),
            MachineOpError::Failed("register the service"),
        ),
    ];
    for root_existed in [false, true] {
        for (what, inject, want) in &cases {
            let h = Host::new();
            if root_existed {
                h.mem.create_dir_all(&h.root()).unwrap();
                h.protect.mark(&h.root(), DirClass::MachineTree);
            }
            inject(&h);
            assert_eq!(h.install("1.0.0"), Err(*want), "{what}");
            assert_clean(&h, root_existed);
        }
    }
    // (4) the install id's randomness.
    let h = Host::new();
    let failing = FakeRng::failing();
    assert_eq!(
        h.install_with(h.ports_with(&failing), "1.0.0", true),
        Err(MachineOpError::Failed("randomness"))
    );
    assert_clean(&h, false);
    // (5) a damaged pack copy.
    let h = Host::new();
    let (setup, mut pack) = payload("1.0.0", true);
    let last = pack.bytes.len() - 1;
    pack.bytes[last] ^= 1;
    let pack_path = h.stage_payload(&pack);
    let r = install(
        h.ports(),
        &InstallRequest {
            machine_home: &h.home,
            display_name: "Hello",
            setup: &setup,
            keyset_version: 1,
            payload_dir: &h.payload_dir(),
            pack: &pack_path,
        },
    );
    assert_eq!(r.err(), Some(MachineOpError::Verify));
    assert_clean(&h, false);
}

// ---- the service switch ----------------------------------------------------------------------------

#[test]
fn the_service_switches_on_confirm() {
    let h = Host::new();
    h.install("1.0.0").unwrap();
    let mut engine = h.engine();
    let l = h.layout();
    assert_eq!(update_to(&mut engine, "1.1.0", 2), ConfirmAnswer::Confirmed);
    assert_eq!(h.registered(), Some(l.service_image(&v("1.1.0"))));
    assert!(
        h.exists(&l.service_version_dir(&v("1.0.0"))),
        "the replaced binary is kept"
    );
    assert_eq!(engine.status().unwrap().service, v("1.1.0"));
    assert_eq!(update_to(&mut engine, "1.2.0", 3), ConfirmAnswer::Confirmed);
    assert_eq!(h.registered(), Some(l.service_image(&v("1.2.0"))));
    assert!(h.exists(&l.service_version_dir(&v("1.1.0"))));
    assert!(
        !h.exists(&l.service_version_dir(&v("1.0.0"))),
        "older binaries go"
    );
}

#[test]
fn a_failing_self_test_keeps_the_registration_and_reconcile_redoes_it() {
    let h = Host::new();
    h.install("1.0.0").unwrap();
    let l = h.layout();
    let new_image = l.service_image(&v("1.1.0"));
    h.registrar.fail_self_test(&new_image);
    {
        let mut engine = h.engine();
        assert_eq!(update_to(&mut engine, "1.1.0", 2), ConfirmAnswer::Confirmed);
        assert_eq!(h.registered(), Some(l.service_image(&v("1.0.0"))));
        assert_eq!(
            engine.status().unwrap().service,
            v("1.0.0"),
            "status names the registered binary"
        );
    }
    // As after a crash between the confirm and the switch: the next open switches.
    h.registrar.pass_self_test(&new_image);
    let _engine = h.engine();
    assert_eq!(h.registered(), Some(new_image));
}

// ---- GC ---------------------------------------------------------------------------------------------

fn make_tree(h: &Host, version: &str) {
    let dir = h.layout().app_dir().join(version);
    h.mem.create_dir_all(&dir).unwrap();
    h.write(&dir.join("app.exe"), b"old");
}

/// The names in `dir`, in listing order.
fn names_in(h: &Host, dir: &Path) -> Vec<String> {
    h.mem
        .list_dir(dir)
        .unwrap()
        .into_iter()
        .map(|e| e.name.to_string_lossy().into_owned())
        .collect()
}

/// The paths `tree_in_use_strict` was asked about from call `from` on; the engine never asks the
/// weaker `tree_in_use`.
fn strict_from(h: &Host, from: usize) -> Vec<PathBuf> {
    assert!(
        h.process.in_use_calls().is_empty(),
        "the engine asked tree_in_use"
    );
    h.process
        .strict_calls()
        .into_iter()
        .skip(from)
        .map(|(p, exclude)| {
            assert!(exclude.is_empty(), "the engine excludes nothing");
            p
        })
        .collect()
}

fn is_gc_name(p: &Path, app_dir: &Path) -> bool {
    p.parent() == Some(app_dir)
        && p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(".gc-") && n.len() == 4 + 16)
}

#[test]
fn gc_keeps_current_previous_and_pending_and_skips_busy_trees() {
    let h = Host::new();
    h.install("1.0.0").unwrap();
    let mut engine = h.engine();
    update_to(&mut engine, "1.1.0", 2);
    // 1.2.0 applied, pending: current and pending 1.2.0, previous 1.1.0.
    stage(&mut engine, &update("1.2.0", 3));
    engine.apply(&v("1.2.0"), Duration::from_secs(1)).unwrap();
    drop(engine);
    for t in ["0.7.0", "0.8.0", "0.9.0"] {
        make_tree(&h, t);
    }
    let l = h.layout();
    let app_dir = l.app_dir();
    // Listing order: 0.7.0, 0.8.0, 0.9.0, 1.0.0 (the old current, not kept).
    // 0.7.0: free, renamed, free again: removed.
    h.process.script_in_use_strict(false);
    h.process.script_in_use_strict(false);
    // 0.8.0: in use at the first check: kept, not renamed.
    h.process.script_in_use_strict(true);
    // 0.9.0: free, but its rename fails: kept.
    h.process.script_in_use_strict(false);
    h.fs.fail_rename_from(&app_dir.join("0.9.0"));
    // 1.0.0: free, renamed, in use at the second check: its `.gc-` folder stays.
    h.process.script_in_use_strict(false);
    h.process.script_in_use_strict(true);
    let from = h.process.strict_calls().len();
    drop(h.engine());
    let names = names_in(&h, &app_dir);
    assert_eq!(names.len(), 5, "{names:?}");
    assert!(names[0].starts_with(".gc-"), "{names:?}");
    assert_eq!(names[1..], ["0.8.0", "0.9.0", "1.1.0", "1.2.0"]);
    let busy = app_dir.join(&names[0]);
    assert!(
        h.exists(&busy.join("app.exe")),
        "the busy tree is whole under its new name"
    );
    let asked = strict_from(&h, from);
    assert_eq!(asked.len(), 6, "{asked:?}");
    assert_eq!(asked[0], app_dir.join("0.7.0"));
    assert!(is_gc_name(&asked[1], &app_dir), "{asked:?}");
    assert_ne!(asked[1], busy);
    assert_eq!(
        asked[2..],
        [
            app_dir.join("0.8.0"),
            app_dir.join("0.9.0"),
            app_dir.join("1.0.0"),
            busy.clone(),
        ]
    );
    // The next open removes the `.gc-` folder once the check says free; 0.8.0 and 0.9.0 are
    // busy this time.
    h.process.script_in_use_strict(false);
    h.process.script_in_use_strict(true);
    h.process.script_in_use_strict(true);
    let from = h.process.strict_calls().len();
    drop(h.engine());
    assert_eq!(names_in(&h, &app_dir), ["0.8.0", "0.9.0", "1.1.0", "1.2.0"]);
    assert_eq!(
        strict_from(&h, from),
        [busy, app_dir.join("0.8.0"), app_dir.join("0.9.0")]
    );
}

#[test]
fn gc_leaves_a_tree_whose_removal_fails() {
    let h = Host::new();
    h.install("1.0.0").unwrap();
    let mut engine = h.engine();
    update_to(&mut engine, "1.1.0", 2);
    drop(engine);
    make_tree(&h, "0.9.0");
    let app_dir = h.layout().app_dir();
    h.fs.fail_remove_in(&app_dir);
    let from = h.process.strict_calls().len();
    drop(h.engine());
    let names = names_in(&h, &app_dir);
    assert_eq!(names.len(), 3, "{names:?}");
    assert!(names[0].starts_with(".gc-"), "{names:?}");
    assert_eq!(names[1..], ["1.0.0", "1.1.0"]);
    let asked = strict_from(&h, from);
    assert_eq!(asked.len(), 2, "{asked:?}");
    assert_eq!(asked[0], app_dir.join("0.9.0"));
    assert_eq!(asked[1], app_dir.join(&names[0]));
}

#[test]
fn gc_keeps_the_staged_tree() {
    let h = Host::new();
    h.install("1.0.0").unwrap();
    let mut engine = h.engine();
    update_to(&mut engine, "1.1.0", 2);
    stage(&mut engine, &update("1.2.0", 3));
    drop(engine);
    let _engine = h.engine();
    let l = h.layout();
    assert!(h.exists(&l.version_dir(&v("1.2.0"))), "staged");
    assert!(h.exists(&l.version_dir(&v("1.1.0"))), "current");
    assert!(h.exists(&l.version_dir(&v("1.0.0"))), "previous");
}

#[test]
fn reconcile_removes_partial_trees_and_gc_leftovers() {
    let h = Host::new();
    h.install("1.0.0").unwrap();
    let l = h.layout();
    let partial = l.app_dir().join("1.1.0.partial");
    let leftover = l.app_dir().join(".gc-0011223344556677");
    h.mem.create_dir_all(&partial).unwrap();
    h.mem.create_dir_all(&leftover).unwrap();
    let from = h.process.strict_calls().len();
    let _engine = h.engine();
    assert_eq!(names_in(&h, &l.app_dir()), ["1.0.0"]);
    // A `.partial` tree is exempt from the guard; the leftover is checked.
    assert_eq!(strict_from(&h, from), [leftover]);
}

#[test]
fn the_leftover_sweep_keeps_a_busy_gc_folder() {
    let h = Host::new();
    h.install("1.0.0").unwrap();
    let l = h.layout();
    let leftover = l.app_dir().join(".gc-0011223344556677");
    h.mem.create_dir_all(&leftover).unwrap();
    h.process.script_in_use_strict(true);
    let from = h.process.strict_calls().len();
    drop(h.engine());
    assert!(h.exists(&leftover), "a busy leftover stays");
    assert_eq!(strict_from(&h, from), std::slice::from_ref(&leftover));
    drop(h.engine());
    assert!(!h.exists(&leftover), "removed once the check says free");
    assert_eq!(strict_from(&h, from), [leftover.clone(), leftover]);
}

#[test]
fn prune_keeps_a_busy_service_folder_at_the_switch_and_at_repair() {
    let h = Host::new();
    h.install("1.0.0").unwrap();
    let l = h.layout();
    let mut engine = h.engine();
    update_to(&mut engine, "1.1.0", 2);
    // The switch to 1.2.0 prunes service\1.0.0: in use, so it stays.
    stage(&mut engine, &update("1.2.0", 3));
    let token = engine.apply(&v("1.2.0"), Duration::from_secs(1)).unwrap();
    h.process.script_in_use_strict(true);
    let from = h.process.strict_calls().len();
    assert_eq!(
        engine.confirm(&v("1.2.0"), &token).unwrap(),
        ConfirmAnswer::Confirmed
    );
    assert_eq!(h.registered(), Some(l.service_image(&v("1.2.0"))));
    assert!(h.exists(&l.service_version_dir(&v("1.0.0"))), "busy: kept");
    let asked = strict_from(&h, from);
    assert_eq!(asked[0], l.service_version_dir(&v("1.0.0")));
    // Repair prunes the folders other than the registered one: 1.0.0 is free now, 1.1.0 busy.
    h.process.script_in_use_strict(false);
    h.process.script_in_use_strict(true);
    let from = h.process.strict_calls().len();
    assert_eq!(engine.repair(), Ok(v("1.2.0")));
    assert!(
        !h.exists(&l.service_version_dir(&v("1.0.0"))),
        "free: removed"
    );
    assert!(h.exists(&l.service_version_dir(&v("1.1.0"))), "busy: kept");
    assert!(h.exists(&l.service_version_dir(&v("1.2.0"))));
    assert_eq!(
        strict_from(&h, from),
        [
            l.service_version_dir(&v("1.0.0")),
            l.service_version_dir(&v("1.1.0")),
        ]
    );
}

// ---- repair and uninstall -------------------------------------------------------------------------

#[test]
fn repair_reregisters_a_missing_service() {
    let h = Host::new();
    h.install("1.0.0").unwrap();
    lunepack_core::ServiceRegistrar::remove(&h.registrar, &app()).unwrap();
    let before = h.record();
    let engine = h.engine();
    assert_eq!(engine.repair(), Ok(v("1.0.0")));
    assert_eq!(h.registered(), Some(h.layout().service_image(&v("1.0.0"))));
    assert_eq!(h.record(), before, "repair changes no record");
}

#[test]
fn repair_targets_the_previous_version_while_one_is_pending() {
    let h = Host::new();
    h.install("1.0.0").unwrap();
    let mut engine = h.engine();
    stage(&mut engine, &update("1.1.0", 2));
    engine.apply(&v("1.1.0"), Duration::from_secs(1)).unwrap();
    assert_eq!(engine.repair(), Ok(v("1.0.0")));
    assert_eq!(h.registered(), Some(h.layout().service_image(&v("1.0.0"))));
}

/// The tombstone `uninstall` renamed `R` to, from the strict log.
fn tombstone_asked(h: &Host, asked: &[PathBuf]) -> PathBuf {
    assert_eq!(asked.len(), 2, "{asked:?}");
    assert_eq!(asked[0], h.root());
    let tomb = asked[1].clone();
    assert_eq!(tomb.parent(), Some(h.home.as_path()));
    assert_ne!(tomb, h.root());
    tomb
}

/// The integration calls from call `from` on, by operation.
fn integration_ops(h: &Host, from: usize) -> Vec<&'static str> {
    h.integration
        .calls()
        .into_iter()
        .skip(from)
        .map(|(op, scope, version)| {
            assert_eq!(scope, Scope::Machine);
            assert_eq!(version, v("1.0.0"));
            op
        })
        .collect()
}

/// An installed 1.0.0 with the counters of the strict log and the integration calls so far.
fn installed() -> (Host, usize, usize) {
    let h = Host::new();
    h.install("1.0.0").unwrap();
    assert!(h.integration.is_applied());
    let image = h.layout().service_image(&v("1.0.0"));
    assert_eq!(h.registered(), Some(image));
    let strict = h.process.strict_calls().len();
    let calls = h.integration.calls().len();
    (h, strict, calls)
}

/// The install is as it was before a refused uninstall.
fn assert_intact(h: &Host) {
    assert!(h.exists(&h.root()));
    assert!(h.exists(&h.layout().version_dir(&v("1.0.0")).join("app.exe")));
    assert_eq!(names_in(h, &h.home), ["Hello"], "no tombstone is left");
    assert_eq!(
        h.registered(),
        Some(h.layout().service_image(&v("1.0.0"))),
        "the service is registered again"
    );
    assert!(h.integration.is_applied());
}

#[test]
fn uninstall_is_refused_in_use_before_the_integration_goes() {
    let (h, strict, calls) = installed();
    h.process.script_in_use_strict(true);
    assert_eq!(h.engine().uninstall(), Err(MachineOpError::InUse));
    assert_intact(&h);
    assert_eq!(strict_from(&h, strict), [h.root()]);
    assert!(
        integration_ops(&h, calls).is_empty(),
        "the integration is not touched"
    );
    // The service was removed (it stops) and registered again with the image read at (1).
    assert_eq!(
        h.registrar.registers().last(),
        Some(&h.layout().service_image(&v("1.0.0")))
    );
}

#[test]
fn uninstall_undoes_an_integration_error() {
    let (h, strict, calls) = installed();
    h.integration.fail("remove");
    assert_eq!(h.engine().uninstall(), Err(MachineOpError::Integration));
    assert_intact(&h);
    assert_eq!(strict_from(&h, strict), [h.root()]);
    assert_eq!(integration_ops(&h, calls), ["remove", "apply"]);
}

#[test]
fn uninstall_undoes_a_failed_rename() {
    let (h, strict, calls) = installed();
    h.fs.fail_rename_from(&h.root());
    assert_eq!(h.engine().uninstall(), Err(MachineOpError::InUse));
    assert_intact(&h);
    assert_eq!(strict_from(&h, strict), [h.root()]);
    assert_eq!(integration_ops(&h, calls), ["remove", "apply"]);
}

#[test]
fn uninstall_undoes_a_busy_tombstone() {
    let (h, strict, calls) = installed();
    h.process.script_in_use_strict(false);
    h.process.script_in_use_strict(true);
    assert_eq!(h.engine().uninstall(), Err(MachineOpError::InUse));
    assert_intact(&h);
    let tomb = tombstone_asked(&h, &strict_from(&h, strict));
    assert!(!h.exists(&tomb), "renamed back");
    assert_eq!(integration_ops(&h, calls), ["remove", "apply"]);
}

#[test]
fn a_failed_reregistration_during_an_undo_is_failed() {
    let (h, strict, _) = installed();
    h.process.script_in_use_strict(true);
    h.registrar.fail_register(true);
    assert_eq!(
        h.engine().uninstall(),
        Err(MachineOpError::Failed("restore the service"))
    );
    assert!(h.exists(&h.root()));
    assert_eq!(h.registered(), None);
    assert_eq!(strict_from(&h, strict), [h.root()]);
}

#[test]
fn the_undo_registers_only_an_image_under_this_root() {
    let (h, strict, _) = installed();
    // Registered after `open`, whose switch would point it back into the tree.
    let engine = h.engine();
    let foreign = abs_path("/elsewhere/service/lunepack-service.exe");
    lunepack_core::ServiceRegistrar::register(&h.registrar, &app(), &foreign).unwrap();
    h.process.script_in_use_strict(true);
    assert_eq!(engine.uninstall(), Err(MachineOpError::InUse));
    assert_eq!(
        h.registered(),
        None,
        "a foreign image is not registered again"
    );
    assert_eq!(h.registrar.registers().last(), Some(&foreign));
    assert!(h.exists(&h.root()));
    assert_eq!(strict_from(&h, strict), [h.root()]);
}

#[test]
fn a_failed_removal_leaves_the_tombstone() {
    let (h, strict, calls) = installed();
    h.fs.fail_remove_in(&h.home);
    assert_eq!(
        h.engine().uninstall(),
        Err(MachineOpError::Failed("remove the install"))
    );
    let tomb = tombstone_asked(&h, &strict_from(&h, strict));
    assert!(!h.exists(&h.root()));
    assert!(h.exists(&tomb.join("app")), "the tombstone stays whole");
    assert_eq!(h.registered(), None);
    assert!(!h.integration.is_applied());
    assert_eq!(integration_ops(&h, calls), ["remove"]);
}

#[test]
fn uninstall_is_complete_when_nothing_uses_the_install() {
    let (h, strict, calls) = installed();
    h.engine().uninstall().unwrap();
    assert!(!h.exists(&h.root()));
    assert!(
        h.mem.list_dir(&h.home).unwrap().is_empty(),
        "no tombstone is left"
    );
    assert_eq!(h.registered(), None);
    assert!(!h.integration.is_applied());
    assert_eq!(integration_ops(&h, calls), ["remove"]);
    let tomb = tombstone_asked(&h, &strict_from(&h, strict));
    assert!(!h.exists(&tomb));
    // A new install goes again.
    h.install("1.0.0").unwrap();
}

// ---- the machine layout ------------------------------------------------------------------------------

#[test]
fn machine_layout_paths_and_the_service_image_inverse() {
    let l = MachineLayout::new(&abs_path("/pf/Hello"));
    let image = l.service_image(&v("1.2.3-beta.1"));
    assert_eq!(
        image,
        abs_path("/pf/Hello/.lunepack/machine/service/1.2.3-beta.1/lunepack-service.exe")
    );
    let (back, version) = MachineLayout::of_service_image(&image).unwrap();
    assert_eq!(back, l);
    assert_eq!(version.to_string(), "1.2.3-beta.1");
    assert_eq!(l.app_dir(), abs_path("/pf/Hello/app"));
    assert_eq!(l.state_dir(), abs_path("/pf/Hello/.lunepack/state"));
    assert_eq!(l.lock_path(), abs_path("/pf/Hello/.lunepack/machine/lock"));
    for bad in [
        "/pf/Hello/.lunepack/machine/service/1.2.3/other.exe",
        "/pf/Hello/.lunepack/machine/service/01.2.3/lunepack-service.exe",
        "/pf/Hello/.lunepack/machine/other/1.2.3/lunepack-service.exe",
        "/pf/Hello/.lunepack/admin/service/1.2.3/lunepack-service.exe",
        "/pf/Hello/app/1.2.3/lunepack-service.exe",
    ] {
        assert!(
            MachineLayout::of_service_image(&abs_path(bad)).is_none(),
            "{bad}"
        );
    }
    assert_eq!(
        lunepack_core::layout::service_path_in_tree(&RelPath::parse("bin/app.exe").unwrap())
            .unwrap()
            .as_str(),
        "bin/lunepack-service.exe"
    );
}

#[test]
fn machine_layout_resolve_root_matches_machine_records_only() {
    let h = Host::new();
    h.install("1.0.0").unwrap();
    let scoped = |scope| {
        lunepack_core::resolve_root_scoped(
            &h.mem,
            &FakeHasher,
            &h.home,
            &app(),
            "Hello",
            lunepack_core::LayoutScheme::WINDOWS,
            scope,
        )
    };
    assert_eq!(
        scoped(Scope::Machine).ok(),
        Some(RootChoice::Existing(h.root()))
    );
    assert!(
        scoped(Scope::User).is_err(),
        "a machine record is not a per-user install"
    );
}
