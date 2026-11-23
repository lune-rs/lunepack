//! M11 step 2: the engine's projections on Linux (`R/current` → `app/<current>`) and macOS (the
//! live bundle `B` in the apps folder holds the current version, FORMAT 17), on first install,
//! apply, the attempt's rollback, rollback, the reconcile at `open` after a cut at every point,
//! GC with parked trees, and uninstall (refusals and success), over the fakes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use lunepack_core::engine::{Engine, InstallRequest, MachineOpError, Ports, install};
use lunepack_core::service::{AttemptAnswer, CommitOutcome, ErrorCode, ObjectKind, Token};
use lunepack_core::setup::VerifiedSetup;
use lunepack_core::{
    AppId, Channel, CodecId, Fs, Hasher, InstallMeta, InstallState, MachineLayout, MachineScheme,
    MachineStore, PayloadKind, RelPath, Target, UpdateConfig, Version, verify_payload_manifest,
};
use lunepack_testkit::{
    ChainFixture, FakeClock, FakeCodec, FakeHasher, FakeMachineIntegration, FakePolicy,
    FakeProcess, FakeProtect, FakePublisherCheck, FakeRegistrar, FakeRng, FakeVerifier, FaultFs,
    MemFs, PackBuilder, RecoverMode, SUITE_APP_ID, SUITE_T0, abs_path,
};

// ---- the two unix schemes --------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Os {
    scheme: MachineScheme,
    target: Target,
    entry: &'static str,
    service: &'static str,
    config: &'static str,
    home: &'static str,
}

const LINUX: Os = Os {
    scheme: MachineScheme::LINUX,
    target: Target::LinuxX86_64,
    entry: "bin/app",
    service: "bin/lunepack-service",
    config: "lunepack-update.json",
    home: "/opt",
};

const MACOS: Os = Os {
    scheme: MachineScheme::MACOS,
    target: Target::MacosAarch64,
    entry: "Contents/MacOS/app",
    service: "Contents/MacOS/lunepack-service",
    config: "Contents/Resources/lunepack-update.json",
    home: "/Library/Application Support/lunepack",
};

const BOTH: [Os; 2] = [LINUX, MACOS];

fn is_mac(os: Os) -> bool {
    os.target.is_macos()
}

fn v(t: &str) -> Version {
    Version::parse(t).unwrap()
}

fn app() -> AppId {
    AppId::parse(SUITE_APP_ID).unwrap()
}

fn fx() -> ChainFixture<'static> {
    ChainFixture::fake()
}

fn meta(os: Os) -> InstallMeta {
    InstallMeta {
        entry: RelPath::parse(os.entry).unwrap(),
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

fn config_bytes(os: Os, version: &str) -> Vec<u8> {
    UpdateConfig::new(
        &fx().trusted_root(1, 1, &[0]),
        v(version),
        os.target,
        "https://updates.example.org/hello/",
        Channel::parse("stable").unwrap(),
        60,
        meta(os),
    )
    .unwrap()
    .to_bytes()
    .unwrap()
}

fn pack_of(os: Os, version: &str) -> PackBuilder {
    let fx = fx();
    let mut pack = PackBuilder::new();
    pack.file(
        fx.hasher,
        os.entry,
        format!("entry of {version}").as_bytes(),
        CodecId::Lzma2,
    );
    pack.file(
        fx.hasher,
        os.service,
        format!("service of {version}").as_bytes(),
        CodecId::Lzma2,
    );
    pack.file(
        fx.hasher,
        os.config,
        &config_bytes(os, version),
        CodecId::Stored,
    );
    pack
}

fn manifest_bytes(os: Os, version: &str, pack: &PackBuilder) -> Vec<u8> {
    let fx = fx();
    fx.envelope(
        PayloadKind::Manifest,
        &fx.manifest_document(version, os.target, pack).to_payload(),
        &[5],
    )
}

fn payload(os: Os, version: &str) -> (VerifiedSetup, PackBuilder) {
    let fx = fx();
    let pack = pack_of(os, version);
    let (_, keys) = fx.verified_chain(&[5], 1);
    let manifest = verify_payload_manifest(
        &keys,
        (&v(version), os.target),
        &manifest_bytes(os, version, &pack),
        SUITE_T0,
        &FakeHasher,
        &FakeVerifier,
    )
    .unwrap();
    let config = UpdateConfig::parse(&config_bytes(os, version)).unwrap();
    (VerifiedSetup { manifest, config }, pack)
}

struct Update {
    keys: Vec<u8>,
    feed: Vec<u8>,
    manifest: Vec<u8>,
    pack: PackBuilder,
}

fn update(os: Os, version: &str, seq: u64) -> Update {
    let fx = fx();
    let pack = pack_of(os, version);
    let manifest = manifest_bytes(os, version, &pack);
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
            vec![fx.release(version, &[(os.target, &manifest)], None)],
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

// ---- the host -------------------------------------------------------------------------------------

struct Host {
    os: Os,
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
    token: std::cell::RefCell<Option<Token>>,
}

impl Host {
    fn new(os: Os) -> Host {
        let mem = MemFs::new();
        for dir in [abs_path(os.home), abs_path("/Applications")] {
            mem.create_dir_all(&dir).unwrap();
            // Durable, as the system's folders are: a cut never takes them away.
            let mut at = Some(dir.as_path());
            while let Some(d) = at {
                mem.sync_dir(d).unwrap();
                at = d.parent();
            }
        }
        Host::over(
            os,
            mem,
            FakeProtect::new(&MemFs::new()),
            FakeRegistrar::new(),
            11,
        )
    }

    fn over(os: Os, mem: MemFs, protect: FakeProtect, registrar: FakeRegistrar, seed: u64) -> Host {
        Host {
            os,
            fs: FaultFs::new(&mem),
            protect: protect.with_fs(&mem),
            policy: FakePolicy::new(),
            integration: FakeMachineIntegration::new(),
            publisher: FakePublisherCheck::new([]),
            registrar,
            process: FakeProcess::new(abs_path("/Applications/Hello.app/Contents/MacOS/app")),
            rng: FakeRng::new(seed),
            clock: FakeClock::new(SUITE_T0 + 3600),
            codec: FakeCodec::new(),
            token: std::cell::RefCell::new(None),
            mem,
        }
    }

    /// The disk a restart finds after a crash, with the protection classes and the registration
    /// (which live outside the disk) carried over.
    fn recovered(&self, mode: RecoverMode) -> Host {
        Host::over(
            self.os,
            self.mem.recover(mode),
            self.protect.clone(),
            self.registrar.clone(),
            97,
        )
    }

    fn ports(&self) -> Ports<'_> {
        self.ports_on(&self.fs)
    }

    fn ports_on<'a>(&'a self, fs: &'a dyn Fs) -> Ports<'a> {
        Ports {
            fs,
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

    fn home(&self) -> PathBuf {
        abs_path(self.os.home)
    }

    fn apps(&self) -> PathBuf {
        abs_path("/Applications")
    }

    fn root(&self) -> PathBuf {
        self.home().join(SUITE_APP_ID)
    }

    fn bundle(&self) -> PathBuf {
        self.apps().join("Hello.app")
    }

    fn layout(&self) -> MachineLayout {
        MachineLayout::with_scheme(&self.root(), self.os.scheme)
    }

    fn payload_dir(&self) -> PathBuf {
        self.home().join(".hello-setup")
    }

    fn write(&self, path: &Path, bytes: &[u8]) {
        let mut w = self.mem.create_new(path).unwrap();
        std::io::Write::write_all(&mut w, bytes).unwrap();
        w.sync().unwrap();
    }

    fn exists(&self, p: &Path) -> bool {
        self.mem.symlink_metadata(p).unwrap().is_some()
    }

    fn names_in(&self, dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = self
            .mem
            .list_dir(dir)
            .unwrap()
            .into_iter()
            .map(|e| e.name.to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Copies the pack of `version` into the admin-only payload folder, as the host does.
    fn prepare_payload(&self, version: &str) {
        let (_, pack) = payload(self.os, version);
        let dir = self.payload_dir();
        if self.exists(&dir) {
            self.mem.remove_dir_all_nofollow(&dir).unwrap();
        }
        self.mem.create_dir_all(&dir).unwrap();
        self.write(&dir.join("pack"), &pack.bytes);
        self.mem.sync_dir(&dir).unwrap();
        self.mem.sync_dir(&self.home()).unwrap();
    }

    fn install_with(&self, ports: Ports<'_>, version: &str) -> Result<PathBuf, MachineOpError> {
        self.prepare_payload(version);
        self.install_prepared(ports, version)
    }

    /// The first install over a payload already prepared.
    fn install_prepared(&self, ports: Ports<'_>, version: &str) -> Result<PathBuf, MachineOpError> {
        let (setup, _) = payload(self.os, version);
        let dir = self.payload_dir();
        let pack_path = dir.join("pack");
        let apps = self.apps();
        install(
            ports,
            &InstallRequest {
                machine_home: &self.home(),
                display_name: "Hello",
                setup: &setup,
                keyset_version: 1,
                payload_dir: &dir,
                pack: &pack_path,
                apps_dir: is_mac(self.os).then_some(apps.as_path()),
            },
        )
        .map(|i| i.root)
    }

    fn install(&self, version: &str) -> Result<PathBuf, MachineOpError> {
        self.install_with(self.ports(), version)
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

    /// The version of the tree at `path` by its own config.
    fn tree_version(&self, path: &Path) -> Version {
        let mut at = path.to_path_buf();
        for name in self.os.config.split('/') {
            at.push(name);
        }
        let bytes = self.mem.read_capped(&at, 1 << 20).unwrap();
        UpdateConfig::parse(&bytes).unwrap().version
    }

    /// The invariant: the disk projects the committed record. Linux: `R/current` is a link to
    /// `app/<current>`, which holds that version. macOS: `R/bundle` names `B`, `B` holds the
    /// current version, both slots are empty and no tree of the current version is parked.
    fn assert_projected(&self) {
        let record = self.record();
        let current = record.current.expect("a current version").version;
        let l = self.layout();
        let app_dir = l.app_dir();
        if is_mac(self.os) {
            let pointer = self.mem.read_link(&self.root().join("bundle")).unwrap();
            assert_eq!(PathBuf::from(pointer), self.bundle());
            assert_eq!(self.tree_version(&self.bundle()), current);
            assert!(
                !self.exists(&app_dir.join(".swap")),
                "the swap slot is empty"
            );
            assert!(!self.exists(&app_dir.join(".out")), "the out slot is empty");
            assert!(
                !self.exists(&l.version_dir(&current)),
                "the current tree is in B"
            );
            assert!(!self.exists(&self.root().join("current")));
        } else {
            let link = self.root().join("current");
            assert_eq!(
                self.mem.read_link(&link).unwrap(),
                format!("app/{current}"),
                "R/current names the committed version"
            );
            assert_eq!(self.tree_version(&l.version_dir(&current)), current);
            assert!(!self.exists(&self.root().join("bundle")));
        }
    }
}

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

fn applied(engine: &mut Engine<'_>, os: Os, version: &str, seq: u64) -> Token {
    stage(engine, &update(os, version, seq));
    engine.apply(&v(version), Duration::from_secs(1)).unwrap()
}

fn update_to(engine: &mut Engine<'_>, os: Os, version: &str, seq: u64) {
    let token = applied(engine, os, version, seq);
    engine.confirm(&v(version), &token).unwrap();
}

// ---- first install -------------------------------------------------------------------------------

#[test]
fn the_first_install_projects_the_record() {
    for os in BOTH {
        let h = Host::new(os);
        assert_eq!(h.install("1.0.0").unwrap(), h.root());
        h.assert_projected();
        let image = h.layout().service_image(&v("1.0.0"));
        assert!(
            h.exists(&image),
            "the service binary is placed from the tree"
        );
        assert_eq!(
            lunepack_core::ServiceRegistrar::image(&h.registrar, &app()).unwrap(),
            Some(image)
        );
        if is_mac(os) {
            assert!(h.exists(&h.bundle().join(os.entry)));
            assert_eq!(h.names_in(&h.apps()), ["Hello.app"]);
            assert!(h.exists(&h.root().join("bundle.id")));
        }
        assert!(!h.exists(&h.payload_dir()));
        // The engine opens over it and finds the current tree.
        assert_eq!(h.engine().status().unwrap().current, v("1.0.0"));
    }
}

#[test]
fn the_linux_root_is_named_by_the_app_id_and_never_taken_over() {
    let h = Host::new(LINUX);
    h.mem.create_dir_all(&h.root()).unwrap();
    h.write(&h.root().join("foreign.txt"), b"x");
    assert_eq!(h.install("1.0.0"), Err(MachineOpError::FolderTaken));
    assert_eq!(h.names_in(&h.root()), ["foreign.txt"]);

    // An empty folder there, protected already, is adopted.
    let h = Host::new(LINUX);
    h.mem.create_dir_all(&h.root()).unwrap();
    h.protect
        .mark(&h.root(), lunepack_core::DirClass::MachineTree);
    h.install("1.0.0").unwrap();
    h.assert_projected();
}

#[test]
fn a_taken_bundle_name_takes_the_second_and_both_taken_refuse() {
    let h = Host::new(MACOS);
    // A foreign bundle and a symlink at the two names are never touched or followed.
    h.mem.create_dir_all(&h.bundle()).unwrap();
    h.write(&h.bundle().join("foreign"), b"x");
    h.install("1.0.0").unwrap();
    let second = h.apps().join(format!("Hello ({SUITE_APP_ID}).app"));
    assert_eq!(
        PathBuf::from(h.mem.read_link(&h.root().join("bundle")).unwrap()),
        second
    );
    assert_eq!(h.tree_version(&second), v("1.0.0"));
    assert_eq!(h.names_in(&h.bundle()), ["foreign"]);

    let h = Host::new(MACOS);
    h.mem.create_dir_all(&h.bundle()).unwrap();
    h.mem
        .symlink(
            "/elsewhere",
            &h.apps().join(format!("Hello ({SUITE_APP_ID}).app")),
        )
        .unwrap();
    assert_eq!(h.install("1.0.0"), Err(MachineOpError::FolderTaken));
    assert!(!h.exists(&h.root()), "nothing was created");
    assert!(h.protect.created().is_empty());
}

#[test]
fn the_apps_folder_is_never_created() {
    let h = Host::new(MACOS);
    h.mem.remove_dir_all_nofollow(&h.apps()).unwrap();
    assert!(matches!(h.install("1.0.0"), Err(MachineOpError::Failed(_))));
    assert!(!h.exists(&h.apps()));
    assert!(!h.exists(&h.root()));
}

#[test]
fn a_failure_after_the_bundle_was_placed_removes_it() {
    let h = Host::new(MACOS);
    let image = h.layout().service_image(&v("1.0.0"));
    h.registrar.fail_self_test(&image);
    assert_eq!(h.install("1.0.0"), Err(MachineOpError::SelfTest));
    assert!(!h.exists(&h.root()));
    assert!(
        h.names_in(&h.apps()).is_empty(),
        "the bundle this run made is gone"
    );
}

#[test]
fn a_projection_error_keeps_the_committed_install_and_open_finishes_it() {
    let h = Host::new(MACOS);
    // The move of the staged tree into the bundle fails once.
    h.fs.fail_rename_from(&h.layout().version_dir(&v("1.0.0")));
    assert!(matches!(h.install("1.0.0"), Err(MachineOpError::Failed(_))));
    assert_eq!(h.record().current.unwrap().version, v("1.0.0"), "committed");
    assert!(!h.exists(&h.bundle()));
    assert!(
        lunepack_core::ServiceRegistrar::image(&h.registrar, &app())
            .unwrap()
            .is_some(),
        "the service is registered, so the next open comes"
    );
    // The next open, over a disk without the fault, finishes the projection.
    let fs: &dyn Fs = &h.mem;
    Engine::open(h.ports_on(fs), &h.root()).unwrap();
    h.assert_projected();
}

// ---- apply, attempt, rollback, GC ------------------------------------------------------------------

#[test]
fn apply_rollback_and_gc_keep_the_projection() {
    for os in BOTH {
        for exchange in [true, false] {
            let h = Host::new(os);
            h.mem.set_exchange_supported(exchange);
            h.install("1.0.0").unwrap();
            let mut engine = h.engine();
            let token = applied(&mut engine, os, "2.0.0", 2);
            h.assert_projected();
            assert_eq!(h.record().current.unwrap().version, v("2.0.0"));
            if is_mac(os) {
                assert_eq!(
                    h.tree_version(&h.layout().version_dir(&v("1.0.0"))),
                    v("1.0.0")
                );
            }
            // A failed start rolls back with its token.
            assert_eq!(engine.rollback(&v("2.0.0"), &token), Ok(v("1.0.0")));
            h.assert_projected();
            if is_mac(os) {
                assert_eq!(
                    h.tree_version(&h.layout().version_dir(&v("2.0.0"))),
                    v("2.0.0")
                );
            }
        }
    }
}

#[test]
fn the_attempt_limit_rolls_back_the_projection() {
    for os in BOTH {
        let h = Host::new(os);
        h.install("1.0.0").unwrap();
        let mut engine = h.engine();
        applied(&mut engine, os, "2.0.0", 2);
        let mut now = 10_000;
        let answer = loop {
            now += 10_000;
            match engine
                .attempt(&v("2.0.0"), Duration::from_secs(now))
                .unwrap()
            {
                AttemptAnswer::Counted { .. } => continue,
                other => break other,
            }
        };
        assert_eq!(
            answer,
            AttemptAnswer::RolledBack {
                current: v("1.0.0")
            }
        );
        h.assert_projected();
    }
}

#[test]
fn gc_collects_parked_trees_and_never_the_slots() {
    for os in BOTH {
        let h = Host::new(os);
        h.install("1.0.0").unwrap();
        {
            let mut engine = h.engine();
            update_to(&mut engine, os, "2.0.0", 2);
            update_to(&mut engine, os, "3.0.0", 3);
        }
        h.assert_projected();
        let app_dir = h.layout().app_dir();
        assert!(!h.exists(&app_dir.join("1.0.0")), "collected");
        assert!(
            h.exists(&app_dir.join("2.0.0")),
            "the previous version is kept"
        );
        // Slots are never versions: an empty slot left on Linux is not collected or touched.
        if !is_mac(os) {
            h.mem.create_dir_all(&app_dir.join(".swap")).unwrap();
            h.mem.create_dir_all(&app_dir.join(".out")).unwrap();
            drop(h.engine());
            assert!(h.exists(&app_dir.join(".swap")));
            assert!(h.exists(&app_dir.join(".out")));
        }
        h.assert_projected();
    }
}

#[test]
fn a_foreign_tree_at_the_bundle_is_never_replaced() {
    let h = Host::new(MACOS);
    h.install("1.0.0").unwrap();
    // Another app's tree put at B: the reconcile refuses to move anything, B stays.
    h.mem.remove_dir_all_nofollow(&h.bundle()).unwrap();
    h.mem
        .create_dir_all(&h.bundle().join("Contents/Resources"))
        .unwrap();
    let mut other = UpdateConfig::parse(&config_bytes(MACOS, "9.0.0")).unwrap();
    other.app_id = AppId::parse("org.example.other").unwrap();
    h.write(
        &h.bundle().join("Contents/Resources/lunepack-update.json"),
        &other.to_bytes().unwrap(),
    );
    let fs: &dyn Fs = &h.mem;
    let engine = Engine::open(h.ports_on(fs), &h.root()).unwrap();
    // The reconcile at open leaves the foreign tree alone.
    assert_eq!(h.tree_version(&h.bundle()), v("9.0.0"));
    assert!(engine.status().is_ok());
    // Uninstall leaves another app's tree at B alone.
    engine.uninstall().unwrap();
    assert!(h.exists(&h.bundle()));
    assert!(!h.exists(&h.root()));
}

// ---- the projection after a cut at every point ------------------------------------------------------

/// Runs `op` over a fresh host prepared by `setup`, cutting the disk at op `n` for every `n` until
/// `op` runs to its end; after each cut the restart's `open` (or, before an install record, the
/// install run again) leaves the disk projecting the committed record.
///
/// macOS is cut with [`RecoverMode::KeepVolatile`] only: `MemFs` keeps each directory's
/// durability apart, so dropping what was not synced splits a rename or exchange between the
/// apps folder and `R/app` that a real volume journals as one (the per-user bundle reconcile's
/// cut tests in `lunepack-core/tests/layout.rs` use the same mode for that reason). Linux's
/// projection stays in `R` and is cut both ways.
fn cut_everywhere(os: Os, exchange: bool, setup: fn(&Host), op: fn(&Host)) {
    let modes: &[RecoverMode] = if is_mac(os) {
        &[RecoverMode::KeepVolatile]
    } else {
        &[RecoverMode::DropVolatile, RecoverMode::KeepVolatile]
    };
    for &mode in modes {
        let mut n = 0;
        loop {
            let h = Host::new(os);
            h.mem.set_exchange_supported(exchange);
            setup(&h);
            let base = h.mem.op_count();
            h.mem.crash_after(base + n);
            op(&h);
            if !h.mem.is_crashed() {
                break;
            }
            let r = h.recovered(mode);
            r.mem.set_exchange_supported(exchange);
            let installed = MachineStore {
                dir: r.layout().state_dir(),
                app_id: app(),
            }
            .load(&r.mem, &FakeHasher)
            .ok()
            .and_then(|l| l.record)
            .is_some_and(|rec| rec.current.is_some());
            if installed {
                drop(r.engine());
            } else {
                r.install("1.0.0")
                    .unwrap_or_else(|e| panic!("cut at {n}: the install again: {e}"));
            }
            r.assert_projected();
            n += 1;
            assert!(n < 2000, "the operation never ends");
        }
        assert!(n > 3, "the operation was cut at {n} points only");
    }
}

fn installed(h: &Host) {
    h.install("1.0.0").unwrap();
}

fn staged_2(h: &Host) {
    installed(h);
    stage(&mut h.engine(), &update(h.os, "2.0.0", 2));
}

fn applied_2(h: &Host) {
    installed(h);
    let mut engine = h.engine();
    let token = applied(&mut engine, h.os, "2.0.0", 2);
    *h.token.borrow_mut() = Some(token);
}

#[test]
fn a_cut_first_install_is_finished() {
    for os in BOTH {
        cut_everywhere(
            os,
            true,
            |h| h.prepare_payload("1.0.0"),
            |h| {
                let _ = h.install_prepared(h.ports(), "1.0.0");
            },
        );
    }
}

#[test]
fn a_cut_apply_is_finished_by_open() {
    for os in BOTH {
        for exchange in [true, false] {
            cut_everywhere(os, exchange, staged_2, |h| {
                if let Ok(mut engine) = Engine::open(h.ports(), &h.root()) {
                    let _ = engine.apply(&v("2.0.0"), Duration::from_secs(1));
                }
            });
        }
    }
}

#[test]
fn a_cut_rollback_is_finished_by_open() {
    for os in BOTH {
        for exchange in [true, false] {
            cut_everywhere(os, exchange, applied_2, |h| {
                let token = h.token.borrow().clone().expect("the token");
                if let Ok(mut engine) = Engine::open(h.ports(), &h.root()) {
                    let _ = engine.rollback(&v("2.0.0"), &token);
                }
            });
        }
    }
}

// ---- uninstall ------------------------------------------------------------------------------------

#[test]
fn uninstall_removes_the_root_and_the_bundle() {
    for os in BOTH {
        let h = Host::new(os);
        h.install("1.0.0").unwrap();
        update_to(&mut h.engine(), os, "2.0.0", 2);
        let strict = h.process.strict_calls().len();
        h.engine().uninstall().unwrap();
        assert!(!h.exists(&h.root()));
        assert!(h.names_in(&h.home()).is_empty(), "no tombstone is left");
        assert!(
            h.names_in(&h.apps()).is_empty(),
            "the bundle and its tombstone are gone"
        );
        assert_eq!(
            lunepack_core::ServiceRegistrar::image(&h.registrar, &app()).unwrap(),
            None
        );
        let asked: Vec<PathBuf> = h
            .process
            .strict_calls()
            .into_iter()
            .skip(strict)
            .map(|(p, _)| p)
            .collect();
        if is_mac(os) {
            // R's scan, B's scan, then both tombstones.
            assert_eq!(asked.len(), 4);
            assert_eq!(asked[0], h.root());
            assert_eq!(asked[1], h.bundle());
            assert_eq!(asked[2].parent(), Some(h.home().as_path()));
            assert_eq!(asked[3].parent(), Some(h.apps().as_path()));
        } else {
            assert_eq!(asked.len(), 2);
            assert_eq!(asked[0], h.root());
        }
    }
}

/// The install is as it was before a refused uninstall.
fn assert_intact(h: &Host) {
    h.assert_projected();
    assert_eq!(
        h.names_in(&h.home()),
        [SUITE_APP_ID],
        "no tombstone is left"
    );
    if is_mac(h.os) {
        assert_eq!(
            h.names_in(&h.apps()),
            ["Hello.app"],
            "no bundle tombstone is left"
        );
    }
    assert_eq!(
        lunepack_core::ServiceRegistrar::image(&h.registrar, &app()).unwrap(),
        Some(h.layout().service_image(&v("1.0.0"))),
        "the service is registered again"
    );
    assert!(h.integration.is_applied());
}

#[test]
fn a_refused_uninstall_restores_everything() {
    type Inject = fn(&Host);
    let cases: Vec<(&str, Inject)> = vec![
        ("R in use", |h| h.process.script_in_use_strict(true)),
        ("B in use", |h| {
            h.process.script_in_use_strict(false);
            h.process.script_in_use_strict(true);
        }),
        ("B's rename fails", |h| h.fs.fail_rename_from(&h.bundle())),
        ("R's rename fails after B's", |h| {
            h.fs.fail_rename_from(&h.root())
        }),
        ("R's tombstone in use", |h| {
            for answer in [false, false, true] {
                h.process.script_in_use_strict(answer);
            }
        }),
        ("B's tombstone in use", |h| {
            for answer in [false, false, false, true] {
                h.process.script_in_use_strict(answer);
            }
        }),
    ];
    for (what, inject) in cases {
        let h = Host::new(MACOS);
        h.install("1.0.0").unwrap();
        inject(&h);
        assert_eq!(h.engine().uninstall(), Err(MachineOpError::InUse), "{what}");
        assert_intact(&h);
    }
    let h = Host::new(LINUX);
    h.install("1.0.0").unwrap();
    h.process.script_in_use_strict(true);
    assert_eq!(h.engine().uninstall(), Err(MachineOpError::InUse));
    assert_intact(&h);
}

#[test]
fn a_projection_error_in_apply_is_internal_and_open_finishes_it() {
    let h = Host::new(MACOS);
    h.install("1.0.0").unwrap();
    let mut engine = h.engine();
    stage(&mut engine, &update(MACOS, "2.0.0", 2));
    h.fs.fail_rename_from(&h.layout().version_dir(&v("2.0.0")));
    let err = engine
        .apply(&v("2.0.0"), Duration::from_secs(1))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    let record = h.record();
    assert_eq!(
        record.current.unwrap().version,
        v("2.0.0"),
        "the record stays committed"
    );
    assert!(record.pending.is_some());
    drop(engine);
    let fs: &dyn Fs = &h.mem;
    Engine::open(h.ports_on(fs), &h.root()).unwrap();
    h.assert_projected();
}
