//! M6 step 6: the first install from an offline payload (M6-D4), with no network.
//!
//! The payload (key set, manifest, pack) is written by the testkit's builders behind a prefix that
//! stands in for the setup file's runtime; the install runs on a `MemFs` with the testkit's fake
//! hasher, verifier, codec, clock, RNG and integration, and a transport that fails the test if it
//! is ever called.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use common::{INSTALL_ID, TARGET, app_id, channel, files, version};
use lunepack::{
    BoxFuture, CancelToken, DownloadOptions, Error, Layout, OfflinePayload, PayloadPart, Phase,
    Progress, Request, Response, Transport, TransportError, UpdateConfigError, Updater,
    UpdaterBuilder, UserLayout, block_on,
};
use lunepack_core::state::{Floors, InstallState, RootParts, Scope, UserScope};
use lunepack_core::{
    CodecId, Fs, FsError, FsErrorKind, InstallMeta, PayloadKind, ReadAt, RelPath, TrustedRoot,
    UpdateConfig,
};
use lunepack_testkit::{
    ChainFixture, FAKE_BASE_URL, FakeClock, FakeCodec, FakeHasher, FakeIntegration, FakeRng,
    FakeVerifier, IntegrationOp, MemFs, PackBuilder, SUITE_CHANNEL, SUITE_T0, abs_path,
};

const V100: &str = "1.0.0";
const FEED: &str = "https://fake.invalid/";
/// The key set's version, distinct from every other number the record holds.
const KEYSET_VERSION: u64 = 3;
/// What stands in for the runtime in front of the payload.
const PREFIX: &[u8] = b"#!runtime bytes stand here\n";

/// Fails the test on any request: an offline install never reaches the network.
struct NoNetwork;

impl Transport for NoNetwork {
    fn get(&self, request: Request) -> BoxFuture<'static, Result<Response, TransportError>> {
        panic!("an offline install made a request: {}", request.url);
    }
}

/// The payload file in memory.
struct Bytes(Vec<u8>);

impl ReadAt for Bytes {
    fn size(&self) -> Result<u64, FsError> {
        Ok(self.0.len() as u64)
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FsError> {
        let start = usize::try_from(offset).expect("offset");
        match self.0.get(start..start + buf.len()) {
            Some(src) => {
                buf.copy_from_slice(src);
                Ok(())
            }
            None => Err(FsError::new(FsErrorKind::Other, Path::new("payload"), None)),
        }
    }
}

fn root_dir() -> PathBuf {
    abs_path("/home/u/.local/share").join(app_id().as_str())
}

fn meta(name: &str) -> InstallMeta {
    InstallMeta {
        entry: RelPath::parse("bin/app").expect("entry"),
        name: name.to_owned(),
        comment: None,
        icon: None,
        categories: Vec::new(),
        bin: Some("app".to_owned()),
        terminal: false,
        publisher: None,
        file_types: Vec::new(),
        url_schemes: Vec::new(),
        autostart: false,
    }
}

/// The parts of a payload, before they are laid out in a file.
struct Parts {
    keys: Vec<u8>,
    manifest: Vec<u8>,
    pack: Vec<u8>,
}

struct Lab {
    fx: ChainFixture<'static>,
    fs: MemFs,
    integration: FakeIntegration,
    clock: Arc<FakeClock>,
}

impl Lab {
    fn new() -> Lab {
        Lab {
            fx: ChainFixture::fake(),
            fs: MemFs::new(),
            integration: FakeIntegration::new(),
            clock: Arc::new(FakeClock::new(SUITE_T0 + 3600)),
        }
    }

    fn root(&self) -> TrustedRoot {
        self.fx.trusted_root(1, 1, &[0])
    }

    /// A root of the same app with another key: what a foreign config names.
    fn other_root(&self) -> TrustedRoot {
        self.fx.trusted_root(1, 1, &[9])
    }

    /// `v`'s key set, manifest and pack; the pack's config names `config_root`.
    fn parts(&self, v: &str, config_root: &TrustedRoot) -> Parts {
        let ks = self.fx.keyset_document(1, KEYSET_VERSION, None, 1, &[1]);
        let keys = self.fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);
        let mut pack = PackBuilder::new();
        for (path, bytes) in files(v) {
            pack.file(&FakeHasher, &path, &bytes, CodecId::Lzma2);
        }
        let config = UpdateConfig::new(
            config_root,
            version(v),
            TARGET,
            FEED,
            channel(),
            60,
            meta(&format!("App {v}")),
        )
        .expect("config");
        pack.file(
            &FakeHasher,
            "lunepack-update.json",
            &config.to_bytes().expect("config bytes"),
            CodecId::Lzma2,
        );
        let doc = self.fx.manifest_document(v, TARGET, &pack);
        let manifest = self
            .fx
            .envelope(PayloadKind::Manifest, &doc.to_payload(), &[1]);
        Parts {
            keys,
            manifest,
            pack: pack.bytes,
        }
    }

    fn updater(&self) -> Updater {
        UpdaterBuilder::new(
            app_id(),
            self.root(),
            &format!("{FAKE_BASE_URL}/feed-{SUITE_CHANNEL}.json"),
            channel(),
            Layout::user(&UserLayout::from_root(
                root_dir(),
                lunepack_core::LayoutScheme::XDG,
            )),
        )
        .transport(Arc::new(NoNetwork))
        .fs(Arc::new(self.fs.clone()))
        .hasher(Arc::new(FakeHasher))
        .verifier(Arc::new(FakeVerifier))
        .codec(Arc::new(FakeCodec::new()))
        .clock(Arc::clone(&self.clock) as Arc<dyn lunepack_core::Clock>)
        .rng(Arc::new(FakeRng::new(9)))
        .integration(Arc::new(self.integration.clone()))
        .workers(2)
        .build()
        .expect("build")
    }

    fn record(&self) -> Option<InstallState> {
        UserScope {
            dir: root_dir().join("state"),
            app_id: app_id(),
        }
        .load(&self.fs, &FakeHasher)
        .expect("load")
        .record
    }

    fn exists(&self, path: &Path) -> bool {
        match self.fs.symlink_metadata(path) {
            Ok(meta) => meta.is_some(),
            // A missing parent is reported either way.
            Err(e) if e.kind == FsErrorKind::NotFound => false,
            Err(e) => panic!("lstat: {e:?}"),
        }
    }
}

/// `PREFIX ‖ keys ‖ manifest ‖ pack` as a payload of `v`.
fn payload(parts: &Parts, v: &str) -> OfflinePayload {
    let mut file = PREFIX.to_vec();
    let mut place = |bytes: &[u8]| {
        let part = PayloadPart {
            offset: file.len() as u64,
            length: bytes.len() as u64,
        };
        file.extend_from_slice(bytes);
        part
    };
    let keys = place(&parts.keys);
    let manifest = place(&parts.manifest);
    let pack = place(&parts.pack);
    OfflinePayload {
        file: Arc::new(Bytes(file)),
        keys,
        manifest,
        pack,
        version: version(v),
        target: TARGET,
    }
}

fn install(
    lab: &Lab,
    payload: OfflinePayload,
    options: DownloadOptions,
) -> Result<lunepack::InstalledVersion, Error> {
    block_on(
        lab.updater()
            .install_from_payload(payload, lab.root(), options),
    )
}

/// Asserts nothing was installed: no current version, no raised floor, nothing integrated.
fn assert_not_installed(lab: &Lab) {
    if let Some(rec) = lab.record() {
        assert!(rec.current.is_none(), "a current version was recorded");
        assert_eq!(rec.floors, Floors::default(), "a floor was raised");
    }
    assert!(!lab.exists(&root_dir().join("current")), "current exists");
    assert!(
        lab.integration.applied().is_empty(),
        "the integration was applied"
    );
}

#[test]
fn a_payload_installs_its_version_with_no_network() {
    let _serial = common::serial();
    let lab = Lab::new();
    let parts = lab.parts(V100, &lab.root());
    let phases = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&phases);
    let options = DownloadOptions {
        progress: Some(Box::new(move |p: &Progress| {
            seen.lock().expect("phases").push(p.phase);
        })),
        cancel: None,
    };
    let got = install(&lab, payload(&parts, V100), options).expect("install");
    assert_eq!(got.version(), &version(V100));
    assert_eq!(got.target(), TARGET);
    assert_eq!(got.issued(), SUITE_T0);

    let rec = lab.record().expect("record");
    let current = rec.current.as_ref().expect("current");
    assert_eq!(current.version, version(V100));
    assert_eq!(current.issued, SUITE_T0);
    assert!(rec.staged.is_none() && rec.staged_issued.is_none());
    let mut expected_id = [0u8; 16];
    lunepack_core::Rng::fill(&FakeRng::new(9), &mut expected_id).expect("rng");
    assert_eq!(rec.install_id, expected_id);
    assert_ne!(rec.install_id, INSTALL_ID);
    // P6: the floors an offline first install records.
    assert_eq!(
        rec.floors,
        Floors {
            root: Some(RootParts::from_trusted(&lab.root())),
            keyset_version: KEYSET_VERSION,
            feed_seq: Default::default(),
        }
    );
    assert_eq!(
        lab.fs
            .read_link(&root_dir().join("current"))
            .expect("current"),
        "versions/1.0.0"
    );
    let tree = root_dir().join("versions/1.0.0");
    for (path, bytes) in files(V100) {
        assert_eq!(
            lab.fs.read_capped(&tree.join(path), 1 << 20).expect("file"),
            bytes
        );
    }
    let ops: Vec<IntegrationOp> = lab.integration.calls().iter().map(|c| c.op).collect();
    assert_eq!(
        ops,
        vec![
            IntegrationOp::Check,
            IntegrationOp::Check,
            IntegrationOp::Apply
        ]
    );
    let applied = lab.integration.calls().pop().expect("apply");
    assert_eq!(applied.install_root, root_dir());
    assert_eq!(applied.meta.name, "App 1.0.0");

    // Progress: the copy as `Install`, the tree as `Stage`, nothing else.
    let phases = phases.lock().expect("phases").clone();
    assert!(phases.contains(&Phase::Install), "{phases:?}");
    assert!(phases.contains(&Phase::Stage), "{phases:?}");
    assert!(
        phases
            .iter()
            .all(|p| matches!(p, Phase::Install | Phase::Stage)),
        "{phases:?}"
    );
    // The copied frames are gone from the cache once the tree is in place.
    let frames = lab
        .fs
        .list_dir(&root_dir().join("cache/frames"))
        .expect("frames");
    assert!(frames.is_empty(), "{} cache entries left", frames.len());
    common::workers_stopped();
}

#[test]
fn a_config_naming_another_root_writes_nothing() {
    let _serial = common::serial();
    let lab = Lab::new();
    let parts = lab.parts(V100, &lab.other_root());
    let got = install(&lab, payload(&parts, V100), DownloadOptions::default());
    assert!(
        matches!(
            got,
            Err(Error::UpdateConfig(UpdateConfigError::RootMismatch("root")))
        ),
        "{got:?}"
    );
    assert!(lab.record().is_none(), "a state record was written");
    assert!(
        !lab.exists(&root_dir().join("versions")),
        "a tree was staged"
    );
    assert!(!lab.exists(&root_dir().join("cache")), "frames were copied");
    assert_not_installed(&lab);
    common::workers_stopped();
}

#[test]
fn an_installed_record_is_already_installed_and_unchanged() {
    let _serial = common::serial();
    let lab = Lab::new();
    let parts = lab.parts(V100, &lab.root());
    install(&lab, payload(&parts, V100), DownloadOptions::default()).expect("first");
    let before = lab.record();
    let got = install(&lab, payload(&parts, V100), DownloadOptions::default());
    assert!(matches!(got, Err(Error::AlreadyInstalled)), "{got:?}");
    assert_eq!(lab.record(), before);
    common::workers_stopped();
}

#[test]
fn a_cancel_at_every_phase_installs_nothing_and_a_rerun_completes() {
    let _serial = common::serial();
    // `None`: cancelled before the call; else at the first progress event of that phase.
    for at in [None, Some(Phase::Install), Some(Phase::Stage)] {
        let lab = Lab::new();
        let parts = lab.parts(V100, &lab.root());
        let cancel = CancelToken::new();
        if at.is_none() {
            cancel.cancel();
        }
        let token = cancel.clone();
        let options = DownloadOptions {
            progress: Some(Box::new(move |p: &Progress| {
                if Some(p.phase) == at {
                    token.cancel();
                }
            })),
            cancel: Some(cancel),
        };
        let got = install(&lab, payload(&parts, V100), options);
        assert!(matches!(got, Err(Error::Cancelled)), "{at:?}: {got:?}");
        assert_not_installed(&lab);
        if at.is_none() {
            assert!(lab.record().is_none(), "a record before any phase ran");
        }
        common::workers_stopped();

        let got = install(&lab, payload(&parts, V100), DownloadOptions::default());
        assert_eq!(
            got.expect("rerun").version(),
            &version(V100),
            "{at:?}: the rerun"
        );
        common::workers_stopped();
    }
}

#[test]
fn a_tampered_or_mislabelled_payload_is_refused_before_any_install() {
    let _serial = common::serial();
    let lab = Lab::new();
    let parts = lab.parts(V100, &lab.root());
    let check = |p: OfflinePayload, what: &str, ok: &dyn Fn(&Error) -> bool| {
        let lab = Lab::new();
        let got = install(&lab, p, DownloadOptions::default());
        match got {
            Err(e) => assert!(ok(&e), "{what}: {e:?}"),
            Ok(_) => panic!("{what}: installed"),
        }
        assert_not_installed(&lab);
        common::workers_stopped();
    };

    // One flipped byte in each part.
    for (i, what) in [(0, "keys"), (1, "manifest"), (2, "pack")] {
        let mut p = Parts {
            keys: parts.keys.clone(),
            manifest: parts.manifest.clone(),
            pack: parts.pack.clone(),
        };
        let bytes = match i {
            0 => &mut p.keys,
            1 => &mut p.manifest,
            _ => &mut p.pack,
        };
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        check(payload(&p, V100), what, &|e| matches!(e, Error::Verify(_)));
    }
    // Another version or target than the manifest's.
    check(payload(&parts, "1.0.0+b"), "version", &|e| {
        matches!(e, Error::Verify(lunepack_core::Error::VersionMismatch))
    });
    let mut p = payload(&parts, V100);
    p.target = lunepack_core::Target::LinuxAarch64;
    check(p, "target", &|e| {
        matches!(
            e,
            Error::Verify(lunepack_core::Error::TargetMismatch { .. })
        )
    });
    // A pack part of another size than the signed one, and a part outside the file.
    let mut p = payload(&parts, V100);
    p.pack.length -= 1;
    check(p, "pack size", &|e| {
        matches!(e, Error::Verify(lunepack_core::Error::ArtifactSize { .. }))
    });
    let mut p = payload(&parts, V100);
    p.pack.offset += 1;
    check(p, "pack outside", &|e| {
        matches!(e, Error::Verify(lunepack_core::Error::Field(_)))
    });
    // A key set part over its cap is refused before it is read.
    let mut p = payload(&parts, V100);
    p.keys.length = 64 * 1024 + 1;
    check(p, "keys cap", &|e| {
        matches!(
            e,
            Error::Verify(lunepack_core::Error::TooLarge { what: "keys", .. })
        )
    });
}

#[test]
fn an_expired_key_set_or_release_key_stops_the_payload() {
    let _serial = common::serial();
    // P8: the fixture's release keys end at `SUITE_T0 + 1000 days`.
    let lab = Lab::new();
    let parts = lab.parts(V100, &lab.root());
    lab.clock.set(SUITE_T0 + 1000 * common::DAY);
    let got = install(&lab, payload(&parts, V100), DownloadOptions::default());
    assert!(
        matches!(
            got,
            Err(Error::Verify(lunepack_core::Error::Threshold { .. }))
        ),
        "{got:?}"
    );
    assert_not_installed(&lab);
    common::workers_stopped();
}

#[test]
fn an_earlier_record_with_no_current_version_is_resumed_with_its_install_id() {
    let _serial = common::serial();
    let lab = Lab::new();
    let store = UserScope {
        dir: root_dir().join("state"),
        app_id: app_id(),
    };
    let loaded = store.load(&lab.fs, &FakeHasher).expect("load");
    let made = store
        .commit(
            &lab.fs,
            &loaded,
            &InstallState::new(1, app_id(), Scope::User, [3; 16], TARGET),
            &FakeHasher,
        )
        .expect("commit");
    let parts = lab.parts(V100, &lab.root());
    install(&lab, payload(&parts, V100), DownloadOptions::default()).expect("install");
    let rec = lab.record().expect("record");
    assert_eq!(rec.install_id, made.install_id);
    assert_eq!(rec.current.expect("current").version, version(V100));
    assert_eq!(rec.floors.keyset_version, KEYSET_VERSION);
    common::workers_stopped();
}

#[test]
fn a_held_updater_lock_is_busy() {
    let _serial = common::serial();
    let lab = Lab::new();
    let parts = lab.parts(V100, &lab.root());
    let state = root_dir().join("state");
    lab.fs.create_dir_all(&state).expect("state dir");
    let guard = lab.fs.try_lock(&state.join("lock")).expect("lock");
    assert!(guard.is_some());
    let got = install(&lab, payload(&parts, V100), DownloadOptions::default());
    assert!(matches!(got, Err(Error::Busy)), "{got:?}");
    drop(guard);
    assert_not_installed(&lab);
    common::workers_stopped();
}
