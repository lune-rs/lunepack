//! M10 step 5: the privileged engine's update operations and the dispatcher, over the fakes,
//! through the in-memory duplex and `ClientSession`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use lunepack_core::engine::{Engine, Ports, serve};
use lunepack_core::service::{
    AttemptAnswer, ClientSession, ClientTimeouts, CommitOutcome, ConfirmAnswer, DocumentKind,
    ErrorCode, ObjectKind, OutgoingDocument, ServerSession, StageBegun, Token, VerifyClass,
};
use lunepack_core::{
    AppId, Channel, CodecId, DirClass, Floors, Fs, InstallMeta, InstallState, LockGuard,
    MachinePolicy, MachineStore, PayloadKind, RelPath, RootParts, Scope, ServiceError,
    Sha256Digest, Target, UPDATE_CONFIG_FILE, UpdateConfig, Version,
};
use lunepack_testkit::{
    ChainFixture, FakeClock, FakeCodec, FakeHasher, FakeIntegration, FakePolicy, FakeProcess,
    FakeProtect, FakePublisherCheck, FakeRegistrar, FakeRng, FakeVerifier, IntegrationOp,
    MemDuplex, MemFs, PackBuilder, SUITE_APP_ID, SUITE_T0, abs_path, mem_duplex, run_protect_suite,
    run_service_channel_suite,
};

const TARGET: Target = Target::WindowsX86_64;
const CONFIG: &str = UPDATE_CONFIG_FILE;

fn v(t: &str) -> Version {
    Version::parse(t).unwrap()
}

fn app() -> AppId {
    AppId::parse(SUITE_APP_ID).unwrap()
}

fn stable() -> Channel {
    Channel::parse("stable").unwrap()
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

fn config_bytes(fx: &ChainFixture<'_>, version: &str, channel: &str, timeout: u64) -> Vec<u8> {
    UpdateConfig::new(
        &fx.trusted_root(1, 1, &[0]),
        v(version),
        TARGET,
        "https://updates.example.org/hello/",
        Channel::parse(channel).unwrap(),
        timeout,
        meta(),
    )
    .unwrap()
    .to_bytes()
    .unwrap()
}

/// The files of a release: an entry that changes per version, a file that never changes, a
/// second changing file and the update config.
fn release_pack(fx: &ChainFixture<'_>, version: &str, channel: &str) -> PackBuilder {
    let mut pack = PackBuilder::new();
    pack.file(
        fx.hasher,
        "app.exe",
        format!("entry of {version}").as_bytes(),
        CodecId::Lzma2,
    )
    .file(
        fx.hasher,
        "readme.txt",
        b"unchanged readme",
        CodecId::Stored,
    )
    .file(
        fx.hasher,
        "lib.dll",
        format!("library of {version}").as_bytes(),
        CodecId::Lzma2,
    )
    .file(
        fx.hasher,
        CONFIG,
        &config_bytes(fx, version, channel, 60),
        CodecId::Stored,
    );
    pack
}

/// The signed documents of one release.
struct Release {
    keys: Vec<u8>,
    feed: Vec<u8>,
    manifest: Vec<u8>,
    pack: PackBuilder,
}

impl Release {
    fn new(fx: &ChainFixture<'_>, version: &str, seq: u64) -> Release {
        Release::with(fx, version, seq, "stable", &[0])
    }

    fn with(
        fx: &ChainFixture<'_>,
        version: &str,
        seq: u64,
        tree_channel: &str,
        keys_signers: &[u8],
    ) -> Release {
        let pack = release_pack(fx, version, tree_channel);
        let manifest = fx.envelope(
            PayloadKind::Manifest,
            &fx.manifest_document(version, TARGET, &pack).to_payload(),
            &[5],
        );
        let keys = fx.envelope(
            PayloadKind::Keys,
            &fx.keyset_document(1, 1, None, 1, &[5]).to_payload(),
            keys_signers,
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
        Release {
            keys,
            feed,
            manifest,
            pack,
        }
    }

    fn documents(&self) -> Vec<OutgoingDocument<'_>> {
        vec![
            OutgoingDocument {
                kind: DocumentKind::Keys,
                bytes: &self.keys,
            },
            OutgoingDocument {
                kind: DocumentKind::Feed,
                bytes: &self.feed,
            },
            OutgoingDocument {
                kind: DocumentKind::Manifest,
                bytes: &self.manifest,
            },
        ]
    }

    fn pack_sha(&self) -> Sha256Digest {
        FakeHasher.sha256_of(&self.pack.bytes)
    }

    /// `(sha256, bytes)` of the frame of `path`.
    fn frame(&self, path: &str) -> (Sha256Digest, Vec<u8>) {
        let e = self
            .pack
            .entries
            .iter()
            .find(|e| e.path.as_str() == path)
            .unwrap();
        let f = e.frame.as_ref().unwrap();
        let (at, len) = (f.offset.get() as usize, f.length.get() as usize);
        (f.sha256, self.pack.bytes[at..at + len].to_vec())
    }
}

trait Sha {
    fn sha256_of(&self, b: &[u8]) -> Sha256Digest;
}

impl Sha for FakeHasher {
    fn sha256_of(&self, b: &[u8]) -> Sha256Digest {
        lunepack_core::Hasher::sha256(self, b)
    }
}

/// A machine install of 1.0.0 at `R` on a fake filesystem, with every port faked.
struct Machine {
    fs: MemFs,
    protect: FakeProtect,
    policy: FakePolicy,
    integration: FakeIntegration,
    publisher: FakePublisherCheck,
    registrar: FakeRegistrar,
    process: FakeProcess,
    rng: FakeRng,
    clock: FakeClock,
    codec: FakeCodec,
    root: PathBuf,
    monotonic: AtomicU64,
}

fn fx() -> ChainFixture<'static> {
    ChainFixture::fake()
}

impl Machine {
    fn new() -> Machine {
        let fs = MemFs::new();
        let protect = FakeProtect::new(&fs);
        let root = abs_path("/pf/Hello");
        let m = Machine {
            protect,
            policy: FakePolicy::new(),
            integration: FakeIntegration::new(),
            publisher: FakePublisherCheck::new([]),
            registrar: FakeRegistrar::new(),
            process: FakeProcess::new(abs_path("/pf/Hello/app/1.0.0/app.exe")),
            rng: FakeRng::new(7),
            clock: FakeClock::new(SUITE_T0 + 3600),
            codec: FakeCodec::new(),
            root,
            monotonic: AtomicU64::new(1000),
            fs,
        };
        for (dir, class) in lunepack_core::engine::protected_dirs(&m.root) {
            m.fs.create_dir_all(&dir).unwrap();
            m.protect.mark(&dir, class);
        }
        m.write_tree("1.0.0");
        let fx = fx();
        let store = m.store();
        let loaded = store.load(&m.fs, &FakeHasher).unwrap();
        let first = InstallState::new(1, app(), Scope::Machine, [9; 16], TARGET)
            .install(v("1.0.0"), SUITE_T0, TARGET, [9; 16])
            .raise_floors(&Floors {
                root: Some(RootParts::from_trusted(&fx.trusted_root(1, 1, &[0]))),
                ..Floors::default()
            });
        store.commit(&m.fs, &loaded, &first, &FakeHasher).unwrap();
        m
    }

    fn store(&self) -> MachineStore {
        MachineStore {
            dir: self.root.join(".lunepack").join("state"),
            app_id: app(),
        }
    }

    fn record(&self) -> InstallState {
        self.store()
            .load(&self.fs, &FakeHasher)
            .unwrap()
            .record
            .unwrap()
    }

    fn write_tree(&self, version: &str) {
        let fx = fx();
        let dir = self.root.join("app").join(version);
        self.fs.create_dir_all(&dir).unwrap();
        let files: [(&str, Vec<u8>); 4] = [
            ("app.exe", format!("entry of {version}").into_bytes()),
            ("readme.txt", b"unchanged readme".to_vec()),
            ("lib.dll", format!("library of {version}").into_bytes()),
            (CONFIG, config_bytes(&fx, version, "stable", 60)),
        ];
        for (name, bytes) in files {
            let mut w = self.fs.create_new(&dir.join(name)).unwrap();
            std::io::Write::write_all(&mut w, &bytes).unwrap();
            w.sync().unwrap();
        }
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
        }
    }

    fn engine(&self) -> Engine<'_> {
        Engine::open(self.ports(), &self.root).expect("open")
    }

    fn advance(&self, secs: u64) {
        self.monotonic.fetch_add(secs, Ordering::SeqCst);
    }

    fn incoming(&self) -> PathBuf {
        self.root.join(".lunepack").join("machine").join("incoming")
    }

    fn uploads(&self) -> usize {
        self.fs.list_dir(&self.incoming()).map_or(0, |e| e.len())
    }

    fn exists(&self, p: &Path) -> bool {
        self.fs.symlink_metadata(p).unwrap().is_some()
    }
}

/// One connection: the engine serves on a scoped thread while `f` runs the client.
fn connect<R>(
    m: &Machine,
    engine: &mut Engine<'_>,
    f: impl FnOnce(&mut ClientSession<MemDuplex>) -> R,
) -> (R, Result<(), ServiceError>) {
    let (client_end, server_end) = mem_duplex();
    thread::scope(|s| {
        let server = s.spawn(|| {
            let session = ServerSession::accept(server_end, app()).expect("hello");
            let now = || Duration::from_secs(m.monotonic.load(Ordering::SeqCst));
            serve(session, engine, &now)
        });
        let timeouts = ClientTimeouts {
            hello: Some(Duration::from_secs(10)),
            answer: Some(Duration::from_secs(30)),
        };
        let mut client = ClientSession::connect(client_end, app(), timeouts).expect("connect");
        let r = f(&mut client);
        drop(client);
        (r, server.join().expect("server thread"))
    })
}

fn answered(code: ErrorCode) -> ServiceError {
    ServiceError::Answered { code, class: None }
}

/// Stages `rel` completely with the pack: begin, put, commit.
fn stage_with_pack(c: &mut ClientSession<MemDuplex>, rel: &Release) -> CommitOutcome {
    assert_eq!(
        c.stage_begin(&stable(), &rel.documents()).unwrap(),
        StageBegun::Ready(v("1.1.0"))
    );
    c.put(
        ObjectKind::Pack,
        rel.pack_sha(),
        rel.pack.bytes.len() as u64,
        &mut &rel.pack.bytes[..],
    )
    .unwrap();
    c.stage_commit(&mut |_, _| {}).unwrap()
}

/// Stages and applies 1.1.0; returns the token.
fn staged_and_applied(m: &Machine, engine: &mut Engine<'_>) -> Token {
    let rel = Release::new(&fx(), "1.1.0", 2);
    let (token, end) = connect(m, engine, |c| {
        assert_eq!(stage_with_pack(c, &rel), CommitOutcome::Staged(v("1.1.0")));
        c.apply(&v("1.1.0")).unwrap()
    });
    end.unwrap();
    token
}

// ---- the full cycle ------------------------------------------------------------------------------

#[test]
fn stage_apply_confirm() {
    let m = Machine::new();
    let mut engine = m.engine();
    let rel = Release::new(&fx(), "1.1.0", 2);
    let (token, end) = connect(&m, &mut engine, |c| {
        let s = c.status().unwrap();
        assert_eq!(s.current, v("1.0.0"));
        assert!(!s.self_update_disabled);
        assert_eq!(
            c.stage_begin(&stable(), &rel.documents()).unwrap(),
            StageBegun::Ready(v("1.1.0"))
        );
        c.put(
            ObjectKind::Pack,
            rel.pack_sha(),
            rel.pack.bytes.len() as u64,
            &mut &rel.pack.bytes[..],
        )
        .unwrap();
        let mut seen = 0;
        assert_eq!(
            c.stage_commit(&mut |_, _| seen += 1).unwrap(),
            CommitOutcome::Staged(v("1.1.0"))
        );
        assert!(seen > 0, "progress was reported");
        assert_eq!(c.status().unwrap().staged, Some(v("1.1.0")));
        c.apply(&v("1.1.0")).unwrap()
    });
    end.unwrap();
    let r = m.record();
    assert_eq!(r.current.as_ref().unwrap().version, v("1.1.0"));
    assert_eq!(r.pending.as_ref().unwrap().version, v("1.1.0"));
    assert_eq!(
        r.health.as_ref().unwrap().token_sha256,
        FakeHasher.sha256_of(token.as_bytes()),
        "only the token's SHA-256 is recorded"
    );
    assert_eq!(r.floors.feed_seq.get(&stable()), Some(&2));
    assert_eq!(m.uploads(), 0, "the session's upload folder is gone");
    assert!(m.exists(&m.root.join("app").join("1.1.0").join("app.exe")));
    let calls = m.integration.calls();
    let last = calls.last().unwrap();
    assert_eq!(
        (last.op, last.scope, last.version.clone()),
        (IntegrationOp::Apply, Scope::Machine, v("1.1.0"))
    );
    assert_eq!(last.install_root, m.root);
    assert!(last.previous.is_some());
    assert!(
        m.protect
            .created()
            .iter()
            .all(|(p, c)| *c == DirClass::AdminOnly && p.starts_with(m.incoming())),
        "uploads go only to admin-only folders under incoming"
    );
    let (answer, end) = connect(&m, &mut engine, |c| c.confirm(&v("1.1.0"), &token));
    end.unwrap();
    assert_eq!(answer.unwrap(), ConfirmAnswer::Confirmed);
    let r = m.record();
    assert!(r.pending.is_none() && r.health.is_none());
}

#[test]
fn the_need_fetch_path_and_the_commit_limit() {
    let m = Machine::new();
    let mut engine = m.engine();
    let rel = Release::new(&fx(), "1.1.0", 2);
    let (_, end) = connect(&m, &mut engine, |c| {
        c.stage_begin(&stable(), &rel.documents()).unwrap();
        let (sha, bytes) = rel.frame("app.exe");
        c.put(ObjectKind::Frame, sha, bytes.len() as u64, &mut &bytes[..])
            .unwrap();
        // readme.txt is unchanged; lib.dll and the config have no source yet.
        match c.stage_commit(&mut |_, _| {}).unwrap() {
            CommitOutcome::NeedFetch { paths, more } => {
                let names: Vec<&str> = paths.iter().map(|p| p.as_str()).collect();
                assert_eq!(names, ["lib.dll", CONFIG]);
                assert!(!more);
            }
            other => panic!("{other:?}"),
        }
        for path in ["lib.dll", CONFIG] {
            let (sha, bytes) = rel.frame(path);
            c.put(ObjectKind::Frame, sha, bytes.len() as u64, &mut &bytes[..])
                .unwrap();
        }
        assert_eq!(
            c.stage_commit(&mut |_, _| {}).unwrap(),
            CommitOutcome::Staged(v("1.1.0"))
        );
    });
    end.unwrap();
    assert_eq!(m.record().staged.unwrap().version, v("1.1.0"));
    // Three commits that need data, then a fourth: malformed, the connection ends.
    let m = Machine::new();
    let mut engine = m.engine();
    let (fourth, end) = connect(&m, &mut engine, |c| {
        c.stage_begin(&stable(), &rel.documents()).unwrap();
        for _ in 0..3 {
            assert!(matches!(
                c.stage_commit(&mut |_, _| {}).unwrap(),
                CommitOutcome::NeedFetch { .. }
            ));
        }
        c.stage_commit(&mut |_, _| {})
    });
    assert_eq!(fourth, Err(answered(ErrorCode::Malformed)));
    assert!(matches!(end, Err(ServiceError::Malformed(_))));
    assert!(m.record().staged.is_none());
    assert_eq!(m.uploads(), 0);
    assert!(!m.exists(&m.root.join("app").join("1.1.0.partial")));
}

// ---- verification ---------------------------------------------------------------------------------

#[test]
fn a_flipped_pack_byte_is_a_hash_mismatch() {
    let m = Machine::new();
    let mut engine = m.engine();
    let rel = Release::new(&fx(), "1.1.0", 2);
    let (r, end) = connect(&m, &mut engine, |c| {
        c.stage_begin(&stable(), &rel.documents()).unwrap();
        let mut bad = rel.pack.bytes.clone();
        bad[3] ^= 1;
        let r = c.put(
            ObjectKind::Pack,
            rel.pack_sha(),
            bad.len() as u64,
            &mut &bad[..],
        );
        // The session goes on: the next commit has no source for anything that changed.
        assert!(matches!(
            c.stage_commit(&mut |_, _| {}).unwrap(),
            CommitOutcome::NeedFetch { .. }
        ));
        r
    });
    end.unwrap();
    assert_eq!(r, Err(answered(ErrorCode::HashMismatch)));
    assert!(m.record().staged.is_none());
}

#[test]
fn documents_under_another_root_fail_verification() {
    let m = Machine::new();
    let mut engine = m.engine();
    let rel = Release::with(&fx(), "1.1.0", 2, "stable", &[3]);
    let (r, end) = connect(&m, &mut engine, |c| {
        c.stage_begin(&stable(), &rel.documents())
    });
    end.unwrap();
    assert_eq!(
        r,
        Err(ServiceError::Answered {
            code: ErrorCode::VerifyFailed,
            class: Some(VerifyClass::Signature)
        })
    );
    assert_eq!(m.uploads(), 0);
}

#[test]
fn equal_older_and_bad_versions_are_no_update() {
    for version in ["1.0.0", "0.9.0", "1.1.0"] {
        let m = Machine::new();
        if version == "1.1.0" {
            let store = m.store();
            let loaded = store.load(&m.fs, &FakeHasher).unwrap();
            let next = loaded.record.clone().unwrap().mark_bad(v("1.1.0"));
            store.commit(&m.fs, &loaded, &next, &FakeHasher).unwrap();
        }
        let mut engine = m.engine();
        let rel = Release::new(&fx(), version, 2);
        let (r, end) = connect(&m, &mut engine, |c| {
            c.stage_begin(&stable(), &rel.documents())
        });
        end.unwrap();
        assert_eq!(r, Ok(StageBegun::NoUpdate), "{version}");
        assert_eq!(m.uploads(), 0);
    }
}

#[test]
fn a_raised_floor_is_committed_and_a_replay_is_a_rollback() {
    let m = Machine::new();
    let mut engine = m.engine();
    let newer = Release::new(&fx(), "1.0.0", 5);
    let older = Release::new(&fx(), "1.1.0", 4);
    let (r, end) = connect(&m, &mut engine, |c| {
        assert_eq!(
            c.stage_begin(&stable(), &newer.documents()).unwrap(),
            StageBegun::NoUpdate
        );
        c.stage_begin(&stable(), &older.documents())
    });
    end.unwrap();
    assert_eq!(m.record().floors.feed_seq.get(&stable()), Some(&5));
    assert_eq!(
        r,
        Err(ServiceError::Answered {
            code: ErrorCode::VerifyFailed,
            class: Some(VerifyClass::Rollback)
        })
    );
}

#[test]
fn put_refuses_unlisted_wrong_size_and_repeated_objects() {
    let m = Machine::new();
    let mut engine = m.engine();
    let rel = Release::new(&fx(), "1.1.0", 2);
    let (rs, end) = connect(&m, &mut engine, |c| {
        c.stage_begin(&stable(), &rel.documents()).unwrap();
        let unlisted = c.put(
            ObjectKind::Frame,
            Sha256Digest::from_bytes([1; 32]),
            3,
            &mut &b"abc"[..],
        );
        let (sha, bytes) = rel.frame("app.exe");
        let wrong_size = c.put(
            ObjectKind::Frame,
            sha,
            bytes.len() as u64 + 1,
            &mut &[bytes.clone(), vec![0]].concat()[..],
        );
        let first = c.put(ObjectKind::Frame, sha, bytes.len() as u64, &mut &bytes[..]);
        let again = c.put(ObjectKind::Frame, sha, bytes.len() as u64, &mut &bytes[..]);
        (unlisted, wrong_size, first, again)
    });
    assert_eq!(rs.0, Err(answered(ErrorCode::NotInManifest)));
    assert_eq!(rs.1, Err(answered(ErrorCode::SizeMismatch)));
    assert_eq!(rs.2, Ok(()));
    assert_eq!(rs.3, Err(answered(ErrorCode::Malformed)));
    assert!(matches!(end, Err(ServiceError::Malformed(_))));
    assert_eq!(m.uploads(), 0);
}

// ---- apply, confirm, rollback, attempt ----------------------------------------------------------

#[test]
fn apply_refusals() {
    let m = Machine::new();
    let mut engine = m.engine();
    let (r, end) = connect(&m, &mut engine, |c| c.apply(&v("1.1.0")));
    end.unwrap();
    assert_eq!(r, Err(answered(ErrorCode::NothingStaged)));
    let rel = Release::new(&fx(), "1.1.0", 2);
    let (rs, end) = connect(&m, &mut engine, |c| {
        stage_with_pack(c, &rel);
        let wrong = c.apply(&v("1.2.0"));
        let ok = c.apply(&v("1.1.0"));
        let again = c.apply(&v("1.1.0"));
        (wrong, ok.is_ok(), again)
    });
    end.unwrap();
    assert_eq!(rs.0, Err(answered(ErrorCode::VersionMismatch)));
    assert!(rs.1);
    assert_eq!(rs.2, Err(answered(ErrorCode::PendingExists)));
}

#[test]
fn confirm_with_a_wrong_token_or_for_another_version() {
    let m = Machine::new();
    let mut engine = m.engine();
    let token = staged_and_applied(&m, &mut engine);
    let before = m.record();
    let (rs, end) = connect(&m, &mut engine, |c| {
        (
            c.confirm(&v("1.1.0"), &Token::from_bytes([0; 32])),
            c.confirm(&v("1.0.0"), &token),
        )
    });
    end.unwrap();
    assert_eq!(rs.0, Err(answered(ErrorCode::TokenMismatch)));
    assert_eq!(rs.1, Ok(ConfirmAnswer::NothingPending));
    assert_eq!(m.record(), before, "the record is unchanged");
}

#[test]
fn rollback_with_the_token() {
    let m = Machine::new();
    let mut engine = m.engine();
    let token = staged_and_applied(&m, &mut engine);
    let (r, end) = connect(&m, &mut engine, |c| c.rollback(&v("1.1.0"), &token));
    end.unwrap();
    assert_eq!(r, Ok(v("1.0.0")));
    let rec = m.record();
    assert_eq!(rec.current.unwrap().version, v("1.0.0"));
    assert!(rec.pending.is_none() && rec.previous.is_none());
    assert_eq!(rec.bad, vec![v("1.1.0")]);
    let calls = m.integration.calls();
    let last = calls.last().unwrap();
    assert_eq!(
        (last.op, last.scope),
        (IntegrationOp::Apply, Scope::Machine)
    );
    assert_eq!(
        last.version,
        v("1.0.0"),
        "refreshed from the previous config"
    );
}

#[test]
fn attempts_under_and_after_the_lease() {
    let m = Machine::new();
    let mut engine = m.engine();
    let applier = staged_and_applied(&m, &mut engine);
    let seq = m.record().seq;
    let (r, end) = connect(&m, &mut engine, |c| c.attempt(&v("1.1.0")));
    end.unwrap();
    assert_eq!(r, Ok(AttemptAnswer::Supervised));
    assert_eq!(m.record().seq, seq, "nothing is committed under a lease");
    // The lease is the health timeout (60 s) plus 15 s.
    m.advance(76);
    let (r, end) = connect(&m, &mut engine, |c| {
        let counted = c.attempt(&v("1.1.0")).unwrap();
        let old = c.confirm(&v("1.1.0"), &applier);
        (counted, old)
    });
    end.unwrap();
    let AttemptAnswer::Counted { attempts, token } = r.0 else {
        panic!("{:?}", r.0)
    };
    assert_eq!(attempts, 1);
    assert_eq!(
        r.1,
        Err(answered(ErrorCode::TokenMismatch)),
        "the applier's old token no longer confirms"
    );
    let (r, end) = connect(&m, &mut engine, |c| c.confirm(&v("1.1.0"), &token));
    end.unwrap();
    assert_eq!(
        r,
        Ok(ConfirmAnswer::Confirmed),
        "the counted start confirms"
    );
    let (r, end) = connect(&m, &mut engine, |c| c.attempt(&v("1.1.0")));
    end.unwrap();
    assert_eq!(r, Ok(AttemptAnswer::NotPending));
}

#[test]
fn the_host_can_ask_whether_a_lease_runs() {
    let m = Machine::new();
    let mut engine = m.engine();
    let now = || Duration::from_secs(m.monotonic.load(Ordering::SeqCst));
    assert!(!engine.lease_running(now()), "nothing applied: no lease");
    staged_and_applied(&m, &mut engine);
    assert!(engine.lease_running(now()), "apply starts the lease");
    m.advance(60);
    assert!(
        engine.lease_running(now()),
        "inside the health window plus 15 s"
    );
    m.advance(16);
    assert!(!engine.lease_running(now()), "the lease has run out");
}

#[test]
fn the_fourth_attempt_rolls_back() {
    let m = Machine::new();
    let mut engine = m.engine();
    staged_and_applied(&m, &mut engine);
    for n in 1..=3 {
        m.advance(76);
        let (r, end) = connect(&m, &mut engine, |c| c.attempt(&v("1.1.0")));
        end.unwrap();
        assert!(
            matches!(r, Ok(AttemptAnswer::Counted { attempts, .. }) if attempts == n),
            "{r:?}"
        );
        let (r, end) = connect(&m, &mut engine, |c| c.attempt(&v("1.1.0")));
        end.unwrap();
        assert_eq!(r, Ok(AttemptAnswer::Supervised), "a counted attempt leases");
    }
    m.advance(76);
    let (r, end) = connect(&m, &mut engine, |c| c.attempt(&v("1.1.0")));
    end.unwrap();
    assert_eq!(
        r,
        Ok(AttemptAnswer::RolledBack {
            current: v("1.0.0")
        })
    );
    let rec = m.record();
    assert_eq!(rec.current.unwrap().version, v("1.0.0"));
    assert_eq!(rec.bad, vec![v("1.1.0")]);
}

// ---- policy, protection, channel, lock -----------------------------------------------------------

#[test]
fn policy_refuses_stage_and_apply_only() {
    let m = Machine::new();
    let mut engine = m.engine();
    let token = staged_and_applied(&m, &mut engine);
    m.policy.set(MachinePolicy {
        self_update_disabled: true,
        no_update_ui: false,
    });
    let rel = Release::new(&fx(), "1.2.0", 3);
    let (rs, end) = connect(&m, &mut engine, |c| {
        (
            c.status().map(|s| s.self_update_disabled),
            c.stage_begin(&stable(), &rel.documents()),
            c.apply(&v("1.1.0")),
            c.attempt(&v("1.1.0")),
            c.confirm(&v("1.1.0"), &token),
        )
    });
    end.unwrap();
    assert_eq!(rs.0, Ok(true));
    assert_eq!(rs.1, Err(answered(ErrorCode::DisabledByPolicy)));
    assert_eq!(rs.2, Err(answered(ErrorCode::DisabledByPolicy)));
    assert_eq!(rs.3, Ok(AttemptAnswer::Supervised));
    assert_eq!(rs.4, Ok(ConfirmAnswer::Confirmed));
}

#[test]
fn a_failing_protection_check_is_not_protected() {
    let m = Machine::new();
    let mut engine = m.engine();
    let before = m.record();
    for (dir, _) in lunepack_core::engine::protected_dirs(&m.root) {
        m.protect.set_unprotected(&dir, true);
        let rel = Release::new(&fx(), "1.1.0", 2);
        let (rs, end) = connect(&m, &mut engine, |c| {
            (
                c.status().err(),
                c.stage_begin(&stable(), &rel.documents()).err(),
            )
        });
        end.unwrap();
        assert_eq!(rs.0, Some(answered(ErrorCode::NotProtected)));
        assert_eq!(rs.1, Some(answered(ErrorCode::NotProtected)));
        m.protect.set_unprotected(&dir, false);
        assert!(
            Engine::open(m.ports(), &m.root).is_ok(),
            "open passes again once protected"
        );
        m.protect.set_unprotected(&dir, true);
        assert_eq!(
            Engine::open(m.ports(), &m.root).err().map(|e| e.code),
            Some(ErrorCode::NotProtected)
        );
        m.protect.set_unprotected(&dir, false);
    }
    assert_eq!(m.record(), before);
}

#[test]
fn another_channel_is_not_allowed() {
    let m = Machine::new();
    let mut engine = m.engine();
    let fx = fx();
    // A feed for channel `beta` (signed for it) against an install that follows `stable`.
    let beta = Channel::parse("beta").unwrap();
    let rel = Release::new(&fx, "1.1.0", 2);
    let (r, end) = connect(&m, &mut engine, |c| c.stage_begin(&beta, &rel.documents()));
    end.unwrap();
    assert_eq!(r, Err(answered(ErrorCode::ChannelNotAllowed)));
}

#[test]
fn the_lock_held_by_another_host_is_busy() {
    let m = Machine::new();
    let mut engine = m.engine();
    let other = m.fs.process();
    let lock: Box<dyn LockGuard> = other
        .try_lock(&m.root.join(".lunepack").join("machine").join("lock"))
        .unwrap()
        .unwrap();
    let (r, end) = connect(&m, &mut engine, |c| c.status().err());
    end.unwrap();
    assert_eq!(r, Some(answered(ErrorCode::Busy)));
    drop(lock);
}

// ---- the session's end -----------------------------------------------------------------------------

#[test]
fn a_connection_dropped_mid_put_leaves_nothing() {
    let m = Machine::new();
    let mut engine = m.engine();
    let rel = Release::new(&fx(), "1.1.0", 2);
    let before = std::cell::RefCell::new(None);
    let (_, end) = connect(&m, &mut engine, |c| {
        c.stage_begin(&stable(), &rel.documents()).unwrap();
        // The floors stage_begin raised are committed; nothing after it may change the record.
        *before.borrow_mut() = Some(m.record());
        assert_eq!(m.uploads(), 1, "the session has its folder");
        // Declare the whole pack, send half of it, then close.
        let half = &rel.pack.bytes[..rel.pack.bytes.len() / 2];
        let r = c.put(
            ObjectKind::Pack,
            rel.pack_sha(),
            rel.pack.bytes.len() as u64,
            &mut &half[..],
        );
        assert!(matches!(r, Err(ServiceError::Source(_))));
    });
    assert!(matches!(end, Err(ServiceError::Malformed(_))));
    assert_eq!(m.uploads(), 0, "the session folder is gone");
    assert!(!m.exists(&m.root.join("app").join("1.1.0.partial")));
    assert!(!m.exists(&m.root.join("app").join("1.1.0")));
    assert_eq!(Some(m.record()), before.into_inner());
}

#[test]
fn leftover_upload_folders_are_removed_at_open() {
    let m = Machine::new();
    let left = m.incoming().join("0123456789abcdef0123456789abcdef");
    m.fs.create_dir_all(&left).unwrap();
    let _engine = m.engine();
    assert_eq!(m.uploads(), 0);
}

#[test]
fn out_of_order_requests_are_malformed() {
    let m = Machine::new();
    let mut engine = m.engine();
    let before = m.record();
    let rel = Release::new(&fx(), "1.1.0", 2);
    let (r, end) = connect(&m, &mut engine, |c| {
        c.put(
            ObjectKind::Pack,
            rel.pack_sha(),
            rel.pack.bytes.len() as u64,
            &mut &rel.pack.bytes[..],
        )
    });
    assert!(matches!(
        r,
        Err(ServiceError::Answered {
            code: ErrorCode::Malformed,
            ..
        }) | Err(ServiceError::Io(_))
    ));
    assert!(matches!(end, Err(ServiceError::Malformed(_))));
    let (r, end) = connect(&m, &mut engine, |c| c.stage_commit(&mut |_, _| {}));
    assert_eq!(r, Err(answered(ErrorCode::Malformed)));
    assert!(matches!(end, Err(ServiceError::Malformed(_))));
    let (r, end) = connect(&m, &mut engine, |c| {
        c.stage_begin(&stable(), &rel.documents()).unwrap();
        c.stage_begin(&stable(), &rel.documents())
    });
    assert_eq!(r, Err(answered(ErrorCode::Malformed)));
    assert!(matches!(end, Err(ServiceError::Malformed(_))));
    // Only the floors the one accepted stage_begin raised changed.
    let after = m.record();
    assert_eq!(
        (after.current, after.staged, after.pending, after.bad),
        (before.current, before.staged, before.pending, before.bad)
    );
    assert_eq!(m.uploads(), 0);
}

// ---- the engine's inputs ---------------------------------------------------------------------------

/// M4-SEC-obs1 and M10-D14: the engine names no user directory, scope or counters record.
#[test]
fn the_engine_source_names_no_user_state() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../lunepack-core/src/engine.rs"),
    )
    .unwrap();
    for word in [
        "MachineScope",
        "InstallCounters",
        "UserScope",
        "LocalAppData",
        "local_app_data",
        "data_home",
        "std::env",
    ] {
        assert!(!src.contains(word), "engine.rs names `{word}`");
    }
}

/// M10-D20: every deletion under `R` asks the strict check; the rename is not called a guard.
#[test]
fn the_engine_asks_only_the_strict_in_use_check() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../lunepack-core/src/engine.rs"),
    )
    .unwrap();
    assert!(
        !src.contains(".tree_in_use("),
        "engine.rs calls tree_in_use instead of tree_in_use_strict"
    );
    assert!(src.contains(".tree_in_use_strict("));
    let flat = src
        .lines()
        .map(|l| {
            l.trim()
                .trim_start_matches("///")
                .trim_start_matches("//")
                .trim()
        })
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        !flat.contains("the rename is the authoritative in-use check"),
        "a comment still calls the rename the guard"
    );
}

/// The fake's strict check has its own queue and log, apart from `tree_in_use`'s.
#[test]
fn the_fake_strict_check_has_its_own_queue() {
    use lunepack_core::Process;
    let fake = FakeProcess::new(abs_path("/pf/Hello/app/1.0.0/app.exe"));
    let tree = abs_path("/pf/Hello/app/0.9.0");
    fake.script_in_use(true);
    fake.script_in_use_strict(true);
    assert!(fake.tree_in_use_strict(&tree, &[]).unwrap());
    assert!(
        !fake.tree_in_use_strict(&tree, &[]).unwrap(),
        "empty: false"
    );
    assert!(
        fake.tree_in_use(&tree, &[]).unwrap(),
        "its queue is untouched"
    );
    assert_eq!(fake.strict_calls(), vec![(tree.clone(), Vec::new()); 2]);
    assert_eq!(fake.in_use_calls(), vec![(tree, Vec::new())]);
}

// ---- the fakes against their suites -------------------------------------------------------------

#[test]
fn the_fakes_pass_their_suites() {
    let fs = MemFs::new();
    let root = abs_path("/scratch");
    fs.create_dir_all(&root).unwrap();
    run_protect_suite(&FakeProtect::new(&fs), &fs, &root);
    run_service_channel_suite(&|| {
        let (a, b) = mem_duplex();
        (Box::new(a), Box::new(b))
    });
}

// ---- the publisher check (M9-D9) ------------------------------------------------------------------

#[test]
fn the_publisher_check_runs_under_the_installed_policy() {
    for (answer, staged) in [(Ok(true), true), (Ok(false), false)] {
        let mut m = Machine::new();
        m.publisher = FakePublisherCheck::new([answer]);
        // The installed tree enforces the check.
        let path = m.root.join("app").join("1.0.0").join(CONFIG);
        let mut config = UpdateConfig::parse(&m.fs.read_capped(&path, 1 << 16).unwrap()).unwrap();
        config.publisher_check = lunepack_core::PublisherPolicy::Enforce;
        m.fs.remove_file(&path).unwrap();
        let mut w = m.fs.create_new(&path).unwrap();
        std::io::Write::write_all(&mut w, &config.to_bytes().unwrap()).unwrap();
        w.sync().unwrap();
        drop(w);
        let mut engine = m.engine();
        let rel = Release::new(&fx(), "1.1.0", 2);
        let (r, end) = connect(&m, &mut engine, |c| {
            c.stage_begin(&stable(), &rel.documents()).unwrap();
            c.put(
                ObjectKind::Pack,
                rel.pack_sha(),
                rel.pack.bytes.len() as u64,
                &mut &rel.pack.bytes[..],
            )
            .unwrap();
            c.stage_commit(&mut |_, _| {})
        });
        end.unwrap();
        let calls = m.publisher.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0.root, m.root.join("app").join("1.0.0"));
        assert_eq!(calls[0].1.root, m.root.join("app").join("1.1.0"));
        let rec = m.record();
        if staged {
            assert_eq!(r, Ok(CommitOutcome::Staged(v("1.1.0"))));
            assert!(rec.bad.is_empty());
        } else {
            assert_eq!(r, Err(answered(ErrorCode::PublisherMismatch)));
            assert!(rec.staged.is_none());
            assert_eq!(
                rec.bad,
                vec![v("1.1.0")],
                "a different publisher is marked bad"
            );
        }
    }
}
