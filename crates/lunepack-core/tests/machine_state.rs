//! The machine side of the install state (M10 step 1): the machine store, the root rule of
//! M4-SEC-obs1 in `MachineScope::effective_floors`, the `last_run` member of an install-counters
//! record (M10-D16), and the machine lifecycle transitions (`lifecycle::machine`, M10-D3).
//!
//! Records are written by the real writer (`commit`, `MachineStore::commit`), or for records only
//! another writer leaves, a payload taken from a `commit` file, edited, and framed by the real
//! framing code through `commit_raw_payload`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use lunepack_core::lifecycle::{self, MAX_ATTEMPTS, machine};
use lunepack_core::state::{MAX_RECORD_BYTES, commit, commit_raw_payload, load};
use lunepack_core::trust::PublicKey;
use lunepack_core::{
    AppId, AttemptOutcome, Channel, ConfirmOutcome, Floors, Fs, Hasher, Health, InstallCounters,
    InstallState, LifecycleError, MachineScope, MachineStore, PendingRef, RootParts, Scope,
    Sha256Digest, StagedRef, StateError, Target, TokenCheck, UserScope, Version,
};
use lunepack_testkit::{FakeHasher, MemFs};
use serde_json::{Map, Value, json};

const H: FakeHasher = FakeHasher;
const TARGET: Target = Target::WindowsX86_64;
const ID: [u8; 16] = [7; 16];

fn app() -> AppId {
    AppId::parse("org.example.hello").unwrap()
}

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn chan(text: &str) -> Channel {
    Channel::parse(text).unwrap()
}

fn key(label: &str) -> PublicKey {
    PublicKey::from_bytes(*H.sha256(label.as_bytes()).as_bytes())
}

fn token(label: &str) -> Sha256Digest {
    H.sha256(label.as_bytes())
}

fn machine_dir() -> PathBuf {
    PathBuf::from("/programs/Hello/.lunepack/state")
}

fn user_dir() -> PathBuf {
    PathBuf::from("/users/u/lunepack/org.example.hello/state")
}

fn store() -> MachineStore {
    MachineStore {
        dir: machine_dir(),
        app_id: app(),
    }
}

fn scope() -> MachineScope {
    MachineScope {
        machine_dir: machine_dir(),
        user_dir: user_dir(),
        app_id: app(),
    }
}

fn payload(file: &[u8]) -> Map<String, Value> {
    let len = u32::from_be_bytes([file[5], file[6], file[7], file[8]]) as usize;
    serde_json::from_slice(&file[9..9 + len]).unwrap()
}

fn record_bytes(fs: &dyn Fs, dir: &Path, seq: u64) -> Vec<u8> {
    fs.read_capped(&dir.join(format!("{seq:020}.rec")), MAX_RECORD_BYTES)
        .unwrap()
}

// ---- effective floors: the root rule (M4-SEC-obs1) ------------------------------------------------

/// A deterministic xorshift, as in `tests/state.rs`.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) % n
    }

    fn root(&mut self) -> Option<RootParts> {
        match self.below(4) {
            0 => None,
            _ => {
                let count = 1 + self.below(3);
                let keys: Vec<PublicKey> = (0..count)
                    .map(|i| key(&format!("k{i}-{}", self.below(4))))
                    .collect();
                let mut unique: Vec<PublicKey> = Vec::new();
                for k in keys {
                    if !unique.contains(&k) {
                        unique.push(k);
                    }
                }
                Some(RootParts {
                    version: 1 + self.below(6),
                    threshold: 1 + self.below(unique.len() as u64),
                    keys: unique,
                })
            }
        }
    }

    fn floors(&mut self) -> Floors {
        let mut feed_seq = BTreeMap::new();
        for c in ["stable", "beta", "nightly"] {
            if self.below(2) == 0 {
                feed_seq.insert(chan(c), self.below(9));
            }
        }
        Floors {
            root: self.root(),
            keyset_version: self.below(9),
            feed_seq,
        }
    }
}

fn machine_with(floors: Floors) -> InstallState {
    let mut m = InstallState::new(1, app(), Scope::Machine, ID, TARGET);
    m.floors = floors;
    m
}

fn counters_with(floors: Floors) -> InstallCounters {
    let mut c = InstallCounters::new(1, app(), ID);
    c.floors = floors;
    c
}

#[test]
fn the_root_comes_only_from_the_machine_record_and_counters_raise_only_counters() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut higher_roots_seen = 0;
    for _ in 0..4000 {
        let m = machine_with(rng.floors());
        let c = counters_with(rng.floors());
        if c.floors.root > m.floors.root {
            higher_roots_seen += 1;
        }
        let e = MachineScope::effective_floors(&m, Some(&c));
        assert_eq!(e.root, m.floors.root, "the root is the machine record's");
        assert_eq!(
            e.keyset_version,
            m.floors.keyset_version.max(c.floors.keyset_version)
        );
        let channels: std::collections::BTreeSet<&Channel> = m
            .floors
            .feed_seq
            .keys()
            .chain(c.floors.feed_seq.keys())
            .collect();
        assert_eq!(e.feed_seq.len(), channels.len());
        for ch in channels {
            let want = m
                .floors
                .feed_seq
                .get(ch)
                .copied()
                .max(c.floors.feed_seq.get(ch).copied());
            assert_eq!(e.feed_seq.get(ch).copied(), want, "feed seq of {ch}");
        }
        assert_eq!(MachineScope::effective_floors(&m, None), m.floors);
    }
    // The generator really produced the dangerous case many times.
    assert!(higher_roots_seen > 500, "{higher_roots_seen}");
}

#[test]
fn a_counters_root_of_a_higher_version_threshold_or_other_keys_never_becomes_the_root() {
    let machine_root = RootParts {
        version: 2,
        threshold: 1,
        keys: vec![key("m")],
    };
    let attacker = [
        RootParts {
            version: 9,
            threshold: 1,
            keys: vec![key("x")],
        },
        RootParts {
            version: 2,
            threshold: 1,
            keys: vec![key("zz-sorts-higher")],
        },
        RootParts {
            version: 2,
            threshold: 2,
            keys: vec![key("m"), key("x")],
        },
    ];
    for machine in [None, Some(machine_root.clone())] {
        let m = machine_with(Floors {
            root: machine.clone(),
            ..Floors::default()
        });
        for root in &attacker {
            let c = counters_with(Floors {
                root: Some(root.clone()),
                keyset_version: 4,
                feed_seq: [(chan("stable"), 3)].into_iter().collect(),
            });
            let e = MachineScope::effective_floors(&m, Some(&c));
            assert_eq!(e.root, machine, "a counters root was taken");
            assert_eq!(e.keyset_version, 4);
            assert_eq!(e.feed_seq.get(&chan("stable")), Some(&3));
        }
    }
}

// ---- the machine store ----------------------------------------------------------------------------

#[test]
fn the_machine_store_commits_and_loads_machine_records_only() {
    let fs = MemFs::new();
    let s = store();
    let loaded = s.load(&fs, &H).unwrap();
    assert!(loaded.record.is_none());
    let user = InstallState::new(1, app(), Scope::User, ID, TARGET);
    assert!(matches!(
        s.commit(&fs, &loaded, &user, &H),
        Err(StateError::Invalid(_))
    ));
    assert!(fs.list_dir(&machine_dir()).is_err(), "nothing written");

    // The store numbers the record itself.
    let first = InstallState::new(42, app(), Scope::Machine, ID, TARGET);
    let written = s.commit(&fs, &loaded, &first, &H).unwrap();
    assert_eq!(written.seq, 1);
    let loaded = s.load(&fs, &H).unwrap();
    assert_eq!(loaded.record.as_ref(), Some(&written));
    // The library's reader sees the same record.
    assert_eq!(
        scope().load_machine(&fs, &H).unwrap().record,
        Some(written.clone())
    );

    // `commit`'s own rules hold: no lowered floor, the app id.
    let raised = written.raise_floors(&Floors {
        keyset_version: 3,
        ..Floors::default()
    });
    let raised = s.commit(&fs, &loaded, &raised, &H).unwrap();
    assert_eq!(raised.seq, 2);
    let loaded = s.load(&fs, &H).unwrap();
    let mut lowered = raised.clone();
    lowered.floors.keyset_version = 2;
    assert!(matches!(
        s.commit(&fs, &loaded, &lowered, &H),
        Err(StateError::FloorLowered)
    ));
    let mut other_app = raised.clone();
    other_app.app_id = AppId::parse("org.example.other").unwrap();
    assert!(matches!(
        s.commit(&fs, &loaded, &other_app, &H),
        Err(StateError::Invalid(_))
    ));
    // A second writer from the same load conflicts.
    s.commit(&fs, &loaded, &raised, &H).unwrap();
    assert!(matches!(
        s.commit(&fs, &loaded, &raised, &H),
        Err(StateError::Conflict { seq: 3 })
    ));
}

#[test]
fn the_machine_store_refuses_a_user_record_in_its_directory() {
    let fs = MemFs::new();
    let user = UserScope {
        dir: machine_dir(),
        app_id: app(),
    };
    let loaded = user.load(&fs, &H).unwrap();
    let record = InstallState::new(1, app(), Scope::User, ID, TARGET);
    user.commit(&fs, &loaded, &record, &H).unwrap();
    assert!(matches!(store().load(&fs, &H), Err(StateError::Invalid(_))));
}

// ---- last_run (M10-D16) ---------------------------------------------------------------------------

fn counters_dir() -> PathBuf {
    let m = InstallState::new(1, app(), Scope::Machine, ID, TARGET);
    scope().counters_dir(&m)
}

fn commit_counters(fs: &dyn Fs, c: &InstallCounters) -> InstallCounters {
    let dir = counters_dir();
    let loaded = load::<InstallCounters>(fs, &dir, &app(), &H).unwrap();
    commit(fs, &dir, &loaded, c, &H).unwrap()
}

fn load_counters(fs: &dyn Fs) -> Result<Option<InstallCounters>, StateError> {
    load::<InstallCounters>(fs, &counters_dir(), &app(), &H).map(|l| l.record)
}

/// Record `seq` of the counters directory written raw from `edited`.
fn raw_counters(fs: &dyn Fs, seq: u64, edited: &Map<String, Value>) {
    let bytes = serde_json::to_vec(edited).unwrap();
    commit_raw_payload(fs, &counters_dir(), seq, &bytes, &H).unwrap();
}

#[test]
fn a_counters_record_without_last_run_reads_none_and_is_written_without_it() {
    let fs = MemFs::new();
    let c = commit_counters(&fs, &InstallCounters::new(1, app(), ID));
    let p = payload(&record_bytes(&fs, &counters_dir(), 1));
    assert!(!p.contains_key("last_run"), "None leaves the member out");
    let back = load_counters(&fs).unwrap().unwrap();
    assert_eq!(back.last_run, None);
    assert_eq!(back, c);
}

#[test]
fn last_run_round_trips_byte_for_byte() {
    for text in ["1.2.0", "2.0.0-rc.1+build.5"] {
        let fs = MemFs::new();
        let mut c = InstallCounters::new(1, app(), ID);
        c.last_run = Some(v(text));
        let written = commit_counters(&fs, &c);
        let bytes = record_bytes(&fs, &counters_dir(), 1);
        assert_eq!(
            payload(&bytes).get("last_run"),
            Some(&Value::String(text.to_owned()))
        );
        let back = load_counters(&fs).unwrap().unwrap();
        assert_eq!(back, written);
        assert_eq!(
            back.last_run.as_ref().map(ToString::to_string).as_deref(),
            Some(text)
        );
        // The record read back, written again by the same writer as record 1, is the same bytes.
        let again = MemFs::new();
        commit_counters(&again, &back);
        assert_eq!(record_bytes(&again, &counters_dir(), 1), bytes, "{text}");
    }
}

#[test]
fn an_unknown_member_is_still_kept_beside_last_run() {
    let fs = MemFs::new();
    commit_counters(&fs, &InstallCounters::new(1, app(), ID));
    let mut p = payload(&record_bytes(&fs, &counters_dir(), 1));
    p.insert("seq".into(), json!(2));
    p.insert("x_future".into(), json!({"a": [1, 2]}));
    p.insert("last_run".into(), json!("1.0.0"));
    raw_counters(&fs, 2, &p);
    let record = load_counters(&fs).unwrap().unwrap();
    assert_eq!(record.seq, 2);
    assert_eq!(record.last_run, Some(v("1.0.0")));
    assert_eq!(record.extra.get("x_future"), Some(&json!({"a": [1, 2]})));
    assert_eq!(record.extra.get("last_run"), None, "last_run is typed");
    let mut next = record.clone();
    next.last_run = Some(v("1.1.0"));
    let next = commit_counters(&fs, &next);
    let written = payload(&record_bytes(&fs, &counters_dir(), 3));
    assert_eq!(written.get("x_future"), Some(&json!({"a": [1, 2]})));
    assert_eq!(written.get("last_run"), Some(&json!("1.1.0")));
    assert_eq!(load_counters(&fs).unwrap(), Some(next));
}

#[test]
fn a_last_run_that_is_not_a_version_text_is_invalid() {
    for bad in [
        json!("not-a-version"),
        json!("1.0"),
        json!(""),
        json!(5),
        json!(null),
        json!({"version": "1.0.0"}),
        json!(["1.0.0"]),
    ] {
        let fs = MemFs::new();
        commit_counters(&fs, &InstallCounters::new(1, app(), ID));
        let mut p = payload(&record_bytes(&fs, &counters_dir(), 1));
        p.insert("seq".into(), json!(2));
        p.insert("last_run".into(), bad.clone());
        raw_counters(&fs, 2, &p);
        assert!(
            matches!(load_counters(&fs), Err(StateError::Invalid(_))),
            "{bad}"
        );
    }
}

#[test]
fn an_extra_member_named_last_run_cannot_be_written() {
    let fs = MemFs::new();
    let mut c = InstallCounters::new(1, app(), ID);
    c.extra.insert("last_run".into(), json!("1.0.0"));
    let dir = counters_dir();
    let loaded = load::<InstallCounters>(&fs, &dir, &app(), &H).unwrap();
    assert!(matches!(
        commit(&fs, &dir, &loaded, &c, &H),
        Err(StateError::Invalid(_))
    ));
}

// ---- machine transitions (M10-D3) -----------------------------------------------------------------

fn empty(scope: Scope) -> InstallState {
    InstallState::new(1, app(), scope, [0; 16], TARGET)
}

fn staged(version: &str) -> StagedRef {
    StagedRef::new(
        v(version),
        TARGET,
        H.sha256(format!("manifest {version}").as_bytes()),
    )
}

/// 1.0.0 installed by the engine (issued 100).
fn installed() -> InstallState {
    machine::install_first(&empty(Scope::Machine), v("1.0.0"), 100, ID).unwrap()
}

/// 1.0.0 installed, 1.1.0 staged (issued 200) and bound.
fn ready() -> InstallState {
    installed().set_staged(Some((staged("1.1.0"), 200)))
}

/// 1.1.0 applied over 1.0.0 and pending, with token "t".
fn pending() -> InstallState {
    machine::apply(&ready(), &v("1.1.0"), token("t")).unwrap()
}

/// `s` as a per-user record.
fn as_user(s: &InstallState) -> InstallState {
    let mut u = s.clone();
    u.scope = Scope::User;
    u
}

#[test]
fn every_machine_transition_refuses_a_user_record_and_changes_nothing() {
    let user = as_user(&pending());
    let ver = v("1.1.0");
    assert_eq!(
        machine::install_first(&empty(Scope::User), v("1.0.0"), 1, ID),
        Err(LifecycleError::UserScope)
    );
    assert_eq!(
        machine::apply(&as_user(&ready()), &ver, token("t")),
        Err(LifecycleError::UserScope)
    );
    assert_eq!(
        machine::confirm(&user, &ver, token("t")),
        Err(LifecycleError::UserScope)
    );
    assert_eq!(
        machine::attempt(&user, &ver, token("n")),
        Err(LifecycleError::UserScope)
    );
    assert_eq!(
        machine::rollback(&user, &ver, token("t")),
        Err(LifecycleError::UserScope)
    );
    let mut at_limit = user.clone();
    at_limit.pending.as_mut().unwrap().attempts = MAX_ATTEMPTS;
    assert_eq!(
        machine::rollback_at_limit(&at_limit, &ver),
        Err(LifecycleError::UserScope)
    );
}

#[test]
fn the_user_transitions_still_refuse_a_machine_record() {
    let m = pending();
    assert_eq!(
        lifecycle::confirm(&m, &v("1.1.0"), TokenCheck::Absent),
        Err(LifecycleError::MachineScope)
    );
    assert_eq!(
        lifecycle::count_attempt(&m, &v("1.1.0")),
        Err(LifecycleError::MachineScope)
    );
    assert_eq!(
        lifecycle::rollback(&m, &v("1.1.0")),
        Err(LifecycleError::MachineScope)
    );
    assert_eq!(
        lifecycle::apply(&ready(), &v("1.1.0"), token("t")),
        Err(LifecycleError::MachineScope)
    );
    assert_eq!(
        lifecycle::install_first(&empty(Scope::Machine), v("1.0.0"), 1, ID),
        Err(LifecycleError::MachineScope)
    );
}

#[test]
fn machine_install_first_and_apply_change_what_their_user_twins_change_but_queue_nothing() {
    // install_first
    let base = empty(Scope::Machine);
    let m = machine::install_first(&base, v("1.0.0"), 100, ID).unwrap();
    let mut u = lifecycle::install_first(&as_user(&base), v("1.0.0"), 100, ID).unwrap();
    assert!(u.lifecycle.is_some(), "the user twin queues events");
    assert_eq!(m.lifecycle, None);
    u.scope = Scope::Machine;
    u.lifecycle = None;
    assert_eq!(m, u);
    assert_eq!(
        machine::install_first(&m, v("1.0.0"), 100, ID),
        Err(LifecycleError::AlreadyInstalled)
    );

    // apply
    let r = ready();
    let m = machine::apply(&r, &v("1.1.0"), token("t")).unwrap();
    let mut u = lifecycle::apply(&as_user(&r), &v("1.1.0"), token("t")).unwrap();
    assert!(u.lifecycle.is_some());
    assert_eq!(m.lifecycle, None);
    assert_eq!(
        m.health,
        Some(Health {
            version: v("1.1.0"),
            token_sha256: token("t")
        })
    );
    u.scope = Scope::Machine;
    u.lifecycle = None;
    assert_eq!(m, u);
    // The refusals are the user twin's.
    assert_eq!(
        machine::apply(&r, &v("1.2.0"), token("t")),
        Err(LifecycleError::StagedVersionMismatch)
    );
    assert_eq!(
        machine::apply(&m, &v("1.1.0"), token("t")),
        Err(LifecycleError::PendingExists)
    );
}

#[test]
fn machine_confirm_requires_the_recorded_token() {
    let p = pending();
    let (out, outcome) = machine::confirm(&p, &v("1.1.0"), token("t")).unwrap();
    assert_eq!(outcome, ConfirmOutcome::Confirmed);
    assert_eq!((&out.pending, &out.health), (&None, &None));
    let mut expect = p.clone();
    expect.pending = None;
    expect.health = None;
    assert_eq!(out, expect);

    // Another token, or none recorded, or one recorded for another version: refused, unchanged.
    assert_eq!(
        machine::confirm(&p, &v("1.1.0"), token("other")),
        Err(LifecycleError::TokenMismatch)
    );
    let mut no_health = p.clone();
    no_health.health = None;
    assert_eq!(
        machine::confirm(&no_health, &v("1.1.0"), token("t")),
        Err(LifecycleError::TokenMismatch)
    );
    let mut other_health = p.clone();
    other_health.health = Some(Health {
        version: v("1.0.0"),
        token_sha256: token("t"),
    });
    assert_eq!(
        machine::confirm(&other_health, &v("1.1.0"), token("t")),
        Err(LifecycleError::TokenMismatch)
    );

    // Nothing pending, or another version pending: nothing to confirm, the record unchanged.
    let (same, outcome) = machine::confirm(&p, &v("1.0.0"), token("t")).unwrap();
    assert_eq!((same, outcome), (p.clone(), ConfirmOutcome::NothingPending));
    let i = installed();
    let (same, outcome) = machine::confirm(&i, &v("1.0.0"), token("t")).unwrap();
    assert_eq!((same, outcome), (i, ConfirmOutcome::NothingPending));
}

#[test]
fn machine_attempt_counts_issues_a_fresh_token_and_stops_at_the_limit() {
    let mut s = pending();
    for n in 1..=MAX_ATTEMPTS {
        let fresh = token(&format!("attempt {n}"));
        let (out, outcome) = machine::attempt(&s, &v("1.1.0"), fresh).unwrap();
        assert_eq!(outcome, AttemptOutcome::Counted(n));
        let mut expect = s.clone();
        expect.pending = Some(PendingRef {
            version: v("1.1.0"),
            attempts: n,
        });
        expect.health = Some(Health {
            version: v("1.1.0"),
            token_sha256: fresh,
        });
        assert_eq!(out, expect);
        // The fresh token confirms; the one it replaced no longer does.
        assert!(machine::confirm(&out, &v("1.1.0"), fresh).is_ok());
        assert_eq!(
            machine::confirm(&out, &v("1.1.0"), token("t")),
            Err(LifecycleError::TokenMismatch)
        );
        s = out;
    }
    let (same, outcome) = machine::attempt(&s, &v("1.1.0"), token("late")).unwrap();
    assert_eq!(outcome, AttemptOutcome::RollBack);
    assert_eq!(same, s, "the record is unchanged");

    assert_eq!(
        machine::attempt(&s, &v("1.0.0"), token("n")),
        Err(LifecycleError::NotPending)
    );
    assert_eq!(
        machine::attempt(&installed(), &v("1.0.0"), token("n")),
        Err(LifecycleError::NotPending)
    );
}

#[test]
fn machine_rollback_checks_the_token_then_rolls_back_like_the_user_twin() {
    let p = pending();
    let out = machine::rollback(&p, &v("1.1.0"), token("t")).unwrap();
    let mut u = lifecycle::rollback(&as_user(&p), &v("1.1.0")).unwrap();
    u.scope = Scope::Machine;
    assert_eq!(out, u);
    assert_eq!(out.current.as_ref().unwrap().version, v("1.0.0"));
    assert_eq!(out.bad, vec![v("1.1.0")]);
    assert_eq!((&out.pending, &out.health), (&None, &None));

    assert_eq!(
        machine::rollback(&p, &v("1.1.0"), token("other")),
        Err(LifecycleError::TokenMismatch)
    );
    let mut no_health = p.clone();
    no_health.health = None;
    assert_eq!(
        machine::rollback(&no_health, &v("1.1.0"), token("t")),
        Err(LifecycleError::TokenMismatch)
    );
    assert_eq!(
        machine::rollback(&p, &v("1.0.0"), token("t")),
        Err(LifecycleError::NotPending)
    );
    assert_eq!(
        machine::rollback(&installed(), &v("1.0.0"), token("t")),
        Err(LifecycleError::NotPending)
    );
}

#[test]
fn machine_rollback_at_limit_needs_exactly_the_limit() {
    let p = pending();
    for attempts in 0..MAX_ATTEMPTS {
        let mut s = p.clone();
        s.pending.as_mut().unwrap().attempts = attempts;
        assert_eq!(
            machine::rollback_at_limit(&s, &v("1.1.0")),
            Err(LifecycleError::NotPending),
            "{attempts}"
        );
    }
    let mut over = p.clone();
    over.pending.as_mut().unwrap().attempts = MAX_ATTEMPTS + 1;
    assert_eq!(
        machine::rollback_at_limit(&over, &v("1.1.0")),
        Err(LifecycleError::NotPending)
    );

    let mut at = p.clone();
    at.pending.as_mut().unwrap().attempts = MAX_ATTEMPTS;
    assert_eq!(
        machine::rollback_at_limit(&at, &v("1.0.0")),
        Err(LifecycleError::NotPending)
    );
    assert_eq!(
        machine::rollback_at_limit(&installed(), &v("1.0.0")),
        Err(LifecycleError::NotPending)
    );
    let out = machine::rollback_at_limit(&at, &v("1.1.0")).unwrap();
    let mut u = lifecycle::rollback(&as_user(&at), &v("1.1.0")).unwrap();
    u.scope = Scope::Machine;
    assert_eq!(out, u);
    assert_eq!(out.bad, vec![v("1.1.0")]);
}

#[test]
fn a_machine_cycle_commits_through_the_machine_store() {
    let fs = MemFs::new();
    let s = store();
    let step = |f: &dyn Fn(&InstallState) -> InstallState| {
        let loaded = s.load(&fs, &H).unwrap();
        let base = loaded
            .record
            .clone()
            .unwrap_or_else(|| empty(Scope::Machine));
        s.commit(&fs, &loaded, &f(&base), &H).unwrap()
    };
    step(&|r| machine::install_first(r, v("1.0.0"), 100, ID).unwrap());
    step(&|r| r.set_staged(Some((staged("1.1.0"), 200))));
    step(&|r| machine::apply(r, &v("1.1.0"), token("t")).unwrap());
    step(&|r| machine::attempt(r, &v("1.1.0"), token("a1")).unwrap().0);
    let last = step(&|r| machine::confirm(r, &v("1.1.0"), token("a1")).unwrap().0);
    assert_eq!(last.seq, 5);
    let loaded = s.load(&fs, &H).unwrap().record.unwrap();
    assert_eq!(loaded, last);
    assert_eq!(loaded.current.as_ref().unwrap().version, v("1.1.0"));
    assert_eq!(loaded.current.as_ref().unwrap().issued, 200);
    assert_eq!((&loaded.pending, &loaded.health), (&None, &None));
    assert_eq!(loaded.lifecycle, None);
    assert_eq!(loaded.scope, Scope::Machine);
}
