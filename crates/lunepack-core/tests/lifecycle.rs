//! The lifecycle transitions (C4, M5-D5, M5-D6, M5-D9, FORMAT.md 12.9) over the real state store
//! and the crash-injecting `MemFs`: every transition's preconditions and outputs, the
//! `staged_issued` binding, record evolution, the floors and the floor time, and a crash at every
//! op of a transition's commit followed by the `current` reconcile.
//!
//! Records are built by the real writer (`commit`), or for records only an older writer leaves,
//! by the real writer and then a field edited through the typed record or the written payload.

use std::path::PathBuf;

use lunepack_core::lifecycle::MAX_ATTEMPTS;
use lunepack_core::state::{self, MAX_BAD_VERSIONS, commit, commit_raw_payload, load};
use lunepack_core::{
    AppId, AttemptOutcome, ConfirmOutcome, CurrentRef, Floors, Fs, Hasher, Health, InstallState,
    Lifecycle, LifecycleError, LifecycleEvent, Loaded, PendingRef, PreviousRef, Scope,
    Sha256Digest, StagedRef, StateError, Target, TokenCheck, Version, apply, confirm,
    count_attempt, deliver_events, gc_keep, install_first, reconcile_current, reinstall_orphaned,
    reset_orphaned, rollback,
};
use lunepack_testkit::{FakeHasher, MemFs, RecoverMode};
use serde_json::{Map, Value, json};

const H: FakeHasher = FakeHasher;
const TARGET: Target = Target::LinuxX86_64;
const ID: [u8; 16] = [7; 16];

fn app() -> AppId {
    AppId::parse("org.example.hello").unwrap()
}

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn root() -> PathBuf {
    PathBuf::from("/home/u/.local/share/org.example.hello")
}

fn state_dir() -> PathBuf {
    root().join("state")
}

fn token(label: &str) -> Sha256Digest {
    H.sha256(label.as_bytes())
}

fn manifest(version: &str) -> Sha256Digest {
    H.sha256(format!("manifest {version}").as_bytes())
}

fn staged(version: &str) -> StagedRef {
    StagedRef::new(v(version), TARGET, manifest(version))
}

fn empty() -> InstallState {
    InstallState::new(1, app(), Scope::User, [0; 16], TARGET)
}

/// 1.0.0 installed (issued 100), no staged version.
fn installed() -> InstallState {
    install_first(&empty(), v("1.0.0"), 100, ID).unwrap()
}

/// 1.0.0 installed, 1.1.0 staged (issued 200) and bound.
fn ready() -> InstallState {
    installed().set_staged(Some((staged("1.1.0"), 200)))
}

/// 1.1.0 applied over 1.0.0 and pending, with token "t".
fn pending() -> InstallState {
    apply(&ready(), &v("1.1.0"), token("t")).unwrap()
}

fn events_of(s: &InstallState) -> Vec<LifecycleEvent> {
    s.lifecycle
        .as_ref()
        .map(|l| l.events.clone())
        .unwrap_or_default()
}

/// `staged_issued` is null or bound to `staged` (P9).
fn assert_binding(s: &InstallState, what: &str) {
    if s.staged_issued.is_some() {
        assert!(
            s.staged_issued_bound().is_some(),
            "{what}: staged_issued is not bound to staged"
        );
    }
}

fn load_state(fs: &dyn Fs) -> Result<Loaded<InstallState>, StateError> {
    load::<InstallState>(fs, &state_dir(), &app(), &H)
}

// ---- install_first ------------------------------------------------------------------------------

#[test]
fn install_first_sets_current_and_queues_installed_and_first_run() {
    let s = installed();
    assert_eq!(
        s.current,
        Some(CurrentRef {
            version: v("1.0.0"),
            issued: 100
        })
    );
    assert_eq!(s.install_id, ID);
    assert_eq!((&s.previous, &s.pending, &s.health), (&None, &None, &None));
    assert_eq!(
        events_of(&s),
        vec![
            LifecycleEvent::Installed {
                version: v("1.0.0")
            },
            LifecycleEvent::FirstRun {
                version: v("1.0.0")
            },
        ]
    );
    assert_eq!(
        install_first(&s, v("2.0.0"), 1, ID),
        Err(LifecycleError::AlreadyInstalled)
    );
}

// ---- reset_orphaned (M8-D16) ------------------------------------------------------------------

#[test]
fn reset_orphaned_keeps_the_floors_and_leaves_a_record_a_first_install_resumes_from() {
    let floors = Floors {
        root: Some(lunepack_core::RootParts {
            version: 3,
            threshold: 1,
            keys: vec![lunepack_core::PublicKey::from_bytes([9; 32])],
        }),
        keyset_version: 5,
        feed_seq: [(lunepack_core::Channel::parse("stable").unwrap(), 41)]
            .into_iter()
            .collect(),
    };
    let mut old = pending()
        .set_staged(Some((staged("1.2.0"), 300)))
        .raise_floors(&floors);
    old.bad = vec![v("0.9.0")];
    old.extra.insert("future".to_owned(), json!({"kept": true}));
    let out = reset_orphaned(&old, [3; 16]).unwrap();
    assert_eq!(out.floors, old.floors);
    assert_eq!(out.current, None);
    assert_eq!(out.install_id, [3; 16]);
    assert_eq!(
        (&out.previous, &out.pending, &out.health, &out.staged),
        (&None, &None, &None, &None)
    );
    assert!(out.staged_issued.is_none() && out.bad.is_empty() && out.lifecycle.is_none());
    assert_eq!(out.extra, old.extra, "unknown members are kept");
    assert_eq!(
        (out.app_id.clone(), out.scope, out.target),
        (old.app_id.clone(), old.scope, old.target)
    );
    // From it a first install ends exactly where reinstall_orphaned would have.
    let via_reset = install_first(&out, v("2.0.0"), 500, [3; 16]).unwrap();
    let direct = reinstall_orphaned(&old, v("2.0.0"), 500, [3; 16]).unwrap();
    assert_eq!(via_reset.floors, direct.floors);
    assert_eq!(via_reset.current, direct.current);
    assert_eq!(events_of(&via_reset), events_of(&direct));
    assert_eq!(
        (
            &via_reset.previous,
            &via_reset.pending,
            &via_reset.staged,
            &via_reset.bad
        ),
        (
            &direct.previous,
            &direct.pending,
            &direct.staged,
            &direct.bad
        )
    );
    // A record with no current version is not orphaned.
    assert!(matches!(
        reset_orphaned(&out, [4; 16]),
        Err(LifecycleError::NotInstalled)
    ));
}

// ---- reinstall_orphaned (M8-D16) --------------------------------------------------------------

#[test]
fn reinstall_orphaned_keeps_exactly_the_floors_and_starts_everything_else_anew() {
    let floors = Floors {
        root: Some(lunepack_core::RootParts {
            version: 3,
            threshold: 1,
            keys: vec![lunepack_core::PublicKey::from_bytes([9; 32])],
        }),
        keyset_version: 5,
        feed_seq: [(lunepack_core::Channel::parse("stable").unwrap(), 41)]
            .into_iter()
            .collect(),
    };
    // A record with every member in use: previous, pending, health, staged with its issued, a bad
    // version, queued events and an unknown member.
    let mut old = pending()
        .set_staged(Some((staged("1.2.0"), 300)))
        .raise_floors(&floors);
    old.bad = vec![v("0.9.0")];
    old.extra.insert("future".to_owned(), json!({"kept": true}));
    assert!(old.previous.is_some() && old.pending.is_some() && old.health.is_some());
    assert!(old.staged_issued_bound().is_some() && old.lifecycle.is_some());

    let new_id = [3; 16];
    let out = reinstall_orphaned(&old, v("2.0.0"), 500, new_id).unwrap();
    assert_eq!(out.floors, old.floors, "the floors carry over");
    assert_eq!(
        out.current,
        Some(CurrentRef {
            version: v("2.0.0"),
            issued: 500
        })
    );
    assert_eq!(out.install_id, new_id);
    assert_eq!(
        (&out.previous, &out.pending, &out.health),
        (&None, &None, &None)
    );
    assert_eq!((&out.staged, &out.staged_issued), (&None, &None));
    assert!(out.bad.is_empty());
    assert_eq!(
        events_of(&out),
        vec![
            LifecycleEvent::Installed {
                version: v("2.0.0")
            },
            LifecycleEvent::FirstRun {
                version: v("2.0.0")
            },
        ]
    );
    assert_eq!(
        (&out.app_id, out.scope, out.target),
        (&old.app_id, old.scope, old.target)
    );
    assert_eq!(
        out.extra, old.extra,
        "unknown members are kept (FORMAT.md 12.8)"
    );

    // It commits over the old record like any transition.
    let (fs, loaded) = stored(&old);
    let committed = commit(&fs, &state_dir(), &loaded, &out, &H).unwrap();
    assert_eq!(committed.floors, floors.max(&old.floors));

    // A record with no current version is not orphaned: install_first takes it.
    assert_eq!(
        reinstall_orphaned(&empty(), v("2.0.0"), 1, new_id),
        Err(LifecycleError::NotInstalled)
    );
    let mut machine = installed();
    machine.scope = Scope::Machine;
    assert_eq!(
        reinstall_orphaned(&machine, v("2.0.0"), 1, new_id),
        Err(LifecycleError::MachineScope)
    );
}

#[test]
fn install_first_clears_the_staged_entry_it_installs_and_keeps_a_newer_one() {
    // The installer stages the version it installs (M5-D8).
    let staged_same = empty().set_staged(Some((staged("1.0.0"), 100)));
    let s = install_first(&staged_same, v("1.0.0"), 100, ID).unwrap();
    assert_eq!((&s.staged, &s.staged_issued), (&None, &None));
    let staged_newer = empty().set_staged(Some((staged("1.1.0"), 200)));
    let s = install_first(&staged_newer, v("1.0.0"), 100, ID).unwrap();
    assert_eq!(s.staged, Some(staged("1.1.0")));
    assert_eq!(s.staged_issued_bound(), Some(200));
}

// ---- apply --------------------------------------------------------------------------------------

#[test]
fn apply_moves_current_to_previous_and_makes_the_staged_version_pending() {
    let before = ready();
    let s = pending();
    assert_eq!(
        s.previous,
        Some(PreviousRef {
            version: v("1.0.0")
        })
    );
    assert_eq!(
        s.current,
        Some(CurrentRef {
            version: v("1.1.0"),
            issued: 200
        }),
        "the floor time is the staged manifest's issued"
    );
    assert_eq!(
        s.pending,
        Some(PendingRef {
            version: v("1.1.0"),
            attempts: 0
        })
    );
    assert_eq!(
        s.health,
        Some(Health {
            version: v("1.1.0"),
            token_sha256: token("t")
        })
    );
    assert_eq!((&s.staged, &s.staged_issued), (&None, &None));
    // 1.0.0's undelivered events are dropped; 1.1.0's are queued.
    assert_eq!(
        events_of(&s),
        vec![
            LifecycleEvent::Updated {
                from: v("1.0.0"),
                to: v("1.1.0")
            },
            LifecycleEvent::FirstRun {
                version: v("1.1.0")
            },
        ]
    );
    assert_eq!(
        (&s.floors, &s.bad, s.target),
        (&before.floors, &before.bad, before.target)
    );
}

#[test]
fn apply_refuses_unless_every_precondition_holds() {
    let t = token("t");
    let cases: Vec<(&str, InstallState, &str, LifecycleError)> = vec![
        (
            "nothing installed",
            empty().set_staged(Some((staged("1.1.0"), 200))),
            "1.1.0",
            LifecycleError::NotInstalled,
        ),
        (
            "nothing staged",
            installed(),
            "1.1.0",
            LifecycleError::NothingStaged,
        ),
        (
            "a version is pending",
            pending().set_staged(Some((staged("1.2.0"), 300))),
            "1.2.0",
            LifecycleError::PendingExists,
        ),
        (
            "staged is not newer",
            installed().set_staged(Some((staged("1.0.0"), 200))),
            "1.0.0",
            LifecycleError::NothingStaged,
        ),
        (
            "staged is bad",
            ready().mark_bad(v("1.1.0")),
            "1.1.0",
            LifecycleError::NothingStaged,
        ),
        (
            "staged for another target",
            installed().set_staged(Some((
                StagedRef::new(v("1.1.0"), Target::LinuxAarch64, manifest("1.1.0")),
                200,
            ))),
            "1.1.0",
            LifecycleError::NothingStaged,
        ),
        (
            "another version asked for",
            ready(),
            "1.2.0",
            LifecycleError::StagedVersionMismatch,
        ),
        (
            "same precedence, other build",
            ready(),
            "1.1.0+other",
            LifecycleError::StagedVersionMismatch,
        ),
    ];
    for (what, s, version, want) in cases {
        assert_eq!(apply(&s, &v(version), t), Err(want), "{what}");
    }
}

#[test]
fn apply_refuses_when_bad_is_full_so_a_rollback_can_always_commit() {
    let mut s = ready();
    s.bad = (0..MAX_BAD_VERSIONS as u64)
        .map(|i| v(&format!("0.0.{i}")))
        .collect();
    assert_eq!(
        apply(&s, &v("1.1.0"), token("t")),
        Err(LifecycleError::BadFull)
    );
    s.bad.pop();
    let applied = apply(&s, &v("1.1.0"), token("t")).unwrap();
    let rolled = rollback(&applied, &v("1.1.0")).unwrap();
    assert_eq!(rolled.bad.len(), MAX_BAD_VERSIONS);
    assert!(rolled.bad.contains(&v("1.1.0")));
}

/// A store holding `record` as written by the real writer, and the loaded result.
fn stored(record: &InstallState) -> (MemFs, Loaded<InstallState>) {
    let fs = MemFs::new();
    commit(&fs, &state_dir(), &load_state(&fs).unwrap(), record, &H).unwrap();
    let loaded = load_state(&fs).unwrap();
    (fs, loaded)
}

#[test]
fn apply_refuses_a_staged_issued_naming_another_entry() {
    // The real writer wrote a bound record; an older writer then replaced `staged` (or its digest)
    // and kept `staged_issued`: edited through the typed record and written by the real writer.
    type Edit = fn(&mut InstallState);
    let edits: [(&str, Edit); 2] = [
        ("another version", |s| s.staged = Some(staged("1.2.0"))),
        ("another digest", |s| {
            s.staged.as_mut().unwrap().manifest_sha256 = manifest("other")
        }),
    ];
    for (what, edit) in edits {
        let (fs, loaded) = stored(&ready());
        let mut s = loaded.record.clone().unwrap();
        edit(&mut s);
        commit(&fs, &state_dir(), &loaded, &s, &H).unwrap();
        let back = load_state(&fs).unwrap().record.unwrap();
        assert!(back.staged_issued.is_some(), "{what}: kept verbatim");
        let version = back.staged.as_ref().unwrap().version.clone();
        assert_eq!(
            apply(&back, &version, token("t")),
            Err(LifecycleError::StagedIssuedUnbound),
            "{what}"
        );
    }
}

#[test]
fn an_m4_record_without_staged_issued_cannot_apply_until_set_staged_binds_it() {
    let (fs, loaded) = stored(&ready());
    let file = fs
        .read_capped(
            &state_dir().join(format!("{:020}.rec", loaded.next_seq - 1)),
            state::MAX_RECORD_BYTES,
        )
        .unwrap();
    let mut p = payload(&file);
    p.remove("staged_issued");
    p.remove("lifecycle");
    p.insert("seq".into(), json!(loaded.next_seq));
    raw(&fs, loaded.next_seq, &p);
    let m4 = load_state(&fs).unwrap().record.unwrap();
    assert_eq!(m4.staged, Some(staged("1.1.0")));
    assert_eq!(m4.staged_issued, None);
    assert_eq!(
        apply(&m4, &v("1.1.0"), token("t")),
        Err(LifecycleError::StagedIssuedUnbound)
    );
    let bound = m4.set_staged(Some((staged("1.1.0"), 250)));
    assert_eq!(
        apply(&bound, &v("1.1.0"), token("t"))
            .unwrap()
            .current
            .unwrap()
            .issued,
        250
    );
}

// ---- confirm ------------------------------------------------------------------------------------

#[test]
fn confirm_with_a_matching_token_or_none_clears_pending_and_health() {
    for check in [TokenCheck::Presented(token("t")), TokenCheck::Absent] {
        let (s, outcome) = confirm(&pending(), &v("1.1.0"), check).unwrap();
        assert_eq!(outcome, ConfirmOutcome::Confirmed, "{check:?}");
        assert_eq!((&s.pending, &s.health), (&None, &None));
        assert_eq!(s.current, pending().current);
        assert_eq!(
            s.previous,
            pending().previous,
            "previous stays for a later rollback"
        );
    }
}

#[test]
fn confirm_refuses_a_mismatched_token_and_changes_nothing() {
    assert_eq!(
        confirm(
            &pending(),
            &v("1.1.0"),
            TokenCheck::Presented(token("other"))
        ),
        Err(LifecycleError::TokenMismatch)
    );
    // No digest recorded for the pending version: a presented token cannot match.
    let mut no_health = pending();
    no_health.health = None;
    assert_eq!(
        confirm(&no_health, &v("1.1.0"), TokenCheck::Presented(token("t"))),
        Err(LifecycleError::TokenMismatch)
    );
    let mut other_version = pending();
    other_version.health.as_mut().unwrap().version = v("1.0.0");
    assert_eq!(
        confirm(
            &other_version,
            &v("1.1.0"),
            TokenCheck::Presented(token("t"))
        ),
        Err(LifecycleError::TokenMismatch)
    );
}

#[test]
fn confirm_by_another_version_or_with_nothing_pending_is_nothing_pending() {
    for (s, own) in [
        (pending(), "1.0.0"),
        (pending(), "1.1.0+other"),
        (installed(), "1.0.0"),
    ] {
        for check in [TokenCheck::Presented(token("t")), TokenCheck::Absent] {
            let (out, outcome) = confirm(&s, &v(own), check).unwrap();
            assert_eq!(outcome, ConfirmOutcome::NothingPending);
            assert_eq!(out, s, "unchanged");
        }
    }
}

// ---- count_attempt ------------------------------------------------------------------------------

#[test]
fn attempts_count_to_three_and_the_fourth_rolls_back() {
    let mut s = pending();
    for n in 1..=MAX_ATTEMPTS {
        let (next, outcome) = count_attempt(&s, &v("1.1.0")).unwrap();
        assert_eq!(outcome, AttemptOutcome::Counted(n));
        assert_eq!(next.pending.as_ref().unwrap().attempts, n);
        s = next;
    }
    let (next, outcome) = count_attempt(&s, &v("1.1.0")).unwrap();
    assert_eq!(outcome, AttemptOutcome::RollBack);
    assert_eq!(next, s, "unchanged");
    assert_eq!(
        count_attempt(&installed(), &v("1.0.0")),
        Err(LifecycleError::NotPending)
    );
    assert_eq!(
        count_attempt(&pending(), &v("1.0.0")),
        Err(LifecycleError::NotPending)
    );
}

// ---- rollback -----------------------------------------------------------------------------------

#[test]
fn rollback_restores_previous_keeps_the_floor_time_and_marks_bad() {
    let mut p = pending().mark_bad(v("1.2.0")).mark_bad(v("0.5.0"));
    // A newer version the bad one staged stays staged; 1.1.0's events go.
    p = p.set_staged(Some((staged("1.3.0"), 400)));
    let s = rollback(&p, &v("1.1.0")).unwrap();
    assert_eq!(
        s.current,
        Some(CurrentRef {
            version: v("1.0.0"),
            issued: 200
        }),
        "issued never decreases"
    );
    assert_eq!((&s.previous, &s.pending, &s.health), (&None, &None, &None));
    assert_eq!(s.bad, vec![v("0.5.0"), v("1.1.0"), v("1.2.0")]);
    assert!(events_of(&s).is_empty());
    assert_eq!(s.staged, Some(staged("1.3.0")));
    assert_eq!(s.staged_issued_bound(), Some(400));
    assert_eq!(s.floors, p.floors);
}

#[test]
fn rollback_needs_the_version_pending_and_a_previous() {
    assert_eq!(
        rollback(&installed(), &v("1.0.0")),
        Err(LifecycleError::NotPending)
    );
    assert_eq!(
        rollback(&pending(), &v("1.0.0")),
        Err(LifecycleError::NotPending)
    );
    let mut no_prev = pending();
    no_prev.previous = None;
    assert_eq!(
        rollback(&no_prev, &v("1.1.0")),
        Err(LifecycleError::NoPrevious)
    );
}

#[test]
fn rollback_clears_a_staged_entry_of_the_bad_version() {
    let mut p = pending();
    p = p.set_staged(Some((staged("1.1.0"), 200)));
    let s = rollback(&p, &v("1.1.0")).unwrap();
    assert_eq!((&s.staged, &s.staged_issued), (&None, &None));
}

#[test]
fn rollback_with_bad_full_still_rolls_back() {
    // Only an older writer gets `bad` full after an apply.
    let mut p = pending();
    p.bad = (0..MAX_BAD_VERSIONS as u64)
        .map(|i| v(&format!("0.0.{i}")))
        .collect();
    let s = rollback(&p, &v("1.1.0")).unwrap();
    assert_eq!(s.current.unwrap().version, v("1.0.0"));
    assert_eq!(s.bad.len(), MAX_BAD_VERSIONS);
}

// ---- events and GC ------------------------------------------------------------------------------

#[test]
fn events_are_delivered_once_to_their_version_only() {
    let mut s = pending();
    s.lifecycle = Some(Lifecycle {
        events: vec![
            LifecycleEvent::FirstRun {
                version: v("0.9.0"),
            },
            LifecycleEvent::Updated {
                from: v("1.0.0"),
                to: v("1.1.0"),
            },
            LifecycleEvent::FirstRun {
                version: v("1.1.0"),
            },
        ],
    });
    let (none, got) = deliver_events(&s, &v("1.0.0")).unwrap();
    assert!(got.is_empty());
    assert_eq!(none, s, "unchanged");
    let (after, got) = deliver_events(&s, &v("1.1.0")).unwrap();
    assert_eq!(
        got,
        vec![
            LifecycleEvent::Updated {
                from: v("1.0.0"),
                to: v("1.1.0")
            },
            LifecycleEvent::FirstRun {
                version: v("1.1.0")
            },
        ]
    );
    assert_eq!(
        events_of(&after),
        vec![LifecycleEvent::FirstRun {
            version: v("0.9.0")
        }]
    );
    let (again, got) = deliver_events(&after, &v("1.1.0")).unwrap();
    assert!(got.is_empty(), "at most once");
    assert_eq!(again, after);
    let (last, _) = deliver_events(&after, &v("0.9.0")).unwrap();
    assert_eq!(last.lifecycle, None, "an empty queue is written as null");
}

#[test]
fn gc_keeps_current_previous_pending_and_staged() {
    let s = pending().set_staged(Some((staged("1.2.0"), 300)));
    let keep: Vec<Version> = gc_keep(&s).into_iter().collect();
    assert_eq!(keep, vec![v("1.0.0"), v("1.1.0"), v("1.2.0")]);
    assert!(gc_keep(&empty()).is_empty());
    assert_eq!(
        gc_keep(&installed()).into_iter().collect::<Vec<_>>(),
        vec![v("1.0.0")]
    );
}

// ---- every transition ---------------------------------------------------------------------------

/// Every transition, from a record where it succeeds.
fn every_transition() -> Vec<(&'static str, InstallState, InstallState)> {
    let p = pending();
    let three = (0..3).fold(p.clone(), |s, _| count_attempt(&s, &v("1.1.0")).unwrap().0);
    vec![
        ("install_first", empty(), installed()),
        ("set_staged", installed(), ready()),
        ("set_staged(None)", ready(), ready().set_staged(None)),
        ("apply", ready(), pending()),
        (
            "confirm",
            p.clone(),
            confirm(&p, &v("1.1.0"), TokenCheck::Absent).unwrap().0,
        ),
        (
            "count_attempt",
            p.clone(),
            count_attempt(&p, &v("1.1.0")).unwrap().0,
        ),
        (
            "rollback",
            three.clone(),
            rollback(&three, &v("1.1.0")).unwrap(),
        ),
        (
            "deliver_events",
            p.clone(),
            deliver_events(&p, &v("1.1.0")).unwrap().0,
        ),
        ("mark_bad", ready(), ready().mark_bad(v("1.1.0"))),
        (
            "install",
            ready(),
            ready().install(v("1.1.0"), 200, TARGET, ID),
        ),
        (
            "raise_floors",
            ready(),
            ready().raise_floors(&Floors::default()),
        ),
    ]
}

#[test]
fn after_every_transition_staged_issued_is_null_or_bound() {
    for (what, _, out) in every_transition() {
        assert_binding(&out, what);
    }
    // Also from an unbound input, which only an older writer leaves.
    let mut unbound = ready();
    unbound.staged = Some(staged("1.2.0"));
    let outs = [
        unbound.set_staged(None),
        unbound.mark_bad(v("0.1.0")),
        unbound.install(v("1.0.0"), 100, TARGET, ID),
        unbound.raise_floors(&Floors::default()),
        deliver_events(&unbound, &v("1.0.0")).unwrap().0,
    ];
    for (i, out) in outs.iter().enumerate() {
        assert_binding(out, &format!("unbound input, transition {i}"));
    }
}

#[test]
fn every_write_refuses_a_machine_record() {
    let machine = |s: InstallState| {
        let mut s = s;
        s.scope = Scope::Machine;
        s
    };
    let m = LifecycleError::MachineScope;
    assert_eq!(install_first(&machine(empty()), v("1.0.0"), 1, ID), Err(m));
    assert_eq!(apply(&machine(ready()), &v("1.1.0"), token("t")), Err(m));
    assert_eq!(
        confirm(&machine(pending()), &v("1.1.0"), TokenCheck::Absent),
        Err(m)
    );
    assert_eq!(count_attempt(&machine(pending()), &v("1.1.0")), Err(m));
    assert_eq!(rollback(&machine(pending()), &v("1.1.0")), Err(m));
    assert_eq!(deliver_events(&machine(pending()), &v("1.1.0")), Err(m));
    // GC's keep set only reads.
    assert_eq!(gc_keep(&machine(pending())), gc_keep(&pending()));
}

#[test]
fn transitions_copy_the_floors_and_a_lowered_floor_never_commits() {
    let floors = Floors {
        root: None,
        keyset_version: 4,
        feed_seq: Default::default(),
    };
    for (what, input, _) in every_transition() {
        let input = input.raise_floors(&floors);
        // Re-run the transition over the raised input by name.
        let out = match what {
            "install_first" => install_first(&input, v("1.0.0"), 100, ID).unwrap(),
            "apply" => apply(&input, &v("1.1.0"), token("t")).unwrap(),
            "confirm" => confirm(&input, &v("1.1.0"), TokenCheck::Absent).unwrap().0,
            "count_attempt" => count_attempt(&input, &v("1.1.0")).unwrap().0,
            "rollback" => rollback(&input, &v("1.1.0")).unwrap(),
            "deliver_events" => deliver_events(&input, &v("1.1.0")).unwrap().0,
            _ => continue,
        };
        assert_eq!(out.floors, input.floors, "{what} changed the floors");
    }
    let (fs, loaded) = stored(&pending().raise_floors(&floors));
    let mut lowered = rollback(loaded.record.as_ref().unwrap(), &v("1.1.0")).unwrap();
    lowered.floors.keyset_version = 3;
    assert!(matches!(
        commit(&fs, &state_dir(), &loaded, &lowered, &H),
        Err(StateError::FloorLowered)
    ));
}

#[test]
fn the_floor_time_never_decreases_over_install_apply_rollback_apply() {
    let fs = MemFs::new();
    let step = |f: &dyn Fn(&InstallState) -> InstallState| -> u64 {
        let loaded = load_state(&fs).unwrap();
        let base = loaded.record.clone().unwrap_or_else(empty);
        let next = f(&base);
        let written = commit(&fs, &state_dir(), &loaded, &next, &H).unwrap();
        written.current.map_or(0, |c| c.issued)
    };
    let times = [
        step(&|s| install_first(s, v("1.0.0"), 100, ID).unwrap()),
        step(&|s| s.set_staged(Some((staged("1.1.0"), 200)))),
        step(&|s| apply(s, &v("1.1.0"), token("a")).unwrap()),
        step(&|s| rollback(s, &v("1.1.0")).unwrap()),
        step(&|s| s.set_staged(Some((staged("1.2.0"), 300)))),
        step(&|s| apply(s, &v("1.2.0"), token("b")).unwrap()),
        step(&|s| {
            confirm(s, &v("1.2.0"), TokenCheck::Presented(token("b")))
                .unwrap()
                .0
        }),
    ];
    assert_eq!(times, [100, 100, 200, 200, 200, 300, 300]);
    let back = load_state(&fs).unwrap().record.unwrap();
    assert_eq!(back.current.unwrap().version, v("1.2.0"));
    assert_eq!(back.bad, vec![v("1.1.0")]);
}

// ---- record evolution ---------------------------------------------------------------------------

/// The JSON payload of a record file.
fn payload(file: &[u8]) -> Map<String, Value> {
    let len = u32::from_be_bytes([file[5], file[6], file[7], file[8]]) as usize;
    serde_json::from_slice(&file[9..9 + len]).unwrap()
}

fn raw(fs: &dyn Fs, seq: u64, edited: &Map<String, Value>) {
    let bytes = serde_json::to_vec(edited).unwrap();
    commit_raw_payload(fs, &state_dir(), seq, &bytes, &H).unwrap();
}

fn newest_payload(fs: &dyn Fs) -> Map<String, Value> {
    let loaded = load_state(fs).unwrap();
    let seq = loaded.next_seq - 1;
    payload(
        &fs.read_capped(
            &state_dir().join(format!("{seq:020}.rec")),
            state::MAX_RECORD_BYTES,
        )
        .unwrap(),
    )
}

#[test]
fn an_unknown_top_level_member_survives_every_transition() {
    let future = json!({"a": [1, 2], "b": null});
    for (what, input, _) in every_transition() {
        // The input as a newer writer left it: the real writer's payload plus `x-future`.
        let (fs, loaded) = stored(&input);
        let mut p = newest_payload(&fs);
        p.insert("x-future".into(), future.clone());
        p.insert("seq".into(), json!(loaded.next_seq));
        raw(&fs, loaded.next_seq, &p);
        let loaded = load_state(&fs).unwrap();
        let record = loaded.record.clone().unwrap();
        assert_eq!(record.extra.get("x-future"), Some(&future), "{what}: read");
        let out = match what {
            "install_first" => install_first(&record, v("1.0.0"), 100, ID).unwrap(),
            "set_staged" => record.set_staged(Some((staged("1.1.0"), 200))),
            "set_staged(None)" => record.set_staged(None),
            "apply" => apply(&record, &v("1.1.0"), token("t")).unwrap(),
            "confirm" => confirm(&record, &v("1.1.0"), TokenCheck::Absent).unwrap().0,
            "count_attempt" => count_attempt(&record, &v("1.1.0")).unwrap().0,
            "rollback" => rollback(&record, &v("1.1.0")).unwrap(),
            "deliver_events" => deliver_events(&record, &v("1.1.0")).unwrap().0,
            "mark_bad" => record.mark_bad(v("1.1.0")),
            "install" => record.install(v("1.1.0"), 200, TARGET, ID),
            "raise_floors" => record.raise_floors(&Floors::default()),
            other => panic!("no case for {other}"),
        };
        let written = commit(&fs, &state_dir(), &loaded, &out, &H).unwrap();
        assert_eq!(
            newest_payload(&fs).get("x-future"),
            Some(&future),
            "{what}: written back"
        );
        assert_eq!(load_state(&fs).unwrap().record, Some(written), "{what}");
    }
}

#[test]
fn lifecycle_module_reads_no_clock_and_records_no_raw_token() {
    let source = include_str!("../src/lifecycle.rs");
    for needle in ["Clock", "SystemTime", "Instant", "now_unix_secs", "Rng"] {
        assert!(!source.contains(needle), "lifecycle.rs mentions {needle}");
    }
}

// ---- a crash at every op of a transition and its reconcile --------------------------------------

fn setup_disk(records: &[InstallState]) -> MemFs {
    let fs = MemFs::new();
    for version in ["1.0.0", "1.1.0", "1.2.0"] {
        fs.create_dir_all(&root().join("versions").join(version))
            .unwrap();
    }
    // Every directory durable in its parent, so a crash loses only what the step under test wrote.
    for dir in root().join("versions").ancestors() {
        fs.sync_dir(dir).unwrap();
    }
    for record in records {
        let loaded = load_state(&fs).unwrap();
        let written = commit(&fs, &state_dir(), &loaded, record, &H).unwrap();
        reconcile_current(&fs, &root(), &written).unwrap();
    }
    fs
}

fn link_agrees(fs: &dyn Fs, record: &InstallState, what: &str) {
    let link = root().join("current");
    match &record.current {
        Some(c) => assert_eq!(
            fs.read_link(&link).unwrap(),
            format!("versions/{}", c.version),
            "{what}"
        ),
        None => assert_eq!(fs.symlink_metadata(&link).unwrap(), None, "{what}"),
    }
}

/// `history` committed (each reconciled), then `next` committed and reconciled with a crash at
/// each op in turn, recovered under both modes: the record is the old or the new one, and after a
/// load and a reconcile `current` agrees with it.
fn crash_every_op(what: &str, history: &[InstallState], next: &InstallState) {
    let fs = setup_disk(history);
    let loaded = load_state(&fs).unwrap();
    let old = loaded.record.clone();
    let new = next.clone().with_seq(loaded.next_seq);
    let base = fs.op_count();
    let written = commit(&fs, &state_dir(), &loaded, next, &H).unwrap();
    assert_eq!(written, new);
    reconcile_current(&fs, &root(), &written).unwrap();
    let total = fs.op_count() - base;
    assert!(total > 4, "{what}: the commit and the reconcile wrote");

    for n in 0..=total {
        let fs = setup_disk(history);
        let loaded = load_state(&fs).unwrap();
        fs.crash_after(fs.op_count() + n);
        if let Ok(written) = commit(&fs, &state_dir(), &loaded, next, &H) {
            let _ = reconcile_current(&fs, &root(), &written);
        }
        for mode in [RecoverMode::DropVolatile, RecoverMode::KeepVolatile] {
            let disk = fs.recover(mode);
            let got = load_state(&disk)
                .unwrap_or_else(|e| panic!("{what} op {n} {mode:?}: {e}"))
                .record;
            assert!(
                got == old || got.as_ref() == Some(&new),
                "{what} op {n} {mode:?}: neither old nor new"
            );
            let record = got.unwrap();
            reconcile_current(&disk, &root(), &record)
                .unwrap_or_else(|e| panic!("{what} op {n} {mode:?}: reconcile: {e}"));
            link_agrees(&disk, &record, &format!("{what} op {n} {mode:?}"));
            // And it is durable: a second crash with nothing volatile kept still agrees.
            let again = disk.recover(RecoverMode::DropVolatile);
            link_agrees(
                &again,
                &record,
                &format!("{what} op {n} {mode:?} after sync"),
            );
        }
    }
}

#[test]
fn a_crash_at_any_op_of_a_transition_and_its_reconcile_converges() {
    let p = pending();
    let three = (0..3).fold(p.clone(), |s, _| count_attempt(&s, &v("1.1.0")).unwrap().0);
    crash_every_op("install_first", &[empty()], &installed());
    crash_every_op("apply", &[installed(), ready()], &pending());
    crash_every_op(
        "confirm",
        &[ready(), p.clone()],
        &confirm(&p, &v("1.1.0"), TokenCheck::Absent).unwrap().0,
    );
    crash_every_op(
        "count_attempt",
        &[ready(), p.clone()],
        &count_attempt(&p, &v("1.1.0")).unwrap().0,
    );
    crash_every_op(
        "rollback",
        &[ready(), three.clone()],
        &rollback(&three, &v("1.1.0")).unwrap(),
    );
    crash_every_op(
        "deliver_events",
        &[ready(), p.clone()],
        &deliver_events(&p, &v("1.1.0")).unwrap().0,
    );
}

#[test]
fn reconcile_heals_a_link_left_behind_by_an_earlier_crash() {
    // The record says 1.1.0 but the link still names 1.0.0 (a crash between commit and flip).
    let fs = setup_disk(&[installed()]);
    let loaded = load_state(&fs).unwrap();
    let mut p = pending();
    p = p.with_seq(loaded.next_seq);
    commit(&fs, &state_dir(), &loaded, &p, &H).unwrap();
    link_agrees(&fs, &installed(), "before");
    reconcile_current(&fs, &root(), &p).unwrap();
    link_agrees(&fs, &p, "after");
}
