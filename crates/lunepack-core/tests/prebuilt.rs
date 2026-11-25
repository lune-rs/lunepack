//! The prebuilt binary list (FORMAT.md 21) with the testkit fakes: the envelope under a key set the
//! caller holds, every payload rule, the rehearsal gate and the kind separation. The accept,
//! wrong-key and cross-kind cases also run with real Ed25519 in
//! `lunepack-crypto/tests/chain_prebuilt.rs`.

use lunepack_core::error::{Error, PrebuiltRule};
use lunepack_core::limits::Limits;
use lunepack_core::{
    BinaryKind, OpenedEnvelope, PayloadKind, PrebuiltList, RollbackFloor, Target, TrustedRoot,
    advance_root, verify_feed, verify_key_set, verify_prebuilt, write_envelope,
};
use lunepack_testkit::{ChainFixture, FakeClock, SUITE_T0};
use serde_json::{Value, json};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

fn row(kind: &str, target: &str, n: u64) -> Value {
    json!({
        "kind": kind,
        "target": target,
        "size": 100 + n,
        "sha256": format!("{n:064x}"),
    })
}

/// A valid release list of two rows.
fn list() -> Value {
    json!({
        "format": 1,
        "kind": "prebuilt",
        "critical": [],
        "version": "0.1.0",
        "source_commit": COMMIT,
        "rehearsal": false,
        "binaries": [row("runtime", "linux-x86_64", 1), row("ui", "macos-universal", 2)],
    })
}

fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

fn edited(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut v = list();
    edit(&mut v);
    bytes(&v)
}

/// `payload` signed as a `prebuilt` envelope by `seeds`, verified under the root of `root_seeds`
/// with `threshold`.
fn verify(
    fx: &ChainFixture<'_>,
    root_seeds: &[u8],
    threshold: u64,
    payload: &[u8],
    seeds: &[u8],
) -> Result<lunepack_core::VerifiedPrebuilt, Error> {
    let root = fx.trusted_root(1, threshold, root_seeds);
    let doc = fx.envelope(PayloadKind::Prebuilt, payload, seeds);
    verify_prebuilt(&root, &doc, fx.verifier)
}

#[test]
fn the_kind_has_its_type_name_and_cap() {
    let k = PayloadKind::Prebuilt;
    assert_eq!(
        k.payload_type(),
        "application/vnd.lunepack.prebuilt.v1+json"
    );
    assert_eq!(k.name(), "prebuilt");
    assert_eq!(k.doc_cap(&Limits::V1), 65_536);
    assert_eq!(Limits::V1.prebuilt_doc_bytes, 65_536);
    assert_eq!(Limits::V1.prebuilt_rows, 64);
    // The four existing kinds keep their caps.
    assert_eq!(PayloadKind::Root.doc_cap(&Limits::V1), 64 * 1024);
    assert_eq!(PayloadKind::Keys.doc_cap(&Limits::V1), 64 * 1024);
    assert_eq!(PayloadKind::Feed.doc_cap(&Limits::V1), 8 * 1024 * 1024);
    assert_eq!(PayloadKind::Manifest.doc_cap(&Limits::V1), 64 * 1024 * 1024);
}

#[test]
fn accepts_at_threshold_one() {
    let fx = ChainFixture::fake();
    let payload = bytes(&list());
    let v = verify(&fx, &[0], 1, &payload, &[0]).unwrap();
    assert_eq!(v.payload(), payload.as_slice());
    assert_eq!(v.version_text(), "0.1.0");
    assert_eq!(v.version().as_semver().minor, 1);
    assert_eq!(v.source_commit(), COMMIT);
    assert!(!v.is_rehearsal());
    let list = v.release_list().unwrap();
    assert_eq!(list.rows().len(), 2);
    let r = list.find(BinaryKind::Ui, Target::MacosUniversal).unwrap();
    assert_eq!(r.size(), 102);
    assert_eq!(r.sha256().to_hex(), format!("{:064x}", 2));
    assert_eq!(list.rows()[0].kind(), BinaryKind::Runtime);
    assert_eq!(list.rows()[0].target(), Target::LinuxX86_64);
    assert!(list.find(BinaryKind::Stub, Target::LinuxX86_64).is_none());
}

#[test]
fn accepts_two_of_three() {
    let fx = ChainFixture::fake();
    let payload = bytes(&list());
    assert!(verify(&fx, &[1, 2, 3], 2, &payload, &[1, 3]).is_ok());
    assert!(verify(&fx, &[1, 2, 3], 2, &payload, &[3, 2, 1]).is_ok());
}

#[test]
fn one_signature_below_a_threshold_of_two_is_refused() {
    let fx = ChainFixture::fake();
    let err = verify(&fx, &[1, 2, 3], 2, &bytes(&list()), &[2]).unwrap_err();
    assert!(matches!(err, Error::Threshold { need: 2, got: 1 }), "{err}");
}

#[test]
fn a_signer_outside_the_key_set_is_refused() {
    let fx = ChainFixture::fake();
    let err = verify(&fx, &[1, 2], 1, &bytes(&list()), &[4]).unwrap_err();
    assert!(matches!(err, Error::Threshold { need: 1, got: 0 }), "{err}");
}

#[test]
fn one_key_signing_twice_counts_once() {
    let fx = ChainFixture::fake();
    let err = verify(&fx, &[1, 2], 2, &bytes(&list()), &[1, 1]).unwrap_err();
    assert!(matches!(err, Error::Threshold { need: 2, got: 1 }), "{err}");
}

#[test]
fn two_key_sets_that_share_no_key_refuse_each_others_lists() {
    let fx = ChainFixture::fake();
    let payload = bytes(&list());
    let a = fx.trusted_root(1, 1, &[1, 2]);
    let b = fx.trusted_root(1, 1, &[3, 4]);
    let by_a = fx.envelope(PayloadKind::Prebuilt, &payload, &[1]);
    let by_b = fx.envelope(PayloadKind::Prebuilt, &payload, &[3]);
    assert!(verify_prebuilt(&a, &by_a, fx.verifier).is_ok());
    assert!(verify_prebuilt(&b, &by_b, fx.verifier).is_ok());
    for err in [
        verify_prebuilt(&b, &by_a, fx.verifier).unwrap_err(),
        verify_prebuilt(&a, &by_b, fx.verifier).unwrap_err(),
    ] {
        assert!(matches!(err, Error::Threshold { need: 1, got: 0 }), "{err}");
    }
}

/// Each payload rule of FORMAT.md 21 (and of 3.2 for every payload), asserted on the error.
#[test]
fn every_payload_rule_refuses_with_its_own_error() {
    let fx = ChainFixture::fake();
    let rule = |r: PrebuiltRule| move |e: &Error| matches!(e, Error::Prebuilt(x) if *x == r);
    type Check = Box<dyn Fn(&Error) -> bool>;
    let cases: Vec<(&str, Vec<u8>, Check)> = vec![
        (
            "format 2",
            edited(|v| v["format"] = json!(2)),
            Box::new(|e| matches!(e, Error::FormatVersion { found: 2 })),
        ),
        (
            "kind keys",
            edited(|v| v["kind"] = json!("keys")),
            Box::new(|e| {
                matches!(
                    e,
                    Error::Kind {
                        expected: "prebuilt"
                    }
                )
            }),
        ),
        (
            "critical entry",
            edited(|v| v["critical"] = json!(["x"])),
            Box::new(|e| matches!(e, Error::UnknownCritical(_))),
        ),
        (
            "duplicate member",
            {
                let t = String::from_utf8(bytes(&list())).unwrap();
                t.replacen('{', "{\"rehearsal\":true,", 1).into_bytes()
            },
            Box::new(|e| matches!(e, Error::Json(_))),
        ),
        (
            "version missing",
            edited(|v| {
                v.as_object_mut().unwrap().remove("version");
            }),
            Box::new(rule(PrebuiltRule::Version)),
        ),
        (
            "version a number",
            edited(|v| v["version"] = json!(1)),
            Box::new(rule(PrebuiltRule::Version)),
        ),
        (
            "version not semver",
            edited(|v| v["version"] = json!("1.0")),
            Box::new(|e| matches!(e, Error::Version(_))),
        ),
        (
            "version over 64 bytes",
            edited(|v| v["version"] = json!(format!("1.0.0-{}", "a".repeat(60)))),
            Box::new(|e| matches!(e, Error::Version(_))),
        ),
        (
            "source_commit 39 hex",
            edited(|v| v["source_commit"] = json!(&COMMIT[..39])),
            Box::new(rule(PrebuiltRule::SourceCommit)),
        ),
        (
            "source_commit 41 hex",
            edited(|v| v["source_commit"] = json!(format!("{COMMIT}0"))),
            Box::new(rule(PrebuiltRule::SourceCommit)),
        ),
        (
            "source_commit uppercase",
            edited(|v| v["source_commit"] = json!(COMMIT.to_uppercase())),
            Box::new(rule(PrebuiltRule::SourceCommit)),
        ),
        (
            "source_commit not hex",
            edited(|v| v["source_commit"] = json!(format!("g{}", &COMMIT[1..]))),
            Box::new(rule(PrebuiltRule::SourceCommit)),
        ),
        (
            "source_commit missing",
            edited(|v| {
                v.as_object_mut().unwrap().remove("source_commit");
            }),
            Box::new(rule(PrebuiltRule::SourceCommit)),
        ),
        (
            "rehearsal a string",
            edited(|v| v["rehearsal"] = json!("false")),
            Box::new(rule(PrebuiltRule::Rehearsal)),
        ),
        (
            "rehearsal a number",
            edited(|v| v["rehearsal"] = json!(0)),
            Box::new(rule(PrebuiltRule::Rehearsal)),
        ),
        (
            "rehearsal missing",
            edited(|v| {
                v.as_object_mut().unwrap().remove("rehearsal");
            }),
            Box::new(rule(PrebuiltRule::Rehearsal)),
        ),
        (
            "binaries empty",
            edited(|v| v["binaries"] = json!([])),
            Box::new(rule(PrebuiltRule::Binaries)),
        ),
        (
            "binaries an object",
            edited(|v| v["binaries"] = row("runtime", "linux-x86_64", 1)),
            Box::new(rule(PrebuiltRule::Binaries)),
        ),
        (
            "binaries missing",
            edited(|v| {
                v.as_object_mut().unwrap().remove("binaries");
            }),
            Box::new(rule(PrebuiltRule::Binaries)),
        ),
        (
            "65 rows",
            edited(|v| {
                v["binaries"] = json!(
                    (0..65)
                        .map(|n| row("runtime", "linux-x86_64", n))
                        .collect::<Vec<_>>()
                )
            }),
            Box::new(|e| {
                matches!(
                    e,
                    Error::TooMany {
                        what: "prebuilt rows",
                        count: 65,
                        max: 64
                    }
                )
            }),
        ),
        (
            "row a string",
            edited(|v| v["binaries"] = json!(["runtime"])),
            Box::new(rule(PrebuiltRule::Row)),
        ),
        (
            "row kind unknown",
            edited(|v| v["binaries"][0]["kind"] = json!("installer")),
            Box::new(rule(PrebuiltRule::Kind)),
        ),
        (
            "row kind another case",
            edited(|v| v["binaries"][0]["kind"] = json!("Runtime")),
            Box::new(rule(PrebuiltRule::Kind)),
        ),
        (
            "row kind missing",
            edited(|v| {
                v["binaries"][0].as_object_mut().unwrap().remove("kind");
            }),
            Box::new(rule(PrebuiltRule::Kind)),
        ),
        (
            "row target unknown",
            edited(|v| v["binaries"][0]["target"] = json!("macos-arm64")),
            Box::new(|e| matches!(e, Error::Target(_))),
        ),
        (
            "row target a number",
            edited(|v| v["binaries"][0]["target"] = json!(7)),
            Box::new(rule(PrebuiltRule::Target)),
        ),
        (
            "row size 0",
            edited(|v| v["binaries"][0]["size"] = json!(0)),
            Box::new(rule(PrebuiltRule::Size)),
        ),
        (
            "row size negative",
            edited(|v| v["binaries"][0]["size"] = json!(-1)),
            Box::new(rule(PrebuiltRule::Size)),
        ),
        (
            "row size a fraction",
            edited(|v| v["binaries"][0]["size"] = json!(1.5)),
            Box::new(rule(PrebuiltRule::Size)),
        ),
        (
            "row size 2^53",
            edited(|v| v["binaries"][0]["size"] = json!(1u64 << 53)),
            Box::new(rule(PrebuiltRule::Size)),
        ),
        (
            "row size a string",
            edited(|v| v["binaries"][0]["size"] = json!("100")),
            Box::new(rule(PrebuiltRule::Size)),
        ),
        (
            "row sha256 uppercase",
            edited(|v| v["binaries"][0]["sha256"] = json!(format!("{:064X}", 0xabcu32))),
            Box::new(rule(PrebuiltRule::Sha256)),
        ),
        (
            "row sha256 63 hex",
            edited(|v| v["binaries"][0]["sha256"] = json!(format!("{:063x}", 1))),
            Box::new(rule(PrebuiltRule::Sha256)),
        ),
        (
            "row sha256 missing",
            edited(|v| {
                v["binaries"][0].as_object_mut().unwrap().remove("sha256");
            }),
            Box::new(rule(PrebuiltRule::Sha256)),
        ),
        (
            "two rows share kind and target",
            edited(|v| {
                v["binaries"] = json!([
                    row("stub", "windows-x86_64", 1),
                    row("stub-console", "windows-x86_64", 2),
                    row("stub", "windows-x86_64", 3),
                ])
            }),
            Box::new(rule(PrebuiltRule::DuplicateRow)),
        ),
    ];
    for (name, payload, check) in cases {
        let err = verify(&fx, &[0], 1, &payload, &[0]).unwrap_err();
        assert!(check(&err), "{name}: refused with {err}");
        // The bare-payload reader refuses it the same way.
        let bare = PrebuiltList::from_payload(&payload).unwrap_err();
        assert_eq!(bare.to_string(), err.to_string(), "{name}");
    }
}

#[test]
fn unknown_members_are_ignored() {
    let fx = ChainFixture::fake();
    let payload = edited(|v| {
        v["notes"] = json!({"nested": [1, 2, {"x": null}]});
        v["binaries"][1]["signed_by"] = json!("ignored");
    });
    let list = verify(&fx, &[0], 1, &payload, &[0])
        .unwrap()
        .release_list()
        .unwrap();
    assert_eq!(list.rows().len(), 2);
}

#[test]
fn every_kind_for_every_target_is_the_largest_list() {
    let fx = ChainFixture::fake();
    let rows: Vec<Value> = Target::ALL
        .iter()
        .flat_map(|t| {
            BinaryKind::ALL
                .iter()
                .map(move |k| row(k.as_str(), t.as_str(), 9))
        })
        .collect();
    assert_eq!(rows.len(), 35);
    let payload = edited(|v| v["binaries"] = json!(rows));
    let list = verify(&fx, &[0], 1, &payload, &[0])
        .unwrap()
        .release_list()
        .unwrap();
    assert_eq!(list.rows().len(), 35);
    for k in BinaryKind::ALL {
        assert_eq!(BinaryKind::parse(k.as_str()), Some(k));
    }
}

#[test]
fn release_list_refuses_a_rehearsal_list_and_rehearsal_list_gives_its_rows() {
    let fx = ChainFixture::fake();
    let rehearsal = edited(|v| v["rehearsal"] = json!(true));
    let v = verify(&fx, &[0], 1, &rehearsal, &[0]).unwrap();
    assert!(v.is_rehearsal());
    assert!(matches!(v.release_list(), Err(Error::RehearsalList)));

    let v = verify(&fx, &[0], 1, &rehearsal, &[0]).unwrap();
    let rows = v.rehearsal_list();
    assert!(rows.is_rehearsal());
    assert_eq!(rows.rows().len(), 2);

    let release = verify(&fx, &[0], 1, &bytes(&list()), &[0]).unwrap();
    assert!(!release.is_rehearsal());
    assert!(!release.release_list().unwrap().is_rehearsal());

    // The verified value's Debug output does not list rows.
    let v = verify(&fx, &[0], 1, &rehearsal, &[0]).unwrap();
    assert!(!format!("{v:?}").contains(&format!("{:064x}", 1)));
}

#[test]
fn a_document_over_the_cap_is_refused_before_parsing() {
    let fx = ChainFixture::fake();
    let root = fx.trusted_root(1, 1, &[0]);
    // Not JSON at all: only the cap can refuse it.
    let junk = vec![b'x'; 65_537];
    let err = verify_prebuilt(&root, &junk, fx.verifier).unwrap_err();
    assert!(
        matches!(
            err,
            Error::TooLarge {
                what: "prebuilt",
                size: 65_537,
                cap: 65_536
            }
        ),
        "{err}"
    );
    // A signed, otherwise valid list padded past the cap.
    let big = edited(|v| v["pad"] = json!("p".repeat(50_000)));
    let doc = fx.envelope(PayloadKind::Prebuilt, &big, &[0]);
    assert!(doc.len() > 65_536);
    assert!(matches!(
        verify_prebuilt(&root, &doc, fx.verifier),
        Err(Error::TooLarge {
            what: "prebuilt",
            ..
        })
    ));
    // The bare payload has the same cap.
    let junk = vec![b' '; 65_537];
    assert!(matches!(
        PrebuiltList::from_payload(&junk),
        Err(Error::TooLarge {
            what: "prebuilt",
            size: 65_537,
            cap: 65_536
        })
    ));
}

#[test]
fn from_payload_gives_the_same_list_as_the_envelope() {
    let fx = ChainFixture::fake();
    for payload in [bytes(&list()), edited(|v| v["rehearsal"] = json!(true))] {
        let bare = PrebuiltList::from_payload(&payload).unwrap();
        let verified = verify(&fx, &[0], 1, &payload, &[0]).unwrap();
        assert_eq!(verified.payload(), payload.as_slice());
        assert_eq!(verified.rehearsal_list(), bare);
    }
}

/// The kind separation (FORMAT.md 2.2, 2.3): a `prebuilt` envelope is refused as each of the four
/// other kinds and each of them is refused as `prebuilt`, with the same payload bytes and the same
/// signatures. Opening fails on the type; with the type rewritten, the signature fails, because
/// the type is part of what is signed.
#[test]
fn a_prebuilt_list_and_the_four_other_kinds_are_never_taken_for_each_other() {
    let fx = ChainFixture::fake();
    let root = fx.trusted_root(1, 1, &[0]);
    let payload = bytes(&list());
    for other in [
        PayloadKind::Root,
        PayloadKind::Keys,
        PayloadKind::Feed,
        PayloadKind::Manifest,
    ] {
        // A prebuilt list where `other` is expected.
        let sig = fx.signature(0, PayloadKind::Prebuilt.payload_type(), &payload);
        let as_prebuilt = write_envelope(PayloadKind::Prebuilt.payload_type(), &payload, &[sig]);
        let err = OpenedEnvelope::open(&as_prebuilt, other, &Limits::V1).unwrap_err();
        assert!(
            matches!(err, Error::PayloadType { expected } if expected == other.payload_type()),
            "{other:?}: {err}"
        );
        let relabelled = write_envelope(other.payload_type(), &payload, &[sig]);
        let opened = OpenedEnvelope::open(&relabelled, other, &Limits::V1).unwrap();
        let err = opened
            .authenticate(root.keys(), 1, fx.verifier)
            .unwrap_err();
        assert!(
            matches!(err, Error::Threshold { need: 1, got: 0 }),
            "{other:?}: {err}"
        );

        // `other` where a prebuilt list is expected.
        let sig = fx.signature(0, other.payload_type(), &payload);
        let as_other = write_envelope(other.payload_type(), &payload, &[sig]);
        let err = verify_prebuilt(&root, &as_other, fx.verifier).unwrap_err();
        assert!(
            matches!(err, Error::PayloadType { expected } if expected == PayloadKind::Prebuilt.payload_type()),
            "{other:?}: {err}"
        );
        let relabelled = write_envelope(PayloadKind::Prebuilt.payload_type(), &payload, &[sig]);
        let err = verify_prebuilt(&root, &relabelled, fx.verifier).unwrap_err();
        assert!(
            matches!(err, Error::Threshold { need: 1, got: 0 }),
            "{other:?}: {err}"
        );
    }
}

/// The real readers of the root, the key set and the feed refuse a `prebuilt` envelope signed by
/// the very keys they trust.
#[test]
fn the_app_readers_refuse_a_prebuilt_list() {
    let fx = ChainFixture::fake();
    let payload = bytes(&list());
    let (root, keys) = fx.verified_chain(&[5], 1);
    let by_root = fx.envelope(PayloadKind::Prebuilt, &payload, &[0]);
    let by_release = fx.envelope(PayloadKind::Prebuilt, &payload, &[5]);
    let expected = |e: &Error, kind: PayloadKind| matches!(e, Error::PayloadType { expected } if *expected == kind.payload_type());

    let err = advance_root(&root, &by_root, fx.hasher, fx.verifier).unwrap_err();
    assert!(expected(&err, PayloadKind::Root), "{err}");

    let clock = lunepack_core::ClockReading::read(&FakeClock::new(SUITE_T0), None);
    let err = verify_key_set(
        &root,
        &by_root,
        &RollbackFloor::default(),
        &clock,
        fx.hasher,
        fx.verifier,
    )
    .unwrap_err();
    assert!(expected(&err, PayloadKind::Keys), "{err}");

    let err = verify_feed(
        &keys,
        &by_release,
        keys.app_id(),
        &lunepack_core::Channel::parse("stable").unwrap(),
        &RollbackFloor::default(),
        &clock,
        fx.verifier,
    )
    .unwrap_err();
    assert!(expected(&err, PayloadKind::Feed), "{err}");

    // A root built with `from_parts` is the key set a list is verified under.
    let built = TrustedRoot::from_parts(
        root.app_id().clone(),
        1,
        1,
        &[fx.public_key(0)],
        fx.hasher,
        fx.verifier,
    )
    .unwrap();
    assert!(verify_prebuilt(&built, &by_root, fx.verifier).is_ok());
}
