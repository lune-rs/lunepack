//! The prebuilt binary list (FORMAT.md 21) with real Ed25519 and SHA-256: accept at threshold 1
//! and at 2 of 3, a wrong key, and the kind separation from the four other kinds. Keys are
//! generated at test time; none is committed. The payload rules run with the fakes in
//! `lunepack-core/tests/prebuilt.rs`.

use ed25519_dalek::{Signer, SigningKey};
use getrandom::SysRng;
use getrandom::rand_core::UnwrapErr;
use lunepack_core::limits::Limits;
use lunepack_core::{Error, OpenedEnvelope, PayloadKind, verify_prebuilt, write_envelope};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};
use lunepack_testkit::ChainFixture;

/// One fresh signing key per seed `0..=7`.
struct Keys(Vec<SigningKey>);

impl Keys {
    fn new() -> Self {
        let mut rng = UnwrapErr(SysRng);
        Keys((0..8).map(|_| SigningKey::generate(&mut rng)).collect())
    }

    fn sign(&self, seed: u8, message: &[u8]) -> ([u8; 32], [u8; 64]) {
        let key = &self.0[usize::from(seed)];
        (key.verifying_key().to_bytes(), key.sign(message).to_bytes())
    }
}

/// A small-order public key, which the real verifier rejects.
fn small_order_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = 1;
    k
}

fn list(rehearsal: bool) -> Vec<u8> {
    format!(
        concat!(
            r#"{{"format":1,"kind":"prebuilt","critical":[],"version":"0.1.0","#,
            r#""source_commit":"0123456789abcdef0123456789abcdef01234567","rehearsal":{},"#,
            r#""binaries":[{{"kind":"runtime","target":"linux-x86_64","size":4096,"#,
            r#""sha256":"{:064x}"}}]}}"#
        ),
        rehearsal, 7
    )
    .into_bytes()
}

fn with_fixture(test: impl Fn(&ChainFixture<'_>)) {
    let keys = Keys::new();
    let sign = |seed: u8, message: &[u8]| keys.sign(seed, message);
    test(&ChainFixture {
        hasher: &Sha256Hasher,
        verifier: &Ed25519Verifier,
        sign: &sign,
        invalid_key: small_order_key(),
    });
}

#[test]
fn accepts_at_threshold_one_and_at_two_of_three() {
    with_fixture(|fx| {
        let payload = list(false);
        let root = fx.trusted_root(1, 1, &[0]);
        let doc = fx.envelope(PayloadKind::Prebuilt, &payload, &[0]);
        let v = verify_prebuilt(&root, &doc, fx.verifier).unwrap();
        assert_eq!(v.payload(), payload.as_slice());
        assert_eq!(v.release_list().unwrap().rows().len(), 1);

        let root = fx.trusted_root(1, 2, &[1, 2, 3]);
        let doc = fx.envelope(PayloadKind::Prebuilt, &payload, &[3, 1]);
        assert!(verify_prebuilt(&root, &doc, fx.verifier).is_ok());
        let doc = fx.envelope(PayloadKind::Prebuilt, &payload, &[2]);
        assert!(matches!(
            verify_prebuilt(&root, &doc, fx.verifier),
            Err(Error::Threshold { need: 2, got: 1 })
        ));
        let doc = fx.envelope(PayloadKind::Prebuilt, &payload, &[2, 2]);
        assert!(matches!(
            verify_prebuilt(&root, &doc, fx.verifier),
            Err(Error::Threshold { need: 2, got: 1 })
        ));
    });
}

#[test]
fn a_rehearsal_list_verifies_but_is_no_release_list() {
    with_fixture(|fx| {
        let root = fx.trusted_root(1, 1, &[0]);
        let doc = fx.envelope(PayloadKind::Prebuilt, &list(true), &[0]);
        let v = verify_prebuilt(&root, &doc, fx.verifier).unwrap();
        assert!(v.is_rehearsal());
        assert!(matches!(v.release_list(), Err(Error::RehearsalList)));
    });
}

#[test]
fn a_wrong_key_is_refused() {
    with_fixture(|fx| {
        let payload = list(false);
        let root = fx.trusted_root(1, 1, &[1, 2]);
        let doc = fx.envelope(PayloadKind::Prebuilt, &payload, &[4]);
        assert!(matches!(
            verify_prebuilt(&root, &doc, fx.verifier),
            Err(Error::Threshold { need: 1, got: 0 })
        ));
        // Two key sets that share no key refuse each other's lists, both ways.
        let other = fx.trusted_root(1, 1, &[3, 4]);
        let by_root = fx.envelope(PayloadKind::Prebuilt, &payload, &[1]);
        assert!(verify_prebuilt(&root, &by_root, fx.verifier).is_ok());
        assert!(verify_prebuilt(&other, &doc, fx.verifier).is_ok());
        assert!(verify_prebuilt(&other, &by_root, fx.verifier).is_err());
        // A signature by the right key over other payload bytes does not count.
        let sig = fx.signature(1, PayloadKind::Prebuilt.payload_type(), &payload);
        let tampered = write_envelope(PayloadKind::Prebuilt.payload_type(), &list(true), &[sig]);
        assert!(matches!(
            verify_prebuilt(&root, &tampered, fx.verifier),
            Err(Error::Threshold { need: 1, got: 0 })
        ));
    });
}

/// Same payload bytes, same real signatures: only the payload type differs, and the type is part
/// of what is signed (FORMAT.md 2.3).
#[test]
fn a_prebuilt_list_and_the_four_other_kinds_are_never_taken_for_each_other() {
    with_fixture(|fx| {
        let root = fx.trusted_root(1, 1, &[0]);
        let payload = list(false);
        let prebuilt = PayloadKind::Prebuilt;
        for other in [
            PayloadKind::Root,
            PayloadKind::Keys,
            PayloadKind::Feed,
            PayloadKind::Manifest,
        ] {
            let sig = fx.signature(0, prebuilt.payload_type(), &payload);
            let doc = write_envelope(prebuilt.payload_type(), &payload, &[sig]);
            assert!(matches!(
                OpenedEnvelope::open(&doc, other, &Limits::V1),
                Err(Error::PayloadType { .. })
            ));
            let relabelled = write_envelope(other.payload_type(), &payload, &[sig]);
            let opened = OpenedEnvelope::open(&relabelled, other, &Limits::V1).unwrap();
            assert!(matches!(
                opened.authenticate(root.keys(), 1, fx.verifier),
                Err(Error::Threshold { need: 1, got: 0 })
            ));

            let sig = fx.signature(0, other.payload_type(), &payload);
            let doc = write_envelope(other.payload_type(), &payload, &[sig]);
            assert!(matches!(
                verify_prebuilt(&root, &doc, fx.verifier),
                Err(Error::PayloadType { .. })
            ));
            let relabelled = write_envelope(prebuilt.payload_type(), &payload, &[sig]);
            assert!(matches!(
                verify_prebuilt(&root, &relabelled, fx.verifier),
                Err(Error::Threshold { need: 1, got: 0 })
            ));
        }
    });
}
