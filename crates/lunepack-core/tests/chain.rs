//! The shared chain walk (`lunepack_core::chain`) over the testkit's chain fixture: the happy path,
//! the order of the checks, and one table of inputs that must each fail with the variant the
//! facade's own composition produced before it moved into core.

use lunepack_core::{
    AppId, Channel, ClockReading, Documents, Error, Floors, MAX_ROOT_STEPS, PayloadKind,
    RollbackFloor, RootParts, RootWalk, Target, TrustedRoot, raised_floors,
    verify_first_install_keys,
};
use lunepack_testkit::{
    ChainFixture, FakeClock, FakeHasher, FakeVerifier, SUITE_APP_ID, SUITE_CHANNEL, SUITE_T0,
};

const DAY: u64 = 86_400;

fn app() -> AppId {
    AppId::parse(SUITE_APP_ID).unwrap()
}

fn channel() -> Channel {
    Channel::parse(SUITE_CHANNEL).unwrap()
}

fn at(now: u64) -> ClockReading {
    ClockReading::read(&FakeClock::new(now), None)
}

/// Signed key-set bytes under root version `root_version` (signed by root seed 0).
fn keys_bytes(
    fx: &ChainFixture<'_>,
    root_version: u64,
    version: u64,
    expires: Option<u64>,
) -> Vec<u8> {
    let doc = fx.keyset_document(root_version, version, expires, 1, &[5]);
    fx.envelope(PayloadKind::Keys, &doc.to_payload(), &[0])
}

/// Signed feed bytes (release seed 5).
fn feed_bytes(fx: &ChainFixture<'_>, seq: u64) -> Vec<u8> {
    let doc = fx.feed_document(
        seq,
        Some(SUITE_T0 + 90 * DAY),
        vec![fx.release("1.0.0", &[(Target::LinuxX86_64, b"m")], None)],
    );
    fx.envelope(PayloadKind::Feed, &doc.to_payload(), &[5])
}

/// `root-<to>.json`: rotation to version `to`, keys of `seeds`, signed by `signers`.
fn rotation(fx: &ChainFixture<'_>, to: u64, seeds: &[u8], signers: &[u8]) -> Vec<u8> {
    let doc = fx.root_document(to, 1, seeds);
    fx.envelope(PayloadKind::Root, &doc.to_payload(), signers)
}

fn root1(fx: &ChainFixture<'_>) -> TrustedRoot {
    fx.trusted_root(1, 1, &[0])
}

fn finish(
    fx: &ChainFixture<'_>,
    walk: RootWalk,
    app_id: &AppId,
    floors: &Floors,
    keys: &[u8],
    feed: &[u8],
    clock: &ClockReading,
) -> Result<Documents, Error> {
    walk.finish(
        app_id,
        &channel(),
        floors,
        keys,
        feed,
        clock,
        fx.hasher,
        fx.verifier,
    )
}

#[test]
fn the_chain_verifies_and_raises_the_floors() {
    let fx = ChainFixture::fake();
    let mut walk = RootWalk::new(root1(&fx));
    assert_eq!(walk.next_version(), Some(2));
    walk.advance(&rotation(&fx, 2, &[0], &[0]), &FakeHasher, &FakeVerifier)
        .unwrap();
    assert_eq!(walk.root().version(), 2);
    assert_eq!(walk.next_version(), Some(3));

    let docs = finish(
        &fx,
        walk,
        &app(),
        &Floors::default(),
        &keys_bytes(&fx, 2, 4, None),
        &feed_bytes(&fx, 7),
        &at(SUITE_T0),
    )
    .unwrap();
    assert_eq!(docs.root.version(), 2);
    assert_eq!(docs.keys.version(), 4);
    assert_eq!(docs.feed.seq(), 7);

    let raised = raised_floors(&docs.root, &docs.keys, &docs.feed, &channel());
    assert_eq!(raised.root, Some(RootParts::from_trusted(&docs.root)));
    assert_eq!(raised.keyset_version, 4);
    assert_eq!(raised.feed_seq.get(&channel()), Some(&7));
    // The same floors the core's own raise computes.
    let floor = RollbackFloor::default().raise(&docs.keys, &docs.feed);
    assert_eq!(raised.to_rollback_floor(), floor.clone());
    // A check against the raised floors accepts the same documents again (equal is allowed).
    finish(
        &fx,
        RootWalk::new(docs.root.clone()),
        &app(),
        &raised,
        &keys_bytes(&fx, 2, 4, None),
        &feed_bytes(&fx, 7),
        &at(SUITE_T0),
    )
    .unwrap();
}

#[test]
fn staged_verification_matches_finish() {
    let fx = ChainFixture::fake();
    let keys = keys_bytes(&fx, 1, 1, None);
    let feed = feed_bytes(&fx, 2);
    let one = finish(
        &fx,
        RootWalk::new(root1(&fx)),
        &app(),
        &Floors::default(),
        &keys,
        &feed,
        &at(SUITE_T0),
    )
    .unwrap();
    let chain = RootWalk::new(root1(&fx))
        .verify_keys(
            &app(),
            &Floors::default(),
            &keys,
            &at(SUITE_T0),
            &FakeHasher,
            &FakeVerifier,
        )
        .unwrap();
    assert_eq!(chain.keys().version(), one.keys.version());
    let two = chain
        .verify_feed(&app(), &channel(), &feed, &at(SUITE_T0), &FakeVerifier)
        .unwrap();
    assert_eq!(two.feed.seq(), one.feed.seq());
    assert_eq!(two.root.version(), one.root.version());
}

#[test]
fn bad_inputs_fail_with_the_variant_the_facade_produced() {
    let fx = ChainFixture::fake();
    let other = AppId::parse("org.example.other").unwrap();
    let good_keys = keys_bytes(&fx, 1, 1, None);
    let good_feed = feed_bytes(&fx, 3);
    let run = |walk: RootWalk, app_id: &AppId, floors: &Floors, keys: &[u8], feed: &[u8]| {
        finish(&fx, walk, app_id, floors, keys, feed, &at(SUITE_T0))
    };
    let fresh = || RootWalk::new(root1(&fx));

    // Wrong app id: the final root is not the app's.
    assert!(matches!(
        run(fresh(), &other, &Floors::default(), &good_keys, &good_feed),
        Err(Error::AppIdMismatch)
    ));

    // Expired key set.
    let expired = keys_bytes(&fx, 1, 1, Some(SUITE_T0 - 1));
    assert!(matches!(
        run(fresh(), &app(), &Floors::default(), &expired, &good_feed),
        Err(Error::Expired { .. })
    ));

    // Feed below the stored floor.
    let mut floors = Floors::default();
    floors.feed_seq.insert(channel(), 9);
    assert!(matches!(
        run(fresh(), &app(), &floors, &good_keys, &good_feed),
        Err(Error::Rollback { .. })
    ));

    // Key set below the stored key-set floor.
    let floors = Floors {
        keyset_version: 5,
        ..Floors::default()
    };
    assert!(matches!(
        run(fresh(), &app(), &floors, &good_keys, &good_feed),
        Err(Error::Rollback { .. })
    ));

    // A key set that names another root version than the walk ended on.
    assert!(matches!(
        run(
            fresh(),
            &app(),
            &Floors::default(),
            &keys_bytes(&fx, 2, 1, None),
            &good_feed
        ),
        Err(Error::KeySetRootVersion { .. })
    ));

    // Feed for another channel.
    let beta = Channel::parse("beta").unwrap();
    assert!(matches!(
        fresh().finish(
            &app(),
            &beta,
            &Floors::default(),
            &good_keys,
            &good_feed,
            &at(SUITE_T0),
            &FakeHasher,
            &FakeVerifier,
        ),
        Err(Error::ChannelMismatch)
    ));

    // A rotation signed by the wrong key; the walk is unchanged by the failed step.
    let mut walk = fresh();
    assert!(matches!(
        walk.advance(&rotation(&fx, 2, &[0], &[3]), &FakeHasher, &FakeVerifier),
        Err(Error::Threshold { .. })
    ));
    assert_eq!(walk.root().version(), 1);
    // A rotation that skips a version.
    assert!(matches!(
        walk.advance(&rotation(&fx, 3, &[0], &[0]), &FakeHasher, &FakeVerifier),
        Err(Error::RootVersion { expected: 2, .. })
    ));
    assert_eq!(walk.root().version(), 1);
}

#[test]
fn too_many_rotations_are_an_error() {
    let fx = ChainFixture::fake();
    // A small cap.
    let mut walk = RootWalk::with_max_steps(root1(&fx), 2);
    for to in 2..=3 {
        walk.advance(&rotation(&fx, to, &[0], &[0]), &FakeHasher, &FakeVerifier)
            .unwrap();
    }
    assert_eq!(walk.next_version(), None);
    assert!(matches!(
        walk.advance(&rotation(&fx, 4, &[0], &[0]), &FakeHasher, &FakeVerifier),
        Err(Error::TooMany {
            what: "root rotations",
            max: 2,
            ..
        })
    ));
    assert_eq!(walk.root().version(), 3);

    // The real cap.
    let mut walk = RootWalk::new(root1(&fx));
    for step in 0..MAX_ROOT_STEPS {
        assert_eq!(walk.next_version(), Some(step + 2));
        walk.advance(
            &rotation(&fx, step + 2, &[0], &[0]),
            &FakeHasher,
            &FakeVerifier,
        )
        .unwrap();
    }
    assert_eq!(walk.next_version(), None);
    assert!(matches!(
        walk.advance(
            &rotation(&fx, MAX_ROOT_STEPS + 2, &[0], &[0]),
            &FakeHasher,
            &FakeVerifier
        ),
        Err(Error::TooMany { .. })
    ));
}

#[test]
fn checks_run_in_the_documented_order() {
    let fx = ChainFixture::fake();
    let other = AppId::parse("org.example.other").unwrap();
    let junk = b"not an envelope".to_vec();
    let expired = keys_bytes(&fx, 1, 1, Some(SUITE_T0 - 1));
    let run = |app_id: &AppId, keys: &[u8], feed: &[u8]| {
        finish(
            &fx,
            RootWalk::new(root1(&fx)),
            app_id,
            &Floors::default(),
            keys,
            feed,
            &at(SUITE_T0),
        )
    };
    // The app id is checked before the key set is opened.
    assert!(matches!(
        run(&other, &junk, &junk),
        Err(Error::AppIdMismatch)
    ));
    // The key set is verified before the feed is opened.
    assert!(matches!(
        run(&app(), &expired, &junk),
        Err(Error::Expired { .. })
    ));
    // With a good key set, a bad feed is the feed's error.
    assert!(run(&app(), &keys_bytes(&fx, 1, 1, None), &junk).is_err());
}

#[test]
fn first_install_keys_verify_without_floors() {
    let fx = ChainFixture::fake();
    let root = root1(&fx);
    let keys = verify_first_install_keys(
        &root,
        &keys_bytes(&fx, 1, 9, None),
        &at(SUITE_T0),
        &FakeHasher,
        &FakeVerifier,
    )
    .unwrap();
    assert_eq!(keys.version(), 9);
    assert!(matches!(
        verify_first_install_keys(
            &root,
            &keys_bytes(&fx, 1, 9, Some(SUITE_T0 - 1)),
            &at(SUITE_T0),
            &FakeHasher,
            &FakeVerifier,
        ),
        Err(Error::Expired { .. })
    ));
}
