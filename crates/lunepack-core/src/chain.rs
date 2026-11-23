//! The trust chain walk (FORMAT.md 5.2, 11.1): the one place that composes
//! [`advance_root`], [`verify_key_set`] and [`verify_feed`], so the library and the privileged
//! engine verify the signed documents the same way and in the same order.
//!
//! The caller fetches; this module only verifies. A check goes: [`RootWalk::new`] from the
//! trusted root, then [`RootWalk::next_version`] and [`RootWalk::advance`] for each rotation the
//! source offers, then [`RootWalk::finish`] with the key-set and feed bytes (or the two stages
//! [`RootWalk::verify_keys`] and [`KeysChain::verify_feed`] when the feed is fetched only after the
//! key set verified). Nothing here is committed: the caller persists [`raised_floors`] after the
//! whole check succeeded.

use crate::error::{Error, Result};
use crate::feed::{VerifiedFeed, verify_feed};
use crate::ident::{AppId, Channel};
use crate::keyset::{VerifiedKeySet, verify_key_set};
use crate::root::{TrustedRoot, advance_root};
use crate::state::{Floors, RootParts};
use crate::traits::{Hasher, Verifier};
use crate::trust::{ClockReading, RollbackFloor};

/// The most root rotations one walk takes (a bound on a hostile source's root chain).
pub const MAX_ROOT_STEPS: u64 = 1024;

/// The signed documents a check verified: the root it walked to, the key set and the feed.
#[derive(Debug, Clone)]
pub struct Documents {
    /// The root the walk ended on.
    pub root: TrustedRoot,
    /// The key set under that root.
    pub keys: VerifiedKeySet,
    /// The feed under that key set.
    pub feed: VerifiedFeed,
}

/// A root rotation walk in progress (FORMAT.md 5.2): the trusted root so far and the number of
/// rotations taken.
#[derive(Debug, Clone)]
pub struct RootWalk {
    root: TrustedRoot,
    steps: u64,
    max_steps: u64,
}

impl RootWalk {
    /// Starts a walk from `root`, which the caller trusts (compiled in, or stored and rebuilt).
    pub fn new(root: TrustedRoot) -> Self {
        RootWalk::with_max_steps(root, MAX_ROOT_STEPS)
    }

    /// Like [`RootWalk::new`] with a lower or higher cap on rotations (tests).
    pub fn with_max_steps(root: TrustedRoot, max_steps: u64) -> Self {
        RootWalk {
            root,
            steps: 0,
            max_steps,
        }
    }

    /// The trusted root so far.
    pub fn root(&self) -> &TrustedRoot {
        &self.root
    }

    /// The root version to ask the source for next, or `None` when the walk has taken as many
    /// rotations as it may.
    pub fn next_version(&self) -> Option<u64> {
        (self.steps < self.max_steps).then(|| self.root.version().saturating_add(1))
    }

    /// Takes one rotation: `bytes` is `root-<next_version>.json`. On an error the walk is
    /// unchanged. A rotation past the cap is [`Error::TooMany`].
    pub fn advance(
        &mut self,
        bytes: &[u8],
        hasher: &dyn Hasher,
        verifier: &dyn Verifier,
    ) -> Result<()> {
        if self.steps >= self.max_steps {
            return Err(Error::TooMany {
                what: "root rotations",
                count: usize::try_from(self.steps.saturating_add(1)).unwrap_or(usize::MAX),
                max: usize::try_from(self.max_steps).unwrap_or(usize::MAX),
            });
        }
        self.root = advance_root(&self.root, bytes, hasher, verifier)?;
        self.steps += 1;
        Ok(())
    }

    /// The root the walk ended on must be `app_id`'s.
    pub fn check_app_id(&self, app_id: &AppId) -> Result<()> {
        if self.root.app_id() != app_id {
            return Err(Error::AppIdMismatch);
        }
        Ok(())
    }

    /// The second stage of FORMAT.md 11.1: the app id of the final root, then the key set under
    /// it against `floors` and `clock`.
    pub fn verify_keys(
        self,
        app_id: &AppId,
        floors: &Floors,
        keys_bytes: &[u8],
        clock: &ClockReading,
        hasher: &dyn Hasher,
        verifier: &dyn Verifier,
    ) -> Result<KeysChain> {
        self.check_app_id(app_id)?;
        let floor = floors.to_rollback_floor();
        let keys = verify_key_set(&self.root, keys_bytes, &floor, clock, hasher, verifier)?;
        Ok(KeysChain {
            root: self.root,
            keys,
            floor,
        })
    }

    /// The whole of FORMAT.md 11.1 after the walk, in order: the app-id check on the final root,
    /// the key set under the root with `floors`, the feed under the key set for `app_id` and
    /// `channel` with `floors`.
    #[allow(clippy::too_many_arguments)]
    pub fn finish(
        self,
        app_id: &AppId,
        channel: &Channel,
        floors: &Floors,
        keys_bytes: &[u8],
        feed_bytes: &[u8],
        clock: &ClockReading,
        hasher: &dyn Hasher,
        verifier: &dyn Verifier,
    ) -> Result<Documents> {
        self.verify_keys(app_id, floors, keys_bytes, clock, hasher, verifier)?
            .verify_feed(app_id, channel, feed_bytes, clock, verifier)
    }
}

/// A walk whose key set verified; the feed comes next.
#[derive(Debug, Clone)]
pub struct KeysChain {
    root: TrustedRoot,
    keys: VerifiedKeySet,
    floor: RollbackFloor,
}

impl KeysChain {
    /// The verified key set.
    pub fn keys(&self) -> &VerifiedKeySet {
        &self.keys
    }

    /// The feed under the key set for `app_id` and `channel`, against the floors the key set was
    /// checked with.
    pub fn verify_feed(
        self,
        app_id: &AppId,
        channel: &Channel,
        feed_bytes: &[u8],
        clock: &ClockReading,
        verifier: &dyn Verifier,
    ) -> Result<Documents> {
        let feed = verify_feed(
            &self.keys,
            feed_bytes,
            app_id,
            channel,
            &self.floor,
            clock,
            verifier,
        )?;
        Ok(Documents {
            root: self.root,
            keys: self.keys,
            feed,
        })
    }
}

/// The key set of a first install (FORMAT.md 13.6): verified under the setup file's root with no
/// floors, there being no stored state yet.
pub fn verify_first_install_keys(
    root: &TrustedRoot,
    keys_bytes: &[u8],
    clock: &ClockReading,
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Result<VerifiedKeySet> {
    verify_key_set(
        root,
        keys_bytes,
        &RollbackFloor::default(),
        clock,
        hasher,
        verifier,
    )
}

/// The floors verified documents raise: the root's parts, the key set's version and `channel`'s
/// feed `seq`.
pub fn raised_floors(
    root: &TrustedRoot,
    keys: &VerifiedKeySet,
    feed: &VerifiedFeed,
    channel: &Channel,
) -> Floors {
    let mut raised = Floors {
        root: Some(RootParts::from_trusted(root)),
        keyset_version: keys.version(),
        ..Floors::default()
    };
    raised.feed_seq.insert(channel.clone(), feed.seq());
    raised
}
