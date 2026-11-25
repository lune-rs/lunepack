//! The project's key sets (M13-D30): the public keys that sign lunepack's own prebuilt binary
//! list (FORMAT.md 21), compiled into the CLI. Public keys only; no private key belongs here.
//!
//! [`PROJECT_ROOTS`] is oldest first and the last entry is the current key set. It is empty until
//! the project's key ceremony: the maintainer makes the key and appends the first entry, as
//! `docs/RELEASING.md` describes. A rotation appends an entry and keeps the earlier ones; an
//! earlier (retired) entry never pins a binary, it only lets `prebuilt verify --root-version <n>`
//! check the list of an older release. Nothing (no flag, environment variable or file) adds to or
//! replaces these entries for `pack`, `prebuilt list` or `prebuilt fetch`.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use lunepack_core::{AppId, Hasher, TrustedRoot, Verifier};

use crate::config::hex32;

/// The app id every project key set is built under (it names no app; FORMAT.md 21 lists are not
/// app documents). It passes the core's app id rule.
pub const PREBUILT_APP_ID: &str = "lunepack-prebuilt";

/// One project key set: a version, a threshold and its Ed25519 public keys as 64 lowercase hex
/// (the form `lunepack keys gen` prints).
#[derive(Debug, Clone, Copy)]
pub struct ProjectKeySet<'a> {
    /// 1 for the first set, then 2, 3, ... without a gap.
    pub version: u64,
    /// How many of `keys` must sign a list (`1 <= threshold <= keys.len()`).
    pub threshold: u64,
    /// The public keys, 1 to 16, none twice.
    pub keys: &'a [&'a str],
}

/// The project's key sets, oldest first; the last is current. Empty: no project key has been
/// made yet (the key ceremony is the maintainer's, see `docs/RELEASING.md`).
pub const PROJECT_ROOTS: &[ProjectKeySet<'static>] = &[];

impl ProjectKeySet<'_> {
    /// The public keys as bytes; the error names the entry and key position, never the text.
    pub fn public_keys(&self) -> Result<Vec<[u8; 32]>> {
        self.keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                hex32(
                    k,
                    &format!("project key set {} key #{}", self.version, i + 1),
                )
            })
            .collect()
    }

    /// The key set as a [`TrustedRoot`] under [`PREBUILT_APP_ID`], built with
    /// [`TrustedRoot::from_parts`], so every check a root document gets applies (1 to 16 keys,
    /// `1 <= threshold <= keys`, no key twice, every key valid).
    pub fn trusted_root(
        &self,
        hasher: &dyn Hasher,
        verifier: &dyn Verifier,
    ) -> Result<TrustedRoot> {
        let app_id = AppId::parse(PREBUILT_APP_ID).context("the prebuilt app id")?;
        TrustedRoot::from_parts(
            app_id,
            self.version,
            self.threshold,
            &self.public_keys()?,
            hasher,
            verifier,
        )
        .with_context(|| format!("project key set {} is not a valid key set", self.version))
    }
}

/// Checks a list of key sets: versions are 1, 2, ... without a gap; every entry builds a
/// [`TrustedRoot`]; no public key appears in two entries. An empty list passes.
pub fn check_roots(
    roots: &[ProjectKeySet<'_>],
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for (i, set) in roots.iter().enumerate() {
        let expected = i as u64 + 1;
        if set.version != expected {
            bail!(
                "project key set #{} has version {}, expected {expected}",
                i + 1,
                set.version
            );
        }
        set.trusted_root(hasher, verifier)?;
        for key in set.public_keys()? {
            if !seen.insert(key) {
                bail!(
                    "project key set {} repeats a public key of an earlier set",
                    set.version
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lunepack_crypto::{Ed25519Verifier, Sha256Hasher, generate_key_file};

    use super::*;

    fn keys(n: usize) -> (tempfile::TempDir, Vec<String>) {
        let dir = tempfile::tempdir().unwrap();
        let keys = (0..n)
            .map(|i| {
                let k = generate_key_file(&dir.path().join(format!("k{i}"))).unwrap();
                lunepack_core::encoding::hex_encode(&k.public_key)
            })
            .collect();
        (dir, keys)
    }

    fn check(roots: &[ProjectKeySet<'_>]) -> Result<()> {
        check_roots(roots, &Sha256Hasher, &Ed25519Verifier)
    }

    #[test]
    fn the_committed_project_roots_pass() {
        check(PROJECT_ROOTS).unwrap();
    }

    #[test]
    fn check_roots_accepts_an_empty_list_and_a_good_chain() {
        check(&[]).unwrap();
        let (_dir, k) = keys(3);
        let one = [k[0].as_str()];
        let two = [k[1].as_str(), k[2].as_str()];
        check(&[
            ProjectKeySet {
                version: 1,
                threshold: 1,
                keys: &one,
            },
            ProjectKeySet {
                version: 2,
                threshold: 2,
                keys: &two,
            },
        ])
        .unwrap();
    }

    #[test]
    fn check_roots_refuses_a_version_gap_or_a_wrong_start() {
        let (_dir, k) = keys(2);
        let a = [k[0].as_str()];
        let b = [k[1].as_str()];
        let err = check(&[ProjectKeySet {
            version: 2,
            threshold: 1,
            keys: &a,
        }])
        .unwrap_err();
        assert!(format!("{err:#}").contains("expected 1"), "{err:#}");
        let err = check(&[
            ProjectKeySet {
                version: 1,
                threshold: 1,
                keys: &a,
            },
            ProjectKeySet {
                version: 3,
                threshold: 1,
                keys: &b,
            },
        ])
        .unwrap_err();
        assert!(format!("{err:#}").contains("expected 2"), "{err:#}");
    }

    #[test]
    fn check_roots_refuses_an_entry_that_is_not_a_key_set() {
        let (_dir, k) = keys(2);
        let two = [k[0].as_str(), k[1].as_str()];
        // Threshold above the key count, and zero.
        for threshold in [3, 0] {
            let err = check(&[ProjectKeySet {
                version: 1,
                threshold,
                keys: &two,
            }])
            .unwrap_err();
            assert!(
                format!("{err:#}").contains("not a valid key set"),
                "{err:#}"
            );
        }
        // No key.
        assert!(
            check(&[ProjectKeySet {
                version: 1,
                threshold: 1,
                keys: &[],
            }])
            .is_err()
        );
        // The same key twice in one set.
        let twice = [k[0].as_str(), k[0].as_str()];
        assert!(
            check(&[ProjectKeySet {
                version: 1,
                threshold: 1,
                keys: &twice,
            }])
            .is_err()
        );
        // Uppercase hex, and a small-order point (not a valid key).
        let upper = k[0].to_uppercase();
        let small = format!("01{}", "0".repeat(62));
        for bad in [upper.as_str(), small.as_str()] {
            let keys = [bad];
            assert!(
                check(&[ProjectKeySet {
                    version: 1,
                    threshold: 1,
                    keys: &keys,
                }])
                .is_err()
            );
        }
    }

    #[test]
    fn check_roots_refuses_a_key_in_two_entries() {
        let (_dir, k) = keys(2);
        let a = [k[0].as_str()];
        let ab = [k[1].as_str(), k[0].as_str()];
        let err = check(&[
            ProjectKeySet {
                version: 1,
                threshold: 1,
                keys: &a,
            },
            ProjectKeySet {
                version: 2,
                threshold: 1,
                keys: &ab,
            },
        ])
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("repeats a public key"),
            "{err:#}"
        );
    }
}
