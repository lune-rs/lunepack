//! The pending-deletes record (P-D8, P-D10): `<prefix>/lunepack-pending-deletes.json` in the
//! private store, `{"format":1,"keys":[...],"uploading":[...]}`.
//!
//! `keys` are full object keys a publish dropped from every feed and has not deleted yet (a failed
//! delete stays here and is retried by the next run). `uploading` are version folders whose
//! objects a push started to upload before any feed listed them, so an abandoned push is visible.
//! Both lists are written sorted and without repeats; a record that is not in this form is refused.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use lunepack_core::StoreKey;
use serde::{Deserialize, Serialize};

/// The record's path under the prefix.
pub const PENDING_NAME: &str = "lunepack-pending-deletes.json";
/// Largest record read.
pub const MAX_PENDING_BYTES: u64 = 4 * 1024 * 1024;
const FORMAT: u64 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    format: u64,
    keys: Vec<String>,
    uploading: Vec<String>,
}

/// A parsed pending-deletes record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pending {
    /// Objects still to delete.
    pub keys: BTreeSet<StoreKey>,
    /// Version folders being uploaded.
    pub uploading: BTreeSet<String>,
}

/// The first segment after `<prefix>/` of `key`: the version folder it lies in.
pub fn version_of<'k>(prefix: &str, key: &'k StoreKey) -> Option<&'k str> {
    key.as_str()
        .strip_prefix(prefix)?
        .strip_prefix('/')?
        .split('/')
        .next()
}

impl Pending {
    /// Parses a record read from the store; every key must be under `prefix`, every version a
    /// folder name, both lists sorted and unique. The error never echoes the record.
    pub fn parse(prefix: &str, bytes: &[u8]) -> Result<Pending> {
        let raw: Raw = serde_json::from_slice(bytes).map_err(|e| {
            anyhow!(
                "{PENDING_NAME}: line {}: not a valid pending-deletes record",
                e.line()
            )
        })?;
        if raw.format != FORMAT {
            bail!(
                "{PENDING_NAME}: format {} is not supported (expected {FORMAT})",
                raw.format
            );
        }
        let mut keys = BTreeSet::new();
        for (i, text) in raw.keys.iter().enumerate() {
            let key = StoreKey::parse(prefix, text)
                .map_err(|e| anyhow!("{PENDING_NAME}: keys[{i}]: {e}"))?;
            match version_of(prefix, &key) {
                Some(v)
                    if StoreKey::version_folder(prefix, v).is_ok()
                        && v != key_rel(prefix, &key) => {}
                _ => bail!("{PENDING_NAME}: keys[{i}] is not inside a version folder"),
            }
            keys.insert(key);
        }
        let mut uploading = BTreeSet::new();
        for (i, v) in raw.uploading.iter().enumerate() {
            StoreKey::version_folder(prefix, v)
                .map_err(|_| anyhow!("{PENDING_NAME}: uploading[{i}] is not a version folder"))?;
            uploading.insert(v.clone());
        }
        let sorted_unique = |list: &[String]| list.windows(2).all(|w| w[0] < w[1]);
        if !sorted_unique(&raw.keys) || !sorted_unique(&raw.uploading) {
            bail!("{PENDING_NAME}: the lists are not sorted and unique");
        }
        Ok(Pending { keys, uploading })
    }

    /// The record's bytes: sorted, unique, one trailing newline.
    pub fn to_bytes(&self) -> Vec<u8> {
        let raw = Raw {
            format: FORMAT,
            keys: self.keys.iter().map(|k| k.as_str().to_owned()).collect(),
            uploading: self.uploading.iter().cloned().collect(),
        };
        let mut text = serde_json::to_vec(&raw).expect("a record serializes");
        text.push(b'\n');
        text
    }
}

/// `key` without `<prefix>/`.
fn key_rel<'k>(prefix: &str, key: &'k StoreKey) -> &'k str {
    &key.as_str()[prefix.len() + 1..]
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "hello";

    fn key(rel: &str) -> StoreKey {
        StoreKey::new(P, rel).unwrap()
    }

    #[test]
    fn a_record_round_trips_sorted_and_unique() {
        let mut p = Pending::default();
        p.keys.insert(key("1.2.0/b.pack"));
        p.keys.insert(key("1.10.0/a.pack"));
        p.uploading.insert("2.0.0".into());
        let bytes = p.to_bytes();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            "{\"format\":1,\"keys\":[\"hello/1.10.0/a.pack\",\"hello/1.2.0/b.pack\"],\"uploading\":[\"2.0.0\"]}\n"
        );
        assert_eq!(Pending::parse(P, &bytes).unwrap(), p);
        assert_eq!(
            Pending::parse(P, b"{\"format\":1,\"keys\":[],\"uploading\":[]}").unwrap(),
            Pending::default()
        );
    }

    #[test]
    fn a_bad_record_is_refused_without_echoing_it() {
        for (text, why) in [
            ("{\"format\":2,\"keys\":[],\"uploading\":[]}", "format 2"),
            ("{\"format\":1,\"keys\":[]}", "not a valid"),
            (
                "{\"format\":1,\"keys\":[],\"uploading\":[],\"x\":1}",
                "not a valid",
            ),
            (
                "{\"format\":1,\"keys\":[\"other/1.0.0/a\"],\"uploading\":[]}",
                "keys[0]",
            ),
            (
                "{\"format\":1,\"keys\":[\"hello/../a\"],\"uploading\":[]}",
                "keys[0]",
            ),
            (
                "{\"format\":1,\"keys\":[\"hello/1.0.0\"],\"uploading\":[]}",
                "not inside a version folder",
            ),
            (
                "{\"format\":1,\"keys\":[\"hello/lunepack-state.json\"],\"uploading\":[]}",
                "not inside a version folder",
            ),
            (
                "{\"format\":1,\"keys\":[\"hello/_x/a\"],\"uploading\":[]}",
                "not inside a version folder",
            ),
            (
                "{\"format\":1,\"keys\":[\"hello/1/b\",\"hello/1/a\"],\"uploading\":[]}",
                "sorted",
            ),
            (
                "{\"format\":1,\"keys\":[\"hello/1/a\",\"hello/1/a\"],\"uploading\":[]}",
                "sorted",
            ),
            (
                "{\"format\":1,\"keys\":[],\"uploading\":[\"a/b\"]}",
                "uploading[0]",
            ),
            (
                "{\"format\":1,\"keys\":[],\"uploading\":[\"2\",\"1\"]}",
                "sorted",
            ),
            ("not json SECRETLIKE", "not a valid"),
        ] {
            let e = format!("{:#}", Pending::parse(P, text.as_bytes()).unwrap_err());
            assert!(e.contains(why), "{text}: {e}");
            assert!(!e.contains("SECRETLIKE"), "{e}");
        }
    }

    #[test]
    fn version_of_is_the_first_segment() {
        assert_eq!(version_of(P, &key("1.2.3/x.pack")), Some("1.2.3"));
        assert_eq!(version_of(P, &key("keys.json")), Some("keys.json"));
    }
}
