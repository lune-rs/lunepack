//! The object store a publisher uploads to (P-D1): validated keys and the trait behind them.
//!
//! [`ObjectStore`] has three operations on whole objects: `get`, `put` and `delete`. It knows
//! nothing of feeds, packs or the layout of a publish; those are the publisher's. The core opens no
//! file and no socket (hard rule 3): a caller hands `put` a reader, and the adapters
//! (`lunepack-http`'s `S3Store` and `DirStore`) do the I/O.
//!
//! The contract, which every implementation must meet and the testkit's store suite checks:
//!
//! - `get` of a missing key is `Ok(None)`, not an error; a body over `max_len` is
//!   [`StoreError::TooLarge`] and is never returned in part;
//! - `put` overwrites; it reads exactly `len` bytes from the reader and stores nothing, and keeps
//!   what was there, when the body is not `len` bytes or its SHA-256 is not `sha256`
//!   ([`StoreError::Mismatch`]);
//! - `delete` of a missing key is `Ok(())`;
//! - an error names the key and, for HTTP, the status; it never carries a credential.
//!
//! A [`StoreKey`] is the only key an operation takes. It is built from the app's prefix and a
//! relative path, both held to one rule set (ASCII, no whitespace, backslash or control byte, no
//! empty, `.` or `..` segment, nothing absolute), so a key can neither leave the prefix nor change
//! meaning in a URL path or on a filesystem.

use std::fmt;
use std::io::{self, Read};

use crate::error::Untrusted;

/// Most bytes in a key (the S3 limit).
pub const MAX_KEY_BYTES: usize = 1024;

/// Why a key text was refused. A refusal never echoes the text, only where the fault is.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreKeyError {
    /// The part has no characters.
    #[error("store key {part} is empty")]
    Empty {
        /// `"prefix"`, `"path"` or `"key"`.
        part: &'static str,
    },
    /// The part starts with `/`.
    #[error("store key {part} starts with /")]
    Absolute {
        /// `"prefix"`, `"path"` or `"key"`.
        part: &'static str,
    },
    /// An empty segment: `a//b` or a trailing `/`.
    #[error("store key {part} has an empty segment (// or a trailing /)")]
    EmptySegment {
        /// `"prefix"`, `"path"` or `"key"`.
        part: &'static str,
    },
    /// A `.` or `..` segment.
    #[error("store key {part} has a . or .. segment")]
    DotSegment {
        /// `"prefix"`, `"path"` or `"key"`.
        part: &'static str,
    },
    /// A space or other ASCII whitespace.
    #[error("store key {part} has whitespace at byte {offset}")]
    Whitespace {
        /// `"prefix"`, `"path"` or `"key"`.
        part: &'static str,
        /// Byte offset in the part.
        offset: usize,
    },
    /// A backslash.
    #[error("store key {part} has a backslash at byte {offset}")]
    Backslash {
        /// `"prefix"`, `"path"` or `"key"`.
        part: &'static str,
        /// Byte offset in the part.
        offset: usize,
    },
    /// A control byte (below 0x20, or DEL).
    #[error("store key {part} has a control byte at byte {offset}")]
    Control {
        /// `"prefix"`, `"path"` or `"key"`.
        part: &'static str,
        /// Byte offset in the part.
        offset: usize,
    },
    /// A byte that is not ASCII.
    #[error("store key {part} has a non-ASCII byte at byte {offset}")]
    NonAscii {
        /// `"prefix"`, `"path"` or `"key"`.
        part: &'static str,
        /// Byte offset in the part.
        offset: usize,
    },
    /// The whole key is over [`MAX_KEY_BYTES`].
    #[error("store key is {len} bytes, over the {MAX_KEY_BYTES} byte cap")]
    TooLong {
        /// Length in bytes.
        len: usize,
    },
    /// A full key text that does not start with `<prefix>/` followed by a path.
    #[error("store key is not under the prefix")]
    NotUnderPrefix,
    /// A version text that is not `[0-9A-Za-z][0-9A-Za-z.+-]*`.
    #[error("version {version:?} is not a usable folder name")]
    BadVersion {
        /// The text, escaped and capped like any untrusted text.
        version: String,
    },
}

/// A validated object key: `<prefix>/<path>`, always under the app's prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StoreKey(String);

impl StoreKey {
    /// The key `<prefix>/<rel>`. Both parts are slash-separated segments of printable ASCII (no
    /// whitespace, backslash or control byte), none empty, `.` or `..`; neither starts with `/`;
    /// the whole key is at most [`MAX_KEY_BYTES`].
    pub fn new(prefix: &str, rel: &str) -> Result<StoreKey, StoreKeyError> {
        check_part("prefix", prefix)?;
        check_part("path", rel)?;
        let len = prefix.len() + 1 + rel.len();
        if len > MAX_KEY_BYTES {
            return Err(StoreKeyError::TooLong { len });
        }
        Ok(StoreKey(format!("{prefix}/{rel}")))
    }

    /// Reads a full key text back (from a pending-deletes record, say): it must be
    /// `<prefix>/<path>` with a valid prefix and path.
    pub fn parse(prefix: &str, full: &str) -> Result<StoreKey, StoreKeyError> {
        check_part("prefix", prefix)?;
        check_part("key", full)?;
        let rel = full
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix('/'))
            .ok_or(StoreKeyError::NotUnderPrefix)?;
        StoreKey::new(prefix, rel)
    }

    /// The folder of one version: `<prefix>/<version>`. `version` must match
    /// `^[0-9A-Za-z][0-9A-Za-z.+-]*$`, so it is one segment and never `.` or `..`.
    pub fn version_folder(prefix: &str, version: &str) -> Result<StoreKey, StoreKeyError> {
        if !is_version_folder(version) {
            return Err(StoreKeyError::BadVersion {
                version: Untrusted::new(version).to_string(),
            });
        }
        StoreKey::new(prefix, version)
    }

    /// The key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StoreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `^[0-9A-Za-z][0-9A-Za-z.+-]*$`.
fn is_version_folder(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))
}

fn check_part(part: &'static str, text: &str) -> Result<(), StoreKeyError> {
    if text.is_empty() {
        return Err(StoreKeyError::Empty { part });
    }
    if text.starts_with('/') {
        return Err(StoreKeyError::Absolute { part });
    }
    for (offset, byte) in text.bytes().enumerate() {
        if byte == b'\\' {
            return Err(StoreKeyError::Backslash { part, offset });
        }
        if byte.is_ascii_whitespace() {
            return Err(StoreKeyError::Whitespace { part, offset });
        }
        if byte < 0x20 || byte == 0x7f {
            return Err(StoreKeyError::Control { part, offset });
        }
        if !byte.is_ascii() {
            return Err(StoreKeyError::NonAscii { part, offset });
        }
    }
    for segment in text.split('/') {
        if segment.is_empty() {
            return Err(StoreKeyError::EmptySegment { part });
        }
        if segment == "." || segment == ".." {
            return Err(StoreKeyError::DotSegment { part });
        }
    }
    Ok(())
}

/// The HTTP method of a store operation, for an error to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreMethod {
    /// [`ObjectStore::get`].
    Get,
    /// [`ObjectStore::put`].
    Put,
    /// [`ObjectStore::delete`].
    Delete,
}

impl StoreMethod {
    /// `GET`, `PUT` or `DELETE`.
    pub const fn describe(self) -> &'static str {
        match self {
            StoreMethod::Get => "GET",
            StoreMethod::Put => "PUT",
            StoreMethod::Delete => "DELETE",
        }
    }
}

impl fmt::Display for StoreMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.describe())
    }
}

/// What kind of transport failure a [`StoreError::Transport`] is: a closed set, so no adapter's
/// error text (which may echo a URL) reaches a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StoreTransportKind {
    /// No connection could be made.
    Connect,
    /// The TLS handshake or certificate check failed.
    Tls,
    /// A connect or read timed out.
    Timeout,
    /// Anything else.
    Other,
}

impl StoreTransportKind {
    /// A fixed lowercase description.
    pub const fn describe(self) -> &'static str {
        match self {
            StoreTransportKind::Connect => "connection failed",
            StoreTransportKind::Tls => "TLS failed",
            StoreTransportKind::Timeout => "timed out",
            StoreTransportKind::Other => "transport failed",
        }
    }
}

/// An [`ObjectStore`] operation failed. The key is always there; a credential never is.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The store answered with a status that is not success (a `get` of a missing key is not one).
    #[error("store: {method} {key} answered status {status}")]
    Status {
        /// The operation.
        method: StoreMethod,
        /// The key.
        key: StoreKey,
        /// The HTTP status.
        status: u16,
    },
    /// No answer came.
    #[error("store: {method} {key}: {}", kind.describe())]
    Transport {
        /// The operation.
        method: StoreMethod,
        /// The key.
        key: StoreKey,
        /// The failure class.
        kind: StoreTransportKind,
    },
    /// The object is longer than the `max_len` the caller allowed.
    #[error("store: {key} is over the {limit} byte limit")]
    TooLarge {
        /// The key.
        key: StoreKey,
        /// The limit the caller gave.
        limit: u64,
    },
    /// Reading the body to upload, or the local store's own storage, failed.
    #[error("store: I/O on {key} failed")]
    Io {
        /// The key.
        key: StoreKey,
        /// The cause (hard rule 4).
        #[source]
        source: io::Error,
    },
    /// The body's length or SHA-256 is not the declared one; nothing was stored.
    #[error("store: the body of {key} is not the declared length or SHA-256")]
    Mismatch {
        /// The key.
        key: StoreKey,
    },
}

/// A store of whole objects under validated keys (see the module docs for the contract).
pub trait ObjectStore: Send + Sync {
    /// The object at `key`, or `None` when there is none. An object longer than `max_len` bytes is
    /// [`StoreError::TooLarge`].
    fn get(&self, key: &StoreKey, max_len: u64) -> Result<Option<Vec<u8>>, StoreError>;

    /// Stores the `len` bytes `body` yields at `key`, replacing any object there. `sha256` is the
    /// SHA-256 of those bytes and `content_type` is what a reader of the object is told. Fails with
    /// [`StoreError::Mismatch`], storing nothing, when the body is not `len` bytes or does not
    /// hash to `sha256`.
    fn put(
        &self,
        key: &StoreKey,
        body: &mut dyn Read,
        len: u64,
        sha256: [u8; 32],
        content_type: &str,
    ) -> Result<(), StoreError>;

    /// Removes the object at `key`; a key with no object is not an error.
    fn delete(&self, key: &StoreKey) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "apps/demo";

    fn refused(prefix: &str, rel: &str) -> StoreKeyError {
        StoreKey::new(prefix, rel).expect_err("refused")
    }

    #[test]
    fn builds_a_key_under_the_prefix() {
        let key = StoreKey::new(P, "1.2.3/pack.bin").unwrap();
        assert_eq!(key.as_str(), "apps/demo/1.2.3/pack.bin");
        assert_eq!(key.to_string(), "apps/demo/1.2.3/pack.bin");
        assert_eq!(StoreKey::new("a", "b").unwrap().as_str(), "a/b");
    }

    #[test]
    fn refuses_an_empty_part() {
        let e = refused("", "x");
        assert_eq!(e, StoreKeyError::Empty { part: "prefix" });
        assert_eq!(e.to_string(), "store key prefix is empty");
        let e = refused(P, "");
        assert_eq!(e, StoreKeyError::Empty { part: "path" });
        assert_eq!(e.to_string(), "store key path is empty");
    }

    #[test]
    fn refuses_a_leading_slash() {
        let e = refused(P, "/x");
        assert_eq!(e, StoreKeyError::Absolute { part: "path" });
        assert_eq!(e.to_string(), "store key path starts with /");
        let e = refused("/apps", "x");
        assert_eq!(e, StoreKeyError::Absolute { part: "prefix" });
        assert_eq!(e.to_string(), "store key prefix starts with /");
    }

    #[test]
    fn refuses_dotdot_and_dot_segments() {
        for rel in ["..", "../x", "a/../b", "a/..", "x/.."] {
            let e = refused(P, rel);
            assert_eq!(e, StoreKeyError::DotSegment { part: "path" }, "{rel}");
            assert_eq!(e.to_string(), "store key path has a . or .. segment");
        }
        for rel in [".", "./x", "a/./b", "a/."] {
            assert_eq!(
                refused(P, rel),
                StoreKeyError::DotSegment { part: "path" },
                "{rel}"
            );
        }
        assert_eq!(
            refused("apps/../x", "y"),
            StoreKeyError::DotSegment { part: "prefix" }
        );
        // A dot inside a name is fine.
        assert!(StoreKey::new(P, "a.b/..c/d..").is_ok());
    }

    #[test]
    fn refuses_empty_segments() {
        for rel in ["a//b", "a/", "a/b/"] {
            let e = refused(P, rel);
            assert_eq!(e, StoreKeyError::EmptySegment { part: "path" }, "{rel}");
            assert_eq!(
                e.to_string(),
                "store key path has an empty segment (// or a trailing /)"
            );
        }
        assert_eq!(
            refused("apps//demo", "x"),
            StoreKeyError::EmptySegment { part: "prefix" }
        );
        assert_eq!(
            refused("apps/", "x"),
            StoreKeyError::EmptySegment { part: "prefix" }
        );
    }

    #[test]
    fn refuses_whitespace() {
        for (rel, offset) in [("a b", 1), (" a", 0), ("a\t", 1), ("a\nb", 1), ("a\rb", 1)] {
            let e = refused(P, rel);
            assert_eq!(
                e,
                StoreKeyError::Whitespace {
                    part: "path",
                    offset
                },
                "{rel:?}"
            );
        }
        assert_eq!(
            refused(P, "a b").to_string(),
            "store key path has whitespace at byte 1"
        );
        assert_eq!(
            refused("my apps", "x"),
            StoreKeyError::Whitespace {
                part: "prefix",
                offset: 2
            }
        );
    }

    #[test]
    fn refuses_a_backslash() {
        let e = refused(P, "a\\b");
        assert_eq!(
            e,
            StoreKeyError::Backslash {
                part: "path",
                offset: 1
            }
        );
        assert_eq!(e.to_string(), "store key path has a backslash at byte 1");
    }

    #[test]
    fn refuses_control_bytes() {
        for (rel, offset) in [("a\0b", 1), ("a\x01", 1), ("a\x7f", 1), ("\x1b[0m", 0)] {
            let e = refused(P, rel);
            assert_eq!(
                e,
                StoreKeyError::Control {
                    part: "path",
                    offset
                },
                "{rel:?}"
            );
        }
        assert_eq!(
            refused(P, "a\0b").to_string(),
            "store key path has a control byte at byte 1"
        );
    }

    #[test]
    fn refuses_non_ascii() {
        for (rel, offset) in [("caf\u{e9}", 3), ("a\u{a0}b", 1), ("\u{202e}x", 0)] {
            let e = refused(P, rel);
            assert_eq!(
                e,
                StoreKeyError::NonAscii {
                    part: "path",
                    offset
                },
                "{rel:?}"
            );
        }
        assert_eq!(
            refused(P, "\u{e9}").to_string(),
            "store key path has a non-ASCII byte at byte 0"
        );
    }

    #[test]
    fn refuses_a_key_over_the_cap() {
        let long = "x".repeat(MAX_KEY_BYTES);
        let e = refused("p", &long);
        assert_eq!(
            e,
            StoreKeyError::TooLong {
                len: 1 + 1 + MAX_KEY_BYTES
            }
        );
        assert_eq!(
            e.to_string(),
            "store key is 1026 bytes, over the 1024 byte cap"
        );
        // Exactly at the cap is fine.
        let fits = "x".repeat(MAX_KEY_BYTES - 2);
        assert!(StoreKey::new("p", &fits).is_ok());
    }

    #[test]
    fn parse_reads_back_a_full_key() {
        let key = StoreKey::new(P, "1.0.0/m.json").unwrap();
        assert_eq!(StoreKey::parse(P, key.as_str()).unwrap(), key);
    }

    #[test]
    fn parse_refuses_a_key_not_under_the_prefix() {
        for full in [
            "other/x",
            "apps/demo",
            "apps/demo/",
            "apps/demox/y",
            "apps/dem/x",
            "x/apps/demo/y",
        ] {
            let e = StoreKey::parse(P, full).expect_err(full);
            assert!(
                matches!(
                    e,
                    StoreKeyError::NotUnderPrefix | StoreKeyError::EmptySegment { .. }
                ),
                "{full}: {e}"
            );
        }
        let e = StoreKey::parse(P, "other/x").unwrap_err();
        assert_eq!(e, StoreKeyError::NotUnderPrefix);
        assert_eq!(e.to_string(), "store key is not under the prefix");
        // A prefix match is by segment, not by characters.
        assert_eq!(
            StoreKey::parse(P, "apps/demox/y").unwrap_err(),
            StoreKeyError::NotUnderPrefix
        );
    }

    #[test]
    fn parse_refuses_what_new_refuses() {
        assert_eq!(
            StoreKey::parse(P, "apps/demo/../x").unwrap_err(),
            StoreKeyError::DotSegment { part: "key" }
        );
        assert_eq!(
            StoreKey::parse(P, "apps/demo/a b").unwrap_err(),
            StoreKeyError::Whitespace {
                part: "key",
                offset: 11
            }
        );
        assert_eq!(
            StoreKey::parse(P, "").unwrap_err(),
            StoreKeyError::Empty { part: "key" }
        );
        assert_eq!(
            StoreKey::parse(P, "/apps/demo/x").unwrap_err(),
            StoreKeyError::Absolute { part: "key" }
        );
    }

    #[test]
    fn version_folder_accepts_the_version_forms() {
        for version in ["1.2.3", "0", "1.0.0-rc.1", "1.0.0+build.5", "2025.11", "v1"] {
            let key = StoreKey::version_folder(P, version).expect(version);
            assert_eq!(key.as_str(), format!("{P}/{version}"));
        }
    }

    #[test]
    fn version_folder_refuses_a_bad_version() {
        for version in [
            "",
            ".",
            "..",
            "-1",
            ".1",
            "+1",
            "1/2",
            "1\\2",
            "1 2",
            "1\n",
            "a/..",
            "caf\u{e9}",
            "1.0/..",
        ] {
            let e = StoreKey::version_folder(P, version).expect_err(version);
            assert!(
                matches!(e, StoreKeyError::BadVersion { .. }),
                "{version:?}: {e}"
            );
        }
        let e = StoreKey::version_folder(P, "1/2").unwrap_err();
        assert_eq!(e.to_string(), "version \"1/2\" is not a usable folder name");
        // The shown text is escaped.
        let e = StoreKey::version_folder(P, "1\n2").unwrap_err();
        assert_eq!(
            e.to_string(),
            "version \"1\\\\n2\" is not a usable folder name"
        );
    }

    #[test]
    fn version_folder_still_checks_the_prefix() {
        assert_eq!(
            StoreKey::version_folder("", "1.0").unwrap_err(),
            StoreKeyError::Empty { part: "prefix" }
        );
    }

    #[test]
    fn store_error_messages_name_the_key_and_status() {
        let key = StoreKey::new(P, "keys.json").unwrap();
        let e = StoreError::Status {
            method: StoreMethod::Put,
            key: key.clone(),
            status: 403,
        };
        assert_eq!(
            e.to_string(),
            "store: PUT apps/demo/keys.json answered status 403"
        );
        let e = StoreError::Transport {
            method: StoreMethod::Get,
            key: key.clone(),
            kind: StoreTransportKind::Timeout,
        };
        assert_eq!(e.to_string(), "store: GET apps/demo/keys.json: timed out");
        let e = StoreError::TooLarge {
            key: key.clone(),
            limit: 9,
        };
        assert_eq!(
            e.to_string(),
            "store: apps/demo/keys.json is over the 9 byte limit"
        );
        let e = StoreError::Mismatch { key: key.clone() };
        assert!(e.to_string().contains("apps/demo/keys.json"));
        let e = StoreError::Io {
            key,
            source: io::Error::other("disk"),
        };
        assert_eq!(e.to_string(), "store: I/O on apps/demo/keys.json failed");
        assert!(std::error::Error::source(&e).is_some());
    }
}
