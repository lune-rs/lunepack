//! The prebuilt binary list, `prebuilt-<version>.sig.json` (FORMAT.md 21): lunepack's own signed
//! list of the binaries a release of lunepack ships (runtime, UI, service, stubs), with their sizes
//! and SHA-256. No app reader opens this kind; lunepack's CLI does.
//!
//! [`verify_prebuilt`] opens the envelope in the order of FORMAT.md 2.6 under a key set the caller
//! already holds (a [`TrustedRoot`] built with [`TrustedRoot::from_parts`]) and only then parses
//! the payload. There is no clock, validity period or floor. The rows of a verified list are
//! reachable only through [`VerifiedPrebuilt::release_list`], which refuses a rehearsal list, or
//! [`VerifiedPrebuilt::rehearsal_list`], whose name a caller that accepts one has to write.
//! [`PrebuiltList::from_payload`] applies the same payload rules to a bare payload.

use std::fmt;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::digest::{Sha256Digest, U53};
use crate::envelope::{OpenedEnvelope, PayloadKind};
use crate::error::{Error, PrebuiltRule, Result};
use crate::limits::Limits;
use crate::root::TrustedRoot;
use crate::target::Target;
use crate::traits::Verifier;
use crate::trust::parse_payload;
use crate::version::Version;

/// Length of a `source_commit`: a git commit id, 40 lowercase hex characters.
const COMMIT_HEX_LEN: usize = 40;

/// The kind of one prebuilt binary (FORMAT.md 21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BinaryKind {
    /// `runtime`
    Runtime,
    /// `ui`
    Ui,
    /// `service`
    Service,
    /// `stub`
    Stub,
    /// `stub-console`
    StubConsole,
}

impl BinaryKind {
    /// Every kind, in FORMAT.md order.
    pub const ALL: [BinaryKind; 5] = [
        BinaryKind::Runtime,
        BinaryKind::Ui,
        BinaryKind::Service,
        BinaryKind::Stub,
        BinaryKind::StubConsole,
    ];

    /// The kind's text.
    pub const fn as_str(self) -> &'static str {
        match self {
            BinaryKind::Runtime => "runtime",
            BinaryKind::Ui => "ui",
            BinaryKind::Service => "service",
            BinaryKind::Stub => "stub",
            BinaryKind::StubConsole => "stub-console",
        }
    }

    /// Parses an exact kind text; anything else (another case included) is `None`.
    pub fn parse(text: &str) -> Option<BinaryKind> {
        BinaryKind::ALL.into_iter().find(|k| k.as_str() == text)
    }
}

impl fmt::Display for BinaryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One row of a prebuilt list: a binary of one kind for one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrebuiltRow {
    kind: BinaryKind,
    target: Target,
    size: u64,
    sha256: Sha256Digest,
}

impl PrebuiltRow {
    /// The binary's kind.
    pub fn kind(&self) -> BinaryKind {
        self.kind
    }

    /// The target it was built for.
    pub fn target(&self) -> Target {
        self.target
    }

    /// Its size in bytes, at least 1.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Its SHA-256.
    pub fn sha256(&self) -> Sha256Digest {
        self.sha256
    }
}

/// A prebuilt list whose payload passed every rule of FORMAT.md 21. Obtained from a verified
/// envelope ([`VerifiedPrebuilt`]) or from a bare payload ([`PrebuiltList::from_payload`]), which
/// checks no signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrebuiltList {
    version: Version,
    version_text: String,
    source_commit: String,
    rehearsal: bool,
    rows: Vec<PrebuiltRow>,
}

impl PrebuiltList {
    /// Applies the payload rules of FORMAT.md 21 to a bare payload (a list kept as a file), with
    /// the same code [`verify_prebuilt`] runs after authentication: the size cap, strict JSON,
    /// `format`, `kind` and `critical`, then the list's fields. It checks no signature.
    pub fn from_payload(payload: &[u8]) -> Result<PrebuiltList> {
        let cap = Limits::V1.prebuilt_doc_bytes;
        let size = payload.len() as u64;
        if size > cap {
            return Err(Error::TooLarge {
                what: PayloadKind::Prebuilt.name(),
                size,
                cap,
            });
        }
        parse_list(payload)
    }

    /// The version, compared by precedence.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// The version exactly as written.
    pub fn version_text(&self) -> &str {
        &self.version_text
    }

    /// The commit the binaries were built from: 40 lowercase hex characters.
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }

    /// Whether the list is a rehearsal list, which never makes a reader accept a binary.
    pub fn is_rehearsal(&self) -> bool {
        self.rehearsal
    }

    /// The rows in document order; no two share a kind and a target.
    pub fn rows(&self) -> &[PrebuiltRow] {
        &self.rows
    }

    /// The row of `kind` for `target`, if the list has one.
    pub fn find(&self, kind: BinaryKind, target: Target) -> Option<&PrebuiltRow> {
        self.rows
            .iter()
            .find(|r| r.kind == kind && r.target == target)
    }
}

/// A prebuilt list whose envelope met the key set's threshold and whose payload passed the rules
/// of FORMAT.md 21; [`verify_prebuilt`] is its only constructor. Its rows are reachable only by
/// consuming it, through [`VerifiedPrebuilt::release_list`] or [`VerifiedPrebuilt::rehearsal_list`].
pub struct VerifiedPrebuilt {
    payload: Vec<u8>,
    list: PrebuiltList,
}

impl fmt::Debug for VerifiedPrebuilt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedPrebuilt")
            .field("version", &self.list.version_text)
            .field("source_commit", &self.list.source_commit)
            .field("rehearsal", &self.list.rehearsal)
            .field("rows", &self.list.rows.len())
            .finish()
    }
}

impl VerifiedPrebuilt {
    /// The exact payload bytes the signatures cover. A reader that also holds the list as a
    /// separate file compares that file with these bytes and uses it only when they are equal.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The version, compared by precedence.
    pub fn version(&self) -> &Version {
        &self.list.version
    }

    /// The version exactly as written.
    pub fn version_text(&self) -> &str {
        &self.list.version_text
    }

    /// The commit the binaries were built from.
    pub fn source_commit(&self) -> &str {
        &self.list.source_commit
    }

    /// Whether the list is a rehearsal list.
    pub fn is_rehearsal(&self) -> bool {
        self.list.rehearsal
    }

    /// The list as a release list: refused with [`Error::RehearsalList`] when it is a rehearsal
    /// list, which never makes a reader accept a binary.
    pub fn release_list(self) -> Result<PrebuiltList> {
        if self.list.rehearsal {
            return Err(Error::RehearsalList);
        }
        Ok(self.list)
    }

    /// The list whether or not it is a rehearsal list. Only a caller that reports or checks a
    /// rehearsal list calls this; one that accepts binaries calls
    /// [`VerifiedPrebuilt::release_list`].
    pub fn rehearsal_list(self) -> PrebuiltList {
        self.list
    }
}

/// Verifies `prebuilt-<version>.sig.json` (FORMAT.md 21) under `root`, a key set the caller
/// already holds. Order: the envelope opens as kind `prebuilt` within its cap and meets the key
/// set's threshold (FORMAT.md 2.6); only then is the payload parsed (format, kind, critical, then
/// the list's fields). No clock is read and the signature has no validity period.
pub fn verify_prebuilt(
    root: &TrustedRoot,
    document: &[u8],
    verifier: &dyn Verifier,
) -> Result<VerifiedPrebuilt> {
    let envelope = OpenedEnvelope::open(document, PayloadKind::Prebuilt, &Limits::V1)?;
    let payload = envelope.authenticate(root.keys(), root.threshold(), verifier)?;
    let list = parse_list(payload)?;
    Ok(VerifiedPrebuilt {
        payload: payload.to_vec(),
        list,
    })
}

/// The payload rules shared by [`verify_prebuilt`] and [`PrebuiltList::from_payload`]. Unknown
/// members are ignored at the top level and in rows (FORMAT.md 3.2); duplicate members are refused
/// by the strict pre-pass of `parse_payload`.
fn parse_list(payload: &[u8]) -> Result<PrebuiltList> {
    let doc: Map<String, Value> = parse_payload(payload, PayloadKind::Prebuilt)?;

    let Some(Value::String(version_text)) = doc.get("version") else {
        return Err(Error::Prebuilt(PrebuiltRule::Version));
    };
    let version = Version::parse(version_text)?;

    let source_commit = match doc.get("source_commit") {
        Some(Value::String(c))
            if c.len() == COMMIT_HEX_LEN
                && c.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            c.clone()
        }
        _ => return Err(Error::Prebuilt(PrebuiltRule::SourceCommit)),
    };

    let Some(&Value::Bool(rehearsal)) = doc.get("rehearsal") else {
        return Err(Error::Prebuilt(PrebuiltRule::Rehearsal));
    };

    let Some(Value::Array(binaries)) = doc.get("binaries") else {
        return Err(Error::Prebuilt(PrebuiltRule::Binaries));
    };
    if binaries.is_empty() {
        return Err(Error::Prebuilt(PrebuiltRule::Binaries));
    }
    let max = Limits::V1.prebuilt_rows;
    if binaries.len() > max {
        return Err(Error::TooMany {
            what: "prebuilt rows",
            count: binaries.len(),
            max,
        });
    }

    let mut rows: Vec<PrebuiltRow> = Vec::with_capacity(binaries.len());
    for value in binaries {
        let row = parse_row(value)?;
        if rows
            .iter()
            .any(|r| r.kind == row.kind && r.target == row.target)
        {
            return Err(Error::Prebuilt(PrebuiltRule::DuplicateRow));
        }
        rows.push(row);
    }

    Ok(PrebuiltList {
        version,
        version_text: version_text.clone(),
        source_commit,
        rehearsal,
        rows,
    })
}

fn parse_row(value: &Value) -> Result<PrebuiltRow> {
    let Value::Object(row) = value else {
        return Err(Error::Prebuilt(PrebuiltRule::Row));
    };
    let kind = match row.get("kind") {
        Some(Value::String(k)) => BinaryKind::parse(k),
        _ => None,
    }
    .ok_or(Error::Prebuilt(PrebuiltRule::Kind))?;
    let Some(Value::String(target)) = row.get("target") else {
        return Err(Error::Prebuilt(PrebuiltRule::Target));
    };
    let target = Target::parse(target)?;
    // The integer rule of every v1 number (FORMAT.md 3.1): no sign, fraction or exponent form.
    let size = row
        .get("size")
        .and_then(|v| U53::deserialize(v).ok())
        .map(U53::get)
        .filter(|&s| s >= 1)
        .ok_or(Error::Prebuilt(PrebuiltRule::Size))?;
    let sha256 = match row.get("sha256") {
        Some(Value::String(h)) => Sha256Digest::from_hex(h).ok(),
        _ => None,
    }
    .ok_or(Error::Prebuilt(PrebuiltRule::Sha256))?;
    Ok(PrebuiltRow {
        kind,
        target,
        size,
        sha256,
    })
}
