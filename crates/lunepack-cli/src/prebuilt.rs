//! What this CLI pins (M13-D25, D31): the prebuilt binary list of its own version, kept as two
//! files compiled into the CLI (`prebuilt.json`, the table, and `prebuilt.sig.json`, its signed
//! envelope, FORMAT.md 21) and checked at every use under the project's current key set
//! ([`crate::project_key`]).
//!
//! A binary is "pinned" only when its SHA-256 and size are in a row of a list that (1) is the
//! compiled-in table, (2) is byte for byte the payload of the compiled-in envelope, (3) which
//! verifies under the current compiled-in key set, (4) has the CLI's own version, and (5) is not a
//! rehearsal list. [`pin_state`] decides this from parameters; [`compiled_in`] is its one caller
//! that passes the compiled-in key sets and files.

use lunepack_core::{BinaryKind, Hasher, PrebuiltList, PrebuiltRow, Target, verify_prebuilt};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};

use crate::cmd_pack::{MAX_RUNTIME_BYTES, MAX_SERVICE_BYTES, MAX_STUB_BYTES, MAX_UI_BYTES};
use crate::project_key::{self, PROJECT_ROOTS, ProjectKeySet};

/// The compiled-in table: the payload of the envelope, as its own file. Zero-length until a
/// release pins its binaries (M13-D3).
const PIN_TABLE: &[u8] = include_bytes!("../prebuilt.json");
/// The compiled-in envelope of the table, signed by the project key set. Zero-length with it.
const PIN_ENVELOPE: &[u8] = include_bytes!("../prebuilt.sig.json");

/// The CLI's own version, which a pinned list must have.
pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// What this CLI pins.
#[derive(Debug)]
pub enum PinState {
    /// The project has no key set: nothing can be pinned.
    NoKey,
    /// A key set, and both list files are empty: nothing is pinned.
    None,
    /// A verified release list of this CLI's version: its rows are pinned.
    Pinned(PrebuiltList),
    /// A verified list of this CLI's version marked as a rehearsal: shown, never pinned.
    Rehearsal(PrebuiltList),
    /// A verified release list of another version: shown, never pinned.
    OtherVersion(PrebuiltList),
    /// Anything else; the text says why. Nothing is pinned.
    Inconsistent(String),
}

impl PinState {
    /// The state's name, as `prebuilt list` prints it.
    pub fn name(&self) -> &'static str {
        match self {
            PinState::NoKey => "no-key",
            PinState::None => "none",
            PinState::Pinned(_) => "pinned",
            PinState::Rehearsal(_) => "rehearsal",
            PinState::OtherVersion(_) => "other-version",
            PinState::Inconsistent(_) => "inconsistent",
        }
    }

    /// The list, in the states that have one.
    pub fn list(&self) -> Option<&PrebuiltList> {
        match self {
            PinState::Pinned(l) | PinState::Rehearsal(l) | PinState::OtherVersion(l) => Some(l),
            _ => None,
        }
    }

    /// The row that pins a binary of `kind` for `target` with exactly these bytes: only in the
    /// state `pinned`, only by a row of that kind whose target is `target` exactly, and only when
    /// the size and SHA-256 match.
    pub fn pinned_row(
        &self,
        kind: BinaryKind,
        target: Target,
        bytes: &[u8],
        hasher: &dyn Hasher,
    ) -> Option<&PrebuiltRow> {
        let PinState::Pinned(list) = self else {
            return None;
        };
        let row = list.find(kind, target)?;
        (row.size() == bytes.len() as u64 && row.sha256() == hasher.sha256(bytes)).then_some(row)
    }
}

/// The largest file `pack` reads for a binary of `kind`; a row's `size` must not be above it.
pub fn kind_cap(kind: BinaryKind) -> u64 {
    match kind {
        BinaryKind::Runtime => MAX_RUNTIME_BYTES,
        BinaryKind::Ui => MAX_UI_BYTES,
        BinaryKind::Service => MAX_SERVICE_BYTES,
        BinaryKind::Stub | BinaryKind::StubConsole => MAX_STUB_BYTES,
    }
}

/// The release asset name of a binary: `lunepack-<kind>-<version>-<target>`, plus `.exe` for a
/// Windows target. Computed, never read from the table.
pub fn asset_name(kind: BinaryKind, version: &str, target: Target) -> String {
    let exe = if target.is_windows() { ".exe" } else { "" };
    format!("lunepack-{kind}-{version}-{}{exe}", target.as_str())
}

/// The state of the compiled-in key sets and list files for this CLI's version: the one caller of
/// [`pin_state`] that passes them.
pub fn compiled_in() -> PinState {
    pin_state(PROJECT_ROOTS, PIN_TABLE, PIN_ENVELOPE, CLI_VERSION)
}

/// Decides what `table` and `envelope` pin under `roots` (oldest first, the last current) for a
/// CLI of `cli_version`. See the module documentation for the five conditions of `pinned`.
pub fn pin_state(
    roots: &[ProjectKeySet<'_>],
    table: &[u8],
    envelope: &[u8],
    cli_version: &str,
) -> PinState {
    let (hasher, verifier) = (Sha256Hasher, Ed25519Verifier);
    let Some(current) = roots.last() else {
        if table.is_empty() && envelope.is_empty() {
            return PinState::NoKey;
        }
        return PinState::Inconsistent("a list is compiled in, but no project key set".into());
    };
    if let Err(e) = project_key::check_roots(roots, &hasher, &verifier) {
        return PinState::Inconsistent(format!("the project key sets are not valid: {e:#}"));
    }
    match (table.is_empty(), envelope.is_empty()) {
        (true, true) => return PinState::None,
        (false, true) => {
            return PinState::Inconsistent("the table is compiled in without its envelope".into());
        }
        (true, false) => {
            return PinState::Inconsistent("the envelope is compiled in without its table".into());
        }
        (false, false) => {}
    }
    let root = match current.trusted_root(&hasher, &verifier) {
        Ok(root) => root,
        Err(e) => return PinState::Inconsistent(format!("{e:#}")),
    };
    let verified = match verify_prebuilt(&root, envelope, &verifier) {
        Ok(v) => v,
        Err(e) => {
            // Say when an earlier (retired) set verifies it: that still pins nothing.
            let retired = roots[..roots.len() - 1].iter().rev().find(|set| {
                set.trusted_root(&hasher, &verifier)
                    .is_ok_and(|r| verify_prebuilt(&r, envelope, &verifier).is_ok())
            });
            return PinState::Inconsistent(match retired {
                Some(set) => format!(
                    "the envelope verifies only under the retired project key set {}, not the \
                     current set {}",
                    set.version, current.version
                ),
                None => format!(
                    "the envelope does not verify under the current project key set {}: {e}",
                    current.version
                ),
            });
        }
    };
    if verified.payload() != table {
        return PinState::Inconsistent("the table is not the envelope's payload".into());
    }
    let rehearsal = verified.is_rehearsal();
    let same_version = verified.version_text() == cli_version;
    let list = verified.rehearsal_list();
    if let Some(row) = list.rows().iter().find(|r| r.size() > kind_cap(r.kind())) {
        return PinState::Inconsistent(format!(
            "the {} row for {} has a size above the {} bytes pack reads",
            row.kind(),
            row.target().as_str(),
            kind_cap(row.kind())
        ));
    }
    match (rehearsal, same_version) {
        (false, true) => PinState::Pinned(list),
        (true, true) => PinState::Rehearsal(list),
        (false, false) => PinState::OtherVersion(list),
        (true, false) => PinState::Inconsistent(format!(
            "the list is a rehearsal list of version {}, not of this CLI's version {cli_version}",
            list.version_text()
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use lunepack_core::encoding::hex_encode;
    use lunepack_core::{PayloadKind, Signer, sign_envelope};
    use lunepack_crypto::{Ed25519Signer, generate_key_file};

    use super::*;

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const TARGET: &str = "linux-x86_64";

    /// Throwaway keys, made now in a temporary directory.
    struct Keys {
        _dir: tempfile::TempDir,
        signers: Vec<Ed25519Signer>,
        hex: Vec<String>,
    }

    fn keys(n: usize) -> Keys {
        let dir = tempfile::tempdir().unwrap();
        let mut signers = Vec::new();
        let mut hex = Vec::new();
        for i in 0..n {
            let k = generate_key_file(&dir.path().join(format!("k{i}"))).unwrap();
            hex.push(hex_encode(&k.public_key));
            signers.push(Ed25519Signer::from_key_file(Path::new(&k.path)).unwrap());
        }
        Keys {
            _dir: dir,
            signers,
            hex,
        }
    }

    fn row(kind: &str, target: &str, bytes: &[u8]) -> String {
        format!(
            r#"{{"kind":"{kind}","target":"{target}","size":{},"sha256":"{}"}}"#,
            bytes.len(),
            Sha256Hasher.sha256(bytes).to_hex()
        )
    }

    fn table(version: &str, rehearsal: bool, rows: &[String]) -> Vec<u8> {
        format!(
            r#"{{"format":1,"kind":"prebuilt","critical":[],"version":"{version}","source_commit":"{COMMIT}","rehearsal":{rehearsal},"binaries":[{}]}}"#,
            rows.join(",")
        )
        .into_bytes()
    }

    fn sign(payload: &[u8], by: &[&Ed25519Signer]) -> Vec<u8> {
        let signers: Vec<&dyn Signer> = by.iter().map(|s| *s as &dyn Signer).collect();
        sign_envelope(
            PayloadKind::Prebuilt,
            payload,
            &signers,
            &Sha256Hasher,
            &Ed25519Verifier,
        )
        .unwrap()
    }

    fn set<'a>(version: u64, keys: &'a [&'a str]) -> ProjectKeySet<'a> {
        ProjectKeySet {
            version,
            threshold: 1,
            keys,
        }
    }

    const RUNTIME: &[u8] = b"a runtime's bytes";

    fn release_table(version: &str, rehearsal: bool) -> Vec<u8> {
        table(version, rehearsal, &[row("runtime", TARGET, RUNTIME)])
    }

    fn reason(state: PinState) -> String {
        match state {
            PinState::Inconsistent(r) => r,
            other => panic!("expected inconsistent, got {}", other.name()),
        }
    }

    #[test]
    fn the_committed_constants_and_files_are_no_key_none_or_pinned() {
        let state = compiled_in();
        assert!(
            matches!(
                state,
                PinState::NoKey | PinState::None | PinState::Pinned(_)
            ),
            "the compiled-in state is {}",
            state.name()
        );
    }

    #[test]
    fn no_key_none_and_a_list_without_a_key() {
        assert!(matches!(pin_state(&[], b"", b"", "0.1.0"), PinState::NoKey));
        let k = keys(1);
        let one = [k.hex[0].as_str()];
        assert!(matches!(
            pin_state(&[set(1, &one)], b"", b"", "0.1.0"),
            PinState::None
        ));
        let t = release_table("0.1.0", false);
        let e = sign(&t, &[&k.signers[0]]);
        assert!(reason(pin_state(&[], &t, &e, "0.1.0")).contains("no project key set"));
        assert!(reason(pin_state(&[], &t, b"", "0.1.0")).contains("no project key set"));
    }

    #[test]
    fn pinned_rehearsal_and_other_version() {
        let k = keys(1);
        let one = [k.hex[0].as_str()];
        let roots = [set(1, &one)];

        let t = release_table("0.1.0", false);
        let e = sign(&t, &[&k.signers[0]]);
        let state = pin_state(&roots, &t, &e, "0.1.0");
        assert_eq!(state.name(), "pinned");
        let target = Target::parse(TARGET).unwrap();
        assert!(
            state
                .pinned_row(BinaryKind::Runtime, target, RUNTIME, &Sha256Hasher)
                .is_some()
        );

        let t = release_table("0.1.0", true);
        let e = sign(&t, &[&k.signers[0]]);
        let state = pin_state(&roots, &t, &e, "0.1.0");
        assert_eq!(state.name(), "rehearsal");
        assert_eq!(state.list().unwrap().rows().len(), 1);
        assert!(
            state
                .pinned_row(BinaryKind::Runtime, target, RUNTIME, &Sha256Hasher)
                .is_none()
        );

        let t = release_table("0.2.0", false);
        let e = sign(&t, &[&k.signers[0]]);
        let state = pin_state(&roots, &t, &e, "0.1.0");
        assert_eq!(state.name(), "other-version");
        assert!(
            state
                .pinned_row(BinaryKind::Runtime, target, RUNTIME, &Sha256Hasher)
                .is_none()
        );

        // A rehearsal list of another version meets neither state's conditions.
        let t = release_table("0.2.0", true);
        let e = sign(&t, &[&k.signers[0]]);
        assert!(reason(pin_state(&roots, &t, &e, "0.1.0")).contains("rehearsal list of version"));
    }

    #[test]
    fn inconsistent_one_file_missing_or_a_table_that_is_not_the_payload() {
        let k = keys(1);
        let one = [k.hex[0].as_str()];
        let roots = [set(1, &one)];
        let t = release_table("0.1.0", false);
        let e = sign(&t, &[&k.signers[0]]);
        assert!(reason(pin_state(&roots, &t, b"", "0.1.0")).contains("without its envelope"));
        assert!(reason(pin_state(&roots, b"", &e, "0.1.0")).contains("without its table"));

        // One byte different: a trailing newline, and one changed byte.
        let mut longer = t.clone();
        longer.push(b'\n');
        assert!(
            reason(pin_state(&roots, &longer, &e, "0.1.0")).contains("not the envelope's payload")
        );
        let mut changed = t.clone();
        let at = changed.iter().position(|b| *b == b'1').unwrap();
        changed[at] = b'2';
        assert!(
            reason(pin_state(&roots, &changed, &e, "0.1.0")).contains("not the envelope's payload")
        );

        // A parse error: the envelope is not an envelope.
        assert!(reason(pin_state(&roots, &t, b"{}", "0.1.0")).contains("does not verify"));
    }

    #[test]
    fn inconsistent_a_signer_outside_the_set_or_a_retired_set() {
        let k = keys(3);
        let a = [k.hex[0].as_str()];
        let b = [k.hex[1].as_str()];
        let t = release_table("0.1.0", false);

        // Signed by a key in no set.
        let e = sign(&t, &[&k.signers[2]]);
        assert!(reason(pin_state(&[set(1, &a)], &t, &e, "0.1.0")).contains("does not verify"));

        // Two sets: signed by the first (retired) one.
        let roots = [set(1, &a), set(2, &b)];
        let e = sign(&t, &[&k.signers[0]]);
        assert!(reason(pin_state(&roots, &t, &e, "0.1.0")).contains("retired project key set 1"));
        // Signed by the current one: pinned.
        let e = sign(&t, &[&k.signers[1]]);
        assert_eq!(pin_state(&roots, &t, &e, "0.1.0").name(), "pinned");
    }

    #[test]
    fn inconsistent_threshold_not_met_or_bad_key_sets() {
        let k = keys(2);
        let two = [k.hex[0].as_str(), k.hex[1].as_str()];
        let roots = [ProjectKeySet {
            version: 1,
            threshold: 2,
            keys: &two,
        }];
        let t = release_table("0.1.0", false);
        let e = sign(&t, &[&k.signers[0]]);
        assert!(reason(pin_state(&roots, &t, &e, "0.1.0")).contains("does not verify"));
        let e = sign(&t, &[&k.signers[0], &k.signers[1]]);
        assert_eq!(pin_state(&roots, &t, &e, "0.1.0").name(), "pinned");

        // A version gap in the key sets makes everything inconsistent, even with empty files.
        let one = [k.hex[0].as_str()];
        assert!(reason(pin_state(&[set(2, &one)], b"", b"", "0.1.0")).contains("not valid"));
    }

    #[test]
    fn inconsistent_a_size_above_what_pack_reads() {
        let k = keys(1);
        let one = [k.hex[0].as_str()];
        let roots = [set(1, &one)];
        let big = format!(
            r#"{{"kind":"stub","target":"windows-x86_64","size":{},"sha256":"{}"}}"#,
            MAX_STUB_BYTES + 1,
            "0".repeat(64)
        );
        let t = table("0.1.0", false, &[big]);
        let e = sign(&t, &[&k.signers[0]]);
        assert!(reason(pin_state(&roots, &t, &e, "0.1.0")).contains("above"));
        // At the cap: accepted.
        let at = format!(
            r#"{{"kind":"stub","target":"windows-x86_64","size":{},"sha256":"{}"}}"#,
            MAX_STUB_BYTES,
            "0".repeat(64)
        );
        let t = table("0.1.0", false, &[at]);
        let e = sign(&t, &[&k.signers[0]]);
        assert_eq!(pin_state(&roots, &t, &e, "0.1.0").name(), "pinned");
    }

    #[test]
    fn classification_needs_exact_bytes_kind_and_target() {
        let k = keys(1);
        let one = [k.hex[0].as_str()];
        let roots = [set(1, &one)];
        let stub = b"MZ an unstamped stub";
        let t = table(
            "0.1.0",
            false,
            &[
                row("runtime", TARGET, RUNTIME),
                row("stub", "windows-x86_64", stub),
                row("runtime", "macos-universal", RUNTIME),
            ],
        );
        let e = sign(&t, &[&k.signers[0]]);
        let state = pin_state(&roots, &t, &e, "0.1.0");
        let linux = Target::parse(TARGET).unwrap();
        let win = Target::parse("windows-x86_64").unwrap();
        let mac = Target::parse("macos-aarch64").unwrap();
        let h = &Sha256Hasher;

        assert!(
            state
                .pinned_row(BinaryKind::Runtime, linux, RUNTIME, h)
                .is_some()
        );
        // One byte different, and one byte longer.
        let mut other = RUNTIME.to_vec();
        other[0] ^= 1;
        assert!(
            state
                .pinned_row(BinaryKind::Runtime, linux, &other, h)
                .is_none()
        );
        let mut longer = RUNTIME.to_vec();
        longer.push(0);
        assert!(
            state
                .pinned_row(BinaryKind::Runtime, linux, &longer, h)
                .is_none()
        );
        // Another kind, or another target with the same bytes.
        assert!(
            state
                .pinned_row(BinaryKind::Service, linux, RUNTIME, h)
                .is_none()
        );
        assert!(
            state
                .pinned_row(BinaryKind::Runtime, win, RUNTIME, h)
                .is_none()
        );
        // No fallback from a per-architecture macOS target to macos-universal.
        assert!(
            state
                .pinned_row(BinaryKind::Runtime, mac, RUNTIME, h)
                .is_none()
        );
        // The stub is pinned as `stub`, not as `stub-console`.
        assert!(state.pinned_row(BinaryKind::Stub, win, stub, h).is_some());
        assert!(
            state
                .pinned_row(BinaryKind::StubConsole, win, stub, h)
                .is_none()
        );
    }

    #[test]
    fn asset_names_are_computed() {
        let win = Target::parse("windows-x86_64").unwrap();
        let linux = Target::parse(TARGET).unwrap();
        assert_eq!(
            asset_name(BinaryKind::StubConsole, "0.1.0", win),
            "lunepack-stub-console-0.1.0-windows-x86_64.exe"
        );
        assert_eq!(
            asset_name(BinaryKind::Runtime, "0.1.0", linux),
            "lunepack-runtime-0.1.0-linux-x86_64"
        );
    }
}
