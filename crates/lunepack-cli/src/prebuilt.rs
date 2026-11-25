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

use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use lunepack_core::{
    BinaryKind, BlockingTransport, CancelToken, FeedKind, Hasher, PrebuiltList, PrebuiltRow,
    Request, Target, verify_prebuilt,
};
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

// ---- fetch ---------------------------------------------------------------------------------------

/// The base URL of the release assets of `version` when `--base-url` is not given.
pub fn default_base_url(version: &str) -> String {
    format!("https://github.com/lune-rs/lunepack/releases/download/v{version}/")
}

/// One line that says why `fetch` does nothing in `state`, or `None` in the state `pinned`.
pub fn fetch_refusal(state: &PinState) -> Option<String> {
    let why = match state {
        PinState::Pinned(_) => return None,
        PinState::NoKey => "no project key is built in, so nothing is pinned".to_owned(),
        PinState::None => "no list is pinned yet".to_owned(),
        PinState::Rehearsal(_) => "its list is a rehearsal list".to_owned(),
        PinState::OtherVersion(_) => "its list is of another version".to_owned(),
        PinState::Inconsistent(reason) => reason.clone(),
    };
    Some(format!(
        "prebuilt fetch needs this CLI in the state pinned, it is in the state {}: {why}",
        state.name()
    ))
}

/// What `prebuilt fetch` was asked for.
pub struct FetchRequest<'a> {
    /// The target id whose rows are fetched.
    pub target: &'a str,
    /// Only these kinds (kind names); all rows of the target when empty.
    pub kinds: &'a [String],
    /// The base URL (`--base-url`), or the default of this CLI's version.
    pub base_url: Option<&'a str>,
    /// The directory the files are placed in; made only once a request is about to be sent.
    pub out: &'a Path,
}

/// What happened to one file.
#[derive(Debug, PartialEq, Eq)]
pub enum Placed {
    /// Downloaded, checked and placed.
    Fetched { asset: String, size: u64 },
    /// Already there with the pinned SHA-256: left alone.
    Present { asset: String },
}

/// How many bytes are read from the network or a file at a time.
const CHUNK: usize = 64 * 1024;

/// Downloads the pinned binaries of one target: for each row, `<base><asset name>`, at most the
/// pinned size plus one byte read, size and SHA-256 checked, and only then placed in `out`.
///
/// Rows come from `state` and nowhere else; in every state but `pinned` nothing happens: no
/// connection is opened and `out` is not made. The state is decided first, so a refused state wins
/// over a refused base URL. Nothing downloaded is run, parsed or unpacked. `transport_for` makes
/// the transport for a base URL that passed the update-feed rule.
pub fn fetch(
    state: &PinState,
    request: &FetchRequest<'_>,
    transport_for: impl FnOnce(&str, FeedKind) -> Result<Box<dyn BlockingTransport>>,
) -> Result<Vec<Placed>> {
    if let Some(refusal) = fetch_refusal(state) {
        bail!("{refusal}");
    }
    let PinState::Pinned(list) = state else {
        bail!("prebuilt fetch needs this CLI in the state pinned");
    };
    let target = Target::parse(request.target).context("--target is not a target id")?;
    let mut kinds = Vec::new();
    for text in request.kinds {
        let kind = BinaryKind::parse(text)
            .with_context(|| format!("--kind {text:?} is not a binary kind"))?;
        if !kinds.contains(&kind) {
            kinds.push(kind);
        }
    }
    let rows: Vec<&PrebuiltRow> = list
        .rows()
        .iter()
        .filter(|r| r.target() == target && (kinds.is_empty() || kinds.contains(&r.kind())))
        .collect();
    if rows.is_empty() {
        bail!(
            "the pinned list has no binary for target {}{}",
            target.as_str(),
            if kinds.is_empty() {
                ""
            } else {
                " of the kinds asked for"
            }
        );
    }
    for kind in &kinds {
        if !rows.iter().any(|r| r.kind() == *kind) {
            bail!(
                "the pinned list has no {kind} binary for target {}",
                target.as_str()
            );
        }
    }

    let mut base = request
        .base_url
        .map_or_else(|| default_base_url(list.version_text()), str::to_owned);
    if !base.ends_with('/') {
        base.push('/');
    }
    let feed_kind =
        lunepack::check_config_feed(&base).map_err(|e| anyhow!("--base-url is refused: {e}"))?;
    let transport = transport_for(&base, feed_kind)?;

    fs::create_dir_all(request.out)
        .with_context(|| format!("cannot create {}", request.out.display()))?;
    let mut placed = Vec::new();
    for row in rows {
        let asset = asset_name(row.kind(), list.version_text(), row.target());
        let dest = request.out.join(&asset);
        if present_with_pinned_hash(&dest, row)? {
            placed.push(Placed::Present { asset });
            continue;
        }
        download(
            transport.as_ref(),
            &format!("{base}{asset}"),
            &asset,
            row,
            &dest,
        )?;
        placed.push(Placed::Fetched {
            asset,
            size: row.size(),
        });
    }
    Ok(placed)
}

/// Whether `dest` is a regular file that has the row's size and SHA-256. A link or a directory
/// under the asset's name is an error, never followed.
fn present_with_pinned_hash(dest: &Path, row: &PrebuiltRow) -> Result<bool> {
    let meta = match fs::symlink_metadata(dest) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", dest.display())),
    };
    if !meta.is_file() {
        bail!("{} exists and is not a regular file", dest.display());
    }
    if meta.len() != row.size() {
        return Ok(false);
    }
    let mut state = Sha256Hasher.sha256_start();
    let mut file =
        fs::File::open(dest).with_context(|| format!("cannot read {}", dest.display()))?;
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("cannot read {}", dest.display()))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        state.update(&buf[..n]);
    }
    Ok(total == row.size() && state.finalize() == row.sha256())
}

/// A temporary file next to its destination, removed unless it was moved into place.
struct TempFile {
    path: PathBuf,
    keep: bool,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.keep {
            // Best effort: this call created the file.
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn create_temp(dest: &Path) -> Result<(TempFile, fs::File)> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = dest.parent().unwrap_or_else(|| Path::new("."));
    let name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .context("the destination has no usable file name")?;
    for _ in 0..16 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!(
            "{}{}-{n}-{name}",
            crate::place::TMP_PREFIX,
            std::process::id()
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o755);
        match options.open(&path) {
            Ok(file) => return Ok((TempFile { path, keep: false }, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("cannot create a file in {}", dir.display()));
            }
        }
    }
    bail!(
        "cannot find a free temporary name next to {}",
        dest.display()
    );
}

/// Requests `url`, reads at most `row.size() + 1` bytes into a temporary file next to `dest`,
/// checks the size and SHA-256 and only then moves the file to `dest` (mode 0755 on Unix). Any
/// failure removes the temporary file and places nothing under the asset's name.
fn download(
    transport: &dyn BlockingTransport,
    url: &str,
    asset: &str,
    row: &PrebuiltRow,
    dest: &Path,
) -> Result<()> {
    let response = transport
        .get(
            &Request {
                url: url.to_owned(),
                range: None,
                if_range: None,
            },
            &CancelToken::new(),
        )
        .with_context(|| format!("cannot fetch {asset}"))?;
    if response.head.status != 200 {
        bail!(
            "cannot fetch {asset}: the server answered {}",
            response.head.status
        );
    }
    let (temp, mut file) = create_temp(dest)?;
    let mut body = response.body.take(row.size() + 1);
    let mut state = Sha256Hasher.sha256_start();
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let n = body
            .read(&mut buf)
            .with_context(|| format!("cannot read {asset}"))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        state.update(&buf[..n]);
        file.write_all(&buf[..n])
            .with_context(|| format!("cannot write {}", temp.path.display()))?;
    }
    if total > row.size() {
        bail!(
            "{asset} is longer than pinned: expected {} bytes, got more than that (the read stopped at {total})",
            row.size()
        );
    }
    if total < row.size() {
        bail!(
            "{asset} is shorter than pinned: expected {} bytes, got {total}",
            row.size()
        );
    }
    let digest = state.finalize();
    if digest != row.sha256() {
        bail!(
            "{asset} is not the pinned file: expected sha256 {}, got {}",
            row.sha256().to_hex(),
            digest.to_hex()
        );
    }
    file.flush()
        .and_then(|()| file.sync_all())
        .with_context(|| format!("cannot write {}", temp.path.display()))?;
    drop(file);
    let mut temp = temp;
    #[cfg(unix)]
    fs::set_permissions(
        &temp.path,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .with_context(|| format!("cannot set the mode of {}", temp.path.display()))?;
    fs::rename(&temp.path, dest).with_context(|| format!("cannot place {}", dest.display()))?;
    temp.keep = true;
    Ok(())
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

    // ---- fetch -----------------------------------------------------------------------------------

    use lunepack_testkit::{FakeOrigin, LoopbackServer, TransportFault};

    const ASSET: &str = "lunepack-runtime-0.1.0-linux-x86_64";
    const SERVICE: &[u8] = b"a service's bytes, a little longer than the runtime's";
    const SERVICE_ASSET: &str = "lunepack-service-0.1.0-linux-x86_64";

    /// The state `pinned` with a runtime and a service row of the Linux target.
    fn pinned(k: &Keys) -> PinState {
        let one = [k.hex[0].as_str()];
        let t = table(
            "0.1.0",
            false,
            &[
                row("runtime", TARGET, RUNTIME),
                row("service", TARGET, SERVICE),
            ],
        );
        let e = sign(&t, &[&k.signers[0]]);
        let state = pin_state(&[set(1, &one)], &t, &e, "0.1.0");
        assert_eq!(state.name(), "pinned");
        state
    }

    fn fetch_with(state: &PinState, out: &Path, base: &str, kinds: &[&str]) -> Result<Vec<Placed>> {
        let kinds: Vec<String> = kinds.iter().map(|k| (*k).to_owned()).collect();
        fetch(
            state,
            &FetchRequest {
                target: TARGET,
                kinds: &kinds,
                base_url: Some(base),
                out,
            },
            crate::cmd_prebuilt::transport_for,
        )
    }

    fn server() -> LoopbackServer {
        LoopbackServer::start(FakeOrigin::new()).unwrap()
    }

    fn files_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn err_text<T>(r: Result<T>) -> String {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn fetch_places_the_pinned_files_over_http_and_over_file() {
        let k = keys(1);
        let state = pinned(&k);
        let dir = tempfile::tempdir().unwrap();

        // A loopback HTTP server; the base URL is given without its closing slash.
        let srv = server();
        srv.origin().put(ASSET, RUNTIME);
        srv.origin().put(SERVICE_ASSET, SERVICE);
        let out = dir.path().join("http");
        let placed = fetch_with(&state, &out, &srv.base_url(), &[]).unwrap();
        assert_eq!(
            placed,
            vec![
                Placed::Fetched {
                    asset: ASSET.to_owned(),
                    size: RUNTIME.len() as u64
                },
                Placed::Fetched {
                    asset: SERVICE_ASSET.to_owned(),
                    size: SERVICE.len() as u64
                },
            ]
        );
        assert_eq!(fs::read(out.join(ASSET)).unwrap(), RUNTIME);
        assert_eq!(fs::read(out.join(SERVICE_ASSET)).unwrap(), SERVICE);
        assert_eq!(
            files_in(&out),
            [ASSET, SERVICE_ASSET],
            "no temporary file is left"
        );
        #[cfg(unix)]
        for name in [ASSET, SERVICE_ASSET] {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(out.join(name)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755, "{name}");
        }
        // A kind filter fetches only that kind.
        let only = dir.path().join("only");
        let placed = fetch_with(&state, &only, &srv.base_url(), &["service"]).unwrap();
        assert_eq!(placed.len(), 1);
        assert_eq!(files_in(&only), [SERVICE_ASSET]);

        // A file: base: the directory of the release assets.
        let src = dir.path().join("release");
        fs::create_dir(&src).unwrap();
        fs::write(src.join(ASSET), RUNTIME).unwrap();
        fs::write(src.join(SERVICE_ASSET), SERVICE).unwrap();
        let base = url::Url::from_directory_path(&src).unwrap().to_string();
        let out = dir.path().join("file");
        fetch_with(&state, &out, &base, &["runtime"]).unwrap();
        assert_eq!(fs::read(out.join(ASSET)).unwrap(), RUNTIME);
        // A file that is not there is a 404 from the directory source.
        fs::remove_file(src.join(SERVICE_ASSET)).unwrap();
        let err = err_text(fetch_with(&state, &dir.path().join("f2"), &base, &[]));
        assert!(err.contains(SERVICE_ASSET) && err.contains("404"), "{err}");
    }

    #[test]
    fn fetch_refuses_a_body_that_is_not_the_pin_and_places_nothing() {
        let k = keys(1);
        let state = pinned(&k);
        let dir = tempfile::tempdir().unwrap();
        let srv = server();
        let out = dir.path().join("out");

        // A 404: the server has no such file.
        let err = err_text(fetch_with(&state, &out, &srv.base_url(), &["runtime"]));
        assert!(err.contains(ASSET) && err.contains("404"), "{err}");

        // Right size, wrong hash: both digests are named.
        let mut wrong = RUNTIME.to_vec();
        wrong[0] ^= 1;
        srv.origin().put(ASSET, wrong.clone());
        let err = err_text(fetch_with(&state, &out, &srv.base_url(), &["runtime"]));
        assert!(err.contains(ASSET), "{err}");
        assert!(
            err.contains(&Sha256Hasher.sha256(RUNTIME).to_hex()),
            "{err}"
        );
        assert!(err.contains(&Sha256Hasher.sha256(&wrong).to_hex()), "{err}");
        assert!(
            files_in(&out).is_empty(),
            "nothing placed, no temporary file"
        );

        // Too short.
        srv.origin().put(ASSET, &RUNTIME[..5]);
        let err = err_text(fetch_with(&state, &out, &srv.base_url(), &["runtime"]));
        assert!(err.contains(ASSET) && err.contains("shorter"), "{err}");
        assert!(
            err.contains(&format!("expected {} bytes, got 5", RUNTIME.len())),
            "{err}"
        );

        // Too long: the server offers more than the pin, and the read stops one byte past it.
        srv.origin().put(ASSET, RUNTIME);
        srv.origin().add_fault(TransportFault::ExtraBytes(1000));
        let err = err_text(fetch_with(&state, &out, &srv.base_url(), &["runtime"]));
        assert!(err.contains(ASSET) && err.contains("longer"), "{err}");
        assert!(
            err.contains(&format!("stopped at {}", RUNTIME.len() + 1)),
            "{err}"
        );
        // A body that never ends is cut at the same point instead of read for ever.
        srv.origin().set_faults(vec![TransportFault::Endless]);
        let err = err_text(fetch_with(&state, &out, &srv.base_url(), &["runtime"]));
        assert!(
            err.contains(&format!("stopped at {}", RUNTIME.len() + 1)),
            "{err}"
        );
        assert!(
            files_in(&out).is_empty(),
            "nothing placed, no temporary file"
        );
    }

    #[test]
    fn fetch_follows_a_redirect() {
        let k = keys(1);
        let state = pinned(&k);
        let dir = tempfile::tempdir().unwrap();
        let srv = server();
        srv.origin().put("moved/runtime-bytes", RUNTIME);
        srv.origin().redirect(ASSET, "moved/runtime-bytes");
        let out = dir.path().join("out");
        fetch_with(&state, &out, &srv.base_url(), &["runtime"]).unwrap();
        assert_eq!(fs::read(out.join(ASSET)).unwrap(), RUNTIME);
        assert_eq!(
            srv.origin().requests().len(),
            2,
            "the redirect was followed"
        );
    }

    #[test]
    fn fetch_keeps_a_present_file_and_replaces_a_wrong_one_only_after_the_new_one_passed() {
        let k = keys(1);
        let state = pinned(&k);
        let dir = tempfile::tempdir().unwrap();
        let srv = server();
        let out = dir.path().join("out");
        fs::create_dir(&out).unwrap();

        // Present with the pinned hash: left alone, no request.
        fs::write(out.join(ASSET), RUNTIME).unwrap();
        let placed = fetch_with(&state, &out, &srv.base_url(), &["runtime"]).unwrap();
        assert_eq!(
            placed,
            vec![Placed::Present {
                asset: ASSET.to_owned()
            }]
        );
        assert!(srv.origin().requests().is_empty());

        // Present with another hash: replaced when the new file passes ...
        fs::write(out.join(ASSET), b"an old build").unwrap();
        srv.origin().put(ASSET, RUNTIME);
        fetch_with(&state, &out, &srv.base_url(), &["runtime"]).unwrap();
        assert_eq!(fs::read(out.join(ASSET)).unwrap(), RUNTIME);

        // ... and kept when it does not.
        fs::write(out.join(ASSET), b"an old build").unwrap();
        let mut wrong = RUNTIME.to_vec();
        wrong[1] ^= 1;
        srv.origin().put(ASSET, wrong);
        fetch_with(&state, &out, &srv.base_url(), &["runtime"]).unwrap_err();
        assert_eq!(fs::read(out.join(ASSET)).unwrap(), b"an old build");
        assert_eq!(files_in(&out), [ASSET]);
    }

    #[test]
    fn fetch_refuses_a_base_url_that_is_not_a_feed_url_before_any_request() {
        let k = keys(1);
        let state = pinned(&k);
        let dir = tempfile::tempdir().unwrap();
        let srv = server();
        for base in [
            "http://example.com/",
            "ftp://example.com/",
            "https://user:secret@example.com/",
            "not a url",
            "file://remote-host/dir/",
        ] {
            let out = dir.path().join("out");
            let err = err_text(fetch_with(&state, &out, base, &[]));
            assert!(err.contains("--base-url is refused"), "{base}: {err}");
            assert!(!err.contains("secret"), "the URL is never shown: {err}");
            assert!(!out.exists(), "{base}: nothing is made");
        }
        assert!(srv.origin().requests().is_empty());
    }

    #[test]
    fn fetch_refuses_every_state_but_pinned_before_any_request() {
        let k = keys(1);
        let one = [k.hex[0].as_str()];
        let roots = [set(1, &one)];
        let sign_table = |t: &[u8]| sign(t, &[&k.signers[0]]);
        let rehearsal = release_table("0.1.0", true);
        let other = release_table("0.2.0", false);
        let plain = release_table("0.1.0", false);
        let states = vec![
            ("no-key", pin_state(&[], b"", b"", "0.1.0")),
            ("none", pin_state(&roots, b"", b"", "0.1.0")),
            (
                "rehearsal",
                pin_state(&roots, &rehearsal, &sign_table(&rehearsal), "0.1.0"),
            ),
            (
                "other-version",
                pin_state(&roots, &other, &sign_table(&other), "0.1.0"),
            ),
            ("inconsistent", pin_state(&roots, &plain, b"", "0.1.0")),
        ];
        let dir = tempfile::tempdir().unwrap();
        let srv = server();
        srv.origin().put(ASSET, RUNTIME);
        for (name, state) in &states {
            assert_eq!(state.name(), *name);
            let out = dir.path().join(format!("out-{name}"));
            let err = err_text(fetch_with(state, &out, &srv.base_url(), &[]));
            assert!(err.contains(&format!("the state {name}")), "{name}: {err}");
            if *name == "inconsistent" {
                assert!(err.contains("without its envelope"), "the reason: {err}");
            }
            assert!(!out.exists(), "{name}: --out is not made");
            // The state wins over a refused base URL.
            let err = err_text(fetch_with(state, &out, "ftp://example.com/", &[]));
            assert!(err.contains(&format!("the state {name}")), "{name}: {err}");
        }
        assert!(
            srv.origin().requests().is_empty(),
            "no request in any refused state"
        );
    }

    #[test]
    fn fetch_needs_a_row_for_the_target_and_the_kind_asked_for() {
        let k = keys(1);
        let state = pinned(&k);
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let ask = |target: &str, kinds: &[&str]| {
            let kinds: Vec<String> = kinds.iter().map(|k| (*k).to_owned()).collect();
            err_text(fetch(
                &state,
                &FetchRequest {
                    target,
                    kinds: &kinds,
                    base_url: Some("https://example.invalid/"),
                    out: &out,
                },
                |_, _| bail!("no transport is needed"),
            ))
        };
        assert!(ask("windows-x86_64", &[]).contains("no binary for target windows-x86_64"));
        assert!(ask(TARGET, &["ui"]).contains("no binary for target"));
        assert!(ask(TARGET, &["runtime", "ui"]).contains("no ui binary"));
        assert!(ask(TARGET, &["firmware"]).contains("not a binary kind"));
        assert!(ask("plan9-mips", &[]).contains("not a target id"));
        assert!(!out.exists());
    }
}
