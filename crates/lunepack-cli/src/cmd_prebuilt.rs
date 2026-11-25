//! `prebuilt` (M13): lunepack's own prebuilt binaries. `prebuilt list` shows the project's key sets
//! compiled into this CLI and what it pins ([`crate::prebuilt`]); `check`, `sign` and `verify` are
//! the commands the release needs around the project key (M13-D27, D35).
//!
//! The key set a `sign` or `verify` runs under is the current built-in one unless the caller names
//! another on the command line: `--root-version` (an earlier built-in set, `verify` only) or
//! `--trusted-key` (keys the caller gives). Those flags are never read from the environment or a
//! config, and the result says which set was used ([`choose_keys`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use lunepack_core::encoding::hex_encode;
use lunepack_core::{
    BinaryKind, BlockingTransport, FeedKind, Hasher, Limits, PayloadKind, PrebuiltList,
    PrebuiltRow, Signer, Target, TrustedRoot, sign_envelope, verify_prebuilt,
};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};
use lunepack_http::{DirSource, UreqOptions, UreqTransport};
use serde_json::{Value, json};

use crate::config::resolve_signer;
use crate::place;
use crate::prebuilt::{self, CLI_VERSION, PinState, asset_name, kind_cap};
use crate::project_key::{self, PROJECT_ROOTS, ProjectKeySet};

/// Arguments of `prebuilt list`.
#[derive(Args)]
pub struct ListArgs {
    /// Show only the rows of this target id, such as `linux-x86_64`.
    #[arg(long)]
    target: Option<String>,
    /// Print one JSON object with `state`, `reason`, `roots`, `list` and `binaries`.
    #[arg(long)]
    json: bool,
}

/// `prebuilt list`: exits non-zero, with the reason, in the state `inconsistent`.
pub fn list(args: &ListArgs) -> Result<()> {
    let target = args
        .target
        .as_deref()
        .map(Target::parse)
        .transpose()
        .context("--target is not a target id")?;
    let state = prebuilt::compiled_in();
    let report = report(PROJECT_ROOTS, &state, target);
    let mut out = io::stdout().lock();
    if args.json {
        writeln!(out, "{report}").context("cannot write to stdout")?;
    } else {
        for line in text(&report) {
            writeln!(out, "{line}").context("cannot write to stdout")?;
        }
    }
    drop(out);
    if let PinState::Inconsistent(reason) = &state {
        bail!("this CLI's pinned binary list is inconsistent: {reason}");
    }
    Ok(())
}

/// The report as one JSON value; the text form is made from it.
fn report(roots: &[ProjectKeySet<'_>], state: &PinState, target: Option<Target>) -> Value {
    let roots: Vec<Value> = roots
        .iter()
        .enumerate()
        .map(|(i, set)| {
            let keys: Vec<Value> = set
                .keys
                .iter()
                .map(|k| {
                    let id = crate::config::hex32(k, "key")
                        .ok()
                        .map(|public| Sha256Hasher.sha256(&public).to_hex());
                    json!({ "public": k, "id": id })
                })
                .collect();
            json!({
                "version": set.version,
                "threshold": set.threshold,
                "current": i + 1 == roots.len(),
                "keys": keys,
            })
        })
        .collect();
    let list = state.list();
    let binaries: Vec<Value> = list
        .map(|l| {
            l.rows()
                .iter()
                .filter(|r| target.is_none_or(|t| r.target() == t))
                .map(|r| row(r, l.version_text()))
                .collect()
        })
        .unwrap_or_default();
    let reason = match state {
        PinState::Inconsistent(r) => Some(r.as_str()),
        _ => None,
    };
    json!({
        "state": state.name(),
        "reason": reason,
        "roots": roots,
        "list": list.map(|l| json!({
            "version": l.version_text(),
            "source_commit": l.source_commit(),
            "rehearsal": l.is_rehearsal(),
        })),
        "binaries": binaries,
    })
}

fn row(r: &PrebuiltRow, version: &str) -> Value {
    json!({
        "kind": r.kind().as_str(),
        "target": r.target().as_str(),
        "size": r.size(),
        "sha256": r.sha256().to_hex(),
        "asset": asset_name(r.kind(), version, r.target()),
    })
}

fn text(report: &Value) -> Vec<String> {
    let s = |v: &Value| v.as_str().unwrap_or_default().to_owned();
    let mut lines = vec![format!("state: {}", s(&report["state"]))];
    if let Some(reason) = report["reason"].as_str() {
        lines.push(format!("reason: {reason}"));
    }
    let roots = report["roots"].as_array().cloned().unwrap_or_default();
    if roots.is_empty() {
        lines.push("key sets: none (no project key has been published)".to_owned());
    }
    for root in &roots {
        let role = if root["current"].as_bool() == Some(true) {
            "current"
        } else {
            "retired"
        };
        lines.push(format!(
            "key set {}: threshold {}, {role}",
            root["version"], root["threshold"]
        ));
        for key in root["keys"].as_array().into_iter().flatten() {
            lines.push(format!(
                "  key: {} id {}",
                s(&key["public"]),
                key["id"].as_str().unwrap_or("(not a valid key)")
            ));
        }
    }
    let list = &report["list"];
    if !list.is_null() {
        lines.push(format!(
            "list: version {}, source commit {}, rehearsal {}",
            s(&list["version"]),
            s(&list["source_commit"]),
            list["rehearsal"]
        ));
    }
    for b in report["binaries"].as_array().into_iter().flatten() {
        lines.push(format!(
            "binary: {} {} size {} sha256 {} asset {}",
            s(&b["kind"]),
            s(&b["target"]),
            b["size"],
            s(&b["sha256"]),
            s(&b["asset"])
        ));
    }
    lines
}

// ---- fetch ---------------------------------------------------------------------------------------

/// Arguments of `prebuilt fetch`.
#[derive(Args)]
pub struct FetchArgs {
    /// The target id whose pinned binaries are downloaded, such as `linux-x86_64`.
    #[arg(long)]
    target: String,
    /// The directory to place the files in (made when a download starts).
    #[arg(long)]
    out: PathBuf,
    /// Only this kind (`runtime`, `ui`, `service`, `stub` or `stub-console`); repeat for several.
    #[arg(long = "kind")]
    kinds: Vec<String>,
    /// Where the release assets are, ending in `/`: `https:`, `file:///` or `http:` to a loopback
    /// address, the rule of an update feed. Default: this version's GitHub release.
    #[arg(long = "base-url")]
    base_url: Option<String>,
}

/// The transport adapters for a base URL that passed the update-feed rule: the directory source
/// for `file:`, ureq for `https:` and for `http:` to a loopback address (with no proxy, as the
/// facade does for an update feed). The one place `prebuilt fetch` reaches an adapter.
pub(crate) fn transport_for(base: &str, kind: FeedKind) -> Result<Box<dyn BlockingTransport>> {
    Ok(match kind {
        FeedKind::File => {
            let url = url::Url::parse(base).context("--base-url is not a URL")?;
            let root = url
                .to_file_path()
                .map_err(|()| anyhow!("--base-url has no local path"))?;
            Box::new(DirSource::new(root))
        }
        FeedKind::Https => Box::new(UreqTransport::new()),
        FeedKind::HttpLoopback => Box::new(UreqTransport::with_options(&UreqOptions {
            direct: true,
            ..UreqOptions::default()
        })),
    })
}

/// `prebuilt fetch`: downloads this CLI's pinned binaries of one target, checks each one's size and
/// SHA-256 against the pinned row and places it. Needs the state `pinned`; makes no request in any
/// other state. `pack` never does this itself (M13-D4).
pub fn fetch(args: &FetchArgs) -> Result<()> {
    let state = prebuilt::compiled_in();
    let placed = prebuilt::fetch(
        &state,
        &prebuilt::FetchRequest {
            target: &args.target,
            kinds: &args.kinds,
            base_url: args.base_url.as_deref(),
            out: &args.out,
        },
        transport_for,
    )?;
    let mut fetched = 0;
    for p in &placed {
        match p {
            prebuilt::Placed::Fetched { asset, size } => {
                fetched += 1;
                say(&format!("fetched: {asset} ({size} bytes)"))?;
            }
            prebuilt::Placed::Present { asset } => say(&format!("present: {asset}"))?,
        }
    }
    say(&format!(
        "{} file(s) in {}: {fetched} fetched, {} already present",
        placed.len(),
        args.out.display(),
        placed.len() - fetched
    ))
}

// ---- check, sign, verify ---------------------------------------------------------------------------

/// Reads one list or envelope file: a regular file, at most one byte over the format's cap (the
/// core refuses an oversized document with its own error, so the size rule is stated once).
fn read_doc(path: &Path, flag: &str) -> Result<Vec<u8>> {
    // Classified before opening: a FIFO blocks on open.
    let meta = fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    if !meta.is_file() {
        bail!("{flag} {} is not a regular file", path.display());
    }
    let cap = Limits::V1.prebuilt_doc_bytes;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|f| f.take(cap + 1).read_to_end(&mut bytes))
        .with_context(|| format!("cannot read {}", path.display()))?;
    Ok(bytes)
}

fn binaries_json(list: &PrebuiltList) -> Vec<Value> {
    list.rows()
        .iter()
        .map(|r| row(r, list.version_text()))
        .collect()
}

fn say(line: &str) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{line}").context("cannot write to stdout")
}

fn binary_line(b: &Value) -> String {
    let s = |v: &Value| v.as_str().unwrap_or_default().to_owned();
    format!(
        "binary: {} {} size {} sha256 {} asset {}",
        s(&b["kind"]),
        s(&b["target"]),
        b["size"],
        s(&b["sha256"]),
        s(&b["asset"])
    )
}

/// Where the key set of a check came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// A built-in set of this CLI; `current` is whether it is the last one.
    BuiltIn { version: u64, current: bool },
    /// Keys the caller gave with `--trusted-key`.
    CommandLine,
}

/// The key set a check runs under, and how it was chosen.
struct Chosen {
    root: TrustedRoot,
    source: Source,
}

impl Chosen {
    /// The key set's keys as `(public key, key id)` hex.
    fn keys(&self) -> Vec<(String, String)> {
        self.root
            .keys()
            .keys()
            .iter()
            .map(|k| (hex_encode(k.public().as_bytes()), k.id().to_hex()))
            .collect()
    }

    fn key_ids(&self) -> String {
        let ids: Vec<String> = self.keys().into_iter().map(|(_, id)| id).collect();
        ids.join(", ")
    }

    /// The sentence that says which key set a result holds under; it is printed with every result.
    fn label(&self) -> String {
        match self.source {
            Source::BuiltIn {
                version,
                current: true,
            } => format!("verified under built-in key set {version}, the current one"),
            Source::BuiltIn {
                version,
                current: false,
            } => format!("verified under built-in key set {version}, which is retired"),
            Source::CommandLine => {
                "verified under a key given on the command line, not a built-in one".to_owned()
            }
        }
    }

    fn json(&self) -> Value {
        let (source, version, current, retired) = match self.source {
            Source::BuiltIn { version, current } => {
                ("built-in", json!(version), json!(current), !current)
            }
            Source::CommandLine => ("command-line", Value::Null, Value::Null, false),
        };
        let keys: Vec<Value> = self
            .keys()
            .into_iter()
            .map(|(public, id)| json!({ "public": public, "id": id }))
            .collect();
        json!({
            "source": source,
            "version": version,
            "current": current,
            "retired": retired,
            "threshold": self.root.threshold(),
            "keys": keys,
            "label": self.label(),
        })
    }

    fn text(&self) -> Vec<String> {
        let mut lines = vec![
            self.label(),
            format!(
                "key set: threshold {} of {}",
                self.root.threshold(),
                self.keys().len()
            ),
        ];
        for (public, id) in self.keys() {
            lines.push(format!("  key: {public} id {id}"));
        }
        lines
    }
}

/// How the caller named a key set on the command line.
struct Selection<'a> {
    root_version: Option<u64>,
    trusted_keys: &'a [String],
    threshold: Option<u64>,
}

/// Chooses the key set a `sign` or `verify` runs under: the current built-in one of `roots`, an
/// earlier built-in one (`root_version`), or the keys the caller gives (`trusted_keys`, with a
/// `threshold` when there is more than one). Either way the set is built by
/// [`ProjectKeySet::trusted_root`], so the rules of a built-in set apply to a given one.
fn choose_keys(roots: &[ProjectKeySet<'_>], sel: &Selection<'_>) -> Result<Chosen> {
    let (hasher, verifier) = (Sha256Hasher, Ed25519Verifier);
    if sel.trusted_keys.is_empty() {
        if sel.threshold.is_some() {
            bail!("--threshold is only for --trusted-key");
        }
        let Some(current) = roots.last() else {
            bail!("this CLI has no project key built in; name the keys with --trusted-key");
        };
        project_key::check_roots(roots, &hasher, &verifier)
            .context("the built-in project key sets are not valid")?;
        let set = match sel.root_version {
            None => current,
            Some(n) => roots
                .iter()
                .find(|s| s.version == n)
                .ok_or_else(|| anyhow!("this CLI has no built-in project key set {n}"))?,
        };
        let root = set.trusted_root(&hasher, &verifier)?;
        return Ok(Chosen {
            root,
            source: Source::BuiltIn {
                version: set.version,
                current: set.version == current.version,
            },
        });
    }
    if sel.root_version.is_some() {
        bail!("--trusted-key and --root-version cannot be used together");
    }
    if sel.trusted_keys.len() > 16 {
        bail!("at most 16 --trusted-key values can be given");
    }
    let threshold = match (sel.threshold, sel.trusted_keys.len()) {
        (Some(t), _) => t,
        (None, 1) => 1,
        (None, _) => bail!("--threshold is required when more than one --trusted-key is given"),
    };
    let keys: Vec<&str> = sel.trusted_keys.iter().map(String::as_str).collect();
    let set = ProjectKeySet {
        version: 1,
        threshold,
        keys: &keys,
    };
    let root = set
        .trusted_root(&hasher, &verifier)
        .context("the --trusted-key and --threshold values are not a key set")?;
    Ok(Chosen {
        root,
        source: Source::CommandLine,
    })
}

// ---- check ---------------------------------------------------------------------------------------

/// Arguments of `prebuilt check`.
#[derive(Args)]
pub struct CheckArgs {
    /// The list (the payload of FORMAT.md 21, a file such as `prebuilt-<version>.json`).
    #[arg(long)]
    list: PathBuf,
    /// Print one JSON object with `version`, `source_commit`, `rehearsal` and `binaries`.
    #[arg(long)]
    json: bool,
}

/// `prebuilt check`: parses a list with the CLI's own parser and prints what it read. No key, no
/// network, no signature; it exits 0 only when the list is accepted.
pub fn check(args: &CheckArgs) -> Result<()> {
    let bytes = read_doc(&args.list, "--list")?;
    let list = PrebuiltList::from_payload(&bytes).context("the list is not accepted")?;
    if args.json {
        return say(&list_json(&list).to_string());
    }
    for line in list_text(&list) {
        say(&line)?;
    }
    Ok(())
}

fn list_json(list: &PrebuiltList) -> Value {
    json!({
        "version": list.version_text(),
        "source_commit": list.source_commit(),
        "rehearsal": list.is_rehearsal(),
        "binaries": binaries_json(list),
    })
}

fn list_text(list: &PrebuiltList) -> Vec<String> {
    let mut lines = vec![format!(
        "list: version {}, source commit {}, rehearsal {}",
        list.version_text(),
        list.source_commit(),
        list.is_rehearsal()
    )];
    lines.extend(binaries_json(list).iter().map(binary_line));
    lines
}

// ---- sign ----------------------------------------------------------------------------------------

/// Arguments of `prebuilt sign`.
#[derive(Args)]
pub struct SignArgs {
    /// The list to sign: its bytes are signed as they are, never re-written.
    #[arg(long)]
    list: PathBuf,
    /// Where to write the envelope (`prebuilt-<version>.sig.json`); it must not exist.
    #[arg(long)]
    out: PathBuf,
    /// A signer: `file:<path>`, `env:<VAR>` or a name from the config; repeat to reach a threshold.
    #[arg(long = "sign", required = true)]
    sign: Vec<String>,
    /// A public key (64 lowercase hex characters) the envelope must verify under instead of the
    /// built-in key set; repeat for 2 to 16 keys with `--threshold`.
    #[arg(long = "trusted-key")]
    trusted_keys: Vec<String>,
    /// How many of the `--trusted-key` keys must sign; required with more than one.
    #[arg(long)]
    threshold: Option<u64>,
}

/// Signs `list_bytes` with the signers `signers()` returns and checks the envelope under the key
/// set `sel` names (or the current built-in one) before returning it: an envelope that does not
/// verify is an error that names the key ids the set expects and the ids that signed (they are
/// public), so a secret that holds the wrong key fails closed. Nothing is written here.
fn sign_list(
    roots: &[ProjectKeySet<'_>],
    sel: &Selection<'_>,
    list_bytes: &[u8],
    cli_version: &str,
    signers: impl FnOnce() -> Result<Vec<Box<dyn Signer>>>,
) -> Result<(Vec<u8>, Chosen)> {
    let list = PrebuiltList::from_payload(list_bytes).context("the list is not accepted")?;
    if list.version_text() != cli_version {
        bail!(
            "the list is of version {}, this CLI is version {cli_version}: sign it with the CLI \
             of its own version",
            list.version_text()
        );
    }
    let chosen = choose_keys(roots, sel)?;
    let signers = signers()?;
    let hasher = Sha256Hasher;
    let signer_ids: Vec<String> = signers
        .iter()
        .map(|s| hasher.sha256(&s.public_key()).to_hex())
        .collect();
    let refs: Vec<&dyn Signer> = signers.iter().map(|s| s.as_ref()).collect();
    let verifier = Ed25519Verifier;
    let envelope = sign_envelope(PayloadKind::Prebuilt, list_bytes, &refs, &hasher, &verifier)
        .context("cannot sign the list")?;
    let verified = verify_prebuilt(&chosen.root, &envelope, &verifier).map_err(|e| {
        anyhow!(
            "the signed envelope does not verify under the key set (nothing was written): {e}; \
             the key set expects key id(s) {} (threshold {}); signed by key id(s) {}",
            chosen.key_ids(),
            chosen.root.threshold(),
            signer_ids.join(", ")
        )
    })?;
    if verified.payload() != list_bytes {
        bail!("the signed envelope does not carry the list's bytes (nothing was written)");
    }
    Ok((envelope, chosen))
}

/// `prebuilt sign`: signers are the existing specs, resolved with the global `--config` path
/// (`file:` and `env:` never read it). No key material is printed or written, and no network is
/// used. The envelope is written with `place::write_new`, so an existing file is an error.
pub fn sign(config: &Path, args: &SignArgs) -> Result<()> {
    let bytes = read_doc(&args.list, "--list")?;
    let sel = Selection {
        root_version: None,
        trusted_keys: &args.trusted_keys,
        threshold: args.threshold,
    };
    let (envelope, chosen) = sign_list(PROJECT_ROOTS, &sel, &bytes, CLI_VERSION, || {
        args.sign
            .iter()
            .map(|s| resolve_signer(config, s))
            .collect()
    })?;
    place::write_new(&args.out, &envelope)?;
    say(&format!("envelope written: {}", args.out.display()))?;
    for line in chosen.text() {
        say(&line)?;
    }
    Ok(())
}

// ---- verify --------------------------------------------------------------------------------------

/// Arguments of `prebuilt verify`.
#[derive(Args)]
pub struct VerifyArgs {
    /// The list file (the payload).
    #[arg(long)]
    list: PathBuf,
    /// The signed envelope (`prebuilt-<version>.sig.json`).
    #[arg(long)]
    sig: PathBuf,
    /// Check under this earlier built-in key set (its version) instead of the current one; the
    /// result says that the set is retired.
    #[arg(long = "root-version")]
    root_version: Option<u64>,
    /// A public key (64 lowercase hex characters) to check under instead of a built-in key set;
    /// repeat for 2 to 16 keys with `--threshold`.
    #[arg(long = "trusted-key")]
    trusted_keys: Vec<String>,
    /// How many of the `--trusted-key` keys must have signed; required with more than one.
    #[arg(long)]
    threshold: Option<u64>,
    /// A directory of downloaded files: each file that bears a row's asset name must have the
    /// row's size and SHA-256 (files are hashed, never run or parsed).
    #[arg(long)]
    dir: Option<PathBuf>,
    /// With `--dir`: every row's file must be present.
    #[arg(long, requires = "dir")]
    all: bool,
    /// Accept a rehearsal list (it is labelled in the result).
    #[arg(long = "allow-rehearsal")]
    allow_rehearsal: bool,
    /// Print one JSON object with the list, the key set used, the rows and the files checked.
    #[arg(long)]
    json: bool,
}

/// A list and envelope that verified, with the key set they verified under.
struct Verdict {
    chosen: Chosen,
    list: PrebuiltList,
}

/// Verifies `sig` under the chosen key set, then requires `list_bytes` to be the envelope's
/// payload byte for byte. A rehearsal list is refused unless `allow_rehearsal`.
fn verify_documents(
    roots: &[ProjectKeySet<'_>],
    sel: &Selection<'_>,
    list_bytes: &[u8],
    sig_bytes: &[u8],
    allow_rehearsal: bool,
) -> Result<Verdict> {
    let chosen = choose_keys(roots, sel)?;
    let verified = verify_prebuilt(&chosen.root, sig_bytes, &Ed25519Verifier).map_err(|e| {
        anyhow!(
            "the envelope does not verify under the key set (key id(s) {}, threshold {}): {e}",
            chosen.key_ids(),
            chosen.root.threshold()
        )
    })?;
    if verified.payload() != list_bytes {
        bail!("the list file is not the envelope's payload, byte for byte");
    }
    let list = if allow_rehearsal {
        verified.rehearsal_list()
    } else {
        verified.release_list().map_err(|_| {
            anyhow!("rehearsal list: it is signed but marked as a rehearsal; pass --allow-rehearsal to check it")
        })?
    };
    Ok(Verdict { chosen, list })
}

/// Checks the files of `dir` against `list`: every file that bears a row's asset name has the
/// row's size and SHA-256; a file named like a lunepack binary of the list's version that no row
/// names is an error; no matching file at all is an error; with `all` every row must be present.
/// Returns the asset names that were checked. Files are read and hashed, never run or parsed, and
/// a symbolic link or other non-regular file under a row's name is an error.
fn check_dir(list: &PrebuiltList, dir: &Path, all: bool) -> Result<Vec<String>> {
    let hasher = Sha256Hasher;
    let version = list.version_text();
    let expected: BTreeMap<String, &PrebuiltRow> = list
        .rows()
        .iter()
        .map(|r| (asset_name(r.kind(), version, r.target()), r))
        .collect();
    let prefixes: Vec<String> = BinaryKind::ALL
        .iter()
        .map(|k| format!("lunepack-{k}-{version}-"))
        .collect();
    let mut names: Vec<String> = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("cannot read {}", dir.display()))?;
        // A name that is not UTF-8 cannot be an asset name.
        if let Some(name) = entry.file_name().to_str() {
            names.push(name.to_owned());
        }
    }
    names.sort();
    let (mut problems, mut checked, mut seen) = (Vec::new(), Vec::new(), BTreeSet::new());
    for name in &names {
        let Some(row) = expected.get(name) else {
            if prefixes.iter().any(|p| name.starts_with(p)) {
                problems.push(format!(
                    "{name}: a lunepack binary of version {version} that no row of the list names"
                ));
            }
            continue;
        };
        seen.insert(name.clone());
        let path = dir.join(name);
        let meta = fs::symlink_metadata(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        if !meta.is_file() {
            problems.push(format!("{name}: not a regular file"));
        } else if meta.len() != row.size() {
            problems.push(format!(
                "{name}: {} bytes, the list says {}",
                meta.len(),
                row.size()
            ));
        } else if row.size() > kind_cap(row.kind()) {
            problems.push(format!(
                "{name}: the list's size is above the {} bytes pack reads for a {}",
                kind_cap(row.kind()),
                row.kind()
            ));
        } else {
            let mut bytes = Vec::new();
            fs::File::open(&path)
                .and_then(|f| f.take(row.size() + 1).read_to_end(&mut bytes))
                .with_context(|| format!("cannot read {}", path.display()))?;
            if bytes.len() as u64 != row.size() {
                problems.push(format!("{name}: changed while it was read"));
            } else if hasher.sha256(&bytes) != row.sha256() {
                problems.push(format!("{name}: the SHA-256 is not the list's"));
            } else {
                checked.push(name.clone());
            }
        }
    }
    if seen.is_empty() {
        problems.push("no file in the directory bears the asset name of a row".to_owned());
    }
    if all {
        for name in expected.keys().filter(|n| !seen.contains(*n)) {
            problems.push(format!("{name}: in the list, not in the directory"));
        }
    }
    if !problems.is_empty() {
        bail!(
            "the files do not match the list:\n  {}",
            problems.join("\n  ")
        );
    }
    Ok(checked)
}

/// `prebuilt verify`: exit 0 only when everything asked for passed.
pub fn verify(args: &VerifyArgs) -> Result<()> {
    let list_bytes = read_doc(&args.list, "--list")?;
    let sig_bytes = read_doc(&args.sig, "--sig")?;
    let sel = Selection {
        root_version: args.root_version,
        trusted_keys: &args.trusted_keys,
        threshold: args.threshold,
    };
    let Verdict { chosen, list } = verify_documents(
        PROJECT_ROOTS,
        &sel,
        &list_bytes,
        &sig_bytes,
        args.allow_rehearsal,
    )?;
    let checked = args
        .dir
        .as_deref()
        .map(|dir| check_dir(&list, dir, args.all))
        .transpose()?;
    if args.json {
        let mut report = list_json(&list);
        report["key_set"] = chosen.json();
        report["files"] = match &checked {
            Some(names) => json!({ "checked": names, "all": args.all }),
            None => Value::Null,
        };
        return say(&report.to_string());
    }
    for line in list_text(&list) {
        say(&line)?;
    }
    for line in chosen.text() {
        say(&line)?;
    }
    if let Some(names) = &checked {
        say(&format!(
            "files: {} checked{}",
            names.len(),
            if args.all { ", every row present" } else { "" }
        ))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lunepack_crypto::{Ed25519Signer, generate_key_file};

    use super::*;

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const TARGET: &str = "linux-x86_64";
    const RUNTIME: &[u8] = b"a runtime's bytes";

    /// Throwaway keys, made now in a temporary directory.
    struct Keys {
        _dir: tempfile::TempDir,
        paths: Vec<PathBuf>,
        hex: Vec<String>,
    }

    impl Keys {
        /// Key `i` as a signer: the key is read from its file each time (a signer is not `Clone`).
        fn signer(&self, i: usize) -> Result<Vec<Box<dyn Signer>>> {
            Ok(vec![Box::new(Ed25519Signer::from_key_file(
                &self.paths[i],
            )?)])
        }
    }

    fn keys(n: usize) -> Keys {
        let dir = tempfile::tempdir().unwrap();
        let (mut paths, mut hex) = (Vec::new(), Vec::new());
        for i in 0..n {
            let k = generate_key_file(&dir.path().join(format!("k{i}.sk"))).unwrap();
            hex.push(hex_encode(&k.public_key));
            paths.push(PathBuf::from(&k.path));
        }
        Keys {
            _dir: dir,
            paths,
            hex,
        }
    }

    fn list_bytes(version: &str, rehearsal: bool) -> Vec<u8> {
        format!(
            r#"{{"format":1,"kind":"prebuilt","critical":[],"version":"{version}","source_commit":"{COMMIT}","rehearsal":{rehearsal},"binaries":[{{"kind":"runtime","target":"{TARGET}","size":{},"sha256":"{}"}}]}}"#,
            RUNTIME.len(),
            Sha256Hasher.sha256(RUNTIME).to_hex()
        )
        .into_bytes()
    }

    fn set<'a>(version: u64, keys: &'a [&'a str]) -> ProjectKeySet<'a> {
        ProjectKeySet {
            version,
            threshold: 1,
            keys,
        }
    }

    fn sel<'a>(
        root_version: Option<u64>,
        trusted_keys: &'a [String],
        threshold: Option<u64>,
    ) -> Selection<'a> {
        Selection {
            root_version,
            trusted_keys,
            threshold,
        }
    }

    fn no_flags() -> Selection<'static> {
        sel(None, &[], None)
    }

    fn signed_by(roots: &[ProjectKeySet<'_>], k: &Keys, by: usize, list: &[u8]) -> Vec<u8> {
        let (envelope, _) = sign_list(roots, &no_flags(), list, "0.1.0", || k.signer(by)).unwrap();
        envelope
    }

    fn err_of<T>(r: Result<T>) -> String {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn a_list_signed_under_set_1_verifies_with_root_version_1_and_is_retired() {
        let k = keys(2);
        let (a, b) = ([k.hex[0].as_str()], [k.hex[1].as_str()]);
        let list = list_bytes("0.1.0", false);
        // Signed while set 1 was the only (current) one.
        let envelope = signed_by(&[set(1, &a)], &k, 0, &list);

        let roots = [set(1, &a), set(2, &b)];
        let v =
            verify_documents(&roots, &sel(Some(1), &[], None), &list, &envelope, false).unwrap();
        assert_eq!(
            v.chosen.source,
            Source::BuiltIn {
                version: 1,
                current: false
            }
        );
        assert!(
            v.chosen
                .label()
                .contains("built-in key set 1, which is retired")
        );
        assert_eq!(v.chosen.json()["retired"], true);

        // The current set 2 refuses it, and so does a set that does not exist.
        let err = err_of(verify_documents(
            &roots,
            &no_flags(),
            &list,
            &envelope,
            false,
        ));
        assert!(err.contains("does not verify"), "{err}");
        for n in [0, 3] {
            let err = err_of(verify_documents(
                &roots,
                &sel(Some(n), &[], None),
                &list,
                &envelope,
                false,
            ));
            assert!(err.contains("no built-in project key set"), "{err}");
        }
        // Without --root-version and signed by set 2: the current one, labelled so.
        let envelope = signed_by(&roots, &k, 1, &list);
        let v = verify_documents(&roots, &no_flags(), &list, &envelope, false).unwrap();
        assert!(
            v.chosen
                .label()
                .contains("built-in key set 2, the current one")
        );
    }

    #[test]
    fn key_selection_rules() {
        let k = keys(2);
        let a = [k.hex[0].as_str()];
        let given = vec![k.hex[0].clone()];
        let two = k.hex.clone();

        // No built-in key and no --trusted-key: refused, with or without --root-version.
        for s in [no_flags(), sel(Some(1), &[], None)] {
            let err = err_of(choose_keys(&[], &s));
            assert!(err.contains("no project key built in"), "{err}");
        }
        // A threshold needs --trusted-key; --trusted-key and --root-version do not mix.
        assert!(
            err_of(choose_keys(&[set(1, &a)], &sel(None, &[], Some(1)))).contains("--threshold")
        );
        let err = err_of(choose_keys(&[set(1, &a)], &sel(Some(1), &given, None)));
        assert!(err.contains("cannot be used together"), "{err}");
        // More than one key needs a threshold; one key defaults to 1.
        let err = err_of(choose_keys(&[], &sel(None, &two, None)));
        assert!(err.contains("--threshold is required"), "{err}");
        let one = choose_keys(&[], &sel(None, &given, None)).unwrap();
        assert_eq!(one.source, Source::CommandLine);
        assert_eq!(one.root.threshold(), 1);
        assert!(
            one.label()
                .contains("a key given on the command line, not a built-in one")
        );
        let both = choose_keys(&[], &sel(None, &two, Some(2))).unwrap();
        assert_eq!(both.root.threshold(), 2);
        // The rules of a built-in set apply: threshold above the count, zero, a repeated key,
        // upper case, short, and more than 16 keys.
        for (keys, t) in [
            (given.clone(), Some(2)),
            (given.clone(), Some(0)),
            (vec![k.hex[0].clone(), k.hex[0].clone()], Some(1)),
            (vec![k.hex[0].to_uppercase()], None),
            (vec![k.hex[0][..63].to_owned()], None),
            (vec![k.hex[0].clone(); 17], Some(1)),
        ] {
            assert!(choose_keys(&[], &sel(None, &keys, t)).is_err(), "{keys:?}");
        }
    }

    #[test]
    fn a_signer_outside_the_key_set_is_refused_and_the_ids_are_named() {
        let k = keys(2);
        let a = [k.hex[0].as_str()];
        let list = list_bytes("0.1.0", false);
        let err = err_of(sign_list(
            &[set(1, &a)],
            &no_flags(),
            &list,
            "0.1.0",
            || k.signer(1),
        ));
        assert!(err.contains("nothing was written"), "{err}");
        let id = |hex: &str| {
            Sha256Hasher
                .sha256(&crate::config::hex32(hex, "k").unwrap())
                .to_hex()
        };
        assert!(err.contains(&id(&k.hex[0])), "expected id missing: {err}");
        assert!(err.contains(&id(&k.hex[1])), "signer id missing: {err}");
    }

    #[test]
    fn sign_needs_a_list_of_the_cli_version_that_the_parser_accepts() {
        let k = keys(1);
        let given = k.hex.clone();
        let s = sel(None, &given, None);
        let signers = || k.signer(0);
        let err = err_of(sign_list(
            &[],
            &s,
            &list_bytes("0.2.0", false),
            "0.1.0",
            signers,
        ));
        assert!(err.contains("version 0.2.0"), "{err}");
        let err = err_of(sign_list(&[], &s, b"{}", "0.1.0", signers));
        assert!(err.contains("not accepted"), "{err}");
        // A rehearsal list signs (the rehearsal run of the workflow signs one).
        sign_list(&[], &s, &list_bytes("0.1.0", true), "0.1.0", signers).unwrap();
    }

    #[test]
    fn a_rehearsal_list_is_refused_unless_allowed_and_an_edited_list_is_refused() {
        let k = keys(1);
        let given = k.hex.clone();
        let s = sel(None, &given, None);
        let list = list_bytes("0.1.0", true);
        let (envelope, _) = sign_list(&[], &s, &list, "0.1.0", || k.signer(0)).unwrap();
        let err = err_of(verify_documents(&[], &s, &list, &envelope, false));
        assert!(err.contains("rehearsal list"), "{err}");
        let v = verify_documents(&[], &s, &list, &envelope, true).unwrap();
        assert!(v.list.is_rehearsal());
        let mut edited = list.clone();
        edited.push(b'\n');
        let err = err_of(verify_documents(&[], &s, &edited, &envelope, true));
        assert!(err.contains("not the envelope's payload"), "{err}");
    }

    #[test]
    fn report_of_no_key_has_no_roots_and_no_binaries() {
        let r = report(&[], &PinState::NoKey, None);
        assert_eq!(r["state"], "no-key");
        assert_eq!(r["roots"], json!([]));
        assert_eq!(r["binaries"], json!([]));
        assert!(r["list"].is_null() && r["reason"].is_null());
        assert!(text(&r).iter().any(|l| l.starts_with("key sets: none")));
    }

    #[test]
    fn report_names_each_key_set_its_keys_and_which_is_current() {
        // Hex forms only; the report does not check that they are valid keys.
        let (a, b) = ("1".repeat(64), "2".repeat(64));
        let ka = [a.as_str()];
        let kb = [b.as_str()];
        let roots = [
            ProjectKeySet {
                version: 1,
                threshold: 1,
                keys: &ka,
            },
            ProjectKeySet {
                version: 2,
                threshold: 1,
                keys: &kb,
            },
        ];
        let r = report(&roots, &PinState::None, None);
        assert_eq!(r["roots"][0]["current"], false);
        assert_eq!(r["roots"][1]["current"], true);
        assert_eq!(r["roots"][1]["keys"][0]["public"], b.as_str());
        let id = Sha256Hasher
            .sha256(&crate::config::hex32(&b, "b").unwrap())
            .to_hex();
        assert_eq!(r["roots"][1]["keys"][0]["id"], id.as_str());
        let lines = text(&r);
        assert!(lines.contains(&"key set 1: threshold 1, retired".to_owned()));
        assert!(lines.contains(&format!("  key: {b} id {id}")));
    }
}
