//! `prebuilt` (M13): lunepack's own prebuilt binaries. `prebuilt list` shows the project's key sets
//! compiled into this CLI and what it pins ([`crate::prebuilt`]).

use std::io::{self, Write as _};

use anyhow::{Context, Result, bail};
use clap::Args;
use lunepack_core::{Hasher, PrebuiltRow, Target};
use lunepack_crypto::Sha256Hasher;
use serde_json::{Value, json};

use crate::prebuilt::{self, PinState, asset_name};
use crate::project_key::{PROJECT_ROOTS, ProjectKeySet};

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

#[cfg(test)]
mod tests {
    use super::*;

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
