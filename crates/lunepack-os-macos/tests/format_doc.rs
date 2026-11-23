//! Keeps the property list and the policy path of `docs/FORMAT.md` 20 honest (M11 step 15): the
//! block `text launchd-plist` must equal, byte for byte, what the registrar writes for the example
//! app `org.example.hello` with no bundle identifier, and the policy file path the document names
//! must be the one the policy reader looks in.
#![cfg(target_os = "macos")]

use std::path::Path;

use lunepack_core::AppId;
use lunepack_os_macos::{POLICY_DIR, daemon_plist};

fn format_md() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/FORMAT.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The text of the first ```` ```text <tag> ```` block, each line ending in a newline, or `None`.
fn text_block(text: &str, tag: &str) -> Option<String> {
    let open = format!("```text {tag}");
    let mut lines = text.lines();
    lines.by_ref().find(|l| *l == open)?;
    let mut out = String::new();
    for line in lines.take_while(|l| !l.starts_with("```")) {
        out.push_str(line);
        out.push('\n');
    }
    Some(out)
}

#[test]
fn the_plist_block_equals_the_registrars_bytes() {
    let app = AppId::parse("org.example.hello").unwrap();
    let exec = Path::new(
        "/Library/Application Support/lunepack/org.example.hello/.lunepack/machine/lunepack-service",
    );
    let block = text_block(&format_md(), "launchd-plist")
        .expect("docs/FORMAT.md has no ```text launchd-plist block");
    assert!(block.len() > 300, "the block was read empty");
    assert_eq!(
        block,
        daemon_plist(&app, exec, None).expect("a plain path"),
        "FORMAT.md 20.5: the property list differs"
    );
}

#[test]
fn the_text_block_reader_rejects_a_missing_block() {
    // The instrument: a tag the document does not have is `None`; a block keeps its line ends.
    assert!(text_block("```text other\na\n```\n", "launchd-plist").is_none());
    assert_eq!(
        text_block("x\n```text t\na\n\tb\n```\nafter\n", "t").as_deref(),
        Some("a\n\tb\n")
    );
}

#[test]
fn the_document_names_the_policy_file_the_reader_uses() {
    let want = format!("`{POLICY_DIR}/<app id>.json`");
    assert!(
        format_md().contains(&want),
        "docs/FORMAT.md 20.6 does not name {want}"
    );
}
