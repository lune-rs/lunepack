//! Keeps the unit files and the policy path of `docs/FORMAT.md` 20 honest (M11 step 15): the two
//! blocks `text systemd-socket-unit` and `text systemd-service-unit` must equal, byte for byte,
//! what the registrar writes for the example app `org.example.hello`, and the policy file path
//! the document names must be the one the policy reader looks in.
#![cfg(target_os = "linux")]

use std::path::Path;

use lunepack_core::AppId;
use lunepack_os_linux::{POLICY_DIR, service_unit_text, socket_unit_text};

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
fn the_unit_blocks_equal_the_registrars_bytes() {
    let md = format_md();
    let app = AppId::parse("org.example.hello").unwrap();
    let exec = Path::new("/opt/org.example.hello/.lunepack/machine/lunepack-service");
    let socket = text_block(&md, "systemd-socket-unit")
        .expect("docs/FORMAT.md has no ```text systemd-socket-unit block");
    let service = text_block(&md, "systemd-service-unit")
        .expect("docs/FORMAT.md has no ```text systemd-service-unit block");
    assert!(
        socket.len() > 100 && service.len() > 100,
        "a block was read empty"
    );
    assert_eq!(
        socket,
        socket_unit_text(&app),
        "FORMAT.md 20.4: the socket unit differs"
    );
    assert_eq!(
        service,
        service_unit_text(&app, exec).expect("a plain path"),
        "FORMAT.md 20.4: the service unit differs"
    );
}

#[test]
fn the_text_block_reader_rejects_a_missing_block() {
    // The instrument: a tag the document does not have is `None`; a block keeps its line ends.
    assert!(text_block("```text other\na\n```\n", "systemd-socket-unit").is_none());
    assert_eq!(
        text_block("x\n```text t\na\nb\n```\nafter\n", "t").as_deref(),
        Some("a\nb\n")
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
