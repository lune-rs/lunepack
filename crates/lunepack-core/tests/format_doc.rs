//! Keeps the examples in `docs/FORMAT.md` honest: every fenced block tagged `json <kind>` parses
//! as that kind with the reader's own checks (`lunepack_core::fuzz::parse_example`), so the
//! document cannot drift from the code unnoticed. Semantics (keys, signatures, bindings) are
//! covered by the verification tests; the examples carry placeholder keys and signatures.
//!
//! Section 19 (the service protocol, M10) has three blocks of its own, each tagged `text <name>`:
//! `service-v1` must equal the golden file `tests/golden/service-v1.txt` line for line (the file's
//! comment lines apart), and `service-v1-codes` and `service-v1-classes` must list the protocol's
//! error codes and verification classes, in the code's order.

use std::path::Path;

use lunepack_core::fuzz::parse_example;
use lunepack_core::service::{ErrorCode, VerifyClass};

const KINDS: [&str; 5] = ["envelope", "root", "keys", "feed", "manifest"];

/// `(kind, body, first line number)` of every ```` ```json <kind> ```` block.
fn example_blocks(text: &str) -> Vec<(String, String, usize)> {
    let mut out = Vec::new();
    let mut current: Option<(String, String, usize)> = None;
    for (index, line) in text.lines().enumerate() {
        match &mut current {
            None => {
                if let Some(kind) = line.strip_prefix("```json ") {
                    current = Some((kind.trim().to_owned(), String::new(), index + 2));
                }
            }
            Some((_, body, _)) => {
                if line.starts_with("```") {
                    out.extend(current.take());
                } else {
                    body.push_str(line);
                    body.push('\n');
                }
            }
        }
    }
    assert!(current.is_none(), "an unterminated code block");
    out
}

fn format_md() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/FORMAT.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

#[test]
fn every_format_example_parses_as_its_kind() {
    let blocks = example_blocks(&format_md());
    for kind in KINDS {
        assert!(
            blocks.iter().any(|(k, _, _)| k == kind),
            "docs/FORMAT.md has no ```json {kind} example"
        );
    }
    for (kind, body, line) in &blocks {
        assert!(
            KINDS.contains(&kind.as_str()),
            "line {line}: unknown example kind {kind:?}"
        );
        if let Err(e) = parse_example(kind, body.as_bytes()) {
            panic!("docs/FORMAT.md line {line}: the {kind} example does not parse: {e}");
        }
    }
}

#[test]
fn the_example_check_rejects_a_broken_example() {
    // The instrument: a known-bad document of each kind must fail, or the test above proves nothing.
    for kind in KINDS {
        assert!(
            parse_example(kind, b"{\"format\":2}").is_err(),
            "{kind} accepted a bad document"
        );
    }
    assert!(parse_example("root", br#"{"format":1,"kind":"root","kind":"root"}"#).is_err());
}

/// The lines of the first ```` ```text <tag> ```` block, or `None`.
fn text_block(text: &str, tag: &str) -> Option<Vec<String>> {
    let open = format!("```text {tag}");
    let mut lines = text.lines();
    lines.by_ref().find(|l| *l == open)?;
    let body: Vec<String> = lines
        .by_ref()
        .take_while(|l| !l.starts_with("```"))
        .map(str::to_owned)
        .collect();
    Some(body)
}

#[test]
fn the_service_protocol_examples_equal_the_golden_file() {
    let doc = text_block(&format_md(), "service-v1")
        .expect("docs/FORMAT.md has no ```text service-v1 block");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/service-v1.txt");
    let golden = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let golden: Vec<&str> = golden
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert!(golden.len() > 20, "the golden file was read empty");
    assert_eq!(
        doc.iter().map(String::as_str).collect::<Vec<_>>(),
        golden,
        "the examples of docs/FORMAT.md 19.7 differ from tests/golden/service-v1.txt"
    );
}

#[test]
fn the_service_protocol_code_lists_equal_the_code() {
    let md = format_md();
    let codes = text_block(&md, "service-v1-codes").expect("no ```text service-v1-codes block");
    let want: Vec<&str> = ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(codes.iter().map(String::as_str).collect::<Vec<_>>(), want);
    let classes =
        text_block(&md, "service-v1-classes").expect("no ```text service-v1-classes block");
    let want: Vec<&str> = VerifyClass::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(classes.iter().map(String::as_str).collect::<Vec<_>>(), want);
}

#[test]
fn the_text_block_reader_rejects_a_missing_block() {
    // The instrument: a tag the document does not have is `None`, not an empty block.
    assert!(text_block("```text other\na\n```\n", "service-v1").is_none());
    assert_eq!(
        text_block("x\n```text t\na\nb\n```\nafter\n", "t"),
        Some(vec!["a".to_owned(), "b".to_owned()])
    );
}
