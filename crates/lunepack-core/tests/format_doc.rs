//! Keeps the examples in `docs/FORMAT.md` honest: every fenced block tagged `json <kind>` parses
//! as that kind with the reader's own checks (`lunepack_core::fuzz::parse_example`), so the
//! document cannot drift from the code unnoticed. Semantics (keys, signatures, bindings) are
//! covered by the verification tests; the examples carry placeholder keys and signatures.
//!
//! Section 19 (the service protocol, M10) has three blocks of its own, each tagged `text <name>`:
//! `service-v1` must equal the golden file `tests/golden/service-v1.txt` line for line (the file's
//! comment lines apart), and `service-v1-codes` and `service-v1-classes` must list the protocol's
//! error codes and verification classes, in the code's order.
//!
//! Section 20 (the Linux and macOS per-machine layout, M11) has one block, `text unix-names`: the
//! endpoint, home, root and link names for the example app id `org.example.hello`, which must equal
//! what the core's `endpoint` and `layout` functions return. The unit files and the property list
//! are checked against the adapters' own writers in `lunepack-os-linux` and `lunepack-os-macos`
//! (`tests/format_doc.rs` of each).

use std::path::Path;

use lunepack_core::endpoint;
use lunepack_core::fuzz::parse_example;
use lunepack_core::service::{ErrorCode, VerifyClass};
use lunepack_core::{AppId, MachineLayout, MachineScheme, UnixOs, Version, machine_user_home};

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

/// The lines of the `text unix-names` block of FORMAT.md 20.9, from the code: `<label> | <value>`.
fn unix_names() -> Vec<String> {
    let app = AppId::parse("org.example.hello").unwrap();
    let version = Version::parse("1.2.3").unwrap();
    let mut out = Vec::new();
    let mut line = |label: &str, value: String| out.push(format!("{label} | {value}"));
    line("app id", app.as_str().to_owned());
    line("version", version.to_string());
    for (os, name, scheme) in [
        (UnixOs::Linux, "linux", MachineScheme::LINUX),
        (UnixOs::Macos, "macos", MachineScheme::MACOS),
    ] {
        let home = Path::new(scheme.home.expect("a unix scheme has a machine home"));
        let root = lunepack_core::machine_root(home, &app);
        let layout = MachineLayout::with_scheme(&root, scheme);
        let show = |p: &Path| p.display().to_string();
        line(&format!("{name} machine home"), show(home));
        line(&format!("{name} install root R"), show(&root));
        line(&format!("{name} versions"), show(&layout.app_dir()));
        line(
            &format!("{name} version tree"),
            show(&layout.version_dir(&version)),
        );
        line(&format!("{name} state"), show(&layout.state_dir()));
        line(&format!("{name} logs"), show(&layout.logs_dir()));
        line(&format!("{name} lock"), show(&layout.lock_path()));
        line(&format!("{name} incoming"), show(&layout.incoming_dir()));
        line(
            &format!("{name} service binary"),
            show(&layout.service_image(&version)),
        );
        line(
            &format!("{name} stable service link"),
            show(
                &layout
                    .stable_service_link()
                    .expect("a unix scheme has the link"),
            ),
        );
        line(
            &format!("{name} per-user home"),
            show(&machine_user_home(Path::new("<data home>"), &app)),
        );
        line(
            &format!("{name} socket directory"),
            endpoint::socket_dir(os).to_owned(),
        );
        line(
            &format!("{name} socket"),
            show(&endpoint::socket_path(os, &app)),
        );
        line(
            &format!("{name} longest socket path"),
            endpoint::max_socket_path(os).to_string(),
        );
    }
    let linux = MachineScheme::LINUX;
    line(
        "linux projection target",
        linux.view.current_target(&version),
    );
    line("linux socket unit", endpoint::systemd_socket_unit(&app));
    line("linux service unit", endpoint::systemd_service_unit(&app));
    line(
        "linux unit directory",
        endpoint::SYSTEMD_UNIT_DIR.to_owned(),
    );
    line("macos label", endpoint::launchd_label(&app));
    line(
        "macos plist",
        endpoint::launchd_plist_path(&app).display().to_string(),
    );
    line(
        "macos launchd socket name",
        endpoint::LAUNCHD_SOCKET_NAME.to_owned(),
    );
    line(
        "service file (unix)",
        lunepack_core::SERVICE_FILE_UNIX.to_owned(),
    );
    out
}

#[test]
fn the_unix_names_equal_the_code() {
    let doc = text_block(&format_md(), "unix-names")
        .expect("docs/FORMAT.md has no ```text unix-names block");
    let want = unix_names();
    assert!(want.len() > 30, "the name list was built empty");
    assert_eq!(
        doc, want,
        "the names of docs/FORMAT.md 20.9 differ from the core's endpoint and layout functions"
    );
}

#[test]
fn every_app_id_socket_path_fits_its_socket_address() {
    // The instrument for the two "longest socket path" lines: the longest app id (64 bytes) still
    // fits on both systems, and the limit is one byte under the `sun_path` size.
    let longest = AppId::parse(&"a".repeat(64)).unwrap();
    for (os, sun_path) in [(UnixOs::Linux, 108), (UnixOs::Macos, 104)] {
        let path = endpoint::socket_path(os, &longest);
        assert!(path.as_os_str().len() <= endpoint::max_socket_path(os));
        assert_eq!(endpoint::max_socket_path(os), sun_path - 1);
    }
}
