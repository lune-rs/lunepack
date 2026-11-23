//! M10 step 4 contract: the service protocol, version 1. The wire bytes are pinned by
//! `tests/golden/service-v1.txt`; every refused frame or message is `malformed` and ends the
//! session; negotiation, `read_data`, the `stage_begin` count rule, the closed code sets and the
//! deadlines behave as the protocol summary says.
//!
//! To rewrite the golden file after a deliberate change (the protocol is append-only once shipped):
//! `LUNEPACK_WRITE_GOLDEN=1 cargo test -p lunepack-core --test service_protocol golden`.

use std::collections::BTreeSet;
use std::io::{self, Cursor, ErrorKind, Read, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

use lunepack_core::service::{
    AttemptAnswer, ClientHello, ClientSession, ClientTimeouts, CommitOutcome, ConfirmAnswer,
    DocumentDecl, DocumentKind, Duplex, ErrorCode, Frame, KIND_DATA, KIND_MESSAGE, MAX_DATA,
    MAX_MESSAGE, ObjectKind, OutgoingDocument, PendingStatus, Request, RequestMsg, Response,
    SERVER_FRAME_DEADLINE, SERVER_HELLO_DEADLINE, ServerHello, ServerSession, StageBegun,
    StatusReport, Token, VerifyClass, check_documents, encode_frame, negotiate, read_frame,
};
use lunepack_core::{AppId, Channel, RelPath, ServiceError, Sha256Digest, Version};

const APP: &str = "org.example.hello";

fn app() -> AppId {
    AppId::parse(APP).unwrap()
}

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn token() -> Token {
    Token::from_bytes([0xab; 32])
}

fn digest() -> Sha256Digest {
    Sha256Digest::from_bytes([0x5a; 32])
}

fn docs() -> Vec<DocumentDecl> {
    vec![
        DocumentDecl {
            kind: DocumentKind::Root,
            bytes: 300,
        },
        DocumentDecl {
            kind: DocumentKind::Keys,
            bytes: 400,
        },
        DocumentDecl {
            kind: DocumentKind::Feed,
            bytes: 500,
        },
        DocumentDecl {
            kind: DocumentKind::Manifest,
            bytes: 600,
        },
    ]
}

fn req(request: Request) -> RequestMsg {
    RequestMsg {
        app: app(),
        request,
    }
}

fn msg(body: &[u8]) -> Vec<u8> {
    encode_frame(KIND_MESSAGE, body).unwrap()
}

fn raw_msg(json: &str) -> Vec<u8> {
    msg(json.as_bytes())
}

fn client_hello() -> Vec<u8> {
    msg(&ClientHello { min: 1, max: 1 }.encode().unwrap())
}

fn server_hello() -> Vec<u8> {
    msg(&ServerHello::Version(1).encode().unwrap())
}

// ---- a scripted duplex ---------------------------------------------------------------------------

/// Reads from a fixed script, records writes and deadlines; a read at or after `time_out_at`
/// bytes fails with `TimedOut`.
struct Script {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    deadlines: Vec<Option<Duration>>,
    time_out_at: Option<u64>,
}

impl Script {
    fn new(input: Vec<u8>) -> Script {
        Script {
            input: Cursor::new(input),
            output: Vec::new(),
            deadlines: Vec::new(),
            time_out_at: None,
        }
    }

    /// The frames this side wrote, decoded as answers.
    fn answers(&self) -> Vec<Response> {
        let mut out = Cursor::new(self.output.clone());
        let mut list = Vec::new();
        while let Some(frame) = read_frame(&mut out).unwrap() {
            let Frame::Message(body) = frame else {
                panic!("the server wrote data")
            };
            if let Ok(r) = Response::decode(&body) {
                list.push(r);
            }
        }
        list
    }
}

impl Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self
            .time_out_at
            .is_some_and(|at| self.input.position() >= at)
        {
            return Err(io::Error::from(ErrorKind::TimedOut));
        }
        self.input.read(buf)
    }
}

impl Write for Script {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Duplex for Script {
    fn set_read_deadline(&mut self, deadline: Option<Duration>) -> io::Result<()> {
        self.deadlines.push(deadline);
        Ok(())
    }
}

fn server_over(input: Vec<u8>) -> Result<ServerSession<Script>, ServiceError> {
    ServerSession::accept(Script::new(input), app())
}

fn with_hello(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut input = client_hello();
    for f in frames {
        input.extend_from_slice(f);
    }
    input
}

/// The first request of a session whose client sent `frames` after the hello.
fn first_request(frames: &[Vec<u8>]) -> (Result<Option<Request>, ServiceError>, Script) {
    let mut s = server_over(with_hello(frames)).expect("hello");
    let r = s.next_request();
    (r, s.into_inner())
}

fn assert_malformed(frames: &[Vec<u8>]) {
    let (r, script) = first_request(frames);
    assert!(
        matches!(r, Err(ServiceError::Malformed(_))),
        "expected malformed, got {r:?}"
    );
    assert_eq!(
        script.answers().last(),
        Some(&Response::error(ErrorCode::Malformed)),
        "the server answers malformed"
    );
}

// ---- the golden file -----------------------------------------------------------------------------

fn status_full() -> StatusReport {
    StatusReport {
        current: v("1.1.0"),
        previous: Some(v("1.0.0")),
        pending: Some(PendingStatus {
            version: v("1.1.0"),
            attempts: 1,
        }),
        staged: Some(v("1.2.0-beta.1")),
        service: v("1.0.0"),
        self_update_disabled: false,
    }
}

fn status_bare() -> StatusReport {
    StatusReport {
        current: v("1.0.0"),
        previous: None,
        pending: None,
        staged: None,
        service: v("1.0.0"),
        self_update_disabled: true,
    }
}

fn all_requests() -> Vec<(&'static str, RequestMsg)> {
    vec![
        ("request status", req(Request::Status)),
        (
            "request stage_begin",
            req(Request::StageBegin {
                channel: Channel::parse("stable").unwrap(),
                documents: docs(),
            }),
        ),
        (
            "request put",
            req(Request::Put {
                kind: ObjectKind::Pack,
                sha256: digest(),
                size: 1_048_576,
            }),
        ),
        ("request stage_commit", req(Request::StageCommit)),
        (
            "request apply",
            req(Request::Apply {
                version: v("1.1.0"),
            }),
        ),
        (
            "request attempt",
            req(Request::Attempt {
                version: v("1.1.0"),
            }),
        ),
        (
            "request confirm",
            req(Request::Confirm {
                version: v("1.1.0"),
                token: token(),
            }),
        ),
        (
            "request rollback",
            req(Request::Rollback {
                version: v("1.1.0"),
                token: token(),
            }),
        ),
    ]
}

fn all_responses() -> Vec<(&'static str, Response)> {
    vec![
        ("answer status", Response::Status(status_full())),
        (
            "answer status (nothing optional)",
            Response::Status(status_bare()),
        ),
        (
            "answer stage_ready",
            Response::StageReady {
                version: v("1.1.0"),
            },
        ),
        ("answer no_update", Response::NoUpdate),
        ("answer put_ok", Response::PutOk),
        ("answer progress", Response::Progress { done: 3, total: 10 }),
        (
            "answer staged",
            Response::Staged {
                version: v("1.1.0"),
            },
        ),
        (
            "answer need_fetch",
            Response::NeedFetch {
                paths: vec![
                    RelPath::parse("bin/app.exe").unwrap(),
                    RelPath::parse("lib/data.bin").unwrap(),
                ],
                more: false,
            },
        ),
        (
            "answer applied",
            Response::Applied {
                version: v("1.1.0"),
                token: token(),
            },
        ),
        (
            "answer attempt supervised",
            Response::Attempt(AttemptAnswer::Supervised),
        ),
        (
            "answer attempt counted",
            Response::Attempt(AttemptAnswer::Counted {
                attempts: 2,
                token: token(),
            }),
        ),
        (
            "answer attempt rolled_back",
            Response::Attempt(AttemptAnswer::RolledBack {
                current: v("1.0.0"),
            }),
        ),
        (
            "answer attempt not_pending",
            Response::Attempt(AttemptAnswer::NotPending),
        ),
        ("answer confirmed", Response::Confirmed),
        ("answer nothing_pending", Response::NothingPending),
        (
            "answer rolled_back",
            Response::RolledBack {
                current: v("1.0.0"),
            },
        ),
        ("answer error", Response::error(ErrorCode::TokenMismatch)),
        (
            "answer error verify_failed",
            Response::Error {
                code: ErrorCode::VerifyFailed,
                class: Some(VerifyClass::Rollback),
            },
        ),
    ]
}

fn golden_entries() -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = vec![
        ("hello client".into(), client_hello()),
        ("hello server".into(), server_hello()),
        (
            "hello unsupported".into(),
            msg(&ServerHello::Unsupported { min: 1, max: 1 }
                .encode()
                .unwrap()),
        ),
    ];
    for (name, r) in all_requests() {
        out.push((name.into(), msg(&r.encode().unwrap())));
    }
    for (name, r) in all_responses() {
        out.push((name.into(), msg(&r.encode().unwrap())));
    }
    out.push((
        "data".into(),
        encode_frame(KIND_DATA, &[0x00, 0x01, 0xfe, 0xff]).unwrap(),
    ));
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One line per frame: `<name> | <length and kind, hex> | <body>`, the body as text for message
/// frames and as hex for data frames.
fn render_golden() -> String {
    let mut text = String::from(
        "# Service protocol version 1: one encoded frame per message (M10-D1). Generated by\n\
         # crates/lunepack-core/tests/service_protocol.rs; append-only once an app ships.\n",
    );
    for (name, frame) in golden_entries() {
        let (head, body) = frame.split_at(5);
        let body = if head[4] == KIND_MESSAGE {
            String::from_utf8(body.to_vec()).unwrap()
        } else {
            hex(body)
        };
        text.push_str(&format!("{name} | {} | {body}\n", hex(head)));
    }
    text
}

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/service-v1.txt")
}

#[test]
fn golden_wire_bytes_are_pinned() {
    let rendered = render_golden();
    if std::env::var_os("LUNEPACK_WRITE_GOLDEN").is_some() {
        std::fs::write(golden_path(), &rendered).unwrap();
    }
    let committed = std::fs::read_to_string(golden_path()).expect("the golden file");
    assert_eq!(
        committed, rendered,
        "the service protocol's encoding changed; version 1 is append-only"
    );
}

#[test]
fn golden_lines_decode_back() {
    let committed = std::fs::read_to_string(golden_path()).expect("the golden file");
    let mut n = 0;
    for line in committed.lines().filter(|l| !l.starts_with('#')) {
        let mut parts = line.splitn(3, " | ");
        let name = parts.next().unwrap();
        let head = parts.next().unwrap();
        let body = parts.next().unwrap();
        let mut frame: Vec<u8> = (0..head.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&head[i..i + 2], 16).unwrap())
            .collect();
        frame.extend_from_slice(body.as_bytes());
        if name == "data" {
            continue;
        }
        let Frame::Message(body) = read_frame(&mut Cursor::new(frame)).unwrap().unwrap() else {
            panic!("{name}: not a message")
        };
        if name.starts_with("request ") {
            let r = RequestMsg::decode(&body).unwrap();
            assert_eq!(r.encode().unwrap(), body, "{name}");
        } else if name.starts_with("answer ") {
            let r = Response::decode(&body).unwrap();
            assert_eq!(r.encode().unwrap(), body, "{name}");
        } else if name == "hello client" {
            ClientHello::decode(&body).unwrap();
        } else {
            ServerHello::decode(&body).unwrap();
        }
        n += 1;
    }
    assert_eq!(n, 3 + all_requests().len() + all_responses().len());
}

#[test]
fn golden_covers_every_message_type() {
    let requests: BTreeSet<&str> = all_requests()
        .iter()
        .map(|(_, r)| r.request.name())
        .collect();
    assert_eq!(
        requests,
        [
            "status",
            "stage_begin",
            "put",
            "stage_commit",
            "apply",
            "attempt",
            "confirm",
            "rollback"
        ]
        .into_iter()
        .collect()
    );
    let answers: BTreeSet<&str> = all_responses().iter().map(|(_, r)| r.name()).collect();
    assert_eq!(
        answers,
        [
            "status",
            "stage_ready",
            "no_update",
            "put_ok",
            "progress",
            "staged",
            "need_fetch",
            "applied",
            "attempt",
            "confirmed",
            "nothing_pending",
            "rolled_back",
            "error"
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn every_message_round_trips() {
    for (name, r) in all_requests() {
        assert_eq!(
            RequestMsg::decode(&r.encode().unwrap()).unwrap(),
            r,
            "{name}"
        );
    }
    for (name, r) in all_responses() {
        assert_eq!(Response::decode(&r.encode().unwrap()).unwrap(), r, "{name}");
    }
}

/// The member names of every message, collected from the golden encodings: a closed list with no
/// path, OS error text, install id, token digest or key material.
#[test]
fn no_message_carries_forbidden_members() {
    fn walk(value: &serde_json::Value, names: &mut BTreeSet<String>) {
        match value {
            serde_json::Value::Object(m) => {
                for (k, v) in m {
                    names.insert(k.clone());
                    walk(v, names);
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|v| walk(v, names)),
            _ => {}
        }
    }
    let mut names = BTreeSet::new();
    for (_, frame) in golden_entries() {
        if frame[4] == KIND_MESSAGE {
            walk(&serde_json::from_slice(&frame[5..]).unwrap(), &mut names);
        }
    }
    let expected: BTreeSet<String> = [
        "app",
        "attempts",
        "bytes",
        "channel",
        "class",
        "code",
        "current",
        "documents",
        "done",
        "kind",
        "max",
        "min",
        "more",
        "outcome",
        "paths",
        "pending",
        "previous",
        "self_update_disabled",
        "service",
        "sha256",
        "size",
        "staged",
        "token",
        "total",
        "type",
        "version",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(names, expected);
}

#[test]
fn the_closed_sets_are_listed() {
    let codes: Vec<&str> = ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(
        codes,
        [
            "malformed",
            "wrong_app",
            "busy",
            "disabled_by_policy",
            "not_protected",
            "verify_failed",
            "channel_not_allowed",
            "not_in_manifest",
            "size_mismatch",
            "hash_mismatch",
            "publisher_mismatch",
            "pending_exists",
            "nothing_staged",
            "version_mismatch",
            "not_pending",
            "token_mismatch",
            "bad_full",
            "too_large",
            "timeout",
            "internal"
        ]
    );
    for c in ErrorCode::ALL {
        // Exhaustive: a new variant fails to compile here until it is listed above.
        match c {
            ErrorCode::Malformed
            | ErrorCode::WrongApp
            | ErrorCode::Busy
            | ErrorCode::DisabledByPolicy
            | ErrorCode::NotProtected
            | ErrorCode::VerifyFailed
            | ErrorCode::ChannelNotAllowed
            | ErrorCode::NotInManifest
            | ErrorCode::SizeMismatch
            | ErrorCode::HashMismatch
            | ErrorCode::PublisherMismatch
            | ErrorCode::PendingExists
            | ErrorCode::NothingStaged
            | ErrorCode::VersionMismatch
            | ErrorCode::NotPending
            | ErrorCode::TokenMismatch
            | ErrorCode::BadFull
            | ErrorCode::TooLarge
            | ErrorCode::Timeout
            | ErrorCode::Internal => {}
        }
        assert_eq!(ErrorCode::from_wire(c.as_str()), Some(*c));
    }
    let classes: Vec<&str> = VerifyClass::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(
        classes,
        [
            "signature",
            "expired",
            "rollback",
            "hash",
            "format",
            "app_mismatch"
        ]
    );
    for c in VerifyClass::ALL {
        match c {
            VerifyClass::Signature
            | VerifyClass::Expired
            | VerifyClass::Rollback
            | VerifyClass::Hash
            | VerifyClass::Format
            | VerifyClass::AppMismatch => {}
        }
        assert_eq!(VerifyClass::from_wire(c.as_str()), Some(*c));
    }
}

#[test]
fn an_error_class_goes_with_verify_failed_only() {
    let bare = Response::Error {
        code: ErrorCode::VerifyFailed,
        class: None,
    };
    assert!(matches!(bare.encode(), Err(ServiceError::Unencodable(_))));
    let extra = Response::Error {
        code: ErrorCode::Busy,
        class: Some(VerifyClass::Hash),
    };
    assert!(matches!(extra.encode(), Err(ServiceError::Unencodable(_))));
    for body in [
        r#"{"type":"error","code":"verify_failed"}"#,
        r#"{"type":"error","code":"busy","class":"hash"}"#,
        r#"{"type":"error","code":"no_such_code"}"#,
        r#"{"type":"error","code":"verify_failed","class":"no_such_class"}"#,
    ] {
        assert!(
            matches!(
                Response::decode(body.as_bytes()),
                Err(ServiceError::Malformed(_))
            ),
            "{body}"
        );
    }
}

#[test]
fn the_token_is_not_shown_by_debug() {
    let shown = format!("{:?}", token());
    assert!(!shown.contains("ab"), "{shown}");
    let applied = format!(
        "{:?}",
        Response::Applied {
            version: v("1.0.0"),
            token: token()
        }
    );
    assert!(!applied.contains(&token().to_hex()));
}

// ---- frames --------------------------------------------------------------------------------------

/// A reader that serves `head` and then fails the test if anything more is read.
struct HeadOnly(Cursor<Vec<u8>>);

impl Read for HeadOnly {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.0.read(buf)?;
        assert!(n > 0, "read past the frame head");
        Ok(n)
    }
}

fn head(n: u32, kind: Option<u8>) -> Vec<u8> {
    let mut h = n.to_le_bytes().to_vec();
    h.extend(kind);
    h
}

#[test]
fn frame_bounds_are_refused_before_the_body() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("n = 0", head(0, None)),
        ("over every cap", head(u32::MAX, None)),
        ("one above the data cap", head((MAX_DATA + 2) as u32, None)),
        (
            "a message one above its cap",
            head((MAX_MESSAGE + 2) as u32, Some(KIND_MESSAGE)),
        ),
        ("kind 0", head(10, Some(0))),
        ("kind 3", head(10, Some(3))),
        ("an empty message", head(1, Some(KIND_MESSAGE))),
        ("an empty data frame", head(1, Some(KIND_DATA))),
    ];
    for (what, bytes) in cases {
        let r = read_frame(&mut HeadOnly(Cursor::new(bytes)));
        assert!(
            matches!(r, Err(ServiceError::Malformed(_))),
            "{what}: {r:?}"
        );
    }
}

#[test]
fn frame_caps_are_inclusive() {
    let big = vec![b'x'; MAX_DATA];
    let frame = encode_frame(KIND_DATA, &big).unwrap();
    assert_eq!(
        read_frame(&mut Cursor::new(frame)).unwrap(),
        Some(Frame::Data(big))
    );
    assert!(encode_frame(KIND_DATA, &vec![0; MAX_DATA + 1]).is_err());
    assert!(encode_frame(KIND_MESSAGE, &vec![b' '; MAX_MESSAGE + 1]).is_err());
    assert!(encode_frame(KIND_DATA, &[]).is_err());
    assert!(encode_frame(3, b"x").is_err());
}

#[test]
fn a_channel_ending_inside_a_frame_is_malformed() {
    let full = raw_msg(r#"{"type":"status","app":"org.example.hello"}"#);
    assert_eq!(read_frame(&mut Cursor::new(Vec::new())).unwrap(), None);
    for cut in 1..full.len() {
        let r = read_frame(&mut Cursor::new(full[..cut].to_vec()));
        assert!(matches!(r, Err(ServiceError::Malformed(_))), "cut {cut}");
    }
}

// ---- malformed messages --------------------------------------------------------------------------

#[test]
fn malformed_requests_end_the_session() {
    let bad: Vec<(&str, Vec<u8>)> = vec![
        ("not UTF-8", msg(b"{\"type\":\"status\",\"app\":\"\xff\"}")),
        ("not JSON", raw_msg("status")),
        ("not an object", raw_msg("[1]")),
        (
            "duplicate key",
            raw_msg(r#"{"type":"status","app":"org.example.hello","app":"org.example.hello"}"#),
        ),
        (
            "unknown member",
            raw_msg(r#"{"type":"status","app":"org.example.hello","x":1}"#),
        ),
        ("missing app", raw_msg(r#"{"type":"status"}"#)),
        (
            "missing version",
            raw_msg(r#"{"type":"apply","app":"org.example.hello"}"#),
        ),
        (
            "wrong type",
            raw_msg(r#"{"type":"apply","app":"org.example.hello","version":1}"#),
        ),
        (
            "unknown type",
            raw_msg(r#"{"type":"install","app":"org.example.hello"}"#),
        ),
        (
            "bad version",
            raw_msg(r#"{"type":"apply","app":"org.example.hello","version":"1.0"}"#),
        ),
        (
            "bad app id",
            raw_msg(r#"{"type":"status","app":"Org.Example"}"#),
        ),
        (
            "bad channel",
            raw_msg(
                r#"{"type":"stage_begin","app":"org.example.hello","channel":"Stable","documents":[{"kind":"keys","bytes":1},{"kind":"feed","bytes":1},{"kind":"manifest","bytes":1}]}"#,
            ),
        ),
        (
            "uppercase digest",
            raw_msg(&format!(
                r#"{{"type":"put","app":"org.example.hello","kind":"pack","sha256":"{}","size":1}}"#,
                "AB".repeat(32)
            )),
        ),
        (
            "integer above 2^53 - 1",
            raw_msg(&format!(
                r#"{{"type":"put","app":"org.example.hello","kind":"pack","sha256":"{}","size":9007199254740992}}"#,
                "ab".repeat(32)
            )),
        ),
        (
            "negative integer",
            raw_msg(&format!(
                r#"{{"type":"put","app":"org.example.hello","kind":"pack","sha256":"{}","size":-1}}"#,
                "ab".repeat(32)
            )),
        ),
        (
            "fractional integer",
            raw_msg(&format!(
                r#"{{"type":"put","app":"org.example.hello","kind":"pack","sha256":"{}","size":1.5}}"#,
                "ab".repeat(32)
            )),
        ),
        (
            "unknown object kind",
            raw_msg(&format!(
                r#"{{"type":"put","app":"org.example.hello","kind":"file","sha256":"{}","size":1}}"#,
                "ab".repeat(32)
            )),
        ),
        (
            "token of 63 characters",
            raw_msg(&format!(
                r#"{{"type":"confirm","app":"org.example.hello","version":"1.0.0","token":"{}"}}"#,
                &"ab".repeat(32)[..63]
            )),
        ),
        (
            "uppercase token",
            raw_msg(&format!(
                r#"{{"type":"rollback","app":"org.example.hello","version":"1.0.0","token":"{}"}}"#,
                "AB".repeat(32)
            )),
        ),
        ("a data frame", encode_frame(KIND_DATA, b"x").unwrap()),
        ("a second hello", client_hello()),
        // M12-D6: `patch` is a kind of version 2; this session speaks version 1.
        (
            "a patch in a version-1 session",
            raw_msg(&format!(
                r#"{{"type":"put","app":"org.example.hello","kind":"patch","sha256":"{}","size":1}}"#,
                "ab".repeat(32)
            )),
        ),
    ];
    for (what, frame) in bad {
        let (r, script) = first_request(std::slice::from_ref(&frame));
        assert!(
            matches!(r, Err(ServiceError::Malformed(_))),
            "{what}: {r:?}"
        );
        assert_eq!(
            script.answers().last(),
            Some(&Response::error(ErrorCode::Malformed)),
            "{what}"
        );
    }
}

#[test]
fn a_session_ends_after_malformed() {
    let mut s = server_over(with_hello(&[
        raw_msg("[]"),
        raw_msg(r#"{"type":"status","app":"org.example.hello"}"#),
    ]))
    .unwrap();
    assert!(matches!(s.next_request(), Err(ServiceError::Malformed(_))));
    assert_eq!(s.next_request(), Err(ServiceError::Ended));
    assert_eq!(
        s.reply(&Response::PutOk),
        Err(ServiceError::Ended),
        "nothing more is written"
    );
}

#[test]
fn another_app_is_wrong_app_and_ends() {
    let (r, script) = first_request(&[raw_msg(r#"{"type":"status","app":"org.example.other"}"#)]);
    assert_eq!(r, Err(ServiceError::WrongApp));
    assert_eq!(r.unwrap_err().code(), ErrorCode::WrongApp);
    assert_eq!(script.answers(), vec![Response::error(ErrorCode::WrongApp)]);
}

#[test]
fn malformed_answers_are_refused() {
    for body in [
        r#"{"type":"status","current":"1.0.0","previous":null,"pending":null,"staged":null,"service":"1.0.0"}"#,
        r#"{"type":"status","current":"1.0.0","previous":null,"pending":{"version":"1.1.0"},"staged":null,"service":"1.0.0","self_update_disabled":false}"#,
        r#"{"type":"progress","done":4,"total":3}"#,
        r#"{"type":"put_ok","x":true}"#,
        r#"{"type":"applied","version":"1.1.0","token":"ab"}"#,
        r#"{"type":"attempt","outcome":"counted","attempts":1}"#,
        r#"{"type":"attempt","outcome":"maybe"}"#,
        r#"{"type":"need_fetch","paths":["../x"],"more":false}"#,
        r#"{"type":"need_fetch","paths":[1],"more":false}"#,
        r#"{"type":"bogus"}"#,
    ] {
        assert!(
            matches!(
                Response::decode(body.as_bytes()),
                Err(ServiceError::Malformed(_))
            ),
            "{body}"
        );
    }
    let many: Vec<String> = (0..65).map(|i| format!("\"f{i}\"")).collect();
    let body = format!(
        r#"{{"type":"need_fetch","paths":[{}],"more":true}}"#,
        many.join(",")
    );
    assert!(Response::decode(body.as_bytes()).is_err());
    let paths: Vec<RelPath> = (0..65)
        .map(|i| RelPath::parse(&format!("f{i}")).unwrap())
        .collect();
    assert!(
        Response::NeedFetch { paths, more: true }.encode().is_err(),
        "65 paths have no encoding"
    );
}

// ---- negotiation ---------------------------------------------------------------------------------

#[test]
fn negotiation_picks_the_highest_common_version() {
    let n = |min, max| negotiate(ClientHello { min, max }, 1, 1);
    assert_eq!(n(1, 1), Ok(ServerHello::Version(1)));
    assert_eq!(n(1, 5), Ok(ServerHello::Version(1)));
    assert_eq!(n(0, 1), Ok(ServerHello::Version(1)));
    assert_eq!(n(2, 3), Ok(ServerHello::Unsupported { min: 1, max: 1 }));
    assert!(matches!(n(3, 2), Err(ServiceError::Malformed(_))));
    assert_eq!(
        negotiate(ClientHello { min: 1, max: 4 }, 2, 3),
        Ok(ServerHello::Version(3))
    );
}

#[test]
fn a_client_offering_three_to_four_gets_unsupported_one_to_two() {
    let input = msg(&ClientHello { min: 3, max: 4 }.encode().unwrap());
    let script = Script::new(input);
    let r = ServerSession::accept(script, app());
    assert_eq!(r.err(), Some(ServiceError::Unsupported { min: 3, max: 4 }));
    // The server's answer, read by a client that offered 2..=3.
    let mut client_in = msg(&ServerHello::Unsupported { min: 1, max: 1 }
        .encode()
        .unwrap());
    let c = ClientSession::connect_range(
        Script::new(std::mem::take(&mut client_in)),
        app(),
        no_timeouts(),
        2,
        3,
    );
    assert_eq!(c.err(), Some(ServiceError::Unsupported { min: 1, max: 1 }));
}

#[test]
fn the_server_writes_unsupported_with_its_range() {
    let input = msg(&ClientHello { min: 3, max: 4 }.encode().unwrap());
    let mut script = Script::new(input);
    // Accept consumes the script; check the bytes through a second run on a shared buffer.
    let _ = ServerSession::accept(&mut script as &mut Script, app());
    let mut out = Cursor::new(script.output.clone());
    let Some(Frame::Message(body)) = read_frame(&mut out).unwrap() else {
        panic!("no answer")
    };
    assert_eq!(
        ServerHello::decode(&body).unwrap(),
        ServerHello::Unsupported { min: 1, max: 2 }
    );
    assert_eq!(read_frame(&mut out).unwrap(), None, "and nothing else");
}

impl Duplex for &mut Script {
    fn set_read_deadline(&mut self, deadline: Option<Duration>) -> io::Result<()> {
        (**self).set_read_deadline(deadline)
    }
}

#[test]
fn a_malformed_hello_closes_without_an_answer() {
    for input in [
        msg(&raw_msg(r#"{"type":"hello","min":3,"max":2}"#)[5..]),
        raw_msg(r#"{"type":"hello","min":1,"max":1,"x":0}"#),
        raw_msg(r#"{"type":"hello","min":1}"#),
        raw_msg(r#"{"type":"hello","min":1,"max":4294967296}"#),
        raw_msg(r#"{"type":"status","app":"org.example.hello"}"#),
        encode_frame(KIND_DATA, b"data before hello").unwrap(),
    ] {
        let mut script = Script::new(input);
        let r = ServerSession::accept(&mut script as &mut Script, app());
        assert!(matches!(r.err(), Some(ServiceError::Malformed(_))));
        assert!(script.output.is_empty());
    }
    assert_eq!(
        server_over(Vec::new()).err(),
        Some(ServiceError::Closed),
        "no hello at all"
    );
}

#[test]
fn a_client_refuses_a_version_it_did_not_offer() {
    let c = ClientSession::connect_range(
        Script::new(msg(&ServerHello::Version(2).encode().unwrap())),
        app(),
        no_timeouts(),
        1,
        1,
    );
    assert!(matches!(c.err(), Some(ServiceError::Malformed(_))));
}

// ---- read_data -----------------------------------------------------------------------------------

/// A sink that records the size of every write.
#[derive(Default)]
struct Chunks {
    sizes: Vec<usize>,
    bytes: Vec<u8>,
}

impl Write for Chunks {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sizes.push(buf.len());
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn put_request(size: u64) -> Vec<u8> {
    msg(&req(Request::Put {
        kind: ObjectKind::Frame,
        sha256: digest(),
        size,
    })
    .encode()
    .unwrap())
}

fn data(bytes: &[u8]) -> Vec<u8> {
    encode_frame(KIND_DATA, bytes).unwrap()
}

#[test]
fn read_data_takes_exactly_total_one_frame_at_a_time() {
    let mut s = server_over(with_hello(&[
        put_request(10),
        data(b"abcd"),
        data(b"efghij"),
        raw_msg(r#"{"type":"status","app":"org.example.hello"}"#),
    ]))
    .unwrap();
    let r = s.next_request().unwrap().unwrap();
    assert_eq!(r.data_len(), 10);
    let mut sink = Chunks::default();
    s.read_data(10, &mut sink).unwrap();
    assert_eq!(sink.bytes, b"abcdefghij");
    assert_eq!(
        sink.sizes,
        vec![4, 6],
        "one write per frame, nothing buffered"
    );
    s.reply(&Response::PutOk).unwrap();
    assert_eq!(s.next_request().unwrap(), Some(Request::Status));
    assert_eq!(s.next_request().unwrap(), None, "closed between requests");
}

#[test]
fn read_data_refuses_anything_but_exactly_total() {
    let status = raw_msg(r#"{"type":"status","app":"org.example.hello"}"#);
    let cases: Vec<(&str, Vec<Vec<u8>>)> = vec![
        (
            "a message in between",
            vec![put_request(10), data(b"abcd"), status.clone()],
        ),
        ("a shorter stream", vec![put_request(10), data(b"abcd")]),
        (
            "one byte more in the last frame",
            vec![put_request(10), data(b"abcd"), data(b"efghijk")],
        ),
    ];
    for (what, frames) in cases {
        let mut s = server_over(with_hello(&frames)).unwrap();
        s.next_request().unwrap().unwrap();
        let r = s.read_data(10, &mut Chunks::default());
        assert!(
            matches!(r, Err(ServiceError::Malformed(_))),
            "{what}: {r:?}"
        );
        let script = s.into_inner();
        assert_eq!(
            script.answers().last(),
            Some(&Response::error(ErrorCode::Malformed)),
            "{what}"
        );
    }
    // One byte more as its own frame: the next read finds data where a request belongs.
    let mut s = server_over(with_hello(&[put_request(4), data(b"abcd"), data(b"e")])).unwrap();
    s.next_request().unwrap().unwrap();
    s.read_data(4, &mut Chunks::default()).unwrap();
    s.reply(&Response::PutOk).unwrap();
    assert!(matches!(s.next_request(), Err(ServiceError::Malformed(_))));
}

/// A sink that fails.
struct Full;

impl Write for Full {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(ErrorKind::StorageFull))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_failing_sink_allows_one_answer() {
    let mut s = server_over(with_hello(&[put_request(4), data(b"abcd")])).unwrap();
    s.next_request().unwrap().unwrap();
    assert_eq!(
        s.read_data(4, &mut Full),
        Err(ServiceError::Sink(ErrorKind::StorageFull))
    );
    assert_eq!(s.next_request(), Err(ServiceError::Ended));
    s.reply(&Response::error(ErrorCode::TooLarge)).unwrap();
    assert_eq!(s.reply(&Response::PutOk), Err(ServiceError::Ended));
}

// ---- stage_begin's documents ---------------------------------------------------------------------

fn decl(kind: DocumentKind, bytes: u64) -> DocumentDecl {
    DocumentDecl { kind, bytes }
}

fn stage_begin_body(documents: &[DocumentDecl]) -> Vec<u8> {
    let list: Vec<String> = documents
        .iter()
        .map(|d| format!(r#"{{"kind":"{}","bytes":{}}}"#, d.kind, d.bytes))
        .collect();
    raw_msg(&format!(
        r#"{{"type":"stage_begin","app":"org.example.hello","channel":"stable","documents":[{}]}}"#,
        list.join(",")
    ))
}

fn tail() -> Vec<DocumentDecl> {
    vec![
        decl(DocumentKind::Keys, 1),
        decl(DocumentKind::Feed, 1),
        decl(DocumentKind::Manifest, 1),
    ]
}

#[test]
fn the_document_count_rule_and_caps_hold_before_any_data() {
    use DocumentKind::*;
    let roots = |n: usize| -> Vec<DocumentDecl> {
        let mut d: Vec<DocumentDecl> = (0..n).map(|_| decl(Root, 10)).collect();
        d.extend(tail());
        d
    };
    assert_eq!(check_documents(&tail()), Ok(()));
    assert_eq!(check_documents(&roots(16)), Ok(()));
    let limits = lunepack_core::Limits::V1;
    let caps = vec![
        decl(Root, limits.root_doc_bytes),
        decl(Keys, limits.keys_doc_bytes),
        decl(Feed, limits.feed_doc_bytes),
        decl(Manifest, limits.manifest_doc_bytes),
    ];
    assert_eq!(check_documents(&caps), Ok(()));
    let bad: Vec<(&str, Vec<DocumentDecl>)> = vec![
        ("17 roots", roots(17)),
        ("none", vec![]),
        ("no manifest", tail()[..2].to_vec()),
        (
            "two keys",
            vec![
                decl(Keys, 1),
                decl(Keys, 1),
                decl(Feed, 1),
                decl(Manifest, 1),
            ],
        ),
        (
            "feed before keys",
            vec![decl(Feed, 1), decl(Keys, 1), decl(Manifest, 1)],
        ),
        (
            "a root after keys",
            vec![
                decl(Keys, 1),
                decl(Root, 1),
                decl(Feed, 1),
                decl(Manifest, 1),
            ],
        ),
        (
            "something after the manifest",
            vec![
                decl(Keys, 1),
                decl(Feed, 1),
                decl(Manifest, 1),
                decl(Manifest, 1),
            ],
        ),
        (
            "an empty document",
            vec![decl(Keys, 0), decl(Feed, 1), decl(Manifest, 1)],
        ),
        (
            "a root over its cap",
            vec![
                decl(Root, limits.root_doc_bytes + 1),
                decl(Keys, 1),
                decl(Feed, 1),
                decl(Manifest, 1),
            ],
        ),
        (
            "keys over the cap",
            vec![
                decl(Keys, limits.keys_doc_bytes + 1),
                decl(Feed, 1),
                decl(Manifest, 1),
            ],
        ),
        (
            "a feed over its cap",
            vec![
                decl(Keys, 1),
                decl(Feed, limits.feed_doc_bytes + 1),
                decl(Manifest, 1),
            ],
        ),
        (
            "a manifest over its cap",
            vec![
                decl(Keys, 1),
                decl(Feed, 1),
                decl(Manifest, limits.manifest_doc_bytes + 1),
            ],
        ),
    ];
    for (what, documents) in bad {
        assert!(check_documents(&documents).is_err(), "{what}");
        // The server refuses the request itself: no data frame follows, and the error is not
        // "the data ended early".
        let (r, _) = first_request(&[stage_begin_body(&documents)]);
        assert!(
            matches!(r, Err(ServiceError::Malformed(_))),
            "{what}: {r:?}"
        );
        let encoded = req(Request::StageBegin {
            channel: Channel::parse("stable").unwrap(),
            documents,
        })
        .encode();
        assert!(encoded.is_err(), "{what}: the writer refuses it too");
    }
    let (r, _) = first_request(&[stage_begin_body(&roots(2))]);
    assert_eq!(r.unwrap().unwrap().data_len(), 23);
}

#[test]
fn malformed_helper_checks_the_answer() {
    assert_malformed(&[raw_msg(
        r#"{"type":"status","app":"org.example.hello","more":1}"#,
    )]);
}

// ---- deadlines -----------------------------------------------------------------------------------

#[test]
fn the_server_sets_its_deadlines_and_reads_no_clock() {
    let mut s = server_over(with_hello(&[put_request(2), data(b"a"), data(b"b")])).unwrap();
    s.next_request().unwrap().unwrap();
    s.read_data(2, &mut Chunks::default()).unwrap();
    s.reply(&Response::PutOk).unwrap();
    assert_eq!(s.next_request().unwrap(), None);
    assert_eq!(
        s.into_inner().deadlines,
        vec![
            Some(SERVER_HELLO_DEADLINE),
            Some(SERVER_FRAME_DEADLINE),
            Some(SERVER_FRAME_DEADLINE),
            Some(SERVER_FRAME_DEADLINE),
            Some(SERVER_FRAME_DEADLINE),
        ]
    );
    assert_eq!(SERVER_HELLO_DEADLINE, Duration::from_secs(5));
    assert_eq!(SERVER_FRAME_DEADLINE, Duration::from_secs(30));
}

#[test]
fn a_timed_out_read_is_timeout_and_ends_the_session() {
    let input = with_hello(&[put_request(4)]);
    let hello_len = client_hello().len() as u64;
    // During the next request.
    let mut script = Script::new(input.clone());
    script.time_out_at = Some(hello_len);
    let mut s = ServerSession::accept(script, app()).unwrap();
    let e = s.next_request().unwrap_err();
    assert_eq!(e, ServiceError::Timeout);
    assert_eq!(e.code(), ErrorCode::Timeout);
    assert_eq!(s.next_request(), Err(ServiceError::Ended));
    assert_eq!(
        s.into_inner().answers(),
        vec![Response::error(ErrorCode::Timeout)]
    );
    // During data.
    let mut script = Script::new(input.clone());
    script.time_out_at = Some(input.len() as u64);
    let mut s = ServerSession::accept(script, app()).unwrap();
    s.next_request().unwrap().unwrap();
    assert_eq!(
        s.read_data(4, &mut Chunks::default()),
        Err(ServiceError::Timeout)
    );
    // During the hello.
    let mut script = Script::new(input);
    script.time_out_at = Some(0);
    assert_eq!(
        ServerSession::accept(script, app()).err(),
        Some(ServiceError::Timeout)
    );
}

// ---- client and server over a threaded channel ---------------------------------------------------

/// One end of an in-memory duplex built on channels; a deadline bounds each wait.
struct Pipe {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
    deadline: Option<Duration>,
}

fn pipe_pair() -> (Pipe, Pipe) {
    let (a_tx, b_rx) = mpsc::channel();
    let (b_tx, a_rx) = mpsc::channel();
    let end = |tx, rx| Pipe {
        tx,
        rx,
        buf: Vec::new(),
        pos: 0,
        deadline: None,
    };
    (end(a_tx, a_rx), end(b_tx, b_rx))
}

impl Read for Pipe {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos == self.buf.len() {
            let next = match self.deadline {
                Some(d) => self.rx.recv_timeout(d).map_err(|e| match e {
                    RecvTimeoutError::Timeout => io::Error::from(ErrorKind::TimedOut),
                    RecvTimeoutError::Disconnected => io::Error::from(ErrorKind::UnexpectedEof),
                }),
                None => self
                    .rx
                    .recv()
                    .map_err(|_| io::Error::from(ErrorKind::UnexpectedEof)),
            };
            match next {
                Ok(chunk) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx
            .send(buf.to_vec())
            .map_err(|_| io::Error::from(ErrorKind::BrokenPipe))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Duplex for Pipe {
    fn set_read_deadline(&mut self, deadline: Option<Duration>) -> io::Result<()> {
        self.deadline = deadline;
        Ok(())
    }
}

fn no_timeouts() -> ClientTimeouts {
    ClientTimeouts {
        hello: None,
        answer: None,
    }
}

fn timeouts() -> ClientTimeouts {
    ClientTimeouts {
        hello: Some(Duration::from_secs(10)),
        answer: Some(Duration::from_secs(10)),
    }
}

/// A fake server that answers every request with a fixed reply and records what it read.
fn serve(end: Pipe) -> thread::JoinHandle<Vec<(Request, Vec<u8>)>> {
    thread::spawn(move || {
        let mut s = ServerSession::accept(end, app()).expect("hello");
        let mut seen = Vec::new();
        while let Ok(Some(request)) = s.next_request() {
            let mut sink = Vec::new();
            s.read_data(request.data_len(), &mut sink).expect("data");
            let answers: Vec<Response> = match &request {
                Request::Status => vec![Response::Status(status_full())],
                Request::StageBegin { .. } => vec![Response::StageReady {
                    version: v("1.1.0"),
                }],
                Request::Put { size, .. } if *size == 3 => {
                    vec![Response::Error {
                        code: ErrorCode::VerifyFailed,
                        class: Some(VerifyClass::Hash),
                    }]
                }
                Request::Put { .. } => vec![Response::PutOk],
                Request::StageCommit => vec![
                    Response::Progress { done: 1, total: 2 },
                    Response::Progress { done: 2, total: 2 },
                    Response::Staged {
                        version: v("1.1.0"),
                    },
                ],
                Request::Apply { version } => vec![Response::Applied {
                    version: version.clone(),
                    token: token(),
                }],
                Request::Attempt { .. } => vec![Response::Attempt(AttemptAnswer::Supervised)],
                Request::Confirm { .. } => vec![Response::Confirmed],
                Request::Rollback { .. } => vec![Response::RolledBack {
                    current: v("1.0.0"),
                }],
            };
            for a in &answers {
                s.reply(a).expect("reply");
            }
            seen.push((request, sink));
        }
        seen
    })
}

#[test]
fn a_whole_conversation_over_a_duplex() {
    let (client_end, server_end) = pipe_pair();
    let server = serve(server_end);
    let mut c = ClientSession::connect(client_end, app(), timeouts()).unwrap();
    assert_eq!(c.version(), 2);
    assert_eq!(c.status().unwrap(), status_full());
    let manifest = vec![7u8; MAX_DATA + 10];
    let documents = [
        OutgoingDocument {
            kind: DocumentKind::Keys,
            bytes: b"keys",
        },
        OutgoingDocument {
            kind: DocumentKind::Feed,
            bytes: b"feed",
        },
        OutgoingDocument {
            kind: DocumentKind::Manifest,
            bytes: &manifest,
        },
    ];
    let channel = Channel::parse("stable").unwrap();
    assert_eq!(
        c.stage_begin(&channel, &documents).unwrap(),
        StageBegun::Ready(v("1.1.0"))
    );
    let pack = vec![9u8; 1024 * 1024];
    c.put(
        ObjectKind::Pack,
        digest(),
        pack.len() as u64,
        &mut &pack[..],
    )
    .unwrap();
    assert_eq!(
        c.put(ObjectKind::Frame, digest(), 3, &mut &b"xyz"[..]),
        Err(ServiceError::Answered {
            code: ErrorCode::VerifyFailed,
            class: Some(VerifyClass::Hash)
        })
    );
    let mut seen = Vec::new();
    assert_eq!(
        c.stage_commit(&mut |d, t| seen.push((d, t))).unwrap(),
        CommitOutcome::Staged(v("1.1.0"))
    );
    assert_eq!(seen, vec![(1, 2), (2, 2)]);
    assert_eq!(c.apply(&v("1.1.0")).unwrap(), token());
    assert_eq!(c.attempt(&v("1.1.0")).unwrap(), AttemptAnswer::Supervised);
    assert_eq!(
        c.confirm(&v("1.1.0"), &token()).unwrap(),
        ConfirmAnswer::Confirmed
    );
    assert_eq!(c.rollback(&v("1.1.0"), &token()).unwrap(), v("1.0.0"));
    drop(c);
    let seen = server.join().unwrap();
    let names: Vec<&str> = seen.iter().map(|(r, _)| r.name()).collect();
    assert_eq!(
        names,
        [
            "status",
            "stage_begin",
            "put",
            "put",
            "stage_commit",
            "apply",
            "attempt",
            "confirm",
            "rollback"
        ]
    );
    let mut concatenated = b"keysfeed".to_vec();
    concatenated.extend_from_slice(&manifest);
    assert_eq!(seen[1].1, concatenated, "documents in the declared order");
    assert_eq!(seen[2].1, pack);
}

#[test]
fn a_client_with_a_short_source_ends_its_session() {
    let (client_end, server_end) = pipe_pair();
    let server = thread::spawn(move || {
        let mut s = ServerSession::accept(server_end, app()).unwrap();
        s.next_request().unwrap();
        s.read_data(10, &mut Vec::new())
    });
    let mut c = ClientSession::connect(client_end, app(), timeouts()).unwrap();
    assert_eq!(
        c.put(ObjectKind::Pack, digest(), 10, &mut &b"short"[..]),
        Err(ServiceError::Source(ErrorKind::UnexpectedEof))
    );
    assert_eq!(c.status(), Err(ServiceError::Ended));
    drop(c);
    assert!(matches!(
        server.join().unwrap(),
        Err(ServiceError::Malformed(_))
    ));
}

#[test]
fn a_client_times_out_through_its_deadline() {
    let (client_end, server_end) = pipe_pair();
    let server = thread::spawn(move || {
        let s = ServerSession::accept(server_end, app()).unwrap();
        // Hold the connection without answering until the client has given up.
        thread::sleep(Duration::from_millis(300));
        drop(s);
    });
    let mut c = ClientSession::connect(
        client_end,
        app(),
        ClientTimeouts {
            hello: Some(Duration::from_secs(10)),
            answer: Some(Duration::from_millis(50)),
        },
    )
    .unwrap();
    let e = c.status().unwrap_err();
    assert_eq!(e, ServiceError::Timeout);
    assert_eq!(e.code(), ErrorCode::Timeout);
    assert_eq!(c.status(), Err(ServiceError::Ended));
    server.join().unwrap();
}

#[test]
fn a_client_refuses_an_answer_that_does_not_fit() {
    let mut input = server_hello();
    input.extend(msg(&Response::PutOk.encode().unwrap()));
    let mut c = ClientSession::connect(Script::new(input), app(), no_timeouts()).unwrap();
    assert!(matches!(c.status(), Err(ServiceError::Malformed(_))));
    assert_eq!(c.status(), Err(ServiceError::Ended));
    // An applied answer for another version.
    let mut input = server_hello();
    input.extend(msg(&Response::Applied {
        version: v("9.9.9"),
        token: token(),
    }
    .encode()
    .unwrap()));
    let mut c = ClientSession::connect(Script::new(input), app(), no_timeouts()).unwrap();
    assert!(matches!(
        c.apply(&v("1.1.0")),
        Err(ServiceError::Malformed(_))
    ));
    // Data from the server.
    let mut input = server_hello();
    input.extend(data(b"x"));
    let mut c = ClientSession::connect(Script::new(input), app(), no_timeouts()).unwrap();
    assert!(matches!(c.status(), Err(ServiceError::Malformed(_))));
}

// ---- the fuzz harness ----------------------------------------------------------------------------

fn harness(side: u8, frames: &[Vec<u8>]) -> bool {
    let mut input = vec![side];
    for f in frames {
        input.extend_from_slice(f);
    }
    lunepack_core::fuzz::accepts("service", &input).expect("the service harness")
}

#[test]
fn the_harness_accepts_exactly_valid_streams() {
    let roots = |n: usize| {
        let mut d: Vec<DocumentDecl> = (0..n).map(|_| decl(DocumentKind::Root, 1)).collect();
        d.extend(tail());
        stage_begin_body(&d)
    };
    let confirm = |t: &str| {
        raw_msg(&format!(
            r#"{{"type":"confirm","app":"org.example.hello","version":"1.0.0","token":"{t}"}}"#
        ))
    };
    let hex64 = "ab".repeat(32);
    assert!(harness(0, &[client_hello(), roots(16), data(&[0; 19])]));
    assert!(!harness(0, &[client_hello(), roots(17), data(&[0; 20])]));
    assert!(harness(0, &[client_hello(), confirm(&hex64)]));
    assert!(!harness(0, &[client_hello(), confirm(&hex64[..63])]));
    assert!(
        !harness(0, &[client_hello(), data(b"x")]),
        "data instead of a request"
    );
    assert!(!harness(0, &[data(b"x")]), "data before the hello");
    let mut cut = with_hello(&[put_request(1), data(b"x")]);
    cut.pop();
    assert!(!harness(0, &[cut]), "a truncated frame");
    assert!(harness(
        1,
        &[server_hello(), msg(&Response::PutOk.encode().unwrap())]
    ));
    assert!(!harness(1, &[server_hello(), data(b"x")]));
    let unsupported = msg(&ServerHello::Unsupported { min: 1, max: 1 }
        .encode()
        .unwrap());
    assert!(harness(1, std::slice::from_ref(&unsupported)));
    assert!(
        !harness(1, &[unsupported, server_hello()]),
        "nothing may follow unsupported"
    );
    assert!(!harness(0, &[]));
}

// ---- version 2 (M12-D6) --------------------------------------------------------------------------

/// A client offering 1..=2 gets version 2 and may `put` a patch; a client limited to version 1
/// gets version 1 from this server, and its own `put` of a patch is refused before any byte is
/// sent; a server limited to version 1 answers a 1..=2 client with version 1.
#[test]
fn version_2_adds_put_of_a_patch_and_version_1_stays() {
    let sha = Sha256Digest::from_bytes([0xab; 32]);
    let put = req(Request::Put {
        kind: ObjectKind::Patch,
        sha256: sha,
        size: 1,
    })
    .encode()
    .unwrap();
    let mut input = msg(&ClientHello { min: 1, max: 2 }.encode().unwrap());
    input.extend_from_slice(&msg(&put));
    let mut s = ServerSession::accept(Script::new(input), app()).expect("hello");
    assert_eq!(s.version(), 2);
    assert_eq!(
        s.next_request(),
        Ok(Some(Request::Put {
            kind: ObjectKind::Patch,
            sha256: sha,
            size: 1
        }))
    );

    // A version-1 server (an older build) answers a 1..=2 client with version 1.
    let input = msg(&ClientHello { min: 1, max: 2 }.encode().unwrap());
    let s = ServerSession::accept_range(Script::new(input), app(), 1, 1).expect("hello");
    assert_eq!(s.version(), 1);

    // A client of version 1 never sends a patch: refused before a byte goes out.
    let mut c =
        ClientSession::connect_range(Script::new(server_hello()), app(), no_timeouts(), 1, 1)
            .expect("connect");
    assert_eq!(c.version(), 1);
    let r = c.put(ObjectKind::Patch, sha, 1, &mut &[0u8][..]);
    assert!(matches!(r, Err(ServiceError::Malformed(_))), "{r:?}");
    let script = c.into_inner();
    let hello_len = msg(&ClientHello { min: 1, max: 1 }.encode().unwrap()).len();
    assert_eq!(script.output.len(), hello_len, "only the hello was written");
}
