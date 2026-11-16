//! Step 2 contract: the UI port. Every message round-trips, every malformed frame is a typed
//! error, a frame cap is enforced before allocation, and the flow reducers accept only what the
//! open prompt and the screen allow.

use std::io::{Cursor, ErrorKind, Read};

use lunepack_core::progress::Phase;
use lunepack_core::ui::{
    AppCard, ChoiceValue, Details, EngineMsg, Flow, FlowState, MAX_FRAME, MAX_ICON_BYTES, Message,
    Outcome, PromptKind, ProtocolError, Screen, StepItem, UiMsg, build_id, check_hello, read_frame,
    write_frame,
};

fn card() -> AppCard {
    AppCard {
        name: "Lunegit".into(),
        version: "2.0.0".into(),
        from_version: None,
        publisher: None,
        icon_png: None,
    }
}

fn hello(flow: Flow) -> EngineMsg {
    EngineMsg::Hello {
        build_id: build_id(),
        flow,
        app: card(),
        details: Details {
            location: None,
            size_bytes: None,
        },
    }
}

fn frame(body: &str) -> Vec<u8> {
    let mut out = (body.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(body.as_bytes());
    out
}

fn read_engine(bytes: &[u8]) -> Result<EngineMsg, ProtocolError> {
    read_frame(&mut Cursor::new(bytes))
}

fn read_ui(bytes: &[u8]) -> Result<UiMsg, ProtocolError> {
    read_frame(&mut Cursor::new(bytes))
}

fn round_trip_engine(msg: &EngineMsg) {
    let mut wire = Vec::new();
    write_frame(&mut wire, msg).expect("write");
    let len = u32::from_le_bytes(wire[..4].try_into().unwrap()) as usize;
    assert_eq!(len, wire.len() - 4, "the prefix is the body length");
    assert_eq!(&read_engine(&wire).expect("read"), msg);
}

fn round_trip_ui(msg: &UiMsg) {
    let mut wire = Vec::new();
    write_frame(&mut wire, msg).expect("write");
    assert_eq!(&read_ui(&wire).expect("read"), msg);
}

// ---- codec ----

#[test]
fn every_engine_message_round_trips() {
    let full_hello = EngineMsg::Hello {
        build_id: build_id(),
        flow: Flow::Update,
        app: AppCard {
            name: "Lunegit".into(),
            version: "2.0.0".into(),
            from_version: Some("1.0.0".into()),
            publisher: Some("Acme".into()),
            icon_png: Some(vec![0x89, b'P', b'N', b'G', 0, 1, 2, 255]),
        },
        details: Details {
            location: Some("/home/u/.local/share/Lunegit".into()),
            size_bytes: Some(123_456_789),
        },
    };
    let mut msgs = vec![full_hello, hello(Flow::Install), hello(Flow::Uninstall)];
    for phase in [
        Phase::Check,
        Phase::Scan,
        Phase::Download,
        Phase::Stage,
        Phase::Install,
        Phase::Wait,
        Phase::Apply,
        Phase::Launch,
        Phase::Confirm,
        Phase::Rollback,
        Phase::Uninstall,
    ] {
        msgs.push(EngineMsg::Progress {
            phase,
            done: 10,
            total: 20,
        });
    }
    for item in [
        StepItem::Verify,
        StepItem::Stage,
        StepItem::Commit,
        StepItem::Integrate,
        StepItem::WaitApp,
        StepItem::Apply,
        StepItem::Launch,
        StepItem::Confirm,
        StepItem::Rollback,
        StepItem::Remove,
    ] {
        msgs.push(EngineMsg::Step { item });
    }
    for kind in [
        PromptKind::Welcome,
        PromptKind::Confirm,
        PromptKind::Done,
        PromptKind::Failed,
        PromptKind::RolledBack,
    ] {
        msgs.push(EngineMsg::Prompt { id: 7, kind });
    }
    msgs.push(EngineMsg::Cancellable(true));
    msgs.push(EngineMsg::Cancellable(false));
    for outcome in [
        Outcome::Installed,
        Outcome::Failed { code: 22 },
        Outcome::Cancelled,
        Outcome::Updated,
        Outcome::RolledBack {
            from: "2.0.0".into(),
            to: "1.0.0".into(),
        },
        Outcome::Uninstalled { leftovers: vec![] },
        Outcome::Uninstalled {
            leftovers: vec!["/a/b".into(), "/c".into()],
        },
        Outcome::UninstallFailed { code: 30 },
    ] {
        msgs.push(EngineMsg::Outcome(outcome));
    }
    msgs.push(EngineMsg::Ping { n: u32::MAX });
    msgs.push(EngineMsg::Close);
    for msg in &msgs {
        round_trip_engine(msg);
    }
}

#[test]
fn every_ui_message_round_trips() {
    for msg in [
        UiMsg::Hello {
            build_id: build_id(),
        },
        UiMsg::Cancel,
        UiMsg::Pong { n: 3 },
        UiMsg::Choice {
            id: 1,
            value: ChoiceValue::Proceed,
        },
        UiMsg::Choice {
            id: 1,
            value: ChoiceValue::Cancel,
        },
        UiMsg::Choice {
            id: 2,
            value: ChoiceValue::Finish { launch: true },
        },
        UiMsg::Choice {
            id: 2,
            value: ChoiceValue::Finish { launch: false },
        },
        UiMsg::Choice {
            id: 3,
            value: ChoiceValue::Retry,
        },
        UiMsg::Choice {
            id: 3,
            value: ChoiceValue::Close,
        },
        UiMsg::Choice {
            id: 4,
            value: ChoiceValue::Reveal { index: 63 },
        },
        UiMsg::Choice {
            id: 5,
            value: ChoiceValue::Acknowledge,
        },
    ] {
        round_trip_ui(&msg);
    }
}

#[test]
fn hand_written_frames_decode() {
    // Independent of the encoder: the wire names are fixed.
    let m = read_engine(&frame(r#"{"v":1,"type":"ping","n":5}"#)).unwrap();
    assert_eq!(m, EngineMsg::Ping { n: 5 });
    let m = read_engine(&frame(
        r#"{"outcome":"uninstalled","leftovers":["/x"],"type":"outcome","v":1}"#,
    ))
    .unwrap();
    assert_eq!(
        m,
        EngineMsg::Outcome(Outcome::Uninstalled {
            leftovers: vec!["/x".into()]
        })
    );
    let m = read_engine(&frame(
        r#"{"v":1,"type":"hello","build_id":"b","flow":"install","app":{"name":"A","version":"1"},"details":{}}"#,
    ))
    .unwrap();
    assert!(matches!(
        m,
        EngineMsg::Hello {
            flow: Flow::Install,
            ..
        }
    ));
    let m = read_ui(&frame(
        r#"{"v":1,"type":"choice","id":4,"value":"reveal","index":2}"#,
    ))
    .unwrap();
    assert_eq!(
        m,
        UiMsg::Choice {
            id: 4,
            value: ChoiceValue::Reveal { index: 2 }
        }
    );
}

#[test]
fn a_length_over_the_cap_is_refused_before_the_body_is_read() {
    // Only the prefix is present: a reader that tried to allocate and read the body would hit EOF
    // (Truncated), not FrameTooLarge.
    let over = (MAX_FRAME as u32 + 1).to_le_bytes();
    assert_eq!(
        read_engine(&over),
        Err(ProtocolError::FrameTooLarge {
            len: MAX_FRAME as u64 + 1
        })
    );
    let huge = u32::MAX.to_le_bytes();
    assert!(matches!(
        read_ui(&huge),
        Err(ProtocolError::FrameTooLarge { .. })
    ));
}

#[test]
fn a_body_of_exactly_the_cap_is_read_and_judged_on_its_content() {
    let mut wire = (MAX_FRAME as u32).to_le_bytes().to_vec();
    wire.extend(std::iter::repeat_n(b' ', MAX_FRAME));
    assert!(matches!(
        read_engine(&wire),
        Err(ProtocolError::NotStrictJson(_))
    ));
}

#[test]
fn the_end_of_the_channel_is_typed() {
    assert_eq!(read_engine(&[]), Err(ProtocolError::Closed));
    assert_eq!(read_engine(&[1, 0]), Err(ProtocolError::Truncated));
    assert_eq!(
        read_engine(&[10, 0, 0, 0, b'{']),
        Err(ProtocolError::Truncated)
    );
    let mut cut = frame(r#"{"v":1,"type":"close"}"#);
    cut.pop();
    assert_eq!(read_engine(&cut), Err(ProtocolError::Truncated));
}

#[test]
fn a_frame_is_read_whole_from_a_one_byte_reader_and_after_an_interrupt() {
    struct Slow<'a> {
        data: &'a [u8],
        interrupt: bool,
    }
    impl Read for Slow<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.interrupt {
                self.interrupt = false;
                return Err(ErrorKind::Interrupted.into());
            }
            if self.data.is_empty() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.data[0];
            self.data = &self.data[1..];
            Ok(1)
        }
    }
    let wire = frame(r#"{"v":1,"type":"ping","n":9}"#);
    let mut slow = Slow {
        data: &wire,
        interrupt: true,
    };
    let msg: EngineMsg = read_frame(&mut slow).unwrap();
    assert_eq!(msg, EngineMsg::Ping { n: 9 });
}

#[test]
fn an_io_error_is_typed() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(ErrorKind::BrokenPipe.into())
        }
    }
    let r: Result<EngineMsg, _> = read_frame(&mut Broken);
    assert_eq!(r, Err(ProtocolError::Io(ErrorKind::BrokenPipe)));
    struct Full;
    impl std::io::Write for Full {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        write_frame(&mut Full, &EngineMsg::Close),
        Err(ProtocolError::Io(ErrorKind::BrokenPipe))
    );
}

#[test]
fn bodies_that_are_not_strict_json_are_refused() {
    let cases: Vec<Vec<u8>> = vec![
        // duplicate keys, at the top and nested
        frame(r#"{"v":1,"type":"close","type":"close"}"#),
        frame(
            r#"{"v":1,"type":"hello","build_id":"b","flow":"install","app":{"name":"A","name":"B","version":"1"},"details":{}}"#,
        ),
        // trailing bytes
        frame(r#"{"v":1,"type":"close"} x"#),
        frame(r#"{"v":1,"type":"close"}{"v":1,"type":"close"}"#),
        // not an object
        frame(r#"[1]"#),
        frame(r#""close""#),
        frame(r#"7"#),
        // empty and syntax errors
        frame(""),
        frame(r#"{"v":1,"type":"close""#),
        // a byte-order mark
        {
            let mut b = vec![0xEF, 0xBB, 0xBF];
            b.extend_from_slice(br#"{"v":1,"type":"close"}"#);
            let mut out = (b.len() as u32).to_le_bytes().to_vec();
            out.extend(b);
            out
        },
        // not UTF-8
        {
            let b = [b'{', 0xFF, 0xFE, b'}'];
            let mut out = (b.len() as u32).to_le_bytes().to_vec();
            out.extend_from_slice(&b);
            out
        },
    ];
    for (i, bytes) in cases.iter().enumerate() {
        assert!(
            matches!(read_engine(bytes), Err(ProtocolError::NotStrictJson(_))),
            "case {i}: {:?}",
            read_engine(bytes)
        );
        assert!(
            matches!(read_ui(bytes), Err(ProtocolError::NotStrictJson(_))),
            "case {i} (ui)"
        );
    }
}

#[test]
fn the_version_must_be_exactly_one() {
    for body in [
        r#"{"v":2,"type":"close"}"#,
        r#"{"v":0,"type":"close"}"#,
        r#"{"v":1.0,"type":"close"}"#,
        r#"{"v":"1","type":"close"}"#,
        r#"{"v":null,"type":"close"}"#,
        r#"{"v":-1,"type":"close"}"#,
    ] {
        assert_eq!(
            read_engine(&frame(body)),
            Err(ProtocolError::BadVersion),
            "{body}"
        );
    }
    assert_eq!(
        read_engine(&frame(r#"{"type":"close"}"#)),
        Err(ProtocolError::MissingField("v"))
    );
}

#[test]
fn an_unknown_or_foreign_type_is_refused() {
    assert_eq!(
        read_engine(&frame(r#"{"v":1,"type":"explode"}"#)),
        Err(ProtocolError::UnknownType)
    );
    // A UI type in the engine's direction and the reverse.
    assert_eq!(
        read_engine(&frame(r#"{"v":1,"type":"pong","n":1}"#)),
        Err(ProtocolError::UnknownType)
    );
    assert_eq!(
        read_ui(&frame(r#"{"v":1,"type":"ping","n":1}"#)),
        Err(ProtocolError::UnknownType)
    );
    assert_eq!(
        read_ui(&frame(r#"{"v":1,"type":"close"}"#)),
        Err(ProtocolError::UnknownType)
    );
    assert_eq!(
        read_engine(&frame(r#"{"v":1}"#)),
        Err(ProtocolError::MissingField("type"))
    );
    assert_eq!(
        read_engine(&frame(r#"{"v":1,"type":7}"#)),
        Err(ProtocolError::WrongType("type"))
    );
}

#[test]
fn a_missing_or_extra_field_is_refused() {
    let engine = [
        (r#"{"v":1,"type":"ping"}"#, ProtocolError::MissingField("n")),
        (
            r#"{"v":1,"type":"ping","n":1,"x":1}"#,
            ProtocolError::ExtraField,
        ),
        (r#"{"v":1,"type":"close","n":1}"#, ProtocolError::ExtraField),
        (
            r#"{"v":1,"type":"step"}"#,
            ProtocolError::MissingField("item"),
        ),
        (
            r#"{"v":1,"type":"outcome","outcome":"failed"}"#,
            ProtocolError::MissingField("code"),
        ),
        (
            r#"{"v":1,"type":"outcome","outcome":"installed","code":1}"#,
            ProtocolError::ExtraField,
        ),
        (
            r#"{"v":1,"type":"outcome","outcome":"rolled_back","from":"1"}"#,
            ProtocolError::MissingField("to"),
        ),
        (
            r#"{"v":1,"type":"hello","build_id":"b","flow":"install","details":{}}"#,
            ProtocolError::MissingField("app"),
        ),
        (
            r#"{"v":1,"type":"hello","build_id":"b","flow":"install","app":{"version":"1"},"details":{}}"#,
            ProtocolError::MissingField("name"),
        ),
        (
            r#"{"v":1,"type":"hello","build_id":"b","flow":"install","app":{"name":"A","version":"1","color":"red"},"details":{}}"#,
            ProtocolError::ExtraField,
        ),
        (
            r#"{"v":1,"type":"hello","build_id":"b","flow":"install","app":{"name":"A","version":"1"},"details":{"disk":1}}"#,
            ProtocolError::ExtraField,
        ),
    ];
    for (body, want) in engine {
        assert_eq!(read_engine(&frame(body)), Err(want), "{body}");
    }
    let ui = [
        (
            r#"{"v":1,"type":"cancel","x":1}"#,
            ProtocolError::ExtraField,
        ),
        (
            r#"{"v":1,"type":"choice","id":1,"value":"proceed","launch":true}"#,
            ProtocolError::ExtraField,
        ),
        (
            r#"{"v":1,"type":"choice","id":1,"value":"finish"}"#,
            ProtocolError::MissingField("launch"),
        ),
        (
            r#"{"v":1,"type":"choice","value":"proceed"}"#,
            ProtocolError::MissingField("id"),
        ),
        (
            r#"{"v":1,"type":"choice","id":1,"value":"reveal"}"#,
            ProtocolError::MissingField("index"),
        ),
    ];
    for (body, want) in ui {
        assert_eq!(read_ui(&frame(body)), Err(want), "{body}");
    }
}

#[test]
fn wrong_types_names_and_ranges_are_refused() {
    let engine = [
        (
            r#"{"v":1,"type":"ping","n":"1"}"#,
            ProtocolError::WrongType("n"),
        ),
        (
            r#"{"v":1,"type":"ping","n":1.5}"#,
            ProtocolError::OutOfRange("n"),
        ),
        (
            r#"{"v":1,"type":"ping","n":-1}"#,
            ProtocolError::OutOfRange("n"),
        ),
        (
            r#"{"v":1,"type":"ping","n":4294967296}"#,
            ProtocolError::OutOfRange("n"),
        ),
        (
            r#"{"v":1,"type":"cancellable","value":1}"#,
            ProtocolError::WrongType("value"),
        ),
        (
            r#"{"v":1,"type":"step","item":"dance"}"#,
            ProtocolError::UnknownValue("item"),
        ),
        (
            r#"{"v":1,"type":"progress","phase":"other","done":1,"total":2}"#,
            ProtocolError::UnknownValue("phase"),
        ),
        (
            r#"{"v":1,"type":"progress","phase":"stage","done":9007199254740992,"total":2}"#,
            ProtocolError::OutOfRange("done"),
        ),
        (
            r#"{"v":1,"type":"prompt","id":1,"kind":"party"}"#,
            ProtocolError::UnknownValue("kind"),
        ),
        (
            r#"{"v":1,"type":"outcome","outcome":"won"}"#,
            ProtocolError::UnknownValue("outcome"),
        ),
        (
            r#"{"v":1,"type":"outcome","outcome":"uninstalled","leftovers":"x"}"#,
            ProtocolError::WrongType("leftovers"),
        ),
        (
            r#"{"v":1,"type":"outcome","outcome":"uninstalled","leftovers":[1]}"#,
            ProtocolError::WrongType("leftovers"),
        ),
        (
            r#"{"v":1,"type":"hello","build_id":"b","flow":"repair","app":{"name":"A","version":"1"},"details":{}}"#,
            ProtocolError::UnknownValue("flow"),
        ),
        (
            r#"{"v":1,"type":"hello","build_id":"b","flow":"install","app":{"name":"A","version":"1","publisher":null},"details":{}}"#,
            ProtocolError::WrongType("publisher"),
        ),
        (
            r#"{"v":1,"type":"hello","build_id":"b","flow":"install","app":[],"details":{}}"#,
            ProtocolError::WrongType("app"),
        ),
        (
            r#"{"v":1,"type":"hello","build_id":"b","flow":"install","app":{"name":"A","version":"1"},"details":{"size_bytes":9007199254740992}}"#,
            ProtocolError::OutOfRange("size_bytes"),
        ),
    ];
    for (body, want) in engine {
        assert_eq!(read_engine(&frame(body)), Err(want), "{body}");
    }
    let ui = [
        (
            r#"{"v":1,"type":"choice","id":1,"value":"dance"}"#,
            ProtocolError::UnknownValue("value"),
        ),
        (
            r#"{"v":1,"type":"choice","id":4294967296,"value":"proceed"}"#,
            ProtocolError::OutOfRange("id"),
        ),
        (
            r#"{"v":1,"type":"pong","n":null}"#,
            ProtocolError::WrongType("n"),
        ),
    ];
    for (body, want) in ui {
        assert_eq!(read_ui(&frame(body)), Err(want), "{body}");
    }
}

fn hello_with(app: AppCard, details: Details) -> EngineMsg {
    EngineMsg::Hello {
        build_id: build_id(),
        flow: Flow::Install,
        app,
        details,
    }
}

fn no_details() -> Details {
    Details {
        location: None,
        size_bytes: None,
    }
}

#[test]
fn the_icon_is_capped_at_encode_and_at_decode() {
    let mut app = card();
    app.icon_png = Some(vec![7; MAX_ICON_BYTES]);
    round_trip_engine(&hello_with(app.clone(), no_details()));

    app.icon_png = Some(vec![7; MAX_ICON_BYTES + 1]);
    let mut sink = Vec::new();
    assert_eq!(
        write_frame(&mut sink, &hello_with(app, no_details())),
        Err(ProtocolError::BadIcon)
    );
    assert!(sink.is_empty(), "nothing is written for a refused message");

    // Decode: a hand-built hello whose icon decodes to one byte over the cap.
    let b64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(vec![7u8; MAX_ICON_BYTES + 1])
    };
    let body = format!(
        r#"{{"v":1,"type":"hello","build_id":"b","flow":"install","app":{{"name":"A","version":"1","icon_png":"{b64}"}},"details":{{}}}}"#
    );
    assert_eq!(read_engine(&frame(&body)), Err(ProtocolError::BadIcon));

    // Not canonical base64: URL-safe alphabet, missing padding, whitespace, junk.
    for bad in ["AQI", "AQ-_", "AQ I=", "!!!!", "AR=="] {
        let body = format!(
            r#"{{"v":1,"type":"hello","build_id":"b","flow":"install","app":{{"name":"A","version":"1","icon_png":"{bad}"}},"details":{{}}}}"#
        );
        assert_eq!(
            read_engine(&frame(&body)),
            Err(ProtocolError::BadIcon),
            "{bad}"
        );
    }
}

#[test]
fn text_from_the_manifest_is_capped_at_encode_and_at_decode() {
    // 128 scalars pass even when they are more than 128 bytes; 129 do not.
    let mut app = card();
    app.name = "é".repeat(128);
    app.publisher = Some("ü".repeat(128));
    round_trip_engine(&hello_with(app.clone(), no_details()));

    for (what, mutate) in [
        (
            "name",
            Box::new(|a: &mut AppCard| a.name = "n".repeat(129)) as Box<dyn Fn(&mut AppCard)>,
        ),
        (
            "version",
            Box::new(|a: &mut AppCard| a.version = "1".repeat(129)),
        ),
        (
            "publisher",
            Box::new(|a: &mut AppCard| a.publisher = Some("p".repeat(129))),
        ),
        (
            "from_version",
            Box::new(|a: &mut AppCard| a.from_version = Some("1".repeat(129))),
        ),
    ] {
        let mut app = card();
        mutate(&mut app);
        let msg = hello_with(app, no_details());
        assert!(
            matches!(msg.encode(), Err(ProtocolError::TooLong { .. })),
            "{what} at encode"
        );
    }

    // The same at decode, by hand.
    let long = "n".repeat(129);
    let body = format!(
        r#"{{"v":1,"type":"hello","build_id":"b","flow":"install","app":{{"name":"{long}","version":"1"}},"details":{{}}}}"#
    );
    assert!(matches!(
        read_engine(&frame(&body)),
        Err(ProtocolError::TooLong { .. })
    ));

    // The location is 4096 bytes at most.
    let msg = hello_with(
        card(),
        Details {
            location: Some("l".repeat(4096)),
            size_bytes: None,
        },
    );
    round_trip_engine(&msg);
    let msg = hello_with(
        card(),
        Details {
            location: Some("l".repeat(4097)),
            size_bytes: None,
        },
    );
    assert!(matches!(msg.encode(), Err(ProtocolError::TooLong { .. })));

    // Leftovers: 64 entries of 4096 bytes at most.
    let ok = EngineMsg::Outcome(Outcome::Uninstalled {
        leftovers: vec!["x".repeat(4096); 64],
    });
    round_trip_engine(&ok);
    let too_many = EngineMsg::Outcome(Outcome::Uninstalled {
        leftovers: vec!["x".into(); 65],
    });
    assert!(matches!(
        too_many.encode(),
        Err(ProtocolError::TooLong { .. })
    ));
    let too_long = EngineMsg::Outcome(Outcome::Uninstalled {
        leftovers: vec!["x".repeat(4097)],
    });
    assert!(matches!(
        too_long.encode(),
        Err(ProtocolError::TooLong { .. })
    ));
    let items = vec![r#""x""#; 65].join(",");
    let body =
        format!(r#"{{"v":1,"type":"outcome","outcome":"uninstalled","leftovers":[{items}]}}"#);
    assert!(matches!(
        read_engine(&frame(&body)),
        Err(ProtocolError::TooLong { .. })
    ));

    // Version strings of a rollback and the build id.
    let rb = EngineMsg::Outcome(Outcome::RolledBack {
        from: "1".repeat(129),
        to: "1".into(),
    });
    assert!(matches!(rb.encode(), Err(ProtocolError::TooLong { .. })));
    assert!(matches!(
        UiMsg::Hello {
            build_id: "b".repeat(257)
        }
        .encode(),
        Err(ProtocolError::TooLong { .. })
    ));
}

#[test]
fn an_encoded_body_over_the_frame_cap_is_refused_and_nothing_is_written() {
    // 64 leftovers whose JSON escapes (a control character is six bytes) outgrow one frame.
    let msg = EngineMsg::Outcome(Outcome::Uninstalled {
        leftovers: vec!["\u{1}".repeat(4096); 64],
    });
    let mut sink = Vec::new();
    assert!(matches!(
        write_frame(&mut sink, &msg),
        Err(ProtocolError::FrameTooLarge { .. })
    ));
    assert!(sink.is_empty());
}

#[test]
fn a_hello_is_judged_by_build_id() {
    assert_eq!(check_hello(&build_id()), Ok(()));
    for other in ["", "0.0.0+ui0", "9.9.9+ui1", &format!("{} ", build_id())] {
        assert_eq!(
            check_hello(other),
            Err(ProtocolError::BuildIdMismatch),
            "{other:?}"
        );
    }
    assert!(build_id().ends_with("+ui1") || build_id().contains("+ui1."));
}

// ---- reducers ----

fn started(flow: Flow) -> FlowState {
    let mut st = FlowState::new();
    st.apply(&hello(flow)).unwrap();
    st
}

fn prompt(st: &mut FlowState, id: u32, kind: PromptKind) {
    st.apply(&EngineMsg::Prompt { id, kind }).expect("prompt");
}

fn choice(id: u32, value: ChoiceValue) -> UiMsg {
    UiMsg::Choice { id, value }
}

fn step(item: StepItem) -> EngineMsg {
    EngineMsg::Step { item }
}

fn progress(phase: Phase) -> EngineMsg {
    EngineMsg::Progress {
        phase,
        done: 1,
        total: 2,
    }
}

fn refuses(st: &FlowState, msg: &EngineMsg) {
    let mut copy = st.clone();
    assert!(
        matches!(copy.apply(msg), Err(ProtocolError::OutOfOrder(_))),
        "{msg:?} on {:?}",
        st.screen()
    );
    assert_eq!(&copy, st, "a refused message changes nothing");
}

#[test]
fn install_happy_path() {
    let mut st = FlowState::expecting(Flow::Install);
    assert_eq!(st.screen(), Screen::Idle);
    st.apply(&hello(Flow::Install)).unwrap();
    assert_eq!(st.flow(), Some(Flow::Install));
    assert_eq!(st.screen(), Screen::InstallWelcome);
    // Nothing is acceptable before the prompt opens.
    assert!(!st.accepts(&choice(1, ChoiceValue::Proceed)));
    prompt(&mut st, 1, PromptKind::Welcome);
    assert_eq!(st.open_prompt(), Some((1, PromptKind::Welcome)));
    assert!(st.accepts(&choice(1, ChoiceValue::Proceed)));
    assert!(st.accepts(&choice(1, ChoiceValue::Cancel)));
    st.answer(&choice(1, ChoiceValue::Proceed)).unwrap();
    assert_eq!(st.screen(), Screen::Installing);
    assert_eq!(st.open_prompt(), None);
    st.apply(&EngineMsg::Cancellable(true)).unwrap();
    for phase in [Phase::Check, Phase::Download, Phase::Stage, Phase::Install] {
        st.apply(&progress(phase)).unwrap();
    }
    for item in [
        StepItem::Verify,
        StepItem::Stage,
        StepItem::Commit,
        StepItem::Integrate,
    ] {
        st.apply(&step(item)).unwrap();
    }
    st.apply(&EngineMsg::Outcome(Outcome::Installed)).unwrap();
    assert_eq!(st.screen(), Screen::InstallDone);
    assert!(!st.cancellable(), "an outcome ends cancelling");
    prompt(&mut st, 2, PromptKind::Done);
    assert!(st.accepts(&choice(2, ChoiceValue::Finish { launch: true })));
    assert!(st.accepts(&choice(2, ChoiceValue::Finish { launch: false })));
    assert!(!st.accepts(&choice(2, ChoiceValue::Close)));
    st.answer(&choice(2, ChoiceValue::Finish { launch: true }))
        .unwrap();
    st.apply(&EngineMsg::Close).unwrap();
    assert_eq!(st.screen(), Screen::Closed);
}

#[test]
fn install_cancel_at_the_welcome_screen() {
    let mut st = started(Flow::Install);
    // `Cancelled` needs a cancel first.
    refuses(&st, &EngineMsg::Outcome(Outcome::Cancelled));
    prompt(&mut st, 1, PromptKind::Welcome);
    st.answer(&choice(1, ChoiceValue::Cancel)).unwrap();
    assert_eq!(st.screen(), Screen::InstallWelcome);
    // The prompt is closed and does not reopen.
    refuses(
        &st,
        &EngineMsg::Prompt {
            id: 2,
            kind: PromptKind::Welcome,
        },
    );
    refuses(&st, &progress(Phase::Stage));
    st.apply(&EngineMsg::Outcome(Outcome::Cancelled)).unwrap();
    st.apply(&EngineMsg::Close).unwrap();
}

#[test]
fn install_failed_then_retry_then_done() {
    let mut st = started(Flow::Install);
    prompt(&mut st, 1, PromptKind::Welcome);
    st.answer(&choice(1, ChoiceValue::Proceed)).unwrap();
    st.apply(&progress(Phase::Stage)).unwrap();
    st.apply(&EngineMsg::Outcome(Outcome::Failed { code: 22 }))
        .unwrap();
    assert_eq!(st.screen(), Screen::InstallFailed);
    // No second outcome, no progress, while the failed prompt is not yet answered.
    refuses(&st, &EngineMsg::Outcome(Outcome::Installed));
    refuses(&st, &progress(Phase::Stage));
    prompt(&mut st, 2, PromptKind::Failed);
    assert!(st.accepts(&choice(2, ChoiceValue::Retry)));
    assert!(st.accepts(&choice(2, ChoiceValue::Close)));
    assert!(!st.accepts(&choice(2, ChoiceValue::Proceed)));
    st.answer(&choice(2, ChoiceValue::Retry)).unwrap();
    assert_eq!(st.screen(), Screen::Installing);
    assert_eq!(st.outcome(), None);
    st.apply(&progress(Phase::Install)).unwrap();
    st.apply(&EngineMsg::Outcome(Outcome::Installed)).unwrap();
    prompt(&mut st, 3, PromptKind::Done);
    st.answer(&choice(3, ChoiceValue::Finish { launch: false }))
        .unwrap();

    // Failing and closing instead of retrying.
    let mut st = started(Flow::Install);
    prompt(&mut st, 1, PromptKind::Welcome);
    st.answer(&choice(1, ChoiceValue::Proceed)).unwrap();
    st.apply(&EngineMsg::Outcome(Outcome::Failed { code: 1 }))
        .unwrap();
    prompt(&mut st, 2, PromptKind::Failed);
    st.answer(&choice(2, ChoiceValue::Close)).unwrap();
    st.apply(&EngineMsg::Close).unwrap();
}

#[test]
fn install_can_fail_before_the_welcome_prompt() {
    let mut st = started(Flow::Install);
    st.apply(&EngineMsg::Outcome(Outcome::Failed { code: 14 }))
        .unwrap();
    prompt(&mut st, 1, PromptKind::Failed);
    st.answer(&choice(1, ChoiceValue::Close)).unwrap();
}

#[test]
fn install_cancel_while_running() {
    let mut st = started(Flow::Install);
    prompt(&mut st, 1, PromptKind::Welcome);
    st.answer(&choice(1, ChoiceValue::Proceed)).unwrap();
    assert!(
        !st.accepts(&UiMsg::Cancel),
        "not cancellable until the engine says so"
    );
    st.apply(&EngineMsg::Cancellable(true)).unwrap();
    assert!(st.accepts(&UiMsg::Cancel));
    st.answer(&UiMsg::Cancel).unwrap();
    st.apply(&EngineMsg::Outcome(Outcome::Cancelled)).unwrap();
}

#[test]
fn update_happy_path_and_the_window_closes() {
    let mut st = FlowState::expecting(Flow::Update);
    st.apply(&hello(Flow::Update)).unwrap();
    assert_eq!(st.screen(), Screen::UpdateWaiting);
    st.apply(&progress(Phase::Wait)).unwrap();
    st.apply(&step(StepItem::WaitApp)).unwrap();
    st.apply(&progress(Phase::Apply)).unwrap();
    assert_eq!(st.screen(), Screen::UpdateApplying);
    st.apply(&step(StepItem::Apply)).unwrap();
    st.apply(&progress(Phase::Launch)).unwrap();
    assert_eq!(st.screen(), Screen::UpdateStarting);
    st.apply(&progress(Phase::Confirm)).unwrap();
    st.apply(&EngineMsg::Outcome(Outcome::Updated)).unwrap();
    // No prompt after an update: the window closes.
    refuses(
        &st,
        &EngineMsg::Prompt {
            id: 1,
            kind: PromptKind::RolledBack,
        },
    );
    st.apply(&EngineMsg::Close).unwrap();
}

#[test]
fn update_phases_do_not_go_back() {
    let mut st = started(Flow::Update);
    st.apply(&progress(Phase::Apply)).unwrap();
    refuses(&st, &progress(Phase::Wait));
    st.apply(&progress(Phase::Launch)).unwrap();
    refuses(&st, &progress(Phase::Apply));
    // A rollback phase stays on the starting screen, and install phases are not update phases.
    st.apply(&progress(Phase::Rollback)).unwrap();
    assert_eq!(st.screen(), Screen::UpdateStarting);
    refuses(&st, &progress(Phase::Stage));
}

#[test]
fn update_rolled_back_needs_its_acknowledgement() {
    let mut st = started(Flow::Update);
    st.apply(&progress(Phase::Launch)).unwrap();
    st.apply(&progress(Phase::Rollback)).unwrap();
    st.apply(&EngineMsg::Outcome(Outcome::RolledBack {
        from: "2.0.0".into(),
        to: "1.0.0".into(),
    }))
    .unwrap();
    assert_eq!(st.screen(), Screen::UpdateRolledBack);
    prompt(&mut st, 1, PromptKind::RolledBack);
    assert!(!st.accepts(&choice(1, ChoiceValue::Close)));
    assert!(st.accepts(&choice(1, ChoiceValue::Acknowledge)));
    st.answer(&choice(1, ChoiceValue::Acknowledge)).unwrap();
    st.apply(&EngineMsg::Close).unwrap();
}

#[test]
fn update_failed_has_a_close_prompt() {
    let mut st = started(Flow::Update);
    st.apply(&EngineMsg::Outcome(Outcome::Failed { code: 8 }))
        .unwrap();
    assert_eq!(st.screen(), Screen::UpdateFailed);
    prompt(&mut st, 1, PromptKind::Failed);
    assert!(st.accepts(&choice(1, ChoiceValue::Close)));
    assert!(!st.accepts(&choice(1, ChoiceValue::Retry)));
}

#[test]
fn uninstall_with_leftovers_and_reveal() {
    let mut st = FlowState::expecting(Flow::Uninstall);
    st.apply(&hello(Flow::Uninstall)).unwrap();
    assert_eq!(st.screen(), Screen::UninstallConfirm);
    prompt(&mut st, 1, PromptKind::Confirm);
    st.answer(&choice(1, ChoiceValue::Proceed)).unwrap();
    assert_eq!(st.screen(), Screen::Uninstalling);
    st.apply(&progress(Phase::Uninstall)).unwrap();
    st.apply(&step(StepItem::Integrate)).unwrap();
    st.apply(&step(StepItem::Remove)).unwrap();
    st.apply(&EngineMsg::Outcome(Outcome::Uninstalled {
        leftovers: vec!["/a".into(), "/b".into()],
    }))
    .unwrap();
    assert_eq!(st.screen(), Screen::UninstallDone);
    prompt(&mut st, 2, PromptKind::Done);
    assert!(st.accepts(&choice(2, ChoiceValue::Reveal { index: 0 })));
    assert!(st.accepts(&choice(2, ChoiceValue::Reveal { index: 1 })));
    // Out of range.
    assert!(!st.accepts(&choice(2, ChoiceValue::Reveal { index: 2 })));
    assert!(!st.accepts(&choice(2, ChoiceValue::Reveal { index: u32::MAX })));
    // A reveal keeps the prompt open; close ends it.
    st.answer(&choice(2, ChoiceValue::Reveal { index: 1 }))
        .unwrap();
    assert_eq!(st.open_prompt(), Some((2, PromptKind::Done)));
    assert!(!st.accepts(&choice(2, ChoiceValue::Finish { launch: true })));
    st.answer(&choice(2, ChoiceValue::Close)).unwrap();
    assert!(
        !st.accepts(&choice(2, ChoiceValue::Close)),
        "a closed prompt takes nothing"
    );
}

#[test]
fn uninstall_with_no_leftovers_has_nothing_to_reveal() {
    let mut st = started(Flow::Uninstall);
    prompt(&mut st, 1, PromptKind::Confirm);
    st.answer(&choice(1, ChoiceValue::Proceed)).unwrap();
    st.apply(&EngineMsg::Outcome(Outcome::Uninstalled {
        leftovers: vec![],
    }))
    .unwrap();
    prompt(&mut st, 2, PromptKind::Done);
    assert!(!st.accepts(&choice(2, ChoiceValue::Reveal { index: 0 })));
    assert!(st.accepts(&choice(2, ChoiceValue::Close)));
}

#[test]
fn uninstall_failed_and_cancelled() {
    let mut st = started(Flow::Uninstall);
    prompt(&mut st, 1, PromptKind::Confirm);
    st.answer(&choice(1, ChoiceValue::Proceed)).unwrap();
    st.apply(&EngineMsg::Outcome(Outcome::UninstallFailed { code: 31 }))
        .unwrap();
    assert_eq!(st.screen(), Screen::UninstallFailed);
    prompt(&mut st, 2, PromptKind::Failed);
    assert!(st.accepts(&choice(2, ChoiceValue::Close)));
    assert!(!st.accepts(&choice(2, ChoiceValue::Retry)));

    let mut st = started(Flow::Uninstall);
    prompt(&mut st, 1, PromptKind::Confirm);
    st.answer(&choice(1, ChoiceValue::Cancel)).unwrap();
    st.apply(&EngineMsg::Outcome(Outcome::Cancelled)).unwrap();
    st.apply(&EngineMsg::Close).unwrap();
}

#[test]
fn a_choice_needs_an_open_prompt_its_id_and_a_value_of_its_set() {
    let mut st = started(Flow::Install);
    // No prompt yet.
    assert!(!st.accepts(&choice(1, ChoiceValue::Proceed)));
    prompt(&mut st, 5, PromptKind::Welcome);
    // A stale or future id.
    assert!(!st.accepts(&choice(4, ChoiceValue::Proceed)));
    assert!(!st.accepts(&choice(6, ChoiceValue::Proceed)));
    // A value of another prompt's set.
    for value in [
        ChoiceValue::Retry,
        ChoiceValue::Close,
        ChoiceValue::Acknowledge,
        ChoiceValue::Finish { launch: true },
        ChoiceValue::Reveal { index: 0 },
    ] {
        assert!(!st.accepts(&choice(5, value)), "{value:?}");
    }
    // A rejected answer is an error and changes nothing.
    let before = st.clone();
    assert!(st.answer(&choice(4, ChoiceValue::Proceed)).is_err());
    assert_eq!(st, before);
    // After the answer the prompt is closed: the same choice again is refused.
    st.answer(&choice(5, ChoiceValue::Proceed)).unwrap();
    assert!(!st.accepts(&choice(5, ChoiceValue::Proceed)));
    assert!(st.answer(&choice(5, ChoiceValue::Cancel)).is_err());
}

#[test]
fn prompt_ids_increase_and_prompts_fit_their_screen() {
    let mut st = started(Flow::Install);
    refuses(
        &st,
        &EngineMsg::Prompt {
            id: 1,
            kind: PromptKind::Done,
        },
    );
    refuses(
        &st,
        &EngineMsg::Prompt {
            id: 1,
            kind: PromptKind::Confirm,
        },
    );
    prompt(&mut st, 3, PromptKind::Welcome);
    // A second prompt while one is open.
    refuses(
        &st,
        &EngineMsg::Prompt {
            id: 4,
            kind: PromptKind::Welcome,
        },
    );
    st.answer(&choice(3, ChoiceValue::Proceed)).unwrap();
    st.apply(&EngineMsg::Outcome(Outcome::Failed { code: 1 }))
        .unwrap();
    // An id that does not increase.
    refuses(
        &st,
        &EngineMsg::Prompt {
            id: 3,
            kind: PromptKind::Failed,
        },
    );
    refuses(
        &st,
        &EngineMsg::Prompt {
            id: 2,
            kind: PromptKind::Failed,
        },
    );
    prompt(&mut st, 4, PromptKind::Failed);
}

#[test]
fn cancel_needs_cancellable_true_and_no_outcome() {
    let mut st = started(Flow::Update);
    assert!(!st.accepts(&UiMsg::Cancel));
    st.apply(&EngineMsg::Cancellable(true)).unwrap();
    assert!(st.accepts(&UiMsg::Cancel));
    st.apply(&EngineMsg::Cancellable(false)).unwrap();
    assert!(
        !st.accepts(&UiMsg::Cancel),
        "cancel after Cancellable(false)"
    );
    assert!(st.answer(&UiMsg::Cancel).is_err());
    st.apply(&EngineMsg::Cancellable(true)).unwrap();
    st.apply(&EngineMsg::Outcome(Outcome::Updated)).unwrap();
    assert!(!st.accepts(&UiMsg::Cancel), "cancel after the outcome");
    refuses(&st, &EngineMsg::Cancellable(true));
}

#[test]
fn pong_answers_the_latest_ping_only() {
    let mut st = started(Flow::Update);
    assert!(!st.accepts(&UiMsg::Pong { n: 1 }), "no ping yet");
    st.apply(&EngineMsg::Ping { n: 1 }).unwrap();
    assert!(st.accepts(&UiMsg::Pong { n: 1 }));
    st.apply(&EngineMsg::Ping { n: 2 }).unwrap();
    assert!(!st.accepts(&UiMsg::Pong { n: 1 }), "a stale n");
    assert!(!st.accepts(&UiMsg::Pong { n: 3 }));
    st.answer(&UiMsg::Pong { n: 2 }).unwrap();
    assert!(!st.accepts(&UiMsg::Pong { n: 2 }), "one pong per ping");
    // A ping changes no screen.
    assert_eq!(st.screen(), Screen::UpdateWaiting);
}

#[test]
fn ping_is_valid_in_every_state_after_the_hello() {
    let mut st = FlowState::new();
    // Before the hello it is out of order, like every other message.
    refuses(&st, &EngineMsg::Ping { n: 1 });
    st.apply(&hello(Flow::Install)).unwrap();
    prompt(&mut st, 1, PromptKind::Welcome);
    let screen = st.screen();
    st.apply(&EngineMsg::Ping { n: 1 }).unwrap(); // a prompt is open
    assert_eq!(st.screen(), screen);
    st.answer(&choice(1, ChoiceValue::Proceed)).unwrap();
    st.apply(&EngineMsg::Ping { n: 2 }).unwrap(); // running
    st.apply(&EngineMsg::Outcome(Outcome::Installed)).unwrap();
    st.apply(&EngineMsg::Ping { n: 3 }).unwrap(); // after the outcome
    st.apply(&EngineMsg::Close).unwrap();
    st.apply(&EngineMsg::Ping { n: 4 }).unwrap(); // closed
    assert_eq!(st.screen(), Screen::Closed);
    assert!(
        st.accepts(&UiMsg::Pong { n: 4 }),
        "the pong that follows the close"
    );
}

#[test]
fn messages_out_of_order_are_errors() {
    // Before the hello.
    let st = FlowState::new();
    for msg in [
        EngineMsg::Close,
        EngineMsg::Cancellable(true),
        progress(Phase::Stage),
        step(StepItem::Verify),
        EngineMsg::Prompt {
            id: 1,
            kind: PromptKind::Welcome,
        },
        EngineMsg::Outcome(Outcome::Installed),
    ] {
        refuses(&st, &msg);
    }
    assert!(!st.accepts(&UiMsg::Cancel));
    assert!(!st.accepts(&choice(1, ChoiceValue::Proceed)));

    // A second hello, and a hello for another flow.
    let st = started(Flow::Install);
    refuses(&st, &hello(Flow::Install));
    let mut engine_side = FlowState::expecting(Flow::Update);
    assert!(matches!(
        engine_side.apply(&hello(Flow::Install)),
        Err(ProtocolError::OutOfOrder(_))
    ));

    // The welcome screen is not running: no progress or step, no outcome of a finished install.
    refuses(&st, &progress(Phase::Stage));
    refuses(&st, &step(StepItem::Verify));
    refuses(&st, &EngineMsg::Outcome(Outcome::Installed));
    refuses(&st, &EngineMsg::Outcome(Outcome::Updated));

    // Progress and steps of another flow.
    let mut st = started(Flow::Install);
    prompt(&mut st, 1, PromptKind::Welcome);
    st.answer(&choice(1, ChoiceValue::Proceed)).unwrap();
    refuses(&st, &progress(Phase::Wait));
    refuses(&st, &progress(Phase::Uninstall));
    refuses(&st, &step(StepItem::Remove));
    refuses(&st, &step(StepItem::WaitApp));
    refuses(
        &st,
        &EngineMsg::Outcome(Outcome::Uninstalled { leftovers: vec![] }),
    );
    refuses(
        &st,
        &EngineMsg::Outcome(Outcome::UninstallFailed { code: 1 }),
    );
    refuses(
        &st,
        &EngineMsg::Outcome(Outcome::RolledBack {
            from: "2".into(),
            to: "1".into(),
        }),
    );
    let mut st = started(Flow::Uninstall);
    prompt(&mut st, 1, PromptKind::Confirm);
    st.answer(&choice(1, ChoiceValue::Proceed)).unwrap();
    refuses(&st, &progress(Phase::Stage));
    refuses(&st, &step(StepItem::Verify));
    refuses(&st, &EngineMsg::Outcome(Outcome::Failed { code: 1 }));

    // After an outcome there is no more work, and after the close there is nothing.
    let mut st = started(Flow::Update);
    st.apply(&EngineMsg::Outcome(Outcome::Updated)).unwrap();
    refuses(&st, &progress(Phase::Launch));
    refuses(&st, &step(StepItem::Launch));
    refuses(&st, &EngineMsg::Outcome(Outcome::Updated));
    st.apply(&EngineMsg::Close).unwrap();
    refuses(&st, &EngineMsg::Close);
    refuses(&st, &EngineMsg::Cancellable(true));
    refuses(&st, &progress(Phase::Launch));
    assert!(!st.accepts(&UiMsg::Cancel));
    assert!(!st.accepts(&choice(1, ChoiceValue::Acknowledge)));
}

#[test]
fn a_progress_or_step_with_a_prompt_open_is_out_of_order() {
    let mut st = started(Flow::Install);
    prompt(&mut st, 1, PromptKind::Welcome);
    refuses(&st, &progress(Phase::Stage));
    refuses(&st, &step(StepItem::Verify));
    refuses(&st, &EngineMsg::Outcome(Outcome::Failed { code: 1 }));
}

#[test]
fn the_ui_hello_is_not_a_reducer_message() {
    let st = started(Flow::Install);
    assert!(!st.accepts(&UiMsg::Hello {
        build_id: build_id()
    }));
    assert!(!FlowState::new().accepts(&UiMsg::Hello {
        build_id: build_id()
    }));
}
