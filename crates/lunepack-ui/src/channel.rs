//! The channel to the engine: a reader thread that decodes the frames on standard input and a
//! writer thread that encodes the answers onto standard output (M6-D1, M6-D2), plus the typed exit
//! codes. Nothing else ever writes to standard output.

use std::io::{Read, Write};
use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;

use lunepack_core::ui::{self, EngineMsg, ProtocolError, UiMsg};

/// How the process ends. The codes are the UI's typed exit codes (docs/RUNTIME.md); the runtime's
/// host maps them to its closed `ui_stopped` reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The engine closed the window, or the user did at the end.
    Closed,
    /// No display: no event loop or no window could be created.
    NoDisplay,
    /// No GPU adapter, or the surface or device could not be opened.
    NoAdapter,
    /// The engine sent something the protocol does not allow.
    Protocol,
    /// The engine's end of the channel closed before `Close`.
    EngineGone,
    /// The engine's build id is not this build's.
    BuildMismatch,
}

impl Exit {
    /// The process exit code.
    pub fn code(self) -> u8 {
        match self {
            Exit::Closed => 0,
            Exit::NoDisplay => 10,
            Exit::NoAdapter => 11,
            Exit::Protocol => 12,
            Exit::EngineGone => 13,
            Exit::BuildMismatch => 14,
        }
    }
}

/// What the reader and writer post to the event loop.
#[derive(Debug)]
pub enum UserEvent {
    /// A frame from the engine.
    Engine(EngineMsg),
    /// The channel ended (or broke): the process should exit with this.
    Ended(Exit),
    /// An accessibility client is waiting for a frame.
    Wake,
}

/// The exit a failed read stands for: an end of the channel (also inside a frame, which is the
/// engine dying mid-write) is the engine gone; anything else is a protocol error.
pub fn exit_for_read_error(e: &ProtocolError) -> Exit {
    match e {
        ProtocolError::Closed | ProtocolError::Truncated | ProtocolError::Io(_) => Exit::EngineGone,
        _ => Exit::Protocol,
    }
}

/// Starts the reader: it decodes frames from `input` and hands each to `post`, which returns
/// whether the event loop is still there. It stops after `Close`, on an error (reported once as
/// [`UserEvent::Ended`]) and when `post` says the loop is gone.
pub fn spawn_reader(
    mut input: impl Read + Send + 'static,
    post: impl Fn(UserEvent) -> bool + Send + 'static,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("lunepack-ui-reader".into())
        .spawn(move || {
            loop {
                match ui::read_frame::<_, EngineMsg>(&mut input) {
                    Ok(msg) => {
                        let close = matches!(msg, EngineMsg::Close);
                        if !post(UserEvent::Engine(msg)) || close {
                            return;
                        }
                    }
                    Err(e) => {
                        post(UserEvent::Ended(exit_for_read_error(&e)));
                        return;
                    }
                }
            }
        })
}

/// Starts the writer: it encodes what is sent on the returned channel onto `output`, flushing
/// each frame. A write that fails (the engine is gone) calls `failed` once and stops.
pub fn spawn_writer(
    mut output: impl Write + Send + 'static,
    failed: impl FnOnce() + Send + 'static,
) -> std::io::Result<Sender<UiMsg>> {
    let (tx, rx) = mpsc::channel::<UiMsg>();
    std::thread::Builder::new()
        .name("lunepack-ui-writer".into())
        .spawn(move || {
            for msg in rx {
                if ui::write_frame(&mut output, &msg)
                    .and_then(|()| output.flush().map_err(|e| ProtocolError::Io(e.kind())))
                    .is_err()
                {
                    failed();
                    return;
                }
            }
        })?;
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn frames(msgs: &[EngineMsg]) -> Vec<u8> {
        let mut out = Vec::new();
        for m in msgs {
            ui::write_frame(&mut out, m).unwrap();
        }
        out
    }

    fn collect(input: Vec<u8>) -> Vec<String> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let handle = spawn_reader(Cursor::new(input), move |ev| {
            sink.lock().unwrap().push(format!("{ev:?}"));
            true
        })
        .unwrap();
        handle.join().unwrap();
        let out = seen.lock().unwrap();
        out.clone()
    }

    #[test]
    fn the_exit_codes_are_the_documented_ones() {
        let codes = [
            (Exit::Closed, 0),
            (Exit::NoDisplay, 10),
            (Exit::NoAdapter, 11),
            (Exit::Protocol, 12),
            (Exit::EngineGone, 13),
            (Exit::BuildMismatch, 14),
        ];
        for (exit, code) in codes {
            assert_eq!(exit.code(), code);
        }
    }

    #[test]
    fn the_reader_posts_frames_in_order_and_stops_at_close() {
        let seen = collect(frames(&[
            EngineMsg::Ping { n: 1 },
            EngineMsg::Close,
            EngineMsg::Ping { n: 2 },
        ]));
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert!(seen[0].contains("Ping"));
        assert!(seen[1].contains("Close"));
    }

    #[test]
    fn an_end_before_close_is_the_engine_gone() {
        let seen = collect(frames(&[EngineMsg::Ping { n: 1 }]));
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert!(seen[1].contains("Ended(EngineGone)"), "{seen:?}");
        // The engine dying inside a frame is the same.
        let mut cut = frames(&[EngineMsg::Ping { n: 1 }]);
        cut.truncate(cut.len() - 2);
        let seen = collect(cut);
        assert!(
            seen.last().unwrap().contains("Ended(EngineGone)"),
            "{seen:?}"
        );
    }

    #[test]
    fn a_frame_that_breaks_the_protocol_is_a_protocol_exit() {
        // An oversize length, then bytes that are not JSON, then an unknown type.
        let mut over = (ui::MAX_FRAME as u32 + 1).to_le_bytes().to_vec();
        over.extend_from_slice(b"x");
        let junk = {
            let body = b"not json";
            let mut v = (body.len() as u32).to_le_bytes().to_vec();
            v.extend_from_slice(body);
            v
        };
        let unknown = {
            let body = br#"{"v":1,"type":"launch_missiles"}"#;
            let mut v = (body.len() as u32).to_le_bytes().to_vec();
            v.extend_from_slice(body);
            v
        };
        for bad in [over, junk, unknown] {
            let seen = collect(bad);
            assert_eq!(seen.len(), 1, "{seen:?}");
            assert!(seen[0].contains("Ended(Protocol)"), "{seen:?}");
        }
    }

    #[test]
    fn the_reader_stops_when_the_loop_is_gone() {
        let handle = spawn_reader(
            Cursor::new(frames(&[
                EngineMsg::Ping { n: 1 },
                EngineMsg::Ping { n: 2 },
            ])),
            |_| false,
        )
        .unwrap();
        handle.join().unwrap();
    }

    /// A writer into a shared buffer.
    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_writer_writes_whole_frames_in_order() {
        let buf = Shared::default();
        let tx = spawn_writer(buf.clone(), || {}).unwrap();
        tx.send(UiMsg::Pong { n: 7 }).unwrap();
        tx.send(UiMsg::Cancel).unwrap();
        drop(tx);
        std::thread::sleep(Duration::from_millis(200));
        let bytes = buf.0.lock().unwrap().clone();
        let mut cur = Cursor::new(bytes);
        assert_eq!(
            ui::read_frame::<_, UiMsg>(&mut cur),
            Ok(UiMsg::Pong { n: 7 })
        );
        assert_eq!(ui::read_frame::<_, UiMsg>(&mut cur), Ok(UiMsg::Cancel));
        assert_eq!(
            ui::read_frame::<_, UiMsg>(&mut cur),
            Err(ProtocolError::Closed)
        );
    }

    #[test]
    fn a_broken_pipe_reports_once() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (done_tx, done_rx) = mpsc::channel();
        let tx = spawn_writer(Broken, move || {
            let _ = done_tx.send(());
        })
        .unwrap();
        tx.send(UiMsg::Cancel).unwrap();
        assert!(done_rx.recv_timeout(Duration::from_secs(2)).is_ok());
    }
}
