//! Smoke test of the real binary: it is spawned with piped stdio and a scripted engine plays each
//! flow over the real protocol, answering and checking `Ping`/`Pong`, and ends the window with
//! `Close`. It also checks the typed exit codes of the failures that need a window (12 protocol
//! error, 13 engine gone, 14 build-id mismatch) and that standard output carries frames only.
//!
//! It opens a window, so it is `#[ignore]`d and run locally with `--ignored` (under Xvfb on
//! a Linux machine with no display). CI does not run it (M6-D13). With no display or adapter it
//! fails, it never skips. No test can click: the choices the user makes are covered by
//! `lunepack-ui-luneui`'s `tests/access.rs` (the keyboard drives every prompt to every choice);
//! here the engine ends each prompt itself.

use std::io::{BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use lunepack_core::progress::Phase;
use lunepack_core::ui::{self, EngineMsg, Outcome, PromptKind, ProtocolError, UiMsg};
use lunepack_ui_luneui::{Os, scenario};

struct Ui {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: Receiver<Result<UiMsg, ProtocolError>>,
    /// Everything the UI sent after its hello.
    seen: Vec<UiMsg>,
    next_ping: u32,
}

fn sleep(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

impl Ui {
    fn start() -> Ui {
        let mut child = Command::new(env!("CARGO_BIN_EXE_lunepack-ui"))
            .arg("--engine")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the binary starts");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut input = BufReader::new(stdout);
            loop {
                let msg = ui::read_frame::<_, UiMsg>(&mut input);
                let stop = msg.is_err();
                if tx.send(msg).is_err() || stop {
                    return;
                }
            }
        });
        Ui {
            child,
            stdin,
            rx,
            seen: Vec::new(),
            next_ping: 1,
        }
    }

    fn send(&mut self, msg: &EngineMsg) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        ui::write_frame(stdin, msg).expect("the frame is written");
        stdin.flush().expect("the frame is flushed");
    }

    /// The next frame within `wait`; `None` on a timeout. A read error is the channel's end.
    fn next(&mut self, wait: Duration) -> Option<Result<UiMsg, ProtocolError>> {
        match self.rx.recv_timeout(wait) {
            Ok(r) => Some(r),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => Some(Err(ProtocolError::Closed)),
        }
    }

    /// The UI's hello, with this build's id. Without one within 30 s the test fails: no display or
    /// no adapter is a failure here, not a skip.
    fn expect_hello(&mut self) {
        match self.next(Duration::from_secs(30)) {
            Some(Ok(UiMsg::Hello { build_id })) => {
                assert_eq!(build_id, ui::build_id(), "the UI's build id");
            }
            other => {
                let code = self.child.try_wait().ok().flatten().and_then(|s| s.code());
                panic!(
                    "no hello from the UI (first frame {other:?}, exit {code:?}): no display or adapter?"
                );
            }
        }
    }

    /// Sends a ping and waits for the matching pong; every other frame is kept.
    fn ping(&mut self) {
        let n = self.next_ping;
        self.next_ping += 1;
        self.send(&EngineMsg::Ping { n });
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(10) {
            match self.next(Duration::from_millis(100)) {
                Some(Ok(UiMsg::Pong { n: got })) => {
                    assert_eq!(got, n, "the pong answers the latest ping");
                    return;
                }
                Some(Ok(other)) => self.seen.push(other),
                Some(Err(e)) => panic!("the UI's channel ended while waiting for pong {n}: {e}"),
                None => {}
            }
        }
        panic!("no pong {n} within 10 s");
    }

    /// Waits for the process to exit and returns its code.
    fn exit_code(&mut self, within: Duration) -> Option<i32> {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status.code();
            }
            if started.elapsed() > within {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("the UI did not exit within {within:?}");
            }
            sleep(20);
        }
    }

    /// Closes the window and checks the process ends with code 0 within a second, having sent
    /// nothing but its hello and pongs.
    fn close(mut self) {
        self.send(&EngineMsg::Close);
        self.stdin = None;
        let started = Instant::now();
        let code = self.exit_code(Duration::from_secs(5));
        assert_eq!(code, Some(0), "exit code after Close");
        assert!(
            started.elapsed() < Duration::from_secs(1) + Duration::from_millis(500),
            "it exits within a second of Close"
        );
        // Whatever is left on the channel is frames or the end of the stream, nothing else.
        while let Some(r) = self.next(Duration::from_millis(200)) {
            match r {
                Ok(msg) => self.seen.push(msg),
                Err(ProtocolError::Closed) => break,
                Err(e) => panic!("standard output carried something that is not a frame: {e}"),
            }
        }
        assert!(
            self.seen.iter().all(|m| matches!(m, UiMsg::Pong { .. })),
            "the UI sent only its hello and pongs: {:?}",
            self.seen
        );
    }
}

#[test]
#[ignore = "opens a window: run with --ignored (locally, before a push that touches the UI)"]
fn the_update_flow_runs_to_updated_and_the_binary_exits_zero() {
    let mut ui = Ui::start();
    ui.expect_hello();
    ui.send(&scenario::update_hello());
    sleep(600);
    ui.ping();
    for i in 1..=5u64 {
        ui.send(&EngineMsg::Progress {
            phase: Phase::Apply,
            done: i * 20,
            total: 100,
        });
        sleep(100);
    }
    ui.send(&EngineMsg::Progress {
        phase: Phase::Launch,
        done: 0,
        total: 0,
    });
    sleep(400);
    ui.send(&EngineMsg::Outcome(Outcome::Updated));
    sleep(400);
    ui.ping();
    ui.close();
}

#[test]
#[ignore = "opens a window: run with --ignored (locally, before a push that touches the UI)"]
fn a_rolled_back_update_waits_at_its_prompt_and_answers_pings() {
    let mut ui = Ui::start();
    ui.expect_hello();
    ui.send(&scenario::update_hello());
    ui.send(&EngineMsg::Progress {
        phase: Phase::Launch,
        done: 0,
        total: 0,
    });
    sleep(300);
    ui.send(&EngineMsg::Outcome(Outcome::RolledBack {
        from: scenario::NEW_VERSION.to_owned(),
        to: scenario::APP_VERSION.to_owned(),
    }));
    ui.send(&EngineMsg::Prompt {
        id: 1,
        kind: PromptKind::RolledBack,
    });
    sleep(500);
    ui.ping();
    ui.close();
}

#[test]
#[ignore = "opens a window: run with --ignored (locally, before a push that touches the UI)"]
fn the_install_flow_shows_its_welcome_and_answers_pings_until_closed() {
    let mut ui = Ui::start();
    ui.expect_hello();
    ui.send(&scenario::install_hello(
        Os::current(),
        scenario::APP_NAME,
        true,
    ));
    ui.send(&EngineMsg::Prompt {
        id: 1,
        kind: PromptKind::Welcome,
    });
    sleep(800);
    ui.ping();
    ui.ping();
    ui.close();
}

#[test]
#[ignore = "opens a window: run with --ignored (locally, before a push that touches the UI)"]
fn the_uninstall_flow_shows_its_confirmation_and_answers_pings_until_closed() {
    let mut ui = Ui::start();
    ui.expect_hello();
    ui.send(&scenario::uninstall_hello(Os::current()));
    ui.send(&EngineMsg::Prompt {
        id: 1,
        kind: PromptKind::Confirm,
    });
    sleep(800);
    ui.ping();
    ui.ping();
    ui.close();
}

#[test]
#[ignore = "opens a window: run with --ignored (locally, before a push that touches the UI)"]
fn a_frame_that_is_out_of_order_ends_the_ui_with_the_protocol_code() {
    let mut ui = Ui::start();
    ui.expect_hello();
    ui.send(&EngineMsg::Prompt {
        id: 1,
        kind: PromptKind::Welcome,
    });
    assert_eq!(ui.exit_code(Duration::from_secs(5)), Some(12));
}

#[test]
#[ignore = "opens a window: run with --ignored (locally, before a push that touches the UI)"]
fn a_hello_from_another_build_ends_the_ui_with_the_mismatch_code() {
    let mut ui = Ui::start();
    ui.expect_hello();
    let mut hello = scenario::update_hello();
    if let EngineMsg::Hello { build_id, .. } = &mut hello {
        *build_id = "0.0.0+ui999".to_owned();
    }
    ui.send(&hello);
    assert_eq!(ui.exit_code(Duration::from_secs(5)), Some(14));
}

#[test]
#[ignore = "opens a window: run with --ignored (locally, before a push that touches the UI)"]
fn the_engine_closing_its_end_before_close_ends_the_ui_with_the_gone_code() {
    let mut ui = Ui::start();
    ui.expect_hello();
    ui.send(&scenario::update_hello());
    sleep(300);
    ui.stdin = None;
    let started = Instant::now();
    assert_eq!(ui.exit_code(Duration::from_secs(5)), Some(13));
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "within a second"
    );
}
