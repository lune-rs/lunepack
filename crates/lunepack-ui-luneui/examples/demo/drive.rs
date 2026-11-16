//! `demo --drive <lunepack-ui>`: this example acts as the engine over the real binary's standard
//! input and output, so each flow shows in a window. It speaks the real protocol (the hello
//! handshake, the reducer, pings and pongs) and plays a scripted operation in real time.
//!
//! The flows that ask first (install, uninstall) wait for the user's click; with `--auto` they
//! show their first screen for a few seconds and the engine closes the window instead.

use std::io::{BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use lunepack_core::progress::Phase;
use lunepack_core::ui::{
    self, ChoiceValue, EngineMsg, Flow, FlowState, Outcome, PromptKind, ProtocolError, StepItem,
    UiMsg,
};
use lunepack_ui_luneui::Os;
use lunepack_ui_luneui::scenario;

/// How the driven operation ends.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The operation succeeds (an update that fails its health check rolls back instead).
    Success,
    /// An update that rolls back, an install or uninstall that fails.
    Failure,
}

struct Link {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<Result<UiMsg, ProtocolError>>,
    state: FlowState,
    next_ping: u32,
}

fn sleep(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

impl Link {
    fn start(program: &Path, flow: Flow) -> Result<Link, String> {
        let mut child = Command::new(program)
            .arg("--engine")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("start {}: {e}", program.display()))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
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
        Ok(Link {
            child,
            stdin,
            rx,
            state: FlowState::expecting(flow),
            next_ping: 1,
        })
    }

    /// Sends `msg`, applying it to the reducer first (the engine sends only what is valid).
    fn send(&mut self, msg: EngineMsg) -> Result<(), String> {
        self.state
            .apply(&msg)
            .map_err(|e| format!("my own message {msg:?}: {e}"))?;
        ui::write_frame(&mut self.stdin, &msg).map_err(|e| format!("write: {e}"))?;
        self.stdin.flush().map_err(|e| format!("flush: {e}"))
    }

    /// The next message from the UI within `wait`, validated against the reducer.
    fn recv(&mut self, wait: Duration) -> Result<Option<UiMsg>, String> {
        match self.rx.recv_timeout(wait) {
            Ok(Ok(msg)) => {
                if matches!(msg, UiMsg::Hello { .. }) {
                    return Ok(Some(msg));
                }
                if !self.state.accepts(&msg) {
                    return Err(format!(
                        "the UI sent a message that is not valid now: {msg:?}"
                    ));
                }
                self.state.answer(&msg).map_err(|e| e.to_string())?;
                Ok(Some(msg))
            }
            Ok(Err(e)) => Err(format!("the UI's channel ended: {e}")),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err("the UI's channel is gone".into()),
        }
    }

    fn handshake(&mut self) -> Result<(), String> {
        let started = Instant::now();
        loop {
            match self.recv(Duration::from_millis(200))? {
                Some(UiMsg::Hello { build_id }) => {
                    return ui::check_hello(&build_id).map_err(|e| e.to_string());
                }
                Some(other) => return Err(format!("expected the UI's hello, got {other:?}")),
                None if started.elapsed() > Duration::from_secs(20) => {
                    return Err("no hello from the UI within 20 s".into());
                }
                None => {}
            }
        }
    }

    /// Waits for an answer to the open prompt, pinging every two seconds like the real engine
    /// does; `auto` gives up after `auto_wait`. A `Cancel` while running is returned as such.
    fn wait_choice(&mut self, auto_wait: Option<Duration>) -> Result<Option<UiMsg>, String> {
        let started = Instant::now();
        let mut last_ping = Instant::now();
        loop {
            if let Some(msg) = self.recv(Duration::from_millis(100))? {
                match msg {
                    UiMsg::Pong { n } => eprintln!("(the UI answered ping {n})"),
                    other => return Ok(Some(other)),
                }
            }
            if last_ping.elapsed() > Duration::from_secs(2) {
                let n = self.next_ping;
                self.next_ping += 1;
                self.send(EngineMsg::Ping { n })?;
                last_ping = Instant::now();
            }
            if auto_wait.is_some_and(|w| started.elapsed() > w) {
                return Ok(None);
            }
        }
    }

    /// Whether the user asked to cancel since the last look (pongs are consumed).
    fn cancel_asked(&mut self) -> Result<bool, String> {
        while let Some(msg) = self.recv(Duration::from_millis(1))? {
            if matches!(msg, UiMsg::Cancel) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Closes the window and returns the binary's exit code.
    fn close(mut self) -> Result<i32, String> {
        let _ = self.send(EngineMsg::Close);
        drop(self.stdin);
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().map_err(|e| e.to_string())? {
                return Ok(status.code().unwrap_or(-1));
            }
            if started.elapsed() > Duration::from_secs(3) {
                let _ = self.child.kill();
                return Err("the UI did not exit within 3 s of Close".into());
            }
            sleep(20);
        }
    }
}

fn prompt(link: &mut Link, id: u32, kind: PromptKind) -> Result<(), String> {
    link.send(EngineMsg::Prompt { id, kind })
}

fn install(link: &mut Link, os: Os, auto: bool, ending: Ending) -> Result<(), String> {
    link.send(scenario::install_hello(os, scenario::APP_NAME, true))?;
    prompt(link, 1, PromptKind::Welcome)?;
    let wait = auto.then(|| Duration::from_secs(4));
    match link.wait_choice(wait)? {
        Some(UiMsg::Choice {
            value: ChoiceValue::Proceed,
            ..
        }) => {}
        Some(UiMsg::Choice {
            value: ChoiceValue::Cancel,
            ..
        }) => {
            return link.send(EngineMsg::Outcome(Outcome::Cancelled));
        }
        _ => return Ok(()),
    }
    link.send(EngineMsg::Cancellable(true))?;
    sleep(400);
    link.send(EngineMsg::Step {
        item: StepItem::Verify,
    })?;
    let total = scenario::TOTAL_BYTES;
    for i in 1..=20u64 {
        if link.cancel_asked()? {
            link.send(EngineMsg::Cancellable(false))?;
            return link.send(EngineMsg::Outcome(Outcome::Cancelled));
        }
        link.send(EngineMsg::Progress {
            phase: Phase::Stage,
            done: total * i / 20,
            total,
        })?;
        sleep(200);
    }
    link.send(EngineMsg::Step {
        item: StepItem::Stage,
    })?;
    link.send(EngineMsg::Step {
        item: StepItem::Integrate,
    })?;
    link.send(EngineMsg::Step {
        item: StepItem::Commit,
    })?;
    link.send(EngineMsg::Cancellable(false))?;
    if ending == Ending::Failure {
        link.send(EngineMsg::Outcome(Outcome::Failed { code: 9 }))?;
        prompt(link, 2, PromptKind::Failed)?;
        link.wait_choice(wait)?;
        return Ok(());
    }
    link.send(EngineMsg::Outcome(Outcome::Installed))?;
    prompt(link, 2, PromptKind::Done)?;
    link.wait_choice(wait)?;
    Ok(())
}

fn uninstall(link: &mut Link, os: Os, auto: bool, ending: Ending) -> Result<(), String> {
    link.send(scenario::uninstall_hello(os))?;
    prompt(link, 1, PromptKind::Confirm)?;
    let wait = auto.then(|| Duration::from_secs(4));
    match link.wait_choice(wait)? {
        Some(UiMsg::Choice {
            value: ChoiceValue::Proceed,
            ..
        }) => {}
        Some(UiMsg::Choice {
            value: ChoiceValue::Cancel,
            ..
        }) => {
            return link.send(EngineMsg::Outcome(Outcome::Cancelled));
        }
        _ => return Ok(()),
    }
    sleep(400);
    link.send(EngineMsg::Step {
        item: StepItem::Integrate,
    })?;
    for i in 1..=10u64 {
        link.send(EngineMsg::Progress {
            phase: Phase::Uninstall,
            done: i * 10,
            total: 100,
        })?;
        sleep(250);
    }
    if ending == Ending::Failure {
        link.send(EngineMsg::Outcome(Outcome::UninstallFailed { code: 25 }))?;
        prompt(link, 2, PromptKind::Failed)?;
        link.wait_choice(wait)?;
        return Ok(());
    }
    link.send(EngineMsg::Step {
        item: StepItem::Remove,
    })?;
    link.send(EngineMsg::Outcome(Outcome::Uninstalled {
        leftovers: scenario::leftovers(os, 1),
    }))?;
    prompt(link, 2, PromptKind::Done)?;
    // `reveal` would open the folder; the demo only lists it and waits for Close.
    while let Some(UiMsg::Choice {
        value: ChoiceValue::Reveal { index },
        ..
    }) = link.wait_choice(wait)?
    {
        eprintln!("(the engine would open the folder of leftover {index})");
    }
    Ok(())
}

fn update(link: &mut Link, ending: Ending) -> Result<(), String> {
    link.send(scenario::update_hello())?;
    sleep(2500);
    for i in 1..=10u64 {
        link.send(EngineMsg::Progress {
            phase: Phase::Apply,
            done: i * 10,
            total: 100,
        })?;
        sleep(250);
    }
    link.send(EngineMsg::Progress {
        phase: Phase::Launch,
        done: 0,
        total: 0,
    })?;
    sleep(2000);
    if ending == Ending::Failure {
        link.send(EngineMsg::Outcome(Outcome::RolledBack {
            from: scenario::NEW_VERSION.to_owned(),
            to: scenario::APP_VERSION.to_owned(),
        }))?;
        prompt(link, 1, PromptKind::RolledBack)?;
        link.wait_choice(None)?;
        return Ok(());
    }
    link.send(EngineMsg::Outcome(Outcome::Updated))?;
    sleep(500);
    Ok(())
}

/// Starts `program` as the UI and plays `flow` over its channel. Returns the binary's exit code.
pub fn drive(
    program: &Path,
    flow: Flow,
    os: Os,
    auto: bool,
    ending: Ending,
) -> Result<i32, String> {
    let mut link = Link::start(program, flow)?;
    link.handshake()?;
    let played = match flow {
        Flow::Install => install(&mut link, os, auto, ending),
        Flow::Uninstall => uninstall(&mut link, os, auto, ending),
        Flow::Update => update(&mut link, ending),
    };
    // A window left open by an error still gets its Close.
    let code = link.close()?;
    played?;
    Ok(code)
}
