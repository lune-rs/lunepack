//! A stand-in `lunepack-ui` for the end-to-end suite (M6 step 11): a small ELF that speaks the
//! engine's frame protocol with no window, so a release can carry it (`pack --ui` only takes an
//! executable image) and the suite can start it, kill it and count its starts without a GPU.
//!
//! It is started as the real UI is (`lunepack-ui --engine`, frames on standard input and output)
//! and is told what to do through the environment the runtime passes on:
//!
//! - `LUNEPACK_E2E_UI_DIR`: a directory it notes its life in, one file per kind and one line per
//!   event: `ui-spawns` (one line per start), `ui-hello` (the flow and the app's name) and
//!   `ui-prompts` (the kind of each prompt). Nothing is noted when it is unset.
//! - `LUNEPACK_E2E_UI_MODE`: `proceed` (the default) says hello, answers every `Ping` and takes
//!   the choice that lets the operation go on (proceed at the welcome and confirm screens, finish
//!   without launching, close, acknowledge); `die` does the same until the operation reports
//!   progress, a finished step or its outcome, and then aborts the process (SIGABRT).
//!
//! On Windows it is a GUI-subsystem program with the build's hardening (the runtime's `build.rs`
//! links examples too), because `pack --ui` holds a `windows-*` UI to the runtime's own image
//! rules (subsystem, `DependentLoadFlags`, manifest, no static `advapi32`).

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

use lunepack_core::ui::{self, ChoiceValue, EngineMsg, Flow, PromptKind, UiMsg};

const DIR_VAR: &str = "LUNEPACK_E2E_UI_DIR";
const MODE_VAR: &str = "LUNEPACK_E2E_UI_MODE";

fn note(name: &str, text: &str) {
    let Some(dir) = std::env::var_os(DIR_VAR) else {
        return;
    };
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(Path::new(&dir).join(name))
    {
        let _ = file.write_all(text.as_bytes());
    }
}

/// The choice that lets the operation go on.
fn choice(kind: PromptKind, flow: Option<Flow>) -> ChoiceValue {
    match kind {
        PromptKind::Welcome | PromptKind::Confirm => ChoiceValue::Proceed,
        PromptKind::Done if flow == Some(Flow::Uninstall) => ChoiceValue::Close,
        PromptKind::Done => ChoiceValue::Finish { launch: false },
        PromptKind::Failed => ChoiceValue::Close,
        PromptKind::RolledBack => ChoiceValue::Acknowledge,
    }
}

fn main() -> ExitCode {
    #[cfg(windows)]
    lunepack_os_windows::harden_dll_search();
    if std::env::args_os().nth(1).as_deref() != Some("--engine".as_ref())
        || std::env::args_os().count() != 2
    {
        eprintln!("usage: e2e_fake_ui --engine");
        return ExitCode::from(2);
    }
    let die = std::env::var(MODE_VAR).is_ok_and(|mode| mode == "die");
    note("ui-spawns", "start\n");
    let mut input = std::io::stdin().lock();
    let mut out = std::io::stdout().lock();
    let mut flow = None;
    loop {
        let Ok(msg) = ui::read_frame::<_, EngineMsg>(&mut input) else {
            return ExitCode::SUCCESS;
        };
        let reply = match msg {
            EngineMsg::Hello {
                build_id,
                flow: shown,
                app,
                ..
            } => {
                flow = Some(shown);
                note("ui-hello", &format!("{shown:?} {}\n", app.name));
                Some(UiMsg::Hello { build_id })
            }
            EngineMsg::Ping { n } => Some(UiMsg::Pong { n }),
            EngineMsg::Prompt { id, kind } => {
                note("ui-prompts", &format!("{kind:?}\n"));
                Some(UiMsg::Choice {
                    id,
                    value: choice(kind, flow),
                })
            }
            EngineMsg::Progress { .. } | EngineMsg::Step { .. } | EngineMsg::Outcome(_) if die => {
                std::process::abort();
            }
            EngineMsg::Close => return ExitCode::SUCCESS,
            _ => None,
        };
        if let Some(reply) = reply
            && ui::write_frame(&mut out, &reply).is_err()
        {
            return ExitCode::SUCCESS;
        }
    }
}
