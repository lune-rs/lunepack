//! The view model: what the screens show, built from the engine's messages and the user's own
//! answers. It owns the instants every animation runs from (screen change, glow change, rail
//! move, bar retarget), recorded from the frame time the caller supplies, so a frame is a pure
//! function of the model and the time. It decides nothing: the engine validates every answer
//! ([`FlowState::accepts`]).

use std::time::Duration;

use lune_ui::image::ImageData;
use lune_ui::motion::Easing;

use lunepack_core::progress::Phase;
use lunepack_core::ui::{
    ChoiceValue, EngineMsg, Flow, FlowState, Outcome, ProtocolError, Screen, StepItem, UiMsg,
    check_hello,
};

use crate::anim;
use crate::icon;
use crate::strings::Os;

/// The window material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Material {
    /// An opaque background (Linux, and the software fallback).
    Opaque,
    /// LuneUI's near-black glass material (Windows and macOS).
    Glass,
}

/// What the screens run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Env {
    /// The OS, which picks the wording.
    pub os: Os,
    /// The window material.
    pub material: Material,
}

impl Env {
    /// This OS's defaults: opaque on Linux, glass on Windows and macOS.
    pub fn current() -> Env {
        let os = Os::current();
        Env {
            os,
            material: if os == Os::Linux {
                Material::Opaque
            } else {
                Material::Glass
            },
        }
    }
}

/// How long the window takes to appear, in ms.
pub const WINDOW_IN_MS: u64 = 250;
/// How long the window takes to fade out after an update, in ms.
pub const CLOSE_MS: u64 = 180;
/// How long the old content takes to leave, in ms.
pub const LEAVE_MS: u64 = 180;
/// How long the new content takes to arrive, in ms.
pub const ENTER_MS: u64 = 250;
/// How long the corner glow takes to cross-fade, in ms.
pub const GLOW_MS: u64 = 350;
/// How long the rail's highlight takes to move, in ms.
pub const RAIL_MS: u64 = 180;
/// How long the bar takes to follow a progress event, in ms.
pub const BAR_MS: u64 = 180;
/// How long a check or a failure mark takes to draw in, in ms.
pub const MARK_MS: u64 = 350;

/// The state of the corner glow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GlowKind {
    Idle,
    Running,
    Ok,
    Warn,
    Err,
}

/// What the main area draws for one screen: a snapshot, so the content that is leaving can still
/// be drawn after the model moved on.
#[derive(Debug, Clone)]
pub(crate) struct View {
    pub screen: Screen,
    pub bar: f32,
    pub steps: u16,
    pub caption: Option<(u64, u64)>,
    pub fail_code: Option<u32>,
    pub outcome: Option<Outcome>,
    pub known: bool,
    pub launch: bool,
    pub all_users: bool,
    pub prompt: Option<(u32, lunepack_core::ui::PromptKind)>,
    pub cancellable: bool,
}

fn bit(item: StepItem) -> u16 {
    1 << match item {
        StepItem::Verify => 0,
        StepItem::Stage => 1,
        StepItem::Commit => 2,
        StepItem::Integrate => 3,
        StepItem::WaitApp => 4,
        StepItem::Apply => 5,
        StepItem::Launch => 6,
        StepItem::Confirm => 7,
        StepItem::Rollback => 8,
        StepItem::Remove => 9,
    }
}

/// The checklist bit of an install step.
pub(crate) fn step_bit(item: StepItem) -> u16 {
    bit(item)
}

/// The rail row a screen is on.
fn rail_index(flow: Option<Flow>, screen: Screen) -> usize {
    match (flow, screen) {
        (Some(Flow::Install), Screen::InstallWelcome) => 0,
        (
            Some(Flow::Install),
            Screen::Installing | Screen::InstallFailed | Screen::AdminCommand | Screen::HandedOff,
        ) => 1,
        (Some(Flow::Install), Screen::InstallDone) => 2,
        (Some(Flow::Uninstall), Screen::UninstallConfirm) => 0,
        (
            Some(Flow::Uninstall),
            Screen::Uninstalling | Screen::UninstallFailed | Screen::AdminCommand,
        ) => 1,
        (Some(Flow::Uninstall), Screen::UninstallDone) => 2,
        _ => 0,
    }
}

fn glow_kind(screen: Screen, outcome: Option<&Outcome>) -> GlowKind {
    match screen {
        Screen::Idle | Screen::Closed => GlowKind::Idle,
        // Nothing ran and nothing failed: the command and the hand-off wait for the person.
        Screen::InstallWelcome
        | Screen::UninstallConfirm
        | Screen::AdminCommand
        | Screen::HandedOff => GlowKind::Idle,
        Screen::Installing
        | Screen::UpdateWaiting
        | Screen::UpdateApplying
        | Screen::UpdateStarting
        | Screen::Uninstalling => GlowKind::Running,
        Screen::InstallDone | Screen::UpdateRolledBack => match outcome {
            Some(Outcome::RolledBack { .. }) => GlowKind::Warn,
            _ => GlowKind::Ok,
        },
        Screen::UninstallDone => match outcome {
            Some(Outcome::Uninstalled { leftovers }) if !leftovers.is_empty() => GlowKind::Warn,
            _ => GlowKind::Ok,
        },
        Screen::InstallFailed | Screen::UpdateFailed | Screen::UninstallFailed => GlowKind::Err,
    }
}

/// What the screens show, and when each thing started changing.
#[derive(Debug, Clone)]
pub struct UiModel {
    pub(crate) env: Env,
    state: FlowState,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) publisher: Option<String>,
    pub(crate) location: Option<String>,
    pub(crate) all_users_location: Option<String>,
    pub(crate) size_bytes: Option<u64>,
    /// The command of [`EngineMsg::AdminCommand`], shown verbatim and never run.
    pub(crate) admin_command: Option<String>,
    pub(crate) icon: Option<ImageData>,
    steps: u16,
    caption: Option<(u64, u64)>,
    frac: f32,
    known: bool,
    bar_from: f32,
    bar_to: f32,
    bar_since: Duration,
    pub(crate) opened: Duration,
    pub(crate) screen_since: Duration,
    pub(crate) prev: Option<View>,
    pub(crate) glow_from: GlowKind,
    pub(crate) glow_to: GlowKind,
    pub(crate) glow_since: Duration,
    pub(crate) rail_from: usize,
    pub(crate) rail_to: usize,
    pub(crate) rail_since: Duration,
    pub(crate) done_since: [Option<Duration>; 3],
    pub(crate) launch: bool,
    pub(crate) all_users: bool,
    minimize: bool,
    pub(crate) closing_since: Option<Duration>,
    pub(crate) dim_since: Option<Duration>,
}

impl UiModel {
    /// A model that waits for the engine's hello.
    pub fn new(env: Env) -> UiModel {
        UiModel {
            env,
            state: FlowState::new(),
            name: String::new(),
            version: String::new(),
            publisher: None,
            location: None,
            all_users_location: None,
            size_bytes: None,
            admin_command: None,
            icon: None,
            steps: 0,
            caption: None,
            frac: 0.0,
            known: false,
            bar_from: 0.0,
            bar_to: 0.0,
            bar_since: Duration::ZERO,
            opened: Duration::ZERO,
            screen_since: Duration::ZERO,
            prev: None,
            glow_from: GlowKind::Idle,
            glow_to: GlowKind::Idle,
            glow_since: Duration::ZERO,
            rail_from: 0,
            rail_to: 0,
            rail_since: Duration::ZERO,
            done_since: [None; 3],
            launch: true,
            all_users: false,
            minimize: false,
            closing_since: None,
            dim_since: None,
        }
    }

    /// The reducer's state.
    pub fn state(&self) -> &FlowState {
        &self.state
    }

    /// The window's title: what the flow does to the app.
    pub fn window_title(&self) -> String {
        match self.state.flow() {
            Some(Flow::Install) => format!("Install {}", self.name),
            Some(Flow::Update) => format!("Update {}", self.name),
            Some(Flow::Uninstall) => format!("Uninstall {}", self.name),
            None => "Lunepack".to_owned(),
        }
    }

    /// The sizes of the window this flow shows.
    pub fn metrics(&self) -> crate::look::Metrics {
        crate::look::Metrics::of(self.state.flow())
    }

    /// The screen to show.
    pub fn screen(&self) -> Screen {
        self.state.screen()
    }

    /// Whether the engine closed the window.
    pub fn is_closed(&self) -> bool {
        self.state.screen() == Screen::Closed
    }

    /// The decoded icon, to register with the renderer under [`icon::ICON_IMAGE`]; `None` draws
    /// the monogram.
    pub fn icon(&self) -> Option<&ImageData> {
        self.icon.as_ref()
    }

    /// Whether the user asked to minimize since the last call (the binary owns the window).
    pub fn take_minimize(&mut self) -> bool {
        std::mem::take(&mut self.minimize)
    }

    pub(crate) fn request_minimize(&mut self) {
        self.minimize = true;
    }

    pub(crate) fn set_launch(&mut self, on: bool) {
        self.launch = on;
    }

    pub(crate) fn set_all_users(&mut self, on: bool) {
        self.all_users = on;
    }

    /// The bar's value at `t`: the tween toward the latest target.
    pub(crate) fn bar_value(&self, t: Duration) -> f32 {
        let e = anim::eased(Easing::QuadOut, t, self.bar_since, BAR_MS);
        self.bar_from + (self.bar_to - self.bar_from) * e
    }

    pub(crate) fn view(&self, t: Duration) -> View {
        View {
            screen: self.state.screen(),
            bar: self.bar_value(t),
            steps: self.steps,
            caption: self.caption,
            fail_code: match self.state.outcome() {
                Some(Outcome::Failed { code } | Outcome::UninstallFailed { code }) => Some(*code),
                _ => None,
            },
            outcome: self.state.outcome().cloned(),
            known: self.known,
            launch: self.launch,
            all_users: self.all_users,
            prompt: self.state.open_prompt(),
            cancellable: self.state.cancellable(),
        }
    }

    /// Applies a message the engine sent, at frame time `t`.
    ///
    /// # Errors
    /// A hello with another build id, or a message that is out of order.
    pub fn apply(&mut self, msg: &EngineMsg, t: Duration) -> Result<(), ProtocolError> {
        if let EngineMsg::Hello { build_id, .. } = msg {
            check_hello(build_id)?;
        }
        let before = self.view(t);
        self.state.apply(msg)?;
        match msg {
            EngineMsg::Hello { app, details, .. } => {
                self.name = app.name.clone();
                self.version = app.version.clone();
                self.publisher = app.publisher.clone();
                self.location = details.location.clone();
                self.all_users_location = details.all_users_location.clone();
                self.size_bytes = details.size_bytes;
                self.icon = app.icon_png.as_deref().and_then(|b| icon::decode(b).ok());
                self.opened = t;
            }
            EngineMsg::Progress { phase, done, total } => {
                let counts = match self.state.flow() {
                    Some(Flow::Install) => {
                        matches!(phase, Phase::Download | Phase::Stage | Phase::Install)
                            && self.steps & bit(StepItem::Stage) == 0
                    }
                    Some(Flow::Update) => matches!(phase, Phase::Apply),
                    Some(Flow::Uninstall) => matches!(phase, Phase::Uninstall),
                    None => false,
                };
                if counts && *total > 0 {
                    self.caption = Some((*done, *total));
                    self.frac = (*done as f64 / *total as f64).clamp(0.0, 1.0) as f32;
                    self.known = true;
                }
            }
            EngineMsg::Step { item } => {
                self.steps |= bit(*item);
                if *item == StepItem::Stage {
                    self.frac = 1.0;
                    if let Some((_, total)) = self.caption {
                        self.caption = Some((total, total));
                    }
                }
            }
            EngineMsg::AdminCommand { command } => self.admin_command = Some(command.clone()),
            EngineMsg::Outcome(Outcome::Updated) => self.closing_since = Some(t),
            EngineMsg::Outcome(Outcome::Uninstalled { .. }) => self.dim_since = Some(t),
            _ => {}
        }
        self.sync(&before, t);
        Ok(())
    }

    /// Records a message the UI sent (after the caller found it valid), at frame time `t`: the
    /// UI side of the same reducer.
    ///
    /// # Errors
    /// The reducer does not accept the message now.
    pub fn sent(&mut self, msg: &UiMsg, t: Duration) -> Result<(), ProtocolError> {
        let before = self.view(t);
        self.state.answer(msg)?;
        if let UiMsg::Choice {
            value: ChoiceValue::Retry,
            ..
        } = msg
        {
            self.steps = 0;
            self.caption = None;
            self.frac = 0.0;
            self.known = false;
        }
        self.sync(&before, t);
        Ok(())
    }

    fn bar_target(&self) -> f32 {
        match self.state.outcome() {
            Some(
                Outcome::Installed
                | Outcome::Updated
                | Outcome::RolledBack { .. }
                | Outcome::Uninstalled { .. },
            ) => 1.0,
            Some(Outcome::Failed { .. } | Outcome::UninstallFailed { .. }) => self.bar_to,
            // One fraction drives the bar, the percentage and the bytes: the staged bytes done of
            // the total. Nothing before the first byte pair; full once the files are staged.
            _ if self.state.screen() == Screen::UpdateStarting => 1.0,
            _ => self.frac,
        }
    }

    fn sync(&mut self, before: &View, t: Duration) {
        let screen = self.state.screen();
        if screen != before.screen {
            self.screen_since = t;
            self.prev = (before.screen != Screen::Idle).then(|| before.clone());
        }
        let kind = glow_kind(screen, self.state.outcome());
        if kind != self.glow_to {
            self.glow_from = self.glow_to;
            self.glow_to = kind;
            self.glow_since = t;
        }
        let idx = rail_index(self.state.flow(), screen);
        if idx != self.rail_to {
            self.rail_from = self.rail_to;
            self.rail_to = idx;
            self.rail_since = t;
        }
        for (i, since) in self.done_since.iter_mut().enumerate() {
            let finished =
                i < idx && matches!(self.state.flow(), Some(Flow::Install | Flow::Uninstall));
            match (finished, *since) {
                (true, None) => *since = Some(t),
                (false, Some(_)) => *since = None,
                _ => {}
            }
        }
        let target = self.bar_target();
        if (target - self.bar_to).abs() > 1e-4 {
            self.bar_from = before.bar;
            self.bar_to = target;
            self.bar_since = t;
        }
    }

    /// Whether anything is still moving at `t`: the caller asks for another frame while it is.
    pub fn animating(&self, t: Duration, tier: lune_ui::motion::MotionTier) -> bool {
        if !anim::animates(tier) || self.state.screen() == Screen::Idle {
            return false;
        }
        let running = matches!(
            self.state.screen(),
            Screen::Installing
                | Screen::UpdateWaiting
                | Screen::UpdateApplying
                | Screen::UpdateStarting
                | Screen::Uninstalling
        ) && self.state.outcome().is_none();
        (running && anim::animates(tier) && (anim::moves(tier) || !self.known))
            || anim::running(t, self.opened, WINDOW_IN_MS)
            || anim::running(t, self.screen_since, LEAVE_MS + ENTER_MS)
            || anim::running(t, self.glow_since, GLOW_MS)
            || anim::running(t, self.rail_since, RAIL_MS)
            || self
                .closing_since
                .is_some_and(|s| anim::running(t, s, CLOSE_MS))
            || self.dim_since.is_some_and(|s| anim::running(t, s, GLOW_MS))
            || anim::running(t, self.bar_since, BAR_MS)
            || self
                .done_since
                .iter()
                .flatten()
                .any(|s| anim::running(t, *s, MARK_MS))
    }

    /// Whether the window may be closed now: the engine closed it, or the update finished and the
    /// window has faded out (`Outcome::Updated`, 180 ms). The binary closes the window then.
    pub fn closable(&self, t: Duration, tier: lune_ui::motion::MotionTier) -> bool {
        self.is_closed()
            || self
                .closing_since
                .is_some_and(|s| !anim::animates(tier) || !anim::running(t, s, CLOSE_MS))
    }

    /// The answer to the window's close button or the OS close request: the screen's Cancel or
    /// Close, or the done screen's finish without launching. `None` when nothing may be answered
    /// now.
    pub fn close_action(&self) -> Option<UiMsg> {
        self.pick(true)
    }

    /// The answer to Esc: the screen's Cancel or Close where it has one.
    pub fn escape_action(&self) -> Option<UiMsg> {
        self.pick(false)
    }

    fn pick(&self, finish_ok: bool) -> Option<UiMsg> {
        use lunepack_core::ui::PromptKind as K;
        let candidates: Vec<UiMsg> = match self.state.open_prompt() {
            Some((id, kind)) => {
                let c = |value| UiMsg::Choice { id, value };
                match kind {
                    K::Welcome | K::Confirm => vec![c(ChoiceValue::Cancel)],
                    K::Failed => vec![c(ChoiceValue::Close)],
                    K::Done if self.state.flow() == Some(Flow::Uninstall) => {
                        vec![c(ChoiceValue::Close)]
                    }
                    K::Done if finish_ok => vec![
                        c(ChoiceValue::Finish { launch: false }),
                        c(ChoiceValue::Close),
                    ],
                    K::Done => vec![],
                    // Esc has nothing to cancel on a rolled-back update; the window's close
                    // button (which the update window lacks) and Enter acknowledge it.
                    K::RolledBack if finish_ok => vec![c(ChoiceValue::Acknowledge)],
                    K::RolledBack => vec![],
                    // The only thing to answer; Esc and the window's close button close it.
                    K::AdminCommand | K::HandedOff => vec![c(ChoiceValue::Close)],
                }
            }
            None => vec![UiMsg::Cancel],
        };
        candidates.into_iter().find(|m| self.state.accepts(m))
    }
}
