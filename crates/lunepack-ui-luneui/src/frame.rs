//! One frame of the installer window: background, corner glow, side rail, the main area with its
//! screen transition, and the caption buttons. Everything animated is a function of the frame
//! time `t` the caller passes and of the instants the model recorded.

use std::time::Duration;

use lune_ui::access::{Node, Role};
use lune_ui::input::{Event, Key, NamedKey};
use lune_ui::motion::{Easing, MotionTier};
use lune_ui::paint::{Rect, Xform};
use lune_ui::ui::Ui;

use lunepack_core::ui::{Flow, Screen, UiMsg};

use crate::anim;
use crate::chrome;
use crate::look;
use crate::model::{CLOSE_MS, ENTER_MS, LEAVE_MS, UiModel, WINDOW_IN_MS};
use crate::screens::{Draw, Out, install, uninstall, update};
use crate::strings::Os;

/// How far content slides when a screen changes, in logical pixels.
const SLIDE: f32 = 12.0;

/// Draws the current screen into `ui` at frame time `t` under `tier`, and returns what the user
/// answered this frame, already recorded in `model` (so the engine sees it once). The caller
/// sends the message, asks for another frame while [`UiModel::animating`] says so, and registers
/// [`UiModel::icon`] with the renderer under [`crate::ICON_IMAGE`].
pub fn frame(ui: &mut Ui<'_>, model: &mut UiModel, t: Duration, tier: MotionTier) -> Option<UiMsg> {
    let mt = model.metrics();
    let (w, h) = (mt.w, mt.h);
    chrome::background(ui, model.env.material, mt);
    if matches!(model.screen(), Screen::Idle | Screen::Closed) {
        return None;
    }

    // The window appears: a fade, a short rise and a settle from 0.98.
    let p_in = if anim::animates(tier) {
        anim::eased(Easing::QuadOut, t, model.opened, WINDOW_IN_MS)
    } else {
        1.0
    };
    let appearing = p_in < 1.0;
    if appearing {
        let full = anim::moves(tier);
        ui.painter().push_xform(Xform {
            origin: (w / 2.0, h / 2.0),
            scale: if full { 0.98 + 0.02 * p_in } else { 1.0 },
            dx: 0.0,
            dy: if full { 8.0 * (1.0 - p_in) } else { 0.0 },
            alpha: p_in,
        });
    }
    // After an update the window fades out: a fade and a settle to 0.98 over 180 ms.
    let closing = model.closing_since;
    if let Some(since) = closing {
        let p_out = if anim::animates(tier) {
            anim::eased(Easing::QuadIn, t, since, CLOSE_MS)
        } else {
            1.0
        };
        ui.painter().push_xform(Xform {
            origin: (w / 2.0, h / 2.0),
            scale: if anim::moves(tier) {
                1.0 - 0.02 * p_out
            } else {
                1.0
            },
            dx: 0.0,
            dy: 0.0,
            alpha: 1.0 - p_out,
        });
    }

    chrome::glow(ui, model, t, tier);
    chrome::rail(ui, model, t, tier);

    let title = model.window_title();
    let dialog_id = ui.id("window");
    let out = ui.node_container(
        Node::new(dialog_id, Role::Dialog, &title, Rect::new(0.0, 0.0, w, h)),
        |ui| main_area(ui, model, t, tier),
    );
    // macOS has its own buttons (M6-D14): the screens draw none there.
    let close_clicked = if model.env.os == Os::Macos {
        None
    } else {
        let caps = look::Captions::of(model.state().flow());
        chrome::caption_buttons(ui, true, w, caps.minimize, caps.close)
    };
    if closing.is_some() {
        ui.painter().pop_xform();
    }
    if appearing {
        ui.painter().pop_xform();
    }

    let mut msg = out.msg;
    if let Some(on) = out.launch {
        model.set_launch(on);
    }
    if let Some(on) = out.all_users {
        model.set_all_users(on);
    }
    match close_clicked {
        Some(true) => msg = msg.or_else(|| model.close_action()),
        Some(false) => model.request_minimize(),
        None => {}
    }
    if msg.is_none() {
        for ev in &ui.input().events {
            if let Event::Key {
                key: Key::Named(key),
                pressed: true,
                repeat: false,
                ..
            } = ev
            {
                match key {
                    NamedKey::Enter if !out.focused => msg = out.primary.clone(),
                    NamedKey::Escape => msg = model.escape_action(),
                    _ => {}
                }
                if msg.is_some() {
                    break;
                }
            }
        }
    }
    let msg = msg.filter(|m| model.state().accepts(m));
    if let Some(m) = &msg {
        let _ = model.sent(m, t);
    }
    if model.animating(t, tier) {
        ui.request_busy_frame(Rect::new(0.0, 0.0, w, h));
    }
    msg
}

/// The main area: the new screen, or, for the first 180 ms after a change, the old one leaving.
fn main_area(ui: &mut Ui<'_>, model: &UiModel, t: Duration, tier: MotionTier) -> Out {
    let el = t.saturating_sub(model.screen_since);
    let cur = model.view(t);
    let moving = model.prev.is_some()
        && anim::animates(tier)
        && el < Duration::from_millis(LEAVE_MS + ENTER_MS);
    let enter_at = if model.prev.is_some() {
        model.screen_since + Duration::from_millis(LEAVE_MS)
    } else {
        model.screen_since
    };
    let slide = |dx: f32, alpha: f32| Xform {
        origin: (0.0, 0.0),
        scale: 1.0,
        dx: if anim::moves(tier) { dx } else { 0.0 },
        dy: 0.0,
        alpha,
    };
    if moving && el < Duration::from_millis(LEAVE_MS) {
        let Some(prev) = &model.prev else {
            return Out::default();
        };
        let p = anim::eased(Easing::QuadIn, t, model.screen_since, LEAVE_MS);
        ui.painter().push_xform(slide(-SLIDE * p, 1.0 - p));
        let d = Draw {
            m: model,
            v: prev,
            t,
            tier,
            live: false,
            mt: model.metrics(),
            enter_at,
        };
        draw(ui, &d);
        ui.painter().pop_xform();
        return Out::default();
    }
    let p = if moving {
        anim::eased(Easing::QuadOut, t, enter_at, ENTER_MS)
    } else {
        1.0
    };
    if p < 1.0 {
        ui.painter().push_xform(slide(SLIDE * (1.0 - p), p));
    }
    let d = Draw {
        m: model,
        v: &cur,
        t,
        tier,
        live: true,
        mt: model.metrics(),
        enter_at,
    };
    let out = draw(ui, &d);
    if p < 1.0 {
        ui.painter().pop_xform();
    }
    out
}

fn draw(ui: &mut Ui<'_>, d: &Draw<'_>) -> Out {
    match d.m.state().flow() {
        Some(Flow::Install) => install::main(ui, d),
        Some(Flow::Update) => update::main(ui, d),
        Some(Flow::Uninstall) => uninstall::main(ui, d),
        None => Out::default(),
    }
}
