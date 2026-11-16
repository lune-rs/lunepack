//! The parts of a window that do not change from screen to screen: the background, the corner
//! glow, the side rail and the caption buttons.

use std::f32::consts::TAU;
use std::time::Duration;

use lune_ui::access::{Action, Node, Role, State};
use lune_ui::color::Rgba;
use lune_ui::image::{Fit, ImageAlign};
use lune_ui::motion::{Easing, MotionTier};
use lune_ui::paint::{Falloff, Rect, StrokeStyle, Xform};
use lune_ui::ui::{Sense, Ui};
use lune_ui::widgets::button::HOVER;

use lunepack_core::ui::Flow;

use crate::anim;
use crate::icon::ICON_IMAGE;
use crate::look::{self, CAPTION_W, ERR, OK, TITLE_H, WARN, white};
use crate::model::{GLOW_MS, GlowKind, Material, RAIL_MS, UiModel};
use crate::strings::{INSTALL_STEPS, UNINSTALL_STEPS};
use crate::widgets;

/// The window's own background.
pub(crate) fn background(ui: &mut Ui<'_>, material: Material, mt: look::Metrics) {
    let theme = *ui.theme();
    let (w, h) = (mt.w, mt.h);
    let color = match material {
        Material::Opaque => lune_ui::color::premul(look::BG_OPAQUE),
        Material::Glass => theme.glass.window.premultiplied(),
    };
    ui.painter()
        .acrylic(Rect::new(0.0, 0.0, w, h), 0.0, color, [0.0; 4], false);
}

/// The corner glow's peak colour and opacity.
fn glow_peak(kind: GlowKind) -> (Rgba, f32) {
    match kind {
        GlowKind::Idle => (white(1.0), 0.04),
        GlowKind::Running => (white(1.0), 0.09),
        GlowKind::Ok => (OK, 0.12),
        GlowKind::Warn => (WARN, 0.12),
        GlowKind::Err => (ERR, 0.12),
    }
}

/// The breathing factor of a running glow: 0.7 to 1.0 over 2.4 s under Full; steady 1.0 under
/// Reduced and Off (opacity breathing is a loop, which Reduced stops).
fn breath(kind: GlowKind, t: Duration, tier: MotionTier) -> f32 {
    if kind == GlowKind::Running && anim::moves(tier) {
        let ph = anim::phase(t, Duration::from_millis(2400));
        0.7 + 0.3 * (0.5 - 0.5 * (TAU * ph).cos())
    } else {
        1.0
    }
}

/// A small, subtle radial glow in the window's top-left corner that follows the state; a state
/// change cross-fades over 350 ms.
pub(crate) fn glow(ui: &mut Ui<'_>, m: &UiModel, t: Duration, tier: MotionTier) {
    let e = if anim::animates(tier) {
        anim::eased(Easing::SineInOut, t, m.glow_since, GLOW_MS)
    } else {
        1.0
    };
    let mut layers: Vec<(GlowKind, f32)> = Vec::with_capacity(2);
    if m.glow_from != m.glow_to && e < 1.0 {
        layers.push((m.glow_from, 1.0 - e));
    }
    layers.push((m.glow_to, if m.glow_from != m.glow_to { e } else { 1.0 }));
    let p = ui.painter();
    for (kind, weight) in layers {
        let (color, peak) = glow_peak(kind);
        let alpha = peak * breath(kind, t, tier) * weight;
        if alpha <= 0.0 {
            continue;
        }
        let (c, r) = m.metrics().glow;
        p.push_xform(Xform {
            origin: (c, c),
            scale: 1.0,
            dx: 0.0,
            dy: 0.0,
            alpha,
        });
        p.radial(
            [c, c],
            [r, r],
            look::tint(color, 1.0),
            look::tint(color, 0.0),
            Falloff::Linear,
        );
        p.pop_xform();
    }
}

const ROW0: f32 = 152.0;
const ROW_STEP: f32 = 34.0;

/// The side rail: the app's identity (it never moves) and the steps of the flow.
pub(crate) fn rail(ui: &mut Ui<'_>, m: &UiModel, t: Duration, tier: MotionTier) {
    let mt = m.metrics();
    let (rail_w, h) = (mt.rail_w, mt.h);
    let p = ui.painter();
    p.fill(Rect::new(0.0, 0.0, rail_w, h), 0.0, [0, 0, 0, 71]);
    p.fill(Rect::new(rail_w - 1.0, 0.0, 1.0, h), 0.0, white(0.08));

    // The update window's rail holds the icon alone, centred.
    let compact = m.state().flow() == Some(Flow::Update);
    let tile = Rect::new(
        if compact { (rail_w - 48.0) / 2.0 } else { 20.0 },
        28.0,
        48.0,
        48.0,
    );
    let id = ui.id("rail-icon");
    // After an uninstall the icon eases to half opacity (an opacity change, so Reduced keeps it).
    let dim = m.dim_since.map_or(0.0, |since| {
        if anim::animates(tier) {
            anim::eased(Easing::QuadOut, t, since, GLOW_MS)
        } else {
            1.0
        }
    });
    let icon_alpha = 1.0 - 0.5 * dim;
    if m.icon.is_some() {
        ui.painter().image(
            tile,
            ICON_IMAGE,
            Fit::Contain,
            ImageAlign::CENTER,
            icon_alpha,
        );
    } else {
        ui.painter().push_xform(Xform {
            origin: (0.0, 0.0),
            scale: 1.0,
            dx: 0.0,
            dy: 0.0,
            alpha: icon_alpha,
        });
        monogram(ui, tile, &m.name);
        ui.painter().pop_xform();
    }
    let mut node = Node::new(id, Role::Image, &m.name, tile);
    node.description = Some("App icon".to_owned());
    ui.node(node);

    if compact {
        return;
    }
    let inner_w = rail_w - 28.0 - 12.0;
    widgets::static_text(
        ui,
        "rail-name",
        true,
        20.0,
        94.0,
        &m.name,
        look::style(14.0, 18.0, 500, white(0.9)),
        Some(inner_w),
    );
    // "Version 1.4.0" cross-fades to "Removed" once an uninstall is done.
    let version_style = look::caption();
    let removed = m.dim_since.is_some();
    for (text, alpha, key) in [
        (format!("Version {}", m.version), 1.0 - dim, "rail-version"),
        ("Removed".to_owned(), dim, "rail-removed"),
    ] {
        if alpha <= 0.0 || (key == "rail-removed" && !removed) {
            continue;
        }
        ui.painter().push_xform(Xform {
            origin: (0.0, 0.0),
            scale: 1.0,
            dx: 0.0,
            dy: 0.0,
            alpha,
        });
        widgets::static_text(
            ui,
            key,
            true,
            20.0,
            116.0,
            &text,
            version_style,
            Some(inner_w),
        );
        ui.painter().pop_xform();
    }

    let flow = m.state().flow();
    let steps: &[&str] = match flow {
        Some(Flow::Install) | None => &INSTALL_STEPS,
        Some(Flow::Uninstall) => &UNINSTALL_STEPS,
        Some(Flow::Update) => &[],
    };
    // The highlight: slides under Full, cross-fades under Reduced, jumps under Off.
    let row_y = |i: f32| ROW0 + i * ROW_STEP;
    let row = |y: f32| Rect::new(14.0, y, rail_w - 28.0, 30.0);
    let hl = white(0.09);
    let p_move = anim::progress(t, m.rail_since, RAIL_MS);
    let (from, to) = (m.rail_from as f32, m.rail_to as f32);
    if tier == MotionTier::Off || m.rail_from == m.rail_to || p_move >= 1.0 {
        ui.painter().fill(row(row_y(to)), 6.0, hl);
    } else if anim::moves(tier) {
        let pos = from + (to - from) * Easing::Linear.eval(p_move);
        ui.painter().fill(row(row_y(pos)), 6.0, hl);
    } else {
        let p = ui.painter();
        p.fill(row(row_y(from)), 6.0, look::tint(hl, (1.0 - p_move) * 0.09));
        p.fill(row(row_y(to)), 6.0, look::tint(hl, p_move * 0.09));
    }

    // A change the model recorded at `t` shows from the next instant on, so the frame at the
    // moment of the answer still equals the screen before it.
    let switched = t > m.rail_since;
    let now_idx = if switched { m.rail_to } else { m.rail_from };
    for (i, label) in steps.iter().enumerate() {
        let y = row_y(i as f32);
        let (cx, cy) = (31.0, y + 15.0);
        let current = i == now_idx;
        let finished = m.done_since[i].filter(|since| t > *since);
        if finished.is_some() {
            widgets::check_mark(ui, cx - 5.0, cy - 5.0, 10.0, OK, finished, t, tier);
        } else if current {
            let color = match m.glow_to {
                GlowKind::Err => ERR,
                GlowKind::Ok => OK,
                GlowKind::Warn => WARN,
                GlowKind::Idle | GlowKind::Running => look::DOT,
            };
            ui.painter()
                .fill(Rect::new(cx - 3.5, cy - 3.5, 7.0, 7.0), 3.5, color);
        } else {
            ui.painter().arc(
                [cx, cy],
                3.0,
                0.0,
                TAU,
                StrokeStyle::solid(white(0.45), 1.0),
            );
        }
        let color = if current { white(0.92) } else { white(0.6) };
        widgets::text(
            ui,
            48.0,
            y + 6.5,
            label,
            look::style(13.0, 17.0, 400, color),
            None,
        );
        let id = ui.id(("rail-step", i));
        let state = if finished.is_some() {
            "done"
        } else if current {
            "current"
        } else {
            "pending"
        };
        let mut node = Node::new(
            id,
            Role::StaticText,
            &format!("Step {} of {}: {}, {}", i + 1, steps.len(), label, state),
            row(y),
        );
        if current {
            node.states.insert(State::Current);
        }
        ui.node(node);
    }
}

/// The tile shown when the app has no icon that decodes: the first letter on a dark tile.
pub(crate) fn monogram(ui: &mut Ui<'_>, tile: Rect, name: &str) {
    let letter: String = name
        .chars()
        .find(|c| !c.is_whitespace())
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_default();
    let p = ui.painter();
    p.fill(tile, 10.0, look::TILE);
    p.ring(tile, 10.0, 1.0, white(0.2), false);
    p.text_centered(
        &lune_ui::text::Spec::plain(letter, look::style(22.0, 28.0, 500, white(0.8))),
        tile,
    );
}

/// The title strip's buttons: Minimize and Close, 46 by 32 at the top right. Returns which was
/// clicked: `Some(false)` for Minimize and `Some(true)` for Close.
pub(crate) fn caption_buttons(
    ui: &mut Ui<'_>,
    interactive: bool,
    w: f32,
    minimize: bool,
    close_button: bool,
) -> Option<bool> {
    let mut clicked = None;
    let shown: Vec<bool> = [(false, minimize), (true, close_button)]
        .into_iter()
        .filter(|(_, on)| *on)
        .map(|(close, _)| close)
        .collect();
    let n = shown.len();
    for (i, close) in shown.into_iter().enumerate() {
        let x = w - CAPTION_W * (n - i) as f32;
        let rect = Rect::new(x, 0.0, CAPTION_W, TITLE_H);
        let id = ui.id(if close {
            "caption-close"
        } else {
            "caption-min"
        });
        let mut hovered = false;
        if interactive {
            let r = ui.interact(id, rect, Sense::CLICK);
            hovered = r.hovered;
            if r.clicked {
                clicked = Some(close);
            }
        }
        let theme = *ui.theme();
        let target = if !hovered {
            white(0.0)
        } else if close {
            theme.caption_close_hover
        } else {
            white(0.1)
        };
        let fill = ui.animate_color(id.with("fill"), target, &HOVER);
        let glyph = if close && hovered {
            white(1.0)
        } else {
            white(0.75)
        };
        let p = ui.painter();
        if fill[3] > 0 {
            p.fill(rect, 0.0, fill);
        }
        let (cx, cy) = (x + CAPTION_W / 2.0, TITLE_H / 2.0);
        if close {
            p.stroke(
                &[[cx - 5.0, cy - 5.0], [cx + 5.0, cy + 5.0]],
                false,
                StrokeStyle::solid(glyph, 1.0),
            );
            p.stroke(
                &[[cx + 5.0, cy - 5.0], [cx - 5.0, cy + 5.0]],
                false,
                StrokeStyle::solid(glyph, 1.0),
            );
        } else {
            p.stroke(
                &[[cx - 5.0, cy + 0.5], [cx + 5.0, cy + 0.5]],
                false,
                StrokeStyle::solid(glyph, 1.0),
            );
        }
        if interactive {
            let mut node = Node::new(
                id,
                Role::Button,
                if close { "Close" } else { "Minimize" },
                rect,
            );
            node.actions.insert(Action::Default);
            ui.node(node);
        }
    }
    clicked
}
