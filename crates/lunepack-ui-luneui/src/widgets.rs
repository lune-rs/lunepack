//! The small drawing pieces the screens share: text, buttons, the checkbox, the progress bar,
//! marks and the spinner. Buttons use LuneUI's own look (`ButtonLook`) with the mock-up's label
//! weight; everything else is drawn with the painter so the marks can draw in.

use std::f32::consts::TAU;
use std::time::Duration;

use lune_ui::access::{Action, Node, Role, State, Value};
use lune_ui::color::Rgba;
use lune_ui::input::NamedKey;
use lune_ui::motion::{Easing, Kind, Motion, MotionTier, cubic_bezier};
use lune_ui::paint::{Rect, StrokeStyle, Xform};
use lune_ui::text::Spec;
use lune_ui::ui::{Sense, Ui};
use lune_ui::widgets::button::{ButtonKind, ButtonLook, ButtonState, FOCUS, HOVER, PRESS};
use lune_ui::widgets::focus_ring::{self, RingKind};

use crate::look::{self, ERR, white};

/// `text` at `(x, y)` in `style`, cut to `max_w` with an ellipsis when given. Returns its size.
pub(crate) fn text(
    ui: &mut Ui<'_>,
    x: f32,
    y: f32,
    text: &str,
    style: lune_ui::text::Style,
    max_w: Option<f32>,
) -> (f32, f32) {
    let mut spec = Spec::plain(text, style);
    if let Some(w) = max_w {
        spec = ui.painter().elide(&spec, w);
    }
    ui.painter().text(&spec, x, y)
}

/// Text drawn and exposed as a static-text node.
#[allow(clippy::too_many_arguments)]
pub(crate) fn static_text(
    ui: &mut Ui<'_>,
    key: &str,
    emit: bool,
    x: f32,
    y: f32,
    s: &str,
    style: lune_ui::text::Style,
    max_w: Option<f32>,
) -> (f32, f32) {
    let size = text(ui, x, y, s, style, max_w);
    if emit {
        let id = ui.id(key);
        let mut node = Node::new(id, Role::StaticText, s, Rect::new(x, y, size.0, size.1));
        node.value = Some(Value::Text(s.to_owned()));
        ui.node(node);
    }
    size
}

/// Wrapped text at `(x, y)`; returns its size.
pub(crate) fn wrapped(
    ui: &mut Ui<'_>,
    x: f32,
    y: f32,
    w: f32,
    s: &str,
    style: lune_ui::text::Style,
) -> (f32, f32) {
    ui.painter().text(&Spec::plain(s, style).wrapped(w), x, y)
}

/// Wrapped text drawn and exposed as a static-text node. Returns its size.
#[allow(clippy::too_many_arguments)]
pub(crate) fn static_wrapped(
    ui: &mut Ui<'_>,
    key: &str,
    emit: bool,
    x: f32,
    y: f32,
    w: f32,
    s: &str,
    style: lune_ui::text::Style,
) -> (f32, f32) {
    let size = wrapped(ui, x, y, w, s, style);
    if emit {
        let id = ui.id(key);
        let mut node = Node::new(id, Role::StaticText, s, Rect::new(x, y, size.0, size.1));
        node.value = Some(Value::Text(s.to_owned()));
        ui.node(node);
    }
    size
}

/// `s` wrapped to `w` and cut to `max_lines`: when it needs more, the last line is elided with an
/// ellipsis. Exposed as one static-text node. Returns the height drawn.
#[allow(clippy::too_many_arguments)]
pub(crate) fn clamped_text(
    ui: &mut Ui<'_>,
    key: &str,
    emit: bool,
    x: f32,
    y: f32,
    w: f32,
    s: &str,
    style: lune_ui::text::Style,
    max_lines: usize,
) -> f32 {
    let spec = Spec::plain(s, style).wrapped(w);
    let lines = ui.painter().text_lines(&spec);
    let height = if lines.len() <= max_lines {
        ui.painter().text(&spec, x, y).1
    } else {
        // The first lines as they wrap, the last one carrying the rest, cut to the width.
        let mut cursor = y;
        for line in &lines[..max_lines - 1] {
            let part = s.get(line.start..line.end).unwrap_or_default().trim_end();
            cursor += ui.painter().text(&Spec::plain(part, style), x, cursor).1;
        }
        let rest = s.get(lines[max_lines - 1].start..).unwrap_or_default();
        let one = ui.painter().elide(&Spec::plain(rest, style), w);
        cursor += ui.painter().text(&one, x, cursor).1;
        cursor - y
    };
    if emit {
        let id = ui.id(key);
        let mut node = Node::new(id, Role::StaticText, s, Rect::new(x, y, w, height));
        node.value = Some(Value::Text(s.to_owned()));
        ui.node(node);
    }
    height
}

/// The width of `s` in `style`.
pub(crate) fn measure(ui: &mut Ui<'_>, s: &str, style: lune_ui::text::Style) -> f32 {
    ui.painter().measure(&Spec::plain(s, style)).0
}

/// The label style of a button.
pub(crate) fn label_style(color: Rgba) -> lune_ui::text::Style {
    look::style(13.0, 17.0, 500, color)
}

/// A button's width: its label and `pad` px each side.
pub(crate) fn button_width(ui: &mut Ui<'_>, label: &str, pad: f32) -> f32 {
    measure(ui, label, label_style([255; 4])) + 2.0 * pad
}

/// What a button reported.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ButtonOut {
    pub clicked: bool,
    pub focused: bool,
}

/// A button in `rect`: LuneUI's `ButtonKind` look, 13 px Medium label, hover and press as the
/// toolkit animates them (press scales every kind by 0.98). `interactive` false draws it at rest
/// with no hit region and no node (the content that is leaving). `enabled` false dims it and
/// reports nothing.
#[allow(clippy::too_many_arguments)]
pub(crate) fn button(
    ui: &mut Ui<'_>,
    key: &str,
    rect: Rect,
    label: &str,
    kind: ButtonKind,
    enabled: bool,
    interactive: bool,
    label_color: Option<Rgba>,
) -> ButtonOut {
    if !interactive {
        let theme = *ui.theme();
        let mut look = ButtonLook::of(&theme, kind, ButtonState::default());
        look.label = label_color.unwrap_or(look.label);
        paint_button(ui, rect, label, &look, 0.0);
        return ButtonOut::default();
    }
    if enabled {
        button_live(ui, key, rect, label, kind, label_color)
    } else {
        ui.with_enabled(false, |ui| {
            button_live(ui, key, rect, label, kind, label_color)
        })
    }
}

fn button_live(
    ui: &mut Ui<'_>,
    key: &str,
    rect: Rect,
    label: &str,
    kind: ButtonKind,
    label_color: Option<Rgba>,
) -> ButtonOut {
    let id = ui.id(key);
    let theme = *ui.theme();
    let mut r = ui.interact(id, rect, Sense::CLICK_FOCUS);
    if r.enabled && (ui.consume_key(id, NamedKey::Enter) || ui.consume_key(id, NamedKey::Space)) {
        r.clicked = true;
    }
    let state = ButtonState {
        hovered: r.hovered,
        pressed: r.pressed,
        focus_visible: r.focus_visible,
    };
    let target = ButtonLook::of(&theme, kind, state);
    let fill = ui.animate_color(id.with("fill"), target.fill, &HOVER);
    let scale = ui.animate_f32(id.with("press"), if r.pressed { 0.98 } else { 1.0 }, &PRESS);
    let ring = ui.animate_f32(id.with("ring"), target.ring, &FOCUS);
    let look = ButtonLook {
        fill,
        label: label_color.unwrap_or(target.label),
        scale,
        ring,
    };
    paint_button(ui, rect, label, &look, ring);
    let mut node = Node::new(id, Role::Button, label, rect);
    if r.enabled {
        node.states.insert(State::Focusable);
        node.actions.insert(Action::Default);
    }
    ui.node(node);
    ButtonOut {
        clicked: r.clicked && r.enabled,
        focused: r.focused,
    }
}

fn paint_button(ui: &mut Ui<'_>, rect: Rect, label: &str, look: &ButtonLook, ring: f32) {
    let p = ui.painter();
    let radius = p.theme.item_radius;
    let scaled = look.scale != 1.0;
    if scaled {
        p.push_xform(Xform {
            origin: (rect.x + rect.w / 2.0, rect.y + rect.h / 2.0),
            scale: look.scale,
            dx: 0.0,
            dy: 0.0,
            alpha: 1.0,
        });
    }
    if look.fill[3] > 0 {
        p.fill(rect, radius, look.fill);
    }
    p.text_centered(&Spec::plain(label, label_style(look.label)), rect);
    focus_ring::paint(p, rect, RingKind::Button, ring);
    if scaled {
        p.pop_xform();
    }
}

/// A checkbox with its label: a 16 px box, the accent fill and a white check when on. Space
/// toggles it. Returns whether it is focused.
pub(crate) fn checkbox(
    ui: &mut Ui<'_>,
    key: &str,
    rect: Rect,
    label: &str,
    checked: &mut bool,
    interactive: bool,
) -> bool {
    let theme = *ui.theme();
    let style = look::style(13.0, 17.0, 400, white(0.8));
    let label_w = measure(ui, label, style);
    let boxr = Rect::new(rect.x, rect.y + (rect.h - 16.0) / 2.0, 16.0, 16.0);
    let hit = Rect::new(rect.x, rect.y, 24.0 + label_w, rect.h);
    let (mut hovered, mut focus_visible, mut focused) = (false, false, false);
    let id = ui.id(key);
    if interactive {
        let r = ui.interact(id, hit, Sense::CLICK_FOCUS);
        if r.clicked || ui.consume_key(id, NamedKey::Space) {
            *checked = !*checked;
        }
        hovered = r.hovered;
        focus_visible = r.focus_visible;
        focused = r.focused;
    }
    let sel = Motion::of(Kind::Selection);
    let on = *checked;
    let fill = ui.animate_color(
        id.with("fill"),
        if on {
            theme.accent
        } else if hovered {
            theme.surface_hover
        } else {
            look::tint(theme.accent, 0.0)
        },
        &sel,
    );
    let ring = ui.animate_color(
        id.with("ring"),
        if on { white(0.0) } else { white(0.3) },
        &sel,
    );
    let mark = ui.animate_color(
        id.with("mark"),
        if on { white(1.0) } else { white(0.0) },
        &sel,
    );
    let focus = ui.animate_f32(
        id.with("focus"),
        if focus_visible { 1.0 } else { 0.0 },
        &FOCUS,
    );
    let p = ui.painter();
    if fill[3] > 0 {
        p.fill(boxr, 3.0, fill);
    }
    if ring[3] > 0 {
        p.ring(boxr, 3.0, 1.0, ring, false);
    }
    if mark[3] > 0 {
        let pts = check_points(boxr.x + 3.0, boxr.y + 3.0, 10.0);
        p.stroke(&pts, false, StrokeStyle::solid(mark, 1.6));
    }
    focus_ring::paint(p, boxr, RingKind::Offset { radius: 3.0 }, focus);
    p.text_in(
        &Spec::plain(label, style),
        Rect::new(boxr.right() + 8.0, rect.y, rect.w, rect.h),
        0.0,
    );
    if interactive {
        let mut node = Node::new(id, Role::Checkbox, label, hit);
        if on {
            node.states.insert(State::Checked);
        }
        node.states.insert(State::Focusable);
        node.actions.insert(Action::Default);
        ui.node(node);
    }
    focused
}

/// The check's three points in a box of `size` at `(x, y)` (the mock-up's 10-unit path).
pub(crate) fn check_points(x: f32, y: f32, size: f32) -> Vec<[f32; 2]> {
    let k = size / 10.0;
    [[1.5, 5.2], [3.7, 7.4], [8.5, 2.6]]
        .iter()
        .map(|p| [x + p[0] * k, y + p[1] * k])
        .collect()
}

/// The first `fraction` of the polyline `pts` by length.
pub(crate) fn partial(pts: &[[f32; 2]], fraction: f32) -> Vec<[f32; 2]> {
    let f = fraction.clamp(0.0, 1.0);
    if f >= 1.0 || pts.len() < 2 {
        return pts.to_vec();
    }
    let len = |a: [f32; 2], b: [f32; 2]| ((b[0] - a[0]).powi(2) + (b[1] - a[1]).powi(2)).sqrt();
    let total: f32 = pts.windows(2).map(|w| len(w[0], w[1])).sum();
    let mut left = total * f;
    let mut out = vec![pts[0]];
    for w in pts.windows(2) {
        let l = len(w[0], w[1]);
        if left >= l {
            out.push(w[1]);
            left -= l;
        } else {
            let k = if l > 0.0 { left / l } else { 0.0 };
            out.push([
                w[0][0] + (w[1][0] - w[0][0]) * k,
                w[0][1] + (w[1][1] - w[0][1]) * k,
            ]);
            break;
        }
    }
    out
}

/// A check mark of `size` at `(x, y)` that draws in over `MARK_MS` from `since`: the stroke grows
/// under Full, and fades in under Reduced; Off shows it whole.
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_mark(
    ui: &mut Ui<'_>,
    x: f32,
    y: f32,
    size: f32,
    color: Rgba,
    since: Option<Duration>,
    t: Duration,
    tier: MotionTier,
) {
    let p = if since.is_some() && tier != MotionTier::Off {
        crate::anim::eased(
            Easing::CUBIC_OUT,
            t,
            since.unwrap_or_default(),
            crate::model::MARK_MS,
        )
    } else {
        1.0
    };
    if p <= 0.0 {
        return;
    }
    let pts = check_points(x, y, size);
    let painter = ui.painter();
    if crate::anim::moves(tier) {
        painter.stroke(&partial(&pts, p), false, StrokeStyle::solid(color, 1.6));
    } else {
        painter.stroke(
            &pts,
            false,
            StrokeStyle::solid(crate::look::tint(color, p * color[3] as f32 / 255.0), 1.6),
        );
    }
}

/// The bar's colours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tone {
    Running,
    Ok,
    Warn,
    Err,
}

impl Tone {
    fn stops(self) -> ([u8; 3], [u8; 3], [u8; 3], f32, Rgba) {
        match self {
            Tone::Running => (
                [0x5E, 0x64, 0x6B],
                [0x9A, 0xA1, 0xA9],
                [0xE2, 0xE5, 0xE8],
                0.55,
                [201, 205, 210, 89],
            ),
            Tone::Ok => (
                [0x3F, 0x8A, 0x5B],
                [0x73, 0xC9, 0x91],
                [0xB3, 0xE8, 0xC6],
                0.6,
                [115, 201, 145, 102],
            ),
            Tone::Warn => (
                [0x8A, 0x6F, 0x1F],
                [0xE2, 0xB9, 0x3D],
                [0xF3, 0xDC, 0x94],
                0.65,
                [226, 185, 61, 102],
            ),
            Tone::Err => (
                [0x8E, 0x3B, 0x43],
                [0xE0, 0x6C, 0x75],
                [0xF2, 0xA7, 0xAD],
                0.7,
                [224, 108, 117, 102],
            ),
        }
    }
}

/// The sheen's period.
pub(crate) const SHEEN_PERIOD: Duration = Duration::from_millis(1800);

/// A 6 px progress bar of `fraction` at `(x, y)` over `w`: a gradient fill with a soft glow, and
/// a sheen band while `sheen` holds the phase (0 to 1). `name` and the value become the node.
#[allow(clippy::too_many_arguments)]
pub(crate) fn bar(
    ui: &mut Ui<'_>,
    key: &str,
    emit: Option<&str>,
    x: f32,
    y: f32,
    w: f32,
    fraction: f32,
    tone: Tone,
    sheen: Option<f32>,
) {
    let fraction = fraction.clamp(0.0, 1.0);
    let track = Rect::new(x, y, w, 6.0);
    let (a, b, c, stop, glow) = tone.stops();
    let rgb = |c: [u8; 3]| [c[0], c[1], c[2], 255];
    let fw = w * fraction;
    let p = ui.painter();
    p.fill(track, 3.0, white(0.08));
    p.ring(track, 3.0, 1.0, white(0.05), false);
    if fw >= 1.0 {
        let fill = Rect::new(x, y, fw, 6.0);
        p.push_clip_rounded(track, 3.0);
        p.shadow(fill, 3.0, 5.0, glow);
        p.pop_clip();
        p.push_clip_rounded(fill, 3.0);
        // The two halves meet on a whole device pixel, so neither edge is antialiased against the
        // other (an overlap would show as a seam while the bar fades).
        let sc = p.s.max(1.0);
        let split = (((x + fw * stop) * sc).round() / sc - x).clamp(0.0, fw);
        p.linear(Rect::new(x, y, split, 6.0), 0.0, rgb(a), rgb(b), 0.0);
        p.linear(
            Rect::new(x + split, y, fw - split, 6.0),
            0.0,
            rgb(b),
            rgb(c),
            0.0,
        );
        if let Some(ph) = sheen {
            let e = cubic_bezier(0.45, 0.0, 0.55, 1.0, ph);
            // The two halves meet on a whole device pixel, so neither edge is antialiased
            // against the other and no seam shows at the peak.
            let s = p.s.max(1.0);
            let snap = |v: f32| (v * s).round() / s;
            let center = snap(x + fw * (-0.5 + 2.0 * e));
            let half = snap(0.15 * fw).max(1.0 / s);
            p.linear(
                Rect::new(center - half, y, half, 6.0),
                0.0,
                white(0.0),
                white(0.65),
                0.0,
            );
            p.linear(
                Rect::new(center, y, half, 6.0),
                0.0,
                white(0.65),
                white(0.0),
                0.0,
            );
        }
        p.pop_clip();
    }
    if let Some(name) = emit {
        let id = ui.id(key);
        let mut node = Node::new(id, Role::Progress, name, track);
        node.value = Some(Value::Number {
            value: f64::from(fraction * 100.0),
            min: 0.0,
            max: 100.0,
            step: 0.0,
        });
        ui.node(node);
    }
}

/// The spinner: a 12 px ring with an arc on it; the arc turns once per 500 ms under Full and
/// stays put under Reduced and Off.
pub(crate) fn spinner(ui: &mut Ui<'_>, cx: f32, cy: f32, t: Duration, tier: MotionTier) {
    let turn = if crate::anim::moves(tier) {
        crate::anim::phase(t, Duration::from_millis(500)) * TAU
    } else {
        0.0
    };
    let p = ui.painter();
    p.arc(
        [cx, cy],
        5.25,
        0.0,
        TAU,
        StrokeStyle::solid(white(0.2), 1.5),
    );
    p.arc(
        [cx, cy],
        5.25,
        -0.75 * std::f32::consts::PI + turn,
        std::f32::consts::FRAC_PI_2,
        StrokeStyle::solid(look::DOT, 1.5),
    );
}

/// A pending marker: a ring.
pub(crate) fn pending_ring(ui: &mut Ui<'_>, cx: f32, cy: f32) {
    ui.painter().arc(
        [cx, cy],
        4.0,
        0.0,
        TAU,
        StrokeStyle::solid(white(0.35), 1.0),
    );
}

/// The failure mark (a circle with an exclamation point) of `size` 16 at `(x, y)`: the circle
/// overshoots slightly and the bar draws in under Full; it fades in under Reduced; Off shows it.
pub(crate) fn failure_mark(
    ui: &mut Ui<'_>,
    x: f32,
    y: f32,
    since: Duration,
    t: Duration,
    tier: MotionTier,
) {
    let p = if tier == MotionTier::Off {
        1.0
    } else {
        crate::anim::progress(t, since, crate::model::MARK_MS)
    };
    let (cx, cy) = (x + 8.0, y + 8.0);
    let painter = ui.painter();
    let full = crate::anim::moves(tier);
    let (radius, alpha, bang) = if full {
        (
            7.0 * Easing::BackOut.eval(p),
            1.0,
            Easing::CUBIC_OUT.eval(p),
        )
    } else {
        (7.0, p, 1.0)
    };
    painter.push_xform(Xform {
        origin: (cx, cy),
        scale: 1.0,
        dx: 0.0,
        dy: 0.0,
        alpha,
    });
    painter.arc(
        [cx, cy],
        radius.max(0.01),
        0.0,
        TAU,
        StrokeStyle::solid(ERR, 1.4),
    );
    painter.stroke(
        &partial(&[[x + 8.0, y + 4.5], [x + 8.0, y + 9.0]], bang),
        false,
        StrokeStyle::solid(ERR, 1.6),
    );
    painter.fill(
        Rect::new(x + 8.0 - 0.9, y + 11.3 - 0.9, 1.8, 1.8),
        0.9,
        look::tint(ERR, bang),
    );
    painter.pop_xform();
}

/// One sweep of the indeterminate bar.
pub(crate) const SWEEP_PERIOD: Duration = Duration::from_millis(2400);
/// One breath of the Reduced indeterminate bar.
pub(crate) const BREATH_PERIOD: Duration = Duration::from_millis(1800);

/// An indeterminate 6 px bar at `(x, y)` over `w`: a soft band sweeps across the track every 2.4 s
/// under Full; under Reduced the band fills the track and breathes in opacity (0.38 to 1, 1.8 s,
/// no movement); under Off it holds at 0.38.
#[allow(clippy::too_many_arguments)]
pub(crate) fn indeterminate_bar(
    ui: &mut Ui<'_>,
    key: &str,
    emit: Option<&str>,
    x: f32,
    y: f32,
    w: f32,
    t: Duration,
    tier: MotionTier,
) {
    let track = Rect::new(x, y, w, 6.0);
    let (lo, mid, hi) = ([0x9A, 0xA1, 0xA9], [0x9A, 0xA1, 0xA9], [0xE2, 0xE5, 0xE8]);
    let rgba = |c: [u8; 3], a: u8| [c[0], c[1], c[2], a];
    let p = ui.painter();
    p.fill(track, 3.0, white(0.08));
    p.ring(track, 3.0, 1.0, white(0.05), false);
    p.push_clip_rounded(track, 3.0);
    let (left, bw, alpha) = match tier {
        MotionTier::Full => {
            let e = cubic_bezier(0.45, 0.0, 0.55, 1.0, crate::anim::phase(t, SWEEP_PERIOD));
            let bw = 0.35 * w;
            (x + bw * (-1.0 + 3.9 * e), bw, 1.0)
        }
        MotionTier::Reduced => {
            let ph = crate::anim::phase(t, BREATH_PERIOD);
            let tri = if ph < 0.5 { ph * 2.0 } else { (1.0 - ph) * 2.0 };
            (
                x,
                w,
                0.38 + 0.62 * (0.5 - 0.5 * (std::f32::consts::PI * tri).cos()),
            )
        }
        MotionTier::Off => (x, w, 0.38),
    };
    p.push_xform(Xform {
        origin: (x, y),
        scale: 1.0,
        dx: 0.0,
        dy: 0.0,
        alpha,
    });
    // The segments meet on whole device pixels, so no antialiased edge pair leaves a seam.
    let sc = p.s.max(1.0);
    let snap = |v: f32| (v * sc).round() / sc;
    let edges = [0.0, 0.4, 0.6, 1.0].map(|k| snap(left + bw * k));
    let stops = [(lo, 0, mid, 255), (mid, 255, hi, 255), (hi, 255, hi, 0)];
    for (i, (c0, a0, c1, a1)) in stops.into_iter().enumerate() {
        let (x0, x1) = (edges[i], edges[i + 1]);
        if x1 > x0 {
            p.linear(
                Rect::new(x0, y, x1 - x0, 6.0),
                0.0,
                rgba(c0, a0),
                rgba(c1, a1),
                0.0,
            );
        }
    }
    p.pop_xform();
    p.pop_clip();
    if let Some(name) = emit {
        let id = ui.id(key);
        let mut node = Node::new(id, Role::Progress, name, track);
        node.states.insert(State::Busy);
        ui.node(node);
    }
}
