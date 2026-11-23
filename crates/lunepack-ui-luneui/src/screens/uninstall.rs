//! The uninstall flow's screens: confirm, removing, done (with or without leftovers) and failed.

use lune_ui::access::{Node, Role, Value};
use lune_ui::paint::{Rect, StrokeStyle};
use lune_ui::ui::Ui;
use lune_ui::widgets::button::ButtonKind;

use lunepack_core::ui::{ChoiceValue, Outcome, Screen, StepItem, UiMsg};

use crate::look::{self, CONTENT_W, CONTENT_X, WARN, white};
use crate::model::step_bit;
use crate::strings;
use crate::widgets::{self, Tone};

use super::install::{fit_end, note, title};
use super::{Btn, Draw, Out};

/// Draws the main area of an uninstall screen.
pub(crate) fn main(ui: &mut Ui<'_>, d: &Draw<'_>) -> Out {
    match d.v.screen {
        Screen::UninstallConfirm => confirm(ui, d),
        Screen::Uninstalling => removing(ui, d),
        Screen::UninstallDone => done(ui, d),
        Screen::UninstallFailed => super::install::failed_screen(
            ui,
            d,
            strings::uninstall_failed_title(),
            &strings::uninstall_failed_note(&d.m.name),
            "Uninstall failed",
            false,
        ),
        Screen::AdminCommand => super::admin::command(ui, d),
        _ => Out::default(),
    }
}

const ROW_H: f32 = 30.0;

/// The icons of a list row, in the mock-up's stroke style.
#[derive(Clone, Copy)]
enum Icon {
    /// A window outline: the app.
    App,
    /// A diagonal arrow: shortcuts.
    Arrow,
    /// Four squares: the OS registration.
    Grid,
    /// A warning triangle: an item left behind.
    Warn,
}

fn icon(ui: &mut Ui<'_>, kind: Icon, x: f32, y: f32) {
    let p = ui.painter();
    match kind {
        Icon::App => p.ring(
            Rect::new(x + 1.5, y + 2.5, 11.0, 9.0),
            1.5,
            1.0,
            white(0.6),
            false,
        ),
        Icon::Arrow => {
            p.stroke(
                &[[x + 3.0, y + 11.0], [x + 11.0, y + 3.0]],
                false,
                StrokeStyle::solid(white(0.6), 1.2),
            );
            p.stroke(
                &[[x + 6.0, y + 3.0], [x + 11.0, y + 3.0], [x + 11.0, y + 8.0]],
                false,
                StrokeStyle::solid(white(0.6), 1.2),
            );
        }
        Icon::Grid => {
            for (dx, dy) in [(2.0, 2.0), (8.0, 2.0), (2.0, 8.0), (8.0, 8.0)] {
                p.ring(
                    Rect::new(x + dx, y + dy, 4.0, 4.0),
                    0.0,
                    1.0,
                    white(0.6),
                    false,
                );
            }
        }
        Icon::Warn => {
            let pts = [
                [x + 7.0, y + 2.0],
                [x + 13.0, y + 12.0],
                [x + 1.0, y + 12.0],
            ];
            p.stroke(&pts, true, StrokeStyle::solid(WARN, 1.3));
            p.stroke(
                &[[x + 7.0, y + 5.5], [x + 7.0, y + 8.5]],
                false,
                StrokeStyle::solid(WARN, 1.3),
            );
            p.fill(Rect::new(x + 6.2, y + 9.8, 1.6, 1.6), 0.8, WARN);
        }
    }
}

/// A card of rows at `y`: each a 14 px icon, a 10 px gap and the text, with white 7 % separators.
/// A row without an icon (`None`) is a plain line. Returns the card's bottom edge.
fn card(
    ui: &mut Ui<'_>,
    d: &Draw<'_>,
    y: f32,
    border: lune_ui::color::Rgba,
    rows: &[(Option<Icon>, String, bool)],
) -> f32 {
    let n = rows.len() as f32;
    let rect = Rect::new(
        CONTENT_X,
        y,
        CONTENT_W,
        2.0 + 8.0 + 31.0 * (n - 1.0) + ROW_H,
    );
    let p = ui.painter();
    p.fill(rect, 8.0, white(0.05));
    p.ring(rect, 8.0, 1.0, border, false);
    for (i, (ic, text, tail)) in rows.iter().enumerate() {
        let ry = rect.y + 5.0 + 31.0 * i as f32;
        if i + 1 < rows.len() {
            ui.painter().fill(
                Rect::new(rect.x + 14.0, ry + ROW_H, rect.w - 28.0, 1.0),
                0.0,
                white(0.07),
            );
        }
        let tx = rect.x + 14.0 + 14.0 + 10.0;
        let max_w = rect.right() - 14.0 - tx;
        let style = if ic.is_some() {
            look::style(13.0, 17.0, 400, white(0.8))
        } else {
            look::style(13.0, 17.0, 400, white(0.6))
        };
        if let Some(kind) = ic {
            icon(ui, *kind, rect.x + 14.0, ry + 8.0);
        }
        let x = if ic.is_some() { tx } else { rect.x + 14.0 };
        let max_w = if ic.is_some() { max_w } else { max_w + 24.0 };
        let shown = if *tail {
            fit_end(ui, text, style, max_w)
        } else {
            text.clone()
        };
        widgets::text(ui, x, ry + 6.5, &shown, style, Some(max_w));
        if d.live {
            let id = ui.id(("row", i));
            let mut node = Node::new(id, Role::StaticText, text, Rect::new(x, ry, max_w, ROW_H));
            node.value = Some(Value::Text(text.clone()));
            ui.node(node);
        }
    }
    rect.bottom()
}

fn confirm(ui: &mut Ui<'_>, d: &Draw<'_>) -> Out {
    let m = d.m;
    title(ui, d, &strings::uninstall_title(&m.name));
    let bottom = note(ui, d, &strings::uninstall_intro(m.env.os));
    let icons = [Icon::App, Icon::Arrow, Icon::Grid];
    let rows: Vec<(Option<Icon>, String, bool)> =
        strings::uninstall_items(m.env.os, m.location.as_deref())
            .into_iter()
            .enumerate()
            .map(|(i, t)| (Some(icons[i.min(2)]), t, false))
            .collect();
    card(ui, d, bottom + 12.0, white(0.1), &rows);

    let open = d.v.prompt.is_some();
    let (clicked, focused) = super::button_group(
        ui,
        d,
        &[
            Btn {
                name: "cancel",
                label: "Cancel",
                kind: ButtonKind::Secondary,
                enabled: open,
                danger: false,
            },
            Btn {
                name: "uninstall",
                label: "Uninstall",
                kind: ButtonKind::Primary,
                enabled: open,
                danger: true,
            },
        ],
    );
    let mut out = Out {
        focused,
        primary: d.choice(ChoiceValue::Proceed),
        ..Out::default()
    };
    if clicked[0] {
        out.msg = d.choice(ChoiceValue::Cancel);
    } else if clicked[1] {
        out.msg = d.choice(ChoiceValue::Proceed);
    }
    out
}

fn removing(ui: &mut Ui<'_>, d: &Draw<'_>) -> Out {
    title(ui, d, "Removing");
    let shortcuts_done = d.v.steps & step_bit(StepItem::Integrate) != 0;
    let bottom = note(ui, d, strings::uninstall_removing_note(shortcuts_done));
    let bar_y = bottom + 24.0;
    if d.v.known {
        let sheen =
            crate::anim::moves(d.tier).then(|| crate::anim::phase(d.t, widgets::SHEEN_PERIOD));
        widgets::bar(
            ui,
            "bar",
            d.live.then_some("Removing"),
            CONTENT_X,
            bar_y,
            CONTENT_W,
            d.v.bar,
            Tone::Running,
            sheen,
        );
        let pct = format!("{}%", (d.v.bar * 100.0).round() as u32);
        let cap = look::caption();
        let w = widgets::measure(ui, &pct, cap);
        widgets::text(ui, CONTENT_X + CONTENT_W - w, bar_y + 14.0, &pct, cap, None);
    } else {
        widgets::indeterminate_bar(
            ui,
            "bar",
            d.live.then_some("Removing"),
            CONTENT_X,
            bar_y,
            CONTENT_W,
            d.t,
            d.tier,
        );
    }
    if !d.v.cancellable {
        return Out::default();
    }
    let (clicked, focused) = super::button_group(
        ui,
        d,
        &[Btn {
            name: "cancel",
            label: "Cancel",
            kind: ButtonKind::Secondary,
            enabled: true,
            danger: false,
        }],
    );
    Out {
        msg: clicked[0].then_some(UiMsg::Cancel),
        focused,
        ..Out::default()
    }
}

/// The most rows the leftovers card shows.
const MAX_ROWS: usize = 3;

fn done(ui: &mut Ui<'_>, d: &Draw<'_>) -> Out {
    let m = d.m;
    let leftovers: &[String] = match &d.v.outcome {
        Some(Outcome::Uninstalled { leftovers }) => leftovers,
        _ => &[],
    };
    title(ui, d, &strings::uninstall_done_title(&m.name));
    let bottom = note(ui, d, &strings::uninstall_done_note(leftovers.len()));
    if !leftovers.is_empty() {
        let mut rows: Vec<(Option<Icon>, String, bool)> = Vec::new();
        if leftovers.len() > MAX_ROWS {
            for l in &leftovers[..MAX_ROWS - 1] {
                rows.push((Some(Icon::Warn), l.clone(), true));
            }
            rows.push((
                None,
                strings::and_more(leftovers.len() - (MAX_ROWS - 1)),
                false,
            ));
        } else {
            for l in leftovers {
                rows.push((Some(Icon::Warn), l.clone(), true));
            }
        }
        card(ui, d, bottom + 12.0, look::tint(WARN, 0.35), &rows);
    }

    let open = d.v.prompt.is_some();
    let mut group = Vec::new();
    if !leftovers.is_empty() {
        group.push(Btn {
            name: "reveal",
            label: "Show folder",
            kind: ButtonKind::Secondary,
            enabled: open,
            danger: false,
        });
    }
    group.push(Btn {
        name: "close",
        label: "Close",
        kind: ButtonKind::Primary,
        enabled: open,
        danger: false,
    });
    let (clicked, focused) = super::button_group(ui, d, &group);
    let mut out = Out {
        focused,
        primary: d.choice(ChoiceValue::Close),
        ..Out::default()
    };
    let last = group.len() - 1;
    if clicked[last] {
        out.msg = d.choice(ChoiceValue::Close);
    } else if group.len() == 2 && clicked[0] {
        out.msg = d.choice(ChoiceValue::Reveal { index: 0 });
    }
    out
}
