//! The update window's screens: waiting for the app to close, applying, starting the new version,
//! rolled back and failed. A small window with a narrow rail that holds the icon alone.

use lune_ui::paint::Rect;
use lune_ui::ui::Ui;
use lune_ui::widgets::button::ButtonKind;

use lunepack_core::ui::{ChoiceValue, Outcome, Screen, UiMsg};

use crate::look::{self, white};
use crate::strings;
use crate::widgets::{self, Tone};

use super::{Btn, Draw, Out};

/// Draws the main area of an update screen.
pub(crate) fn main(ui: &mut Ui<'_>, d: &Draw<'_>) -> Out {
    let m = d.m;
    match d.v.screen {
        Screen::UpdateWaiting => {
            heading(
                ui,
                d,
                &strings::update_waiting_title(&m.name),
                &strings::update_waiting_note(&m.version),
            );
            widgets::indeterminate_bar(
                ui,
                "bar",
                d.live.then_some("Waiting for the app to close"),
                d.mt.content_x,
                BAR_Y,
                d.mt.content_w(),
                d.t,
                d.tier,
            );
            cancel_only(ui, d)
        }
        Screen::UpdateApplying => {
            let percent = d.v.known.then(|| (d.v.bar * 100.0).round() as u32);
            heading(
                ui,
                d,
                &strings::update_applying_title(&m.version),
                &strings::update_applying_note(percent),
            );
            if d.v.known {
                running_bar(ui, d, "Updating", d.v.bar);
            } else {
                widgets::indeterminate_bar(
                    ui,
                    "bar",
                    d.live.then_some("Updating"),
                    d.mt.content_x,
                    BAR_Y,
                    d.mt.content_w(),
                    d.t,
                    d.tier,
                );
            }
            cancel_only(ui, d)
        }
        Screen::UpdateStarting => {
            heading(
                ui,
                d,
                &strings::update_starting_title(&m.name, &m.version),
                strings::update_starting_note(),
            );
            running_bar(ui, d, "Starting the new version", 1.0);
            Out::default()
        }
        Screen::UpdateRolledBack => {
            let (from, to) = match &d.v.outcome {
                Some(Outcome::RolledBack { from, to }) => (from.as_str(), to.as_str()),
                _ => ("", ""),
            };
            heading(
                ui,
                d,
                strings::update_rolled_back_title(),
                &strings::update_rolled_back_note(from, to),
            );
            widgets::bar(
                ui,
                "bar",
                d.live.then_some("Update undone"),
                d.mt.content_x,
                BAR_Y,
                d.mt.content_w(),
                1.0,
                Tone::Warn,
                None,
            );
            single_button(ui, d, "ok", "OK", ChoiceValue::Acknowledge)
        }
        Screen::UpdateFailed => failed(ui, d),
        _ => Out::default(),
    }
}

/// The bar's top: under the title and its line, with the mock-up's 10 px gap.
const BAR_Y: f32 = 85.0;

/// The title (14 on 20, Medium) and the line under it (11 on 15), both cut to the content width.
fn heading(ui: &mut Ui<'_>, d: &Draw<'_>, title: &str, note: &str) {
    let w = Some(d.mt.content_w());
    widgets::static_text(
        ui,
        "title",
        d.live,
        d.mt.content_x,
        d.mt.content_top,
        title,
        look::style(14.0, 20.0, 500, white(0.9)),
        w,
    );
    widgets::static_text(
        ui,
        "note",
        d.live,
        d.mt.content_x,
        d.mt.content_top + 24.0,
        note,
        look::caption(),
        w,
    );
}

fn running_bar(ui: &mut Ui<'_>, d: &Draw<'_>, name: &str, fraction: f32) {
    let sheen = crate::anim::moves(d.tier).then(|| crate::anim::phase(d.t, widgets::SHEEN_PERIOD));
    widgets::bar(
        ui,
        "bar",
        d.live.then_some(name),
        d.mt.content_x,
        BAR_Y,
        d.mt.content_w(),
        fraction,
        Tone::Running,
        sheen,
    );
}

/// A Cancel button, only while the engine allows cancelling.
fn cancel_only(ui: &mut Ui<'_>, d: &Draw<'_>) -> Out {
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

/// One primary button answering the open prompt with `value`.
fn single_button(
    ui: &mut Ui<'_>,
    d: &Draw<'_>,
    name: &str,
    label: &str,
    value: ChoiceValue,
) -> Out {
    let (clicked, focused) = super::button_group(
        ui,
        d,
        &[Btn {
            name,
            label,
            kind: ButtonKind::Primary,
            enabled: d.v.prompt.is_some(),
            danger: false,
        }],
    );
    Out {
        msg: if clicked[0] { d.choice(value) } else { None },
        primary: d.choice(value),
        focused,
        ..Out::default()
    }
}

/// The failed update: the title, the reason in the caption style (two lines at most), the error
/// bar at the fraction reached (full when the engine never reported one), Copy details bottom-left
/// and Close bottom-right.
fn failed(ui: &mut Ui<'_>, d: &Draw<'_>) -> Out {
    let m = d.m;
    let code = d.v.fail_code.unwrap_or(70);
    widgets::static_text(
        ui,
        "title",
        d.live,
        d.mt.content_x,
        d.mt.content_top,
        strings::update_failed_title(),
        look::style(14.0, 20.0, 500, white(0.9)),
        Some(d.mt.content_w()),
    );
    let reason = strings::failure_reason(code, &m.name);
    let h = widgets::clamped_text(
        ui,
        "reason",
        d.live,
        d.mt.content_x,
        d.mt.content_top + 24.0,
        d.mt.content_w(),
        &reason,
        look::caption(),
        2,
    );
    let fraction = if d.v.known { d.v.bar } else { 1.0 };
    widgets::bar(
        ui,
        "bar",
        d.live.then_some("Update failed"),
        d.mt.content_x,
        d.mt.content_top + 24.0 + h + 14.0,
        d.mt.content_w(),
        fraction,
        Tone::Err,
        None,
    );
    let open = d.v.prompt.is_some();
    let copy_w = widgets::button_width(ui, "Copy details", d.mt.btn_pad);
    let copy = widgets::button(
        ui,
        "copy",
        Rect::new(
            d.mt.content_x,
            d.mt.content_bottom - d.mt.btn_h,
            copy_w,
            d.mt.btn_h,
        ),
        "Copy details",
        ButtonKind::Secondary,
        true,
        d.live,
        None,
    );
    if copy.clicked {
        ui.clipboard_write(format!(
            "{} {}\nUpdate failed: {} (exit code {code})",
            m.name,
            m.version,
            strings::kind_name(code)
        ));
    }
    let (clicked, focused) = super::button_group(
        ui,
        d,
        &[Btn {
            name: "close",
            label: "Close",
            kind: ButtonKind::Primary,
            enabled: open,
            danger: false,
        }],
    );
    Out {
        msg: if clicked[0] {
            d.choice(ChoiceValue::Close)
        } else {
            None
        },
        primary: d.choice(ChoiceValue::Close),
        focused: focused || copy.focused,
        ..Out::default()
    }
}
