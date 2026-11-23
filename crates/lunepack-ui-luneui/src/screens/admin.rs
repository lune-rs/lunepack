//! The two screens that end an operation the window cannot finish itself (M11 step 8): the
//! command to run in a terminal as an administrator (Linux without a prompt of its own, M11-D9;
//! an unelevated repair or uninstall on macOS, M11-D14), and "continue in Installer" (the macOS
//! `.pkg`, M11-D8). Both sit where the failed screens do: a title and a line, a card, Close at the
//! bottom right. The command is the engine's text, shown as it is and never run here.

use lune_ui::paint::Rect;
use lune_ui::text::Spec;
use lune_ui::ui::Ui;
use lune_ui::widgets::button::ButtonKind;
use lune_ui::widgets::scroll_area::{Bars, Extent, ScrollOptions};

use lunepack_core::ui::{ChoiceValue, Flow};

use crate::look::{self, CONTENT_BOTTOM, CONTENT_W, CONTENT_X, white};
use crate::strings;
use crate::widgets;

use super::install::{note, title};
use super::{Btn, Draw, Out};

/// The card's lowest edge: a button's height and a gap above the button row.
const CARD_BOTTOM: f32 = CONTENT_BOTTOM - 32.0 - 16.0;
/// The text's inset in the card: sides and top and bottom.
const PAD_X: f32 = 14.0;
const PAD_Y: f32 = 11.0;

/// The command's text style (the welcome card's value style).
fn command_style() -> lune_ui::text::Style {
    look::style(13.0, 17.0, 400, white(0.85))
}

/// The screen with the command to run as an administrator.
pub(crate) fn command(ui: &mut Ui<'_>, d: &Draw<'_>) -> Out {
    let m = d.m;
    let command = m.admin_command.as_deref().unwrap_or_default();
    title(ui, d, strings::admin_command_title());
    let note_bottom = note(
        ui,
        d,
        &strings::admin_command_note(m.state().flow() == Some(Flow::Install), &m.name),
    );

    // The card holds the whole text; a text taller than the room scrolls inside it, clipped to
    // the inner rectangle, and is never cut or elided.
    let style = command_style();
    let inner_w = CONTENT_W - 2.0 * PAD_X;
    let spec = Spec::plain(command, style).wrapped(inner_w);
    let text_h = ui.painter().measure(&spec).1;
    let top = note_bottom + 18.0;
    // A text that does not fit gets a whole number of lines, so the first view never cuts a line
    // in half at the card's edge; the rest scrolls.
    let room = CARD_BOTTOM - top - 2.0 * PAD_Y;
    let shown_h = if text_h <= room {
        text_h
    } else {
        (room / style.line).floor() * style.line
    };
    let height = 2.0 * PAD_Y + shown_h;
    let card = Rect::new(CONTENT_X, top, CONTENT_W, height);
    {
        let p = ui.painter();
        p.fill(card, 8.0, white(0.05));
        p.ring(card, 8.0, 1.0, white(0.1), false);
    }
    let inner = Rect::new(
        card.x + PAD_X,
        card.y + PAD_Y,
        inner_w,
        card.h - 2.0 * PAD_Y,
    );
    if !d.live {
        // Leaving: the picture only, clipped to the card as the live scroll area is.
        let p = ui.painter();
        p.push_clip(inner);
        p.text(&spec, inner.x, inner.y);
        p.pop_clip();
    } else if text_h <= inner.h {
        ui.selectable_text(
            "command",
            Rect::new(inner.x, inner.y, inner_w, text_h),
            &spec,
            command,
        );
    } else {
        let opts = ScrollOptions {
            bars: (Bars::Disabled, Bars::Auto),
            ..ScrollOptions::default()
        };
        ui.scroll_area("command-scroll", inner, &opts, |ui, view| {
            let at = view.viewport;
            ui.selectable_text(
                "command",
                Rect::new(at.x, at.y, inner_w, text_h),
                &spec,
                command,
            );
            ((), Extent::new(f64::from(inner_w), f64::from(text_h)))
        });
    }

    let open = d.v.prompt.is_some();
    let copy_w = widgets::button_width(ui, strings::admin_command_copy(), d.mt.btn_pad);
    let copy = widgets::button(
        ui,
        "copy",
        Rect::new(CONTENT_X, CONTENT_BOTTOM - 32.0, copy_w, 32.0),
        strings::admin_command_copy(),
        ButtonKind::Secondary,
        true,
        d.live,
        None,
    );
    if copy.clicked {
        ui.clipboard_write(command.to_owned());
    }
    close_out(ui, d, open, copy.focused)
}

/// The screen that says to continue in the system's installer.
pub(crate) fn handed_off(ui: &mut Ui<'_>, d: &Draw<'_>) -> Out {
    title(ui, d, strings::handed_off_title());
    note(ui, d, &strings::handed_off_note(&d.m.name));
    let open = d.v.prompt.is_some();
    close_out(ui, d, open, false)
}

/// The Close button, alone at the bottom right, and what Enter answers.
fn close_out(ui: &mut Ui<'_>, d: &Draw<'_>, open: bool, other_focus: bool) -> Out {
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
        focused: focused || other_focus,
        ..Out::default()
    }
}
