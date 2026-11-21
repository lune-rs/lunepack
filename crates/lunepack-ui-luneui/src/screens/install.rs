//! The install flow's four screens: welcome, installing, done and failed.

use lune_ui::access::{Node, Role, Value};
use lune_ui::paint::{Rect, StrokeStyle};
use lune_ui::text::{Spec, Style};
use lune_ui::ui::Ui;
use lune_ui::widgets::button::ButtonKind;

use lunepack_core::ui::{ChoiceValue, Screen, StepItem, UiMsg};

use crate::look::{self, CONTENT_BOTTOM, CONTENT_TOP, CONTENT_W, CONTENT_X, ERR, OK, white};
use crate::model::step_bit;
use crate::strings;
use crate::widgets::{self, Tone};

use super::{Btn, Draw, Out};

/// Draws the main area of an install screen.
pub(crate) fn main(ui: &mut Ui<'_>, d: &Draw<'_>) -> Out {
    match d.v.screen {
        Screen::InstallWelcome => welcome(ui, d),
        Screen::Installing => installing(ui, d),
        Screen::InstallDone => done(ui, d),
        Screen::InstallFailed => failed(ui, d),
        _ => Out::default(),
    }
}

pub(crate) fn title(ui: &mut Ui<'_>, d: &Draw<'_>, text: &str) {
    widgets::static_text(
        ui,
        "title",
        d.live,
        CONTENT_X,
        CONTENT_TOP,
        text,
        look::h1(),
        Some(CONTENT_W),
    );
}

/// The line under the title, wrapped to the content; returns its bottom edge.
pub(crate) fn note(ui: &mut Ui<'_>, d: &Draw<'_>, text: &str) -> f32 {
    let (_, h) = widgets::static_wrapped(
        ui,
        "note",
        d.live,
        CONTENT_X,
        70.0,
        CONTENT_W,
        text,
        look::body(),
    );
    70.0 + h
}

fn welcome(ui: &mut Ui<'_>, d: &Draw<'_>) -> Out {
    let m = d.m;
    // The all-users choice exists only when the engine offered it; ticked, the note and the
    // location describe the install for everyone.
    let offered = m.state().all_users_offered();
    let mut all_users = offered && d.v.all_users;
    title(ui, d, &strings::install_title(&m.name));
    let scope_note = if all_users {
        strings::install_scope_all_users()
    } else {
        strings::install_scope()
    };
    let note_bottom = note(ui, d, scope_note);

    // The card: location, size and, when the package names one, the verified publisher.
    let mut rows: Vec<(&str, String, bool)> = Vec::new();
    let location = if all_users {
        m.all_users_location.as_ref()
    } else {
        m.location.as_ref()
    };
    if let Some(loc) = location {
        rows.push(("Location", loc.clone(), false));
    }
    if let Some(size) = m.size_bytes {
        rows.push(("Size", strings::size_text(size), false));
    }
    if let Some(publisher) = &m.publisher {
        rows.push(("Publisher", format!("{publisher}, verified"), true));
    }
    if !rows.is_empty() {
        let n = rows.len() as f32;
        let card = Rect::new(
            CONTENT_X,
            note_bottom + 18.0,
            CONTENT_W,
            2.0 + 8.0 + 33.0 * (n - 1.0) + 32.0,
        );
        let p = ui.painter();
        p.fill(card, 8.0, white(0.05));
        p.ring(card, 8.0, 1.0, white(0.1), false);
        for (i, (label, value, verified)) in rows.iter().enumerate() {
            let y = card.y + 5.0 + 33.0 * i as f32;
            if i + 1 < rows.len() {
                ui.painter().fill(
                    Rect::new(card.x + 14.0, y + 32.0, card.w - 28.0, 1.0),
                    0.0,
                    white(0.07),
                );
            }
            let key_style = look::style(13.0, 17.0, 400, white(0.6));
            let value_style = look::style(13.0, 17.0, 400, white(0.85));
            widgets::text(ui, card.x + 14.0, y + 7.5, label, key_style, None);
            let key_w = widgets::measure(ui, label, key_style);
            let mark_w = if *verified { 18.0 } else { 0.0 };
            let max_w = card.w - 28.0 - key_w - 16.0 - mark_w;
            let shown = fit_end(ui, value, value_style, max_w);
            let w = widgets::measure(ui, &shown, value_style);
            let right = card.right() - 14.0;
            widgets::text(ui, right - w, y + 7.5, &shown, value_style, None);
            if *verified {
                let mx = right - w - 18.0;
                let pts = [
                    [mx + 2.0, y + 16.5],
                    [mx + 4.5, y + 19.0],
                    [mx + 10.0, y + 13.5],
                ];
                ui.painter()
                    .stroke(&pts, false, StrokeStyle::solid(OK, 1.6));
            }
        }
    }

    let open = d.v.prompt.is_some();
    // Bottom-left, level with the buttons, as the done screen's checkbox; drawn before them so
    // the Tab order is the box, Cancel, Install.
    let before = all_users;
    let box_focus = offered
        && widgets::checkbox(
            ui,
            "all_users",
            Rect::new(CONTENT_X, CONTENT_BOTTOM - 32.0, 200.0, 32.0),
            strings::install_all_users_label(),
            &mut all_users,
            d.live && open,
        );
    let proceed = if all_users {
        ChoiceValue::ProceedAllUsers
    } else {
        ChoiceValue::Proceed
    };
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
                name: "install",
                label: "Install",
                kind: ButtonKind::Primary,
                enabled: open,
                danger: false,
            },
        ],
    );
    let mut out = Out {
        focused: focused || box_focus,
        primary: d.choice(proceed),
        all_users: (all_users != before).then_some(all_users),
        ..Out::default()
    };
    if clicked[0] {
        out.msg = d.choice(ChoiceValue::Cancel);
    } else if clicked[1] {
        out.msg = d.choice(proceed);
    }
    out
}

/// `text` cut at its start so its tail (the folder name of a path) stays, within `max_w`.
pub(crate) fn fit_end(ui: &mut Ui<'_>, text: &str, style: Style, max_w: f32) -> String {
    if widgets::measure(ui, text, style) <= max_w {
        return text.to_owned();
    }
    let chars: Vec<char> = text.chars().collect();
    let (mut lo, mut hi) = (0usize, chars.len());
    // The fewest dropped leading characters that fit.
    while lo < hi {
        let mid = (lo + hi) / 2;
        let cand: String = std::iter::once('\u{2026}')
            .chain(chars[mid..].iter().copied())
            .collect();
        if widgets::measure(ui, &cand, style) <= max_w {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    std::iter::once('\u{2026}')
        .chain(chars[lo..].iter().copied())
        .collect()
}

/// The checklist bits in the order the engine reports them.
const ROW_ITEMS: [StepItem; 4] = [
    StepItem::Verify,
    StepItem::Stage,
    StepItem::Integrate,
    StepItem::Commit,
];

fn installing(ui: &mut Ui<'_>, d: &Draw<'_>) -> Out {
    title(ui, d, "Installing");
    let v = d.v;
    let sheen = crate::anim::moves(d.tier).then(|| crate::anim::phase(d.t, widgets::SHEEN_PERIOD));
    widgets::bar(
        ui,
        "bar",
        d.live.then_some("Installation progress"),
        CONTENT_X,
        80.0,
        CONTENT_W,
        v.bar,
        Tone::Running,
        sheen,
    );
    let cap = look::caption();
    if let Some((done, total)) = v.caption {
        widgets::text(
            ui,
            CONTENT_X,
            94.0,
            &strings::progress_text(done, total),
            cap,
            None,
        );
    }
    let pct = format!("{}%", (v.bar * 100.0).round() as u32);
    let w = widgets::measure(ui, &pct, cap);
    widgets::text(ui, CONTENT_X + CONTENT_W - w, 94.0, &pct, cap, None);

    let mut running_seen = false;
    for (i, label) in strings::install_rows(d.m.env.os).iter().enumerate() {
        let y = 125.0 + 26.0 * i as f32;
        let (cx, cy) = (CONTENT_X + 6.0, y + 13.0);
        let done = v.steps & step_bit(ROW_ITEMS[i]) != 0;
        let (color, kind) = if done {
            (white(0.75), 0)
        } else if !running_seen {
            running_seen = true;
            (white(0.92), 1)
        } else {
            (white(0.6), 2)
        };
        match kind {
            0 => widgets::check_mark(ui, cx - 6.0, cy - 6.0, 12.0, OK, None, d.t, d.tier),
            1 => widgets::spinner(ui, cx, cy, d.t, d.tier),
            _ => widgets::pending_ring(ui, cx, cy),
        }
        widgets::text(
            ui,
            CONTENT_X + 22.0,
            y + 4.5,
            label,
            look::style(13.0, 17.0, 400, color),
            None,
        );
    }

    let (clicked, focused) = super::button_group(
        ui,
        d,
        &[Btn {
            name: "cancel",
            label: "Cancel",
            kind: ButtonKind::Secondary,
            enabled: v.cancellable,
            danger: false,
        }],
    );
    Out {
        msg: clicked[0].then_some(UiMsg::Cancel),
        focused,
        ..Out::default()
    }
}

fn done(ui: &mut Ui<'_>, d: &Draw<'_>) -> Out {
    let m = d.m;
    title(ui, d, "All set");
    let note_bottom = note(ui, d, &strings::install_done(m.env.os, &m.name, &m.version));
    widgets::bar(
        ui,
        "bar",
        d.live.then_some("Installation complete"),
        CONTENT_X,
        note_bottom + 18.0,
        CONTENT_W,
        1.0,
        Tone::Ok,
        None,
    );
    let open = d.v.prompt.is_some();
    let mut launch = d.v.launch;
    let row = Rect::new(CONTENT_X, CONTENT_BOTTOM - 32.0, 200.0, 32.0);
    let box_focus = widgets::checkbox(
        ui,
        "launch",
        row,
        &format!("Open {} now", m.name),
        &mut launch,
        d.live && open,
    );
    let (clicked, focused) = super::button_group(
        ui,
        d,
        &[Btn {
            name: "finish",
            label: "Finish",
            kind: ButtonKind::Primary,
            enabled: open,
            danger: false,
        }],
    );
    let finish = |launch| d.choice(ChoiceValue::Finish { launch });
    Out {
        msg: if clicked[0] { finish(launch) } else { None },
        primary: finish(launch),
        focused: focused || box_focus,
        launch: (launch != d.v.launch).then_some(launch),
        ..Out::default()
    }
}

fn failed(ui: &mut Ui<'_>, d: &Draw<'_>) -> Out {
    failed_screen(
        ui,
        d,
        strings::install_failed_title(),
        &strings::install_failed_note(d.m.env.os),
        "Install failed",
        true,
    )
}

/// The failed layout both flows share: the title and a line, the error bar at the fraction
/// reached, a card with the reason, Copy details bottom-left and Close (and, when the flow can
/// retry, Try again) bottom-right.
pub(crate) fn failed_screen(
    ui: &mut Ui<'_>,
    d: &Draw<'_>,
    heading: &str,
    line: &str,
    what: &str,
    retry: bool,
) -> Out {
    let m = d.m;
    let code = d.v.fail_code.unwrap_or(70);
    title(ui, d, heading);
    let note_bottom = note(ui, d, line);
    let bar_y = note_bottom + 16.0;
    widgets::bar(
        ui,
        "bar",
        d.live.then_some(what),
        CONTENT_X,
        bar_y,
        CONTENT_W,
        d.v.bar,
        Tone::Err,
        None,
    );
    let reason = strings::failure_reason(code, &m.name);
    let text_x = CONTENT_X + 14.0 + 16.0 + 10.0;
    let text_w = CONTENT_W - 28.0 - 26.0;
    let style = look::style(12.0, 17.0, 400, white(0.7));
    let th = ui
        .painter()
        .measure(&Spec::plain(&reason, style).wrapped(text_w))
        .1;
    let card = Rect::new(CONTENT_X, bar_y + 22.0, CONTENT_W, 20.0 + th + 2.0);
    {
        let p = ui.painter();
        p.fill(card, 8.0, white(0.05));
        p.ring(card, 8.0, 1.0, look::tint(ERR, 0.35), false);
    }
    widgets::failure_mark(ui, CONTENT_X + 14.0, card.y + 11.0, d.enter_at, d.t, d.tier);
    widgets::wrapped(ui, text_x, card.y + 11.0, text_w, &reason, style);
    if d.live {
        let id = ui.id("reason");
        let mut node = Node::new(id, Role::Alert, &reason, card);
        node.value = Some(Value::Text(reason.clone()));
        ui.node(node);
    }

    let open = d.v.prompt.is_some();
    let copy_w = widgets::button_width(ui, "Copy details", d.mt.btn_pad);
    let copy_rect = Rect::new(CONTENT_X, CONTENT_BOTTOM - 32.0, copy_w, 32.0);
    let copy = widgets::button(
        ui,
        "copy",
        copy_rect,
        "Copy details",
        ButtonKind::Secondary,
        true,
        d.live,
        None,
    );
    if copy.clicked {
        let details = format!(
            "{} {}\n{what}: {} (exit code {code})",
            m.name,
            m.version,
            strings::kind_name(code)
        );
        ui.clipboard_write(details);
    }
    let mut group = vec![Btn {
        name: "close",
        label: "Close",
        kind: if retry {
            ButtonKind::Secondary
        } else {
            ButtonKind::Primary
        },
        enabled: open,
        danger: false,
    }];
    if retry {
        group.push(Btn {
            name: "retry",
            label: "Try again",
            kind: ButtonKind::Primary,
            enabled: open,
            danger: false,
        });
    }
    let (clicked, focused) = super::button_group(ui, d, &group);
    let primary = if retry {
        ChoiceValue::Retry
    } else {
        ChoiceValue::Close
    };
    let mut out = Out {
        focused: focused || copy.focused,
        primary: d.choice(primary),
        ..Out::default()
    };
    if clicked[0] {
        out.msg = d.choice(ChoiceValue::Close);
    } else if retry && clicked[1] {
        out.msg = d.choice(ChoiceValue::Retry);
    }
    out
}
