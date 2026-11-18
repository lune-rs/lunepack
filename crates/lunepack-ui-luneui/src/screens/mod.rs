//! The screens of the three flows. Each draws the main area (right of the rail) for one screen of
//! a [`View`] and reports what the user did.

pub(crate) mod install;
pub(crate) mod uninstall;
pub(crate) mod update;

use std::time::Duration;

use lune_ui::motion::MotionTier;
use lune_ui::paint::Rect;
use lune_ui::ui::Ui;
use lune_ui::widgets::button::ButtonKind;

use lunepack_core::ui::{ChoiceValue, UiMsg};

use crate::look::{self, Metrics};
use crate::model::{UiModel, View};
use crate::widgets;

/// What one frame of the main area needs.
pub(crate) struct Draw<'a> {
    pub m: &'a UiModel,
    pub v: &'a View,
    pub t: Duration,
    pub tier: MotionTier,
    /// Whether this is the content the user can act on (false while it is leaving).
    pub live: bool,
    /// The window's sizes.
    pub mt: Metrics,
    /// When the content started to arrive, for marks that draw in with it.
    pub enter_at: Duration,
}

/// What the user did in the main area this frame.
#[derive(Debug, Default)]
pub(crate) struct Out {
    /// The answer the user gave.
    pub msg: Option<UiMsg>,
    /// What Enter answers when no button has the focus.
    pub primary: Option<UiMsg>,
    /// Whether a button or the checkbox has the focus.
    pub focused: bool,
    /// The "open now" checkbox changed.
    pub launch: Option<bool>,
}

impl Draw<'_> {
    /// The choice `value` of the open prompt, if one is open.
    pub(crate) fn choice(&self, value: ChoiceValue) -> Option<UiMsg> {
        self.v.prompt.map(|(id, _)| UiMsg::Choice { id, value })
    }
}

/// One button of a group.
pub(crate) struct Btn<'a> {
    pub name: &'a str,
    pub label: &'a str,
    pub kind: ButtonKind,
    pub enabled: bool,
    /// The label is drawn in the error colour (a destructive confirmation).
    pub danger: bool,
}

/// The bottom-right button group: the last button's right edge at the content edge, 8 px apart,
/// 32 high with their bottom at the content's bottom. Returns whether each was clicked, and
/// whether one has the focus.
pub(crate) fn button_group(ui: &mut Ui<'_>, d: &Draw<'_>, group: &[Btn<'_>]) -> (Vec<bool>, bool) {
    let widths: Vec<f32> = group
        .iter()
        .map(|b| widgets::button_width(ui, b.label, d.mt.btn_pad))
        .collect();
    // Positions from the right edge; drawn left to right so the Tab order is the visual one.
    let mut xs = vec![0.0; group.len()];
    let mut x = d.mt.content_r;
    for i in (0..group.len()).rev() {
        x -= widths[i];
        xs[i] = x;
        x -= 8.0;
    }
    let mut clicked = vec![false; group.len()];
    let mut focused = false;
    for (i, b) in group.iter().enumerate() {
        let rect = Rect::new(
            xs[i],
            d.mt.content_bottom - d.mt.btn_h,
            widths[i],
            d.mt.btn_h,
        );
        let color = b.danger.then_some(look::DANGER);
        let out = widgets::button(ui, b.name, rect, b.label, b.kind, b.enabled, d.live, color);
        clicked[i] = out.clicked;
        focused |= out.focused;
    }
    (clicked, focused)
}
