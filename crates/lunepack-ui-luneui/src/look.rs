//! The look of the screens ("B revised"): the sizes, colours and text styles every screen shares.
//! Colours are the approved mock-up's own numbers; LuneUI's theme supplies the button, hover and
//! focus colours.

use lune_ui::color::Rgba;
use lune_ui::text::{Font, Style};
use lune_ui::theme::Theme;
use lune_ui::{GlassLayer, LuminosityCurve};
use lunepack_core::ui::Flow;

/// The installer window's size in logical pixels.
pub const WINDOW: (f32, f32) = (560.0, 360.0);
/// The side rail's width, its right border included.
pub const RAIL_W: f32 = 184.0;
/// The title strip's height (the caption buttons).
pub const TITLE_H: f32 = 32.0;
/// A caption button's width.
pub const CAPTION_W: f32 = 46.0;
/// The main area's left edge, right edge, first line and bottom edge.
pub const CONTENT_X: f32 = 212.0;
/// The main area's right edge.
pub const CONTENT_R: f32 = 532.0;
/// The first line of the main area.
pub const CONTENT_TOP: f32 = 38.0;
/// The bottom edge of the main area's last row.
pub const CONTENT_BOTTOM: f32 = 340.0;
/// The width of the main area's content.
pub const CONTENT_W: f32 = CONTENT_R - CONTENT_X;

/// Success.
pub const OK: Rgba = [0x73, 0xC9, 0x91, 0xFF];
/// Failure.
pub const ERR: Rgba = [0xE0, 0x6C, 0x75, 0xFF];
/// Warning.
pub const WARN: Rgba = [0xE2, 0xB9, 0x3D, 0xFF];
/// The current step's dot and the spinner's arc.
pub const DOT: Rgba = [0xC9, 0xCD, 0xD2, 0xFF];
/// The label of a destructive confirmation.
pub const DANGER: Rgba = [0xE8, 0x84, 0x8C, 0xFF];
/// The opaque window background (Linux, and the software fallback).
pub const BG_OPAQUE: Rgba = [0x18, 0x18, 0x1A, 0xFF];
/// The monogram tile's fill.
pub const TILE: Rgba = [0x2A, 0x2D, 0x31, 0xFF];

/// The window glass layer's tint opacity at pure black (M6-D15, R3-Q2 "moderately": LuneUI's
/// `near_black` has 0.60). Lower is more see-through; the screens' text keeps its contrast because
/// the glass is still blurred and tinted black.
pub const WINDOW_BLACK_MAX: f64 = 0.45;

/// The side rail's black fill alpha, out of 255, on every material (M6-D15, R3-Q2: 71 before).
/// Opaque windows draw the rail over [`BG_OPAQUE`], so only the glass look is meant to change; the
/// opaque material keeps [`RAIL_FILL_OPAQUE`].
pub const RAIL_FILL_GLASS: u8 = 48;

/// The side rail's black fill alpha on the opaque material (unchanged by M6-D15).
pub const RAIL_FILL_OPAQUE: u8 = 71;

/// The window's glass layer (M6-D15, R3-Q2): LuneUI's `near_black::WINDOW` with a lower
/// `black_max_opacity`. LuneUI's own constants are read, never patched (D39).
pub const WINDOW_GLASS: GlassLayer = GlassLayer {
    curve: LuminosityCurve {
        black_max_opacity: WINDOW_BLACK_MAX,
        ..lune_ui::near_black::WINDOW.curve
    },
    ..lune_ui::near_black::WINDOW
};

/// How far the side rail's content (icon, name, version, steps and their highlight) moves down on
/// macOS, in logical pixels (M6-D14, step 8 batch 4): the OS's window buttons end about 21 px from the
/// top, over the rail; the icon tile then starts at y 38, level with the main area's first line.
pub const MACOS_RAIL_DROP: f32 = 10.0;

/// White at `alpha` (0 to 1).
pub fn white(alpha: f32) -> Rgba {
    [255, 255, 255, (alpha.clamp(0.0, 1.0) * 255.0).round() as u8]
}

/// `c` at `alpha` (0 to 1), keeping its hue.
pub fn tint(c: Rgba, alpha: f32) -> Rgba {
    [
        c[0],
        c[1],
        c[2],
        (alpha.clamp(0.0, 1.0) * 255.0).round() as u8,
    ]
}

/// The theme every screen draws with: LuneUI's near-black one.
pub fn theme() -> Theme {
    lune_ui::near_black::THEME
}

/// A proportional-font style.
pub fn style(size: f32, line: f32, weight: u16, color: Rgba) -> Style {
    Style {
        font: Font::Ui,
        size,
        line,
        weight,
        color,
        italic: false,
    }
}

/// The heading: 18 on 24, Medium, white 90 %.
pub fn h1() -> Style {
    style(18.0, 24.0, 500, white(0.9))
}

/// Body text: 13 on 19, white 70 %.
pub fn body() -> Style {
    style(13.0, 19.0, 400, white(0.7))
}

/// A caption: 11 on 15, white 60 %.
pub fn caption() -> Style {
    style(11.0, 15.0, 400, white(0.6))
}

/// The sizes of one window. The installer and the uninstaller share one; the update window is a
/// small one with a narrow rail that holds the icon only.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Metrics {
    /// Window width.
    pub w: f32,
    /// Window height.
    pub h: f32,
    /// The side rail's width, its right border included.
    pub rail_w: f32,
    /// The main area's left edge.
    pub content_x: f32,
    /// The main area's right edge.
    pub content_r: f32,
    /// The first line of the main area.
    pub content_top: f32,
    /// The bottom edge of the last row of buttons.
    pub content_bottom: f32,
    /// A button's height.
    pub btn_h: f32,
    /// A button's side padding.
    pub btn_pad: f32,
    /// The corner glow's centre (on both axes) and radius.
    pub glow: (f32, f32),
}

/// The window buttons one flow's window offers (M6-D14): install can be minimized or closed, the
/// update window only minimized, the uninstall window only closed. One function of the flow, so
/// the buttons the screens draw (Windows, Linux) and the ones the OS draws (macOS) cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Captions {
    /// A Minimize button.
    pub minimize: bool,
    /// A Close button.
    pub close: bool,
}

impl Captions {
    /// The buttons of the window a flow shows (the installer's until a hello names the flow).
    pub fn of(flow: Option<Flow>) -> Captions {
        match flow {
            Some(Flow::Update) => Captions {
                minimize: true,
                close: false,
            },
            Some(Flow::Uninstall) => Captions {
                minimize: false,
                close: true,
            },
            Some(Flow::Install) | None => Captions {
                minimize: true,
                close: true,
            },
        }
    }

    /// How many buttons.
    pub fn count(self) -> usize {
        usize::from(self.minimize) + usize::from(self.close)
    }
}

impl Metrics {
    /// The installer and uninstaller window.
    pub const FULL: Metrics = Metrics {
        w: 560.0,
        h: 360.0,
        rail_w: RAIL_W,
        content_x: CONTENT_X,
        content_r: CONTENT_R,
        content_top: CONTENT_TOP,
        content_bottom: CONTENT_BOTTOM,
        btn_h: 32.0,
        btn_pad: 16.0,
        glow: (15.0, 97.0),
    };

    /// The update window.
    pub const UPDATE: Metrics = Metrics {
        w: 440.0,
        h: 180.0,
        rail_w: 96.0,
        content_x: 116.0,
        content_r: 420.0,
        content_top: 32.0,
        content_bottom: 164.0,
        btn_h: 28.0,
        btn_pad: 14.0,
        glow: (10.0, 83.0),
    };

    /// The metrics of the window a flow shows (the installer's until a hello names the flow).
    pub fn of(flow: Option<lunepack_core::ui::Flow>) -> Metrics {
        match flow {
            Some(lunepack_core::ui::Flow::Update) => Metrics::UPDATE,
            _ => Metrics::FULL,
        }
    }

    /// The width of the main area's content.
    pub fn content_w(&self) -> f32 {
        self.content_r - self.content_x
    }
}
