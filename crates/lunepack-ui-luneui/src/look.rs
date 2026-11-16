//! The look of the screens ("B revised"): the sizes, colours and text styles every screen shares.
//! Colours are the approved mock-up's own numbers; LuneUI's theme supplies the button, hover and
//! focus colours.

use lune_ui::color::Rgba;
use lune_ui::text::{Font, Style};
use lune_ui::theme::Theme;

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
/// The opaque window background (Linux, and the software fallback).
pub const BG_OPAQUE: Rgba = [0x18, 0x18, 0x1A, 0xFF];
/// The monogram tile's fill.
pub const TILE: Rgba = [0x2A, 0x2D, 0x31, 0xFF];

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
