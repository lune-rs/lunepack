//! The installer and updater screens drawn with LuneUI (M6): the adapter between the core's UI
//! port and the toolkit. It decides nothing; the engine does (D36, D41). The `lunepack-ui`
//! binary owns the event loop, and this crate is the only one that may depend on LuneUI, wgpu, winit
//! and AccessKit (the boundary check).
//!
//! - [`UiModel`] holds what the screens show, built from the engine's messages
//!   ([`UiModel::apply`]) and the user's own answers; it records the instants every animation
//!   runs from.
//! - [`frame`] draws the current screen into a LuneUI frame at frame time `t` and returns the
//!   user's answer. Animation is a pure function of `t`: nothing here reads a clock.
//! - [`render::Renderer`] draws scripted frames headless, for the goldens and the demo.
//!
//! The crate reads no file, network or process: the fonts are embedded and the app icon arrives
//! as PNG bytes in the hello, decoded within caps ([`icon::decode`]).

#![forbid(unsafe_code)]

mod anim;
mod chrome;
mod frame;
pub mod icon;
pub mod look;
mod model;
pub mod render;
pub mod scenario;
mod screens;
mod strings;
mod widgets;

pub use frame::frame;
pub use icon::ICON_IMAGE;
pub use model::{Env, Material, UiModel};
pub use strings::Os;
/// The toolkit, the GPU API and the window library, for the `lunepack-ui` binary: the boundary check
/// lets this crate alone depend on them, so the binary names them through here.
pub use {lune_ui, wgpu, winit};

/// The UI family the fonts register under.
pub const FONT_FAMILY: &str = "RznSans";

/// The embedded fonts (RznSans Regular and Medium), in the order a `TextCache` takes them.
pub fn fonts() -> [&'static [u8]; 2] {
    [
        include_bytes!("../assets/fonts/RznSans-Regular.ttf").as_slice(),
        include_bytes!("../assets/fonts/RznSans-Medium.ttf").as_slice(),
    ]
}
