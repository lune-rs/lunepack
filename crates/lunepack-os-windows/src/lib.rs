//! Windows install, shortcut, autostart and process-restart adapter.
//!
//! Today it holds the reduce-motion reader (M6-D8): [`prefers_reduced_motion`] reads the OS's
//! client-area animation setting through `SystemParametersInfoW` (user32, no window stack).

/// Whether the user asked for reduced motion: `Some(true)` when the "show animations in Windows"
/// setting is off, `Some(false)` when it is on, `None` when it cannot be read (and always `None`
/// off Windows). `None` means the full motion tier.
pub fn prefers_reduced_motion() -> Option<bool> {
    animations_enabled().map(|on| !on)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn animations_enabled() -> Option<bool> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SPI_GETCLIENTAREAANIMATION, SystemParametersInfoW,
    };
    let mut enabled: i32 = 0;
    // SAFETY: `SPI_GETCLIENTAREAANIMATION` writes one `BOOL` (a 32-bit integer) through the
    // pointer; `enabled` is exactly that, lives for the whole call, and nothing else aliases it.
    // The call has no other pointer arguments (`uiParam` and `fWinIni` are 0).
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_GETCLIENTAREAANIMATION,
            0,
            (&raw mut enabled).cast::<core::ffi::c_void>(),
            0,
        )
    };
    (ok != 0).then_some(enabled != 0)
}

#[cfg(not(windows))]
fn animations_enabled() -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reader_never_panics_and_is_none_off_windows() {
        let value = prefers_reduced_motion();
        if cfg!(not(windows)) {
            assert_eq!(value, None);
        }
    }
}
