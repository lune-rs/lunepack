//! Windows install, shortcut, autostart and process-restart adapter.
//!
//! Today it holds the reduce-motion reader (M6-D8): [`prefers_reduced_motion`] reads the OS's
//! client-area animation setting through `SystemParametersInfoW` (user32, no window stack), and the
//! small Windows helpers of M7: the DLL search hardening ([`harden_dll_search`]) and the shell
//! helpers of [`shell`] (known folders, a message box, the app user model id, the foreground right),
//! and, on Windows only, [`WindowsProcess`] (M7 step 5): the core's `Process` over the Win32 process
//! APIs, and [`WindowsIntegration`] (M7 steps 6 and 7): the core's `OsIntegration` (the launcher
//! stub at the install root, the uninstall entry, the hidden `.lunepack` directory, the Start-menu
//! shortcut with its app user model id, and the file types, URL schemes and autostart the app
//! declares) with [`remove_stub_leftovers`] for the GC; and the launcher stub's two helpers
//! ([`raw_command_line`], [`ignore_console_interrupts`]).
//! [`WinPublisherCheck`] (M9 step 6) is the core's `PublisherCheck` over `WinVerifyTrust`.
//! [`WindowsProtect`] (M10 step 7) is the core's `Protect` over explicit security descriptors, with
//! the descriptor reader, the token queries ([`standing`], [`current_user_sid`]) and the per-machine
//! known folders ([`program_files`], [`common_start_menu_programs`], [`local_app_data`]).
//! The public API is safe and builds on every OS; off Windows the helpers are no-ops or
//! `Unsupported`.

#[cfg(windows)]
mod classes;
mod harden;
#[cfg(windows)]
mod integration;
mod launcher;
#[cfg(windows)]
mod process;
#[cfg(windows)]
mod publisher;
#[cfg(windows)]
mod registry;
#[cfg(any(windows, test))]
mod security;
mod shell;
#[cfg(windows)]
mod shortcut;
#[cfg(windows)]
mod stub_place;
#[cfg(any(windows, test))]
mod trust_status;

pub use harden::harden_dll_search;
#[cfg(windows)]
pub use integration::{MARKER_VALUE, UNINSTALL_KEY, WinScope, WindowsIntegration};
pub use launcher::{ignore_console_interrupts, raw_command_line};
#[cfg(windows)]
pub use process::WindowsProcess;
#[cfg(windows)]
pub use publisher::WinPublisherCheck;
#[cfg(any(windows, test))]
pub use security::{
    ACE_ALLOWED, ACE_ALLOWED_CALLBACK, ACE_DENIED, ACE_DENIED_CALLBACK, Ace, CheckError,
    Descriptor, INHERIT_ONLY_ACE, READ_CLASS, SID_ADMINISTRATORS, SID_ALL_APP_PACKAGES,
    SID_CREATOR_GROUP, SID_CREATOR_OWNER, SID_EVERYONE, SID_SYSTEM, SID_TRUSTED_INSTALLER,
    SID_USERS, judge,
};
#[cfg(windows)]
pub use security::{WindowsProtect, check_dir, current_user_sid, read_descriptor, standing};
pub use shell::{
    MessageKind, allow_set_foreground, common_start_menu_programs, local_app_data, message_box,
    process_aumid, program_files, set_process_aumid, start_menu_programs, user_program_files,
};
#[cfg(windows)]
pub use stub_place::remove_stub_leftovers;

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
