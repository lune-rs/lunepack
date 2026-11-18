//! DLL search hardening (M7-D10): one call, first in every shipped Windows binary's `main`.

/// Limits this process's later `LoadLibrary` calls to `System32` (`SetDefaultDllDirectories` with
/// `LOAD_LIBRARY_SEARCH_SYSTEM32`), so a DLL planted beside the executable (a `Setup.exe` in
/// Downloads) is never picked up. The link-time `DependentLoadFlags` covers only the static
/// imports; this covers every load after it. Call it as the first statement of `main`.
///
/// A failure is ignored: the call exists on every Windows version the project supports, and a
/// process that could not apply it has nothing better to do than go on. No-op off Windows.
pub fn harden_dll_search() {
    imp::harden_dll_search();
}

#[cfg(windows)]
mod imp {
    #[allow(unsafe_code)]
    pub(super) fn harden_dll_search() {
        use windows_sys::Win32::System::LibraryLoader::{
            LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
        };
        // SAFETY: `SetDefaultDllDirectories` takes one flags value and no pointer; every value is
        // either accepted or rejected with a zero return, which is ignored by design.
        let _ = unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) };
    }
}

#[cfg(not(windows))]
mod imp {
    pub(super) fn harden_dll_search() {}
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_does_not_panic_and_can_be_repeated() {
        super::harden_dll_search();
        super::harden_dll_search();
    }
}
