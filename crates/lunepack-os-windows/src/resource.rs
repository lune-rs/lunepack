//! The process's own resources (M10-D4): [`own_resource`] returns the bytes of an `RT_RCDATA`
//! resource of the running executable's image, read through the loader's resource functions from
//! the mapped image. The image file is never opened from disk, so what is read is what the system
//! loaded when the process started (and, for a Setup an administrator consented to, what the
//! administrator consented to).

/// The bytes of the `RT_RCDATA` resource `id` in this process's own image; `None` when there is no
/// such resource (and always off Windows).
pub fn own_resource(id: u16) -> Option<Vec<u8>> {
    imp::own_resource(id)
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use std::ptr::null;

    use windows_sys::Win32::Foundation::HMODULE;
    use windows_sys::Win32::System::LibraryLoader::{
        FindResourceW, GetModuleHandleW, LoadResource, LockResource, SizeofResource,
    };

    /// `RT_RCDATA` (10) as the integer resource type `MAKEINTRESOURCE(10)`.
    const RT_RCDATA: *const u16 = 10usize as *const u16;

    /// The most bytes of one resource that are returned: far above any anchor, far below memory.
    const MAX_BYTES: u32 = 1024 * 1024;

    /// The bytes of the resource `kind`/`id` in `module`.
    pub(crate) fn resource_in(module: HMODULE, kind: *const u16, id: u16) -> Option<Vec<u8>> {
        // A resource id is passed as a small integer in the pointer (MAKEINTRESOURCE).
        let name = usize::from(id) as *const u16;
        // SAFETY: `module` is a loaded module (the caller's contract); `name` and `kind` are
        // integer resource identifiers, which the call accepts in place of a string pointer.
        let found = unsafe { FindResourceW(module, name, kind) };
        if found.is_null() {
            return None;
        }
        // SAFETY: `found` is the handle `FindResourceW` returned for `module`.
        let size = unsafe { SizeofResource(module, found) };
        if size == 0 || size > MAX_BYTES {
            return None;
        }
        // SAFETY: as above; for a loaded image `LoadResource` returns a handle whose
        // `LockResource` is the address of the resource inside the mapped image.
        let loaded = unsafe { LoadResource(module, found) };
        if loaded.is_null() {
            return None;
        }
        // SAFETY: `loaded` came from `LoadResource` for this module.
        let data = unsafe { LockResource(loaded) };
        if data.is_null() {
            return None;
        }
        // SAFETY: the resource is `size` readable bytes at `data`, inside the module's mapped image
        // (which stays loaded for the process's life, or for the caller's use of `module`); the
        // bytes are copied out before returning.
        Some(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), size as usize) }.to_vec())
    }

    pub(super) fn own_resource(id: u16) -> Option<Vec<u8>> {
        // SAFETY: a null module name asks for the handle of the executable that started the
        // process; no reference count is taken and the image stays mapped for the process's life.
        let module = unsafe { GetModuleHandleW(null()) };
        if module.is_null() {
            return None;
        }
        resource_in(module, RT_RCDATA, id)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows_sys::Win32::Foundation::FreeLibrary;
        use windows_sys::Win32::System::LibraryLoader::{LOAD_LIBRARY_AS_DATAFILE, LoadLibraryExW};
        use windows_sys::Win32::UI::WindowsAndMessaging::RT_VERSION;

        #[test]
        fn this_test_binary_has_no_rcdata_resource() {
            assert_eq!(own_resource(1), None);
            assert_eq!(super::super::own_resource(1), None);
            assert_eq!(own_resource(0xffff), None);
        }

        /// Known answer: `kernel32.dll` carries its version information as `RT_VERSION` 1, whose
        /// first structure's key is the text `VS_VERSION_INFO` in UTF-16. Proves the reader finds
        /// and copies a real resource (the `RT_RCDATA` lookup is the same call with another type).
        #[test]
        fn the_reader_finds_a_real_resource_by_type_and_id() {
            let name: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
            // SAFETY: `name` is NUL-terminated; a data-file load maps the resources without
            // running the library.
            let module = unsafe {
                LoadLibraryExW(
                    name.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_AS_DATAFILE,
                )
            };
            assert!(!module.is_null(), "load kernel32 as a data file");
            let bytes = resource_in(module, RT_VERSION, 1).expect("kernel32 has version info");
            let needle: Vec<u8> = "VS_VERSION_INFO"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            assert!(
                bytes.windows(needle.len()).any(|w| w == needle),
                "the copied bytes hold the version structure"
            );
            // The same module has no RT_RCDATA 1.
            assert_eq!(resource_in(module, RT_RCDATA, 1), None);
            // SAFETY: `module` was returned by `LoadLibraryExW` and is freed once.
            unsafe { FreeLibrary(module) };
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub(super) fn own_resource(_id: u16) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    #[test]
    fn off_windows_there_is_no_resource() {
        assert_eq!(super::own_resource(1), None);
    }
}
