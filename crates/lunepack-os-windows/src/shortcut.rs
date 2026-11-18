//! The Start-menu shortcut (M7-D4, M7-D15): a `.lnk` read and written through the shell's COM
//! objects (`IShellLinkW`, `IPersistFile`, `IPropertyStore`). Each call initialises COM for the
//! calling thread (apartment-threaded) and uninitialises it before it returns; no COM object
//! outlives a call.
//!
//! A write goes to a temporary name beside the shortcut and is renamed over it, so a reader never
//! sees a half-written `.lnk`. The shortcut carries `System.AppUserModel.ID` (M7-D9), which is
//! also how a shortcut is recognised as lunepack's.

use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;

use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows::Win32::Storage::EnhancedStorage::PKEY_AppUserModel_ID;
use windows::Win32::System::Com::StructuredStorage::PROPVARIANT;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoUninitialize, IPersistFile, STGM_READ,
};
use windows::Win32::System::Variant::VT_LPWSTR;
use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
use windows::Win32::UI::Shell::{IShellLinkW, SHStrDupW, ShellLink};
use windows::core::{Interface as _, PCWSTR};

use crate::stub_place;

/// `SLGP_RAWPATH`: the target as stored, with no environment-variable expansion.
const SLGP_RAWPATH: u32 = 4;

/// The longest path read back, in UTF-16 units (the long-path limit).
const MAX_PATH_UNITS: usize = 32_768;

/// What a shortcut is made from.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LinkSpec<'a> {
    /// The program it starts.
    pub target: &'a Path,
    /// Its working directory.
    pub working_dir: &'a Path,
    /// The file the icon comes from (icon index 0).
    pub icon: &'a Path,
    /// `System.AppUserModel.ID`.
    pub aumid: &'a str,
}

/// What a shortcut holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkInfo {
    pub target: String,
    pub working_dir: String,
    pub icon: String,
    pub icon_index: i32,
    /// `None` when the shortcut has no `System.AppUserModel.ID` (or not as a string).
    pub aumid: Option<String>,
}

fn com_error(e: &windows::core::Error) -> io::Error {
    io::Error::from_raw_os_error(e.code().0)
}

/// COM initialised on this thread for as long as the value lives.
struct Com {
    uninit: bool,
}

impl Com {
    #[allow(unsafe_code)]
    fn init() -> io::Result<Com> {
        // SAFETY: the call takes no pointer (a null reserved argument) and a mode constant.
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if hr.is_ok() {
            // S_OK or S_FALSE (already initialised in this mode): both need a matching uninit.
            Ok(Com { uninit: true })
        } else if hr == RPC_E_CHANGED_MODE {
            // The thread is already in another mode; the objects work, and it is not ours to undo.
            Ok(Com { uninit: false })
        } else {
            Err(io::Error::from_raw_os_error(hr.0))
        }
    }
}

impl Drop for Com {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if self.uninit {
            // SAFETY: balances the successful `CoInitializeEx` of `init` on this same thread.
            unsafe { CoUninitialize() };
        }
    }
}

/// A NUL-terminated UTF-16 copy of `path`.
fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn text(units: &[u16]) -> String {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

/// A `VT_LPWSTR` property value holding `value` (the shell stores the app user model id as one).
#[allow(unsafe_code)]
fn lpwstr(value: &str) -> windows::core::Result<PROPVARIANT> {
    let units: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `units` is NUL-terminated and outlives the call. The copy is allocated with the COM
    // allocator, which is what `PropVariantClear` (run when the value drops) frees it with.
    let copy = unsafe { SHStrDupW(PCWSTR(units.as_ptr())) }?;
    let mut value = PROPVARIANT::default();
    // SAFETY: `value` is a freshly zeroed variant that nothing else refers to; writing its type
    // and the string pointer (both plain `Copy` fields of the union) makes a valid `VT_LPWSTR`.
    unsafe {
        let inner = &mut *value.Anonymous.Anonymous;
        inner.vt = VT_LPWSTR;
        inner.Anonymous.pwszVal = copy;
    }
    Ok(value)
}

/// Reads the shortcut at `path`: `None` when the file is not a shell link (the shell refuses to
/// load it), an error when COM or a property cannot be used.
#[allow(unsafe_code)]
pub(crate) fn read(path: &Path) -> io::Result<Option<LinkInfo>> {
    let _com = Com::init()?;
    // SAFETY: the class id is a valid constant and no outer object is given.
    let link: IShellLinkW = unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| com_error(&e))?;
    let file: IPersistFile = link.cast().map_err(|e| com_error(&e))?;
    let file_name = wide(path);
    // SAFETY: `file_name` is NUL-terminated and outlives the call.
    if unsafe { file.Load(PCWSTR(file_name.as_ptr()), STGM_READ) }.is_err() {
        return Ok(None);
    }

    let mut target = vec![0u16; MAX_PATH_UNITS];
    // SAFETY: the buffer is writable for its whole length; a null find-data pointer is allowed.
    unsafe { link.GetPath(&mut target, std::ptr::null_mut(), SLGP_RAWPATH) }
        .map_err(|e| com_error(&e))?;
    let mut dir = vec![0u16; MAX_PATH_UNITS];
    // SAFETY: as above.
    unsafe { link.GetWorkingDirectory(&mut dir) }.map_err(|e| com_error(&e))?;
    let mut icon = vec![0u16; MAX_PATH_UNITS];
    let mut icon_index = 0i32;
    // SAFETY: the buffer is writable for its whole length; `icon_index` is a valid out pointer.
    unsafe { link.GetIconLocation(&mut icon, &mut icon_index) }.map_err(|e| com_error(&e))?;

    let store: IPropertyStore = link.cast().map_err(|e| com_error(&e))?;
    // SAFETY: the key is a valid constant.
    let value = unsafe { store.GetValue(&PKEY_AppUserModel_ID) }.map_err(|e| com_error(&e))?;
    let aumid = (value.vt() == VT_LPWSTR)
        .then(|| value.to_string())
        .filter(|s| !s.is_empty());

    Ok(Some(LinkInfo {
        target: text(&target),
        working_dir: text(&dir),
        icon: text(&icon),
        icon_index,
        aumid,
    }))
}

/// Writes the shortcut at `path` (replacing a file there) from `spec`.
#[allow(unsafe_code)]
pub(crate) fn write(path: &Path, spec: &LinkSpec<'_>) -> io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let mut temp_name = name.to_os_string();
    temp_name.push(format!(".new-{}", stub_place::temp_hex()));
    let temp = path.with_file_name(temp_name);

    let result = save(&temp, spec).and_then(|()| stub_place::replace_file(&temp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[allow(unsafe_code)]
fn save(to: &Path, spec: &LinkSpec<'_>) -> io::Result<()> {
    let _com = Com::init()?;
    // SAFETY: the class id is a valid constant and no outer object is given.
    let link: IShellLinkW = unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| com_error(&e))?;
    let target = wide(spec.target);
    let dir = wide(spec.working_dir);
    let icon = wide(spec.icon);
    // SAFETY: each string is NUL-terminated and outlives its call.
    unsafe {
        link.SetPath(PCWSTR(target.as_ptr()))
            .map_err(|e| com_error(&e))?;
        link.SetWorkingDirectory(PCWSTR(dir.as_ptr()))
            .map_err(|e| com_error(&e))?;
        link.SetIconLocation(PCWSTR(icon.as_ptr()), 0)
            .map_err(|e| com_error(&e))?;
    }
    let store: IPropertyStore = link.cast().map_err(|e| com_error(&e))?;
    let aumid = lpwstr(spec.aumid).map_err(|e| com_error(&e))?;
    // SAFETY: the key and the value are valid for the calls.
    unsafe {
        store
            .SetValue(&PKEY_AppUserModel_ID, &aumid)
            .map_err(|e| com_error(&e))?;
        store.Commit().map_err(|e| com_error(&e))?;
    }
    let file: IPersistFile = link.cast().map_err(|e| com_error(&e))?;
    let file_name = wide(to);
    // SAFETY: `file_name` is NUL-terminated and outlives the call.
    unsafe { file.Save(PCWSTR(file_name.as_ptr()), true) }.map_err(|e| com_error(&e))
}
