//! A small safe layer over the registry API (advapi32) for the integration: open, create, read
//! and write `REG_SZ` and `REG_DWORD` values, delete a value or a whole key. Paths are relative to
//! a [`Hive`]; nothing here follows a value into the filesystem.

use std::io;
use std::os::windows::ffi::OsStrExt as _;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE, KEY_WRITE, REG_DWORD,
    REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteTreeW,
    RegDeleteValueW, RegOpenKeyExW, RegQueryInfoKeyW, RegQueryValueExW, RegSetValueExW,
};

/// The most bytes of one value that are read; a longer value reads as [`Value::Other`].
const MAX_VALUE_BYTES: u32 = 64 * 1024;

/// A registry root (M10 adds the local machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hive {
    /// `HKEY_CURRENT_USER`.
    CurrentUser,
}

impl Hive {
    fn handle(self) -> HKEY {
        match self {
            Hive::CurrentUser => HKEY_CURRENT_USER,
        }
    }
}

/// A value as read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    /// `REG_SZ`, without its terminating NULs.
    Str(String),
    /// `REG_DWORD`.
    Dword(u32),
    /// Any other type, a string that is not UTF-16, or a value over the read cap.
    Other,
}

/// A NUL-terminated UTF-16 copy of `s`.
fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn check(code: u32) -> io::Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

/// An open key, closed on drop.
#[derive(Debug)]
pub(crate) struct Key(HKEY);

impl Drop for Key {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `self.0` is a key this value opened and owns; it is closed exactly once here.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

impl Key {
    /// Opens `hive\path` for reading, and for writing when `write`; `None` when it does not exist.
    #[allow(unsafe_code)]
    pub(crate) fn open(hive: Hive, path: &str, write: bool) -> io::Result<Option<Key>> {
        let sub = wide(path);
        let access = if write {
            KEY_READ | KEY_WRITE
        } else {
            KEY_READ
        };
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: `sub` is a NUL-terminated buffer that outlives the call; `key` is a valid out
        // pointer that receives a handle this function then owns.
        let code = unsafe { RegOpenKeyExW(hive.handle(), sub.as_ptr(), 0, access, &mut key) };
        match code {
            ERROR_SUCCESS => Ok(Some(Key(key))),
            ERROR_FILE_NOT_FOUND => Ok(None),
            other => Err(io::Error::from_raw_os_error(other as i32)),
        }
    }

    /// Opens `hive\path` for reading and writing, creating it (and missing parents) when absent.
    #[allow(unsafe_code)]
    pub(crate) fn create(hive: Hive, path: &str) -> io::Result<Key> {
        let sub = wide(path);
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: `sub` is NUL-terminated and outlives the call; the class is null, the security
        // attributes are null (the default descriptor), `key` is a valid out pointer and the
        // disposition pointer may be null.
        let code = unsafe {
            RegCreateKeyExW(
                hive.handle(),
                sub.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_READ,
                std::ptr::null(),
                &mut key,
                std::ptr::null_mut(),
            )
        };
        check(code)?;
        Ok(Key(key))
    }

    /// The value `name`, `None` when absent.
    #[allow(unsafe_code)]
    pub(crate) fn get(&self, name: &str) -> io::Result<Option<Value>> {
        let name = wide(name);
        let mut kind: u32 = 0;
        let mut len: u32 = 0;
        // SAFETY: `name` is NUL-terminated and outlives the call; a null data pointer asks only
        // for the type and size, written to the two valid out pointers.
        let code = unsafe {
            RegQueryValueExW(
                self.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                std::ptr::null_mut(),
                &mut len,
            )
        };
        match code {
            ERROR_SUCCESS => {}
            ERROR_FILE_NOT_FOUND => return Ok(None),
            other => return Err(io::Error::from_raw_os_error(other as i32)),
        }
        if len > MAX_VALUE_BYTES || (kind != REG_SZ && kind != REG_DWORD) {
            return Ok(Some(Value::Other));
        }
        // A value can grow between the two calls; one more round, then give up as `Other`.
        for _ in 0..2 {
            let mut buf = vec![0u8; len as usize];
            let mut got = len;
            // SAFETY: `buf` holds `got` writable bytes and outlives the call; the other pointers
            // are as above.
            let code = unsafe {
                RegQueryValueExW(
                    self.0,
                    name.as_ptr(),
                    std::ptr::null(),
                    &mut kind,
                    buf.as_mut_ptr(),
                    &mut got,
                )
            };
            match code {
                ERROR_SUCCESS => {
                    buf.truncate(got as usize);
                    return Ok(Some(decode(kind, &buf)));
                }
                ERROR_MORE_DATA if got <= MAX_VALUE_BYTES => len = got,
                ERROR_MORE_DATA => return Ok(Some(Value::Other)),
                ERROR_FILE_NOT_FOUND => return Ok(None),
                other => return Err(io::Error::from_raw_os_error(other as i32)),
            }
        }
        Ok(Some(Value::Other))
    }

    /// Writes `name` as `REG_SZ` (NUL-terminated).
    #[allow(unsafe_code)]
    pub(crate) fn set_str(&self, name: &str, value: &str) -> io::Result<()> {
        let name = wide(name);
        let data = wide(value);
        let bytes = u32::try_from(data.len() * 2)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "value too long"))?;
        // SAFETY: `name` and `data` are NUL-terminated buffers that outlive the call; `bytes` is
        // exactly the byte length of `data`, terminator included, as `REG_SZ` requires.
        check(unsafe {
            RegSetValueExW(
                self.0,
                name.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr().cast(),
                bytes,
            )
        })
    }

    /// Writes `name` as `REG_DWORD`.
    #[allow(unsafe_code)]
    pub(crate) fn set_dword(&self, name: &str, value: u32) -> io::Result<()> {
        let name = wide(name);
        let data = value.to_le_bytes();
        // SAFETY: `name` is NUL-terminated and outlives the call; `data` is the four bytes of a
        // `REG_DWORD`, read-only for the call.
        check(unsafe { RegSetValueExW(self.0, name.as_ptr(), 0, REG_DWORD, data.as_ptr(), 4) })
    }

    /// Writes `name` as `REG_SZ` unless it already holds exactly `value`; whether it wrote.
    pub(crate) fn ensure_str(&self, name: &str, value: &str) -> io::Result<bool> {
        if self.get(name)? == Some(Value::Str(value.to_owned())) {
            return Ok(false);
        }
        self.set_str(name, value)?;
        Ok(true)
    }

    /// How many subkeys and values the key has.
    #[allow(unsafe_code)]
    pub(crate) fn counts(&self) -> io::Result<(u32, u32)> {
        let mut subkeys: u32 = 0;
        let mut values: u32 = 0;
        // SAFETY: every pointer the call may write through is either null (an output not asked
        // for) or a valid `u32` that outlives the call; the key handle is open.
        check(unsafe {
            RegQueryInfoKeyW(
                self.0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
                &mut subkeys,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut values,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        })?;
        Ok((subkeys, values))
    }

    /// Whether the key has no subkey and no value.
    pub(crate) fn is_empty(&self) -> io::Result<bool> {
        Ok(self.counts()? == (0, 0))
    }

    /// Deletes the value `name`; an absent value is fine.
    #[allow(unsafe_code)]
    pub(crate) fn delete_value(&self, name: &str) -> io::Result<()> {
        let name = wide(name);
        // SAFETY: `name` is NUL-terminated and outlives the call.
        match unsafe { RegDeleteValueW(self.0, name.as_ptr()) } {
            ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
            other => Err(io::Error::from_raw_os_error(other as i32)),
        }
    }
}

fn decode(kind: u32, buf: &[u8]) -> Value {
    if kind == REG_DWORD {
        return match <[u8; 4]>::try_from(buf) {
            Ok(b) => Value::Dword(u32::from_le_bytes(b)),
            Err(_) => Value::Other,
        };
    }
    let (pairs, rest) = buf.as_chunks::<2>();
    if !rest.is_empty() {
        return Value::Other;
    }
    let mut units: Vec<u16> = pairs.iter().map(|&c| u16::from_le_bytes(c)).collect();
    while units.last() == Some(&0) {
        units.pop();
    }
    match String::from_utf16(&units) {
        Ok(s) => Value::Str(s),
        Err(_) => Value::Other,
    }
}

/// Deletes `hive\path` with every subkey and value; an absent key is fine.
#[allow(unsafe_code)]
pub(crate) fn delete_tree(hive: Hive, path: &str) -> io::Result<()> {
    let (parent, leaf) = match path.rsplit_once('\\') {
        Some((parent, leaf)) => (Some(parent), leaf),
        None => (None, path),
    };
    let parent_key = match parent {
        Some(p) => match Key::open(hive, p, true)? {
            Some(k) => Some(k),
            None => return Ok(()),
        },
        None => None,
    };
    let handle = parent_key.as_ref().map_or(hive.handle(), |k| k.0);
    let leaf = wide(leaf);
    // SAFETY: `handle` is the hive or a key opened above with write access that lives until the
    // end of this function; `leaf` is NUL-terminated and outlives the call. `RegDeleteTreeW`
    // with a subkey name deletes that subkey itself as well as its contents.
    match unsafe { RegDeleteTreeW(handle, leaf.as_ptr()) } {
        ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
        other => Err(io::Error::from_raw_os_error(other as i32)),
    }
}

/// Deletes the key `hive\path` only when it has no subkey (`RegDeleteKeyW`); an absent key is
/// fine.
#[allow(unsafe_code)]
pub(crate) fn delete_key(hive: Hive, path: &str) -> io::Result<()> {
    let sub = wide(path);
    // SAFETY: `sub` is NUL-terminated and outlives the call; the hive is a predefined handle.
    match unsafe { RegDeleteKeyW(hive.handle(), sub.as_ptr()) } {
        ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
        other => Err(io::Error::from_raw_os_error(other as i32)),
    }
}

/// Deletes the key `hive\path` when it has neither subkey nor value. For the keys an association
/// made (`.ext\OpenWithProgids`, `.ext`).
pub(crate) fn delete_if_empty(hive: Hive, path: &str) -> io::Result<()> {
    match Key::open(hive, path, false)? {
        Some(key) if key.is_empty()? => {
            drop(key);
            delete_key(hive, path)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_decode_strict() {
        assert_eq!(decode(REG_DWORD, &[1, 0, 0, 0]), Value::Dword(1));
        assert_eq!(decode(REG_DWORD, &[1, 0, 0]), Value::Other);
        assert_eq!(decode(REG_SZ, &[b'a', 0, 0, 0]), Value::Str("a".to_owned()));
        assert_eq!(decode(REG_SZ, &[b'a', 0, b'b']), Value::Other);
        assert_eq!(decode(REG_SZ, &[0x00, 0xd8]), Value::Other);
    }
}
