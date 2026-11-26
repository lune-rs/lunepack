//! The one place that holds the rules every entry point follows (M14-D3, D5, D6):
//!
//! - a panic never crosses the boundary: it becomes `internal`, or the documented neutral value
//!   of an accessor, and its payload is dropped, never printed or kept;
//! - the thread's last reason is cleared on entry to every status-returning function;
//! - a call from inside a progress callback is refused with `usage`;
//! - a non-NULL `out` slot is set to NULL before anything else, so an error leaves NULL and the
//!   caller never frees a stale pointer;
//! - input strings are checked UTF-8, and typed values (channel, version, flags, arguments) are
//!   checked here once, not per function.

#![allow(unsafe_code)]
// raw pointers from C: every unsafe block says what the caller promised.
// Called from the entry points of the next steps; until they land only the tests call them.
#![allow(dead_code)]

use std::cell::Cell;
use std::ffi::{CStr, OsString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use lunepack::{Channel, Version};

use crate::status::{
    Fail, LUNEPACK_STATUS_INTERNAL, LUNEPACK_STATUS_OK, LUNEPACK_STATUS_USAGE, LunepackStatus,
};

thread_local! {
    /// The reason name of this thread's last failed call.
    static REASON: Cell<Option<&'static CStr>> = const { Cell::new(None) };
    /// Whether this thread is inside a progress callback.
    static IN_CALLBACK: Cell<bool> = const { Cell::new(false) };
}

/// The reason name of this thread's last failed call.
pub(crate) fn last_reason() -> Option<&'static CStr> {
    REASON.get()
}

/// Whether this thread is inside a progress callback.
pub(crate) fn in_callback() -> bool {
    IN_CALLBACK.get()
}

/// Marks the calling thread as inside a progress callback until dropped, so a panic in the
/// callback path cannot leave the mark set. The progress bridge holds one around each callback.
pub(crate) struct CallbackScope {
    before: bool,
}

impl CallbackScope {
    pub(crate) fn enter() -> CallbackScope {
        CallbackScope {
            before: IN_CALLBACK.replace(true),
        }
    }
}

impl Drop for CallbackScope {
    fn drop(&mut self) {
        IN_CALLBACK.set(self.before);
    }
}

fn run(f: impl FnOnce() -> Result<(), Fail>) -> LunepackStatus {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => LUNEPACK_STATUS_OK,
        Ok(Err(fail)) => {
            REASON.set(fail.reason());
            fail.status()
        }
        // The payload is dropped here: it may hold text from a facade `expect`.
        Err(_) => LUNEPACK_STATUS_INTERNAL,
    }
}

/// The guard of a status-returning function with no output handle.
pub(crate) fn call(f: impl FnOnce() -> Result<(), Fail>) -> LunepackStatus {
    REASON.set(None);
    if in_callback() {
        return LUNEPACK_STATUS_USAGE;
    }
    run(f)
}

/// The guard of a status-returning function with one output handle: `out` is cleared first (when
/// it is not NULL), a NULL `out` is `usage`, and `f` gets the slot to fill on success.
pub(crate) fn call_out<T>(
    out: *mut *mut T,
    f: impl FnOnce(OutSlot<T>) -> Result<(), Fail>,
) -> LunepackStatus {
    REASON.set(None);
    let slot = OutSlot::clear(out);
    if in_callback() {
        return LUNEPACK_STATUS_USAGE;
    }
    match slot {
        Some(slot) => run(|| f(slot)),
        None => LUNEPACK_STATUS_USAGE,
    }
}

/// The guard of an accessor or a `_free`: no status and no change to the reason; a panic gives
/// `fallback`. Allowed inside a progress callback.
pub(crate) fn quiet<R>(fallback: R, f: impl FnOnce() -> R) -> R {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(fallback)
}

/// A caller's `T**` output slot, already set to NULL.
pub(crate) struct OutSlot<T>(*mut *mut T);

impl<T> OutSlot<T> {
    /// Sets a non-NULL `out` to NULL and returns the slot; NULL gives `None`.
    pub(crate) fn clear(out: *mut *mut T) -> Option<OutSlot<T>> {
        if out.is_null() {
            return None;
        }
        // SAFETY: `out` is non-NULL and the caller promises a writable `T*` slot for the call.
        unsafe { out.write(ptr::null_mut()) };
        Some(OutSlot(out))
    }

    /// Hands `value` to the caller as a heap handle, which its `_free` releases.
    pub(crate) fn set(self, value: T) {
        // SAFETY: `clear` checked the slot is non-NULL and writable, and nothing has used it since.
        unsafe { self.0.write(Box::into_raw(Box::new(value))) };
    }
}

/// An input string: NULL is `None`; text that is not UTF-8 is `usage`. The string is read only
/// during the call; the lifetime is the caller's promise, not a borrow of anything of ours.
pub(crate) fn utf8<'a>(p: *const c_char) -> Result<Option<&'a str>, Fail> {
    if p.is_null() {
        return Ok(None);
    }
    // SAFETY: non-NULL, and the caller promises a NUL-terminated string valid for the call.
    let s = unsafe { CStr::from_ptr(p) };
    s.to_str().map(Some).map_err(|_| Fail::usage())
}

/// An input string that must be given: NULL is `usage`.
pub(crate) fn required_utf8<'a>(p: *const c_char) -> Result<&'a str, Fail> {
    utf8(p)?.ok_or_else(Fail::usage)
}

/// An optional channel id: NULL is `None`; a text `Channel::parse` refuses is `usage`.
pub(crate) fn channel(p: *const c_char) -> Result<Option<Channel>, Fail> {
    utf8(p)?
        .map(|s| Channel::parse(s).map_err(|_| Fail::usage()))
        .transpose()
}

/// A version that must be given and canonical: strict SemVer whose text is exactly its own
/// rendering (`1.0`, `01.0.0` and the like are `usage`).
pub(crate) fn version(p: *const c_char) -> Result<Version, Fail> {
    let text = required_utf8(p)?;
    let version = Version::parse(text).map_err(|_| Fail::usage())?;
    if version.to_string() == text {
        Ok(version)
    } else {
        Err(Fail::usage())
    }
}

/// Flag bits: any bit outside `known` is `usage`.
pub(crate) fn flags(bits: u32, known: u32) -> Result<u32, Fail> {
    if bits & !known == 0 {
        Ok(bits)
    } else {
        Err(Fail::usage())
    }
}

/// An argument vector: `(NULL, 0)` is `None` (the process's own arguments); `(NULL, n > 0)` and a
/// NULL or non-UTF-8 entry are `usage`.
pub(crate) fn args(argv: *const *const c_char, n: usize) -> Result<Option<Vec<OsString>>, Fail> {
    if argv.is_null() {
        return if n == 0 { Ok(None) } else { Err(Fail::usage()) };
    }
    // SAFETY: non-NULL, and the caller promises `n` readable `char*` entries for the call.
    let entries = unsafe { std::slice::from_raw_parts(argv, n) };
    entries
        .iter()
        .map(|p| required_utf8(*p).map(OsString::from))
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn a_panic_becomes_internal_and_the_next_call_works() {
        assert_eq!(call(|| panic!("boom")), LUNEPACK_STATUS_INTERNAL);
        assert_eq!(call(|| Ok(())), LUNEPACK_STATUS_OK);
        assert_eq!(quiet(7, || -> i32 { panic!("boom") }), 7);
        // A panic inside an argument check is contained too: it is inside the guard.
        assert_eq!(
            call(|| {
                let _: &str = utf8(ptr::null())?.expect("a panic, not a status");
                Ok(())
            }),
            LUNEPACK_STATUS_INTERNAL
        );
    }

    #[test]
    fn a_failure_sets_the_reason_and_the_next_call_clears_it() {
        let fail = Fail::of(&lunepack::Error::PublisherMismatch {
            reason: lunepack::PublisherOutcome::Os,
        });
        assert_eq!(call(|| Err(fail)), fail.status());
        assert_eq!(last_reason(), Some(c"os"));
        assert_eq!(call(|| Ok(())), LUNEPACK_STATUS_OK);
        assert_eq!(last_reason(), None);
        // Cleared on entry even when the call is refused.
        assert_eq!(call(|| Err(fail)), fail.status());
        let scope = CallbackScope::enter();
        assert_eq!(call(|| Ok(())), LUNEPACK_STATUS_USAGE);
        assert_eq!(last_reason(), None);
        drop(scope);
    }

    #[test]
    fn a_call_from_inside_a_callback_is_refused_and_the_scope_ends_with_its_drop() {
        assert!(!in_callback());
        let scope = CallbackScope::enter();
        assert!(in_callback());
        let mut ran = false;
        assert_eq!(
            call(|| {
                ran = true;
                Ok(())
            }),
            LUNEPACK_STATUS_USAGE
        );
        assert!(!ran, "a refused call runs nothing");
        // An accessor is allowed inside a callback.
        assert_eq!(quiet(0, || 5), 5);
        drop(scope);
        assert!(!in_callback());
        assert_eq!(call(|| Ok(())), LUNEPACK_STATUS_OK);
    }

    #[test]
    fn a_panic_inside_a_callback_scope_does_not_leave_it_set() {
        let result = catch_unwind(|| {
            let _scope = CallbackScope::enter();
            panic!("callback path");
        });
        assert!(result.is_err());
        assert!(!in_callback());
    }

    #[test]
    fn out_is_cleared_first_and_a_null_out_is_usage() {
        let mut slot: *mut u32 = 0x10 as *mut u32;
        // An error leaves NULL, not the caller's old pointer.
        assert_eq!(
            call_out(&mut slot, |_| Err::<(), _>(Fail::usage())),
            LUNEPACK_STATUS_USAGE
        );
        assert!(slot.is_null());
        slot = 0x10 as *mut u32;
        // A reentrant refusal clears it too.
        let scope = CallbackScope::enter();
        assert_eq!(call_out(&mut slot, |_| Ok(())), LUNEPACK_STATUS_USAGE);
        assert!(slot.is_null());
        drop(scope);
        // A panic leaves it NULL and gives internal.
        slot = 0x10 as *mut u32;
        assert_eq!(
            call_out(&mut slot, |_| -> Result<(), Fail> { panic!("boom") }),
            LUNEPACK_STATUS_INTERNAL
        );
        assert!(slot.is_null());
        // Success hands over a heap value the caller frees.
        assert_eq!(
            call_out(&mut slot, |out| {
                out.set(41);
                Ok(())
            }),
            LUNEPACK_STATUS_OK
        );
        assert!(!slot.is_null());
        // SAFETY: `set` made it with `Box::into_raw(Box::new(41u32))`.
        assert_eq!(*unsafe { Box::from_raw(slot) }, 41);
        // NULL out.
        assert_eq!(
            call_out::<u32>(ptr::null_mut(), |_| Ok(())),
            LUNEPACK_STATUS_USAGE
        );
    }

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn strings_must_be_utf8() {
        assert_eq!(utf8(ptr::null()), Ok(None));
        assert_eq!(utf8(c"abc".as_ptr()), Ok(Some("abc")));
        let bad = CString::new(vec![0xff, 0xfe, b'x']).unwrap();
        assert_eq!(utf8(bad.as_ptr()), Err(Fail::usage()));
        assert_eq!(required_utf8(ptr::null()), Err(Fail::usage()));
    }

    #[test]
    fn versions_must_be_canonical_semver() {
        for ok in ["1.0.0", "0.1.0-rc.1", "2.3.4+build.5", "10.20.30"] {
            let text = c(ok);
            assert_eq!(version(text.as_ptr()).unwrap().to_string(), ok, "{ok}");
        }
        for bad in ["1.0", "01.0.0", "v1.0.0", " 1.0.0", "1.0.0 ", "", "1.0.0.0"] {
            let text = c(bad);
            assert_eq!(version(text.as_ptr()), Err(Fail::usage()), "{bad:?}");
        }
        assert_eq!(version(ptr::null()), Err(Fail::usage()));
    }

    #[test]
    fn channels_follow_channel_parse() {
        assert_eq!(channel(ptr::null()), Ok(None));
        assert_eq!(
            channel(c"stable".as_ptr()).unwrap().unwrap().as_str(),
            "stable"
        );
        for bad in ["", "Stable", "-x", "a b", &"a".repeat(33)] {
            let text = c(bad);
            assert_eq!(channel(text.as_ptr()), Err(Fail::usage()), "{bad:?}");
        }
    }

    #[test]
    fn unknown_flag_bits_are_usage() {
        assert_eq!(flags(0, 0b11), Ok(0));
        assert_eq!(flags(0b11, 0b11), Ok(0b11));
        assert_eq!(flags(0b100, 0b11), Err(Fail::usage()));
        assert_eq!(flags(0b101, 0b11), Err(Fail::usage()));
        assert_eq!(flags(1 << 31, 0xff), Err(Fail::usage()));
    }

    #[test]
    fn argument_vectors() {
        assert_eq!(args(ptr::null(), 0), Ok(None));
        assert_eq!(args(ptr::null(), 2), Err(Fail::usage()));
        let a = c("--one");
        let b = c("two");
        let argv = [a.as_ptr(), b.as_ptr()];
        assert_eq!(
            args(argv.as_ptr(), 2),
            Ok(Some(vec![OsString::from("--one"), OsString::from("two")]))
        );
        // A present vector of length 0 is an empty argument list, not "the process's own".
        assert_eq!(args(argv.as_ptr(), 0), Ok(Some(Vec::new())));
        let with_null = [a.as_ptr(), ptr::null()];
        assert_eq!(args(with_null.as_ptr(), 2), Err(Fail::usage()));
        let bad = CString::new(vec![0xff]).unwrap();
        let with_bad = [bad.as_ptr()];
        assert_eq!(args(with_bad.as_ptr(), 1), Err(Fail::usage()));
    }
}
