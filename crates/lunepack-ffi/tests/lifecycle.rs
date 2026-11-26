//! The C binding's lifecycle functions, called through the rlib as a C app calls them (M14 step 4).
//!
//! A test process has no update configuration above its executable, so every function that finds
//! its installation fails with `update_config` here; the outcomes over an installed tree (events,
//! a rollback's exit, confirmed, scheduled) are proved by the end-to-end rows of steps 6 to 8. What
//! this file holds: the argument checks that fire before discovery, the refusals, and every
//! accessor over a handle built from plain values.

#![allow(unsafe_code)] // every call below passes raw handles and strings, as C does.

use std::ffi::{CStr, CString, c_char};
use std::ptr;

use lunepack::{LifecycleEvent, StartupAction, Version};
use lunepack_ffi::unstable_internals::{live_handles, startup_handle};
use lunepack_ffi::*;

const USAGE: LunepackStatus = 2;
const UPDATE_CONFIG: LunepackStatus = 14;

fn v(text: &str) -> Version {
    Version::parse(text).expect("version")
}

fn text(p: *const c_char) -> Option<String> {
    (!p.is_null()).then(|| {
        // SAFETY: a non-NULL result is a NUL-terminated string the handle keeps alive.
        unsafe { CStr::from_ptr(p) }
            .to_str()
            .expect("UTF-8")
            .to_owned()
    })
}

fn startup(args: *const *const c_char, n: usize) -> (LunepackStatus, *mut LunepackStartup) {
    let mut out = 0x10 as *mut LunepackStartup;
    // SAFETY: `args` is NULL or `n` live strings, `out` is writable.
    let status = unsafe { lunepack_startup(args, n, &mut out) };
    (status, out)
}

fn apply(
    expect: *const c_char,
    flags: u32,
    args: *const *const c_char,
    n: usize,
) -> LunepackStatus {
    // SAFETY: the pointers are NULL or valid for the call.
    unsafe { lunepack_apply_and_restart(expect, flags, args, n) }
}

#[test]
fn startup_without_an_update_config_is_update_config_with_out_null() {
    let (status, out) = startup(ptr::null(), 0);
    assert_eq!(status, UPDATE_CONFIG);
    assert!(out.is_null());
    let a = CString::new("--open").unwrap();
    let argv = [a.as_ptr()];
    let (status, out) = startup(argv.as_ptr(), 1);
    assert_eq!(status, UPDATE_CONFIG);
    assert!(out.is_null());
    assert_eq!(
        text(lunepack_status_name(UPDATE_CONFIG)).as_deref(),
        Some("update_config")
    );
    assert!(lunepack_last_error_reason().is_null());
}

#[test]
fn startup_argument_checks_fire_before_discovery() {
    // (NULL, n > 0) and a NULL or non-UTF-8 entry are `usage`, not `update_config`.
    let (status, out) = startup(ptr::null(), 2);
    assert_eq!((status, out), (USAGE, ptr::null_mut()));
    let a = CString::new("x").unwrap();
    let with_null = [a.as_ptr(), ptr::null()];
    let (status, out) = startup(with_null.as_ptr(), 2);
    assert_eq!((status, out), (USAGE, ptr::null_mut()));
    let bad = CString::new(vec![0xff, 0xfe]).unwrap();
    let with_bad = [bad.as_ptr()];
    let (status, out) = startup(with_bad.as_ptr(), 1);
    assert_eq!((status, out), (USAGE, ptr::null_mut()));
    // NULL out.
    // SAFETY: a NULL out slot is the case under test.
    let status = unsafe { lunepack_startup(ptr::null(), 0, ptr::null_mut()) };
    assert_eq!(status, USAGE);
}

#[test]
fn confirm_without_an_update_config_is_update_config_and_a_null_out_is_usage() {
    let mut outcome = 99u32;
    // SAFETY: `outcome` is writable.
    let status = unsafe { lunepack_confirm_healthy(&mut outcome) };
    assert_eq!(status, UPDATE_CONFIG);
    assert_eq!(outcome, 0, "cleared on failure");
    // SAFETY: a NULL out is the case under test.
    assert_eq!(unsafe { lunepack_confirm_healthy(ptr::null_mut()) }, USAGE);
}

#[test]
fn apply_checks_its_arguments_before_discovery_and_then_needs_an_update_config() {
    // Valid arguments get as far as discovery.
    let a = CString::new("--after-update").unwrap();
    let argv = [a.as_ptr()];
    assert_eq!(apply(ptr::null(), 0, argv.as_ptr(), 1), UPDATE_CONFIG);
    assert_eq!(apply(ptr::null(), 3, ptr::null(), 0), UPDATE_CONFIG);
    let good = CString::new("1.2.3").unwrap();
    assert_eq!(apply(good.as_ptr(), 1, ptr::null(), 0), UPDATE_CONFIG);
    // A non-canonical version is `usage`.
    for bad in ["1.0", "01.0.0", "v1.0.0", "", "1.0.0 "] {
        let text = CString::new(bad).unwrap();
        assert_eq!(apply(text.as_ptr(), 0, ptr::null(), 0), USAGE, "{bad:?}");
    }
    // So are flag bits other than 1 and 2, and a bad argument vector.
    for flags in [4, 8, 7, 0x8000_0000] {
        assert_eq!(apply(ptr::null(), flags, ptr::null(), 0), USAGE, "{flags}");
    }
    assert_eq!(apply(ptr::null(), 0, ptr::null(), 1), USAGE);
    let with_null = [ptr::null()];
    assert_eq!(apply(ptr::null(), 0, with_null.as_ptr(), 1), USAGE);
    // Non-UTF-8 version text.
    let bad = CString::new(vec![0xff]).unwrap();
    assert_eq!(apply(bad.as_ptr(), 0, ptr::null(), 0), USAGE);
}

#[test]
fn the_startup_accessors_over_a_handle_built_from_values() {
    let before = live_handles();
    let events = [
        LifecycleEvent::Installed {
            version: v("1.0.0"),
        },
        LifecycleEvent::Updated {
            from: v("1.0.0"),
            to: v("1.1.0"),
        },
        LifecycleEvent::FirstRun {
            version: v("1.1.0"),
        },
    ];
    let s = startup_handle(&events, StartupAction::Exit, true, &v("1.1.0"));
    assert!(!s.is_null());
    assert_eq!(live_handles(), before + 1);
    // SAFETY: `s` is a live handle until its free at the end.
    unsafe {
        assert!(lunepack_startup_should_exit(s));
        assert!(lunepack_startup_pending(s));
        assert_eq!(
            text(lunepack_startup_tree_version(s)).as_deref(),
            Some("1.1.0")
        );
        assert_eq!(lunepack_startup_event_count(s), 3);
        let first = lunepack_startup_event_version(s, 0);
        assert_eq!(text(first).as_deref(), Some("1.0.0"));
        for (i, kind, version, from) in [
            (0, LUNEPACK_EVENT_INSTALLED, "1.0.0", None),
            (1, LUNEPACK_EVENT_UPDATED, "1.1.0", Some("1.0.0")),
            (2, LUNEPACK_EVENT_FIRST_RUN, "1.1.0", None),
        ] {
            assert_eq!(lunepack_startup_event_kind(s, i), kind, "{i}");
            assert_eq!(
                text(lunepack_startup_event_version(s, i)).as_deref(),
                Some(version)
            );
            assert_eq!(text(lunepack_startup_event_from(s, i)).as_deref(), from);
        }
        assert_eq!(lunepack_startup_event_kind(s, 3), 0);
        assert!(lunepack_startup_event_version(s, 3).is_null());
        assert!(lunepack_startup_event_from(s, 3).is_null());
        // Stable until free.
        assert_eq!(lunepack_startup_event_version(s, 0), first);
        lunepack_startup_free(s);
    }
    assert_eq!(live_handles(), before);

    let s = startup_handle(&[], StartupAction::Continue, false, &v("2.0.0"));
    // SAFETY: as above.
    unsafe {
        assert!(!lunepack_startup_should_exit(s));
        assert!(!lunepack_startup_pending(s));
        assert_eq!(lunepack_startup_event_count(s), 0);
        lunepack_startup_free(s);
    }
    assert_eq!(live_handles(), before);
}

/// The numbers the header promises. A lifecycle call from inside a progress callback is refused
/// with `usage`: `tests/updater.rs` makes those calls from its callback.
#[test]
fn the_constants_the_header_promises() {
    assert_eq!(LUNEPACK_EVENT_INSTALLED, 1);
    assert_eq!(LUNEPACK_EVENT_UPDATED, 2);
    assert_eq!(LUNEPACK_EVENT_FIRST_RUN, 3);
    assert_eq!(LUNEPACK_CONFIRM_CONFIRMED, 1);
    assert_eq!(LUNEPACK_CONFIRM_NOTHING_PENDING, 2);
    assert_eq!(LUNEPACK_APPLY_NO_UI, 1);
    assert_eq!(LUNEPACK_APPLY_BACKGROUND, 2);
}
