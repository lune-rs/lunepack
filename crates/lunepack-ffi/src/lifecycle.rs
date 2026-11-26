//! The lifecycle calls of the running app (M14-D2): `startup` at every start, `confirm_healthy`
//! once it works, `apply_and_restart` to restart into a staged version.
//!
//! The binding calls the facade's free functions `startup`, `startup_with_args`,
//! `confirm_healthy` and `apply_and_restart` only, never their `_for` forms: the free functions
//! keep the health token a per-machine install issues to the process (the `export_kept` and
//! `import_kept` hand-off), which the `_for` forms skip.

#![allow(unsafe_code)] // raw handles and strings from C: every unsafe block says what the caller promised.

use std::ffi::{CString, c_char};
use std::ptr;

use lunepack::{
    ApplyOptions, ConfirmOutcome, Installation, LifecycleEvent, StartupAction, UiChoice, Version,
};

use crate::guard;
use crate::status::{Fail, LunepackStatus};
use crate::updater::Live;

/// The app was installed at this version (`lunepack_startup_event_kind`).
pub const LUNEPACK_EVENT_INSTALLED: u32 = 1;
/// The app was updated; `event_version` is the new version and `event_from` the old one.
pub const LUNEPACK_EVENT_UPDATED: u32 = 2;
/// This version runs for the first time.
pub const LUNEPACK_EVENT_FIRST_RUN: u32 = 3;

/// The version was confirmed healthy (`lunepack_confirm_healthy`).
pub const LUNEPACK_CONFIRM_CONFIRMED: u32 = 1;
/// Nothing to confirm: nothing is pending, or another version is, or the tree is not installed.
pub const LUNEPACK_CONFIRM_NOTHING_PENDING: u32 = 2;

/// `lunepack_apply_and_restart` flag: the applier shows no update window.
pub const LUNEPACK_APPLY_NO_UI: u32 = 1;
/// `lunepack_apply_and_restart` flag: start the new version without bringing it to the front
/// (macOS; elsewhere it changes nothing).
pub const LUNEPACK_APPLY_BACKGROUND: u32 = 2;

/// Every apply flag this version knows; any other bit is `usage`.
const APPLY_FLAGS: u32 = LUNEPACK_APPLY_NO_UI | LUNEPACK_APPLY_BACKGROUND;

/// One lifecycle event, as converted data.
struct Event {
    kind: u32,
    version: CString,
    from: Option<CString>,
}

/// What `lunepack_startup` found and did: plain data, immutable until `lunepack_startup_free`.
/// Safe to read from several threads at once.
pub struct LunepackStartup {
    should_exit: bool,
    pending: bool,
    tree_version: CString,
    events: Vec<Event>,
    _live: Live,
}

// The accessors are read-only data: `Send + Sync` as a compile-time fact (D5).
const _: () = {
    const fn send_sync<T: Send + Sync>() {}
    send_sync::<LunepackStartup>();
};

fn cstring(version: &Version) -> Result<CString, Fail> {
    CString::new(version.to_string()).map_err(|_| Fail::internal())
}

/// The handle's data from what the facade's `Startup` holds and the tree's own version.
fn convert(
    events: &[LifecycleEvent],
    action: StartupAction,
    pending: bool,
    tree: &Version,
) -> Result<LunepackStartup, Fail> {
    let events = events
        .iter()
        .map(|event| {
            Ok(match event {
                LifecycleEvent::Installed { version } => Event {
                    kind: LUNEPACK_EVENT_INSTALLED,
                    version: cstring(version)?,
                    from: None,
                },
                LifecycleEvent::Updated { from, to } => Event {
                    kind: LUNEPACK_EVENT_UPDATED,
                    version: cstring(to)?,
                    from: Some(cstring(from)?),
                },
                LifecycleEvent::FirstRun { version } => Event {
                    kind: LUNEPACK_EVENT_FIRST_RUN,
                    version: cstring(version)?,
                    from: None,
                },
            })
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    Ok(LunepackStartup {
        should_exit: action == StartupAction::Exit,
        pending,
        tree_version: cstring(tree)?,
        events,
        _live: Live::new(),
    })
}

/// A startup handle over the given values, for the Rust tests (the facade's `Startup` cannot be
/// built outside it, and a test process has no installed tree). Release it with
/// `lunepack_startup_free`. Not part of the C ABI.
pub fn startup_handle(
    events: &[LifecycleEvent],
    action: StartupAction,
    pending: bool,
    tree: &Version,
) -> *mut LunepackStartup {
    convert(events, action, pending, tree).map_or(ptr::null_mut(), |s| Box::into_raw(Box::new(s)))
}

/// The start of the running app: call it at every start, before anything else. It reconciles the
/// install, counts this start when this version is pending its health check (the fourth
/// unconfirmed start rolls back, starts the previous version and sets `should_exit`), and
/// delivers the lifecycle events queued for this version, each once.
///
/// `args` and `nargs` are the process's own arguments after the program name, for the relaunch of
/// a rollback: `(NULL, 0)` takes them from the process; otherwise `nargs` UTF-8 strings. `out`
/// receives the handle (NULL on failure). A process with no update configuration above its
/// executable (a development run) gets `update_config`. Release the handle with
/// `lunepack_startup_free`.
///
/// # Safety
/// `args` is NULL or points to `nargs` NUL-terminated strings valid for the call; `out` is a
/// writable slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_startup(
    args: *const *const c_char,
    nargs: usize,
    out: *mut *mut LunepackStartup,
) -> LunepackStatus {
    guard::call_out(out, |slot| {
        let args = guard::args(args, nargs)?;
        // The tree's own version for the handle; `startup` finds the same installation again from
        // the same executable path.
        let tree = Installation::from_current_exe()
            .map_err(|e| Fail::of(&e))?
            .tree_version()
            .clone();
        let started = match args {
            None => lunepack::startup(),
            Some(args) => lunepack::startup_with_args(args),
        }
        .map_err(|e| Fail::of(&e))?;
        slot.set(convert(
            &started.events,
            started.action,
            started.pending,
            &tree,
        )?);
        Ok(())
    })
}

/// Whether the app must exit now: this version was rolled back and the previous one has been
/// started in its place. false for NULL.
///
/// # Safety
/// `startup` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_startup_should_exit(startup: *const LunepackStartup) -> bool {
    guard::quiet(false, || {
        // SAFETY: NULL is checked by `as_ref`; otherwise the caller promises a live handle.
        unsafe { startup.as_ref() }.is_some_and(|s| s.should_exit)
    })
}

/// Whether this version still waits for `lunepack_confirm_healthy`. false for NULL.
///
/// # Safety
/// `startup` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_startup_pending(startup: *const LunepackStartup) -> bool {
    guard::quiet(false, || {
        // SAFETY: NULL is checked by `as_ref`; otherwise the caller promises a live handle.
        unsafe { startup.as_ref() }.is_some_and(|s| s.pending)
    })
}

/// The running tree's own version, as canonical SemVer text. Valid, unchanged, until the handle
/// is freed. NULL for NULL.
///
/// # Safety
/// `startup` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_startup_tree_version(
    startup: *const LunepackStartup,
) -> *const c_char {
    guard::quiet(ptr::null(), || {
        // SAFETY: NULL is checked by `as_ref`; otherwise the caller promises a live handle.
        unsafe { startup.as_ref() }.map_or(ptr::null(), |s| s.tree_version.as_ptr())
    })
}

/// How many lifecycle events were delivered, oldest first. 0 for NULL.
///
/// # Safety
/// `startup` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_startup_event_count(startup: *const LunepackStartup) -> usize {
    guard::quiet(0, || {
        // SAFETY: NULL is checked by `as_ref`; otherwise the caller promises a live handle.
        unsafe { startup.as_ref() }.map_or(0, |s| s.events.len())
    })
}

fn event<'a>(startup: *const LunepackStartup, i: usize) -> Option<&'a Event> {
    // SAFETY: NULL is checked by `as_ref`; otherwise the caller promises a live handle.
    unsafe { startup.as_ref() }.and_then(|s| s.events.get(i))
}

/// The kind of event `i`: `LUNEPACK_EVENT_INSTALLED`, `_UPDATED` or `_FIRST_RUN`; a kind a later
/// version adds is a new number. 0 for an index out of range or NULL.
///
/// # Safety
/// `startup` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_startup_event_kind(
    startup: *const LunepackStartup,
    i: usize,
) -> u32 {
    guard::quiet(0, || event(startup, i).map_or(0, |e| e.kind))
}

/// The version event `i` is for: the installed or first-run version, or the new version of an
/// update. Valid, unchanged, until the handle is freed. NULL for an index out of range or NULL.
///
/// # Safety
/// `startup` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_startup_event_version(
    startup: *const LunepackStartup,
    i: usize,
) -> *const c_char {
    guard::quiet(ptr::null(), || {
        event(startup, i).map_or(ptr::null(), |e| e.version.as_ptr())
    })
}

/// The version an update came from, for an `LUNEPACK_EVENT_UPDATED` event; NULL for any other
/// event, an index out of range or NULL. Valid until the handle is freed.
///
/// # Safety
/// `startup` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_startup_event_from(
    startup: *const LunepackStartup,
    i: usize,
) -> *const c_char {
    guard::quiet(ptr::null(), || {
        event(startup, i)
            .and_then(|e| e.from.as_ref())
            .map_or(ptr::null(), |from| from.as_ptr())
    })
}

/// Releases a startup handle. NULL does nothing.
///
/// # Safety
/// `startup` is NULL or a handle not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_startup_free(startup: *mut LunepackStartup) {
    guard::quiet((), || {
        if !startup.is_null() {
            // SAFETY: made by `Box::into_raw` in `lunepack_startup`; freed once.
            drop(unsafe { Box::from_raw(startup) });
        }
    });
}

/// The running version confirms its health, once it works. `out_outcome` receives
/// `LUNEPACK_CONFIRM_CONFIRMED` or `LUNEPACK_CONFIRM_NOTHING_PENDING` (0 on failure); a NULL
/// `out_outcome` is `usage`. A health token the process holds that is malformed or does not
/// match is `token_mismatch`; a process with no update configuration gets `update_config`.
///
/// # Safety
/// `out_outcome` is a writable `uint32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_confirm_healthy(out_outcome: *mut u32) -> LunepackStatus {
    if !out_outcome.is_null() {
        // SAFETY: non-NULL, and the caller promises a writable `uint32_t`.
        unsafe { out_outcome.write(0) };
    }
    guard::call(|| {
        if out_outcome.is_null() {
            return Err(Fail::usage());
        }
        let outcome = match lunepack::confirm_healthy().map_err(|e| Fail::of(&e))? {
            ConfirmOutcome::Confirmed => LUNEPACK_CONFIRM_CONFIRMED,
            ConfirmOutcome::NothingPending => LUNEPACK_CONFIRM_NOTHING_PENDING,
        };
        // SAFETY: checked non-NULL above; the caller promises a writable `uint32_t`.
        unsafe { out_outcome.write(outcome) };
        Ok(())
    })
}

/// The options of `lunepack_apply_and_restart`, every argument checked.
fn apply_options(
    expect_version: *const c_char,
    flags: u32,
    args: *const *const c_char,
    nargs: usize,
) -> Result<ApplyOptions, Fail> {
    let expect_version = match guard::utf8(expect_version)? {
        None => None,
        Some(_) => Some(guard::version(expect_version)?),
    };
    let flags = guard::flags(flags, APPLY_FLAGS)?;
    let restart_args = guard::args(args, nargs)?.unwrap_or_default();
    Ok(ApplyOptions {
        expect_version,
        wait_for: None,
        restart_args,
        ui: if flags & LUNEPACK_APPLY_NO_UI != 0 {
            UiChoice::Never
        } else {
            UiChoice::Auto
        },
        background: flags & LUNEPACK_APPLY_BACKGROUND != 0,
    })
}

/// Hands the staged version to the runtime: it starts the runtime detached to wait for this
/// process, apply the staged version and start it with `args`. The call returns; THE APP MUST EXIT
/// NEXT (the library never exits the process). Nothing is started when nothing usable is staged
/// (`nothing_staged`) or the staged version is not `expect_version` (`unexpected_version`).
///
/// `expect_version` is NULL or the canonical version the app expects to be staged (`1.0`, `v1.0.0`
/// and other non-canonical text is `usage`). `flags` is `LUNEPACK_APPLY_NO_UI` and
/// `LUNEPACK_APPLY_BACKGROUND` or'd (any other bit is `usage`). `args`, `nargs`: the arguments the
/// new version is started with, `nargs` UTF-8 strings; `(NULL, 0)` is none.
///
/// # Safety
/// `expect_version` is NULL or a NUL-terminated string valid for the call; `args` is NULL or
/// points to `nargs` such strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_apply_and_restart(
    expect_version: *const c_char,
    flags: u32,
    args: *const *const c_char,
    nargs: usize,
) -> LunepackStatus {
    guard::call(|| {
        let options = apply_options(expect_version, flags, args, nargs)?;
        lunepack::apply_and_restart(options)
            .map(drop)
            .map_err(|e| Fail::of(&e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, OsString};

    fn v(text: &str) -> Version {
        Version::parse(text).expect("version")
    }

    #[test]
    fn apply_options_carry_the_arguments_in_order_and_the_flags() {
        let a = CString::new("--after-update").unwrap();
        let b = CString::new("two words").unwrap();
        let argv = [a.as_ptr(), b.as_ptr()];
        let expect = CString::new("1.2.3").unwrap();
        let o = apply_options(expect.as_ptr(), 0, argv.as_ptr(), 2).expect("options");
        assert_eq!(
            o.restart_args,
            vec![
                OsString::from("--after-update"),
                OsString::from("two words")
            ]
        );
        assert_eq!(o.expect_version, Some(v("1.2.3")));
        assert_eq!(o.ui, UiChoice::Auto);
        assert!(!o.background);
        assert!(o.wait_for.is_none());
        let o = apply_options(ptr::null(), 3, ptr::null(), 0).expect("options");
        assert_eq!(o.ui, UiChoice::Never);
        assert!(o.background);
        assert!(o.restart_args.is_empty());
        assert_eq!(o.expect_version, None);
        let o = apply_options(ptr::null(), 2, ptr::null(), 0).expect("options");
        assert_eq!((o.ui, o.background), (UiChoice::Auto, true));
    }

    #[test]
    fn apply_options_refuse_bad_arguments_as_usage() {
        for bad in ["1.0", "01.0.0", "v1.0.0", "", " 1.0.0"] {
            let text = CString::new(bad).unwrap();
            assert_eq!(
                apply_options(text.as_ptr(), 0, ptr::null(), 0).err(),
                Some(Fail::usage()),
                "{bad:?}"
            );
        }
        for flags in [4, 8, 0x8000_0000, 7, u32::MAX] {
            assert_eq!(
                apply_options(ptr::null(), flags, ptr::null(), 0).err(),
                Some(Fail::usage()),
                "{flags}"
            );
        }
        assert_eq!(
            apply_options(ptr::null(), 0, ptr::null(), 1).err(),
            Some(Fail::usage())
        );
        let argv = [ptr::null()];
        assert_eq!(
            apply_options(ptr::null(), 0, argv.as_ptr(), 1).err(),
            Some(Fail::usage())
        );
    }

    fn text(p: *const c_char) -> Option<String> {
        // SAFETY: a non-NULL result is a NUL-terminated string the handle keeps alive.
        (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned())
    }

    #[test]
    fn convert_keeps_order_kinds_recipients_and_the_from_of_an_update_only() {
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
        let s = convert(&events, StartupAction::Continue, true, &v("1.1.0")).expect("convert");
        assert!(!s.should_exit && s.pending);
        let p: *const LunepackStartup = &s;
        // SAFETY: `p` points to a live value for the whole block.
        unsafe {
            assert_eq!(lunepack_startup_event_count(p), 3);
            let kinds: Vec<u32> = (0..3).map(|i| lunepack_startup_event_kind(p, i)).collect();
            assert_eq!(kinds, [1, 2, 3]);
            let versions: Vec<_> = (0..3)
                .map(|i| text(lunepack_startup_event_version(p, i)))
                .collect();
            assert_eq!(
                versions,
                [
                    Some("1.0.0".into()),
                    Some("1.1.0".into()),
                    Some("1.1.0".into())
                ]
            );
            let froms: Vec<_> = (0..3)
                .map(|i| text(lunepack_startup_event_from(p, i)))
                .collect();
            assert_eq!(froms, [None, Some("1.0.0".into()), None]);
            assert_eq!(
                text(lunepack_startup_tree_version(p)).as_deref(),
                Some("1.1.0")
            );
            assert!(lunepack_startup_pending(p));
            assert!(!lunepack_startup_should_exit(p));
            // Out of range.
            assert_eq!(lunepack_startup_event_kind(p, 3), 0);
            assert_eq!(lunepack_startup_event_kind(p, usize::MAX), 0);
            assert!(lunepack_startup_event_version(p, 3).is_null());
            assert!(lunepack_startup_event_from(p, 3).is_null());
            // Pointers are stable across calls.
            assert_eq!(
                lunepack_startup_event_version(p, 1),
                lunepack_startup_event_version(p, 1)
            );
        }
    }

    #[test]
    fn should_exit_is_true_exactly_for_the_exit_action() {
        for (action, want) in [
            (StartupAction::Continue, false),
            (StartupAction::Exit, true),
        ] {
            let s = convert(&[], action, false, &v("2.0.0")).expect("convert");
            // SAFETY: a live value.
            assert_eq!(unsafe { lunepack_startup_should_exit(&s) }, want);
        }
    }

    #[test]
    fn null_handles_give_null_zero_or_false() {
        // SAFETY: NULL is allowed by every accessor and by free.
        unsafe {
            assert!(!lunepack_startup_should_exit(ptr::null()));
            assert!(!lunepack_startup_pending(ptr::null()));
            assert!(lunepack_startup_tree_version(ptr::null()).is_null());
            assert_eq!(lunepack_startup_event_count(ptr::null()), 0);
            assert_eq!(lunepack_startup_event_kind(ptr::null(), 0), 0);
            assert!(lunepack_startup_event_version(ptr::null(), 0).is_null());
            assert!(lunepack_startup_event_from(ptr::null(), 0).is_null());
            lunepack_startup_free(ptr::null_mut());
        }
    }
}
