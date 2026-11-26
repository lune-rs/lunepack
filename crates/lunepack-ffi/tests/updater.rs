//! The C binding's updater functions, called through the rlib as a C app calls them, over a fake
//! origin and an in-memory filesystem (M14 step 3). The running-app discovery (`open`) is proved by
//! the installed-layout end-to-end rows; here its refusals are.

#![allow(unsafe_code)] // every call below passes raw handles, as C does.

mod common;

use std::collections::{BTreeSet, HashSet};
use std::ffi::{CStr, c_char, c_void};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, ThreadId};
use std::time::Duration;

use common::*;
use lunepack::CancelToken;
use lunepack::blocking;
use lunepack_ffi::unstable_internals::{live_handles, updater_handle};
use lunepack_ffi::*;
use lunepack_testkit::{FakeOrigin, FakeTransport, SUITE_T0};

const OK: LunepackStatus = 0;
const USAGE: LunepackStatus = 2;
const BUSY: LunepackStatus = 4;
const CANCELLED: LunepackStatus = 5;
const UPDATE_CONFIG: LunepackStatus = 14;

fn text(p: *const c_char) -> Option<String> {
    (!p.is_null()).then(|| {
        // SAFETY: a non-NULL result is a NUL-terminated string the library keeps alive.
        unsafe { CStr::from_ptr(p) }
            .to_str()
            .expect("UTF-8")
            .to_owned()
    })
}

/// A world with 1.0.0 installed and 1.1.0 published, and its updater handle.
fn world_with_update() -> (World, *mut LunepackUpdater) {
    let w = World::new();
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.1.0");
    let u = updater_handle(w.updater());
    (w, u)
}

fn new_token() -> *mut LunepackCancelToken {
    let t = lunepack_cancel_token_new();
    assert!(!t.is_null());
    t
}

fn check(
    u: *const LunepackUpdater,
    cancel: *const LunepackCancelToken,
    f: LunepackProgressFn,
    ud: *mut c_void,
) -> (LunepackStatus, *mut LunepackUpdateInfo) {
    let mut out = 0x10 as *mut LunepackUpdateInfo;
    // SAFETY: `u` is a live handle (or NULL on purpose), `cancel` NULL or live, `out` writable.
    let status = unsafe { lunepack_updater_check(u, cancel, f, ud, &mut out) };
    (status, out)
}

fn download(
    u: *const LunepackUpdater,
    info: *const LunepackUpdateInfo,
    cancel: *const LunepackCancelToken,
    f: LunepackProgressFn,
    ud: *mut c_void,
) -> (LunepackStatus, *mut LunepackDownloaded) {
    let mut out = 0x10 as *mut LunepackDownloaded;
    // SAFETY: as in `check`; `info` is live.
    let status = unsafe { lunepack_updater_download(u, info, cancel, f, ud, &mut out) };
    (status, out)
}

fn stage(
    u: *const LunepackUpdater,
    d: *mut LunepackDownloaded,
    cancel: *const LunepackCancelToken,
    f: LunepackProgressFn,
    ud: *mut c_void,
) -> (LunepackStatus, *mut LunepackStaged) {
    let mut out = 0x10 as *mut LunepackStaged;
    // SAFETY: as in `check`; `d` is a live handle that this call consumes.
    let status = unsafe { lunepack_updater_stage(u, d, cancel, f, ud, &mut out) };
    (status, out)
}

/// Check, download and stage everything, freeing the intermediate handles; returns the staged one.
fn update_fully(u: *const LunepackUpdater) -> *mut LunepackStaged {
    let (s, info) = check(u, ptr::null(), None, ptr::null_mut());
    assert_eq!(s, OK);
    assert!(!info.is_null());
    let (s, d) = download(u, info, ptr::null(), None, ptr::null_mut());
    assert_eq!(s, OK);
    // SAFETY: `info` is live and freed once.
    unsafe { lunepack_update_info_free(info) };
    let (s, staged) = stage(u, d, ptr::null(), None, ptr::null_mut());
    assert_eq!(s, OK);
    assert!(!staged.is_null());
    staged
}

// ---- open --------------------------------------------------------------------------------------

#[test]
fn open_refuses_without_an_update_config_and_a_bad_channel_and_a_null_out() {
    let _s = serial();
    let mut out = 0x10 as *mut LunepackUpdater;
    // SAFETY: NULL channel is allowed; `out` is writable.
    let status = unsafe { lunepack_updater_open(ptr::null(), &mut out) };
    // This test binary has no update configuration above it: the status of `NoUpdateConfig`.
    assert_eq!(status, UPDATE_CONFIG);
    assert_eq!(
        text(lunepack_status_name(status)).as_deref(),
        Some("update_config")
    );
    assert!(out.is_null());
    assert!(lunepack_last_error_reason().is_null());

    // A channel outside the rule is `usage`, decided before anything is looked for on disk.
    for bad in [c"Bad Channel", c"", c"-x"] {
        out = 0x10 as *mut LunepackUpdater;
        // SAFETY: a valid NUL-terminated string and a writable slot.
        let status = unsafe { lunepack_updater_open(bad.as_ptr(), &mut out) };
        assert_eq!(status, USAGE, "{bad:?}");
        assert!(out.is_null());
    }
    // A valid channel still reaches the discovery.
    // SAFETY: as above.
    let status = unsafe { lunepack_updater_open(c"beta".as_ptr(), &mut out) };
    assert_eq!(status, UPDATE_CONFIG);
    // NULL out.
    // SAFETY: a NULL out slot is the case under test.
    let status = unsafe { lunepack_updater_open(ptr::null(), ptr::null_mut()) };
    assert_eq!(status, USAGE);
}

// ---- check, download, stage, staged --------------------------------------------------------------

#[test]
fn check_with_no_update_is_ok_and_null() {
    let _s = serial();
    let before = live_handles();
    let w = World::new();
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.0.0");
    let u = updater_handle(w.updater());
    let (status, info) = check(u, ptr::null(), None, ptr::null_mut());
    assert_eq!(status, OK);
    assert!(info.is_null());
    // SAFETY: `u` is live and freed once.
    unsafe { lunepack_updater_free(u) };
    assert_eq!(live_handles(), before);
    workers_stopped();
}

#[test]
fn check_finds_the_update_the_facade_finds() {
    let _s = serial();
    let before = live_handles();
    let (w, u) = world_with_update();
    let facade = blocking::Updater::from(w.updater())
        .check(&CancelToken::new())
        .expect("check")
        .expect("an update");
    let (status, info) = check(u, ptr::null(), None, ptr::null_mut());
    assert_eq!(status, OK);
    assert!(!info.is_null());
    // SAFETY: `info` is a live handle.
    unsafe {
        assert_eq!(
            text(lunepack_update_info_version(info)).as_deref(),
            Some("1.1.0")
        );
        assert_eq!(
            text(lunepack_update_info_version(info)),
            Some(facade.version().to_string())
        );
        assert_eq!(
            lunepack_update_info_download_size_max(info),
            facade.download_size_max()
        );
        assert_eq!(
            lunepack_update_info_download_size_max(info),
            w.pack("1.1.0").bytes.len() as u64
        );
        assert_eq!(
            lunepack_update_info_time_checked(info),
            facade.time_checked()
        );
        assert!(lunepack_update_info_time_checked(info));
        lunepack_update_info_free(info);
        lunepack_updater_free(u);
    }
    assert_eq!(live_handles(), before);
    workers_stopped();
}

#[test]
fn download_then_stage_stage_what_the_facades_blocking_calls_stage() {
    let _s = serial();
    let before = live_handles();
    let (w, u) = world_with_update();

    // The facade's own calls, in a world of their own.
    let reference = World::new();
    reference.install("1.0.0", SUITE_T0 - 10 * DAY);
    reference.publish(1, "1.1.0");
    let ru = blocking::Updater::from(reference.updater());
    let cancel = CancelToken::new();
    let info = ru.check(&cancel).expect("check").expect("update");
    let downloaded = ru
        .download(&info, lunepack::DownloadOptions::default(), &cancel)
        .expect("download");
    let want = ru.stage(downloaded, &cancel).expect("stage");

    // Nothing is staged yet.
    let mut out = 0x10 as *mut LunepackStaged;
    // SAFETY: `u` is live and `out` writable.
    assert_eq!(unsafe { lunepack_updater_staged(u, &mut out) }, OK);
    assert!(out.is_null());

    let staged = update_fully(u);
    // SAFETY: `staged` is a live handle until its free below.
    unsafe {
        assert_eq!(
            text(lunepack_staged_version(staged)),
            Some(want.version().to_string())
        );
        assert!(lunepack_staged_publisher(staged).is_null());
    }
    for (path, bytes) in files("1.1.0") {
        assert_eq!(
            w.read(&w.versions_dir.join("1.1.0").join(&path)),
            bytes,
            "{path}"
        );
        assert_eq!(
            w.read(&w.versions_dir.join("1.1.0").join(&path)),
            reference.read(&want.tree().join(&path)),
            "{path}"
        );
    }

    // `staged` finds the same tree again.
    // SAFETY: as above.
    assert_eq!(unsafe { lunepack_updater_staged(u, &mut out) }, OK);
    assert!(!out.is_null());
    // SAFETY: `out` is a live handle.
    unsafe {
        assert_eq!(text(lunepack_staged_version(out)).as_deref(), Some("1.1.0"));
        // The finding is not recorded for a re-opened version.
        assert!(lunepack_staged_publisher(out).is_null());
        lunepack_staged_free(out);
        lunepack_staged_free(staged);
        lunepack_updater_free(u);
    }
    assert_eq!(live_handles(), before);
    drop(ru);
    workers_stopped();
}

#[test]
fn stage_consumes_the_downloaded_handle_whatever_the_status() {
    let _s = serial();
    let before = live_handles();
    let (_w, u) = world_with_update();
    let (_, info) = check(u, ptr::null(), None, ptr::null_mut());
    let make = || {
        let (s, d) = download(u, info, ptr::null(), None, ptr::null_mut());
        assert_eq!(s, OK);
        d
    };
    let live_with_one = live_handles() + 1;

    // A NULL `out` is `usage`, and the handle is consumed.
    let d = make();
    assert_eq!(live_handles(), live_with_one);
    // SAFETY: a NULL out slot is the case under test; `d` is live and consumed by the call.
    let status = unsafe {
        lunepack_updater_stage(u, d, ptr::null(), None, ptr::null_mut(), ptr::null_mut())
    };
    assert_eq!(status, USAGE);
    assert_eq!(live_handles(), live_with_one - 1);

    // A NULL updater is `usage`: consumed.
    let d = make();
    let (s, out) = stage(ptr::null(), d, ptr::null(), None, ptr::null_mut());
    assert_eq!((s, out), (USAGE, ptr::null_mut()));
    assert_eq!(live_handles(), live_with_one - 1);

    // A cancelled token is `cancelled`: consumed, nothing staged.
    let d = make();
    let token = new_token();
    // SAFETY: `token` is live.
    unsafe { lunepack_cancel_token_cancel(token) };
    let (s, out) = stage(u, d, token, None, ptr::null_mut());
    assert_eq!((s, out), (CANCELLED, ptr::null_mut()));
    assert_eq!(live_handles(), live_with_one - 1);

    // A NULL downloaded is `usage` and consumes nothing.
    let (s, out) = stage(u, ptr::null_mut(), ptr::null(), None, ptr::null_mut());
    assert_eq!((s, out), (USAGE, ptr::null_mut()));

    // SAFETY: each handle is live and freed once.
    unsafe {
        lunepack_cancel_token_free(token);
        lunepack_update_info_free(info);
        lunepack_updater_free(u);
    }
    assert_eq!(live_handles(), before);
    workers_stopped();
}

// ---- progress -----------------------------------------------------------------------------------

/// `(phase, done, total, file path, file source)` of one event.
type Event = (LunepackPhase, u64, u64, Option<String>, LunepackSource);

/// A call to make from inside the callback, with the notes it leaves.
type Hook = Box<dyn FnMut(&mut Vec<String>) + Send>;

#[derive(Default)]
struct Recorder {
    events: Vec<Event>,
    threads: HashSet<ThreadId>,
    /// Run for every event, to make calls from inside the callback.
    hook: Option<Hook>,
    notes: Vec<String>,
}

extern "C" fn record(ud: *mut c_void, p: *const LunepackProgress) {
    // SAFETY: `ud` is the recorder the test passed, alive and used by this thread only for the
    // call; `p` is valid during the callback.
    let (rec, p) = unsafe { (&mut *ud.cast::<Recorder>(), &*p) };
    rec.threads.insert(thread::current().id());
    rec.events
        .push((p.phase, p.done, p.total, text(p.file_path), p.file_source));
    if let Some(mut hook) = rec.hook.take() {
        hook(&mut rec.notes);
        rec.hook = Some(hook);
    }
}

fn recorder() -> (Box<Recorder>, *mut c_void) {
    let mut rec = Box::<Recorder>::default();
    let ud = ptr::addr_of_mut!(*rec).cast::<c_void>();
    (rec, ud)
}

#[test]
fn progress_runs_only_on_the_calling_thread_and_only_during_the_call() {
    let _s = serial();
    let (w, u) = world_with_update();
    let release_files: BTreeSet<String> = files("1.1.0").into_iter().map(|(p, _)| p).collect();
    let addr = u as usize;
    let result = thread::spawn(move || {
        let u = addr as *mut LunepackUpdater;
        let (mut rec, ud) = recorder();
        let (s, info) = check(u, ptr::null(), Some(record), ud);
        assert_eq!(s, OK);
        let (s, d) = download(u, info, ptr::null(), Some(record), ud);
        assert_eq!(s, OK);
        let download_events = rec.events.len();
        let (s, staged) = stage(u, d, ptr::null(), Some(record), ud);
        assert_eq!(s, OK);
        let stage_events = rec.events.len() - download_events;
        let at_return = rec.events.len();
        // Nothing arrives after the call returned.
        thread::sleep(Duration::from_millis(100));
        assert_eq!(rec.events.len(), at_return);
        // SAFETY: both handles are live and freed once.
        unsafe {
            lunepack_update_info_free(info);
            lunepack_staged_free(staged);
        }
        rec.hook = None;
        (thread::current().id(), rec, download_events, stage_events)
    })
    .join()
    .expect("the calling thread");
    let (caller, rec, download_events, stage_events) = result;
    assert_eq!(
        rec.threads,
        HashSet::from([caller]),
        "every event on the caller's thread"
    );
    assert!(download_events > 0, "the download reports progress");
    assert!(stage_events > 0, "the stage reports progress");
    let phases: BTreeSet<LunepackPhase> = rec.events.iter().map(|e| e.0).collect();
    assert!(phases.contains(&LUNEPACK_PHASE_DOWNLOAD), "{phases:?}");
    assert!(phases.contains(&LUNEPACK_PHASE_STAGE), "{phases:?}");
    for (phase, done, total, path, source) in &rec.events {
        assert!(*phase != LUNEPACK_PHASE_UNKNOWN, "{phase}");
        assert!(text(lunepack_phase_name(*phase)).is_some());
        assert!(done <= total || *total == 0, "{done} of {total}");
        match path {
            Some(path) => {
                assert!(release_files.contains(path), "{path}");
                assert!(text(lunepack_source_name(*source)).is_some(), "{source}");
            }
            None => assert_eq!(*source, LUNEPACK_SOURCE_UNKNOWN),
        }
    }
    // SAFETY: `u` is live and freed once.
    unsafe { lunepack_updater_free(u) };
    drop(w);
    workers_stopped();
}

#[test]
fn a_callback_that_calls_lunepack_is_refused_and_one_that_cancels_ends_the_operation() {
    let _s = serial();
    let w0 = World::new();
    w0.install("1.0.0", SUITE_T0 - 10 * DAY);
    w0.publish(1, "1.1.0");
    // Every request yields once, so the operation takes several polls and the token set in the
    // callback is looked at before it can finish.
    let transport = Arc::new(YieldTransport {
        inner: Arc::clone(&w0.transport),
    });
    let w = World::with_transport(w0.origin.clone(), transport);
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    let u = updater_handle(w.updater());
    let (s, info) = check(u, ptr::null(), None, ptr::null_mut());
    assert_eq!(s, OK);

    // A spare downloaded handle, to stage from inside a callback.
    let (s, spare) = download(u, info, ptr::null(), None, ptr::null_mut());
    assert_eq!(s, OK);
    let before = live_handles();

    let token = new_token();
    let (uaddr, taddr, saddr) = (u as usize, token as usize, spare as usize);
    let (mut rec, ud) = recorder();
    rec.hook = Some(Box::new(move |notes| {
        if !notes.is_empty() {
            return;
        }
        // Another operation from inside the callback: `usage`, and `out` stays NULL.
        let (s, out) = check(
            uaddr as *const LunepackUpdater,
            ptr::null(),
            None,
            ptr::null_mut(),
        );
        notes.push(format!("check {s} {}", out.is_null()));
        let (s, out) = stage(
            uaddr as *const LunepackUpdater,
            saddr as *mut LunepackDownloaded,
            ptr::null(),
            None,
            ptr::null_mut(),
        );
        notes.push(format!("stage {s} {}", out.is_null()));
        let mut o = 0x10 as *mut LunepackStaged;
        // SAFETY: a live updater and a writable slot.
        let s = unsafe { lunepack_updater_staged(uaddr as *const LunepackUpdater, &mut o) };
        notes.push(format!("staged {s} {}", o.is_null()));
        // The token's own functions work from inside a callback.
        let t = taddr as *const LunepackCancelToken;
        // SAFETY: `t` is a live token.
        unsafe {
            notes.push(format!(
                "cancelled {}",
                lunepack_cancel_token_is_cancelled(t)
            ));
            lunepack_cancel_token_cancel(t);
            notes.push(format!(
                "cancelled {}",
                lunepack_cancel_token_is_cancelled(t)
            ));
        }
    }));
    let (s, out) = download(u, info, token, Some(record), ud);
    assert_eq!((s, out), (CANCELLED, ptr::null_mut()), "{:?}", rec.events);
    assert_eq!(
        rec.notes,
        [
            format!("check {USAGE} true"),
            format!("stage {USAGE} true"),
            format!("staged {USAGE} true"),
            "cancelled false".to_owned(),
            "cancelled true".to_owned(),
        ]
    );
    // The `stage` from inside the callback consumed the spare handle all the same.
    assert_eq!(live_handles(), before - 1);
    // SAFETY: each handle is live and freed once.
    unsafe {
        lunepack_cancel_token_free(token);
        lunepack_update_info_free(info);
        lunepack_updater_free(u);
    }
    workers_stopped();
}

// ---- cancel -------------------------------------------------------------------------------------

#[test]
fn a_token_cancelled_before_the_call_gives_cancelled_without_network_access() {
    let _s = serial();
    let (w, u) = world_with_update();
    let (_, info) = check(u, ptr::null(), None, ptr::null_mut());
    assert!(!info.is_null());
    let token = new_token();
    // SAFETY: `token` is live.
    unsafe { lunepack_cancel_token_cancel(token) };
    w.origin.clear_requests();

    let (s, out) = check(u, token, None, ptr::null_mut());
    assert_eq!((s, out), (CANCELLED, ptr::null_mut()));
    let (s, out) = download(u, info, token, None, ptr::null_mut());
    assert_eq!((s, out), (CANCELLED, ptr::null_mut()));
    assert!(w.origin.requests().is_empty(), "{:?}", w.origin.requests());
    // SAFETY: each handle is live and freed once.
    unsafe {
        lunepack_cancel_token_free(token);
        lunepack_update_info_free(info);
        lunepack_updater_free(u);
    }
    workers_stopped();
}

#[test]
fn cancel_from_another_thread_mid_download_gives_cancelled_and_a_later_download_resumes() {
    let _s = serial();
    let origin = FakeOrigin::new();
    let entered = Arc::new(AtomicBool::new(false));
    let open = Arc::new(AtomicBool::new(true));
    let gate = GateTransport {
        inner: Arc::new(FakeTransport::new(origin.clone())),
        entered: Arc::clone(&entered),
        open: Arc::clone(&open),
    };
    let w = World::with_transport(origin, Arc::new(gate));
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.1.0");
    let u = updater_handle(w.updater());
    let (s, info) = check(u, ptr::null(), None, ptr::null_mut());
    assert_eq!(s, OK);

    // Hold the next request at the gate; cancel once the download is inside it.
    open.store(false, Ordering::SeqCst);
    entered.store(false, Ordering::SeqCst);
    let token = new_token();
    let (taddr, flag) = (token as usize, Arc::clone(&entered));
    let helper = thread::spawn(move || {
        assert!(
            wait_until(Duration::from_secs(10), || flag.load(Ordering::SeqCst)),
            "the download never reached the transport"
        );
        // SAFETY: the token outlives this thread (joined below).
        unsafe { lunepack_cancel_token_cancel(taddr as *const LunepackCancelToken) };
    });
    let (s, out) = download(u, info, token, None, ptr::null_mut());
    helper.join().expect("helper");
    assert_eq!((s, out), (CANCELLED, ptr::null_mut()));

    // The part is kept: the next call continues it and the stage completes.
    open.store(true, Ordering::SeqCst);
    let (s, d) = download(u, info, ptr::null(), None, ptr::null_mut());
    assert_eq!(s, OK);
    let (s, staged) = stage(u, d, ptr::null(), None, ptr::null_mut());
    assert_eq!(s, OK);
    // SAFETY: each handle is live and freed once.
    unsafe {
        assert_eq!(
            text(lunepack_staged_version(staged)).as_deref(),
            Some("1.1.0")
        );
        lunepack_staged_free(staged);
        lunepack_cancel_token_free(token);
        lunepack_update_info_free(info);
        lunepack_updater_free(u);
    }
    workers_stopped();
}

// ---- threads ------------------------------------------------------------------------------------

#[test]
fn two_threads_checking_with_one_updater_both_return() {
    let _s = serial();
    let (_w, u) = world_with_update();
    let addr = u as usize;
    for _ in 0..10 {
        let run = move || {
            let (s, info) = check(
                addr as *const LunepackUpdater,
                ptr::null(),
                None,
                ptr::null_mut(),
            );
            // SAFETY: NULL or a live handle, freed once.
            unsafe { lunepack_update_info_free(info.cast_const().cast_mut()) };
            s
        };
        let a = thread::spawn(run);
        let b = thread::spawn(run);
        for status in [a.join().expect("a"), b.join().expect("b")] {
            assert!(status == OK || status == BUSY, "{status}");
        }
    }
    // SAFETY: `u` is live and freed once.
    unsafe { lunepack_updater_free(u) };
    workers_stopped();
}

#[test]
fn an_operation_holding_the_lock_makes_the_second_thread_busy() {
    let _s = serial();
    let origin = FakeOrigin::new();
    let entered = Arc::new(AtomicBool::new(false));
    let open = Arc::new(AtomicBool::new(false));
    let gate = GateTransport {
        inner: Arc::new(FakeTransport::new(origin.clone())),
        entered: Arc::clone(&entered),
        open: Arc::clone(&open),
    };
    let w = World::with_transport(origin, Arc::new(gate));
    w.install("1.0.0", SUITE_T0 - 10 * DAY);
    w.publish(1, "1.1.0");
    let u = updater_handle(w.updater());
    let addr = u as usize;
    let first = thread::spawn(move || {
        let (s, info) = check(
            addr as *const LunepackUpdater,
            ptr::null(),
            None,
            ptr::null_mut(),
        );
        (s, info as usize)
    });
    assert!(wait_until(Duration::from_secs(10), || entered.load(Ordering::SeqCst)));
    let (s, info) = check(u, ptr::null(), None, ptr::null_mut());
    assert_eq!((s, info), (BUSY, ptr::null_mut()));
    open.store(true, Ordering::SeqCst);
    let (s, info) = first.join().expect("first");
    assert_eq!(s, OK);
    assert!(info != 0);
    // SAFETY: each handle is live and freed once.
    unsafe {
        lunepack_update_info_free(info as *mut LunepackUpdateInfo);
        lunepack_updater_free(u);
    }
    workers_stopped();
}

struct SendPtr(*mut LunepackDownloaded);
// SAFETY: a `LunepackDownloaded` has one owner at a time and may move to another thread (D5);
// the test hands it over and does not touch it again here.
unsafe impl Send for SendPtr {}

#[test]
fn a_downloaded_handle_moves_to_another_thread_and_is_staged_there() {
    let _s = serial();
    let before = live_handles();
    let (_w, u) = world_with_update();
    let (_, info) = check(u, ptr::null(), None, ptr::null_mut());
    let (s, d) = download(u, info, ptr::null(), None, ptr::null_mut());
    assert_eq!(s, OK);
    let (uaddr, d) = (u as usize, SendPtr(d));
    let staged = thread::spawn(move || {
        let d = d;
        let (s, staged) = stage(
            uaddr as *const LunepackUpdater,
            d.0,
            ptr::null(),
            None,
            ptr::null_mut(),
        );
        assert_eq!(s, OK);
        staged as usize
    })
    .join()
    .expect("stage thread") as *mut LunepackStaged;
    // SAFETY: each handle is live and freed once.
    unsafe {
        assert_eq!(
            text(lunepack_staged_version(staged)).as_deref(),
            Some("1.1.0")
        );
        lunepack_staged_free(staged);
        lunepack_update_info_free(info);
        lunepack_updater_free(u);
    }
    assert_eq!(live_handles(), before);
    workers_stopped();
}

// ---- handles ------------------------------------------------------------------------------------

#[test]
fn accessors_given_null_return_null_zero_or_false_and_free_null_is_a_no_op() {
    let _s = serial();
    // SAFETY: NULL is allowed by every accessor and every `_free`.
    unsafe {
        assert!(lunepack_update_info_version(ptr::null()).is_null());
        assert_eq!(lunepack_update_info_download_size_max(ptr::null()), 0);
        assert!(!lunepack_update_info_time_checked(ptr::null()));
        assert!(lunepack_staged_version(ptr::null()).is_null());
        assert!(lunepack_staged_publisher(ptr::null()).is_null());
        lunepack_update_info_free(ptr::null_mut());
        lunepack_downloaded_free(ptr::null_mut());
        lunepack_staged_free(ptr::null_mut());
        lunepack_updater_free(ptr::null_mut());
        lunepack_cancel_token_free(ptr::null_mut());
    }
    // A NULL updater, info or out is `usage` and leaves `*out` NULL.
    let (s, out) = check(ptr::null(), ptr::null(), None, ptr::null_mut());
    assert_eq!((s, out), (USAGE, ptr::null_mut()));
    let (s, out) = download(ptr::null(), ptr::null(), ptr::null(), None, ptr::null_mut());
    assert_eq!((s, out), (USAGE, ptr::null_mut()));
    let mut staged = 0x10 as *mut LunepackStaged;
    // SAFETY: NULL updater is the case under test; `staged` is writable.
    let status = unsafe { lunepack_updater_staged(ptr::null(), &mut staged) };
    assert_eq!(status, USAGE);
    assert!(staged.is_null());
    // SAFETY: NULL out is the case under test.
    let status = unsafe {
        lunepack_updater_check(
            ptr::null(),
            ptr::null(),
            None,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(status, USAGE);
}

#[test]
fn every_returned_pointer_stays_valid_and_unchanged_until_its_handle_is_freed() {
    let _s = serial();
    let (_w, u) = world_with_update();
    let (_, info) = check(u, ptr::null(), None, ptr::null_mut());
    // SAFETY: `info` is live until its free below.
    let (p1, p2) = unsafe {
        (
            lunepack_update_info_version(info),
            lunepack_update_info_version(info),
        )
    };
    assert_eq!(p1, p2);
    assert_eq!(text(p1).as_deref(), Some("1.1.0"));
    // Other calls on the updater and other handles do not disturb it.
    let staged = update_fully(u);
    // SAFETY: `staged` is live until its free below.
    let (s1, s2) = unsafe {
        (
            lunepack_staged_version(staged),
            lunepack_staged_version(staged),
        )
    };
    assert_eq!(s1, s2);
    assert_eq!(text(s1).as_deref(), Some("1.1.0"));
    assert_eq!(text(p1).as_deref(), Some("1.1.0"));
    // SAFETY: each handle is live and freed once.
    unsafe {
        lunepack_staged_free(staged);
        lunepack_update_info_free(info);
        lunepack_updater_free(u);
    }
    workers_stopped();
}

#[test]
fn a_failure_of_a_class_without_a_reason_leaves_no_reason() {
    let _s = serial();
    let (_w, u) = world_with_update();
    let token = new_token();
    // SAFETY: `token` is live.
    unsafe { lunepack_cancel_token_cancel(token) };
    let (s, _) = check(u, token, None, ptr::null_mut());
    assert_eq!(s, CANCELLED);
    assert!(lunepack_last_error_reason().is_null());
    // SAFETY: each handle is live and freed once.
    unsafe {
        lunepack_cancel_token_free(token);
        lunepack_updater_free(u);
    }
    workers_stopped();
}
