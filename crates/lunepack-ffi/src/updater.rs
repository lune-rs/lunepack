//! The running app's own updater (M14-D2): open, check, download, stage, staged, and the result
//! handles. Each function is one facade call the runtime's `check` and `download` commands make
//! (`crates/lunepack-runtime/src/cli/commands.rs`), wrapped in the guard.

#![allow(unsafe_code)] // raw handles and strings from C: every unsafe block says what the caller promised.

use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use lunepack::blocking;
use lunepack::{
    CancelToken, CheckOptions, DownloadOptions, Downloaded, Error, Installation, StagedVersion,
    UpdateInfo,
};

use crate::cancel::LunepackCancelToken;
use crate::guard;
use crate::progress::{Bridge, LunepackProgressFn};
use crate::status::{Fail, LunepackStatus, publisher_name};

/// Handles alive now, for the tests' leak check.
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// Counts one live handle for as long as it exists.
pub(crate) struct Live;

impl Live {
    pub(crate) fn new() -> Live {
        LIVE.fetch_add(1, Ordering::SeqCst);
        Live
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

/// How many updater, update-info, downloaded, staged and startup handles are alive: every `_free` and every
/// consuming call lowers it. For the tests; not part of the C ABI.
pub fn live_handles() -> usize {
    LIVE.load(Ordering::SeqCst)
}

/// The running app's updater, made by `lunepack_updater_open` from its own tree's configuration
/// and released by `lunepack_updater_free`. Safe to use from several threads at once; two
/// operations at the same time give one `busy`.
pub struct LunepackUpdater {
    inner: blocking::Updater,
    _live: Live,
}

/// An update `lunepack_updater_check` found, immutable until `lunepack_update_info_free`. Safe to
/// read from several threads at once.
pub struct LunepackUpdateInfo {
    info: UpdateInfo,
    version: CString,
    _live: Live,
}

/// A completed download, the input of `lunepack_updater_stage`, which consumes it. One owner at a
/// time: it may be moved to another thread, never used from two at once.
pub struct LunepackDownloaded {
    downloaded: Downloaded,
    _live: Live,
}

/// A staged version tree, immutable until `lunepack_staged_free`. Safe to read from several
/// threads at once.
pub struct LunepackStaged {
    version: CString,
    publisher: Option<&'static CStr>,
    _live: Live,
}

// The threading contract of D5, as compile-time facts. `Downloaded` holds the boxed progress
// callback (`FnMut + Send`), so it is `Send` and never `Sync`.
const _: () = {
    const fn send<T: Send>() {}
    const fn send_sync<T: Send + Sync>() {}
    send_sync::<blocking::Updater>();
    send_sync::<UpdateInfo>();
    send_sync::<StagedVersion>();
    send::<Downloaded>();
    send_sync::<LunepackUpdater>();
    send_sync::<LunepackUpdateInfo>();
    send_sync::<LunepackStaged>();
    send_sync::<LunepackCancelToken>();
    send::<LunepackDownloaded>();
};

/// A handle for an updater the caller built itself, for the Rust tests (a C app can only open the
/// updater of its own tree). Release it with `lunepack_updater_free`. Not part of the C ABI.
pub fn updater_handle(updater: lunepack::Updater) -> *mut LunepackUpdater {
    Box::into_raw(Box::new(LunepackUpdater {
        inner: blocking::Updater::from(updater),
        _live: Live::new(),
    }))
}

fn updater<'a>(p: *const LunepackUpdater) -> Result<&'a LunepackUpdater, Fail> {
    // SAFETY: NULL is checked by `as_ref`; otherwise the caller promises a live handle for the call.
    unsafe { p.as_ref() }.ok_or_else(Fail::usage)
}

/// The token to run under: the caller's (a clone shares its flag), or a fresh one for NULL.
fn token(p: *const LunepackCancelToken) -> CancelToken {
    // SAFETY: NULL is checked by `as_ref`; otherwise the caller promises a live handle for the call.
    unsafe { p.as_ref() }.map_or_else(CancelToken::new, |t| t.token().clone())
}

fn text(version: &lunepack::Version) -> Result<CString, Fail> {
    CString::new(version.to_string()).map_err(|_| Fail::internal())
}

/// Opens the updater of the running app, from the update configuration its own tree carries: the
/// root key, the feed and the channel come from there and nowhere else (D44); no argument names
/// them. `channel` (NULL: the configured one) picks another channel of the same feed; text that is
/// not a channel id is `usage`. `out` receives the handle (NULL on failure). A process with no
/// update configuration above its executable (a development run) gets `update_config`; a tree
/// that is not installed gets `not_installed`. Release the handle with `lunepack_updater_free`.
///
/// # Safety
/// `channel` is NULL or a NUL-terminated string valid for the call; `out` is a writable slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_updater_open(
    channel: *const c_char,
    out: *mut *mut LunepackUpdater,
) -> LunepackStatus {
    guard::call_out(out, |slot| {
        let channel = guard::channel(channel)?;
        let inst = Installation::from_current_exe().map_err(|e| Fail::of(&e))?;
        // No network and no state for a tree that is not installed, as the command line does,
        // unless it is a macOS bundle the check may adopt.
        if !inst.is_installed() && !inst.adoptable() {
            return Err(Fail::of(&Error::NotInstalled));
        }
        let mut builder = inst.updater_builder().map_err(|e| Fail::of(&e))?;
        if let Some(channel) = channel {
            builder = builder.channel(channel);
        }
        let updater = builder.build().map_err(|e| Fail::of(&e))?;
        slot.set(LunepackUpdater {
            inner: blocking::Updater::from(updater),
            _live: Live::new(),
        });
        Ok(())
    })
}

/// Releases an updater. NULL does nothing. No operation may still run on it.
///
/// # Safety
/// `updater` is NULL or a handle from `lunepack_updater_open` not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_updater_free(updater: *mut LunepackUpdater) {
    free(updater);
}

/// Checks the feed for an update. `out` receives a handle when there is one and NULL when there is
/// none (status ok either way). `cancel` is NULL or a token that ends the call with `cancelled`;
/// `progress` is NULL or a callback (a check reports progress only when it adopts a macOS bundle).
///
/// # Safety
/// `updater` is a live handle, `cancel` NULL or a live token, `progress` NULL or a valid
/// callback, `user_data` whatever the callback expects, `out` a writable slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_updater_check(
    updater: *const LunepackUpdater,
    cancel: *const LunepackCancelToken,
    progress: LunepackProgressFn,
    user_data: *mut c_void,
    out: *mut *mut LunepackUpdateInfo,
) -> LunepackStatus {
    guard::call_out(out, |slot| {
        let updater = self::updater(updater)?;
        let options = CheckOptions {
            progress: Bridge::new(progress, user_data).map(Bridge::into_callback),
            cancel: None,
        };
        let outcome = updater
            .inner
            .check_with(options, &token(cancel))
            .map_err(|e| Fail::of(&e))?;
        if let Some(info) = outcome.update {
            slot.set(LunepackUpdateInfo {
                version: text(info.version())?,
                info,
                _live: Live::new(),
            });
        }
        Ok(())
    })
}

/// The new version as canonical SemVer text. Valid, unchanged, until the handle is freed. NULL
/// for a NULL handle.
///
/// # Safety
/// `info` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_update_info_version(
    info: *const LunepackUpdateInfo,
) -> *const c_char {
    guard::quiet(ptr::null(), || {
        // SAFETY: NULL is checked by `as_ref`; otherwise the caller promises a live handle.
        unsafe { info.as_ref() }.map_or(ptr::null(), |i| i.version.as_ptr())
    })
}

/// The most bytes a download of this update fetches: the pack's signed size. 0 for NULL.
///
/// # Safety
/// `info` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_update_info_download_size_max(
    info: *const LunepackUpdateInfo,
) -> u64 {
    guard::quiet(0, || {
        // SAFETY: NULL is checked by `as_ref`; otherwise the caller promises a live handle.
        unsafe { info.as_ref() }.map_or(0, |i| i.info.download_size_max())
    })
}

/// Whether expiry and key windows were checked; false when the clock was implausible and they
/// were skipped. false for NULL.
///
/// # Safety
/// `info` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_update_info_time_checked(
    info: *const LunepackUpdateInfo,
) -> bool {
    guard::quiet(false, || {
        // SAFETY: NULL is checked by `as_ref`; otherwise the caller promises a live handle.
        unsafe { info.as_ref() }.is_some_and(|i| i.info.time_checked())
    })
}

/// Releases an update-info handle. NULL does nothing.
///
/// # Safety
/// `info` is NULL or a handle not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_update_info_free(info: *mut LunepackUpdateInfo) {
    free(info);
}

/// Downloads the update `info` describes into the cache, resumably: a download that was cancelled
/// or ended early keeps its part, and the next call continues it. `out` receives the handle for
/// `lunepack_updater_stage`, or NULL on failure. A `progress` callback runs during this call only.
///
/// # Safety
/// As `lunepack_updater_check`, and `info` is a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_updater_download(
    updater: *const LunepackUpdater,
    info: *const LunepackUpdateInfo,
    cancel: *const LunepackCancelToken,
    progress: LunepackProgressFn,
    user_data: *mut c_void,
    out: *mut *mut LunepackDownloaded,
) -> LunepackStatus {
    guard::call_out(out, |slot| {
        let updater = self::updater(updater)?;
        // SAFETY: NULL is checked by `as_ref`; otherwise the caller promises a live handle.
        let info = unsafe { info.as_ref() }.ok_or_else(Fail::usage)?;
        let options = DownloadOptions {
            progress: Bridge::new(progress, user_data).map(Bridge::into_callback),
            cancel: None,
        };
        let downloaded = updater
            .inner
            .download(&info.info, options, &token(cancel))
            .map_err(|e| Fail::of(&e))?
            // The download's callback ends with the call: the handle keeps no C pointer.
            .with_options(DownloadOptions::default());
        slot.set(LunepackDownloaded {
            downloaded,
            _live: Live::new(),
        });
        Ok(())
    })
}

/// Releases a downloaded handle that was not staged. NULL does nothing.
///
/// # Safety
/// `downloaded` is NULL or a handle not yet freed or staged.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_downloaded_free(downloaded: *mut LunepackDownloaded) {
    free(downloaded);
}

/// Builds the new version's tree from the download and verifies it. CONSUMES `downloaded`
/// whenever it is not NULL, whatever the status: do not free or reuse it afterwards. `out`
/// receives the staged handle, or NULL on failure. The runtime's `download` command stages the
/// same way. A `progress` callback runs during this call only.
///
/// # Safety
/// As `lunepack_updater_check`, and `downloaded` is NULL or a handle not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_updater_stage(
    updater: *const LunepackUpdater,
    downloaded: *mut LunepackDownloaded,
    cancel: *const LunepackCancelToken,
    progress: LunepackProgressFn,
    user_data: *mut c_void,
    out: *mut *mut LunepackStaged,
) -> LunepackStatus {
    // Ownership passes first: nothing below, not a NULL `out` and not a refused reentrant call,
    // may leave the caller unsure whether to free the handle.
    let owned = take(downloaded);
    guard::call_out(out, move |slot| {
        let updater = self::updater(updater)?;
        let owned = owned.ok_or_else(Fail::usage)?;
        let downloaded = owned.downloaded.with_options(DownloadOptions {
            progress: Bridge::new(progress, user_data).map(Bridge::into_callback),
            cancel: None,
        });
        let staged = updater
            .inner
            .stage(downloaded, &token(cancel))
            .map_err(|e| Fail::of(&e))?;
        slot.set(staged_handle(staged)?);
        Ok(())
    })
}

/// The version staged in this install, if any: `out` receives a handle, or NULL when nothing is
/// staged (status ok either way).
///
/// # Safety
/// `updater` is a live handle and `out` a writable slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_updater_staged(
    updater: *const LunepackUpdater,
    out: *mut *mut LunepackStaged,
) -> LunepackStatus {
    guard::call_out(out, |slot| {
        let updater = self::updater(updater)?;
        if let Some(staged) = updater.inner.staged().map_err(|e| Fail::of(&e))? {
            slot.set(staged_handle(staged)?);
        }
        Ok(())
    })
}

fn staged_handle(staged: StagedVersion) -> Result<LunepackStaged, Fail> {
    Ok(LunepackStaged {
        version: text(staged.version())?,
        publisher: staged.publisher().and_then(publisher_name),
        _live: Live::new(),
    })
}

/// The staged version as canonical SemVer text. Valid, unchanged, until the handle is freed. NULL
/// for a NULL handle.
///
/// # Safety
/// `staged` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_staged_version(staged: *const LunepackStaged) -> *const c_char {
    guard::quiet(ptr::null(), || {
        // SAFETY: NULL is checked by `as_ref`; otherwise the caller promises a live handle.
        unsafe { staged.as_ref() }.map_or(ptr::null(), |s| s.version.as_ptr())
    })
}

/// What the publisher check reported when it let this version through, as the runtime names it
/// (`different`, `installed_unsigned`, `installed_invalid`, `candidate_unsigned`,
/// `candidate_invalid`, `os`), or NULL: no finding, or a handle from `lunepack_updater_staged`
/// (the finding is not recorded). Static string. NULL for a NULL handle.
///
/// # Safety
/// `staged` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_staged_publisher(staged: *const LunepackStaged) -> *const c_char {
    guard::quiet(ptr::null(), || {
        // SAFETY: NULL is checked by `as_ref`; otherwise the caller promises a live handle.
        unsafe { staged.as_ref() }
            .and_then(|s| s.publisher)
            .map_or(ptr::null(), CStr::as_ptr)
    })
}

/// Releases a staged handle. NULL does nothing.
///
/// # Safety
/// `staged` is NULL or a handle not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_staged_free(staged: *mut LunepackStaged) {
    free(staged);
}

/// Takes back ownership of a handle the caller passes in; NULL is `None`.
fn take<T>(p: *mut T) -> Option<Box<T>> {
    // SAFETY: non-NULL, and the caller promises a handle this library made with `Box::into_raw`
    // and has not freed.
    (!p.is_null()).then(|| unsafe { Box::from_raw(p) })
}

fn free<T>(p: *mut T) {
    guard::quiet((), || drop(take(p)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use lunepack::PublisherOutcome as P;

    /// The staged handle names a finding as the runtime's `publisher` member does.
    #[test]
    fn publisher_findings_are_named_as_the_runtime_names_them() {
        for finding in [
            P::Different,
            P::InstalledUnsigned,
            P::InstalledInvalid,
            P::CandidateUnsigned,
            P::CandidateInvalid,
            P::Os,
        ] {
            let name = publisher_name(finding).expect("a name");
            assert_eq!(name.to_str(), Ok(finding.code()), "{finding:?}");
        }
    }
}
