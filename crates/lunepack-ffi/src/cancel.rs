//! The cancel token (M14-D2, D5): one flag a caller sets from any thread, even from inside a
//! progress callback, to cancel the operations it was given to.

#![allow(unsafe_code)] // `no_mangle` entry points over caller-owned raw pointers.

use lunepack::CancelToken;

use crate::guard;
use crate::status::LunepackStatus;

/// A cancel token: an opaque handle made by `lunepack_cancel_token_new` and released by
/// `lunepack_cancel_token_free`. Safe to use from several threads at once; cancelling is
/// permanent. A function that takes a token accepts NULL for "no token".
pub struct LunepackCancelToken {
    inner: CancelToken,
}

impl LunepackCancelToken {
    /// The facade token operations observe.
    #[allow(dead_code)] // the updater functions of the next step pass it to their options.
    pub(crate) fn token(&self) -> &CancelToken {
        &self.inner
    }
}

// The binding hands the handle to several threads (D5): `Send + Sync` is a compile-time fact.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LunepackCancelToken>();
};

/// Makes a token that is not cancelled. `out` receives the handle (NULL on failure); release it
/// with `lunepack_cancel_token_free`.
#[unsafe(no_mangle)]
pub extern "C" fn lunepack_cancel_token_new(out: *mut *mut LunepackCancelToken) -> LunepackStatus {
    guard::call_out(out, |slot| {
        slot.set(LunepackCancelToken {
            inner: CancelToken::new(),
        });
        Ok(())
    })
}

/// Cancels the token and wakes whatever waits on it. Callable from any thread and from inside a
/// progress callback. NULL does nothing.
///
/// # Safety
/// `token` is NULL or a live handle from `lunepack_cancel_token_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_cancel_token_cancel(token: *const LunepackCancelToken) {
    guard::quiet((), || {
        // SAFETY: NULL is checked by `as_ref`; otherwise the caller promises a live handle.
        if let Some(token) = unsafe { token.as_ref() } {
            token.inner.cancel();
        }
    });
}

/// Whether the token was cancelled. NULL is not cancelled. Callable from any thread and from
/// inside a progress callback.
///
/// # Safety
/// `token` is NULL or a live handle from `lunepack_cancel_token_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_cancel_token_is_cancelled(
    token: *const LunepackCancelToken,
) -> bool {
    guard::quiet(false, || {
        // SAFETY: NULL is checked by `as_ref`; otherwise the caller promises a live handle.
        unsafe { token.as_ref() }.is_some_and(|t| t.inner.is_cancelled())
    })
}

/// Releases a token. NULL does nothing. The handle must not be used afterwards, and no operation
/// still running may hold it.
///
/// # Safety
/// `token` is NULL or a handle from `lunepack_cancel_token_new` not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lunepack_cancel_token_free(token: *mut LunepackCancelToken) {
    guard::quiet((), || {
        if !token.is_null() {
            // SAFETY: made by `Box::into_raw` in `lunepack_cancel_token_new`; freed once.
            drop(unsafe { Box::from_raw(token) });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{LUNEPACK_STATUS_OK, LUNEPACK_STATUS_USAGE};
    use std::future::poll_fn;
    use std::ptr;
    use std::task::Poll;

    fn new_token() -> *mut LunepackCancelToken {
        let mut t = ptr::null_mut();
        assert_eq!(lunepack_cancel_token_new(&mut t), LUNEPACK_STATUS_OK);
        assert!(!t.is_null());
        t
    }

    #[test]
    fn new_cancel_is_cancelled_free() {
        let t = new_token();
        // SAFETY: `t` is a live handle until the free at the end.
        unsafe {
            assert!(!lunepack_cancel_token_is_cancelled(t));
            lunepack_cancel_token_cancel(t);
            assert!(lunepack_cancel_token_is_cancelled(t));
            lunepack_cancel_token_cancel(t); // permanent and idempotent
            assert!(lunepack_cancel_token_is_cancelled(t));
            lunepack_cancel_token_free(t);
        }
    }

    #[test]
    fn null_is_accepted_everywhere() {
        // SAFETY: NULL is allowed by every function's contract.
        unsafe {
            lunepack_cancel_token_cancel(ptr::null());
            assert!(!lunepack_cancel_token_is_cancelled(ptr::null()));
            lunepack_cancel_token_free(ptr::null_mut());
        }
        assert_eq!(
            lunepack_cancel_token_new(ptr::null_mut()),
            LUNEPACK_STATUS_USAGE
        );
    }

    #[test]
    fn cancel_and_is_cancelled_work_inside_a_callback_but_new_does_not() {
        let t = new_token();
        let scope = guard::CallbackScope::enter();
        // SAFETY: `t` is live.
        unsafe {
            lunepack_cancel_token_cancel(t);
            assert!(lunepack_cancel_token_is_cancelled(t));
        }
        let mut other = 0x10 as *mut LunepackCancelToken;
        assert_eq!(lunepack_cancel_token_new(&mut other), LUNEPACK_STATUS_USAGE);
        assert!(other.is_null());
        drop(scope);
        // SAFETY: `t` is live and freed once.
        unsafe { lunepack_cancel_token_free(t) };
    }

    #[test]
    fn cancel_from_another_thread_wakes_a_blocked_run() {
        let t = new_token();
        // A raw pointer is not `Send`; the token is, and so is a usize holding its address.
        let addr = t as usize;
        // SAFETY: `t` is live until the free below, after the helper thread has joined.
        let facade = unsafe { &*t }.token().clone();
        let helper = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            // SAFETY: the handle outlives this thread (joined before the free).
            unsafe { lunepack_cancel_token_cancel(addr as *const LunepackCancelToken) };
        });
        // The same wait `blocking::run` makes: park until the token's waker fires.
        lunepack::block_on(poll_fn(|cx| {
            facade.register_waker(cx.waker());
            if facade.is_cancelled() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }));
        helper.join().expect("helper thread");
        assert!(facade.is_cancelled());
        // SAFETY: `t` is live and freed once.
        unsafe { lunepack_cancel_token_free(t) };
    }
}
