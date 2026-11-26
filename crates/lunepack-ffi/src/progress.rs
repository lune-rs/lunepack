//! The progress bridge (M14-D5): turns a C function pointer and its `void *` into the facade's
//! boxed progress callback.
//!
//! The facade runs the callback on the thread that polls the operation, which for the blocking
//! API is the calling thread, and the bridge does not trust that: an event that arrives on any
//! other thread is dropped, never delivered to C. While C runs, the thread is marked as inside a
//! callback, so every lunepack call it makes except the cancel token's is refused with `usage`.

#![allow(unsafe_code)] // a C callback and its user pointer cross the boundary here.

use std::ffi::{CString, c_char, c_void};
use std::ptr;
use std::thread::{self, ThreadId};

use lunepack::{Progress, ProgressCallback};

use crate::guard::CallbackScope;
use crate::{LunepackPhase, LunepackSource, phase_number, source_number};

/// One progress event. It lives on the stack of the library for the duration of the callback only:
/// copy what is needed, keep no pointer from it.
#[repr(C)]
pub struct LunepackProgress {
    /// `LUNEPACK_PHASE_*`, or `LUNEPACK_PHASE_UNKNOWN` for a phase this version does not know.
    pub phase: LunepackPhase,
    /// Bytes done in the phase.
    pub done: u64,
    /// Bytes the phase needs (0 while unknown).
    pub total: u64,
    /// The signed relative path of the file this event is about, UTF-8, or NULL when it is not
    /// about one file. Valid during the callback only.
    pub file_path: *const c_char,
    /// Bytes done for that file (0 without a file).
    pub file_done: u64,
    /// Bytes that file needs (0 without a file).
    pub file_total: u64,
    /// `LUNEPACK_SOURCE_*` of that file's bytes (`LUNEPACK_SOURCE_UNKNOWN` without a file).
    pub file_source: LunepackSource,
}

/// A progress callback. It runs on the thread that made the call, only during the call. It must
/// not unwind or `longjmp` out. Every function that returns a status
/// gives `LUNEPACK_STATUS_USAGE` when called from it; accessors, name lookups, `_free` functions
/// and `lunepack_cancel_token_cancel` and `lunepack_cancel_token_is_cancelled` are allowed. NULL
/// means no callback.
pub type LunepackProgressFn =
    Option<extern "C" fn(user_data: *mut c_void, progress: *const LunepackProgress)>;

/// A callback and its user pointer, bound to the thread that made the call.
pub(crate) struct Bridge {
    f: extern "C" fn(*mut c_void, *const LunepackProgress),
    user_data: *mut c_void,
    thread: ThreadId,
}

// SAFETY: the bridge never dereferences `user_data` and calls `f` only on `thread` (checked in
// `deliver`), so moving it to another thread, where the facade may hold or drop it, touches no C
// state: it is dropped there without a call.
unsafe impl Send for Bridge {}

impl Bridge {
    /// A bridge for `f`, bound to the calling thread; `None` for no callback.
    pub(crate) fn new(f: LunepackProgressFn, user_data: *mut c_void) -> Option<Bridge> {
        f.map(|f| Bridge {
            f,
            user_data,
            thread: thread::current().id(),
        })
    }

    /// The facade's callback for this bridge.
    pub(crate) fn into_callback(self) -> ProgressCallback {
        // A method call captures the whole bridge (and its `Send`), not its pointer field.
        Box::new(move |progress: &Progress| self.deliver(progress))
    }

    fn deliver(&self, progress: &Progress) {
        if thread::current().id() != self.thread {
            return;
        }
        // A path with an interior NUL cannot be a signed relative path; it is sent as no file.
        let path = progress
            .file
            .as_ref()
            .and_then(|f| CString::new(f.path.as_str()).ok());
        let event = LunepackProgress {
            phase: phase_number(progress.phase),
            done: progress.done,
            total: progress.total,
            file_path: path.as_ref().map_or(ptr::null(), |p| p.as_ptr()),
            file_done: progress.file.as_ref().map_or(0, |f| f.done),
            file_total: progress.file.as_ref().map_or(0, |f| f.total),
            file_source: progress
                .file
                .as_ref()
                .map_or(0, |f| source_number(f.source)),
        };
        let _scope = CallbackScope::enter();
        (self.f)(self.user_data, &event);
    }
}
