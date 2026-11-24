//! Progress coalescing (M4-D3, M4-D19): workers report into a [`ProgressSink`]; the polling task
//! drains a [`ProgressPump`] and calls the app's callback with the latest snapshot.
//!
//! Workers never call the app's callback themselves, so the callback runs on the thread that polls
//! the operation. Updates between two polls collapse into one event. A worker's update wakes the
//! polling task only on the clean-to-dirty transition, so a flood of updates costs one wake.
//!
//! Coalescing never drops a whole phase (C9): a phase change while updates are still undelivered
//! first queues the last snapshot of the phase it ends, and the next pump delivers the queued
//! snapshots, oldest first, before the latest. A phase that starts and ends between two polls (a
//! short scan whose job finished before its first poll) is still seen once, at its last state.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::Waker;

use lunepack_core::{FileProgress, Phase, Progress};

/// Most phase-end snapshots kept between two pumps. Phase changes come from the operation's own
/// code on the polling thread (a handful per operation), so the cap is never reached in practice;
/// it only bounds memory.
const PHASE_QUEUE_CAP: usize = 16;

struct Meta {
    phase: Phase,
    total: u64,
    file: Option<FileProgress>,
    /// The last snapshots of phases that ended with updates still undelivered, oldest first.
    ended: VecDeque<Progress>,
}

struct Shared {
    done: AtomicU64,
    dirty: AtomicBool,
    meta: Mutex<Meta>,
    waker: Mutex<Option<Waker>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // Only plain stores happen under these locks.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    fn mark_dirty(&self) {
        if !self.dirty.swap(true, Ordering::SeqCst) {
            let waker = lock(&self.waker).clone();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    /// The current snapshot, read under the held `meta` lock.
    fn snapshot_of(&self, meta: &Meta) -> Progress {
        Progress {
            phase: meta.phase,
            done: self.done.load(Ordering::SeqCst),
            total: meta.total,
            file: meta.file.clone(),
        }
    }
}

/// A new progress channel, starting in `phase` with `total` bytes to do.
pub fn progress(phase: Phase, total: u64) -> (ProgressSink, ProgressPump) {
    let shared = Arc::new(Shared {
        done: AtomicU64::new(0),
        dirty: AtomicBool::new(false),
        meta: Mutex::new(Meta {
            phase,
            total,
            file: None,
            ended: VecDeque::new(),
        }),
        waker: Mutex::new(None),
    });
    (
        ProgressSink {
            shared: Arc::clone(&shared),
        },
        ProgressPump { shared, last: None },
    )
}

/// The workers' side: cheap updates (an atomic add, or a short lock) that never call back.
#[derive(Clone)]
pub struct ProgressSink {
    shared: Arc<Shared>,
}

impl ProgressSink {
    /// Adds `n` bytes done in the current phase (lock-free).
    pub fn add_done(&self, n: u64) {
        self.shared.done.fetch_add(n, Ordering::SeqCst);
        self.shared.mark_dirty();
    }

    /// Sets the file being worked on (or none).
    pub fn set_file(&self, file: Option<FileProgress>) {
        lock(&self.shared.meta).file = file;
        self.shared.mark_dirty();
    }

    /// Sets the total of the current phase without touching `done` (what is to do became known
    /// after the phase started).
    pub fn set_total(&self, total: u64) {
        lock(&self.shared.meta).total = total;
        self.shared.mark_dirty();
    }

    /// Raises the total of the current phase by `n` bytes (saturating); `done` is untouched.
    pub fn add_total(&self, n: u64) {
        {
            let mut meta = lock(&self.shared.meta);
            meta.total = meta.total.saturating_add(n);
        }
        self.shared.mark_dirty();
    }

    /// Lowers the total of the current phase by `n` bytes (saturating at 0): work that will not be
    /// done after all.
    pub fn sub_total(&self, n: u64) {
        {
            let mut meta = lock(&self.shared.meta);
            meta.total = meta.total.saturating_sub(n);
        }
        self.shared.mark_dirty();
    }

    /// The current phase's `(total, done)` bytes, read together.
    pub(crate) fn totals(&self) -> (u64, u64) {
        let meta = lock(&self.shared.meta);
        (meta.total, self.shared.done.load(Ordering::SeqCst))
    }

    /// Starts `phase` with `total` bytes to do: `done` goes back to 0 and the file to none. When
    /// the phase it ends has updates the pump has not delivered yet (its own start included), its
    /// last snapshot is queued so the callback still sees it.
    pub fn set_phase(&self, phase: Phase, total: u64) {
        {
            let mut meta = lock(&self.shared.meta);
            if meta.phase != phase && self.shared.dirty.load(Ordering::SeqCst) {
                let last = self.shared.snapshot_of(&meta);
                if meta.ended.len() >= PHASE_QUEUE_CAP {
                    meta.ended.pop_front();
                }
                meta.ended.push_back(last);
            }
            meta.phase = phase;
            meta.total = total;
            meta.file = None;
            self.shared.done.store(0, Ordering::SeqCst);
        }
        self.shared.mark_dirty();
    }
}

impl std::fmt::Debug for ProgressSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressSink").finish_non_exhaustive()
    }
}

/// The polling side. Call [`ProgressPump::register_waker`] with the polling task's waker, then
/// [`ProgressPump::pump`], on every poll of the operation.
pub struct ProgressPump {
    shared: Arc<Shared>,
    last: Option<Progress>,
}

impl ProgressPump {
    /// Stores the waker a worker's next update wakes (on the clean-to-dirty transition only).
    pub fn register_waker(&self, waker: &Waker) {
        let mut held = lock(&self.shared.waker);
        match &mut *held {
            Some(w) => w.clone_from(waker),
            None => *held = Some(waker.clone()),
        }
    }

    /// Calls `callback` with the last snapshot of each phase that ended since the last pump
    /// (oldest first), then with the latest snapshot; a snapshot equal to the one delivered just
    /// before it is skipped. Returns whether it was called.
    pub fn pump<F: FnMut(&Progress) + ?Sized>(&mut self, callback: &mut F) -> bool {
        if !self.shared.dirty.swap(false, Ordering::SeqCst) {
            return false;
        }
        let (ended, snapshot) = {
            let mut meta = lock(&self.shared.meta);
            let ended = std::mem::take(&mut meta.ended);
            (ended, self.shared.snapshot_of(&meta))
        };
        let mut called = false;
        for event in ended.into_iter().chain(std::iter::once(snapshot)) {
            if self.last.as_ref() == Some(&event) {
                continue;
            }
            callback(&event);
            self.last = Some(event);
            called = true;
        }
        called
    }
}

impl std::fmt::Debug for ProgressPump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressPump").finish_non_exhaustive()
    }
}
