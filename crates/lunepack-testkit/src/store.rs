//! An in-memory [`ObjectStore`] with failure injection, and the contract suite every store runs.
//!
//! [`MemStore`] holds objects in a map, checks every `put` against its declared length and SHA-256
//! with the hasher it was given (there is no accept-everything mode), and logs every call in
//! order, so a test can assert what a publisher did and when. A fault is injected by operation and
//! key: it fires on every matching call after the first `after` matching calls have passed.
//!
//! [`run_store_suite`] is what each adapter's `tests/` runs against its real store, under a prefix
//! of its choosing, with the same hasher the store checks bodies with.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lunepack_core::{Hasher, ObjectStore, StoreError, StoreKey, StoreMethod, StoreTransportKind};

/// What an injected fault makes an operation return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreFault {
    /// [`StoreError::Status`] with this status (nothing is stored or removed).
    Status(u16),
    /// [`StoreError::Transport`] of this kind (nothing is stored or removed).
    Transport(StoreTransportKind),
    /// [`StoreError::Io`] (nothing is stored or removed).
    Io,
    /// A `put` that stores its object and then fails with [`StoreError::Status`] `500`, as a
    /// server does when the answer is lost after the write. On other operations it is as
    /// [`StoreFault::Status`] `500`.
    LostAnswer,
}

#[derive(Debug, Clone)]
struct Injection {
    method: StoreMethod,
    key: Option<StoreKey>,
    /// Matching calls still to let through.
    after: usize,
    fault: StoreFault,
}

#[derive(Default)]
struct Inner {
    objects: BTreeMap<StoreKey, Entry>,
    injections: Vec<Injection>,
    calls: Vec<(StoreMethod, StoreKey)>,
}

#[derive(Clone)]
struct Entry {
    body: Vec<u8>,
    content_type: String,
}

/// An in-memory object store. Clone it to share one store between a publisher and a test: the
/// clones see the same objects.
#[derive(Clone)]
pub struct MemStore {
    hasher: Arc<dyn Hasher>,
    inner: Arc<Mutex<Inner>>,
}

impl MemStore {
    /// An empty store that checks bodies with `hasher`.
    pub fn new(hasher: Arc<dyn Hasher>) -> MemStore {
        MemStore {
            hasher,
            inner: Arc::default(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stores `body` at `key` without any check or log entry (test setup).
    pub fn seed(&self, key: &StoreKey, body: &[u8]) {
        self.lock().objects.insert(
            key.clone(),
            Entry {
                body: body.to_vec(),
                content_type: String::new(),
            },
        );
    }

    /// The object at `key`, without a log entry or a fault (test inspection).
    pub fn contents(&self, key: &StoreKey) -> Option<Vec<u8>> {
        self.lock().objects.get(key).map(|e| e.body.clone())
    }

    /// The content type `put` stored with the object at `key`.
    pub fn content_type(&self, key: &StoreKey) -> Option<String> {
        self.lock()
            .objects
            .get(key)
            .map(|entry| entry.content_type.clone())
    }

    /// Every key in the store, sorted.
    pub fn keys(&self) -> Vec<StoreKey> {
        self.lock().objects.keys().cloned().collect()
    }

    /// Every operation attempted so far, in order, faulted ones included.
    pub fn calls(&self) -> Vec<(StoreMethod, StoreKey)> {
        self.lock().calls.clone()
    }

    /// Forgets the log of calls.
    pub fn clear_calls(&self) {
        self.lock().calls.clear();
    }

    /// Makes every `method` call on `key` (any key when `None`) fail with `fault` from now on.
    pub fn inject(&self, method: StoreMethod, key: Option<&StoreKey>, fault: StoreFault) {
        self.inject_after(method, key, 0, fault);
    }

    /// Like [`MemStore::inject`], but the first `after` matching calls go through.
    pub fn inject_after(
        &self,
        method: StoreMethod,
        key: Option<&StoreKey>,
        after: usize,
        fault: StoreFault,
    ) {
        self.lock().injections.push(Injection {
            method,
            key: key.cloned(),
            after,
            fault,
        });
    }

    /// Removes every injected fault.
    pub fn clear_faults(&self) {
        self.lock().injections.clear();
    }

    /// Logs the call and returns the fault that fires on it, if any.
    fn begin(&self, method: StoreMethod, key: &StoreKey) -> Option<StoreFault> {
        let mut inner = self.lock();
        inner.calls.push((method, key.clone()));
        let mut fired = None;
        for injection in &mut inner.injections {
            if injection.method != method || injection.key.as_ref().is_some_and(|k| k != key) {
                continue;
            }
            if injection.after > 0 {
                injection.after -= 1;
            } else if fired.is_none() {
                fired = Some(injection.fault);
            }
        }
        fired
    }
}

fn fault_error(fault: StoreFault, method: StoreMethod, key: &StoreKey) -> StoreError {
    match fault {
        StoreFault::Status(status) => StoreError::Status {
            method,
            key: key.clone(),
            status,
        },
        StoreFault::LostAnswer => StoreError::Status {
            method,
            key: key.clone(),
            status: 500,
        },
        StoreFault::Transport(kind) => StoreError::Transport {
            method,
            key: key.clone(),
            kind,
        },
        StoreFault::Io => StoreError::Io {
            key: key.clone(),
            source: io::Error::other("injected fault"),
        },
    }
}

impl ObjectStore for MemStore {
    fn get(&self, key: &StoreKey, max_len: u64) -> Result<Option<Vec<u8>>, StoreError> {
        if let Some(fault) = self.begin(StoreMethod::Get, key) {
            return Err(fault_error(fault, StoreMethod::Get, key));
        }
        let inner = self.lock();
        match inner.objects.get(key) {
            None => Ok(None),
            Some(entry) if entry.body.len() as u64 > max_len => Err(StoreError::TooLarge {
                key: key.clone(),
                limit: max_len,
            }),
            Some(entry) => Ok(Some(entry.body.clone())),
        }
    }

    fn put(
        &self,
        key: &StoreKey,
        body: &mut dyn Read,
        len: u64,
        sha256: [u8; 32],
        content_type: &str,
    ) -> Result<(), StoreError> {
        let fault = self.begin(StoreMethod::Put, key);
        if let Some(fault) = fault
            && fault != StoreFault::LostAnswer
        {
            return Err(fault_error(fault, StoreMethod::Put, key));
        }
        // One byte past `len` tells a body that is too long from one that is exact.
        let mut bytes = Vec::new();
        body.take(len.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| StoreError::Io {
                key: key.clone(),
                source,
            })?;
        if bytes.len() as u64 != len || self.hasher.sha256(&bytes).as_bytes() != &sha256 {
            return Err(StoreError::Mismatch { key: key.clone() });
        }
        self.lock().objects.insert(
            key.clone(),
            Entry {
                body: bytes,
                content_type: content_type.to_owned(),
            },
        );
        match fault {
            Some(fault) => Err(fault_error(fault, StoreMethod::Put, key)),
            None => Ok(()),
        }
    }

    fn delete(&self, key: &StoreKey) -> Result<(), StoreError> {
        if let Some(fault) = self.begin(StoreMethod::Delete, key) {
            return Err(fault_error(fault, StoreMethod::Delete, key));
        }
        self.lock().objects.remove(key);
        Ok(())
    }
}

/// A reader that yields its bytes one small piece at a time, so a store that assumes one `read`
/// returns everything is caught.
struct Trickle<'a> {
    rest: &'a [u8],
    step: usize,
}

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.rest.len().min(self.step).min(buf.len());
        buf[..n].copy_from_slice(&self.rest[..n]);
        self.rest = &self.rest[n..];
        Ok(n)
    }
}

fn put_ok(store: &dyn ObjectStore, hasher: &dyn Hasher, key: &StoreKey, body: &[u8], ct: &str) {
    let digest = *hasher.sha256(body).as_bytes();
    store
        .put(
            key,
            &mut Trickle {
                rest: body,
                step: 7,
            },
            body.len() as u64,
            digest,
            ct,
        )
        .unwrap_or_else(|e| panic!("put {key} ({} bytes): {e}", body.len()));
}

fn get_ok(store: &dyn ObjectStore, key: &StoreKey) -> Option<Vec<u8>> {
    store
        .get(key, u64::MAX)
        .unwrap_or_else(|e| panic!("get {key}: {e}"))
}

fn is_mismatch(result: Result<(), StoreError>, key: &StoreKey, what: &str) {
    match result {
        Err(StoreError::Mismatch { key: k }) => assert_eq!(&k, key, "{what}: error names the key"),
        other => panic!("{what}: expected Mismatch, got {other:?}"),
    }
}

/// The store contract (`lunepack_core::store`). `hasher` is the SHA-256 the store checks bodies
/// with (a real one for a real store); `prefix` is where the suite may write and delete, and it
/// must hold nothing the suite did not put there.
///
/// It checks: a missing key is `None` for `get` and `Ok` for `delete`; `put` then `get` returns the
/// bytes (empty, one byte, a body bigger than any buffer, read in pieces); `put` overwrites;
/// `delete` removes only its key; `get` past `max_len` is `TooLarge` and at `max_len` is the
/// object; a body shorter or longer than `len`, or with another SHA-256, is `Mismatch` and leaves
/// what was at the key untouched.
pub fn run_store_suite(store: &dyn ObjectStore, hasher: &dyn Hasher, prefix: &str) {
    let key = |rel: &str| StoreKey::new(prefix, rel).expect("suite key");

    // A missing key.
    let missing = key("suite/missing.bin");
    assert_eq!(get_ok(store, &missing), None, "get of a missing key");
    store
        .delete(&missing)
        .expect("delete of a missing key is Ok");

    // put, get, overwrite, delete.
    let a = key("suite/a.json");
    put_ok(store, hasher, &a, b"first", "application/json");
    assert_eq!(get_ok(store, &a).as_deref(), Some(&b"first"[..]));
    put_ok(store, hasher, &a, b"second, longer", "application/json");
    assert_eq!(
        get_ok(store, &a).as_deref(),
        Some(&b"second, longer"[..]),
        "put overwrites"
    );
    put_ok(store, hasher, &a, b"x", "application/json");
    assert_eq!(
        get_ok(store, &a).as_deref(),
        Some(&b"x"[..]),
        "a shorter put replaces a longer object"
    );

    // Empty and large bodies.
    let empty = key("suite/empty");
    put_ok(store, hasher, &empty, b"", "application/octet-stream");
    assert_eq!(
        get_ok(store, &empty).as_deref(),
        Some(&b""[..]),
        "empty object"
    );
    let big: Vec<u8> = (0..300_000u32)
        .map(|i| (i.wrapping_mul(31) >> 3) as u8)
        .collect();
    let big_key = key("suite/1.0.0/big.pack");
    let digest = *hasher.sha256(&big).as_bytes();
    store
        .put(
            &big_key,
            &mut Trickle {
                rest: &big,
                step: 4093,
            },
            big.len() as u64,
            digest,
            "application/octet-stream",
        )
        .expect("put of a large body");
    assert_eq!(
        get_ok(store, &big_key).as_deref(),
        Some(&big[..]),
        "large object"
    );

    // max_len.
    match store.get(&big_key, big.len() as u64 - 1) {
        Err(StoreError::TooLarge { key: k, limit }) => {
            assert_eq!(k, big_key, "TooLarge names the key");
            assert_eq!(limit, big.len() as u64 - 1, "TooLarge names the limit");
        }
        other => panic!("get one byte over max_len: expected TooLarge, got {other:?}"),
    }
    assert_eq!(
        store
            .get(&big_key, big.len() as u64)
            .expect("get at max_len")
            .as_deref(),
        Some(&big[..]),
        "get at exactly max_len"
    );
    match store.get(&a, 0) {
        Err(StoreError::TooLarge { limit: 0, .. }) => {}
        other => panic!("get of 1 byte with max_len 0: expected TooLarge, got {other:?}"),
    }
    assert_eq!(
        store.get(&empty, 0).expect("empty at max_len 0").as_deref(),
        Some(&b""[..])
    );

    // A refused put changes nothing, over an existing object and over no object.
    let body = b"the declared body";
    let good = *hasher.sha256(body).as_bytes();
    let fresh = key("suite/refused.bin");
    for (what, target) in [("new key", &fresh), ("existing key", &a)] {
        let before = get_ok(store, target);
        let shorter = body.len() as u64 - 1;
        is_mismatch(
            store.put(target, &mut &body[..], shorter, good, "text/plain"),
            target,
            &format!("{what}: len shorter than the body"),
        );
        is_mismatch(
            store.put(
                target,
                &mut &body[..],
                body.len() as u64 + 1,
                good,
                "text/plain",
            ),
            target,
            &format!("{what}: len longer than the body"),
        );
        let mut wrong = good;
        wrong[0] ^= 1;
        is_mismatch(
            store.put(
                target,
                &mut &body[..],
                body.len() as u64,
                wrong,
                "text/plain",
            ),
            target,
            &format!("{what}: another SHA-256"),
        );
        is_mismatch(
            store.put(target, &mut &b""[..], 0, good, "text/plain"),
            target,
            &format!("{what}: an empty body with the SHA-256 of another"),
        );
        assert_eq!(
            get_ok(store, target),
            before,
            "{what}: a refused put left the object as it was"
        );
    }

    // delete removes its key only.
    let near = key("suite/a.json.bak");
    put_ok(store, hasher, &near, b"neighbour", "text/plain");
    store.delete(&a).expect("delete");
    assert_eq!(get_ok(store, &a), None, "deleted key");
    assert_eq!(
        get_ok(store, &near).as_deref(),
        Some(&b"neighbour"[..]),
        "a key that shares a prefix with the deleted one"
    );
    store.delete(&a).expect("second delete is Ok");

    // Clean up what the suite made.
    for k in [&empty, &big_key, &near] {
        store.delete(k).expect("cleanup");
    }
    assert_eq!(get_ok(store, &big_key), None, "cleanup removed the key");
}
