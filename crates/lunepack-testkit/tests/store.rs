//! The in-memory object store passes the store contract suite, and the suite catches stores that
//! break the contract.

use std::io::Read;
use std::sync::Arc;

use lunepack_core::{Hasher, ObjectStore, StoreError, StoreKey, StoreMethod, StoreTransportKind};
use lunepack_testkit::{FakeHasher, MemStore, StoreFault, run_store_suite};

const PREFIX: &str = "apps/demo";

fn mem() -> MemStore {
    MemStore::new(Arc::new(FakeHasher))
}

fn key(rel: &str) -> StoreKey {
    StoreKey::new(PREFIX, rel).unwrap()
}

fn put(store: &MemStore, k: &StoreKey, body: &[u8]) -> Result<(), StoreError> {
    let digest = *FakeHasher.sha256(body).as_bytes();
    store.put(k, &mut &body[..], body.len() as u64, digest, "text/plain")
}

#[test]
fn mem_store_passes_the_store_suite() {
    let store = mem();
    run_store_suite(&store, &FakeHasher, PREFIX);
    assert!(store.keys().is_empty(), "the suite cleans up after itself");
}

#[test]
fn mem_store_keeps_the_content_type() {
    let store = mem();
    let k = key("feed.json");
    put(&store, &k, b"{}").unwrap();
    assert_eq!(store.content_type(&k).as_deref(), Some("text/plain"));
    assert_eq!(store.contents(&k).as_deref(), Some(&b"{}"[..]));
}

/// A store that stores whatever it is given: it checks neither length nor SHA-256.
struct Lenient(MemStore);

impl ObjectStore for Lenient {
    fn get(&self, key: &StoreKey, max_len: u64) -> Result<Option<Vec<u8>>, StoreError> {
        self.0.get(key, max_len)
    }
    fn put(
        &self,
        key: &StoreKey,
        body: &mut dyn Read,
        len: u64,
        _sha256: [u8; 32],
        content_type: &str,
    ) -> Result<(), StoreError> {
        let mut bytes = Vec::new();
        body.read_to_end(&mut bytes).unwrap();
        let digest = *FakeHasher.sha256(&bytes).as_bytes();
        let _ = len;
        self.0.put(
            key,
            &mut &bytes[..],
            bytes.len() as u64,
            digest,
            content_type,
        )
    }
    fn delete(&self, key: &StoreKey) -> Result<(), StoreError> {
        self.0.delete(key)
    }
}

#[test]
#[should_panic(expected = "Mismatch")]
fn the_suite_catches_a_store_that_does_not_check_the_body() {
    run_store_suite(&Lenient(mem()), &FakeHasher, PREFIX);
}

/// A store whose delete of a missing key is an error.
struct StrictDelete(MemStore);

impl ObjectStore for StrictDelete {
    fn get(&self, key: &StoreKey, max_len: u64) -> Result<Option<Vec<u8>>, StoreError> {
        self.0.get(key, max_len)
    }
    fn put(
        &self,
        key: &StoreKey,
        body: &mut dyn Read,
        len: u64,
        sha256: [u8; 32],
        content_type: &str,
    ) -> Result<(), StoreError> {
        self.0.put(key, body, len, sha256, content_type)
    }
    fn delete(&self, key: &StoreKey) -> Result<(), StoreError> {
        if self.0.contents(key).is_none() {
            return Err(StoreError::Status {
                method: StoreMethod::Delete,
                key: key.clone(),
                status: 404,
            });
        }
        self.0.delete(key)
    }
}

#[test]
#[should_panic(expected = "delete of a missing key is Ok")]
fn the_suite_catches_a_delete_that_fails_on_a_missing_key() {
    run_store_suite(&StrictDelete(mem()), &FakeHasher, PREFIX);
}

#[test]
fn mem_store_refuses_a_body_for_another_hasher() {
    // The store checks with the hasher it was built with: a digest from another one is refused.
    let store = mem();
    let k = key("x");
    let other = lunepack_testkit::FakeHasher.sha256(b"other");
    let err = store
        .put(&k, &mut &b"body"[..], 4, *other.as_bytes(), "text/plain")
        .unwrap_err();
    assert!(matches!(err, StoreError::Mismatch { .. }), "{err}");
    assert!(store.contents(&k).is_none());
}

#[test]
fn injected_faults_fire_by_operation_and_key() {
    let store = mem();
    let a = key("a");
    let b = key("b");
    store.inject(StoreMethod::Put, Some(&a), StoreFault::Status(503));
    match put(&store, &a, b"1") {
        Err(StoreError::Status {
            method: StoreMethod::Put,
            status: 503,
            key,
        }) => assert_eq!(key, a),
        other => panic!("{other:?}"),
    }
    assert!(store.contents(&a).is_none(), "a faulted put stores nothing");
    put(&store, &b, b"2").expect("another key is not faulted");
    // A get of the faulted key is not faulted (the fault is for put).
    assert_eq!(store.get(&a, 10).unwrap(), None);
    store.clear_faults();
    put(&store, &a, b"1").expect("fault cleared");
}

#[test]
fn injected_faults_can_wait_for_n_calls() {
    let store = mem();
    let a = key("a");
    store.inject_after(
        StoreMethod::Put,
        None,
        2,
        StoreFault::Transport(StoreTransportKind::Timeout),
    );
    put(&store, &a, b"1").unwrap();
    put(&store, &a, b"2").unwrap();
    match put(&store, &a, b"3") {
        Err(StoreError::Transport {
            kind: StoreTransportKind::Timeout,
            ..
        }) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(store.contents(&a).as_deref(), Some(&b"2"[..]));
}

#[test]
fn a_lost_answer_stores_the_object_and_still_fails() {
    let store = mem();
    let a = key("a");
    store.inject(StoreMethod::Put, Some(&a), StoreFault::LostAnswer);
    assert!(matches!(
        put(&store, &a, b"1"),
        Err(StoreError::Status { status: 500, .. })
    ));
    assert_eq!(store.contents(&a).as_deref(), Some(&b"1"[..]));
}

#[test]
fn io_and_delete_faults() {
    let store = mem();
    let a = key("a");
    put(&store, &a, b"1").unwrap();
    store.inject(StoreMethod::Delete, Some(&a), StoreFault::Io);
    let err = store.delete(&a).unwrap_err();
    assert!(matches!(err, StoreError::Io { .. }), "{err}");
    assert_eq!(
        store.contents(&a).as_deref(),
        Some(&b"1"[..]),
        "a faulted delete keeps the object"
    );
    store.inject(StoreMethod::Get, None, StoreFault::Status(500));
    assert!(matches!(
        store.get(&a, 10),
        Err(StoreError::Status {
            method: StoreMethod::Get,
            status: 500,
            ..
        })
    ));
}

#[test]
fn the_call_log_keeps_order_and_faulted_calls() {
    let store = mem();
    let a = key("a");
    let b = key("b");
    store.inject(StoreMethod::Delete, Some(&b), StoreFault::Status(500));
    put(&store, &a, b"1").unwrap();
    store.get(&b, 10).unwrap();
    let _ = store.delete(&b);
    store.delete(&a).unwrap();
    assert_eq!(
        store.calls(),
        vec![
            (StoreMethod::Put, a.clone()),
            (StoreMethod::Get, b.clone()),
            (StoreMethod::Delete, b),
            (StoreMethod::Delete, a),
        ]
    );
    store.clear_calls();
    assert!(store.calls().is_empty());
}

#[test]
fn clones_share_the_objects() {
    let store = mem();
    let other = store.clone();
    put(&store, &key("a"), b"1").unwrap();
    assert_eq!(other.contents(&key("a")).as_deref(), Some(&b"1"[..]));
}
