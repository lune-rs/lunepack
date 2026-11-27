//! The object-store adapters (P-D1, P-D2): `S3Store` against a fake S3 that checks every
//! request's SigV4 signature, and `DirStore` over a temporary directory. Both run the core's store
//! contract suite, then their own cases.

use std::collections::hash_map::RandomState;
use std::fs;
use std::hash::{BuildHasher, Hasher as _};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::Arc;

use lunepack_core::{
    HashState, Hasher, ObjectStore, Sha256Digest, StoreError, StoreKey, StoreMethod,
    StoreTransportKind,
};
use lunepack_http::{Credentials, DirStore, S3ConfigError, S3Store};
use lunepack_testkit::{FakeClock, FakeS3Config, FakeS3Server, S3Fault, run_store_suite};
use sha2::{Digest, Sha256};

const BUCKET: &str = "lunepack-test";
const REGION: &str = "auto";
const PREFIX: &str = "apps/demo";
/// 2023-11-14T22:13:20Z.
const NOW: u64 = 1_700_000_000;

/// A SHA-256 [`Hasher`] over `sha2` (the testkit's own hasher is deliberately not SHA-256).
struct RealSha256;

struct State(Sha256);

impl HashState for State {
    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }

    fn finalize(self: Box<Self>) -> Sha256Digest {
        Sha256Digest::from_bytes(self.0.finalize().into())
    }
}

impl Hasher for RealSha256 {
    fn sha256_start(&self) -> Box<dyn HashState> {
        Box::new(State(Sha256::new()))
    }
}

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// A credential made at run time (none is committed).
fn fresh(label: &str) -> String {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(u64::from(std::process::id()));
    format!("{label}-{:016x}", hasher.finish())
}

struct Fixture {
    server: FakeS3Server,
    clock: FakeClock,
    access: String,
    secret: String,
}

impl Fixture {
    fn new() -> Fixture {
        let clock = FakeClock::new(NOW);
        let access = fresh("AKID");
        let secret = fresh("secret");
        let server = FakeS3Server::start(FakeS3Config::new(
            &[BUCKET, "other-bucket"],
            REGION,
            &access,
            &secret,
            Arc::new(clock.clone()),
        ))
        .expect("fake S3");
        Fixture {
            server,
            clock,
            access,
            secret,
        }
    }

    fn store_with(&self, bucket: &str, region: &str, secret: &str, clock: &FakeClock) -> S3Store {
        S3Store::new(
            &self.server.endpoint(),
            bucket,
            region,
            Credentials::new(self.access.clone(), secret),
            Arc::new(clock.clone()),
        )
        .expect("store")
    }

    fn store(&self) -> S3Store {
        self.store_with(BUCKET, REGION, &self.secret, &self.clock)
    }

    fn leaks(&self, text: &str) -> bool {
        leaks(text, &[&self.access, &self.secret])
    }
}

fn leaks(text: &str, secrets: &[&str]) -> bool {
    secrets.iter().any(|s| text.contains(s))
}

fn key(rel: &str) -> StoreKey {
    StoreKey::new(PREFIX, rel).expect("key")
}

fn put(store: &dyn ObjectStore, k: &StoreKey, body: &[u8]) -> Result<(), StoreError> {
    store.put(
        k,
        &mut &body[..],
        body.len() as u64,
        sha(body),
        "application/json",
    )
}

// --- S3Store ---------------------------------------------------------------------------------

#[test]
fn s3_store_passes_the_store_contract_suite() {
    let f = Fixture::new();
    run_store_suite(&f.store(), &RealSha256, PREFIX);
    // Every request the suite made was signed correctly, or the fake would have refused it.
    let requests = f.server.requests();
    assert!(requests.len() > 30, "{} requests", requests.len());
    assert!(
        requests.iter().all(|r| r.error_code.is_none()
            || r.error_code.as_deref() == Some("NoSuchKey")
            || r.status == 0),
        "unexpected refusals: {:?}",
        requests
            .iter()
            .filter(|r| r.error_code.is_some())
            .map(|r| (&r.method, &r.key, &r.error_code))
            .collect::<Vec<_>>()
    );
}

#[test]
fn dir_store_passes_the_store_contract_suite() {
    let dir = tempfile::tempdir().expect("tempdir");
    run_store_suite(&DirStore::new(dir.path()), &RealSha256, PREFIX);
    // The suite cleans up after itself: no temporary file is left.
    let mut leftovers = Vec::new();
    collect_files(dir.path(), &mut leftovers);
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
}

fn collect_files(dir: &std::path::Path, out: &mut Vec<String>) {
    for entry in fs::read_dir(dir).expect("read_dir") {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path.display().to_string());
        }
    }
}

#[test]
fn keys_with_awkward_characters_round_trip_and_are_signed_encoded_once() {
    let f = Fixture::new();
    let store = f.store();
    for rel in [
        "1.0.0+build.5/pack.bin",
        "1.0.0-rc.1/a~b_c.d",
        "v/100%/x",
        "v/a?b#c&d=e",
        "v/$dollar@at,comma;semi",
        "v/(paren)[bracket]{brace}'quote\"dq",
        "v/a%2Bb",
        "v/plus+plus",
    ] {
        let k = key(rel);
        let body = format!("body of {rel}").into_bytes();
        put(&store, &k, &body).unwrap_or_else(|e| panic!("put {rel}: {e}"));
        assert_eq!(
            f.server.object(BUCKET, k.as_str()),
            Some(body.clone()),
            "the fake stored it under the decoded key {rel}"
        );
        assert_eq!(store.get(&k, 1 << 20).expect("get"), Some(body), "{rel}");
        store.delete(&k).expect("delete");
        assert_eq!(f.server.object(BUCKET, k.as_str()), None, "{rel}");
    }
    assert!(
        f.server
            .requests()
            .iter()
            .all(|r| r.error_code.is_none() || r.error_code.as_deref() == Some("NoSuchKey")),
        "every signature was accepted"
    );
    // The `+` went on the wire as %2B, in the path the signature covers.
    assert!(
        f.server
            .requests()
            .iter()
            .any(|r| r.target.contains("1.0.0%2Bbuild.5")),
        "{:?}",
        f.server
            .requests()
            .iter()
            .map(|r| &r.target)
            .collect::<Vec<_>>()
    );
}

#[test]
fn put_sends_the_body_with_its_length_hash_and_content_type() {
    let f = Fixture::new();
    let store = f.store();
    let k = key("1.0.0/feed.json");
    put(&store, &k, b"{\"a\":1}").expect("put");
    assert_eq!(
        f.server.object(BUCKET, k.as_str()).as_deref(),
        Some(&b"{\"a\":1}"[..])
    );
    assert_eq!(
        f.server.content_type(BUCKET, k.as_str()).as_deref(),
        Some("application/json")
    );
    let request = f.server.requests().pop().expect("a request");
    assert_eq!(request.method, "PUT");
    assert_eq!(request.status, 200);
    assert_eq!(request.body_len, 7);
    assert_eq!(request.amz_date.as_deref(), Some("20231114T221320Z"));
    let auth = request.authorization.expect("authorization");
    assert!(
        auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date,"),
        "{}",
        auth.replace(&f.access, "<key>")
    );
    assert!(auth.contains("/20231114/auto/s3/aws4_request"));
}

#[test]
fn a_large_upload_streams_from_a_file() {
    let f = Fixture::new();
    let store = f.store();
    let body: Vec<u8> = (0..5_000_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("pack.bin");
    fs::write(&path, &body).expect("write");
    let k = key("2.0.0/pack.bin");
    let mut file = fs::File::open(&path).expect("open");
    store
        .put(
            &k,
            &mut file,
            body.len() as u64,
            sha(&body),
            "application/octet-stream",
        )
        .expect("put");
    assert_eq!(f.server.object(BUCKET, k.as_str()), Some(body.clone()));
    assert_eq!(store.get(&k, 5_000_000).expect("get"), Some(body));
}

/// A reader that yields some bytes, then fails.
struct Failing {
    left: usize,
}

impl Read for Failing {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            return Err(io::Error::other("disk went away"));
        }
        let n = self.left.min(buf.len()).min(1000);
        buf[..n].fill(7);
        self.left -= n;
        Ok(n)
    }
}

#[test]
fn a_failing_reader_is_an_io_error_and_stores_nothing() {
    let f = Fixture::new();
    let store = f.store();
    let k = key("1.0.0/pack.bin");
    f.server.seed(BUCKET, k.as_str(), b"old");
    match store.put(&k, &mut Failing { left: 50_000 }, 100_000, [0; 32], "x/y") {
        Err(StoreError::Io { key, .. }) => assert_eq!(key, k),
        other => panic!("expected Io, got {other:?}"),
    }
    assert_eq!(
        f.server.object(BUCKET, k.as_str()).as_deref(),
        Some(&b"old"[..])
    );
}

#[test]
fn a_wrong_body_is_a_mismatch_and_never_completes_the_request() {
    let f = Fixture::new();
    let store = f.store();
    let k = key("1.0.0/pack.bin");
    let body = vec![9u8; 200_000];
    f.server.seed(BUCKET, k.as_str(), b"old");
    // Another hash.
    let mut wrong = sha(&body);
    wrong[31] ^= 1;
    assert!(matches!(
        store.put(&k, &mut &body[..], body.len() as u64, wrong, "x/y"),
        Err(StoreError::Mismatch { .. })
    ));
    // Longer than declared, and shorter.
    assert!(matches!(
        store.put(&k, &mut &body[..], 100, sha(&body[..100]), "x/y"),
        Err(StoreError::Mismatch { .. })
    ));
    assert!(matches!(
        store.put(&k, &mut &body[..], 300_000, sha(&body), "x/y"),
        Err(StoreError::Mismatch { .. })
    ));
    assert_eq!(
        f.server.object(BUCKET, k.as_str()).as_deref(),
        Some(&b"old"[..])
    );
    // The cut-off requests are in the fake's log with no answer, never with a stored body.
    let puts: Vec<_> = f
        .server
        .requests()
        .into_iter()
        .filter(|r| r.method == "PUT")
        .collect();
    assert!(
        puts.iter().all(|r| r.status == 0 || r.status >= 400),
        "{puts:?}"
    );
}

// --- statuses ----------------------------------------------------------------------------------

#[test]
fn statuses_map_to_results() {
    let f = Fixture::new();
    let store = f.store();
    let k = key("1.0.0/manifest.json");
    // 404 on get is None, not an error.
    assert_eq!(store.get(&k, 100).expect("get"), None);
    // 200 / 204 are success.
    put(&store, &k, b"{}").expect("put 200");
    store.delete(&k).expect("delete 204");
    // Other statuses are errors naming the method, the key and the status.
    for (status, method) in [
        (500u16, "GET"),
        (503, "PUT"),
        (403, "DELETE"),
        (307, "GET"),
        (301, "PUT"),
    ] {
        f.server
            .inject(method, Some(k.as_str()), 0, S3Fault::Status(status));
        let result = match method {
            "GET" => store.get(&k, 100).map(|_| ()),
            "PUT" => put(&store, &k, b"{}"),
            _ => store.delete(&k),
        };
        match result {
            Err(StoreError::Status {
                method: m,
                key,
                status: s,
            }) => {
                assert_eq!(m.describe(), method);
                assert_eq!(key, k);
                assert_eq!(s, status);
            }
            other => panic!("{method} {status}: {other:?}"),
        }
        f.server.clear_faults();
    }
    // A redirect was not followed: the fake saw each request once.
    assert!(
        f.server
            .requests()
            .iter()
            .filter(|r| r.status == 307)
            .count()
            == 1
    );
}

#[test]
fn a_status_after_the_write_leaves_the_object_stored() {
    let f = Fixture::new();
    let store = f.store();
    let k = key("1.0.0/a.bin");
    f.server.inject(
        "PUT",
        Some(k.as_str()),
        0,
        S3Fault::StatusAfterApplying(500),
    );
    assert!(matches!(
        put(&store, &k, b"kept"),
        Err(StoreError::Status { status: 500, .. })
    ));
    assert_eq!(
        f.server.object(BUCKET, k.as_str()).as_deref(),
        Some(&b"kept"[..])
    );
}

#[test]
fn a_hangup_and_a_closed_port_are_transport_errors() {
    let f = Fixture::new();
    let store = f.store();
    let k = key("1.0.0/a.bin");
    f.server.inject("GET", None, 0, S3Fault::Hangup);
    match store.get(&k, 10) {
        Err(StoreError::Transport { method, key, .. }) => {
            assert_eq!(method, StoreMethod::Get);
            assert_eq!(key, k);
        }
        other => panic!("{other:?}"),
    }
    f.server.clear_faults();

    // Nothing listens on the port any more.
    let port = {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        listener.local_addr().expect("addr").port()
    };
    let dead = S3Store::new(
        &format!("http://127.0.0.1:{port}"),
        BUCKET,
        REGION,
        Credentials::new(f.access.clone(), f.secret.clone()),
        Arc::new(f.clock.clone()),
    )
    .expect("store");
    match dead.delete(&k) {
        Err(StoreError::Transport { kind, .. }) => assert_eq!(kind, StoreTransportKind::Connect),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_get_over_the_limit_is_too_large_by_the_declared_length() {
    let f = Fixture::new();
    let store = f.store();
    let k = key("1.0.0/big.bin");
    f.server.seed(BUCKET, k.as_str(), &vec![1u8; 10_000]);
    assert!(matches!(
        store.get(&k, 9_999),
        Err(StoreError::TooLarge { limit: 9_999, .. })
    ));
    assert_eq!(
        store.get(&k, 10_000).expect("get").map(|b| b.len()),
        Some(10_000)
    );
}

// --- the signature is really checked -----------------------------------------------------------

#[test]
fn the_fake_refuses_a_wrong_secret_scope_bucket_and_clock() {
    let f = Fixture::new();
    let k = key("1.0.0/a.bin");
    let code_of = |store: &S3Store| -> (u16, String) {
        f.server.clear_requests();
        let result = store.get(&k, 10);
        let status = match result {
            Err(StoreError::Status { status, .. }) => status,
            other => panic!("expected a status error, got {other:?}"),
        };
        (
            status,
            f.server.requests()[0]
                .error_code
                .clone()
                .unwrap_or_default(),
        )
    };

    // A secret that is not the server's.
    let wrong_secret = f.store_with(BUCKET, REGION, "not-the-secret", &f.clock);
    assert_eq!(
        code_of(&wrong_secret),
        (403, "SignatureDoesNotMatch".to_owned())
    );
    // Another region in the scope.
    let wrong_region = f.store_with(BUCKET, "us-east-1", &f.secret, &f.clock);
    assert_eq!(
        code_of(&wrong_region),
        (400, "AuthorizationHeaderMalformed".to_owned())
    );
    // A bucket the server does not hold.
    let wrong_bucket = f.store_with("unknown-bucket", REGION, &f.secret, &f.clock);
    assert_eq!(code_of(&wrong_bucket), (404, "NoSuchBucket".to_owned()));
    // Another bucket it does hold works (signed with the same credentials).
    let other = f.store_with("other-bucket", REGION, &f.secret, &f.clock);
    assert_eq!(other.get(&k, 10).expect("get"), None);

    // A clock more than 15 minutes off, either way.
    let behind = FakeClock::new(NOW - 16 * 60);
    assert_eq!(
        code_of(&f.store_with(BUCKET, REGION, &f.secret, &behind)),
        (403, "RequestTimeTooSkewed".to_owned())
    );
    let ahead = FakeClock::new(NOW + 16 * 60);
    assert_eq!(
        code_of(&f.store_with(BUCKET, REGION, &f.secret, &ahead)),
        (403, "RequestTimeTooSkewed".to_owned())
    );
    // Within the window it is accepted.
    let near = FakeClock::new(NOW - 14 * 60);
    assert_eq!(
        f.store_with(BUCKET, REGION, &f.secret, &near)
            .get(&k, 10)
            .expect("get"),
        None
    );
}

#[test]
fn the_signing_time_is_the_clock_given_to_the_store() {
    // Both sides on a clock far in the past: the system clock is nowhere in the exchange.
    let clock = FakeClock::new(1_000_000_000);
    let access = fresh("AKID");
    let secret = fresh("secret");
    let server = FakeS3Server::start(FakeS3Config::new(
        &[BUCKET],
        REGION,
        &access,
        &secret,
        Arc::new(clock.clone()),
    ))
    .expect("fake S3");
    let store = S3Store::new(
        &server.endpoint(),
        BUCKET,
        REGION,
        Credentials::new(access, secret),
        Arc::new(clock.clone()),
    )
    .expect("store");
    let k = key("1.0.0/a.bin");
    put(&store, &k, b"x").expect("put");
    assert_eq!(
        server.requests()[0].amz_date.as_deref(),
        Some("20010909T014640Z")
    );
    // Time moves on between requests.
    clock.advance_secs(3600);
    assert_eq!(store.get(&k, 10).expect("get").as_deref(), Some(&b"x"[..]));
    assert_eq!(
        server.requests()[1].amz_date.as_deref(),
        Some("20010909T024640Z")
    );
}

/// Sends raw bytes to the fake and returns the status line's code.
fn raw_status(f: &Fixture, request: &str) -> u16 {
    let mut stream = TcpStream::connect(f.server.addr()).expect("connect");
    stream.write_all(request.as_bytes()).expect("write");
    let mut reply = String::new();
    let _ = stream.read_to_string(&mut reply);
    reply
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

#[test]
fn the_fake_is_not_an_accept_everything_server() {
    let f = Fixture::new();
    let host = f.server.addr();
    let path = format!("/{BUCKET}/{PREFIX}/1.0.0/a.bin");
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    // No credentials at all.
    assert_eq!(
        raw_status(&f, &format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n")),
        403
    );
    // A well-formed header with a made-up signature.
    let forged = format!(
        "AWS4-HMAC-SHA256 Credential={}/20231114/{REGION}/s3/aws4_request, \
         SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={}",
        f.access,
        "0".repeat(64)
    );
    assert_eq!(
        raw_status(
            &f,
            &format!(
                "GET {path} HTTP/1.1\r\nHost: {host}\r\nx-amz-content-sha256: {empty}\r\n\
                 x-amz-date: 20231114T221320Z\r\nAuthorization: {forged}\r\n\r\n"
            )
        ),
        403
    );
    assert_eq!(
        f.server
            .requests()
            .last()
            .and_then(|r| r.error_code.clone())
            .as_deref(),
        Some("SignatureDoesNotMatch")
    );
}

#[test]
fn a_403_on_a_get_is_an_error_with_the_listbucket_hint_never_an_absent_key() {
    let f = Fixture::new();
    let wrong = f.store_with(BUCKET, REGION, "not-the-secret", &f.clock);
    let k = key("1.0.0/missing.bin");
    let e = wrong.get(&k, 1).expect_err("403 is not absent");
    assert!(matches!(
        e,
        StoreError::Status {
            status: 403,
            method: StoreMethod::Get,
            ..
        }
    ));
    let text = e.to_string();
    assert!(
        text.contains("GET")
            && text.contains("1.0.0/missing.bin")
            && text.contains("403")
            && text.contains("s3:ListBucket"),
        "{text}"
    );
    assert!(!f.leaks(&text));
}

// --- secrets never reach a message ---------------------------------------------------------------

#[test]
fn no_error_or_debug_text_holds_a_credential() {
    let f = Fixture::new();
    // The control: the check does catch a text that holds one.
    assert!(f.leaks(&format!("failed with {}", f.secret)));
    assert!(f.leaks(&format!("key {} was refused", f.access)));
    assert!(!f.leaks("store: GET apps/demo/1.0.0/a.bin answered status 403"));

    let store = f.store();
    let k = key("1.0.0/a.bin");
    let mut texts: Vec<String> = Vec::new();
    let mut note = |e: &StoreError| {
        texts.push(e.to_string());
        texts.push(format!("{e:?}"));
        texts.push(format!("{e:#?}"));
    };

    // A refused signature, a status, a hangup, a closed port, a mismatch, a failed reader.
    let wrong = f.store_with(BUCKET, REGION, "not-the-secret", &f.clock);
    note(&wrong.get(&k, 1).expect_err("403"));
    f.server.inject("PUT", None, 0, S3Fault::Status(500));
    note(&put(&store, &k, b"x").expect_err("500"));
    f.server.clear_faults();
    f.server.inject("GET", None, 0, S3Fault::Hangup);
    note(&store.get(&k, 1).expect_err("hangup"));
    f.server.clear_faults();
    note(
        &store
            .put(&k, &mut &b"abc"[..], 3, [0; 32], "x/y")
            .expect_err("mismatch"),
    );
    note(
        &store
            .put(&k, &mut Failing { left: 10 }, 20, [0; 32], "x/y")
            .expect_err("reader"),
    );
    let port = {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        l.local_addr().expect("addr").port()
    };
    let dead = S3Store::new(
        &format!("http://127.0.0.1:{port}"),
        BUCKET,
        REGION,
        Credentials::new(f.access.clone(), f.secret.clone()),
        Arc::new(f.clock.clone()),
    )
    .expect("store");
    note(&dead.get(&k, 1).expect_err("closed port"));

    // The adapter's own Debug, the credentials' Debug, and the construction errors.
    texts.push(format!("{store:?}"));
    texts.push(format!("{store:#?}"));
    texts.push(format!(
        "{:?}",
        Credentials::new(f.access.clone(), f.secret.clone())
    ));
    for bad in [
        S3Store::new(
            &format!("http://user:{}@127.0.0.1", f.secret),
            BUCKET,
            REGION,
            Credentials::new(f.access.clone(), f.secret.clone()),
            Arc::new(f.clock.clone()),
        ),
        S3Store::new(
            "http://127.0.0.1",
            BUCKET,
            REGION,
            Credentials::new(format!("{} ", f.access), f.secret.clone()),
            Arc::new(f.clock.clone()),
        ),
    ] {
        let e = bad.expect_err("refused");
        texts.push(e.to_string());
        texts.push(format!("{e:?}"));
    }

    assert!(texts.len() > 20);
    for text in &texts {
        assert!(!f.leaks(text), "a credential reached: {text}");
    }
}

// --- construction ------------------------------------------------------------------------------

fn build(endpoint: &str, bucket: &str, region: &str) -> Result<S3Store, S3ConfigError> {
    S3Store::new(
        endpoint,
        bucket,
        region,
        Credentials::new("AKIDTEST", "secret-test"),
        Arc::new(FakeClock::new(NOW)),
    )
}

#[test]
fn endpoints_are_https_or_loopback_http() {
    assert!(build("https://s3.example.com", BUCKET, REGION).is_ok());
    assert!(build("https://s3.example.com:9000/", BUCKET, REGION).is_ok());
    assert!(build("http://127.0.0.1:9000", BUCKET, REGION).is_ok());
    assert!(build("http://127.1.2.3", BUCKET, REGION).is_ok());
    assert!(build("http://[::1]:9000", BUCKET, REGION).is_ok());
    assert!(build("http://localhost:9000", BUCKET, REGION).is_ok());
    for insecure in [
        "http://example.com",
        "http://10.0.0.1:9000",
        "http://203.0.113.5",
        "http://[2001:db8::1]",
        "http://localhost.example.com",
    ] {
        assert_eq!(
            build(insecure, BUCKET, REGION).expect_err(insecure),
            S3ConfigError::InsecureEndpoint,
            "{insecure}"
        );
    }
    for form in [
        "https://user@s3.example.com",
        "https://user:pw@s3.example.com",
        "https://s3.example.com/path",
        "https://s3.example.com/?q=1",
        "https://s3.example.com/#frag",
    ] {
        assert_eq!(
            build(form, BUCKET, REGION).expect_err(form),
            S3ConfigError::EndpointForm,
            "{form}"
        );
    }
    for bad in ["ftp://s3.example.com", "s3.example.com", "file:///tmp", ""] {
        assert!(build(bad, BUCKET, REGION).is_err(), "{bad:?}");
    }
}

#[test]
fn bucket_region_and_credentials_are_checked() {
    let ep = "https://s3.example.com";
    for bad in [
        "",
        "ab",
        "UPPER",
        "has_underscore",
        "-lead",
        "trail-",
        "a b c",
        &"a".repeat(64),
        "a/b",
    ] {
        assert_eq!(
            build(ep, bad, REGION).expect_err(bad),
            S3ConfigError::BadBucket,
            "{bad:?}"
        );
    }
    assert!(build(ep, "my.bucket-1", REGION).is_ok());
    for bad in ["", "US-EAST", "a b", "a/b", &"a".repeat(33)] {
        assert_eq!(
            build(ep, BUCKET, bad).expect_err(bad),
            S3ConfigError::BadRegion,
            "{bad:?}"
        );
    }
    assert!(build(ep, BUCKET, "us-east-1").is_ok());
    for (id, secret) in [
        ("", "s"),
        ("a", ""),
        ("a b", "s"),
        ("a/b", "s"),
        ("a,b", "s"),
        ("a", "s\n"),
    ] {
        let result = S3Store::new(
            ep,
            BUCKET,
            REGION,
            Credentials::new(id, secret),
            Arc::new(FakeClock::new(NOW)),
        );
        assert_eq!(
            result.expect_err("bad credentials"),
            S3ConfigError::BadCredentials
        );
    }
}

#[test]
fn r2_builds_its_endpoint_from_the_account_id() {
    let clock = || Arc::new(FakeClock::new(NOW));
    let id = "0123456789abcdef0123456789abcdef";
    let store = S3Store::r2(
        id,
        BUCKET,
        Credentials::new("AKIDTEST", "secret-test"),
        clock(),
    )
    .expect("r2");
    let shown = format!("{store:?}");
    assert!(
        shown.contains(&format!("https://{id}.r2.cloudflarestorage.com")),
        "{shown}"
    );
    assert!(shown.contains("\"auto\""), "{shown}");
    for bad in [
        "0123456789ABCDEF0123456789ABCDEF",
        "0123456789abcdef0123456789abcde",
        "0123456789abcdef0123456789abcdef0",
        "0123456789abcdef0123456789abcdeg",
        "evil.example.com/0123456789abcdef",
        "",
    ] {
        let result = S3Store::r2(
            bad,
            BUCKET,
            Credentials::new("AKIDTEST", "secret-test"),
            clock(),
        );
        assert_eq!(
            result.expect_err(bad),
            S3ConfigError::BadAccountId,
            "{bad:?}"
        );
    }
}

// --- DirStore ----------------------------------------------------------------------------------

#[test]
fn dir_store_refuses_a_key_that_differs_only_by_case() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = DirStore::new(dir.path());
    let lower = key("1.0.0/manifest.json");
    let upper = key("1.0.0/MANIFEST.json");
    let upper_dir = key("1.0.0X/a");
    put(&store, &lower, b"lower").expect("put");
    // put and get of the other spelling are refused, whether or not the file system folds case.
    assert!(matches!(
        put(&store, &upper, b"upper"),
        Err(StoreError::Io { .. })
    ));
    assert!(matches!(store.get(&upper, 100), Err(StoreError::Io { .. })));
    assert!(matches!(store.delete(&upper), Err(StoreError::Io { .. })));
    // A directory on the way, too.
    let folded_dir = key("1.0.0/manifest.json/x");
    assert!(put(&store, &folded_dir, b"x").is_err());
    let other_case_dir = StoreKey::new(PREFIX, "1.0.0/Manifest.json/x").expect("key");
    assert!(put(&store, &other_case_dir, b"x").is_err());
    let _ = upper_dir;
    // The first object is untouched, and no second entry appeared.
    assert_eq!(
        store.get(&lower, 100).expect("get").as_deref(),
        Some(&b"lower"[..])
    );
    let entries: Vec<String> = fs::read_dir(dir.path().join("apps/demo/1.0.0"))
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, ["manifest.json"]);
    // The exact spelling still works, and a different name is fine.
    put(&store, &lower, b"again").expect("overwrite");
    put(&store, &key("1.0.0/other.json"), b"o").expect("other");
}

#[test]
fn dir_store_keeps_keys_apart_from_the_file_system() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = DirStore::new(dir.path());
    // Names a Windows file system would read as something else are refused everywhere.
    for rel in [
        "1.0.0/con",
        "1.0.0/NUL.txt",
        "1.0.0/a:b",
        "1.0.0/a?b",
        "1.0.0/a*b",
        "1.0.0/trailing.",
        "1.0.0/a\"b",
        "1.0.0/a<b",
        "1.0.0/a|b",
        "1.0.0/com1.json",
    ] {
        assert!(
            matches!(put(&store, &key(rel), b"x"), Err(StoreError::Io { .. })),
            "{rel}"
        );
        assert!(
            matches!(store.get(&key(rel), 10), Err(StoreError::Io { .. })),
            "{rel}"
        );
    }
    // `+` and friends are fine.
    put(&store, &key("1.0.0+b1/pack.bin"), b"x").expect("plus");
    // A file where a directory is needed, and a directory where a file is.
    put(&store, &key("v/file"), b"x").expect("file");
    assert!(matches!(
        put(&store, &key("v/file/inner"), b"y"),
        Err(StoreError::Io { .. })
    ));
    assert_eq!(store.get(&key("v/file/inner"), 10).expect("get"), None);
    put(&store, &key("w/dir/inner"), b"y").expect("inner");
    assert!(matches!(
        put(&store, &key("w/dir"), b"z"),
        Err(StoreError::Io { .. })
    ));
    assert_eq!(store.get(&key("w/dir"), 10).expect("get"), None);
    store
        .delete(&key("w/dir"))
        .expect("delete of a directory key is a no-op");
    assert_eq!(
        store.get(&key("w/dir/inner"), 10).expect("get").as_deref(),
        Some(&b"y"[..])
    );
    // Deleting the last object removes the empty directories it leaves, up to the root.
    store.delete(&key("w/dir/inner")).expect("delete");
    assert!(!dir.path().join("apps/demo/w").exists());
    assert!(dir.path().exists());
}

#[test]
fn dir_store_refused_and_failed_puts_leave_no_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = DirStore::new(dir.path());
    let k = key("1.0.0/pack.bin");
    put(&store, &k, b"old").expect("put");
    assert!(matches!(
        store.put(&k, &mut &b"new body"[..], 8, [1; 32], "x/y"),
        Err(StoreError::Mismatch { .. })
    ));
    assert!(matches!(
        store.put(&k, &mut Failing { left: 5000 }, 9000, [1; 32], "x/y"),
        Err(StoreError::Io { .. })
    ));
    assert_eq!(
        store.get(&k, 100).expect("get").as_deref(),
        Some(&b"old"[..])
    );
    let entries: Vec<String> = fs::read_dir(dir.path().join("apps/demo/1.0.0"))
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, ["pack.bin"], "no temporary file is left");
}

#[cfg(unix)]
#[test]
fn dir_store_does_not_follow_a_symlink() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside");
    fs::write(outside.path().join("secret.txt"), b"outside").expect("write");
    let store = DirStore::new(dir.path());
    put(&store, &key("1.0.0/a.bin"), b"x").expect("put");
    // A link to a file elsewhere, and a link to a directory elsewhere.
    std::os::unix::fs::symlink(
        outside.path().join("secret.txt"),
        dir.path().join("apps/demo/1.0.0/link.bin"),
    )
    .expect("symlink");
    std::os::unix::fs::symlink(outside.path(), dir.path().join("apps/demo/linked"))
        .expect("symlink");
    assert!(matches!(
        store.get(&key("1.0.0/link.bin"), 100),
        Err(StoreError::Io { .. })
    ));
    assert!(matches!(
        put(&store, &key("1.0.0/link.bin"), b"y"),
        Err(StoreError::Io { .. })
    ));
    assert!(matches!(
        store.get(&key("linked/secret.txt"), 100),
        Err(StoreError::Io { .. })
    ));
    assert!(matches!(
        put(&store, &key("linked/new.txt"), b"y"),
        Err(StoreError::Io { .. })
    ));
    assert_eq!(
        fs::read(outside.path().join("secret.txt")).expect("read"),
        b"outside"
    );
    assert!(!outside.path().join("new.txt").exists());
}
