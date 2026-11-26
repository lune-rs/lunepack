//! A fake S3 server on a loopback socket, for the store adapter's tests: it holds objects in
//! memory, **checks every request's SigV4 signature** with a verifier of its own (a second
//! implementation, written apart from the adapter's and held to the same AWS examples), and can
//! answer chosen statuses or hang up.
//!
//! What it enforces, as a real S3 does and a little stricter:
//!
//! - the credential's access key, region, service and date match the configured ones and the
//!   request's `x-amz-date`; that time is within 15 minutes of the server's own clock;
//! - `host`, `x-amz-content-sha256` and `x-amz-date` are signed, and the signed headers are sorted;
//! - the request path is exactly the canonical SigV4 encoding of the key path (so an unencoded `+`
//!   or lowercase hex is refused), and there is no query;
//! - the signature is right (`403 SignatureDoesNotMatch`), then `x-amz-content-sha256` is the hash
//!   of the body (`400 XAmzContentSHA256Mismatch`); a body shorter than its `Content-Length` (a
//!   client that gave up) stores nothing and is logged with status `0`.
//!
//! The server never reads a secret from the request and never prints one.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use lunepack_core::Clock;
use sha2::{Digest, Sha256};

use crate::http_server::{TICK, is_retry, write_all};

/// How long a client may take to send a whole request.
const REQUEST_DEADLINE: Duration = Duration::from_secs(30);
/// Longest request head accepted.
const MAX_HEAD: usize = 16 * 1024;
/// Largest body accepted.
const MAX_BODY: usize = 64 * 1024 * 1024;
/// How far a request's time may be from the server's clock.
const MAX_SKEW_SECS: u64 = 15 * 60;

/// What the server is: its buckets, region, the one credential it accepts and the clock it judges
/// request times by.
#[derive(Clone)]
pub struct FakeS3Config {
    buckets: Vec<String>,
    region: String,
    access_key: String,
    secret_key: String,
    clock: Arc<dyn Clock>,
}

impl FakeS3Config {
    /// A server with these `buckets` that accepts only this credential, for this region.
    pub fn new(
        buckets: &[&str],
        region: &str,
        access_key: &str,
        secret_key: &str,
        clock: Arc<dyn Clock>,
    ) -> FakeS3Config {
        FakeS3Config {
            buckets: buckets.iter().map(|b| (*b).to_owned()).collect(),
            region: region.to_owned(),
            access_key: access_key.to_owned(),
            secret_key: secret_key.to_owned(),
            clock,
        }
    }
}

impl std::fmt::Debug for FakeS3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeS3Config")
            .field("buckets", &self.buckets)
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

/// What an injected fault does to a request that passed the signature check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3Fault {
    /// Answer this status with an empty body (the operation is not carried out).
    Status(u16),
    /// Carry the operation out, then answer this status (a lost answer).
    StatusAfterApplying(u16),
    /// Close the connection without answering.
    Hangup,
}

/// One request the server saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Request {
    /// `GET`, `PUT`, `DELETE`...
    pub method: String,
    /// The request target as sent.
    pub target: String,
    /// The bucket, once the signature was accepted (empty before).
    pub bucket: String,
    /// The decoded key, once the signature was accepted (empty before).
    pub key: String,
    /// The status answered; `0` when the connection ended with no answer.
    pub status: u16,
    /// The S3 error code of a refusal.
    pub error_code: Option<String>,
    /// The `Authorization` header, as received.
    pub authorization: Option<String>,
    /// The `x-amz-date` header, as received.
    pub amz_date: Option<String>,
    /// Body bytes received.
    pub body_len: usize,
}

#[derive(Clone)]
struct Object {
    body: Vec<u8>,
    content_type: String,
}

#[derive(Clone)]
struct Injection {
    method: String,
    key: Option<String>,
    after: usize,
    fault: S3Fault,
}

#[derive(Default)]
struct State {
    objects: BTreeMap<(String, String), Object>,
    injections: Vec<Injection>,
    requests: Vec<S3Request>,
}

struct Shared {
    config: FakeS3Config,
    state: Mutex<State>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The server; stops on drop.
pub struct FakeS3Server {
    shared: Arc<Shared>,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl FakeS3Server {
    /// Starts serving on `127.0.0.1:0`.
    pub fn start(config: FakeS3Config) -> io::Result<FakeS3Server> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(Shared {
            config,
            state: Mutex::new(State::default()),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let accept = {
            let (shared, stop, connections) = (shared.clone(), stop.clone(), connections.clone());
            thread::Builder::new()
                .name("lunepack-fake-s3-accept".to_owned())
                .spawn(move || accept_loop(&listener, &shared, &stop, &connections))?
        };
        Ok(FakeS3Server {
            shared,
            addr,
            stop,
            accept: Some(accept),
            connections,
        })
    }

    /// `http://127.0.0.1:<port>`.
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The socket address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The object at `bucket`/`key`.
    pub fn object(&self, bucket: &str, key: &str) -> Option<Vec<u8>> {
        self.shared
            .lock()
            .objects
            .get(&(bucket.to_owned(), key.to_owned()))
            .map(|o| o.body.clone())
    }

    /// The content type the object was stored with.
    pub fn content_type(&self, bucket: &str, key: &str) -> Option<String> {
        self.shared
            .lock()
            .objects
            .get(&(bucket.to_owned(), key.to_owned()))
            .map(|o| o.content_type.clone())
    }

    /// Stores an object without a request (test setup).
    pub fn seed(&self, bucket: &str, key: &str, body: &[u8]) {
        self.shared.lock().objects.insert(
            (bucket.to_owned(), key.to_owned()),
            Object {
                body: body.to_vec(),
                content_type: String::new(),
            },
        );
    }

    /// Every key in `bucket`, sorted.
    pub fn keys(&self, bucket: &str) -> Vec<String> {
        self.shared
            .lock()
            .objects
            .keys()
            .filter(|(b, _)| b == bucket)
            .map(|(_, k)| k.clone())
            .collect()
    }

    /// Every request seen so far, in the order they finished.
    pub fn requests(&self) -> Vec<S3Request> {
        self.shared.lock().requests.clone()
    }

    /// Forgets the request log.
    pub fn clear_requests(&self) {
        self.shared.lock().requests.clear();
    }

    /// Makes `method` requests for `key` (any key when `None`; the decoded key) get `fault` once
    /// the first `after` matching requests have gone through.
    pub fn inject(&self, method: &str, key: Option<&str>, after: usize, fault: S3Fault) {
        self.shared.lock().injections.push(Injection {
            method: method.to_owned(),
            key: key.map(str::to_owned),
            after,
            fault,
        });
    }

    /// Removes every injected fault.
    pub fn clear_faults(&self) {
        self.shared.lock().injections.clear();
    }
}

impl Drop for FakeS3Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
        let handles = std::mem::take(
            &mut *self
                .connections
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        for handle in handles {
            let _ = handle.join();
        }
    }
}

fn accept_loop(
    listener: &TcpListener,
    shared: &Arc<Shared>,
    stop: &Arc<AtomicBool>,
    connections: &Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    for incoming in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = incoming else { continue };
        let (shared, stop) = (shared.clone(), stop.clone());
        let Ok(handle) = thread::Builder::new()
            .name("lunepack-fake-s3-conn".to_owned())
            .spawn(move || handle_connection(stream, &shared, &stop))
        else {
            continue;
        };
        let mut held = connections.lock().unwrap_or_else(PoisonError::into_inner);
        held.retain(|h| !h.is_finished());
        held.push(handle);
    }
}

/// A request as received.
struct Received {
    method: String,
    target: String,
    /// Lowercase names, trimmed values.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Received {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

enum ReadOutcome {
    Complete(Received),
    /// The head was fine but the body was cut off (the client gave up).
    CutOff(Received),
    /// A request the fake does not accept (answer this status).
    Refused(Received, u16, &'static str),
    /// Nothing usable arrived.
    Nothing,
}

fn read_request(stream: &mut TcpStream, stop: &AtomicBool) -> ReadOutcome {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let mut data: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let head_end = loop {
        if stop.load(Ordering::SeqCst) || Instant::now() > deadline {
            return ReadOutcome::Nothing;
        }
        if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        if data.len() > MAX_HEAD {
            return ReadOutcome::Nothing;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return ReadOutcome::Nothing,
            Ok(n) => data.extend_from_slice(&chunk[..n]),
            Err(e) if is_retry(e.kind()) => {}
            Err(_) => return ReadOutcome::Nothing,
        }
    };
    let text = String::from_utf8_lossy(&data[..head_end]).into_owned();
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or("/").to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect();
    let mut received = Received {
        method,
        target,
        headers,
        body: data[head_end + 4..].to_vec(),
    };
    if received.header("transfer-encoding").is_some() {
        return ReadOutcome::Refused(received, 411, "MissingContentLength");
    }
    let wanted = match received.header("content-length") {
        None => 0,
        Some(text) => match text.parse::<usize>() {
            Ok(n) if n <= MAX_BODY => n,
            _ => return ReadOutcome::Refused(received, 400, "InvalidRequest"),
        },
    };
    while received.body.len() < wanted {
        if stop.load(Ordering::SeqCst) || Instant::now() > deadline {
            return ReadOutcome::CutOff(received);
        }
        match stream.read(&mut chunk) {
            Ok(0) => return ReadOutcome::CutOff(received),
            Ok(n) => received.body.extend_from_slice(&chunk[..n]),
            Err(e) if is_retry(e.kind()) => {}
            Err(_) => return ReadOutcome::CutOff(received),
        }
    }
    received.body.truncate(wanted);
    ReadOutcome::Complete(received)
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        412 => "Precondition Failed",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

struct Answer {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
    error_code: Option<String>,
}

impl Answer {
    fn empty(status: u16) -> Answer {
        Answer {
            status,
            content_type: None,
            body: Vec::new(),
            error_code: None,
        }
    }

    fn error(status: u16, code: &str) -> Answer {
        Answer {
            status,
            content_type: Some("application/xml".to_owned()),
            body: format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code></Error>"
            )
            .into_bytes(),
            error_code: Some(code.to_owned()),
        }
    }
}

fn handle_connection(mut stream: TcpStream, shared: &Shared, stop: &AtomicBool) {
    if stream.set_read_timeout(Some(TICK)).is_err()
        || stream.set_write_timeout(Some(TICK)).is_err()
        || stream.set_nodelay(true).is_err()
    {
        return;
    }
    let (received, forced) = match read_request(&mut stream, stop) {
        ReadOutcome::Nothing => return,
        ReadOutcome::CutOff(received) => {
            log(shared, &received, "", "", 0, None);
            return;
        }
        ReadOutcome::Refused(received, status, code) => (received, Some((status, code))),
        ReadOutcome::Complete(received) => (received, None),
    };
    let mut bucket = String::new();
    let mut key = String::new();
    let (answer, hangup) = match forced {
        Some((status, code)) => (Answer::error(status, code), false),
        None => match verify(&shared.config, &received) {
            Err((status, code)) => (Answer::error(status, code), false),
            Ok((b, k)) => {
                bucket = b;
                key = k;
                serve(shared, &received, &bucket, &key)
            }
        },
    };
    if hangup {
        log(shared, &received, &bucket, &key, 0, None);
        return;
    }
    let mut head = format!("HTTP/1.1 {} {}\r\n", answer.status, reason(answer.status));
    if answer.status != 204 {
        head.push_str(&format!("Content-Length: {}\r\n", answer.body.len()));
    }
    if let Some(content_type) = &answer.content_type {
        head.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    log(
        shared,
        &received,
        &bucket,
        &key,
        answer.status,
        answer.error_code.clone(),
    );
    if write_all(&mut stream, head.as_bytes(), stop) {
        let _ = write_all(&mut stream, &answer.body, stop);
    }
    let _ = std::io::Write::flush(&mut stream);
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

fn log(
    shared: &Shared,
    received: &Received,
    bucket: &str,
    key: &str,
    status: u16,
    error_code: Option<String>,
) {
    shared.lock().requests.push(S3Request {
        method: received.method.clone(),
        target: received.target.clone(),
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        status,
        error_code,
        authorization: received.header("authorization").map(str::to_owned),
        amz_date: received.header("x-amz-date").map(str::to_owned),
        body_len: received.body.len(),
    });
}

/// Carries out an authenticated request; the bool is "hang up instead of answering".
fn serve(shared: &Shared, received: &Received, bucket: &str, key: &str) -> (Answer, bool) {
    let fault = {
        let mut state = shared.lock();
        let mut fired = None;
        for injection in &mut state.injections {
            if injection.method != received.method
                || injection.key.as_deref().is_some_and(|k| k != key)
            {
                continue;
            }
            if injection.after > 0 {
                injection.after -= 1;
            } else if fired.is_none() {
                fired = Some(injection.fault);
            }
        }
        fired
    };
    match fault {
        Some(S3Fault::Hangup) => return (Answer::empty(0), true),
        Some(S3Fault::Status(status)) => return (Answer::empty(status), false),
        _ => {}
    }
    let mut answer = {
        let mut state = shared.lock();
        let slot = (bucket.to_owned(), key.to_owned());
        match received.method.as_str() {
            "GET" => match state.objects.get(&slot) {
                Some(object) => Answer {
                    status: 200,
                    content_type: Some(if object.content_type.is_empty() {
                        "application/octet-stream".to_owned()
                    } else {
                        object.content_type.clone()
                    }),
                    body: object.body.clone(),
                    error_code: None,
                },
                None => Answer::error(404, "NoSuchKey"),
            },
            "PUT" => {
                state.objects.insert(
                    slot,
                    Object {
                        body: received.body.clone(),
                        content_type: received
                            .header("content-type")
                            .unwrap_or_default()
                            .to_owned(),
                    },
                );
                Answer::empty(200)
            }
            "DELETE" => {
                state.objects.remove(&slot);
                Answer::empty(204)
            }
            _ => Answer::error(405, "MethodNotAllowed"),
        }
    };
    if let Some(S3Fault::StatusAfterApplying(status)) = fault {
        answer = Answer::empty(status);
    }
    (answer, false)
}

// --- the verifier: a SigV4 implementation of its own -------------------------------------------

type Denied = (u16, &'static str);

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// HMAC-SHA256 by RFC 2104, built from whole buffers.
fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut padded = if key.len() > 64 {
        sha256(key).to_vec()
    } else {
        key.to_vec()
    };
    padded.resize(64, 0);
    let mut inner: Vec<u8> = padded.iter().map(|b| b ^ 0x36).collect();
    inner.extend_from_slice(message);
    let mut outer: Vec<u8> = padded.iter().map(|b| b ^ 0x5c).collect();
    outer.extend_from_slice(&sha256(&inner));
    sha256(&outer)
}

/// The SigV4 path encoding of S3: unreserved bytes and `/` stay, the rest is `%XX`.
fn encode_path(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(char::from(b));
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn decode_path(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let pair = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(pair, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

/// `YYYYMMDDTHHMMSSZ` as Unix seconds.
fn parse_amz_date(text: &str) -> Option<u64> {
    let b = text.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let num = |a: usize, z: usize| -> Option<i64> {
        let part = text.get(a..z)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (year, month, day) = (num(0, 4)?, num(4, 6)?, num(6, 8)?);
    let (hour, minute, second) = (num(9, 11)?, num(11, 13)?, num(13, 15)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    // Days from civil (Hinnant).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).ok()
}

/// The signature for a request, from the already-validated parts.
fn expected_signature(
    secret: &str,
    method: &str,
    uri: &str,
    signed_headers: &[(String, String)],
    payload_hash: &str,
    amz_date: &str,
    region: &str,
) -> String {
    let mut canonical = format!("{method}\n{uri}\n\n");
    for (name, value) in signed_headers {
        let folded = value.split_ascii_whitespace().collect::<Vec<_>>().join(" ");
        canonical.push_str(&format!("{name}:{folded}\n"));
    }
    let names: Vec<&str> = signed_headers.iter().map(|(n, _)| n.as_str()).collect();
    canonical.push_str(&format!("\n{}\n{payload_hash}", names.join(";")));
    let day = &amz_date[..8];
    let scope = format!("{day}/{region}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        to_hex(&sha256(canonical.as_bytes()))
    );
    let mut key = hmac(format!("AWS4{secret}").as_bytes(), day.as_bytes()).to_vec();
    for part in [region.as_bytes(), b"s3", b"aws4_request"] {
        key = hmac(&key, part).to_vec();
    }
    to_hex(&hmac(&key, to_sign.as_bytes()))
}

/// Checks the request's signature and form; on success the bucket and the decoded key.
fn verify(config: &FakeS3Config, request: &Received) -> Result<(String, String), Denied> {
    let authorization = request
        .header("authorization")
        .ok_or((403, "AccessDenied"))?;
    let fields = authorization
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or((400, "AuthorizationHeaderMalformed"))?;
    let field = |name: &str| {
        fields
            .split(',')
            .map(str::trim)
            .find_map(|f| f.strip_prefix(name))
    };
    let credential = field("Credential=").ok_or((400, "AuthorizationHeaderMalformed"))?;
    let signed_names = field("SignedHeaders=").ok_or((400, "AuthorizationHeaderMalformed"))?;
    let given = field("Signature=").ok_or((400, "AuthorizationHeaderMalformed"))?;

    let scope: Vec<&str> = credential.split('/').collect();
    let [access_key, day, region, service, terminator] = scope[..] else {
        return Err((400, "AuthorizationHeaderMalformed"));
    };
    if access_key != config.access_key {
        return Err((403, "InvalidAccessKeyId"));
    }
    if region != config.region || service != "s3" || terminator != "aws4_request" {
        return Err((400, "AuthorizationHeaderMalformed"));
    }

    let amz_date = request.header("x-amz-date").ok_or((403, "AccessDenied"))?;
    let at = parse_amz_date(amz_date).ok_or((400, "AuthorizationHeaderMalformed"))?;
    if &amz_date[..8] != day {
        return Err((400, "AuthorizationHeaderMalformed"));
    }
    let now = config.clock.now_unix_secs();
    if at.abs_diff(now) > MAX_SKEW_SECS {
        return Err((403, "RequestTimeTooSkewed"));
    }

    let names: Vec<&str> = signed_names.split(';').collect();
    if !names.windows(2).all(|w| w[0] < w[1]) {
        return Err((400, "AuthorizationHeaderMalformed"));
    }
    for required in ["host", "x-amz-content-sha256", "x-amz-date"] {
        if !names.contains(&required) {
            return Err((403, "AccessDenied"));
        }
    }
    let mut signed_headers = Vec::new();
    for name in &names {
        let value = request.header(name).ok_or((403, "AccessDenied"))?;
        signed_headers.push(((*name).to_owned(), value.to_owned()));
    }

    if request.target.contains('?') {
        return Err((400, "InvalidRequest"));
    }
    let raw_path = request.target.as_str();
    let decoded = decode_path(raw_path).ok_or((400, "InvalidURI"))?;
    if !raw_path.starts_with('/') || encode_path(&decoded) != raw_path {
        return Err((400, "InvalidURI"));
    }

    let payload_hash = request
        .header("x-amz-content-sha256")
        .ok_or((403, "AccessDenied"))?;
    let well_formed = payload_hash.len() == 64
        && payload_hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !well_formed {
        return Err((400, "InvalidRequest"));
    }

    let wanted = expected_signature(
        &config.secret_key,
        &request.method,
        raw_path,
        &signed_headers,
        payload_hash,
        amz_date,
        &config.region,
    );
    if wanted != given {
        return Err((403, "SignatureDoesNotMatch"));
    }
    if to_hex(&sha256(&request.body)) != payload_hash {
        return Err((400, "XAmzContentSHA256Mismatch"));
    }

    let path = String::from_utf8(decoded).map_err(|_| (400, "InvalidURI"))?;
    let rest = path.strip_prefix('/').ok_or((400, "InvalidURI"))?;
    let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
    if !config.buckets.iter().any(|b| b == bucket) {
        return Err((404, "NoSuchBucket"));
    }
    if key.is_empty() {
        return Err((400, "InvalidRequest"));
    }
    Ok((bucket.to_owned(), key.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn header(name: &str, value: &str) -> (String, String) {
        (name.to_owned(), value.to_owned())
    }

    #[test]
    fn the_verifier_reproduces_the_aws_get_object_example() {
        let headers = [
            header("host", "examplebucket.s3.amazonaws.com"),
            header("range", "bytes=0-9"),
            header("x-amz-content-sha256", EMPTY),
            header("x-amz-date", "20130524T000000Z"),
        ];
        assert_eq!(
            expected_signature(
                SECRET,
                "GET",
                "/test.txt",
                &headers,
                EMPTY,
                "20130524T000000Z",
                "us-east-1"
            ),
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn the_verifier_reproduces_the_aws_put_object_example() {
        let body_hash = to_hex(&sha256(b"Welcome to Amazon S3."));
        let headers = [
            header("date", "Fri, 24 May 2013 00:00:00 GMT"),
            header("host", "examplebucket.s3.amazonaws.com"),
            header("x-amz-content-sha256", &body_hash),
            header("x-amz-date", "20130524T000000Z"),
            header("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ];
        assert_eq!(
            expected_signature(
                SECRET,
                "PUT",
                &encode_path(b"/test$file.text"),
                &headers,
                &body_hash,
                "20130524T000000Z",
                "us-east-1"
            ),
            "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    #[test]
    fn hmac_matches_rfc_4231_cases_2_and_6() {
        assert_eq!(
            to_hex(&hmac(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            to_hex(&hmac(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn dates_parse_to_unix_seconds() {
        assert_eq!(parse_amz_date("19700101T000000Z"), Some(0));
        assert_eq!(parse_amz_date("20130524T000000Z"), Some(1_369_353_600));
        assert_eq!(parse_amz_date("20000229T235959Z"), Some(951_868_799));
        assert_eq!(parse_amz_date("21000101T000000Z"), Some(4_102_444_800));
        assert_eq!(parse_amz_date("20131324T000000Z"), None);
        assert_eq!(parse_amz_date("2013-05-24"), None);
        assert_eq!(parse_amz_date("20130524T000000"), None);
    }

    #[test]
    fn path_encoding_is_canonical_only() {
        assert_eq!(encode_path(b"/a/1.0.0+b/c d"), "/a/1.0.0%2Bb/c%20d");
        assert_eq!(decode_path("/a/%2B"), Some(b"/a/+".to_vec()));
        assert_eq!(decode_path("/a/%2"), None);
        assert_eq!(decode_path("/a/%zz"), None);
    }
}
