//! The object-store adapters of `lunepack_core::ObjectStore` (P-D1): [`S3Store`] (an S3-compatible
//! HTTP store, SigV4-signed, R2 first) and [`DirStore`] (a local directory, for tests and dry
//! runs).
//!
//! # `S3Store`
//!
//! - Path-style URLs, `<endpoint>/<bucket>/<key>`, each key segment URI-encoded for SigV4 (so a
//!   `+` in a version is `%2B`, in the URL and in the signature). The request's parts are built
//!   once and the request is sent from those parts.
//! - `https` only, except an `http` endpoint on a loopback address (the tests' fake). Redirects are
//!   never followed. Proxy and TLS settings are the transport's (`UreqTransport`).
//! - `200` and `204` are success for `put` and `delete`, `200` for `get`; a `get` answered `404` is
//!   `None` (unless the answer's `<Code>` says the bucket is missing); anything else is [`StoreError::Status`] naming the method, the key and the status. A
//!   transport failure is a [`StoreError::Transport`] of a closed kind: no error text of the HTTP
//!   stack, which can echo a URL, reaches a message.
//! - The signing time comes from the [`Clock`] given to the store, which is the system clock in
//!   the CLI, never the clock that honours `SOURCE_DATE_EPOCH`.
//! - `put` streams the reader and checks, as it goes, that it yields exactly `len` bytes hashing to
//!   `sha256`; the last bytes are held back until the check passes, so a body that fails it never
//!   completes the request and nothing is stored (the server also checks `x-amz-content-sha256`).
//!
//! # `DirStore`
//!
//! Keys map to files under a root. A `put` writes a temporary file and renames it. A key that
//! differs from an existing entry only by ASCII case is refused (the on-disk name is compared, so a
//! case-insensitive file system cannot merge two keys), as are symlinks on the way and names a
//! Windows file system would read as something else.

use std::cell::RefCell;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use lunepack_core::{
    Clock, ObjectStore, StoreError, StoreKey, StoreMethod, StoreTransportKind, TransportErrorKind,
};
use sha2::{Digest, Sha256};
use ureq::{Agent, RequestBuilder, SendBody};
use url::{Host, Url};

use crate::proxy::{self, Selection};
use crate::sigv4::{
    Credentials, EMPTY_SHA256_HEX, SigningInput, amz_date, authorization, hex_lower, uri_encode,
};
use crate::ureq_transport::{UreqOptions, agent_config, io_kind, kind_of};

/// Why an [`S3Store`] could not be built. A message never echoes the endpoint's text or a
/// credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum S3ConfigError {
    /// The endpoint is not a URL.
    #[error("the store endpoint is not a valid URL")]
    BadEndpoint,
    /// The endpoint has a userinfo, a path, a query or a fragment.
    #[error("the store endpoint must be scheme://host[:port] only")]
    EndpointForm,
    /// An `http` endpoint that is not a loopback address.
    #[error("the store endpoint must be https (http is allowed for a loopback address only)")]
    InsecureEndpoint,
    /// A bucket name outside 3-63 lowercase letters, digits, `.` and `-`.
    #[error("the bucket name is not a valid bucket name")]
    BadBucket,
    /// A region that is not 1-32 lowercase letters, digits and `-`.
    #[error("the region is not valid")]
    BadRegion,
    /// An R2 account id that is not 32 lowercase hexadecimal characters.
    #[error("the account id must be 32 lowercase hexadecimal characters")]
    BadAccountId,
    /// A credential that is empty or has a character that cannot be put in a header.
    #[error("the access key or the secret key is empty or has a character that cannot be used")]
    BadCredentials,
}

/// The region R2 expects in a signature.
const R2_REGION: &str = "auto";

/// An S3-compatible store (see the module docs).
pub struct S3Store {
    agent: Agent,
    /// `scheme://host[:port]`, no trailing slash.
    origin: String,
    /// `host[:port]` as it is put in the request and signed.
    host: String,
    bucket: String,
    region: String,
    credentials: Credentials,
    clock: Arc<dyn Clock>,
    /// Connect without a proxy (an `http` loopback endpoint).
    direct: bool,
}

impl fmt::Debug for S3Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Store")
            .field("origin", &self.origin)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl S3Store {
    /// A store on `endpoint` (`https://host[:port]`), in `bucket`, signing for `region` with
    /// `credentials` at the time `clock` gives.
    pub fn new(
        endpoint: &str,
        bucket: &str,
        region: &str,
        credentials: Credentials,
        clock: Arc<dyn Clock>,
    ) -> Result<S3Store, S3ConfigError> {
        S3Store::with_options(
            endpoint,
            bucket,
            region,
            credentials,
            clock,
            &UreqOptions::default(),
        )
    }

    /// Like [`S3Store::new`], with the transport's timeouts. The redirect limit and `direct` of
    /// `options` are not used: a store never follows a redirect, and a loopback `http` endpoint is
    /// always reached directly.
    pub fn with_options(
        endpoint: &str,
        bucket: &str,
        region: &str,
        credentials: Credentials,
        clock: Arc<dyn Clock>,
        options: &UreqOptions,
    ) -> Result<S3Store, S3ConfigError> {
        let url = Url::parse(endpoint).map_err(|_| S3ConfigError::BadEndpoint)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.path(), "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(S3ConfigError::EndpointForm);
        }
        let host = url.host_str().ok_or(S3ConfigError::BadEndpoint)?.to_owned();
        let loopback = match url.host() {
            Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        match url.scheme() {
            "https" => {}
            "http" if loopback => {}
            "http" => return Err(S3ConfigError::InsecureEndpoint),
            _ => return Err(S3ConfigError::BadEndpoint),
        }
        if !is_bucket_name(bucket) {
            return Err(S3ConfigError::BadBucket);
        }
        if region.is_empty()
            || region.len() > 32
            || !region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(S3ConfigError::BadRegion);
        }
        if !credentials.is_well_formed() {
            return Err(S3ConfigError::BadCredentials);
        }
        let host_header = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        };
        let agent = Agent::new_with_config(agent_config(&UreqOptions {
            // A store answers where it is asked; a redirect is an error, not something to follow
            // with a signed request.
            max_redirects: 0,
            direct: false,
            ..options.clone()
        }));
        Ok(S3Store {
            agent,
            origin: format!("{}://{host_header}", url.scheme()),
            host: host_header,
            bucket: bucket.to_owned(),
            region: region.to_owned(),
            credentials,
            clock,
            direct: url.scheme() == "http",
        })
    }

    /// A store on Cloudflare R2: `https://<account_id>.r2.cloudflarestorage.com`, region `auto`.
    pub fn r2(
        account_id: &str,
        bucket: &str,
        credentials: Credentials,
        clock: Arc<dyn Clock>,
    ) -> Result<S3Store, S3ConfigError> {
        if account_id.len() != 32
            || !account_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(S3ConfigError::BadAccountId);
        }
        S3Store::new(
            &format!("https://{account_id}.r2.cloudflarestorage.com"),
            bucket,
            R2_REGION,
            credentials,
            clock,
        )
    }

    /// The parts of one request, signed. What is returned is what must be sent.
    fn prepare(&self, key: &StoreKey, method: StoreMethod, payload_sha256_hex: &str) -> Prepared {
        let path = format!(
            "/{}/{}",
            uri_encode(&self.bucket, false),
            uri_encode(key.as_str(), true)
        );
        let date = amz_date(self.clock.now_unix_secs());
        let authorization = authorization(
            &self.credentials,
            &SigningInput {
                method: method.describe(),
                canonical_uri: &path,
                canonical_query: "",
                headers: &[
                    ("host", &self.host),
                    ("x-amz-content-sha256", payload_sha256_hex),
                    ("x-amz-date", &date),
                ],
                payload_sha256_hex,
                amz_date: &date,
                region: &self.region,
            },
        );
        Prepared {
            url: format!("{}{path}", self.origin),
            headers: [
                ("x-amz-content-sha256", payload_sha256_hex.to_owned()),
                ("x-amz-date", date),
                ("authorization", authorization),
            ],
        }
    }

    /// Adds the signed headers and the proxy choice to a request.
    fn configure<B>(&self, request: RequestBuilder<B>, prepared: &Prepared) -> RequestBuilder<B> {
        let mut request = request;
        for (name, value) in &prepared.headers {
            request = request.header(*name, value.as_str());
        }
        let selection = if self.direct {
            Selection::Override(None)
        } else {
            proxy::select(&prepared.url)
        };
        match selection {
            Selection::AgentDefault => request,
            Selection::Override(chosen) => request.config().proxy(chosen).build(),
        }
    }

    fn status_error(method: StoreMethod, key: &StoreKey, status: u16) -> StoreError {
        StoreError::Status {
            method,
            key: key.clone(),
            status,
        }
    }

    fn transport_error(method: StoreMethod, key: &StoreKey, e: &ureq::Error) -> StoreError {
        StoreError::Transport {
            method,
            key: key.clone(),
            kind: store_kind(kind_of(e)),
        }
    }
}

/// What [`S3Store::prepare`] builds.
struct Prepared {
    url: String,
    headers: [(&'static str, String); 3],
}

fn store_kind(kind: TransportErrorKind) -> StoreTransportKind {
    match kind {
        TransportErrorKind::Connect => StoreTransportKind::Connect,
        TransportErrorKind::Tls => StoreTransportKind::Tls,
        TransportErrorKind::Timeout => StoreTransportKind::Timeout,
        _ => StoreTransportKind::Other,
    }
}

/// 3-63 characters of lowercase letters, digits, `.` and `-`, starting and ending alphanumeric.
fn is_bucket_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (3..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
}

/// Why a streamed upload was stopped by its own reader.
enum Stopped {
    /// The body was not `len` bytes or did not hash to the declared SHA-256.
    Mismatch,
    /// Reading the body failed.
    Io(io::Error),
}

/// The upload's reader: passes the bytes through while it counts and hashes them, and holds the
/// last read back until the length and the hash are right, so a wrong body can never complete the
/// request.
struct Checked<'a> {
    inner: &'a mut dyn Read,
    remaining: u64,
    expected: [u8; 32],
    hasher: Sha256,
    stopped: &'a RefCell<Option<Stopped>>,
    finished: bool,
}

impl<'a> Checked<'a> {
    fn new(
        inner: &'a mut dyn Read,
        len: u64,
        expected: [u8; 32],
        stopped: &'a RefCell<Option<Stopped>>,
    ) -> Checked<'a> {
        Checked {
            inner,
            remaining: len,
            expected,
            hasher: Sha256::new(),
            stopped,
            finished: false,
        }
    }

    fn stop(&self, why: Stopped) -> io::Error {
        *self.stopped.borrow_mut() = Some(why);
        io::Error::other("upload stopped")
    }

    /// Runs once all `len` bytes have been read: no byte may follow, and the hash must match.
    fn finish(&mut self) -> io::Result<()> {
        let mut one = [0u8; 1];
        loop {
            match self.inner.read(&mut one) {
                Ok(0) => break,
                Ok(_) => return Err(self.stop(Stopped::Mismatch)),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(self.stop(Stopped::Io(e))),
            }
        }
        if self.hasher.clone().finalize().as_slice() != self.expected {
            return Err(self.stop(Stopped::Mismatch));
        }
        self.finished = true;
        Ok(())
    }
}

impl Read for Checked<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.finished || buf.is_empty() {
            return Ok(0);
        }
        let room = usize::try_from(self.remaining).map_or(buf.len(), |r| r.min(buf.len()));
        let read = loop {
            match self.inner.read(&mut buf[..room]) {
                Ok(n) => break n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(self.stop(Stopped::Io(e))),
            }
        };
        if read == 0 {
            // The body ended before `len` bytes.
            return Err(self.stop(Stopped::Mismatch));
        }
        self.hasher.update(&buf[..read]);
        self.remaining -= read as u64;
        if self.remaining == 0 {
            self.finish()?;
        }
        Ok(read)
    }
}

impl ObjectStore for S3Store {
    fn get(&self, key: &StoreKey, max_len: u64) -> Result<Option<Vec<u8>>, StoreError> {
        let method = StoreMethod::Get;
        let prepared = self.prepare(key, method, EMPTY_SHA256_HEX);
        let response = self
            .configure(self.agent.get(&prepared.url), &prepared)
            .call()
            .map_err(|e| S3Store::transport_error(method, key, &e))?;
        match response.status().as_u16() {
            200 => {}
            404 => {
                // An absent key is `None`; an absent bucket answers 404 too, and is a fault (a
                // misspelt bucket must not read as "nothing published").
                let mut answer = Vec::new();
                let _ = response
                    .into_body()
                    .into_reader()
                    .take(4096)
                    .read_to_end(&mut answer);
                if contains(&answer, b"<Code>NoSuchBucket</Code>") {
                    return Err(S3Store::status_error(method, key, 404));
                }
                return Ok(None);
            }
            status => return Err(S3Store::status_error(method, key, status)),
        }
        let too_large = || StoreError::TooLarge {
            key: key.clone(),
            limit: max_len,
        };
        let declared = response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        if declared.is_some_and(|len| len > max_len) {
            return Err(too_large());
        }
        let mut body = Vec::new();
        response
            .into_body()
            .into_reader()
            .take(max_len.saturating_add(1))
            .read_to_end(&mut body)
            .map_err(|e| StoreError::Transport {
                method,
                key: key.clone(),
                kind: store_kind(read_kind(&e)),
            })?;
        if body.len() as u64 > max_len {
            return Err(too_large());
        }
        Ok(Some(body))
    }

    fn put(
        &self,
        key: &StoreKey,
        body: &mut dyn Read,
        len: u64,
        sha256: [u8; 32],
        content_type: &str,
    ) -> Result<(), StoreError> {
        let method = StoreMethod::Put;
        if !content_type
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ')
        {
            return Err(StoreError::Io {
                key: key.clone(),
                source: io::Error::new(io::ErrorKind::InvalidInput, "unusable content type"),
            });
        }
        let stopped = RefCell::new(None);
        let mut checked = Checked::new(body, len, sha256, &stopped);
        if len == 0 {
            // Nothing to stream: judge the empty body before anything is sent.
            if checked.finish().is_err() {
                return Err(stopped_error(stopped.into_inner(), key));
            }
        }
        let prepared = self.prepare(key, method, &hex_lower(&sha256));
        let request = self
            .agent
            .put(&prepared.url)
            .content_type(content_type)
            .header("content-length", len.to_string());
        let result = self
            .configure(request, &prepared)
            .send(SendBody::from_reader(&mut checked));
        match result {
            Ok(response) => match response.status().as_u16() {
                200 | 204 => Ok(()),
                status => Err(S3Store::status_error(method, key, status)),
            },
            Err(e) => {
                let stopped = stopped.into_inner();
                if stopped.is_some() {
                    Err(stopped_error(stopped, key))
                } else {
                    Err(S3Store::transport_error(method, key, &e))
                }
            }
        }
    }

    fn delete(&self, key: &StoreKey) -> Result<(), StoreError> {
        let method = StoreMethod::Delete;
        let prepared = self.prepare(key, method, EMPTY_SHA256_HEX);
        let response = self
            .configure(self.agent.delete(&prepared.url), &prepared)
            .call()
            .map_err(|e| S3Store::transport_error(method, key, &e))?;
        match response.status().as_u16() {
            200 | 204 => Ok(()),
            status => Err(S3Store::status_error(method, key, status)),
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn stopped_error(stopped: Option<Stopped>, key: &StoreKey) -> StoreError {
    match stopped {
        Some(Stopped::Io(source)) => StoreError::Io {
            key: key.clone(),
            source,
        },
        _ => StoreError::Mismatch { key: key.clone() },
    }
}

/// The failure class of a body read that went wrong.
fn read_kind(e: &io::Error) -> TransportErrorKind {
    match e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ureq::Error>())
    {
        Some(ureq_error) => kind_of(ureq_error),
        None => io_kind(e),
    }
}

// ---------------------------------------------------------------------------------------------

/// A store in a local directory (see the module docs).
#[derive(Debug, Clone)]
pub struct DirStore {
    root: PathBuf,
}

/// Names of the temporary files `put` writes.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl DirStore {
    /// A store under `root`, made absolute against the current directory. The directory is
    /// created by the first `put`.
    pub fn new(root: impl Into<PathBuf>) -> DirStore {
        let root = root.into();
        let root = std::path::absolute(&root).unwrap_or(root);
        DirStore { root }
    }

    /// The directory the store lives in.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The on-disk path of `key`. `Ok(None)` when something on the way is missing and `create` is
    /// off; with `create`, the directories on the way are made. An entry that differs from a
    /// segment only by case, a symlink, or a file where a directory is needed is an error.
    fn locate(&self, key: &StoreKey, create: bool) -> io::Result<Option<PathBuf>> {
        let segments: Vec<&str> = key.as_str().split('/').collect();
        if create {
            fs::create_dir_all(&self.root)?;
        }
        let mut path = self.root.clone();
        for (index, segment) in segments.iter().enumerate() {
            check_segment(segment)?;
            let last = index + 1 == segments.len();
            match entry_type(&path, segment)? {
                Some(file_type) => {
                    if file_type.is_symlink() {
                        return Err(invalid("a symbolic link is on the key's path"));
                    }
                    if !last && !file_type.is_dir() {
                        if create {
                            return Err(invalid("a file is where the key needs a directory"));
                        }
                        return Ok(None);
                    }
                    path.push(segment);
                }
                None => {
                    if !create {
                        return Ok(None);
                    }
                    path.push(segment);
                    if !last {
                        fs::create_dir(&path)?;
                    }
                }
            }
        }
        Ok(Some(path))
    }

    /// Removes the empty directories above `path`, up to the root.
    fn prune(&self, path: &Path) {
        let mut dir = path.parent();
        while let Some(parent) = dir {
            if parent == self.root
                || !parent.starts_with(&self.root)
                || fs::remove_dir(parent).is_err()
            {
                break;
            }
            dir = parent.parent();
        }
    }
}

fn invalid(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, why)
}

/// Whether the directory `dir` has an entry named exactly `name`, and its type. An entry that
/// differs from `name` only by ASCII case is an error.
fn entry_type(dir: &Path, name: &str) -> io::Result<Option<fs::FileType>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut exact = None;
    for entry in entries {
        let entry = entry?;
        let on_disk = entry.file_name();
        let on_disk = on_disk.to_string_lossy();
        if on_disk == name {
            exact = Some(entry.file_type()?);
        } else if on_disk.eq_ignore_ascii_case(name) {
            return Err(invalid(
                "an entry that differs from the key only by case already exists",
            ));
        }
    }
    Ok(exact)
}

/// Refuses a segment a Windows file system would read as something else: a reserved device name,
/// a stream or drive separator, a wildcard, a trailing dot.
fn check_segment(segment: &str) -> io::Result<()> {
    const RESERVED: [&str; 22] = [
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
        "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    let stem = segment.split('.').next().unwrap_or(segment);
    if segment.ends_with('.')
        || segment
            .bytes()
            .any(|b| matches!(b, b':' | b'<' | b'>' | b'"' | b'|' | b'?' | b'*'))
        || RESERVED.iter().any(|name| stem.eq_ignore_ascii_case(name))
    {
        return Err(invalid("the key has a name a directory store cannot hold"));
    }
    Ok(())
}

impl ObjectStore for DirStore {
    fn get(&self, key: &StoreKey, max_len: u64) -> Result<Option<Vec<u8>>, StoreError> {
        let io_error = |source| StoreError::Io {
            key: key.clone(),
            source,
        };
        let Some(path) = self.locate(key, false).map_err(io_error)? else {
            return Ok(None);
        };
        let too_large = || StoreError::TooLarge {
            key: key.clone(),
            limit: max_len,
        };
        let meta = match fs::metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_error(e)),
        };
        if meta.is_dir() {
            // Other keys live below this one; there is no object at it.
            return Ok(None);
        }
        if meta.len() > max_len {
            return Err(too_large());
        }
        let mut body = Vec::new();
        File::open(&path)
            .and_then(|file| file.take(max_len.saturating_add(1)).read_to_end(&mut body))
            .map_err(io_error)?;
        if body.len() as u64 > max_len {
            return Err(too_large());
        }
        Ok(Some(body))
    }

    fn put(
        &self,
        key: &StoreKey,
        body: &mut dyn Read,
        len: u64,
        sha256: [u8; 32],
        _content_type: &str,
    ) -> Result<(), StoreError> {
        let io_error = |source| StoreError::Io {
            key: key.clone(),
            source,
        };
        let path = self
            .locate(key, true)
            .map_err(io_error)?
            .ok_or_else(|| io_error(invalid("the key has no place")))?;
        if path.is_dir() {
            return Err(io_error(invalid("a directory is at the key")));
        }
        let dir = path.parent().unwrap_or(&self.root);
        let (temp_path, mut temp) = create_temp(dir).map_err(io_error)?;
        let outcome = copy_checked(body, &mut temp, len, sha256);
        drop(temp);
        match outcome {
            Ok(true) => fs::rename(&temp_path, &path).map_err(|e| {
                let _ = fs::remove_file(&temp_path);
                io_error(e)
            }),
            Ok(false) => {
                let _ = fs::remove_file(&temp_path);
                Err(StoreError::Mismatch { key: key.clone() })
            }
            Err(e) => {
                let _ = fs::remove_file(&temp_path);
                Err(io_error(e))
            }
        }
    }

    fn delete(&self, key: &StoreKey) -> Result<(), StoreError> {
        let io_error = |source| StoreError::Io {
            key: key.clone(),
            source,
        };
        let Some(path) = self.locate(key, false).map_err(io_error)? else {
            return Ok(());
        };
        match fs::metadata(&path) {
            Ok(meta) if meta.is_dir() => return Ok(()),
            Ok(_) => match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_error(e)),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_error(e)),
        }
        self.prune(&path);
        Ok(())
    }
}

/// A new temporary file next to the key's file.
fn create_temp(dir: &Path) -> io::Result<(PathBuf, File)> {
    for _ in 0..16 {
        let name = format!(
            ".lunepack-put-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = dir.join(name);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("no unused temporary file name"))
}

/// Copies `body` to `out`, reading no more than `len` bytes and one more to see whether there is
/// any. `Ok(false)` when the body is not `len` bytes or does not hash to `expected`.
fn copy_checked(
    body: &mut dyn Read,
    out: &mut File,
    len: u64,
    expected: [u8; 32],
) -> io::Result<bool> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = match body.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        total += n as u64;
        if total > len {
            return Ok(false);
        }
        hasher.update(&buffer[..n]);
        out.write_all(&buffer[..n])?;
    }
    out.flush()?;
    Ok(total == len && hasher.finalize().as_slice() == expected)
}
