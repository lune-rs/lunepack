//! The service protocol, versions 1 and 2 (M10-D1, C8; version 2 adds `put` of kind `patch`,
//! M12-D6, and is otherwise version 1 byte for byte): the conversation between an app's copy of the
//! library (the client) and the machine install's LocalSystem service (the server) over a duplex
//! byte channel. Pure: the codec and both session types work over any [`Duplex`]; no pipe, clock or
//! file is touched here. Deadlines are set only through [`Duplex::set_read_deadline`].
//!
//! Frame: a `u32` little-endian length `n` (1 ≤ n), then `n` bytes whose first is the kind:
//! [`KIND_MESSAGE`] (body ≤ [`MAX_MESSAGE`] bytes of strict JSON, one object, duplicate keys
//! refused, integers ≤ 2^53 − 1) or [`KIND_DATA`] (body 1 to [`MAX_DATA`] bytes). A larger `n`,
//! another kind or an empty body is refused before any allocation.
//!
//! Hello (the same in every version): the client sends `{"type":"hello","min":a,"max":b}`; the
//! server answers `{"type":"hello","version":v}` with the highest common version, or
//! `{"type":"unsupported","min":a,"max":b}` with its own range and closes.
//!
//! Within version 1 every message has a closed member set, and every request carries `app`. A frame
//! or message the protocol refuses is `malformed`: the server answers `error{malformed}` (after the
//! hello; before it, it only closes) and ends the session, the client ends its session; nothing is
//! retried or skipped. The wire encoding is written here by hand in a fixed member order (`type`,
//! then `app` on requests, then the members in the order of the protocol summary), so it does not
//! depend on `serde_json`'s map features; `tests/golden/service-v1.txt` pins it.
//!
//! No message carries a path of the file system, an OS error text, an install id, a token digest or
//! key material. `need_fetch` carries release paths (the manifest's relative entry paths).
//!
//! Data that follows `stage_begin` (the documents, concatenated in the declared order) and `put`
//! (the object) travels in data frames, which may be split anywhere; the server reads all of it
//! ([`ServerSession::read_data`]) before it answers the request, or ends the session.

use std::fmt;
use std::io::{ErrorKind, Read, Write};
// `Duration` is a plain value (no clock is read); the purity test forbids `std::time` as a whole.
use core::time::Duration;

use serde_json::{Map, Value};

use crate::digest::Sha256Digest;
use crate::encoding::{hex_decode_array, hex_encode};
pub use crate::error::ServiceError;
use crate::ident::{AppId, Channel};
use crate::json::check_strict;
use crate::limits::{Limits, MAX_JSON_INT};
use crate::path::RelPath;
use crate::version::Version;

/// The lowest protocol version this build speaks.
pub const PROTOCOL_MIN: u32 = 1;
/// The highest protocol version this build speaks: version 2 is version 1 plus `put` of kind
/// `patch` (M12-D6).
pub const PROTOCOL_MAX: u32 = 2;
/// The first protocol version with `put{kind:"patch"}`.
pub const PROTOCOL_PATCH: u32 = 2;
/// Frame kind of a message frame.
pub const KIND_MESSAGE: u8 = 1;
/// Frame kind of a data frame.
pub const KIND_DATA: u8 = 2;
/// Largest message body in bytes.
pub const MAX_MESSAGE: usize = 65_536;
/// Largest data body in bytes.
pub const MAX_DATA: usize = 262_144;
/// Most root documents a `stage_begin` declares.
pub const MAX_ROOTS: usize = 16;
/// Most paths one `need_fetch` carries.
pub const MAX_NEED_FETCH: usize = 64;
/// Most `stage_commit` requests one session may make (enforced by the server's dispatcher).
pub const MAX_COMMITS: u32 = 3;
/// The server's deadline for the client's hello (M10-D11).
pub const SERVER_HELLO_DEADLINE: Duration = Duration::from_secs(5);
/// The server's deadline for every later frame (M10-D11).
pub const SERVER_FRAME_DEADLINE: Duration = Duration::from_secs(30);

/// A byte channel to the peer with a settable read deadline. Implemented by the named-pipe
/// adapters and the testkit's in-memory pair.
pub trait Duplex: Read + Write + Send {
    /// Bounds every read from now on: a read that has not completed `deadline` after this call
    /// fails with [`ErrorKind::TimedOut`] (or [`ErrorKind::WouldBlock`]). `None` lifts the bound.
    fn set_read_deadline(&mut self, deadline: Option<Duration>) -> std::io::Result<()>;
}

impl<D: Duplex + ?Sized> Duplex for Box<D> {
    fn set_read_deadline(&mut self, deadline: Option<Duration>) -> std::io::Result<()> {
        (**self).set_read_deadline(deadline)
    }
}

// ---- closed sets ---------------------------------------------------------------------------------

macro_rules! wire_enum {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident => $text:literal),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $variant),*
        }

        impl $name {
            /// Every value, in wire order.
            pub const ALL: &'static [$name] = &[$($name::$variant),*];

            /// The wire name.
            pub fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $text),*
                }
            }

            /// The value named `text`, if any.
            pub fn from_wire(text: &str) -> Option<$name> {
                match text {
                    $($text => Some($name::$variant),)*
                    _ => None,
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

wire_enum! {
    /// The error codes of version 1, a closed set (append-only in later versions).
    ErrorCode {
        /// A frame or message the protocol refuses; the connection ends.
        Malformed => "malformed",
        /// The request names another app than the service's.
        WrongApp => "wrong_app",
        /// Another host holds the engine's lock.
        Busy => "busy",
        /// An administrator's policy disables self-update.
        DisabledByPolicy => "disabled_by_policy",
        /// The install tree is not protected as it must be.
        NotProtected => "not_protected",
        /// A document or object failed verification (with a [`VerifyClass`]).
        VerifyFailed => "verify_failed",
        /// The channel is not the installed tree's.
        ChannelNotAllowed => "channel_not_allowed",
        /// The object is not listed in the verified manifest.
        NotInManifest => "not_in_manifest",
        /// The object's size differs from the manifest's.
        SizeMismatch => "size_mismatch",
        /// The object's hash differs from the manifest's.
        HashMismatch => "hash_mismatch",
        /// The publisher check (M9) refused the staged tree.
        PublisherMismatch => "publisher_mismatch",
        /// A version is already pending its health check.
        PendingExists => "pending_exists",
        /// Nothing usable is staged.
        NothingStaged => "nothing_staged",
        /// The version is not the one staged or pending.
        VersionMismatch => "version_mismatch",
        /// The version is not pending.
        NotPending => "not_pending",
        /// The token does not match.
        TokenMismatch => "token_mismatch",
        /// The bad list is full.
        BadFull => "bad_full",
        /// Something is over a cap.
        TooLarge => "too_large",
        /// A read timed out; the connection ends.
        Timeout => "timeout",
        /// Anything else; no detail crosses the boundary.
        Internal => "internal",
    }
}

wire_enum! {
    /// Why `verify_failed` was answered, a closed set.
    VerifyClass {
        /// A signature or key check failed.
        Signature => "signature",
        /// A document has expired.
        Expired => "expired",
        /// A document is older than a recorded floor.
        Rollback => "rollback",
        /// A hash differs.
        Hash => "hash",
        /// A document breaks its format.
        Format => "format",
        /// A document is for another app.
        AppMismatch => "app_mismatch",
    }
}

wire_enum! {
    /// The kind of a document a `stage_begin` declares.
    DocumentKind {
        /// A root document (`root-<k>.json`).
        Root => "root",
        /// The key set.
        Keys => "keys",
        /// The channel's feed.
        Feed => "feed",
        /// The candidate's manifest.
        Manifest => "manifest",
    }
}

wire_enum! {
    /// The kind of an object a `put` uploads.
    ObjectKind {
        /// The release's pack.
        Pack => "pack",
        /// One compressed file (a frame).
        Frame => "frame",
        /// One delta patch (FORMAT.md 9.3); version 2 and above only.
        Patch => "patch",
    }
}

impl DocumentKind {
    fn rank(self) -> u8 {
        match self {
            DocumentKind::Root => 0,
            DocumentKind::Keys => 1,
            DocumentKind::Feed => 2,
            DocumentKind::Manifest => 3,
        }
    }

    /// FORMAT 4's cap for this document.
    pub fn cap(self, limits: &Limits) -> u64 {
        match self {
            DocumentKind::Root => limits.root_doc_bytes,
            DocumentKind::Keys => limits.keys_doc_bytes,
            DocumentKind::Feed => limits.feed_doc_bytes,
            DocumentKind::Manifest => limits.manifest_doc_bytes,
        }
    }
}

// ---- values --------------------------------------------------------------------------------------

/// A health token: 32 bytes, 64 lowercase hex characters on the wire. `Debug` does not show it.
#[derive(Clone, PartialEq, Eq)]
pub struct Token([u8; 32]);

impl Token {
    /// Wraps raw token bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Token {
        Token(bytes)
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses 64 lowercase hex characters.
    pub fn parse(text: &str) -> Option<Token> {
        hex_decode_array::<32>(text).ok().map(Token)
    }

    /// 64 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(..)")
    }
}

/// One document a `stage_begin` declares: its kind and its size in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentDecl {
    /// The kind.
    pub kind: DocumentKind,
    /// The size in bytes (1 to the kind's cap).
    pub bytes: u64,
}

/// Checks the count rule and the caps of a `stage_begin`'s documents: roots first (at most
/// [`MAX_ROOTS`]), then exactly one `keys`, one `feed` and one `manifest`, in that order; every size
/// from 1 to FORMAT 4's cap for its kind ([`Limits::V1`]).
pub fn check_documents(documents: &[DocumentDecl]) -> Result<(), &'static str> {
    let mut roots = 0usize;
    let mut last: Option<DocumentKind> = None;
    for d in documents {
        if d.bytes == 0 || d.bytes > d.kind.cap(&Limits::V1) {
            return Err("a document size is outside its cap");
        }
        if d.kind == DocumentKind::Root {
            if last.is_some_and(|k| k != DocumentKind::Root) {
                return Err("a root after the other documents");
            }
            roots += 1;
            if roots > MAX_ROOTS {
                return Err("more than 16 roots");
            }
        } else {
            // Keys follows the roots (or nothing), feed follows keys, manifest follows feed.
            let want = last.map_or(1, |k| k.rank() + 1).max(1);
            if d.kind.rank() != want {
                return Err("documents out of order or repeated");
            }
        }
        last = Some(d.kind);
    }
    if last != Some(DocumentKind::Manifest) {
        return Err("keys, feed and manifest are each required once");
    }
    Ok(())
}

/// What `pending` reports in a `status` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingStatus {
    /// The pending version.
    pub version: Version,
    /// Start attempts counted so far.
    pub attempts: u64,
}

/// The `status` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    /// The current version.
    pub current: Version,
    /// The previous version, if any.
    pub previous: Option<Version>,
    /// The version pending its health check, if any.
    pub pending: Option<PendingStatus>,
    /// The staged version, if any.
    pub staged: Option<Version>,
    /// The version of the running service binary.
    pub service: Version,
    /// Whether an administrator's policy disables self-update.
    pub self_update_disabled: bool,
}

/// The `attempt` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptAnswer {
    /// A supervision lease is running; nothing changed.
    Supervised,
    /// The attempt was counted; the token lets this start confirm.
    Counted {
        /// Attempts counted so far.
        attempts: u64,
        /// The fresh token.
        token: Token,
    },
    /// The attempt limit was reached; the version was rolled back.
    RolledBack {
        /// The current version after the rollback.
        current: Version,
    },
    /// The version is not pending.
    NotPending,
}

/// A request of version 1 (the `app` member travels beside it, [`RequestMsg`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Report the machine record's state.
    Status,
    /// Start a stage session with the signed documents that follow as data.
    StageBegin {
        /// The channel.
        channel: Channel,
        /// The documents, in order ([`check_documents`]).
        documents: Vec<DocumentDecl>,
    },
    /// Upload one object that follows as data.
    Put {
        /// Pack or frame.
        kind: ObjectKind,
        /// Its SHA-256.
        sha256: Sha256Digest,
        /// Its size in bytes (at least 1).
        size: u64,
    },
    /// Build the staged tree.
    StageCommit,
    /// Make the staged version current and pending.
    Apply {
        /// The staged version.
        version: Version,
    },
    /// A start of the pending version without a token.
    Attempt {
        /// The pending version.
        version: Version,
    },
    /// The pending version is healthy.
    Confirm {
        /// The pending version.
        version: Version,
        /// The token.
        token: Token,
    },
    /// The pending version failed; go back.
    Rollback {
        /// The pending version.
        version: Version,
        /// The token.
        token: Token,
    },
}

impl Request {
    /// The number of data bytes that follow this request: the documents' total for
    /// `stage_begin`, the size for `put`, 0 otherwise.
    pub fn data_len(&self) -> u64 {
        match self {
            Request::StageBegin { documents, .. } => documents.iter().map(|d| d.bytes).sum(),
            Request::Put { size, .. } => *size,
            _ => 0,
        }
    }

    /// The wire name.
    pub fn name(&self) -> &'static str {
        match self {
            Request::Status => "status",
            Request::StageBegin { .. } => "stage_begin",
            Request::Put { .. } => "put",
            Request::StageCommit => "stage_commit",
            Request::Apply { .. } => "apply",
            Request::Attempt { .. } => "attempt",
            Request::Confirm { .. } => "confirm",
            Request::Rollback { .. } => "rollback",
        }
    }
}

/// A request with the app id it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMsg {
    /// The app the request is for.
    pub app: AppId,
    /// The request.
    pub request: Request,
}

/// An answer of version 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The `status` answer.
    Status(StatusReport),
    /// `stage_begin`: the documents verified; this version will be staged.
    StageReady {
        /// The version the engine selected.
        version: Version,
    },
    /// `stage_begin`: the documents verified; no update is offered.
    NoUpdate,
    /// `put`: the object was accepted.
    PutOk,
    /// `stage_commit`: work done so far.
    Progress {
        /// Units done.
        done: u64,
        /// Units in total (`done` ≤ `total`).
        total: u64,
    },
    /// `stage_commit`: the version is staged.
    Staged {
        /// The staged version.
        version: Version,
    },
    /// `stage_commit`: these release paths still need an object.
    NeedFetch {
        /// At most [`MAX_NEED_FETCH`] paths.
        paths: Vec<RelPath>,
        /// Whether more paths need one.
        more: bool,
    },
    /// `apply`: the version is current and pending.
    Applied {
        /// The applied version.
        version: Version,
        /// The one-time token.
        token: Token,
    },
    /// The `attempt` answer.
    Attempt(AttemptAnswer),
    /// `confirm`: the version is healthy.
    Confirmed,
    /// `confirm`: nothing is pending.
    NothingPending,
    /// `rollback`: the previous version is current again.
    RolledBack {
        /// The current version.
        current: Version,
    },
    /// The request was refused.
    Error {
        /// Why.
        code: ErrorCode,
        /// For `verify_failed` only (required there, absent otherwise).
        class: Option<VerifyClass>,
    },
}

impl Response {
    /// An `error` answer without a class.
    pub fn error(code: ErrorCode) -> Response {
        Response::Error { code, class: None }
    }

    /// The wire name.
    pub fn name(&self) -> &'static str {
        match self {
            Response::Status(_) => "status",
            Response::StageReady { .. } => "stage_ready",
            Response::NoUpdate => "no_update",
            Response::PutOk => "put_ok",
            Response::Progress { .. } => "progress",
            Response::Staged { .. } => "staged",
            Response::NeedFetch { .. } => "need_fetch",
            Response::Applied { .. } => "applied",
            Response::Attempt(_) => "attempt",
            Response::Confirmed => "confirmed",
            Response::NothingPending => "nothing_pending",
            Response::RolledBack { .. } => "rolled_back",
            Response::Error { .. } => "error",
        }
    }
}

/// The client's hello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHello {
    /// The lowest version the client speaks.
    pub min: u32,
    /// The highest version the client speaks.
    pub max: u32,
}

/// The server's hello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerHello {
    /// The version both speak.
    Version(u32),
    /// No common version; the server's range. The server closes after it.
    Unsupported {
        /// The server's lowest version.
        min: u32,
        /// The server's highest version.
        max: u32,
    },
}

/// The server's answer to `client` when it speaks `min..=max`: the highest common version, or
/// `unsupported` with the server's range. `min > max` in the client's hello is malformed.
pub fn negotiate(client: ClientHello, min: u32, max: u32) -> Result<ServerHello, ServiceError> {
    if client.min > client.max {
        return Err(ServiceError::Malformed("hello: min above max"));
    }
    let high = client.max.min(max);
    if high >= client.min.max(min) {
        Ok(ServerHello::Version(high))
    } else {
        Ok(ServerHello::Unsupported { min, max })
    }
}

// ---- encoding ------------------------------------------------------------------------------------

/// A JSON object written member by member in call order.
struct Obj(String);

impl Obj {
    fn new(ty: &str) -> Obj {
        let mut o = Obj(String::from("{"));
        o.key("type");
        o.0.push_str(&json_str(ty));
        o
    }

    fn key(&mut self, key: &str) {
        if self.0.len() > 1 {
            self.0.push(',');
        }
        self.0.push_str(&json_str(key));
        self.0.push(':');
    }

    fn str(mut self, key: &str, value: &str) -> Obj {
        self.key(key);
        self.0.push_str(&json_str(value));
        self
    }

    fn opt_str(mut self, key: &str, value: Option<&str>) -> Obj {
        self.key(key);
        match value {
            Some(v) => self.0.push_str(&json_str(v)),
            None => self.0.push_str("null"),
        }
        self
    }

    fn uint(mut self, key: &str, value: u64) -> Result<Obj, ServiceError> {
        if value > MAX_JSON_INT {
            return Err(ServiceError::Unencodable("an integer above 2^53 - 1"));
        }
        self.key(key);
        self.0.push_str(&value.to_string());
        Ok(self)
    }

    fn boolean(mut self, key: &str, value: bool) -> Obj {
        self.key(key);
        self.0.push_str(if value { "true" } else { "false" });
        self
    }

    fn raw(mut self, key: &str, json: &str) -> Obj {
        self.key(key);
        self.0.push_str(json);
        self
    }

    fn finish(mut self) -> Result<Vec<u8>, ServiceError> {
        self.0.push('}');
        if self.0.len() > MAX_MESSAGE {
            return Err(ServiceError::Unencodable("a message over 65,536 bytes"));
        }
        Ok(self.0.into_bytes())
    }
}

fn json_str(text: &str) -> String {
    // A string always serialises.
    serde_json::to_string(text).unwrap_or_else(|_| String::from("\"\""))
}

impl ClientHello {
    /// The message body.
    pub fn encode(&self) -> Result<Vec<u8>, ServiceError> {
        Obj::new("hello")
            .uint("min", u64::from(self.min))?
            .uint("max", u64::from(self.max))?
            .finish()
    }

    /// The client hello in `body`.
    pub fn decode(body: &[u8]) -> Result<ClientHello, ServiceError> {
        let (ty, mut f) = open(body)?;
        if ty != "hello" {
            return Err(ServiceError::Malformed("expected the client's hello"));
        }
        let min = f.u32("min")?;
        let max = f.u32("max")?;
        f.done()?;
        if min > max {
            return Err(ServiceError::Malformed("hello: min above max"));
        }
        Ok(ClientHello { min, max })
    }
}

impl ServerHello {
    /// The message body.
    pub fn encode(&self) -> Result<Vec<u8>, ServiceError> {
        match *self {
            ServerHello::Version(v) => Obj::new("hello").uint("version", u64::from(v))?.finish(),
            ServerHello::Unsupported { min, max } => Obj::new("unsupported")
                .uint("min", u64::from(min))?
                .uint("max", u64::from(max))?
                .finish(),
        }
    }

    /// The server hello in `body`.
    pub fn decode(body: &[u8]) -> Result<ServerHello, ServiceError> {
        let (ty, mut f) = open(body)?;
        let hello = match ty.as_str() {
            "hello" => ServerHello::Version(f.u32("version")?),
            "unsupported" => {
                let min = f.u32("min")?;
                let max = f.u32("max")?;
                if min > max {
                    return Err(ServiceError::Malformed("unsupported: min above max"));
                }
                ServerHello::Unsupported { min, max }
            }
            _ => return Err(ServiceError::Malformed("expected the server's hello")),
        };
        f.done()?;
        Ok(hello)
    }
}

fn request_obj(ty: &str, app: &AppId) -> Obj {
    Obj::new(ty).str("app", app.as_str())
}

impl RequestMsg {
    /// The message body.
    pub fn encode(&self) -> Result<Vec<u8>, ServiceError> {
        let o = request_obj(self.request.name(), &self.app);
        match &self.request {
            Request::Status | Request::StageCommit => o.finish(),
            Request::StageBegin { channel, documents } => {
                check_documents(documents).map_err(ServiceError::Unencodable)?;
                let mut list = String::from("[");
                for (i, d) in documents.iter().enumerate() {
                    if i > 0 {
                        list.push(',');
                    }
                    let item = Obj::new_plain()
                        .str("kind", d.kind.as_str())
                        .uint("bytes", d.bytes)?;
                    list.push_str(&item.close());
                }
                list.push(']');
                o.str("channel", channel.as_str())
                    .raw("documents", &list)
                    .finish()
            }
            Request::Put { kind, sha256, size } => {
                if *size == 0 {
                    return Err(ServiceError::Unencodable("an empty object"));
                }
                o.str("kind", kind.as_str())
                    .str("sha256", &sha256.to_hex())
                    .uint("size", *size)?
                    .finish()
            }
            Request::Apply { version } | Request::Attempt { version } => {
                o.str("version", &version.to_string()).finish()
            }
            Request::Confirm { version, token } | Request::Rollback { version, token } => o
                .str("version", &version.to_string())
                .str("token", &token.to_hex())
                .finish(),
        }
    }

    /// The request in `body`.
    pub fn decode(body: &[u8]) -> Result<RequestMsg, ServiceError> {
        let (ty, mut f) = open(body)?;
        let app = f.app()?;
        let request = match ty.as_str() {
            "status" => Request::Status,
            "stage_commit" => Request::StageCommit,
            "stage_begin" => {
                let channel = f.channel("channel")?;
                let Value::Array(items) = f.take("documents")? else {
                    return Err(ServiceError::Malformed("documents is not a list"));
                };
                if items.len() > MAX_ROOTS + 3 {
                    return Err(ServiceError::Malformed("too many documents"));
                }
                let mut documents = Vec::with_capacity(items.len());
                for item in items {
                    let mut d = Fields::of(item)?;
                    let kind = d.name("kind", DocumentKind::from_wire)?;
                    let bytes = d.uint("bytes")?;
                    d.done()?;
                    documents.push(DocumentDecl { kind, bytes });
                }
                check_documents(&documents).map_err(ServiceError::Malformed)?;
                Request::StageBegin { channel, documents }
            }
            "put" => {
                let kind = f.name("kind", ObjectKind::from_wire)?;
                let sha256 = f.digest("sha256")?;
                let size = f.uint("size")?;
                if size == 0 {
                    return Err(ServiceError::Malformed("an empty object"));
                }
                Request::Put { kind, sha256, size }
            }
            "apply" => Request::Apply {
                version: f.version("version")?,
            },
            "attempt" => Request::Attempt {
                version: f.version("version")?,
            },
            "confirm" => Request::Confirm {
                version: f.version("version")?,
                token: f.token("token")?,
            },
            "rollback" => Request::Rollback {
                version: f.version("version")?,
                token: f.token("token")?,
            },
            _ => return Err(ServiceError::Malformed("unknown request type")),
        };
        f.done()?;
        Ok(RequestMsg { app, request })
    }
}

impl Obj {
    fn new_plain() -> Obj {
        Obj(String::from("{"))
    }

    fn close(mut self) -> String {
        self.0.push('}');
        self.0
    }
}

fn opt_version(v: Option<&Version>) -> Option<String> {
    v.map(Version::to_string)
}

impl Response {
    /// The message body.
    pub fn encode(&self) -> Result<Vec<u8>, ServiceError> {
        let o = Obj::new(self.name());
        match self {
            Response::NoUpdate
            | Response::PutOk
            | Response::Confirmed
            | Response::NothingPending => o.finish(),
            Response::Status(s) => {
                let pending = match &s.pending {
                    Some(p) => Obj::new_plain()
                        .str("version", &p.version.to_string())
                        .uint("attempts", p.attempts)?
                        .close(),
                    None => String::from("null"),
                };
                o.str("current", &s.current.to_string())
                    .opt_str("previous", opt_version(s.previous.as_ref()).as_deref())
                    .raw("pending", &pending)
                    .opt_str("staged", opt_version(s.staged.as_ref()).as_deref())
                    .str("service", &s.service.to_string())
                    .boolean("self_update_disabled", s.self_update_disabled)
                    .finish()
            }
            Response::StageReady { version } | Response::Staged { version } => {
                o.str("version", &version.to_string()).finish()
            }
            Response::Progress { done, total } => {
                if done > total {
                    return Err(ServiceError::Unencodable("progress done above total"));
                }
                o.uint("done", *done)?.uint("total", *total)?.finish()
            }
            Response::NeedFetch { paths, more } => {
                if paths.len() > MAX_NEED_FETCH {
                    return Err(ServiceError::Unencodable("more than 64 paths"));
                }
                let list: Vec<String> = paths.iter().map(|p| json_str(p.as_str())).collect();
                o.raw("paths", &format!("[{}]", list.join(",")))
                    .boolean("more", *more)
                    .finish()
            }
            Response::Applied { version, token } => o
                .str("version", &version.to_string())
                .str("token", &token.to_hex())
                .finish(),
            Response::Attempt(a) => match a {
                AttemptAnswer::Supervised => o.str("outcome", "supervised").finish(),
                AttemptAnswer::Counted { attempts, token } => o
                    .str("outcome", "counted")
                    .uint("attempts", *attempts)?
                    .str("token", &token.to_hex())
                    .finish(),
                AttemptAnswer::RolledBack { current } => o
                    .str("outcome", "rolled_back")
                    .str("current", &current.to_string())
                    .finish(),
                AttemptAnswer::NotPending => o.str("outcome", "not_pending").finish(),
            },
            Response::RolledBack { current } => o.str("current", &current.to_string()).finish(),
            Response::Error { code, class } => {
                let o = o.str("code", code.as_str());
                match (code, class) {
                    (ErrorCode::VerifyFailed, Some(c)) => o.str("class", c.as_str()).finish(),
                    (ErrorCode::VerifyFailed, None) => {
                        Err(ServiceError::Unencodable("verify_failed without a class"))
                    }
                    (_, None) => o.finish(),
                    (_, Some(_)) => Err(ServiceError::Unencodable("a class on another code")),
                }
            }
        }
    }

    /// The answer in `body`.
    pub fn decode(body: &[u8]) -> Result<Response, ServiceError> {
        let (ty, mut f) = open(body)?;
        let response = match ty.as_str() {
            "status" => {
                let current = f.version("current")?;
                let previous = f.opt_version("previous")?;
                let pending = match f.take("pending")? {
                    Value::Null => None,
                    other => {
                        let mut p = Fields::of(other)?;
                        let version = p.version("version")?;
                        let attempts = p.uint("attempts")?;
                        p.done()?;
                        Some(PendingStatus { version, attempts })
                    }
                };
                let staged = f.opt_version("staged")?;
                let service = f.version("service")?;
                let self_update_disabled = f.boolean("self_update_disabled")?;
                Response::Status(StatusReport {
                    current,
                    previous,
                    pending,
                    staged,
                    service,
                    self_update_disabled,
                })
            }
            "stage_ready" => Response::StageReady {
                version: f.version("version")?,
            },
            "no_update" => Response::NoUpdate,
            "put_ok" => Response::PutOk,
            "progress" => {
                let done = f.uint("done")?;
                let total = f.uint("total")?;
                if done > total {
                    return Err(ServiceError::Malformed("progress done above total"));
                }
                Response::Progress { done, total }
            }
            "staged" => Response::Staged {
                version: f.version("version")?,
            },
            "need_fetch" => {
                let Value::Array(items) = f.take("paths")? else {
                    return Err(ServiceError::Malformed("paths is not a list"));
                };
                if items.len() > MAX_NEED_FETCH {
                    return Err(ServiceError::Malformed("more than 64 paths"));
                }
                let mut paths = Vec::with_capacity(items.len());
                for item in items {
                    let Value::String(s) = item else {
                        return Err(ServiceError::Malformed("a path is not a string"));
                    };
                    paths.push(
                        RelPath::parse(&s)
                            .map_err(|_| ServiceError::Malformed("a path the rules refuse"))?,
                    );
                }
                let more = f.boolean("more")?;
                Response::NeedFetch { paths, more }
            }
            "applied" => Response::Applied {
                version: f.version("version")?,
                token: f.token("token")?,
            },
            "attempt" => {
                let outcome = f.string("outcome")?;
                Response::Attempt(match outcome.as_str() {
                    "supervised" => AttemptAnswer::Supervised,
                    "counted" => AttemptAnswer::Counted {
                        attempts: f.uint("attempts")?,
                        token: f.token("token")?,
                    },
                    "rolled_back" => AttemptAnswer::RolledBack {
                        current: f.version("current")?,
                    },
                    "not_pending" => AttemptAnswer::NotPending,
                    _ => return Err(ServiceError::Malformed("unknown attempt outcome")),
                })
            }
            "confirmed" => Response::Confirmed,
            "nothing_pending" => Response::NothingPending,
            "rolled_back" => Response::RolledBack {
                current: f.version("current")?,
            },
            "error" => {
                let code = f.name("code", ErrorCode::from_wire)?;
                let class = if code == ErrorCode::VerifyFailed {
                    Some(f.name("class", VerifyClass::from_wire)?)
                } else {
                    None
                };
                Response::Error { code, class }
            }
            _ => return Err(ServiceError::Malformed("unknown answer type")),
        };
        f.done()?;
        Ok(response)
    }
}

// ---- decoding helpers ----------------------------------------------------------------------------

/// The members of one JSON object, taken one by one; [`Fields::done`] refuses what is left.
struct Fields(Map<String, Value>);

fn open(body: &[u8]) -> Result<(String, Fields), ServiceError> {
    check_strict(body).map_err(|_| ServiceError::Malformed("not strict JSON"))?;
    let value: Value =
        serde_json::from_slice(body).map_err(|_| ServiceError::Malformed("not strict JSON"))?;
    let mut f = Fields::of(value)?;
    let ty = f.string("type")?;
    Ok((ty, f))
}

impl Fields {
    fn of(value: Value) -> Result<Fields, ServiceError> {
        match value {
            Value::Object(m) => Ok(Fields(m)),
            _ => Err(ServiceError::Malformed("not an object")),
        }
    }

    fn take(&mut self, key: &'static str) -> Result<Value, ServiceError> {
        self.0
            .remove(key)
            .ok_or(ServiceError::Malformed("a member is missing"))
    }

    fn string(&mut self, key: &'static str) -> Result<String, ServiceError> {
        match self.take(key)? {
            Value::String(s) => Ok(s),
            _ => Err(ServiceError::Malformed("a member has the wrong type")),
        }
    }

    fn uint(&mut self, key: &'static str) -> Result<u64, ServiceError> {
        let Value::Number(n) = self.take(key)? else {
            return Err(ServiceError::Malformed("a member has the wrong type"));
        };
        match n.as_u64() {
            Some(v) if v <= MAX_JSON_INT => Ok(v),
            _ => Err(ServiceError::Malformed("an integer out of range")),
        }
    }

    fn u32(&mut self, key: &'static str) -> Result<u32, ServiceError> {
        u32::try_from(self.uint(key)?)
            .map_err(|_| ServiceError::Malformed("an integer out of range"))
    }

    fn boolean(&mut self, key: &'static str) -> Result<bool, ServiceError> {
        match self.take(key)? {
            Value::Bool(b) => Ok(b),
            _ => Err(ServiceError::Malformed("a member has the wrong type")),
        }
    }

    fn name<T>(&mut self, key: &'static str, of: fn(&str) -> Option<T>) -> Result<T, ServiceError> {
        of(&self.string(key)?).ok_or(ServiceError::Malformed("a name outside its closed set"))
    }

    fn version(&mut self, key: &'static str) -> Result<Version, ServiceError> {
        Version::parse(&self.string(key)?)
            .map_err(|_| ServiceError::Malformed("a version the rules refuse"))
    }

    fn opt_version(&mut self, key: &'static str) -> Result<Option<Version>, ServiceError> {
        match self.take(key)? {
            Value::Null => Ok(None),
            Value::String(s) => Version::parse(&s)
                .map(Some)
                .map_err(|_| ServiceError::Malformed("a version the rules refuse")),
            _ => Err(ServiceError::Malformed("a member has the wrong type")),
        }
    }

    fn app(&mut self) -> Result<AppId, ServiceError> {
        AppId::parse(&self.string("app")?)
            .map_err(|_| ServiceError::Malformed("an app id the rules refuse"))
    }

    fn channel(&mut self, key: &'static str) -> Result<Channel, ServiceError> {
        Channel::parse(&self.string(key)?)
            .map_err(|_| ServiceError::Malformed("a channel the rules refuse"))
    }

    fn digest(&mut self, key: &'static str) -> Result<Sha256Digest, ServiceError> {
        Sha256Digest::from_hex(&self.string(key)?)
            .map_err(|_| ServiceError::Malformed("a digest that is not 64 lowercase hex"))
    }

    fn token(&mut self, key: &'static str) -> Result<Token, ServiceError> {
        Token::parse(&self.string(key)?).ok_or(ServiceError::Malformed(
            "a token that is not 64 lowercase hex",
        ))
    }

    fn done(self) -> Result<(), ServiceError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ServiceError::Malformed("an unknown member"))
        }
    }
}

// ---- frames --------------------------------------------------------------------------------------

/// One frame read from the channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A message body (strict JSON, not yet decoded).
    Message(Vec<u8>),
    /// A data body.
    Data(Vec<u8>),
}

fn io_error(kind: ErrorKind) -> ServiceError {
    match kind {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => ServiceError::Timeout,
        k => ServiceError::Io(k),
    }
}

/// Reads until `buf` is full. `Ok(n)` with `n < buf.len()` means the channel ended after `n` bytes.
fn fill<R: Read + ?Sized>(input: &mut R, buf: &mut [u8]) -> Result<usize, ServiceError> {
    let mut got = 0;
    while got < buf.len() {
        match input.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(io_error(e.kind())),
        }
    }
    Ok(got)
}

/// Reads one frame. `Ok(None)`: the channel ended between frames. The length and the kind are
/// checked before the body is allocated; the end of the channel inside a frame is malformed.
pub fn read_frame<R: Read + ?Sized>(input: &mut R) -> Result<Option<Frame>, ServiceError> {
    let mut head = [0u8; 5];
    match fill(input, &mut head[..4])? {
        0 => return Ok(None),
        4 => {}
        _ => return Err(ServiceError::Malformed("the channel ended inside a frame")),
    }
    let n = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
    if n == 0 {
        return Err(ServiceError::Malformed("a frame without a kind"));
    }
    if n > MAX_DATA + 1 {
        return Err(ServiceError::Malformed("a frame over its cap"));
    }
    if fill(input, &mut head[4..])? < 1 {
        return Err(ServiceError::Malformed("the channel ended inside a frame"));
    }
    let len = n - 1;
    let cap = match head[4] {
        KIND_MESSAGE => MAX_MESSAGE,
        KIND_DATA => MAX_DATA,
        _ => return Err(ServiceError::Malformed("an unknown frame kind")),
    };
    if len == 0 {
        return Err(ServiceError::Malformed("an empty frame body"));
    }
    if len > cap {
        return Err(ServiceError::Malformed("a frame over its cap"));
    }
    let mut body = vec![0u8; len];
    if fill(input, &mut body)? < len {
        return Err(ServiceError::Malformed("the channel ended inside a frame"));
    }
    Ok(Some(if head[4] == KIND_MESSAGE {
        Frame::Message(body)
    } else {
        Frame::Data(body)
    }))
}

/// The bytes of one frame of `kind` around `body`, or why it cannot be written.
pub fn encode_frame(kind: u8, body: &[u8]) -> Result<Vec<u8>, ServiceError> {
    let cap = match kind {
        KIND_MESSAGE => MAX_MESSAGE,
        KIND_DATA => MAX_DATA,
        _ => return Err(ServiceError::Unencodable("an unknown frame kind")),
    };
    if body.is_empty() || body.len() > cap {
        return Err(ServiceError::Unencodable("a frame body outside its bounds"));
    }
    let mut frame = Vec::with_capacity(5 + body.len());
    frame.extend_from_slice(&((body.len() + 1) as u32).to_le_bytes());
    frame.push(kind);
    frame.extend_from_slice(body);
    Ok(frame)
}

/// Writes one frame in one `write_all`, then flushes.
pub fn write_frame<W: Write + ?Sized>(
    out: &mut W,
    kind: u8,
    body: &[u8],
) -> Result<(), ServiceError> {
    let frame = encode_frame(kind, body)?;
    out.write_all(&frame)
        .and_then(|()| out.flush())
        .map_err(|e| io_error(e.kind()))
}

// ---- server session ------------------------------------------------------------------------------

/// The server's side of one connection: the hello (with the 5 s deadline), then requests (each
/// frame with the 30 s deadline), their data and the answers. Refused input answers
/// `error{malformed}` and ends the session; a timed-out read answers `error{timeout}` and ends it.
pub struct ServerSession<D: Duplex> {
    io: D,
    app: AppId,
    version: u32,
    readable: bool,
    writable: bool,
}

impl<D: Duplex> ServerSession<D> {
    /// Reads the client's hello and answers it for the app `app`. No common version answers
    /// `unsupported` and returns [`ServiceError::Unsupported`] with the client's range; a malformed
    /// hello closes without an answer.
    pub fn accept(io: D, app: AppId) -> Result<ServerSession<D>, ServiceError> {
        Self::accept_range(io, app, PROTOCOL_MIN, PROTOCOL_MAX)
    }

    /// [`ServerSession::accept`] speaking only `min..=max` (tests: a server of an older build).
    pub fn accept_range(
        mut io: D,
        app: AppId,
        min: u32,
        max: u32,
    ) -> Result<ServerSession<D>, ServiceError> {
        io.set_read_deadline(Some(SERVER_HELLO_DEADLINE))
            .map_err(|e| ServiceError::Io(e.kind()))?;
        let hello = match read_frame(&mut io)? {
            None => return Err(ServiceError::Closed),
            Some(Frame::Data(_)) => return Err(ServiceError::Malformed("data before the hello")),
            Some(Frame::Message(body)) => ClientHello::decode(&body)?,
        };
        let answer = negotiate(hello, min.max(PROTOCOL_MIN), max.min(PROTOCOL_MAX))?;
        write_frame(&mut io, KIND_MESSAGE, &answer.encode()?)?;
        match answer {
            ServerHello::Version(version) => Ok(ServerSession {
                io,
                app,
                version,
                readable: true,
                writable: true,
            }),
            ServerHello::Unsupported { .. } => Err(ServiceError::Unsupported {
                min: hello.min,
                max: hello.max,
            }),
        }
    }

    /// The negotiated version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Ends the session after answering `error{code}` (best effort for the answer).
    fn end_with(&mut self, code: ErrorCode) {
        if self.writable
            && let Ok(body) = Response::error(code).encode()
        {
            let _ = write_frame(&mut self.io, KIND_MESSAGE, &body);
        }
        self.readable = false;
        self.writable = false;
    }

    fn fail(&mut self, err: ServiceError) -> ServiceError {
        match err {
            ServiceError::Malformed(_) => self.end_with(ErrorCode::Malformed),
            ServiceError::Timeout => self.end_with(ErrorCode::Timeout),
            _ => {
                self.readable = false;
                self.writable = false;
            }
        }
        err
    }

    fn frame(&mut self) -> Result<Option<Frame>, ServiceError> {
        self.io
            .set_read_deadline(Some(SERVER_FRAME_DEADLINE))
            .map_err(|e| ServiceError::Io(e.kind()))?;
        read_frame(&mut self.io)
    }

    /// The next request. `Ok(None)`: the client closed the connection between requests. A request
    /// for another app answers `error{wrong_app}` and ends the session.
    pub fn next_request(&mut self) -> Result<Option<Request>, ServiceError> {
        if !self.readable {
            return Err(ServiceError::Ended);
        }
        let msg = match self.frame() {
            Ok(None) => {
                self.readable = false;
                return Ok(None);
            }
            Ok(Some(Frame::Data(_))) => {
                return Err(self.fail(ServiceError::Malformed("data where a request belongs")));
            }
            Ok(Some(Frame::Message(body))) => match RequestMsg::decode(&body) {
                Ok(msg) => msg,
                Err(e) => return Err(self.fail(e)),
            },
            Err(e) => return Err(self.fail(e)),
        };
        if msg.app != self.app {
            self.end_with(ErrorCode::WrongApp);
            return Err(ServiceError::WrongApp);
        }
        // A kind a version does not know is a member value outside its closed set.
        if let Request::Put {
            kind: ObjectKind::Patch,
            ..
        } = msg.request
            && self.version < PROTOCOL_PATCH
        {
            return Err(self.fail(ServiceError::Malformed("put of a patch below version 2")));
        }
        Ok(Some(msg.request))
    }

    /// Reads exactly `total` bytes of data frames into `sink`, one frame at a time. A message
    /// frame in between, the end of the channel or a frame past `total` is malformed. A failing
    /// sink returns [`ServiceError::Sink`]; the session then reads nothing more but may still
    /// answer once.
    pub fn read_data<W: Write + ?Sized>(
        &mut self,
        total: u64,
        sink: &mut W,
    ) -> Result<(), ServiceError> {
        if !self.readable {
            return Err(ServiceError::Ended);
        }
        let mut left = total;
        while left > 0 {
            let body = match self.frame() {
                Ok(Some(Frame::Data(body))) => body,
                Ok(Some(Frame::Message(_))) => {
                    return Err(self.fail(ServiceError::Malformed("a message inside data")));
                }
                Ok(None) => return Err(self.fail(ServiceError::Malformed("the data ended early"))),
                Err(e) => return Err(self.fail(e)),
            };
            if body.len() as u64 > left {
                return Err(self.fail(ServiceError::Malformed("more data than declared")));
            }
            if let Err(e) = sink.write_all(&body) {
                self.readable = false;
                return Err(ServiceError::Sink(e.kind()));
            }
            left -= body.len() as u64;
        }
        Ok(())
    }

    /// Sends one answer. After a failed sink this is the session's last write.
    pub fn reply(&mut self, response: &Response) -> Result<(), ServiceError> {
        if !self.writable {
            return Err(ServiceError::Ended);
        }
        let body = response.encode()?;
        if !self.readable {
            self.writable = false;
        }
        write_frame(&mut self.io, KIND_MESSAGE, &body).inspect_err(|_| {
            self.readable = false;
            self.writable = false;
        })
    }

    /// The channel back.
    pub fn into_inner(self) -> D {
        self.io
    }
}

// ---- client session ------------------------------------------------------------------------------

/// The client's read deadlines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientTimeouts {
    /// For the server's hello.
    pub hello: Option<Duration>,
    /// For each later frame from the server (every `progress` restarts it).
    pub answer: Option<Duration>,
}

/// What `stage_begin` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageBegun {
    /// This version will be staged.
    Ready(Version),
    /// No update is offered.
    NoUpdate,
}

/// What `stage_commit` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// The version is staged.
    Staged(Version),
    /// These release paths still need an object.
    NeedFetch {
        /// At most [`MAX_NEED_FETCH`] paths.
        paths: Vec<RelPath>,
        /// Whether more need one.
        more: bool,
    },
}

/// What `confirm` answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmAnswer {
    /// The version is healthy.
    Confirmed,
    /// Nothing is pending.
    NothingPending,
}

/// One document `stage_begin` sends.
#[derive(Debug, Clone, Copy)]
pub struct OutgoingDocument<'a> {
    /// Its kind.
    pub kind: DocumentKind,
    /// Its bytes.
    pub bytes: &'a [u8],
}

/// The client's side of one connection: the hello, then one method per request. An `error` answer
/// is [`ServiceError::Answered`]; anything the protocol refuses ends the session.
pub struct ClientSession<D: Duplex> {
    io: D,
    app: AppId,
    version: u32,
    timeouts: ClientTimeouts,
    open: bool,
}

impl<D: Duplex> ClientSession<D> {
    /// Sends the hello for versions [`PROTOCOL_MIN`]..=[`PROTOCOL_MAX`] and reads the server's.
    pub fn connect(
        io: D,
        app: AppId,
        timeouts: ClientTimeouts,
    ) -> Result<ClientSession<D>, ServiceError> {
        Self::connect_range(io, app, timeouts, PROTOCOL_MIN, PROTOCOL_MAX)
    }

    /// [`ClientSession::connect`] offering `min..=max` (tests; versions above
    /// [`PROTOCOL_MAX`] are not implemented, and a server choosing one is malformed).
    pub fn connect_range(
        mut io: D,
        app: AppId,
        timeouts: ClientTimeouts,
        min: u32,
        max: u32,
    ) -> Result<ClientSession<D>, ServiceError> {
        let body = ClientHello { min, max }.encode()?;
        write_frame(&mut io, KIND_MESSAGE, &body)?;
        io.set_read_deadline(timeouts.hello)
            .map_err(|e| ServiceError::Io(e.kind()))?;
        let hello = match read_frame(&mut io)? {
            None => return Err(ServiceError::Closed),
            Some(Frame::Data(_)) => return Err(ServiceError::Malformed("data before the hello")),
            Some(Frame::Message(body)) => ServerHello::decode(&body)?,
        };
        match hello {
            ServerHello::Version(v) if v >= min.max(PROTOCOL_MIN) && v <= max.min(PROTOCOL_MAX) => {
                Ok(ClientSession {
                    io,
                    app,
                    version: v,
                    timeouts,
                    open: true,
                })
            }
            ServerHello::Version(_) => Err(ServiceError::Malformed("a version not offered")),
            ServerHello::Unsupported { min, max } => Err(ServiceError::Unsupported { min, max }),
        }
    }

    /// The negotiated version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The channel back.
    pub fn into_inner(self) -> D {
        self.io
    }

    fn end(&mut self, err: ServiceError) -> ServiceError {
        self.open = false;
        err
    }

    fn send(&mut self, request: Request) -> Result<(), ServiceError> {
        if !self.open {
            return Err(ServiceError::Ended);
        }
        let body = RequestMsg {
            app: self.app.clone(),
            request,
        }
        .encode()?;
        write_frame(&mut self.io, KIND_MESSAGE, &body).map_err(|e| self.end(e))
    }

    /// One answer; `error` becomes [`ServiceError::Answered`].
    fn answer(&mut self) -> Result<Response, ServiceError> {
        if let Err(e) = self.io.set_read_deadline(self.timeouts.answer) {
            return Err(self.end(ServiceError::Io(e.kind())));
        }
        let response = match read_frame(&mut self.io) {
            Ok(Some(Frame::Message(body))) => Response::decode(&body).map_err(|e| self.end(e))?,
            Ok(Some(Frame::Data(_))) => {
                return Err(self.end(ServiceError::Malformed("data from the server")));
            }
            Ok(None) => return Err(self.end(ServiceError::Closed)),
            Err(e) => return Err(self.end(e)),
        };
        if let Response::Error { code, class } = response {
            if matches!(
                code,
                ErrorCode::Malformed | ErrorCode::WrongApp | ErrorCode::Timeout
            ) {
                self.open = false;
            }
            return Err(ServiceError::Answered { code, class });
        }
        Ok(response)
    }

    fn unexpected(&mut self) -> ServiceError {
        self.end(ServiceError::Malformed(
            "an answer that does not fit the request",
        ))
    }

    /// Streams `size` bytes from `source` as data frames. A failed write reads one answer in case
    /// the server refused early; a short source ends the session.
    fn stream(&mut self, source: &mut dyn Read, size: u64) -> Result<(), ServiceError> {
        let mut left = size;
        let mut buf = vec![0u8; MAX_DATA.min(usize::try_from(size).unwrap_or(MAX_DATA))];
        while left > 0 {
            let n = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
            let got = match fill(source, &mut buf[..n]) {
                Ok(got) => got,
                Err(e) => {
                    let kind = match e {
                        ServiceError::Io(k) => k,
                        _ => ErrorKind::TimedOut,
                    };
                    return Err(self.end(ServiceError::Source(kind)));
                }
            };
            if got < n {
                return Err(self.end(ServiceError::Source(ErrorKind::UnexpectedEof)));
            }
            if let Err(e) = write_frame(&mut self.io, KIND_DATA, &buf[..n]) {
                return match self.answer() {
                    Err(answered @ ServiceError::Answered { .. }) => {
                        self.open = false;
                        Err(answered)
                    }
                    _ => Err(self.end(e)),
                };
            }
            left -= n as u64;
        }
        Ok(())
    }

    /// `status`.
    pub fn status(&mut self) -> Result<StatusReport, ServiceError> {
        self.send(Request::Status)?;
        match self.answer()? {
            Response::Status(s) => Ok(s),
            _ => Err(self.unexpected()),
        }
    }

    /// `stage_begin` with `documents` (in order: roots, keys, feed, manifest), their bytes streamed
    /// after the request.
    pub fn stage_begin(
        &mut self,
        channel: &Channel,
        documents: &[OutgoingDocument<'_>],
    ) -> Result<StageBegun, ServiceError> {
        let decls: Vec<DocumentDecl> = documents
            .iter()
            .map(|d| DocumentDecl {
                kind: d.kind,
                bytes: d.bytes.len() as u64,
            })
            .collect();
        self.send(Request::StageBegin {
            channel: channel.clone(),
            documents: decls,
        })?;
        for d in documents {
            self.stream(&mut { d.bytes }, d.bytes.len() as u64)?;
        }
        match self.answer()? {
            Response::StageReady { version } => Ok(StageBegun::Ready(version)),
            Response::NoUpdate => Ok(StageBegun::NoUpdate),
            _ => Err(self.unexpected()),
        }
    }

    /// `put` of one object of `size` bytes read from `source`.
    pub fn put(
        &mut self,
        kind: ObjectKind,
        sha256: Sha256Digest,
        size: u64,
        source: &mut dyn Read,
    ) -> Result<(), ServiceError> {
        if kind == ObjectKind::Patch && self.version < PROTOCOL_PATCH {
            return Err(ServiceError::Malformed("put of a patch below version 2"));
        }
        self.send(Request::Put { kind, sha256, size })?;
        self.stream(source, size)?;
        match self.answer()? {
            Response::PutOk => Ok(()),
            _ => Err(self.unexpected()),
        }
    }

    /// `stage_commit`; `progress(done, total)` is called for every `progress` answer.
    pub fn stage_commit(
        &mut self,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<CommitOutcome, ServiceError> {
        self.send(Request::StageCommit)?;
        loop {
            match self.answer()? {
                Response::Progress { done, total } => progress(done, total),
                Response::Staged { version } => return Ok(CommitOutcome::Staged(version)),
                Response::NeedFetch { paths, more } => {
                    return Ok(CommitOutcome::NeedFetch { paths, more });
                }
                _ => return Err(self.unexpected()),
            }
        }
    }

    /// `apply{version}`: the token of the now pending version.
    pub fn apply(&mut self, version: &Version) -> Result<Token, ServiceError> {
        self.send(Request::Apply {
            version: version.clone(),
        })?;
        match self.answer()? {
            Response::Applied { version: v, token } if &v == version => Ok(token),
            _ => Err(self.unexpected()),
        }
    }

    /// `attempt{version}`.
    pub fn attempt(&mut self, version: &Version) -> Result<AttemptAnswer, ServiceError> {
        self.send(Request::Attempt {
            version: version.clone(),
        })?;
        match self.answer()? {
            Response::Attempt(a) => Ok(a),
            _ => Err(self.unexpected()),
        }
    }

    /// `confirm{version, token}`.
    pub fn confirm(
        &mut self,
        version: &Version,
        token: &Token,
    ) -> Result<ConfirmAnswer, ServiceError> {
        self.send(Request::Confirm {
            version: version.clone(),
            token: token.clone(),
        })?;
        match self.answer()? {
            Response::Confirmed => Ok(ConfirmAnswer::Confirmed),
            Response::NothingPending => Ok(ConfirmAnswer::NothingPending),
            _ => Err(self.unexpected()),
        }
    }

    /// `rollback{version, token}`: the current version afterwards.
    pub fn rollback(&mut self, version: &Version, token: &Token) -> Result<Version, ServiceError> {
        self.send(Request::Rollback {
            version: version.clone(),
            token: token.clone(),
        })?;
        match self.answer()? {
            Response::RolledBack { current } => Ok(current),
            _ => Err(self.unexpected()),
        }
    }
}

// ---- fuzz harness --------------------------------------------------------------------------------

/// A replayed peer: reads come from the input, writes are dropped, deadlines are ignored.
struct Replay<'a, 'b> {
    input: &'b mut &'a [u8],
}

impl Read for Replay<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for Replay<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Duplex for Replay<'_, '_> {
    fn set_read_deadline(&mut self, _: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
}

/// The `service` harness (see [`crate::fuzz::service`]). True when every frame was valid and the
/// stream ended on a frame boundary: a negotiation that ends in `unsupported` counts when nothing
/// follows the hello.
pub(crate) fn fuzz_run(data: &[u8]) -> bool {
    let Some((&side, rest)) = data.split_first() else {
        return false;
    };
    let Ok(app) = AppId::parse(crate::fuzz::FUZZ_APP_ID) else {
        return false;
    };
    let mut input = rest;
    let io = Replay { input: &mut input };
    let outcome = if side % 2 == 0 {
        fuzz_server(io, app)
    } else {
        fuzz_client(io, app)
    };
    match outcome {
        Ok(()) => true,
        Err(ServiceError::Unsupported { .. }) => input.is_empty(),
        Err(_) => false,
    }
}

fn fuzz_server(io: Replay<'_, '_>, app: AppId) -> Result<(), ServiceError> {
    let mut session = ServerSession::accept(io, app)?;
    while let Some(request) = session.next_request()? {
        session.read_data(request.data_len(), &mut std::io::sink())?;
        session.reply(&Response::error(ErrorCode::Internal))?;
    }
    Ok(())
}

fn fuzz_client(io: Replay<'_, '_>, app: AppId) -> Result<(), ServiceError> {
    let timeouts = ClientTimeouts {
        hello: None,
        answer: None,
    };
    let mut io = ClientSession::connect(io, app, timeouts)?.into_inner();
    loop {
        match read_frame(&mut io)? {
            None => return Ok(()),
            Some(Frame::Message(body)) => {
                Response::decode(&body)?;
            }
            Some(Frame::Data(_)) => return Err(ServiceError::Malformed("data from the server")),
        }
    }
}
