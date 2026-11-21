//! The traits behind everything external the core needs (hard rule 3): hashing, signature
//! verification, the clock, randomness and frame decoding on the reading side; frame encoding, signing and the
//! code-signing hook on the producing side. Core code never reaches for a digest, a signature
//! algorithm, the time, a codec or a private key any other way. Each trait is object-safe and
//! `Send + Sync`; implementations live in adapter crates, fakes in `lunepack-testkit`.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::digest::Sha256Digest;
use crate::error::{
    ConnectError, ElevationError, Error, ProtectError, PublisherError, Result, ServiceRegError,
};
use crate::ident::AppId;
use crate::path::RelPath;
use crate::service::Duplex;

/// A streaming SHA-256 computation, created by [`Hasher::sha256_start`].
pub trait HashState: Send {
    /// Feeds more bytes.
    fn update(&mut self, data: &[u8]);
    /// Ends the computation.
    fn finalize(self: Box<Self>) -> Sha256Digest;
}

/// SHA-256, one-shot and streaming.
pub trait Hasher: Send + Sync {
    /// Starts a streaming computation.
    fn sha256_start(&self) -> Box<dyn HashState>;

    /// SHA-256 of `data` in one call.
    fn sha256(&self, data: &[u8]) -> Sha256Digest {
        let mut state = self.sha256_start();
        state.update(data);
        state.finalize()
    }
}

/// Signature algorithms of format v1 (FORMAT.md 2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlg {
    /// Ed25519 (RFC 8032), strict verification.
    Ed25519,
}

impl SignatureAlg {
    /// The id written in key lists.
    pub const fn id(self) -> &'static str {
        match self {
            SignatureAlg::Ed25519 => "ed25519",
        }
    }

    /// Parses an algorithm id; compared byte for byte, any other value is rejected.
    pub fn from_id(id: &str) -> Option<SignatureAlg> {
        match id {
            "ed25519" => Some(SignatureAlg::Ed25519),
            _ => None,
        }
    }
}

/// Signature verification.
pub trait Verifier: Send + Sync {
    /// Verifies `signature` over `message` with `public_key`. Strict semantics: a signature that
    /// is not canonical or a key that is small-order must fail. `Ok(())` only for a valid one.
    fn verify(
        &self,
        alg: SignatureAlg,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), Error>;

    /// `Ok(())` when `public_key` is a valid key for `alg`: for Ed25519 a canonical point
    /// encoding that is not small-order (FORMAT.md 2.5). Readers call it on every key of a key
    /// list before the list is trusted.
    fn check_public_key(&self, alg: SignatureAlg, public_key: &[u8; 32]) -> Result<(), Error>;
}

/// The reader's clock; the only source of `now` (FORMAT.md 11.3).
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch (UTC).
    fn now_unix_secs(&self) -> u64;
}

/// The source of randomness: the only way the core or a caller of the core obtains random bytes
/// (hard rule 3). The real one reads the operating system's generator; the testkit's fake is a
/// seeded, deterministic sequence.
pub trait Rng: Send + Sync {
    /// Fills all of `buf` with random bytes. On failure `buf` must be treated as unfilled; an
    /// implementation never falls back to a weaker source.
    fn fill(&self, buf: &mut [u8]) -> Result<(), Error>;
}

/// Codec ids of format v1 (FORMAT.md 9.0); the set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodecId {
    /// The file's bytes unchanged.
    Stored,
    /// One raw LZMA2 stream.
    Lzma2,
    /// x86 BCJ filter then one raw LZMA2 stream.
    BcjX86Lzma2,
    /// ARM64 BCJ filter then one raw LZMA2 stream.
    BcjArm64Lzma2,
    /// BCJ2: four sub-streams.
    Bcj2,
}

impl CodecId {
    /// The id written in manifests.
    pub const fn id(self) -> &'static str {
        match self {
            CodecId::Stored => "stored",
            CodecId::Lzma2 => "lzma2",
            CodecId::BcjX86Lzma2 => "bcj-x86+lzma2",
            CodecId::BcjArm64Lzma2 => "bcj-arm64+lzma2",
            CodecId::Bcj2 => "bcj2",
        }
    }

    /// Parses a codec id, byte for byte; an unknown id (another case included) is `None`.
    pub fn from_id(id: &str) -> Option<CodecId> {
        match id {
            "stored" => Some(CodecId::Stored),
            "lzma2" => Some(CodecId::Lzma2),
            "bcj-x86+lzma2" => Some(CodecId::BcjX86Lzma2),
            "bcj-arm64+lzma2" => Some(CodecId::BcjArm64Lzma2),
            "bcj2" => Some(CodecId::Bcj2),
            _ => None,
        }
    }
}

/// One encoded stream of a frame, already checked against its signed descriptor.
#[derive(Debug, Clone, Copy)]
pub struct StreamView<'a> {
    /// The stream's encoded bytes.
    pub input: &'a [u8],
    /// Exact number of bytes this stream decodes to.
    pub decoded_size: u64,
    /// LZMA2 dictionary bytes the decoder may use, at most; `None` for a stored stream.
    pub dict_size: Option<u32>,
}

/// A frame whose hash and descriptor were verified, ready to decode.
#[derive(Debug, Clone, Copy)]
pub struct FrameView<'a> {
    /// The codec.
    pub codec: CodecId,
    /// Exact size of the decoded file.
    pub output_size: u64,
    /// The frame's streams in order (one, or four for BCJ2).
    pub streams: &'a [StreamView<'a>],
}

/// What a decoder consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeReport {
    /// Input bytes consumed, one entry per stream, in stream order.
    pub consumed: Vec<u64>,
}

/// Frame decoding. The caller wraps `out` in an exact-size, hashing writer.
///
/// A decoder must:
/// - produce exactly `output_size` bytes;
/// - make each stream decode to exactly its `decoded_size`, BCJ2's sub-streams included (core
///   sees only the total, so it cannot check them; a stream that decodes to another size is
///   [`CodecError::StreamSize`](crate::error::CodecError::StreamSize) even when the total fits);
/// - report the input it really consumed, per stream;
/// - allocate no more than each stream's `dict_size` (plus a fixed overhead);
/// - stop on the first write error.
pub trait Codec: Send + Sync {
    /// Decodes `frame` into `out` and reports the bytes consumed per stream.
    fn decode(&self, frame: &FrameView<'_>, out: &mut dyn Write) -> Result<DecodeReport, Error>;
}

/// One encoded stream of an [`EncodedFrame`] (BCJ2 only): what the manifest's `streams` records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedStream {
    /// Encoded bytes of the stream, at least 1.
    pub length: u64,
    /// Bytes the stream decodes to.
    pub decoded_size: u64,
    /// LZMA2 dictionary of MAIN, CALL and JUMP; `None` for RC.
    pub dict_size: Option<u32>,
}

/// The result of encoding one file: the frame's bytes and the descriptor fields the encoder alone
/// knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFrame {
    /// The codec the frame was encoded with.
    pub codec: CodecId,
    /// The frame's bytes (all streams back to back for BCJ2).
    pub bytes: Vec<u8>,
    /// The LZMA2 dictionary, for the LZMA2 variants; `None` for `stored` and `bcj2`.
    pub dict_size: Option<u32>,
    /// The four sub-streams, for `bcj2` only; `None` otherwise.
    pub streams: Option<Vec<EncodedStream>>,
}

/// Frame encoding for one file. The output is deterministic: the same codec and input give the
/// same bytes, whatever the host or the thread count.
pub trait Encoder: Send + Sync {
    /// Encodes `input` (at least one byte) with `codec`. An id the encoder does not implement is an
    /// error.
    fn encode(&self, codec: CodecId, input: &[u8]) -> Result<EncodedFrame, Error>;

    /// An upper bound, in bytes, on the memory one [`Encoder::encode`] call of `codec` over
    /// `input_len` bytes needs, excluding `input` itself.
    fn encode_memory(&self, codec: CodecId, input_len: u64) -> u64;
}

/// An Ed25519 signer. The private key never leaves the implementation.
///
/// Signatures are deterministic (Ed25519, RFC 8032): signing the same message twice gives the same
/// bytes. `Debug` is a supertrait so a signer can be logged, which is why an implementation's `Debug`
/// must not print secret material.
pub trait Signer: Send + Sync + std::fmt::Debug {
    /// The signature algorithm.
    fn alg(&self) -> SignatureAlg;

    /// The public key.
    fn public_key(&self) -> [u8; 32];

    /// Signs `message`.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error>;
}

/// The code-signing hook (C2 stage 2). It runs on the assembled tree before any file is hashed;
/// `plan` is [`crate::codesign::sign_plan`]'s list of the items to sign, inner to outer (a
/// bundle's contents before the bundle, the tree root last). The identity implementation changes
/// nothing.
pub trait CodeSign: Send + Sync {
    /// Signs the items of `plan` under `root` in place, in order.
    fn sign_tree(
        &self,
        root: &std::path::Path,
        plan: &[crate::codesign::SignItem],
    ) -> Result<(), Error>;
}

/// One tree whose operating-system code-signing publisher is asked about (M9-D8, M9-D7): its root
/// directory (on macOS, the bundle) and the entry, the path of the executable inside it that
/// `install.entry` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTree {
    /// The tree's root directory (absolute).
    pub root: PathBuf,
    /// The tree's entry, relative to `root`.
    pub entry: RelPath,
}

/// The publisher-continuity check (M9, C7): whether two trees were published by the same
/// operating-system code-signing identity. Object-safe and `Send + Sync`; it reads the two trees
/// and calls the operating system, never the network.
///
/// The answer is `Ok(true)`, `Ok(false)`, or a [`PublisherError`] from a closed set. An adapter
/// returns a verdict about the candidate or the installed tree only for the operating-system
/// statuses its documentation lists; every other failure is [`PublisherError::Os`] (M9-R1-D2).
pub trait PublisherCheck: Send + Sync {
    /// Whether `candidate` is signed by the publisher of `installed`.
    fn same_publisher(
        &self,
        installed: &SignedTree,
        candidate: &SignedTree,
    ) -> std::result::Result<bool, PublisherError>;
}

// ---- the machine-install ports (M10) -------------------------------------------------------------

/// The protection class of a directory the privileged engine creates or checks (M10-D9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DirClass {
    /// A directory of the machine tree (`R`, `R\app`, `R\.lunepack`, `R\.lunepack\state`):
    /// owner Administrators, full control for LocalSystem and Administrators, read and execute
    /// for Users and app packages, nothing else.
    MachineTree,
    /// An admin-only directory (`R\.lunepack\machine` and below): owner Administrators, full
    /// control for LocalSystem and Administrators, nothing for anyone else.
    AdminOnly,
}

/// Protected directories (M10-D9): creates a directory with an explicit protected descriptor of
/// its class, and checks that an existing one is protected as its class says. Object-safe and
/// `Send + Sync`.
pub trait Protect: Send + Sync {
    /// Creates the directory `path` (its parent must exist) with the descriptor of `class`. An
    /// existing entry at `path` is [`ProtectError::Exists`] and is left unchanged.
    fn create_dir(&self, path: &Path, class: DirClass) -> std::result::Result<(), ProtectError>;

    /// `Ok(())` when `path` is a real directory (not a link) protected as `class` says: nobody
    /// outside the class's writers holds a write-class right and the owner is Administrators,
    /// LocalSystem or TrustedInstaller. A missing directory is [`ProtectError::NotFound`]; any
    /// other shape is [`ProtectError::NotProtected`].
    fn check(&self, path: &Path, class: DirClass) -> std::result::Result<(), ProtectError>;
}

/// The operating system's registration of an app's update service (M10-D10). Object-safe and
/// `Send + Sync`.
pub trait ServiceRegistrar: Send + Sync {
    /// Registers the service of `app_id` with the binary `image`, replacing a registration that
    /// exists, with its descriptor and demand start.
    fn register(&self, app_id: &AppId, image: &Path) -> std::result::Result<(), ServiceRegError>;

    /// The binary the registration names; `None` when the service is not registered.
    fn image(&self, app_id: &AppId) -> std::result::Result<Option<PathBuf>, ServiceRegError>;

    /// Points the registration at `image`; the running service is not restarted.
    fn set_image(&self, app_id: &AppId, image: &Path) -> std::result::Result<(), ServiceRegError>;

    /// Runs `image --self-test` once; `Ok(())` only when it exits 0 within its time limit.
    fn self_test(&self, image: &Path) -> std::result::Result<(), ServiceRegError>;

    /// Stops and deletes the registration; a missing one is not an error.
    fn remove(&self, app_id: &AppId) -> std::result::Result<(), ServiceRegError>;
}

/// An administrator's policy for one app (M10-D12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MachinePolicy {
    /// Self-update is switched off: the engine refuses `stage_begin` and `apply`.
    pub self_update_disabled: bool,
    /// The runtime shows no update window.
    pub no_update_ui: bool,
}

/// Reads the machine policy (M10-D12). An unreadable policy counts as on: the implementation
/// returns `true` for each value it cannot read, so the answer is infallible.
pub trait PolicySource: Send + Sync {
    /// The policy for `app_id`.
    fn read(&self, app_id: &AppId) -> MachinePolicy;
}

/// Connects a client to the update service of an app (the named pipe on Windows). Object-safe and
/// `Send + Sync`.
pub trait ServiceConnector: Send + Sync {
    /// A channel to the service of `app_id`, its owner checked; the caller then runs the hello.
    fn connect(&self, app_id: &AppId) -> std::result::Result<Box<dyn Duplex>, ConnectError>;
}

/// What the current process may do (M10-D15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// A standard user's process.
    Standard,
    /// An administrator's process without a split token (UAC off, or the built-in account).
    Admin,
    /// An administrator's process holding the full token of a UAC elevation.
    UacElevated,
}

/// An elevated child process started by [`Elevation::run_elevated`].
pub trait ElevatedChild: Send {
    /// Waits for the child and returns its exit code.
    fn wait(&mut self) -> std::result::Result<i32, ElevationError>;
}

/// What [`Elevation::run_elevated`] did.
pub enum Elevated {
    /// The child runs elevated.
    Started(Box<dyn ElevatedChild>),
    /// The user declined the elevation prompt; nothing runs.
    Declined,
}

impl std::fmt::Debug for Elevated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Elevated::Started(_) => "Started(..)",
            Elevated::Declined => "Declined",
        })
    }
}

/// The current process's standing and the hand-off to an elevated child (M10-D15). Object-safe
/// and `Send + Sync`.
pub trait Elevation: Send + Sync {
    /// The current process's standing.
    fn standing(&self) -> Standing;

    /// Starts `exe` with `args` elevated, asking the user when the system needs to.
    fn run_elevated(
        &self,
        exe: &Path,
        args: &[String],
    ) -> std::result::Result<Elevated, ElevationError>;
}
