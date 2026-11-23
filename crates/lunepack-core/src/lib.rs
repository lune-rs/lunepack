//! Pure update-framework logic and the traits behind every external or replaceable capability; depends on no adapter or I/O crate.

pub mod cancel;
pub mod chain;
pub mod codesign;
pub mod digest;
pub mod encoding;
pub mod endpoint;
pub mod engine;
pub mod envelope;
pub mod error;
pub mod feed;
pub mod fetch;
pub mod frame;
pub mod fs;
#[doc(hidden)]
pub mod fuzz;
pub mod ident;
pub mod integration;
pub mod json;
pub mod keyset;
pub mod layout;
pub mod lifecycle;
pub mod limits;
pub mod manifest;
pub mod pack;
pub mod path;
pub mod pe;
pub mod policy;
pub mod process;
pub mod progress;
pub mod root;
pub mod service;
pub mod setup;
pub mod stage;
pub mod state;
pub mod stub;
pub mod target;
pub mod traits;
pub mod transport;
pub mod trust;
pub mod ui;
pub mod unix_protect;
pub mod update_config;
pub mod version;
pub mod write;

pub use cancel::CancelToken;
pub use chain::{
    Documents, KeysChain, MAX_ROOT_STEPS, RootWalk, raised_floors, verify_first_install_keys,
};
pub use codesign::{
    ArgvTemplate, Decision, ExpandCtx, Expanded, PlanEntry, PlanEntryKind, PublisherOutcome,
    SignItem, SignKind, SignPlanError, TemplateError, TemplateRole, decide, macho_slices_signed,
    pe_is_signed, sign_plan,
};
pub use digest::{Sha256Digest, U53};
pub use envelope::{EnvelopeSignature, OpenedEnvelope, PayloadKind, pae, write_envelope};
pub use error::{
    ConnectError, DesktopPathError, ElevationError, Error, FeedRule, LayoutError, LifecycleError,
    ProtectError, PublisherError, Result, ServiceError, ServiceRegError, StageError, StateError,
    UpdateConfigError,
};
pub use feed::{
    ArtifactRef, CheckedRef, FeedDocument, FeedTargetEntry, ReleaseDoc, Rollout, RolloutDoc,
    VerifiedFeed, VerifiedRelease, verify_feed,
};
pub use fetch::{
    ContentRange, FetchPlan, FetchPolicy, Outcome, RangeError, ResponseInfo, Run, check_document,
    plan_fetch,
};
pub use frame::{
    CheckedFrame, FrameDesc, MAX_PATCH_WINDOW, PATCH_WINDOW_ALIGN, StreamDesc, check_file_frame,
    decode_patch_verified, decode_verified, decoder_memory, is_patch_codec, patch_decoder_memory,
    patch_window,
};
pub use fs::{
    DirEntryInfo, FileKind, FileWrite, Fs, FsError, FsErrorKind, LockGuard, Meta, PlaceFacts,
    ReadAt,
};
pub use ident::{AppId, Channel};
pub use integration::{
    IntegrationError, IntegrationItem, IntegrationReport, IntegrationRequest, OsIntegration,
};
pub use keyset::{KeySetDocument, ReleaseKeyEntry, VerifiedKeySet, verify_key_set};
pub use layout::{
    BundleDiscovery, BundleProbe, Discovery, LayoutScheme, LocationReason, MachineLayout,
    MachineOs, MachineScheme, NameRule, Projection, RootChoice, RootNaming, SERVICE_FILE,
    SERVICE_FILE_UNIX, UnixOs, UserLayout, bundle_orphaned, bundle_replaced, check_place, discover,
    discover_bundle, ensure_no_foreign_record, is_tombstone_of, machine_root, machine_user_home,
    macos_name_ok, read_bundle_identity, reconcile_bundle, reconcile_current, remove_tombstones,
    resolve_bundle_target, resolve_root, resolve_root_scoped, root_valid_for_uninstall,
    set_bundle_pointer, tombstone_name, tree_candidates, version_config_path, windows_name_ok,
    write_bundle_identity,
};
pub use lifecycle::{
    AttemptOutcome, ConfirmOutcome, TokenCheck, apply, confirm, count_attempt, deliver_events,
    gc_keep, install_first, reinstall_orphaned, reset_orphaned, rollback,
};
pub use limits::Limits;
pub use manifest::{
    DeltaDoc, EntryDoc, ManifestDocument, PatchDoc, VerifiedDelta, VerifiedEntry, VerifiedManifest,
    VerifiedPatch, read_entry, verify_manifest, verify_payload_manifest,
};
pub use pack::{
    DeltaFile, DeltaPatch, FileClass, FinishedRelease, PackedFile, ReleaseLayout,
    RuntimeImageError, candidates, check_pe_stub, check_runtime_image, check_service_image,
    check_ui_image, classify, pack_file,
};
pub use path::{EntryKind, RelPath, validate_path, validate_tree};
pub use policy::{Candidate, in_rollout, rollout_bucket, select_candidate};
pub use process::{
    Child, ChildStdio, ExitKind, Process, ProcessError, ProcessErrorKind, ProcessId, SpawnSpec,
    WaitOutcome,
};
pub use progress::{FileProgress, Phase, Progress, Source};
pub use root::{RootDocument, TrustedRoot, advance_root};
pub use service::{ClientSession, Duplex, ServerSession};
pub use stage::{
    PatchSource, SourceFor, StageEnv, StageInput, StagedVersion, TreeDifference, TreeMismatch,
    patch_cost, scan, stage, verify_tree,
};
pub use state::{
    CurrentRef, Floors, Health, InstallCounters, InstallState, Lifecycle, LifecycleEvent, Loaded,
    MachineScope, MachineStore, PendingRef, PreviousRef, Record, RootParts, Scope, StagedIssued,
    StagedRef, UserScope,
};
pub use stub::{LaunchTarget, STUB_CONTRACT_VERSION, STUB_FILE, StubError, launch_target};
pub use target::Target;
pub use traits::{
    Clock, CodeSign, Codec, CodecId, DecodeReport, EncodedFrame, EncodedPatch, EncodedStream,
    Encoder, FrameView, HashState, Hasher, PatchView, PublisherCheck, Rng, SignatureAlg,
    SignedTree, Signer, StreamView, Verifier,
};
pub use traits::{
    DirClass, Elevated, ElevatedChild, Elevation, MachinePolicy, PolicySource, Protect,
    ServiceConnector, ServiceRegistrar, Standing,
};
pub use transport::{
    BlockingResponse, BlockingTransport, Body, BoxFuture, ByteRange, Head, Request, Response,
    Transport, TransportError, TransportErrorKind, Validator,
};
pub use trust::{ClockReading, KeyEntry, KeyRing, PublicKey, RollbackFloor};
pub use update_config::{
    FeedKind, FileType, InstallMeta, PublisherPolicy, UPDATE_CONFIG_FILE, UpdateConfig, check_feed,
    desktop_safe_path,
};
pub use version::Version;
pub use write::{
    DEFAULT_FEED_LIFETIME_SECS, next_feed, next_key_set, rollout_seed, rotate_root, sign_envelope,
};
