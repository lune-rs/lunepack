//! In-memory fakes and contract suites for the core traits (test support only, never published).
//!
//! Every fake here is deterministic and offers no accept-everything mode. The hasher and the
//! signature scheme are deliberately not SHA-256 and not Ed25519, so no core test can pass by
//! assuming the real algorithm. Contract suites (the `run_*_suite` functions) are what each
//! adapter's `tests/` runs against its real implementation.

mod clock;
mod codec;
mod docs;
pub mod exe_headers;
mod hasher;
mod http_server;
mod integration;
mod memfs;
mod process;
mod rng;
mod seeds;
mod signer;
mod suites;
mod transport;
mod verifier;

use std::path::PathBuf;

pub use clock::{FakeClock, YEAR_2100_UNIX_SECS};
pub use codec::{FakeCodec, FakeEncoded, FakeStreamLayout, Fault};
pub use docs::{
    ChainFixture, PackBuilder, SUITE_APP_ID, SUITE_CHANNEL, SUITE_T0, TRUST_CHAIN_CASES, fake_sign,
    run_trust_chain_suite,
};
pub use hasher::FakeHasher;
pub use http_server::LoopbackServer;
pub use integration::{
    FakeIntegration, IntegrationCall, IntegrationOp, SuiteHooks, run_integration_suite,
    run_integration_suite_with,
};
pub use memfs::{MemFs, RecoverMode};
pub use process::{
    ChildScript, FakeChildPipes, FakePipeReader, FakePipeWriter, FakeProcess, SpawnRecord,
    run_process_suite,
};
pub use rng::FakeRng;
pub use seeds::{Seed, fuzz_seeds, sample_update_config};
pub use signer::FakeSigner;
pub use suites::{
    HashKat, SHA256_KATS, SignFixture, TransportCaps, VerifyKat, run_blocking_transport_suite,
    run_blocking_transport_suite_with, run_clock_suite, run_codec_suite, run_fs_suite,
    run_fs_suite_with, run_hasher_suite, run_rng_suite, run_signer_suite, run_transport_suite,
    run_verifier_suite,
};
pub use transport::{
    FAKE_BASE_URL, FakeBlockingTransport, FakeOrigin, FakeTransport, SeenRequest, TransportFault,
    TransportFixture,
};
pub use verifier::{FAKE_INVALID_KEYS, FakeKeyPair, FakeVerifier};

/// A test path written in POSIX form (`/a/b`) as an absolute path on this platform: unchanged on
/// Unix, and on drive `C:` on Windows (`C:\a\b`), where `/a/b` has no prefix and is not absolute.
/// For literal paths given to code that requires an absolute one (`tree_candidates`, `discover`,
/// a spawn's program); the in-memory filesystem ignores the prefix.
pub fn abs_path(posix: &str) -> PathBuf {
    assert!(
        posix.starts_with('/'),
        "abs_path takes a path that starts with /"
    );
    if cfg!(windows) {
        PathBuf::from(format!("C:{}", posix.replace('/', "\\")))
    } else {
        PathBuf::from(posix)
    }
}
