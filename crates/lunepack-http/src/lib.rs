//! HTTP release-source adapters implementing the core's sync [`BlockingTransport`] (M4-D1).
//!
//! - [`UreqTransport`]: `http`/`https` through ureq with rustls (ring) and the **platform
//!   verifier** as the only trust source, system proxies as M4-D14 orders them, no content coding
//!   (no `Accept-Encoding` is sent, nothing is decoded) and no query or userinfo in an error.
//! - [`DirSource`]: `file:` URLs under one directory, for local mirrors and tests; it answers
//!   `Range` like a server would and offers no validator.
//!
//! - [`S3Store`] and [`DirStore`]: the adapters of the core's `ObjectStore` (P-D1), an
//!   S3-compatible HTTP store signed with SigV4 of our own (P-D2) and a local directory.
//!
//! The first two hand the core the response as it came: every header lowercased with duplicates kept, 4xx
//! and 5xx as a [`Head`], the body as a plain `Read`. The core's response rules (`classify`) judge
//! the answer; this crate never does.
//!
//! The crate is the only place `ring` may enter the dependency graph (M4-D16, checked by
//! `xtask check-boundaries`).
//!
//! [`BlockingTransport`]: lunepack_core::BlockingTransport
//! [`Head`]: lunepack_core::Head

mod dir;
mod proxy;
mod sigv4;
mod store;
mod ureq_transport;

pub use dir::DirSource;
pub use proxy::proxy_for_url;
pub use sigv4::Credentials;
pub use store::{DirStore, S3ConfigError, S3Store};
pub use ureq_transport::{UreqOptions, UreqTransport};
