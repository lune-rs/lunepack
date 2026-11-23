//! The per-machine update service (M10-D7): `lunepack-service.exe`, started by the Windows service
//! control manager as LocalSystem. It opens the privileged engine of the install it lives in and
//! serves it over one named pipe, one connection at a time (M10-D11). It is the third composition
//! root: it wires the engine's ports to the adapters in [`host`], and nothing else does.
//!
//! The service reads no environment variable and no working directory, and does not impersonate:
//! its root comes from its own image path ([`location`]), everything else from the machine record
//! under that root.

pub mod args;
pub mod location;
pub mod logfile;
pub mod session;

#[cfg(windows)]
pub mod host;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod host_unix;

/// The process's exit codes.
pub mod exit {
    /// Done (a `--self-test` that passed, a service stopped by the control manager or idle).
    pub const OK: u8 = 0;
    /// The service or its self-test failed after it started.
    pub const FAILED: u8 = 1;
    /// The command line was not understood, the system has no host, or the process was not
    /// started by the init system for its socket (unix).
    pub const USAGE: u8 = 2;
    /// The image is not where the service may run from.
    pub const LOCATION: u8 = 3;
    /// The engine could not be opened (the tree is not protected, no machine record).
    pub const ENGINE: u8 = 4;
}
