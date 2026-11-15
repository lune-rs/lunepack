//! Linux install, shortcut, autostart and process-restart adapter.
//!
//! [`LinuxProcess`] implements the core's [`Process`](lunepack_core::Process) over
//! `std::process` and `/proc`. Everything here is `cfg(target_os = "linux")`; on other platforms
//! the crate is empty.

#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
mod procfs;

#[cfg(target_os = "linux")]
pub use process::LinuxProcess;
