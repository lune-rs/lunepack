//! Linux install, shortcut, autostart and process-restart adapter.
//!
//! [`LinuxProcess`] implements the core's [`Process`](lunepack_core::Process) over
//! `std::process` and `/proc`. [`XdgIntegration`] implements
//! [`OsIntegration`](lunepack_core::OsIntegration) for a per-user install: an XDG desktop entry
//! and a command link ([`xdg_dirs`] works out the directories). Everything here is
//! `cfg(target_os = "linux")`; on other platforms the crate is empty, except [`motion`], whose
//! parser is plain and testable everywhere.

pub mod motion;
#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
mod procfs;
#[cfg(target_os = "linux")]
mod xdg;

#[cfg(target_os = "linux")]
pub use process::LinuxProcess;
#[cfg(target_os = "linux")]
pub use xdg::{XdgDirs, XdgEnv, XdgIntegration, xdg_dirs};

#[cfg(target_os = "linux")]
pub use motion::prefers_reduced_motion;
