//! Linux install, shortcut, autostart and process-restart adapter.
//!
//! [`LinuxProcess`] implements the core's [`Process`](lunepack_core::Process) over
//! `std::process` and `/proc`. [`XdgIntegration`] implements
//! [`OsIntegration`](lunepack_core::OsIntegration) for a per-user install: an XDG desktop entry
//! and a command link ([`xdg_dirs`] works out the directories).
//!
//! The per-machine ports (M11): [`LinuxProtect`] (protected directories), [`SystemdRegistrar`]
//! (the socket-activated service), [`ActivatedListener`] and [`UnixConnector`] (the service's
//! socket, both ends), [`FilePolicy`] (the administrator's policy file), [`PkexecElevation`] (the
//! hand-off to an administrator) and [`MachineIntegration`] (the system-wide desktop entries).
//!
//! Everything here is `cfg(target_os = "linux")`; on other platforms the crate is empty, except
//! [`motion`], whose parser is plain and testable everywhere.

#[cfg(target_os = "linux")]
mod elevate;
pub mod motion;
#[cfg(target_os = "linux")]
mod policy;
#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
mod procfs;
#[cfg(target_os = "linux")]
mod protect;
mod publisher;
#[cfg(target_os = "linux")]
mod socket;
#[cfg(target_os = "linux")]
mod systemd;
#[cfg(target_os = "linux")]
mod xdg;

#[cfg(target_os = "linux")]
pub use elevate::{
    PKEXEC, PKEXEC_DECLINED, PKEXEC_NO_AGENT, PkexecChild, PkexecElevation, effective_uid,
    set_root_umask,
};
#[cfg(target_os = "linux")]
pub use policy::{FilePolicy, MAX_POLICY_BYTES, POLICY_DIR};
#[cfg(target_os = "linux")]
pub use protect::{LinuxProtect, class_mode};
#[cfg(target_os = "linux")]
pub use socket::{
    ActivatedListener, ActivationError, CONNECT_RETRY, SYSTEMD_FD, UnixConnector, UnixDuplex,
    check_listener, peer_uid,
};
#[cfg(target_os = "linux")]
pub use systemd::{SELF_TEST_LIMIT, SystemdRegistrar, service_unit_text, socket_unit_text};

#[cfg(target_os = "linux")]
pub use process::LinuxProcess;
pub use publisher::NoPublisherCheck;
#[cfg(target_os = "linux")]
pub use xdg::{MachineIntegration, XdgDirs, XdgEnv, XdgIntegration, xdg_dirs};

#[cfg(target_os = "linux")]
pub use motion::prefers_reduced_motion;
