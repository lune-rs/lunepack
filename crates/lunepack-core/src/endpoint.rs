//! The names of an app's update service on Linux and macOS (M11-D4): the socket path the client
//! connects to and the init system's registration that owns it. Every later app version must find
//! them (D28), so they are fixed here and derived from the app id alone.
//!
//! Linux: systemd units `/etc/systemd/system/lunepack-<app id>.socket` (listening on
//! `/run/lunepack/<app id>.sock`) and `lunepack-<app id>.service`. macOS: the LaunchDaemon
//! `/Library/LaunchDaemons/lunepack-<app id>.plist` with the label `lunepack-<app id>`, whose
//! socket `lunepack` listens on `/var/run/lunepack-<app id>.sock`.

use std::path::PathBuf;

use crate::ident::AppId;
use crate::layout::UnixOs;

/// The prefix of every registration name (units, label, plist).
pub const NAME_PREFIX: &str = "lunepack-";
/// The socket directory on Linux: root-owned, mode 0755, made by systemd (`DirectoryMode`).
pub const SOCKET_DIR_LINUX: &str = "/run/lunepack";
/// The socket directory on macOS: the system's `/var/run` (root:daemon 0775, M11-D5).
pub const SOCKET_DIR_MACOS: &str = "/var/run";
/// The socket file's suffix.
pub const SOCKET_SUFFIX: &str = ".sock";
/// Where the systemd units are written.
pub const SYSTEMD_UNIT_DIR: &str = "/etc/systemd/system";
/// Where the LaunchDaemon plist is written.
pub const LAUNCH_DAEMONS_DIR: &str = "/Library/LaunchDaemons";
/// The name of the socket in the LaunchDaemon's `Sockets` dictionary, the name the daemon passes
/// to `launch_activate_socket`.
pub const LAUNCHD_SOCKET_NAME: &str = "lunepack";
/// Most bytes of a socket path on Linux (`sun_path` is 108 bytes with its terminating NUL).
pub const MAX_SOCKET_PATH_LINUX: usize = 107;
/// Most bytes of a socket path on macOS (`sun_path` is 104 bytes with its terminating NUL).
pub const MAX_SOCKET_PATH_MACOS: usize = 103;

/// The directory the socket of every app lives in on `os`; the client requires it to be owned by
/// uid 0 and writable by no one else (M11-D5).
pub const fn socket_dir(os: UnixOs) -> &'static str {
    match os {
        UnixOs::Linux => SOCKET_DIR_LINUX,
        UnixOs::Macos => SOCKET_DIR_MACOS,
    }
}

/// The most bytes a socket path may have on `os`.
pub const fn max_socket_path(os: UnixOs) -> usize {
    match os {
        UnixOs::Linux => MAX_SOCKET_PATH_LINUX,
        UnixOs::Macos => MAX_SOCKET_PATH_MACOS,
    }
}

/// The socket of `app_id`'s update service: `/run/lunepack/<app id>.sock` on Linux,
/// `/var/run/lunepack-<app id>.sock` on macOS. At most [`max_socket_path`] bytes for every app
/// id (at most 64 bytes).
pub fn socket_path(os: UnixOs, app_id: &AppId) -> PathBuf {
    let id = app_id.as_str();
    match os {
        UnixOs::Linux => PathBuf::from(format!("{SOCKET_DIR_LINUX}/{id}{SOCKET_SUFFIX}")),
        UnixOs::Macos => PathBuf::from(format!(
            "{SOCKET_DIR_MACOS}/{NAME_PREFIX}{id}{SOCKET_SUFFIX}"
        )),
    }
}

/// The systemd socket unit's name: `lunepack-<app id>.socket`.
pub fn systemd_socket_unit(app_id: &AppId) -> String {
    format!("{NAME_PREFIX}{}.socket", app_id.as_str())
}

/// The systemd service unit's name: `lunepack-<app id>.service`.
pub fn systemd_service_unit(app_id: &AppId) -> String {
    format!("{NAME_PREFIX}{}.service", app_id.as_str())
}

/// `/etc/systemd/system/lunepack-<app id>.socket`, `/`-separated on every host (M12-D11).
pub fn systemd_socket_unit_path(app_id: &AppId) -> PathBuf {
    PathBuf::from(format!(
        "{SYSTEMD_UNIT_DIR}/{}",
        systemd_socket_unit(app_id)
    ))
}

/// `/etc/systemd/system/lunepack-<app id>.service`, `/`-separated on every host (M12-D11).
pub fn systemd_service_unit_path(app_id: &AppId) -> PathBuf {
    PathBuf::from(format!(
        "{SYSTEMD_UNIT_DIR}/{}",
        systemd_service_unit(app_id)
    ))
}

/// The LaunchDaemon's label: `lunepack-<app id>`.
pub fn launchd_label(app_id: &AppId) -> String {
    format!("{NAME_PREFIX}{}", app_id.as_str())
}

/// `/Library/LaunchDaemons/lunepack-<app id>.plist`, `/`-separated on every host (M12-D11).
pub fn launchd_plist_path(app_id: &AppId) -> PathBuf {
    PathBuf::from(format!(
        "{LAUNCH_DAEMONS_DIR}/{}.plist",
        launchd_label(app_id)
    ))
}
