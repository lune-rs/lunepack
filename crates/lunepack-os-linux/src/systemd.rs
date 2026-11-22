//! The update service's registration with systemd (M11-D3, M11-D4): a socket unit that listens on
//! `/run/lunepack/<app id>.sock` for every local user and starts the service unit on the first
//! connection (`Accept=no`: one long-lived daemon), and a service unit that runs the stable link
//! `R/.lunepack/machine/lunepack-service`.
//!
//! The registered image is what the stable link names; switching the service to another version
//! is a new link renamed over the stable one (C8's atomic rename over the stable path), so the
//! units never change after `register`. Every tool is run by absolute path with an empty
//! environment, never through a shell or `PATH`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use lunepack_core::endpoint;
use lunepack_core::layout::{MACHINE_SERVICE_DIR, SERVICE_FILE_UNIX, UnixOs};
use lunepack_core::{AppId, MachineLayout, MachineScheme, ServiceRegError, ServiceRegistrar};

use crate::elevate::root_tool;

/// How long a self-test may run.
pub const SELF_TEST_LIMIT: Duration = Duration::from_secs(10);
/// Most bytes of a unit file read back.
const MAX_UNIT_BYTES: u64 = 64 * 1024;
/// The systemctl binaries tried, in order.
const SYSTEMCTL: [&str; 2] = ["/usr/bin/systemctl", "/bin/systemctl"];
/// The line that marks a unit as lunepack's.
const MARKER: &str = "# Written by lunepack; do not edit.";

/// Whether every byte of `text` is one a unit file carries without quoting or escaping (no space,
/// `%`, `\`, `$`, `;`, quote or control character).
fn unit_safe(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
}

/// The socket unit of `app_id` (M11-D4), byte for byte.
pub fn socket_unit_text(app_id: &AppId) -> String {
    let id = app_id.as_str();
    let socket = endpoint::socket_path(UnixOs::Linux, app_id);
    format!(
        "{MARKER}\n\
         [Unit]\n\
         Description=lunepack update service socket of {id}\n\
         \n\
         [Socket]\n\
         ListenStream={}\n\
         SocketMode=0666\n\
         SocketUser=root\n\
         SocketGroup=root\n\
         DirectoryMode=0755\n\
         Accept=no\n\
         \n\
         [Install]\n\
         WantedBy=sockets.target\n",
        socket.display()
    )
}

/// The service unit of `app_id` whose daemon is the stable link `exec` (M11-D4), byte for byte;
/// `None` when `exec` holds a byte a unit file would need to escape.
pub fn service_unit_text(app_id: &AppId, exec: &Path) -> Option<String> {
    let exec = exec.to_str().filter(|e| unit_safe(e))?;
    let id = app_id.as_str();
    Some(format!(
        "{MARKER}\n\
         [Unit]\n\
         Description=lunepack update service of {id}\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exec}\n\
         NoNewPrivileges=yes\n\
         ProtectHome=yes\n\
         PrivateTmp=yes\n\
         RestrictAddressFamilies=AF_UNIX\n\
         UMask=0022\n"
    ))
}

/// [`ServiceRegistrar`] over systemd.
#[derive(Debug, Clone)]
pub struct SystemdRegistrar {
    unit_dir: PathBuf,
    /// The systemctl to run; `None` picks the first root-owned one of [`SYSTEMCTL`] per call.
    systemctl: Option<PathBuf>,
}

impl Default for SystemdRegistrar {
    fn default() -> Self {
        SystemdRegistrar::new()
    }
}

impl SystemdRegistrar {
    /// Units in [`endpoint::SYSTEMD_UNIT_DIR`], the system's systemctl.
    pub fn new() -> SystemdRegistrar {
        SystemdRegistrar {
            unit_dir: PathBuf::from(endpoint::SYSTEMD_UNIT_DIR),
            systemctl: None,
        }
    }

    /// For tests: units in `unit_dir` and `systemctl` (a fake) run instead. Never used by a
    /// composition root.
    #[doc(hidden)]
    pub fn for_tests(unit_dir: PathBuf, systemctl: PathBuf) -> SystemdRegistrar {
        SystemdRegistrar {
            unit_dir,
            systemctl: Some(systemctl),
        }
    }

    fn socket_unit_path(&self, app_id: &AppId) -> PathBuf {
        self.unit_dir.join(endpoint::systemd_socket_unit(app_id))
    }

    fn service_unit_path(&self, app_id: &AppId) -> PathBuf {
        self.unit_dir.join(endpoint::systemd_service_unit(app_id))
    }

    /// Runs systemctl with `args`; a non-zero exit is an error with its code.
    fn systemctl(&self, args: &[&str]) -> Result<(), ServiceRegError> {
        let tool = match &self.systemctl {
            Some(tool) => tool.clone(),
            None => SYSTEMCTL
                .iter()
                .map(PathBuf::from)
                .find(|p| root_tool(p))
                .ok_or(ServiceRegError::Os("systemctl not found"))?,
        };
        let status = Command::new(tool)
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| ServiceRegError::Os("systemctl could not be run"))?;
        match status.code() {
            Some(0) => Ok(()),
            Some(code) => Err(ServiceRegError::OsCode("systemctl", code.unsigned_abs())),
            None => Err(ServiceRegError::Os("systemctl ended by a signal")),
        }
    }

    /// The stable link a registration's service unit names: the `ExecStart=` path of a unit of
    /// ours. `None` when the unit is missing.
    fn registered_link(&self, app_id: &AppId) -> Result<Option<PathBuf>, ServiceRegError> {
        let path = self.service_unit_path(app_id);
        let text = match read_capped(&path) {
            Ok(bytes) => {
                String::from_utf8(bytes).map_err(|_| ServiceRegError::Os("the unit is not ours"))?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ServiceRegError::Os("the unit could not be read")),
        };
        if text.lines().next() != Some(MARKER) {
            return Err(ServiceRegError::Os("the unit is not ours"));
        }
        let mut execs = text.lines().filter_map(|l| l.strip_prefix("ExecStart="));
        let (Some(exec), None) = (execs.next(), execs.next()) else {
            return Err(ServiceRegError::Os("the unit is not ours"));
        };
        let link = PathBuf::from(exec);
        let shaped = unit_safe(exec)
            && link.is_absolute()
            && link.file_name().and_then(|n| n.to_str()) == Some(SERVICE_FILE_UNIX);
        if !shaped {
            return Err(ServiceRegError::Os("the unit is not ours"));
        }
        Ok(Some(link))
    }
}

/// Reads at most [`MAX_UNIT_BYTES`] of `path`, not following a link.
fn read_capped(path: &Path) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_UNIT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_UNIT_BYTES {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(bytes)
}

/// Makes `dir`'s entries durable.
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Writes `bytes` to `dir/name` through a temporary file renamed over it, mode 0644, durable.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let temp = dir.join(format!(".{name}.lunepack-tmp"));
    let _ = fs::remove_file(&temp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temp, dir.join(name))?;
    sync_dir(dir)
}

/// The stable link's target for `version`'s image: `service/<version>/lunepack-service`, relative
/// to the machine directory the link is in.
fn link_target(version: &lunepack_core::Version) -> String {
    format!("{MACHINE_SERVICE_DIR}/{version}/{SERVICE_FILE_UNIX}")
}

/// Points the stable link `link` at `target`: a new link beside it renamed over it, then the
/// directory synced.
fn switch_link(link: &Path, target: &str) -> io::Result<()> {
    let dir = link
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let temp = dir.join(format!(".{SERVICE_FILE_UNIX}.lunepack-new"));
    match fs::remove_file(&temp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    symlink(target, &temp)?;
    fs::rename(&temp, link)?;
    sync_dir(dir)
}

/// The layout and version of a Linux service image, else an error.
fn image_layout(image: &Path) -> Result<(MachineLayout, lunepack_core::Version), ServiceRegError> {
    MachineLayout::of_service_image_as(image, MachineScheme::LINUX)
        .ok_or(ServiceRegError::Os("not a service image"))
}

impl ServiceRegistrar for SystemdRegistrar {
    fn register(&self, app_id: &AppId, image: &Path) -> Result<(), ServiceRegError> {
        let (layout, version) = image_layout(image)?;
        let link = layout
            .stable_service_link()
            .ok_or(ServiceRegError::Os("no stable link"))?;
        let service = service_unit_text(app_id, &link)
            .ok_or(ServiceRegError::Os("the install root is not a plain path"))?;
        switch_link(&link, &link_target(&version))
            .map_err(|_| ServiceRegError::Os("the service link could not be written"))?;
        let socket_unit = endpoint::systemd_socket_unit(app_id);
        let service_unit = endpoint::systemd_service_unit(app_id);
        write_atomic(&self.unit_dir, &service_unit, service.as_bytes())
            .and_then(|()| {
                write_atomic(
                    &self.unit_dir,
                    &socket_unit,
                    socket_unit_text(app_id).as_bytes(),
                )
            })
            .map_err(|_| ServiceRegError::Os("the units could not be written"))?;
        self.systemctl(&["daemon-reload"])?;
        self.systemctl(&["enable", "--now", &socket_unit])
    }

    fn image(&self, app_id: &AppId) -> Result<Option<PathBuf>, ServiceRegError> {
        let Some(link) = self.registered_link(app_id)? else {
            return Ok(None);
        };
        let target = fs::read_link(&link)
            .map_err(|_| ServiceRegError::Os("the service link could not be read"))?;
        // Only `service/<version>/lunepack-service`, relative: never a path out of `R`.
        let plain = target.is_relative()
            && target
                .components()
                .all(|c| matches!(c, Component::Normal(_)));
        let dir = link
            .parent()
            .ok_or(ServiceRegError::Os("the unit is not ours"))?;
        let image = dir.join(&target);
        let (layout, _) = image_layout(&image)?;
        if !plain || layout.stable_service_link().as_deref() != Some(link.as_path()) {
            return Err(ServiceRegError::Os("the service link is not ours"));
        }
        Ok(Some(image))
    }

    fn set_image(&self, app_id: &AppId, image: &Path) -> Result<(), ServiceRegError> {
        let (layout, version) = image_layout(image)?;
        let link = self
            .registered_link(app_id)?
            .ok_or(ServiceRegError::NotRegistered)?;
        if layout.stable_service_link().as_deref() != Some(link.as_path()) {
            return Err(ServiceRegError::Os("the image is another install's"));
        }
        switch_link(&link, &link_target(&version))
            .map_err(|_| ServiceRegError::Os("the service link could not be switched"))
    }

    fn self_test(&self, image: &Path) -> Result<(), ServiceRegError> {
        let mut child = Command::new(image)
            .arg("--self-test")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ServiceRegError::SelfTestFailed)?;
        let deadline = Instant::now() + SELF_TEST_LIMIT;
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(_)) => return Err(ServiceRegError::SelfTestFailed),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(None) | Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ServiceRegError::SelfTestFailed);
                }
            }
        }
    }

    fn remove(&self, app_id: &AppId) -> Result<(), ServiceRegError> {
        let socket = self.socket_unit_path(app_id);
        let service = self.service_unit_path(app_id);
        let present = |p: &Path| fs::symlink_metadata(p).is_ok();
        if !present(&socket) && !present(&service) {
            return Ok(());
        }
        let socket_unit = endpoint::systemd_socket_unit(app_id);
        let service_unit = endpoint::systemd_service_unit(app_id);
        self.systemctl(&["disable", "--now", &socket_unit, &service_unit])?;
        for path in [&socket, &service] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return Err(ServiceRegError::Os("a unit could not be removed")),
            }
        }
        sync_dir(&self.unit_dir).map_err(|_| ServiceRegError::Os("the unit folder"))?;
        self.systemctl(&["daemon-reload"])
    }
}
