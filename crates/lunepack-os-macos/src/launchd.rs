//! The update service's registration with launchd (M11-D3, M11-D4): one LaunchDaemon in the
//! system domain, `/Library/LaunchDaemons/lunepack-<app id>.plist`, whose socket `lunepack`
//! listens on `/var/run/lunepack-<app id>.sock` for every local user (`SockPathMode` 438, 0666)
//! and starts the daemon, the stable link `R/.lunepack/machine/lunepack-service`, on the first
//! connection. No `RunAtLoad`, no `KeepAlive`: the daemon exits when idle and launchd keeps the
//! socket.
//!
//! The registered image is what the stable link names; switching the service to another version
//! is a new link renamed over the stable one, so the plist never changes after `register`.
//! `launchctl` runs by absolute path with an empty environment, never through a shell.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use lunepack_core::endpoint;
use lunepack_core::layout::{MACHINE_SERVICE_DIR, SERVICE_FILE_UNIX, UnixOs};
use lunepack_core::{AppId, MachineLayout, MachineScheme, ServiceRegError, ServiceRegistrar};

use crate::integration::{escape, unescape};

/// How long a self-test may run.
pub const SELF_TEST_LIMIT: Duration = Duration::from_secs(10);
/// launchctl.
pub const LAUNCHCTL: &str = "/bin/launchctl";
/// Most bytes of a plist read back.
const MAX_PLIST_BYTES: u64 = 64 * 1024;
/// The comment that marks a plist as lunepack's.
const MARKER: &str = "<!-- Written by lunepack; do not edit. -->";
/// How long a replaced job may take to leave the system domain before `bootstrap` (a bootstrap
/// racing the bootout before it fails; seen by probe P-M3's re-install).
const BOOTOUT_WAIT: Duration = Duration::from_secs(5);
/// How many times `bootstrap` is tried, a second apart.
const BOOTSTRAP_TRIES: u32 = 3;

/// Whether `path` is a regular file owned by root that neither its group nor others may write.
fn root_tool(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0)
}

/// The LaunchDaemon property list of `app_id` whose daemon is the stable link `exec` (M11-D4),
/// byte for byte. `bundle_id`, the bundle identifier the signed install metadata carries, adds
/// `AssociatedBundleIdentifiers` (so the system shows the daemon under the app); without one the
/// key is left out. Every string is XML-escaped; `None` when a string holds a control character.
pub fn daemon_plist(app_id: &AppId, exec: &Path, bundle_id: Option<&str>) -> Option<String> {
    let exec = exec.to_str()?;
    let plain = |t: &str| !t.is_empty() && !t.chars().any(char::is_control);
    if !plain(exec) || !bundle_id.is_none_or(plain) {
        return None;
    }
    let label = endpoint::launchd_label(app_id);
    let socket = endpoint::socket_path(UnixOs::Macos, app_id);
    let socket = socket.to_str()?;
    let associated = match bundle_id {
        Some(id) => format!(
            "\t<key>AssociatedBundleIdentifiers</key>\n\
             \t<array>\n\
             \t\t<string>{}</string>\n\
             \t</array>\n",
            escape(id)
        ),
        None => String::new(),
    };
    Some(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         {MARKER}\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{label}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         \t\t<string>{exec}</string>\n\
         \t</array>\n\
         \t<key>Sockets</key>\n\
         \t<dict>\n\
         \t\t<key>{name}</key>\n\
         \t\t<dict>\n\
         \t\t\t<key>SockPathName</key>\n\
         \t\t\t<string>{socket}</string>\n\
         \t\t\t<key>SockPathMode</key>\n\
         \t\t\t<integer>438</integer>\n\
         \t\t</dict>\n\
         \t</dict>\n\
         {associated}\
         </dict>\n\
         </plist>\n",
        label = escape(&label),
        exec = escape(exec),
        name = endpoint::LAUNCHD_SOCKET_NAME,
        socket = escape(socket),
    ))
}

/// The daemon's program in a plist [`daemon_plist`] wrote: the one string of `ProgramArguments`.
fn program_of(text: &str) -> Option<PathBuf> {
    if text.lines().nth(2) != Some(MARKER) {
        return None;
    }
    const START: &str = "\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>";
    let mut found = text.match_indices(START);
    let (at, _) = found.next()?;
    if found.next().is_some() {
        return None;
    }
    let rest = &text[at + START.len()..];
    let end = rest.find("</string>\n\t</array>\n")?;
    Some(PathBuf::from(unescape(&rest[..end])?))
}

/// [`ServiceRegistrar`] over launchd's system domain.
#[derive(Debug, Clone)]
pub struct LaunchdRegistrar {
    dir: PathBuf,
    launchctl: PathBuf,
    /// Whether launchctl must be a root-owned file (false only in tests, which run a fake).
    require_root_tool: bool,
    /// The bundle identifier from the signed install metadata, for `AssociatedBundleIdentifiers`.
    bundle_id: Option<String>,
}

impl LaunchdRegistrar {
    /// Daemons in [`endpoint::LAUNCH_DAEMONS_DIR`], [`LAUNCHCTL`]; `bundle_id` from the signed
    /// install metadata (or `None`).
    pub fn new(bundle_id: Option<String>) -> LaunchdRegistrar {
        LaunchdRegistrar {
            dir: PathBuf::from(endpoint::LAUNCH_DAEMONS_DIR),
            launchctl: PathBuf::from(LAUNCHCTL),
            require_root_tool: true,
            bundle_id,
        }
    }

    /// For tests: plists in `dir` and `launchctl` (a fake) run instead. Never used by a
    /// composition root.
    #[doc(hidden)]
    pub fn for_tests(
        dir: PathBuf,
        launchctl: PathBuf,
        bundle_id: Option<String>,
    ) -> LaunchdRegistrar {
        LaunchdRegistrar {
            dir,
            launchctl,
            require_root_tool: false,
            bundle_id,
        }
    }

    fn plist_path(&self, app_id: &AppId) -> PathBuf {
        self.dir
            .join(format!("{}.plist", endpoint::launchd_label(app_id)))
    }

    /// Runs launchctl with `args`; its exit code (`None` for a signal).
    fn launchctl(&self, args: &[&str]) -> Result<Option<i32>, ServiceRegError> {
        if self.require_root_tool && !root_tool(&self.launchctl) {
            return Err(ServiceRegError::Os("launchctl not found"));
        }
        let status = Command::new(&self.launchctl)
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| ServiceRegError::Os("launchctl could not be run"))?;
        Ok(status.code())
    }

    /// Whether the job `label` is loaded in the system domain.
    fn loaded(&self, label: &str) -> Result<bool, ServiceRegError> {
        Ok(self.launchctl(&["print", &format!("system/{label}")])? == Some(0))
    }

    /// Unloads `label`, waiting until it has left the domain.
    fn bootout(&self, label: &str) -> Result<(), ServiceRegError> {
        if !self.loaded(label)? {
            return Ok(());
        }
        let _ = self.launchctl(&["bootout", &format!("system/{label}")])?;
        let deadline = Instant::now() + BOOTOUT_WAIT;
        while self.loaded(label)? {
            if Instant::now() >= deadline {
                return Err(ServiceRegError::Os("the old job did not unload"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }

    /// The stable link the plist names; `None` when there is no plist.
    fn registered_link(&self, app_id: &AppId) -> Result<Option<PathBuf>, ServiceRegError> {
        let bytes = match read_capped(&self.plist_path(app_id)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ServiceRegError::Os("the plist could not be read")),
        };
        let text = String::from_utf8(bytes).map_err(|_| ServiceRegError::Os("not ours"))?;
        let link = program_of(&text).ok_or(ServiceRegError::Os("the plist is not ours"))?;
        let shaped = link.is_absolute()
            && link.file_name().and_then(|n| n.to_str()) == Some(SERVICE_FILE_UNIX);
        if !shaped {
            return Err(ServiceRegError::Os("the plist is not ours"));
        }
        Ok(Some(link))
    }
}

fn read_capped(path: &Path) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_PLIST_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PLIST_BYTES {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(bytes)
}

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
    file.set_permissions(fs::Permissions::from_mode(0o644))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temp, dir.join(name))?;
    sync_dir(dir)
}

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

fn image_layout(image: &Path) -> Result<(MachineLayout, lunepack_core::Version), ServiceRegError> {
    MachineLayout::of_service_image_as(image, MachineScheme::MACOS)
        .ok_or(ServiceRegError::Os("not a service image"))
}

impl ServiceRegistrar for LaunchdRegistrar {
    fn register(&self, app_id: &AppId, image: &Path) -> Result<(), ServiceRegError> {
        let (layout, version) = image_layout(image)?;
        let link = layout
            .stable_service_link()
            .ok_or(ServiceRegError::Os("no stable link"))?;
        let plist = daemon_plist(app_id, &link, self.bundle_id.as_deref())
            .ok_or(ServiceRegError::Os("the install root is not plain text"))?;
        switch_link(&link, &link_target(&version))
            .map_err(|_| ServiceRegError::Os("the service link could not be written"))?;
        let label = endpoint::launchd_label(app_id);
        self.bootout(&label)?;
        let name = format!("{label}.plist");
        write_atomic(&self.dir, &name, plist.as_bytes())
            .map_err(|_| ServiceRegError::Os("the plist could not be written"))?;
        let path = self.dir.join(&name);
        let path = path
            .to_str()
            .ok_or(ServiceRegError::Os("the plist path is not text"))?;
        let mut last = None;
        for attempt in 0..BOOTSTRAP_TRIES {
            if attempt > 0 {
                std::thread::sleep(Duration::from_secs(1));
            }
            match self.launchctl(&["bootstrap", "system", path])? {
                Some(0) => return Ok(()),
                code => last = code,
            }
        }
        Err(match last {
            Some(code) => ServiceRegError::OsCode("launchctl bootstrap", code.unsigned_abs()),
            None => ServiceRegError::Os("launchctl ended by a signal"),
        })
    }

    fn image(&self, app_id: &AppId) -> Result<Option<PathBuf>, ServiceRegError> {
        let Some(link) = self.registered_link(app_id)? else {
            return Ok(None);
        };
        let target = fs::read_link(&link)
            .map_err(|_| ServiceRegError::Os("the service link could not be read"))?;
        let plain = target.is_relative()
            && target
                .components()
                .all(|c| matches!(c, Component::Normal(_)));
        let dir = link
            .parent()
            .ok_or(ServiceRegError::Os("the plist is not ours"))?;
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
        let path = self.plist_path(app_id);
        let label = endpoint::launchd_label(app_id);
        self.bootout(&label)?;
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(ServiceRegError::Os("the plist could not be removed")),
        }
        sync_dir(&self.dir).map_err(|_| ServiceRegError::Os("the daemons folder"))
    }
}
