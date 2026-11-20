//! The macOS installer app and its `.dmg` (M8-D7, M8-D9 step 9).
//!
//! [`write_app`] lays `Install <name>.app` out in a directory, from bytes the caller took out of
//! the release's verified frames. [`Hdiutil`] then builds the image with the system's `hdiutil`
//! (argv, never a shell), bounded in time, with one retry after a pause when `hdiutil create` fails
//! with "Resource busy" (GitHub's hosted Macs do that now and then), and verifies it.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::tool;

/// The installer app's executable and runtime, as M8-D7 names them.
pub const UI_NAME: &str = "lunepack-ui";
/// The runtime's file name in the installer app.
pub const RUNTIME_NAME: &str = "lunepack-runtime";
/// The payload file's name in `Contents/Resources`.
pub const PAYLOAD_NAME: &str = "lunepack-setup.payload";
/// The icon's file name in `Contents/Resources`, without the extension (`CFBundleIconFile`).
pub const ICON_NAME: &str = "lunepack-installer";

/// The system `hdiutil`.
const SYSTEM_HDIUTIL: &str = "/usr/bin/hdiutil";
/// How long `hdiutil create` may run.
const CREATE_TIMEOUT: Duration = Duration::from_secs(20 * 60);
/// How long `hdiutil verify` may run.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// How many times `hdiutil verify` is tried while the image is still busy (a pause between).
const VERIFY_ATTEMPTS: u32 = 6;
/// The pause before the one retry after "Resource busy".
const BUSY_PAUSE: Duration = Duration::from_secs(5);
/// Longest volume name, in characters (M8-D9).
pub const MAX_VOLUME_CHARS: usize = 27;

/// The files of the installer app (M8-D7). Every byte is from a verified frame or generated.
pub struct InstallerApp<'a> {
    /// The app's directory name, `Install <name>.app`.
    pub dir_name: &'a str,
    /// The release's UI binary: the app's main executable.
    pub ui: &'a [u8],
    /// The release's runtime, beside the UI.
    pub runtime: &'a [u8],
    /// The generated `Info.plist`.
    pub plist: &'a [u8],
    /// The payload file (FORMAT.md 14 without the runtime part).
    pub payload: &'a [u8],
    /// The `.icns` file, when the release has one.
    pub icon: Option<&'a [u8]>,
}

fn make_dir(path: &Path) -> Result<()> {
    fs::create_dir(path).with_context(|| format!("cannot create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("cannot set the mode of {}", path.display()))?;
    }
    Ok(())
}

fn make_file(path: &Path, bytes: &[u8], exec: bool) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .with_context(|| format!("cannot write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = if exec { 0o755 } else { 0o644 };
        file.set_permissions(fs::Permissions::from_mode(mode))
            .with_context(|| format!("cannot set the mode of {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = exec;
    Ok(())
}

/// Writes the installer app into the existing directory `parent` and returns its path. Nothing
/// is overwritten (`create_new` everywhere) and no extended attribute is set.
pub fn write_app(parent: &Path, app: &InstallerApp<'_>) -> Result<PathBuf> {
    let root = parent.join(app.dir_name);
    let contents = root.join("Contents");
    let macos = contents.join("MacOS");
    let resources = contents.join("Resources");
    for dir in [&root, &contents, &macos, &resources] {
        make_dir(dir)?;
    }
    make_file(&macos.join(UI_NAME), app.ui, true)?;
    make_file(&macos.join(RUNTIME_NAME), app.runtime, true)?;
    make_file(&contents.join("Info.plist"), app.plist, false)?;
    make_file(&resources.join(PAYLOAD_NAME), app.payload, false)?;
    if let Some(icon) = app.icon {
        make_file(&resources.join(format!("{ICON_NAME}.icns")), icon, false)?;
    }
    Ok(root)
}

/// The volume name of the image: `name` cut to [`MAX_VOLUME_CHARS`] characters.
pub fn volume_name(name: &str) -> String {
    name.chars().take(MAX_VOLUME_CHARS).collect()
}

/// A way to run `hdiutil`; the fields are public to the module's tests. (`create` and `verify` still
/// take a scratch directory; since M9 step 2 the runner keeps the output in memory and ignores it.)
pub struct Hdiutil {
    program: PathBuf,
    create_timeout: Duration,
    verify_timeout: Duration,
    busy_pause: Duration,
}

/// What a bounded run produced.
struct Ran {
    success: bool,
    /// Its standard error, then its standard output, as text (each capped by the runner).
    output: String,
}

impl Hdiutil {
    /// The system's `hdiutil` with the production bounds.
    pub fn system() -> Hdiutil {
        Hdiutil {
            program: PathBuf::from(SYSTEM_HDIUTIL),
            create_timeout: CREATE_TIMEOUT,
            verify_timeout: VERIFY_TIMEOUT,
            busy_pause: BUSY_PAUSE,
        }
    }

    /// Runs `hdiutil args...` through the bounded tool runner (M9-D3), killing it after `timeout`.
    fn run(&self, args: &[&std::ffi::OsStr], timeout: Duration) -> Result<Ran> {
        let mut argv: Vec<OsString> = vec![self.program.clone().into_os_string()];
        argv.extend(args.iter().map(|a| (*a).to_owned()));
        match tool::run_captured(&argv, timeout) {
            Ok(c) => Ok(Ran {
                success: c.status.success(),
                output: format!(
                    "{}{}",
                    String::from_utf8_lossy(&c.stderr),
                    String::from_utf8_lossy(&c.stdout)
                ),
            }),
            Err(e) if e.is_timeout() => bail!(
                "hdiutil did not finish within {} seconds and was stopped",
                timeout.as_secs()
            ),
            Err(e) => Err(anyhow::Error::new(e).context("hdiutil could not be run")),
        }
    }

    /// `hdiutil create -format ULMO -fs APFS -volname <volname> -srcfolder <src> <out>`, with one
    /// retry after a pause when it fails with "Resource busy". `out` must end in `.dmg` (hdiutil
    /// would add the extension itself) and must not exist; a partial file a failed run left is
    /// removed before the retry (it is the file this call asked `hdiutil` to create).
    pub fn create(&self, volname: &str, src: &Path, out: &Path, _scratch: &Path) -> Result<()> {
        if out.extension().and_then(|e| e.to_str()) != Some("dmg") {
            bail!("{}: the image's file name must end in .dmg", out.display());
        }
        let args: Vec<&std::ffi::OsStr> = vec![
            "create".as_ref(),
            "-format".as_ref(),
            "ULMO".as_ref(),
            "-fs".as_ref(),
            "APFS".as_ref(),
            "-volname".as_ref(),
            volname.as_ref(),
            // No Spotlight index of the scratch volume: `mds` opening it is what leaves the image
            // attached (and `verify` "Resource temporarily unavailable") on a busy Mac.
            "-nospotlight".as_ref(),
            "-srcfolder".as_ref(),
            src.as_os_str(),
            out.as_os_str(),
        ];
        let mut attempt = 0;
        loop {
            attempt += 1;
            let ran = self.run(&args, self.create_timeout)?;
            if ran.success {
                return Ok(());
            }
            let busy = is_busy(&ran.output);
            if busy && attempt == 1 {
                if fs::symlink_metadata(out).is_ok() {
                    fs::remove_file(out)
                        .with_context(|| format!("cannot remove {}", out.display()))?;
                }
                std::thread::sleep(self.busy_pause);
                continue;
            }
            bail!("hdiutil create failed: {}", ran.output.trim());
        }
    }

    /// `hdiutil verify <dmg>`, with the same one retry after a pause when the image is still busy
    /// (right after `create`, `hdiutil verify` sometimes answers "Resource temporarily
    /// unavailable").
    pub fn verify(&self, dmg: &Path, _scratch: &Path) -> Result<()> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let ran = self.run(&["verify".as_ref(), dmg.as_os_str()], self.verify_timeout)?;
            if ran.success {
                return Ok(());
            }
            if is_busy(&ran.output) && attempt < VERIFY_ATTEMPTS {
                std::thread::sleep(self.busy_pause);
                continue;
            }
            bail!("hdiutil verify failed: {}", ran.output.trim());
        }
    }
}

/// Whether `hdiutil` failed because the image or device is busy for the moment.
fn is_busy(output: &str) -> bool {
    let text = output.to_ascii_lowercase();
    text.contains("resource busy") || text.contains("resource temporarily unavailable")
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use std::time::Instant;

    use super::*;

    /// A fake `hdiutil`: a script that appends a line to `calls`, then runs `body` (with `$n` the
    /// call number).
    fn fake(dir: &Path, body: &str) -> Hdiutil {
        let script = dir.join("hdiutil");
        let calls = dir.join("calls");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$@\" >> '{calls}'\nn=$(wc -l < '{calls}' | tr -d ' ')\n{body}\n",
                calls = calls.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        Hdiutil {
            program: script,
            create_timeout: Duration::from_secs(30),
            verify_timeout: Duration::from_secs(30),
            busy_pause: Duration::from_millis(10),
        }
    }

    fn calls(dir: &Path) -> Vec<String> {
        fs::read_to_string(dir.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn create_passes_the_documented_argv() {
        let tmp = tempfile::tempdir().unwrap();
        let h = fake(tmp.path(), "exit 0");
        let out = tmp.path().join("x.dmg");
        h.create("My Vol", Path::new("/src dir"), &out, tmp.path())
            .unwrap();
        assert_eq!(
            calls(tmp.path()),
            [format!(
                "create -format ULMO -fs APFS -volname My Vol -nospotlight -srcfolder /src dir {}",
                out.display()
            )]
        );
    }

    #[test]
    fn create_retries_once_after_resource_busy() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("x.dmg");
        let h = fake(
            tmp.path(),
            &format!(
                "if [ \"$n\" = 1 ]; then echo partial > '{}'; echo 'hdiutil: create failed - Resource busy' >&2; exit 1; fi\n\
                 [ ! -e '{}' ] || exit 7\nexit 0",
                out.display(),
                out.display()
            ),
        );
        h.create("v", tmp.path(), &out, tmp.path()).unwrap();
        assert_eq!(calls(tmp.path()).len(), 2);
    }

    #[test]
    fn create_gives_up_after_the_second_resource_busy() {
        let tmp = tempfile::tempdir().unwrap();
        let h = fake(
            tmp.path(),
            "echo 'create failed - Resource busy' >&2; exit 1",
        );
        let err = h
            .create("v", tmp.path(), &tmp.path().join("x.dmg"), tmp.path())
            .unwrap_err();
        assert!(format!("{err}").contains("Resource busy"), "{err}");
        assert_eq!(calls(tmp.path()).len(), 2);
    }

    #[test]
    fn verify_retries_while_the_image_is_busy_and_then_gives_up() {
        let tmp = tempfile::tempdir().unwrap();
        let dmg = tmp.path().join("x.dmg");
        let h = fake(
            tmp.path(),
            "if [ \"$n\" -lt 3 ]; then echo 'verify: Resource temporarily unavailable' >&2; exit 1; fi\nexit 0",
        );
        h.verify(&dmg, tmp.path()).unwrap();
        assert_eq!(calls(tmp.path()).len(), 3);
        let tmp2 = tempfile::tempdir().unwrap();
        let h = fake(
            tmp2.path(),
            "echo 'verify: Resource temporarily unavailable' >&2; exit 1",
        );
        let err = h.verify(&dmg, tmp2.path()).unwrap_err();
        assert!(
            format!("{err}").contains("temporarily unavailable"),
            "{err}"
        );
        assert_eq!(calls(tmp2.path()).len(), VERIFY_ATTEMPTS as usize);
    }

    #[test]
    fn another_failure_is_not_retried() {
        let tmp = tempfile::tempdir().unwrap();
        let h = fake(tmp.path(), "echo 'no space left' >&2; exit 1");
        let err = h
            .create("v", tmp.path(), &tmp.path().join("x.dmg"), tmp.path())
            .unwrap_err();
        assert!(format!("{err}").contains("no space left"), "{err}");
        assert_eq!(calls(tmp.path()).len(), 1);
    }

    #[test]
    fn a_run_past_its_bound_is_killed() {
        let tmp = tempfile::tempdir().unwrap();
        let mut h = fake(tmp.path(), "exec sleep 30");
        h.create_timeout = Duration::from_millis(200);
        let started = Instant::now();
        let err = h
            .create("v", tmp.path(), &tmp.path().join("x.dmg"), tmp.path())
            .unwrap_err();
        assert!(format!("{err}").contains("did not finish"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn the_image_name_must_end_in_dmg() {
        let tmp = tempfile::tempdir().unwrap();
        let h = fake(tmp.path(), "exit 0");
        assert!(
            h.create("v", tmp.path(), &tmp.path().join("x.img"), tmp.path())
                .is_err()
        );
        assert!(calls(tmp.path()).is_empty());
    }

    #[test]
    fn verify_reports_a_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let h = fake(tmp.path(), "echo 'bad checksum' >&2; exit 1");
        let err = h.verify(&tmp.path().join("x.dmg"), tmp.path()).unwrap_err();
        assert!(format!("{err}").contains("bad checksum"), "{err}");
        assert_eq!(
            calls(tmp.path()),
            [format!("verify {}", tmp.path().join("x.dmg").display())]
        );
    }

    #[test]
    fn the_volume_name_is_cut_at_27_characters() {
        assert_eq!(volume_name("Hello"), "Hello");
        let long = "\u{e9}".repeat(40);
        assert_eq!(volume_name(&long).chars().count(), 27);
    }

    #[test]
    fn write_app_lays_the_files_out_and_refuses_to_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let app = InstallerApp {
            dir_name: "Install Hello.app",
            ui: b"ui",
            runtime: b"rt",
            plist: b"plist",
            payload: b"payload!",
            icon: Some(b"icns"),
        };
        let root = write_app(tmp.path(), &app).unwrap();
        let mode = |p: &str| fs::metadata(root.join(p)).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            fs::read(root.join("Contents/MacOS/lunepack-ui")).unwrap(),
            b"ui"
        );
        assert_eq!(mode("Contents/MacOS/lunepack-ui"), 0o755);
        assert_eq!(mode("Contents/MacOS/lunepack-runtime"), 0o755);
        assert_eq!(mode("Contents/Info.plist"), 0o644);
        assert_eq!(mode("Contents/Resources/lunepack-setup.payload"), 0o644);
        assert_eq!(mode("Contents/Resources/lunepack-installer.icns"), 0o644);
        assert_eq!(mode("Contents"), 0o755);
        assert!(write_app(tmp.path(), &app).is_err());
    }
}
