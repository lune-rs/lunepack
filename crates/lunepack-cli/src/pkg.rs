//! The macOS installer package for all users (M11-D8, M11 step 7).
//!
//! `setup` builds one `.pkg` per macOS release that holds the update service. Its payload is the
//! release's own `lunepack-runtime` and the payload file of FORMAT.md 14.4, laid out under the
//! machine home's root-only `.installer/<app id>/` folder (variant V1: the payload starts at `/`,
//! so the folders above `.installer` are recorded as root 0755, which Installer leaves alone on a
//! Mac where they exist). Its only script is a `postinstall` that runs that runtime as
//! `machine-install --pkg` and passes it nothing Installer could influence.
//!
//! The package is built with the system's `pkgbuild` and `productbuild` (argv, never a shell,
//! bounded in time, through [`crate::tool`]) on a macOS host only, as the `.dmg` is built with
//! `hdiutil`. Signing, notarizing and stapling are the signing stage's ([`crate::codesign`]).

use std::fs::{self, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use flate2::read::ZlibDecoder;
use lunepack_core::AppId;
use lunepack_core::layout::MACHINE_HOME_MACOS;

use crate::dmg::{PAYLOAD_NAME, RUNTIME_NAME};
use crate::tool;

/// The system `pkgbuild`.
const SYSTEM_PKGBUILD: &str = "/usr/bin/pkgbuild";
/// The system `productbuild`.
const SYSTEM_PRODUCTBUILD: &str = "/usr/bin/productbuild";
/// How long each of the two tools may run.
const BUILD_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// The component package's file name inside the build directory.
const COMPONENT_NAME: &str = "component.pkg";
/// The folder of the machine home that holds the payload of every app's first install.
const INSTALLER_DIR: &str = ".installer";

/// What the package is made of; every byte is from a verified frame or generated.
pub struct PkgSpec<'a> {
    /// The app id: the payload's folder, and the package identifier's stem.
    pub app_id: &'a AppId,
    /// The release's version, as written in its manifest (shown by Installer).
    pub version: &'a str,
    /// The installer's title: the signed display name.
    pub title: &'a str,
    /// The oldest macOS the package accepts (`x.y`).
    pub min_os: &'a str,
    /// The release's `lunepack-runtime`.
    pub runtime: &'a [u8],
    /// The payload file (FORMAT.md 14.4).
    pub payload: &'a [u8],
}

/// The tools that build a `.pkg`; the fields are public to the module's tests.
pub struct PkgTools {
    pkgbuild: PathBuf,
    productbuild: PathBuf,
    timeout: Duration,
}

impl PkgTools {
    /// The system's tools with the production bound.
    pub fn system() -> PkgTools {
        PkgTools {
            pkgbuild: PathBuf::from(SYSTEM_PKGBUILD),
            productbuild: PathBuf::from(SYSTEM_PRODUCTBUILD),
            timeout: BUILD_TIMEOUT,
        }
    }

    /// Builds the package of `spec` into the new file `out`, working in new folders under the
    /// existing directory `work` (the caller removes it).
    pub fn build(&self, spec: &PkgSpec<'_>, work: &Path, out: &Path) -> Result<()> {
        if !cfg!(target_os = "macos") {
            bail!("a .pkg is built on a macOS host only");
        }
        if fs::symlink_metadata(out).is_ok() {
            bail!("{} already exists", out.display());
        }
        let leaf = leaf_dir(spec.app_id);
        let root = work.join("pkg-root");
        let scripts = work.join("pkg-scripts");
        let parts = work.join("pkg-parts");
        // The payload root is recorded as `/` itself: root 0755 like every folder above `.installer`
        // (the work directory around it is the caller's private scratch).
        make_dir(&root, 0o755)?;
        make_dir(&scripts, 0o700)?;
        make_dir(&parts, 0o700)?;
        // The payload tree: each folder with the mode the package must record (P4, M11-D8).
        let mut at = root.clone();
        let mut below_installer = false;
        for component in leaf.split('/').filter(|c| !c.is_empty()) {
            at = at.join(component);
            below_installer |= component == INSTALLER_DIR;
            make_dir(&at, if below_installer { 0o700 } else { 0o755 })?;
        }
        write_file(&at.join(RUNTIME_NAME), spec.runtime, 0o700)?;
        write_file(&at.join(PAYLOAD_NAME), spec.payload, 0o600)?;
        write_file(
            &scripts.join("postinstall"),
            postinstall(spec.app_id).as_bytes(),
            0o755,
        )?;

        let identifier = identifier(spec.app_id);
        let component = parts.join(COMPONENT_NAME);
        self.run(
            &self.pkgbuild,
            &[
                "--root".as_ref(),
                root.as_os_str(),
                "--install-location".as_ref(),
                "/".as_ref(),
                "--scripts".as_ref(),
                scripts.as_os_str(),
                "--identifier".as_ref(),
                identifier.as_ref(),
                "--version".as_ref(),
                spec.version.as_ref(),
                "--ownership".as_ref(),
                "recommended".as_ref(),
                component.as_os_str(),
            ],
        )?;
        let dist = work.join("distribution.xml");
        write_file(
            &dist,
            distribution(&identifier, spec.version, spec.title, spec.min_os)?.as_bytes(),
            0o600,
        )?;
        self.run(
            &self.productbuild,
            &[
                "--distribution".as_ref(),
                dist.as_os_str(),
                "--package-path".as_ref(),
                parts.as_os_str(),
                out.as_os_str(),
            ],
        )
    }

    fn run(&self, program: &Path, args: &[&std::ffi::OsStr]) -> Result<()> {
        let mut argv: Vec<std::ffi::OsString> = vec![program.as_os_str().to_owned()];
        argv.extend(args.iter().map(|a| (*a).to_owned()));
        tool::run_tool(&argv, self.timeout, &[])
            .map(drop)
            .map_err(|e| anyhow::anyhow!("{e}"))
    }
}

/// The payload folder of `app_id` below `/`: `Library/Application Support/lunepack/.installer/<id>`.
fn leaf_dir(app_id: &AppId) -> String {
    format!(
        "{}/{INSTALLER_DIR}/{}",
        MACHINE_HOME_MACOS.trim_start_matches('/'),
        app_id.as_str()
    )
}

/// The component package's identifier: the app id with `_` as `-` (a package identifier allows
/// letters, digits, `.` and `-`), then `.lunepack-machine`.
pub fn identifier(app_id: &AppId) -> String {
    format!("{}.lunepack-machine", app_id.as_str().replace('_', "-"))
}

/// The package's `postinstall` (M11-D8): one fixed command that runs the staged runtime in its
/// `--pkg` mode. It reads no argument (`$1`..`$4`), no environment variable and changes no
/// directory; an app id is `[a-z0-9._-]`, so the quoted path holds nothing the shell would read.
pub fn postinstall(app_id: &AppId) -> String {
    format!(
        "#!/bin/sh\nexec \"{MACHINE_HOME_MACOS}/{INSTALLER_DIR}/{}/{RUNTIME_NAME}\" machine-install --pkg\n",
        app_id.as_str()
    )
}

/// The distribution document: the local system domain only (`enable_localSystem`; no user-home
/// or anywhere install), no customization, one hidden choice for the component package.
pub fn distribution(identifier: &str, version: &str, title: &str, min_os: &str) -> Result<String> {
    if title.chars().any(char::is_control) {
        bail!("the installer's title holds a control character");
    }
    let (identifier, version, title, min_os) = (
        xml_escape(identifier),
        xml_escape(version),
        xml_escape(title),
        xml_escape(min_os),
    );
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
<installer-gui-script minSpecVersion=\"2\">\n\
  <title>{title}</title>\n\
  <domains enable_localSystem=\"true\" enable_currentUserHome=\"false\" enable_anywhere=\"false\"/>\n\
  <options customize=\"never\" require-scripts=\"false\"/>\n\
  <allowed-os-versions><os-version min=\"{min_os}\"/></allowed-os-versions>\n\
  <choices-outline><line choice=\"default\"><line choice=\"{identifier}\"/></line></choices-outline>\n\
  <choice id=\"default\"/>\n\
  <choice id=\"{identifier}\" visible=\"false\"><pkg-ref id=\"{identifier}\"/></choice>\n\
  <pkg-ref id=\"{identifier}\" version=\"{version}\">{COMPONENT_NAME}</pkg-ref>\n\
</installer-gui-script>\n"
    ))
}

/// `text` as XML character data or an attribute value.
fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

fn make_dir(path: &Path, mode: u32) -> Result<()> {
    fs::create_dir(path).with_context(|| format!("cannot create {}", path.display()))?;
    set_mode(path, mode)
}

fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .with_context(|| format!("cannot write {}", path.display()))?;
    drop(file);
    set_mode(path, mode)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("cannot set the mode of {}", path.display()))
}

/// A `.pkg` is built on a macOS host only ([`PkgTools::build`] refuses elsewhere first).
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// The first bytes of a `xar` archive (the `.pkg` container): the magic.
const XAR_MAGIC: &[u8; 4] = b"xar!";
/// The fixed part of the header up to the checksum algorithm.
const XAR_HEADER_FIXED: usize = 28;
/// The longest table of contents read (compressed and expanded alike).
const MAX_TOC_BYTES: u64 = 16 * 1024 * 1024;

/// Whether the `.pkg` at `path` carries a signature: its `xar` table of contents has a
/// `<signature>` (or CMS `<x-signature>`) element. A sanity check of what the developer's
/// `sign_installer` template did, not a verification (`pkgutil --check-signature` is that).
pub fn pkg_is_signed_file(path: &Path) -> io::Result<bool> {
    let mut file = fs::File::open(path)?;
    let mut fixed = [0u8; XAR_HEADER_FIXED];
    if file.read_exact(&mut fixed).is_err() {
        return Ok(false);
    }
    let be16 = |at: usize| u64::from(u16::from_be_bytes([fixed[at], fixed[at + 1]]));
    let be64 = |at: usize| u64::from_be_bytes(fixed[at..at + 8].try_into().unwrap_or([0; 8]));
    let (header, compressed, expanded) = (be16(4), be64(8), be64(16));
    if &fixed[..4] != XAR_MAGIC
        || header < XAR_HEADER_FIXED as u64
        || compressed == 0
        || compressed > MAX_TOC_BYTES
        || expanded > MAX_TOC_BYTES
    {
        return Ok(false);
    }
    file.seek(SeekFrom::Start(header))?;
    let mut toc = vec![0u8; compressed as usize];
    if file.read_exact(&mut toc).is_err() {
        return Ok(false);
    }
    Ok(toc_is_signed(&toc, expanded))
}

/// Whether the zlib-compressed table of contents `toc` (at most `expanded` bytes once expanded)
/// holds a signature element.
fn toc_is_signed(toc: &[u8], expanded: u64) -> bool {
    let mut xml = Vec::new();
    if ZlibDecoder::new(toc)
        .take(expanded.saturating_add(1))
        .read_to_end(&mut xml)
        .is_err()
        || xml.len() as u64 != expanded
    {
        return false;
    }
    let has = |needle: &[u8]| xml.windows(needle.len()).any(|w| w == needle);
    has(b"<signature ") || has(b"<signature>") || has(b"<x-signature ") || has(b"<x-signature>")
}

#[cfg(test)]
mod tests {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;

    use super::*;

    fn app() -> AppId {
        AppId::parse("org.example.hello_app").unwrap()
    }

    #[test]
    fn the_postinstall_is_one_fixed_command_and_reads_nothing() {
        let text = postinstall(&app());
        assert_eq!(
            text,
            "#!/bin/sh\nexec \"/Library/Application Support/lunepack/.installer/org.example.hello_app/lunepack-runtime\" machine-install --pkg\n"
        );
        // No positional parameter, no environment variable, no `cd`, no second command.
        assert!(!text.contains('$') && !text.contains("cd "), "{text}");
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn the_identifier_uses_only_package_identifier_characters() {
        assert_eq!(identifier(&app()), "org.example.hello-app.lunepack-machine");
    }

    #[test]
    fn the_distribution_allows_the_local_system_domain_only() {
        let text = distribution("org.example.lunepack-machine", "1.2.3", "Hello", "10.15").unwrap();
        assert!(text.contains(
            "<domains enable_localSystem=\"true\" enable_currentUserHome=\"false\" enable_anywhere=\"false\"/>"
        ));
        assert!(text.contains("<os-version min=\"10.15\"/>"));
        assert!(text.contains("<title>Hello</title>"));
        assert!(text.contains("version=\"1.2.3\">component.pkg</pkg-ref>"));
    }

    #[test]
    fn the_title_is_escaped_and_a_control_character_is_refused() {
        let text = distribution("a.b", "1.0.0", "A & B <\"it's\">", "10.15").unwrap();
        assert!(
            text.contains("<title>A &amp; B &lt;&quot;it&apos;s&quot;&gt;</title>"),
            "{text}"
        );
        assert!(distribution("a.b", "1.0.0", "A\nB", "10.15").is_err());
        assert!(distribution("a.b", "1.0.0", "A\u{7f}B", "10.15").is_err());
    }

    /// A `xar` archive's start: the header and a zlib table of contents holding `xml`.
    fn xar(xml: &str) -> Vec<u8> {
        let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
        z.write_all(xml.as_bytes()).unwrap();
        let toc = z.finish().unwrap();
        let mut out = b"xar!".to_vec();
        out.extend_from_slice(&28u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(toc.len() as u64).to_be_bytes());
        out.extend_from_slice(&(xml.len() as u64).to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&toc);
        out.extend_from_slice(&[0u8; 64]);
        out
    }

    fn signed(bytes: &[u8]) -> bool {
        let dir = tempfile::tempdir().unwrap();
        let at = dir.path().join("x.pkg");
        fs::write(&at, bytes).unwrap();
        pkg_is_signed_file(&at).unwrap()
    }

    #[test]
    fn a_signature_element_in_the_table_of_contents_is_a_signed_package() {
        let toc = |inner: &str| format!("<xar><toc><checksum style=\"sha1\"/>{inner}</toc></xar>");
        assert!(signed(&xar(&toc(
            "<signature style=\"RSA\"><size>256</size></signature>"
        ))));
        assert!(signed(&xar(&toc(
            "<x-signature style=\"CMS\"><size>9</size></x-signature>"
        ))));
        assert!(!signed(&xar(&toc("<file><name>Bom</name></file>"))));
        // A file's name is escaped in the table, so it cannot spell the element.
        assert!(!signed(&xar(&toc(
            "<file><name>&lt;signature &gt;</name></file>"
        ))));
    }

    #[test]
    fn the_signed_check_is_total_on_short_or_foreign_input() {
        assert!(!signed(&[]));
        assert!(!signed(b"xar!"));
        assert!(!signed(&[0u8; 200]));
        let mut bad = xar("<signature >");
        bad[0] = b'y';
        assert!(!signed(&bad));
        // A table that expands to more or less than its header says.
        let mut lying = xar("<signature >");
        lying[16..24].copy_from_slice(&5u64.to_be_bytes());
        assert!(!signed(&lying));
        // A table whose compressed size is absurd.
        let mut huge = xar("<signature >");
        huge[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(!signed(&huge));
        // A table cut short.
        let whole = xar("<signature >");
        assert!(!signed(&whole[..34]));
    }
}
