//! Stamping of the Windows stub and the setup file's runtime (M7-D14, step 12): an icon and a
//! VERSIONINFO resource written with `editpe` (pure Rust), then a check that nothing the hardening
//! of M7-D10 depends on changed (P3).
//!
//! Every function works on bytes: no file is opened here. The output is a function of the input
//! bytes and the [`Fields`] only (no time, no host), so stamping twice gives the same bytes (C2).
//! Messages name a field or an option, never a value read from a file.

use std::fmt;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use editpe::types::{FixedFileInfo, VersionU16, VersionU32};
use editpe::{Image, VersionInfo, VersionStringTable};
use lunepack_core::pe::{PeHeaders, PeImage};
use lunepack_core::{RelPath, Version};

use crate::release_dir::read_capped;

/// Largest `.ico` or `.png` icon file read, in bytes.
pub const MAX_ICON_BYTES: u64 = 4 * 1024 * 1024;
/// Most images an `.ico` file may hold.
const MAX_ICO_IMAGES: usize = 64;
/// The string table key of the VERSIONINFO: English (United States), Unicode.
const STRING_TABLE: &str = "040904b0";
/// The PNG file signature.
const PNG_SIGNATURE: [u8; 8] = *b"\x89PNG\r\n\x1a\n";
/// Largest side of a PNG wrapped as an icon, in pixels.
const MAX_PNG_SIDE: u32 = 256;

/// What a stamp writes (M7-D14).
pub struct Fields<'a> {
    /// `FileDescription`: the app's name (the setup file's: `<name> Setup`).
    pub description: &'a str,
    /// `ProductName`: the app's name.
    pub product: &'a str,
    /// `CompanyName`: the publisher, when the config names one.
    pub company: Option<&'a str>,
    /// The release's full version text: `FileVersion` and `ProductVersion`.
    pub version_text: &'a str,
    /// The numeric `major.minor.patch.0`, see [`version_numbers`].
    pub numbers: [u16; 4],
    /// `OriginalFilename`: the stub's entry file name (the setup file's own name).
    pub original_filename: &'a str,
    /// The icon as `.ico` file bytes, checked by [`check_ico`] or built by [`ico_from_png`].
    pub icon: Option<&'a [u8]>,
}

/// `major.minor.patch.0`, each of the three at most 65535 (they are 16-bit fields of the numeric
/// version); a larger one fails the pack and names `--version`.
pub fn version_numbers(version: &Version) -> Result<[u16; 4]> {
    let v = version.as_semver();
    let part = |n: u64| {
        u16::try_from(n).map_err(|_| {
            anyhow!("--version: a Windows target's version components must be at most 65535")
        })
    };
    Ok([part(v.major)?, part(v.minor)?, part(v.patch)?, 0])
}

/// Why bytes are not an icon this packager accepts. Carries no byte of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconError {
    /// Not an ICO file, or a truncated or inconsistent one.
    Ico(&'static str),
    /// Not a PNG file, or one over [`MAX_PNG_SIDE`] pixels or not square.
    Png(&'static str),
}

impl fmt::Display for IconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IconError::Ico(why) => write!(f, "not a valid .ico file ({why})"),
            IconError::Png(why) => write!(f, "not a usable PNG icon ({why})"),
        }
    }
}

impl std::error::Error for IconError {}

fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn le32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// Checks `bytes` as an ICO file: the directory header, between one and 64 entries, every image
/// inside the file and after the directory.
pub fn check_ico(bytes: &[u8]) -> std::result::Result<(), IconError> {
    use IconError::Ico;
    if le16(bytes, 0) != Some(0) || le16(bytes, 2) != Some(1) {
        return Err(Ico("no icon directory header"));
    }
    let count = usize::from(le16(bytes, 4).ok_or(Ico("truncated"))?);
    if count == 0 || count > MAX_ICO_IMAGES {
        return Err(Ico("no images, or too many"));
    }
    let dir_end = 6 + 16 * count;
    if bytes.len() < dir_end {
        return Err(Ico("truncated directory"));
    }
    for i in 0..count {
        let entry = 6 + 16 * i;
        let size = le32(bytes, entry + 8).ok_or(Ico("truncated"))?;
        let offset = le32(bytes, entry + 12).ok_or(Ico("truncated"))?;
        let end = u64::from(offset) + u64::from(size);
        if size == 0 || (offset as usize) < dir_end || end > bytes.len() as u64 {
            return Err(Ico("an image lies outside the file"));
        }
    }
    Ok(())
}

/// Wraps a PNG file as a one-image `.ico` (a PNG-in-ICO entry: no decoding, no resampling, so the
/// bytes are deterministic). The PNG must be square and at most 256 pixels a side.
pub fn ico_from_png(png: &[u8]) -> std::result::Result<Vec<u8>, IconError> {
    use IconError::Png;
    if !png.starts_with(&PNG_SIGNATURE)
        || be32(png, 8) != Some(13)
        || png.get(12..16) != Some(b"IHDR")
    {
        return Err(Png("no PNG header"));
    }
    let width = be32(png, 16).ok_or(Png("truncated"))?;
    let height = be32(png, 20).ok_or(Png("truncated"))?;
    if width == 0 || width != height {
        return Err(Png("not square"));
    }
    if width > MAX_PNG_SIDE {
        return Err(Png("over 256 pixels"));
    }
    // A side of 256 is stored as 0.
    let side = u8::try_from(width).unwrap_or(0);
    let mut ico = Vec::with_capacity(22 + png.len());
    ico.extend_from_slice(&[0, 0, 1, 0, 1, 0]); // reserved, type 1 (icon), one image
    ico.extend_from_slice(&[side, side, 0, 0]); // width, height, colors, reserved
    ico.extend_from_slice(&1u16.to_le_bytes()); // planes
    ico.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
    ico.extend_from_slice(
        &u32::try_from(png.len())
            .map_err(|_| Png("too large"))?
            .to_le_bytes(),
    );
    ico.extend_from_slice(&22u32.to_le_bytes()); // the image follows the directory
    ico.extend_from_slice(png);
    Ok(ico)
}

/// The `[windows] icon` file at `path`, read and checked as an ICO (M7-D14). Errors name the
/// option, never the file's content.
pub fn windows_icon_file(path: &Path) -> Result<Vec<u8>> {
    let bytes = read_capped(path, MAX_ICON_BYTES)
        .map_err(|_| anyhow!("[windows] icon: cannot be read as a file of at most 4 MiB"))?
        .ok_or_else(|| anyhow!("[windows] icon: the file does not exist"))?;
    check_ico(&bytes).map_err(|e| anyhow!("[windows] icon: {e}"))?;
    Ok(bytes)
}

/// The icon `install.icon` gives (M7-D14): an SVG gives none; a PNG is wrapped as a PNG-in-ICO
/// entry, and one that is not square or is over 256 pixels is an error. `read` yields the file's
/// bytes and is called only for a PNG.
pub fn install_icon(
    icon: &RelPath,
    read: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<Option<Vec<u8>>> {
    let name = icon.components().last().unwrap_or_default();
    let ext = name.rsplit_once('.').map_or("", |(_, e)| e);
    if !ext.eq_ignore_ascii_case("png") {
        return Ok(None);
    }
    let bytes = read()?;
    ico_from_png(&bytes)
        .map(Some)
        .map_err(|e| anyhow!("install.icon: {e}"))
}

fn version_info(fields: &Fields<'_>) -> VersionInfo {
    let [major, minor, patch, build] = fields.numbers;
    let number = |hi: u16, lo: u16| (u32::from(hi) << 16) | u32::from(lo);
    let info = FixedFileInfo {
        file_version: VersionU32 {
            major: number(major, minor),
            minor: number(patch, build),
        },
        product_version: VersionU32 {
            major: number(major, minor),
            minor: number(patch, build),
        },
        ..FixedFileInfo::default()
    };
    let mut table = VersionStringTable {
        key: STRING_TABLE.to_owned(),
        ..Default::default()
    };
    let mut put = |key: &str, value: &str| {
        table.strings.insert(key.to_owned(), value.to_owned());
    };
    if let Some(company) = fields.company {
        put("CompanyName", company);
    }
    put("FileDescription", fields.description);
    put("FileVersion", fields.version_text);
    put("OriginalFilename", fields.original_filename);
    put("ProductName", fields.product);
    put("ProductVersion", fields.version_text);
    VersionInfo {
        info,
        strings: vec![table],
        vars: vec![VersionU16 {
            major: 0x0409,
            minor: 0x04b0,
        }],
    }
}

/// Writes the icon and the version info into `image` with `editpe` and returns the new bytes.
fn write_resources(image: &[u8], fields: &Fields<'_>) -> Result<Vec<u8>> {
    let mut image =
        Image::parse(image.to_vec()).context("the image cannot be read for stamping")?;
    let mut resources = image.resource_directory().cloned().unwrap_or_default();
    if let Some(icon) = fields.icon {
        resources
            .set_main_icon(icon)
            .context("the icon cannot be stamped")?;
    }
    resources
        .set_version_info(&version_info(fields))
        .context("the version info cannot be stamped")?;
    image
        .set_resource_directory(resources)
        .context("the resources cannot be written")?;
    let mut out = Vec::new();
    image
        .write_writer(&mut out)
        .context("the stamped image cannot be written")?;
    Ok(out)
}

/// The name of the first field the hardening of M7-D10 depends on that differs between two images
/// (P3), `None` when all are equal: machine, subsystem, imports, delay imports,
/// `DependentLoadFlags`, the `RT_MANIFEST` bytes.
pub fn first_changed_field(before: &PeImage, after: &PeImage) -> Option<&'static str> {
    if before.headers.machine != after.headers.machine {
        Some("machine")
    } else if before.headers.subsystem != after.headers.subsystem {
        Some("subsystem")
    } else if before.imports != after.imports {
        Some("import table")
    } else if before.delay_imports != after.delay_imports {
        Some("delay-import table")
    } else if before.dependent_load_flags != after.dependent_load_flags {
        Some("DependentLoadFlags")
    } else if before.manifest != after.manifest {
        Some("RT_MANIFEST")
    } else {
        None
    }
}

/// A function that stamps image bytes; [`write_resources`] outside tests.
type Stamper = dyn Fn(&[u8], &Fields<'_>) -> Result<Vec<u8>>;

/// Stamps `image` with `fields` through `stamper` and refuses the result when a hardening field
/// changed (P3). `stamper` is [`write_resources`] outside tests.
fn stamp_with(image: &[u8], fields: &Fields<'_>, stamper: &Stamper) -> Result<Vec<u8>> {
    let before = PeImage::parse(image).map_err(|_| anyhow!("the image is not a readable PE"))?;
    let stamped = stamper(image, fields)?;
    let after = PeImage::parse(&stamped)
        .map_err(|_| anyhow!("the stamped image is not a readable PE (nothing was written)"))?;
    if let Some(field) = first_changed_field(&before, &after) {
        bail!("stamping changed the image's {field} (nothing was written)");
    }
    Ok(stamped)
}

/// Stamps `image` (a hardened Windows PE, already checked by the caller) with `fields`, then
/// verifies the P3 invariant: machine, subsystem, imports, `DependentLoadFlags` and the manifest
/// bytes are what they were. The caller checks the result again with `check_pe_stub` or
/// `check_runtime_image`.
pub fn stamp(image: &[u8], fields: &Fields<'_>) -> Result<Vec<u8>> {
    stamp_with(image, fields, &write_resources)
}

/// Removes the Authenticode certificate table of a signed PE, which a stamp would invalidate and
/// which `lunepack setup` must not carry inside its runtime copy (M7-D11). The table must end
/// exactly at the end of the file and start 8-aligned after the image; anything else is refused.
/// An image with no table is returned as it is.
pub fn strip_certificate_table(image: &[u8]) -> Result<Vec<u8>> {
    let headers = PeHeaders::parse(image, image.len() as u64)
        .map_err(|_| anyhow!("the runtime is not a readable PE"))?;
    let table = headers.security();
    if table.is_zero() {
        return Ok(image.to_vec());
    }
    let (offset, size) = (u64::from(table.address), u64::from(table.size));
    if offset % 8 != 0
        || offset < headers.image_end()
        || offset.checked_add(size) != Some(image.len() as u64)
    {
        bail!("the runtime's certificate table is not at the end of the file");
    }
    // The security directory is data directory 4; its entry follows the optional header's fixed
    // part (112 bytes in PE32+, 96 in PE32), which starts 24 bytes after `PE\0\0`.
    let lfanew = le32(image, 0x3C).ok_or_else(|| anyhow!("the runtime's headers are truncated"))?;
    let dirs = lfanew as usize + 24 + if headers.pe32_plus { 112 } else { 96 };
    let entry = dirs + 4 * 8;
    let mut out = image[..offset as usize].to_vec();
    out.get_mut(entry..entry + 8)
        .ok_or_else(|| anyhow!("the runtime's headers are truncated"))?
        .fill(0);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lunepack_testkit::exe_headers::{PeSpec, pe_image};

    const GUI: u16 = 2;

    fn fields(icon: Option<&[u8]>) -> Fields<'_> {
        Fields {
            description: "Hello",
            product: "Hello",
            company: Some("Example Org"),
            version_text: "1.2.3-rc.1+b7",
            numbers: [1, 2, 3, 0],
            original_filename: "hello.exe",
            icon,
        }
    }

    fn png(side: u32) -> Vec<u8> {
        let mut p = PNG_SIGNATURE.to_vec();
        p.extend_from_slice(&13u32.to_be_bytes());
        p.extend_from_slice(b"IHDR");
        p.extend_from_slice(&side.to_be_bytes());
        p.extend_from_slice(&side.to_be_bytes());
        p.extend_from_slice(&[8, 6, 0, 0, 0, 0, 0, 0, 0]);
        p
    }

    #[test]
    fn numbers_name_the_version_option_and_not_the_value() {
        let ok = Version::parse("65535.1.2").unwrap();
        assert_eq!(version_numbers(&ok).unwrap(), [65535, 1, 2, 0]);
        for text in ["65536.0.0", "1.65536.0", "1.0.70000"] {
            let e = version_numbers(&Version::parse(text).unwrap())
                .unwrap_err()
                .to_string();
            assert!(e.starts_with("--version"), "{e}");
            assert!(!e.contains("65536") && !e.contains("70000"), "{e}");
        }
    }

    #[test]
    fn ico_checks() {
        let ico = ico_from_png(&png(64)).unwrap();
        assert_eq!(check_ico(&ico), Ok(()));
        assert_eq!(ico[6], 64);
        assert_eq!(ico_from_png(&png(256)).unwrap()[6], 0, "256 is stored as 0");
        assert!(check_ico(&[]).is_err());
        assert!(check_ico(&ico[..21]).is_err());
        assert!(check_ico(&ico[..ico.len() - 1]).is_err(), "image cut short");
        let mut zero_images = ico.clone();
        zero_images[4] = 0;
        assert!(check_ico(&zero_images).is_err());
        let mut inside_directory = ico.clone();
        inside_directory[18..22].copy_from_slice(&6u32.to_le_bytes());
        assert!(check_ico(&inside_directory).is_err());
        let mut not_icon = ico;
        not_icon[2] = 2;
        assert!(check_ico(&not_icon).is_err());
    }

    #[test]
    fn png_rules() {
        assert!(ico_from_png(&png(1)).is_ok());
        assert_eq!(
            ico_from_png(&png(257)).unwrap_err(),
            IconError::Png("over 256 pixels")
        );
        let mut tall = png(32);
        tall[20..24].copy_from_slice(&33u32.to_be_bytes());
        assert_eq!(
            ico_from_png(&tall).unwrap_err(),
            IconError::Png("not square")
        );
        assert!(ico_from_png(&png(0)).is_err());
        assert!(ico_from_png(b"<svg/>").is_err());
        assert!(ico_from_png(&[]).is_err());
    }

    #[test]
    fn the_hardening_fields_survive_a_stamp_and_the_version_info_reads_back() {
        let spec = PeSpec::hardened(GUI);
        let input = pe_image(0x8664, &spec);
        let ico = ico_from_png(&png(32)).unwrap();
        let out = stamp(&input, &fields(Some(&ico))).expect("stamps");
        let (before, after) = (
            PeImage::parse(&input).unwrap(),
            PeImage::parse(&out).unwrap(),
        );
        assert_eq!(first_changed_field(&before, &after), None);
        assert_eq!(after.headers.machine, 0x8664);
        assert_eq!(after.headers.subsystem, GUI);
        assert_eq!(after.imports, spec.imports);
        assert_eq!(after.delay_imports, spec.delay_imports);
        assert_eq!(after.dependent_load_flags, Some(0x800));
        assert_eq!(after.manifest, spec.manifest);
        let read = Image::parse(out.clone()).unwrap();
        let resources = read.resource_directory().unwrap();
        let info = resources.get_version_info().unwrap().unwrap();
        let strings = &info.strings[0].strings;
        for (key, value) in [
            ("CompanyName", "Example Org"),
            ("FileDescription", "Hello"),
            ("FileVersion", "1.2.3-rc.1+b7"),
            ("OriginalFilename", "hello.exe"),
            ("ProductName", "Hello"),
            ("ProductVersion", "1.2.3-rc.1+b7"),
        ] {
            assert_eq!(strings.get(key).map(String::as_str), Some(value), "{key}");
        }
        assert_eq!(info.info.file_version.major, 0x0001_0002);
        assert_eq!(info.info.file_version.minor, 0x0003_0000);
        assert!(resources.get_main_icon().unwrap().is_some());
    }

    #[test]
    fn every_field_set_comes_out_equal_for_both_machines_and_subsystems() {
        for (machine, subsystem) in [(0x8664, 2), (0xAA64, 3)] {
            let mut spec = PeSpec::hardened(subsystem);
            spec.imports.push("ADVAPI32.dll".to_owned());
            let input = pe_image(machine, &spec);
            let out = stamp(&input, &fields(None)).expect("stamps");
            let after = PeImage::parse(&out).unwrap();
            assert_eq!(after.headers.machine, machine);
            assert_eq!(after.headers.subsystem, subsystem);
            assert_eq!(after.imports, spec.imports);
            assert_eq!(after.manifest, spec.manifest);
        }
    }

    #[test]
    fn stamping_is_deterministic() {
        let input = pe_image(0x8664, &PeSpec::hardened(GUI));
        let ico = ico_from_png(&png(48)).unwrap();
        let a = stamp(&input, &fields(Some(&ico))).unwrap();
        let b = stamp(&input, &fields(Some(&ico))).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, input);
    }

    #[test]
    fn a_stamper_that_drops_the_manifest_or_the_flags_is_refused_by_name() {
        let input = pe_image(0x8664, &PeSpec::hardened(GUI));
        let broken = |spec: PeSpec| {
            let bytes = pe_image(0x8664, &spec);
            move |_: &[u8], _: &Fields<'_>| Ok(bytes.clone())
        };
        let mut no_manifest = PeSpec::hardened(GUI);
        no_manifest.manifest = None;
        let e = stamp_with(&input, &fields(None), &broken(no_manifest)).unwrap_err();
        assert_eq!(
            e.to_string(),
            "stamping changed the image's RT_MANIFEST (nothing was written)"
        );
        let mut no_flags = PeSpec::hardened(GUI);
        no_flags.dependent_load_flags = Some(0);
        let e = stamp_with(&input, &fields(None), &broken(no_flags)).unwrap_err();
        assert!(e.to_string().contains("DependentLoadFlags"), "{e}");
        let mut other_subsystem = PeSpec::hardened(GUI);
        other_subsystem.subsystem = 3;
        let e = stamp_with(&input, &fields(None), &broken(other_subsystem)).unwrap_err();
        assert!(e.to_string().contains("subsystem"), "{e}");
        let mut more_imports = PeSpec::hardened(GUI);
        more_imports.imports.push("WINHTTP.dll".to_owned());
        let e = stamp_with(&input, &fields(None), &broken(more_imports)).unwrap_err();
        assert!(e.to_string().contains("import table"), "{e}");
        let e = stamp_with(&input, &fields(None), &|_: &[u8], _: &Fields<'_>| {
            Ok(b"not a pe".to_vec())
        })
        .unwrap_err();
        assert!(e.to_string().contains("not a readable PE"), "{e}");
    }

    #[test]
    fn a_certificate_table_is_stripped_and_an_unsigned_image_is_left_alone() {
        let unsigned = pe_image(0x8664, &PeSpec::hardened(GUI));
        assert_eq!(strip_certificate_table(&unsigned).unwrap(), unsigned);
        let mut spec = PeSpec::hardened(GUI);
        let table = vec![0xAB; 64];
        spec.security_dir = Some((unsigned.len() as u32, table.len() as u32));
        let mut signed = pe_image(0x8664, &spec);
        assert_eq!(signed.len(), unsigned.len());
        signed.extend_from_slice(&table);
        let stripped = strip_certificate_table(&signed).unwrap();
        assert_eq!(stripped, unsigned);
        // Bytes after the table, or a table not at the end: refused.
        let mut after = signed.clone();
        after.push(0);
        assert!(strip_certificate_table(&after).is_err());
        let mut inside = pe_image(0x8664, &{
            let mut s = PeSpec::hardened(GUI);
            s.security_dir = Some((64, 64));
            s
        });
        inside.extend_from_slice(&[0; 64]);
        assert!(strip_certificate_table(&inside).is_err());
        assert!(strip_certificate_table(b"MZ").is_err());
    }
}
