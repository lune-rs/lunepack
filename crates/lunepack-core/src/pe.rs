//! A small fail-closed reader of Windows PE images (M7-D10, M7-D11): the machine, the subsystem,
//! the import and delay-import DLL names, the load config's `DependentLoadFlags`, the security
//! (certificate table) directory, the bytes of the first `RT_MANIFEST` resource and the file span
//! of an `RT_RCDATA` resource ([`rcdata`]).
//!
//! Every offset is bound-checked: a truncated or inconsistent image is a [`PeError`], never a
//! panic. The reader accepts the shapes a linker writes and refuses the rest, so it can refuse an
//! image the Windows loader would still run; it is used only on images lunepack builds or checks.
//! [`PeHeaders::parse`] reads the headers and the section table alone and works on a prefix of
//! the file (the setup locator reads a few KiB from the start); [`PeImage::parse`] needs the whole
//! file.

/// `IMAGE_FILE_MACHINE_AMD64`.
pub const MACHINE_X86_64: u16 = 0x8664;
/// `IMAGE_FILE_MACHINE_ARM64`.
pub const MACHINE_ARM64: u16 = 0xAA64;
/// `IMAGE_SUBSYSTEM_WINDOWS_GUI`.
pub const SUBSYSTEM_GUI: u16 = 2;
/// `IMAGE_SUBSYSTEM_WINDOWS_CUI` (console).
pub const SUBSYSTEM_CONSOLE: u16 = 3;
/// `LOAD_LIBRARY_SEARCH_SYSTEM32`, the `DependentLoadFlags` every shipped binary carries.
pub const LOAD_LIBRARY_SEARCH_SYSTEM32: u16 = 0x800;
/// `RT_MANIFEST`.
pub const RT_MANIFEST: u32 = 24;
/// `RT_RCDATA`.
pub const RT_RCDATA: u32 = 10;

/// The optional header magic of a PE32 image.
pub const PE32_MAGIC: u16 = 0x10b;
/// The optional header magic of a PE32+ image.
pub const PE32_PLUS_MAGIC: u16 = 0x20b;

const DIR_IMPORT: usize = 1;
const DIR_RESOURCE: usize = 2;
const DIR_SECURITY: usize = 4;
const DIR_LOAD_CONFIG: usize = 10;
const DIR_DELAY_IMPORT: usize = 13;

const MAX_SECTIONS: usize = 96;
const MAX_IMPORTS: usize = 1024;
const MAX_DLL_NAME: usize = 256;
const MAX_MANIFEST: u32 = 1 << 20;
const IMPORT_DESC: usize = 20;
const DELAY_DESC: usize = 32;
const SECTION_HEADER: usize = 40;

/// Why bytes are not a PE image this reader accepts. Carries no byte of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PeError {
    /// No `MZ` header, or no `PE\0\0` signature where `e_lfanew` points.
    #[error("not a PE image")]
    NotPe,
    /// Truncated or inconsistent: what is wrong, never a value from the file.
    #[error("malformed PE image: {0}")]
    Malformed(&'static str),
}

type Result<T> = std::result::Result<T, PeError>;

fn bad<T>(what: &'static str) -> Result<T> {
    Err(PeError::Malformed(what))
}

fn slice(bytes: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    bytes.get(at..at.checked_add(len)?)
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(slice(bytes, at, 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(slice(bytes, at, 4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(slice(bytes, at, 8)?.try_into().ok()?))
}

/// The largest `e_lfanew` the Windows loader accepts: `RtlImageNtHeaderEx` refuses an image whose
/// `e_lfanew` is 256 MiB or more.
pub const MAX_E_LFANEW: u64 = 0x1000_0000;

/// Whether a file of `len` bytes whose first bytes are `head` is a PE image as far as the Windows
/// loader is concerned: it starts with `MZ` and has `PE\0\0` where `e_lfanew` points, whatever
/// else is wrong with the headers. The signature is looked for in `head` when it lies inside, and
/// otherwise read from the file through `read_at(offset)` (the four bytes at `offset`; only called
/// for an offset the loader would accept and the file holds), so a file whose `e_lfanew` lies past
/// any bounded prefix is still found. A failed read is the caller's error: the answer is never
/// guessed "not a PE".
///
/// This is the one rule the packager's sign plan and the client's publisher check share; it needs no
/// valid headers, so it is the right question for a file [`PeHeaders::parse`] refuses.
pub fn has_pe_signature<E>(
    head: &[u8],
    len: u64,
    read_at: impl FnOnce(u64) -> std::result::Result<[u8; 4], E>,
) -> std::result::Result<bool, E> {
    let Some(lfanew) = head
        .starts_with(b"MZ")
        .then(|| u32_at(head, 0x3C))
        .flatten()
    else {
        return Ok(false);
    };
    let at = u64::from(lfanew);
    if at >= MAX_E_LFANEW || at + 4 > len {
        return Ok(false);
    }
    // `at` is below 256 MiB, so it fits `usize` on every target.
    match slice(head, at as usize, 4) {
        Some(sig) => Ok(sig == b"PE\0\0"),
        None => Ok(read_at(at)? == *b"PE\0\0"),
    }
}

/// One data directory entry: an RVA (a file offset for the security directory) and a size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataDir {
    /// The RVA, or for the security directory the file offset.
    pub address: u32,
    /// The size in bytes.
    pub size: u32,
}

impl DataDir {
    /// Both fields zero: the directory is absent.
    pub fn is_zero(self) -> bool {
        self.address == 0 && self.size == 0
    }
}

/// One section header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    /// `VirtualAddress`.
    pub rva: u32,
    /// `VirtualSize`.
    pub virtual_size: u32,
    /// `PointerToRawData`.
    pub raw_ptr: u32,
    /// `SizeOfRawData`.
    pub raw_size: u32,
}

/// The headers and the section table of a PE image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeHeaders {
    /// The COFF machine.
    pub machine: u16,
    /// PE32+ (else PE32).
    pub pe32_plus: bool,
    /// The optional header's subsystem.
    pub subsystem: u16,
    /// The preferred image base.
    pub image_base: u64,
    /// `SizeOfHeaders`.
    pub size_of_headers: u32,
    /// The section table.
    pub sections: Vec<Section>,
    dirs: Vec<DataDir>,
}

impl PeHeaders {
    /// Reads the headers of an image of `file_len` bytes from `head`, a prefix of it (or all of
    /// it). Everything up to the end of the section table must be in `head`; every section's raw
    /// data must lie inside `file_len`.
    pub fn parse(head: &[u8], file_len: u64) -> Result<PeHeaders> {
        if !head.starts_with(b"MZ") {
            return Err(PeError::NotPe);
        }
        let lfanew = u32_at(head, 0x3C).ok_or(PeError::Malformed("DOS header truncated"))?;
        let pe = usize::try_from(lfanew).map_err(|_| PeError::Malformed("e_lfanew"))?;
        match slice(head, pe, 4) {
            Some(b"PE\0\0") => {}
            Some(_) => return Err(PeError::NotPe),
            None => return bad("e_lfanew past the headers"),
        }
        let coff = pe + 4;
        let (Some(machine), Some(nsections), Some(opt_size)) = (
            u16_at(head, coff),
            u16_at(head, coff + 2),
            u16_at(head, coff + 16),
        ) else {
            return bad("COFF header truncated");
        };
        let nsections = usize::from(nsections);
        if nsections == 0 || nsections > MAX_SECTIONS {
            return bad("section count");
        }
        let opt = coff + 20;
        let opt_size = usize::from(opt_size);
        let opt_bytes = slice(head, opt, opt_size).ok_or(PeError::Malformed("optional header"))?;
        let pe32_plus = match u16_at(opt_bytes, 0) {
            Some(PE32_PLUS_MAGIC) => true,
            Some(PE32_MAGIC) => false,
            _ => return bad("optional header magic"),
        };
        let (dirs_at, count_at) = if pe32_plus { (112, 108) } else { (96, 92) };
        let image_base = if pe32_plus {
            u64_at(opt_bytes, 24)
        } else {
            u32_at(opt_bytes, 28).map(u64::from)
        };
        let (Some(image_base), Some(size_of_headers), Some(subsystem), Some(count)) = (
            image_base,
            u32_at(opt_bytes, 60),
            u16_at(opt_bytes, 68),
            u32_at(opt_bytes, count_at),
        ) else {
            return bad("optional header truncated");
        };
        if count > 16 {
            return bad("data directory count");
        }
        let count = count as usize;
        if dirs_at + 8 * count > opt_size {
            return bad("data directories outside the optional header");
        }
        let dirs = (0..count)
            .map(|i| DataDir {
                address: u32_at(opt_bytes, dirs_at + 8 * i).unwrap_or(0),
                size: u32_at(opt_bytes, dirs_at + 8 * i + 4).unwrap_or(0),
            })
            .collect();
        let table = opt + opt_size;
        let table_end = table + SECTION_HEADER * nsections;
        if table_end > head.len() {
            return bad("section table past the headers");
        }
        if u64::from(size_of_headers) < table_end as u64 || u64::from(size_of_headers) > file_len {
            return bad("SizeOfHeaders");
        }
        let mut sections = Vec::with_capacity(nsections);
        for i in 0..nsections {
            let at = table + SECTION_HEADER * i;
            let s = Section {
                virtual_size: u32_at(head, at + 8).unwrap_or(0),
                rva: u32_at(head, at + 12).unwrap_or(0),
                raw_size: u32_at(head, at + 16).unwrap_or(0),
                raw_ptr: u32_at(head, at + 20).unwrap_or(0),
            };
            if s.raw_size > 0 {
                let end = u64::from(s.raw_ptr) + u64::from(s.raw_size);
                if u64::from(s.raw_ptr) < u64::from(size_of_headers) || end > file_len {
                    return bad("section data outside the file");
                }
            }
            if s.rva.checked_add(s.virtual_size.max(s.raw_size)).is_none() {
                return bad("section extent");
            }
            sections.push(s);
        }
        Ok(PeHeaders {
            machine,
            pe32_plus,
            subsystem,
            image_base,
            size_of_headers,
            sections,
            dirs,
        })
    }

    /// Data directory `index`; zero when the image has fewer directories.
    pub fn dir(&self, index: usize) -> DataDir {
        self.dirs.get(index).copied().unwrap_or_default()
    }

    /// The security (certificate table) directory: a file offset and a size.
    pub fn security(&self) -> DataDir {
        self.dir(DIR_SECURITY)
    }

    /// Where the image ends in the file: the end of the headers and of every section's raw data.
    /// Bytes after it are the overlay (a setup payload, a certificate table).
    pub fn image_end(&self) -> u64 {
        self.sections
            .iter()
            .filter(|s| s.raw_size > 0)
            .map(|s| u64::from(s.raw_ptr) + u64::from(s.raw_size))
            .fold(u64::from(self.size_of_headers), u64::max)
    }

    /// The file offset of `len` bytes at `rva`, which must lie inside one section's raw data.
    fn file_offset(&self, rva: u32, len: usize) -> Result<u64> {
        let s = self
            .sections
            .iter()
            .find(|s| rva >= s.rva && rva - s.rva < s.virtual_size.max(s.raw_size))
            .ok_or(PeError::Malformed("RVA in no section"))?;
        let inner = (rva - s.rva) as usize;
        if inner
            .checked_add(len)
            .is_none_or(|end| end > s.raw_size as usize)
        {
            return bad("RVA range outside the section's data");
        }
        Ok(u64::from(s.raw_ptr) + inner as u64)
    }

    /// `len` bytes at `rva` of `bytes` (the whole file), inside one section's raw data.
    fn at_rva<'b>(&self, bytes: &'b [u8], rva: u32, len: usize) -> Result<&'b [u8]> {
        let at = self.file_offset(rva, len)?;
        slice(bytes, at as usize, len).ok_or(PeError::Malformed("RVA range"))
    }

    /// The rest of the section's data from `rva`, at most `cap` bytes.
    fn rest_at_rva<'b>(&self, bytes: &'b [u8], rva: u32, cap: usize) -> Result<&'b [u8]> {
        let s = self
            .sections
            .iter()
            .find(|s| rva >= s.rva && rva - s.rva < s.virtual_size.max(s.raw_size))
            .ok_or(PeError::Malformed("RVA in no section"))?;
        let inner = (rva - s.rva) as usize;
        let left = (s.raw_size as usize)
            .checked_sub(inner)
            .ok_or(PeError::Malformed("RVA outside the section's data"))?;
        slice(bytes, s.raw_ptr as usize + inner, left.min(cap))
            .ok_or(PeError::Malformed("RVA range"))
    }

    fn dll_name(&self, bytes: &[u8], rva: u32) -> Result<String> {
        let text = self.rest_at_rva(bytes, rva, MAX_DLL_NAME + 1)?;
        let len = text
            .iter()
            .position(|&c| c == 0)
            .ok_or(PeError::Malformed("DLL name not terminated"))?;
        let name = &text[..len];
        if name.is_empty() || !name.iter().all(|c| c.is_ascii_graphic() || *c == b' ') {
            return bad("DLL name");
        }
        Ok(String::from_utf8_lossy(name).into_owned())
    }
}

/// What the packager checks in a Windows binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImage {
    /// The headers.
    pub headers: PeHeaders,
    /// The DLLs of the import table, in order.
    pub imports: Vec<String>,
    /// The DLLs of the delay-import table, in order.
    pub delay_imports: Vec<String>,
    /// The load config's `DependentLoadFlags`; `None` without a load config or when it is too
    /// short to hold the field.
    pub dependent_load_flags: Option<u16>,
    /// The bytes of the first `RT_MANIFEST` resource.
    pub manifest: Option<Vec<u8>>,
}

impl PeImage {
    /// Reads the whole image `bytes`.
    pub fn parse(bytes: &[u8]) -> Result<PeImage> {
        let headers = PeHeaders::parse(bytes, bytes.len() as u64)?;
        let imports = imports(&headers, bytes)?;
        let delay_imports = delay_imports(&headers, bytes)?;
        let dependent_load_flags = load_flags(&headers, bytes)?;
        let manifest = manifest(&headers, bytes)?;
        Ok(PeImage {
            headers,
            imports,
            delay_imports,
            dependent_load_flags,
            manifest,
        })
    }

    /// The import and delay-import DLL names together.
    pub fn all_imports(&self) -> impl Iterator<Item = &str> {
        self.imports
            .iter()
            .chain(&self.delay_imports)
            .map(String::as_str)
    }
}

/// Whether `name` (a DLL name) is a C runtime DLL (`vcruntime*`, `msvcp*`, `api-ms-win-crt-*`,
/// `ucrtbase*`), ASCII case-insensitively.
pub fn is_c_runtime(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["vcruntime", "msvcp", "api-ms-win-crt-", "ucrtbase"]
        .iter()
        .any(|p| n.starts_with(p))
}

fn imports(h: &PeHeaders, bytes: &[u8]) -> Result<Vec<String>> {
    let dir = h.dir(DIR_IMPORT);
    if dir.address == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for i in 0..=MAX_IMPORTS {
        let rva = (i * IMPORT_DESC)
            .try_into()
            .ok()
            .and_then(|off: u32| dir.address.checked_add(off))
            .ok_or(PeError::Malformed("import table"))?;
        let desc = h.at_rva(bytes, rva, IMPORT_DESC)?;
        if desc.iter().all(|&b| b == 0) {
            return Ok(out);
        }
        if i == MAX_IMPORTS {
            break;
        }
        let name = u32_at(desc, 12).unwrap_or(0);
        let first_thunk = u32_at(desc, 16).unwrap_or(0);
        if name == 0 || first_thunk == 0 {
            return bad("import descriptor");
        }
        out.push(h.dll_name(bytes, name)?);
    }
    bad("too many imports")
}

fn delay_imports(h: &PeHeaders, bytes: &[u8]) -> Result<Vec<String>> {
    let dir = h.dir(DIR_DELAY_IMPORT);
    if dir.address == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for i in 0..=MAX_IMPORTS {
        let rva = (i * DELAY_DESC)
            .try_into()
            .ok()
            .and_then(|off: u32| dir.address.checked_add(off))
            .ok_or(PeError::Malformed("delay-import table"))?;
        let desc = h.at_rva(bytes, rva, DELAY_DESC)?;
        if desc.iter().all(|&b| b == 0) {
            return Ok(out);
        }
        if i == MAX_IMPORTS {
            break;
        }
        let attributes = u32_at(desc, 0).unwrap_or(0);
        let name = u32_at(desc, 4).unwrap_or(0);
        // Bit 0 set: the fields are RVAs; clear (the old form): virtual addresses.
        let name = if attributes & 1 == 1 {
            name
        } else {
            u64::from(name)
                .checked_sub(h.image_base)
                .and_then(|r| u32::try_from(r).ok())
                .ok_or(PeError::Malformed("delay-import name"))?
        };
        if name == 0 {
            return bad("delay-import descriptor");
        }
        out.push(h.dll_name(bytes, name)?);
    }
    bad("too many delay imports")
}

fn load_flags(h: &PeHeaders, bytes: &[u8]) -> Result<Option<u16>> {
    let dir = h.dir(DIR_LOAD_CONFIG);
    if dir.address == 0 {
        return Ok(None);
    }
    // The offset of `DependentLoadFlags` in IMAGE_LOAD_CONFIG_DIRECTORY64 / 32.
    let at = if h.pe32_plus { 78 } else { 54 };
    let size = u32_at(h.at_rva(bytes, dir.address, 4)?, 0).unwrap_or(0) as usize;
    if size < at + 2 {
        return Ok(None);
    }
    let config = h.at_rva(bytes, dir.address, at + 2)?;
    Ok(u16_at(config, at))
}

/// The entries of the resource directory at `rva`: `(name or id, offset, is a directory)`.
fn resource_entries(
    h: &PeHeaders,
    bytes: &[u8],
    base: u32,
    rva: u32,
) -> Result<Vec<(u32, u32, bool)>> {
    let head = h.at_rva(bytes, rva, 16)?;
    let count =
        usize::from(u16_at(head, 12).unwrap_or(0)) + usize::from(u16_at(head, 14).unwrap_or(0));
    let table = h.at_rva(
        bytes,
        rva.checked_add(16)
            .ok_or(PeError::Malformed("resource directory"))?,
        count * 8,
    )?;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let name = u32_at(table, i * 8).unwrap_or(0);
        let off = u32_at(table, i * 8 + 4).unwrap_or(0);
        let target = base
            .checked_add(off & 0x7fff_ffff)
            .ok_or(PeError::Malformed("resource offset"))?;
        out.push((name, target, off & 0x8000_0000 != 0));
    }
    Ok(out)
}

fn manifest(h: &PeHeaders, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let base = h.dir(DIR_RESOURCE).address;
    if base == 0 {
        return Ok(None);
    }
    let Some(&(_, types, is_dir)) = resource_entries(h, bytes, base, base)?
        .iter()
        .find(|e| e.0 == RT_MANIFEST)
    else {
        return Ok(None);
    };
    // Type, then name, then language: each level must be a directory with an entry, the last
    // entry a data entry.
    if !is_dir {
        return bad("resource tree");
    }
    let &(_, names, is_dir) = resource_entries(h, bytes, base, types)?
        .first()
        .ok_or(PeError::Malformed("empty manifest resource"))?;
    if !is_dir {
        return bad("resource tree");
    }
    let &(_, data, is_dir) = resource_entries(h, bytes, base, names)?
        .first()
        .ok_or(PeError::Malformed("empty manifest resource"))?;
    if is_dir {
        return bad("resource tree");
    }
    let entry = h.at_rva(bytes, data, 16)?;
    let rva = u32_at(entry, 0).unwrap_or(0);
    let size = u32_at(entry, 4).unwrap_or(0);
    if size == 0 || size > MAX_MANIFEST {
        return bad("manifest size");
    }
    Ok(Some(h.at_rva(bytes, rva, size as usize)?.to_vec()))
}

/// Where an `RT_RCDATA` resource's data lies in the file (M10-D4): `len` bytes from `file_offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RcdataSpan {
    /// The file offset of the resource's first byte.
    pub file_offset: u64,
    /// The resource's size in bytes.
    pub len: u32,
}

/// The span of the `RT_RCDATA` resource with the integer id `id` in the image `bytes` (the whole
/// file, or the image part of it), read like [`PeImage`]'s manifest: type, then name, then
/// language. `Ok(None)` when the image has no resource directory, no `RT_RCDATA` type or no entry
/// `id` under it. The id's entry must be a directory holding exactly one language entry, a data
/// entry whose bytes lie inside one section's raw data (so the loader maps exactly those bytes at
/// the resource's RVA); anything else, or a truncated directory, is a [`PeError`].
pub fn rcdata(bytes: &[u8], id: u16) -> Result<Option<RcdataSpan>> {
    let h = PeHeaders::parse(bytes, bytes.len() as u64)?;
    let base = h.dir(DIR_RESOURCE).address;
    if base == 0 {
        return Ok(None);
    }
    let Some(&(_, names, is_dir)) = resource_entries(&h, bytes, base, base)?
        .iter()
        .find(|e| e.0 == RT_RCDATA)
    else {
        return Ok(None);
    };
    if !is_dir {
        return bad("resource tree");
    }
    // An integer id has the high bit clear; a string name's entry has it set, so it never equals.
    let Some(&(_, languages, is_dir)) = resource_entries(&h, bytes, base, names)?
        .iter()
        .find(|e| e.0 == u32::from(id))
    else {
        return Ok(None);
    };
    if !is_dir {
        return bad("resource tree");
    }
    let languages = resource_entries(&h, bytes, base, languages)?;
    let [(_, data, false)] = languages.as_slice() else {
        return bad("RT_RCDATA resource: not exactly one language data entry");
    };
    let entry = h.at_rva(bytes, *data, 16)?;
    let rva = u32_at(entry, 0).unwrap_or(0);
    let size = u32_at(entry, 4).unwrap_or(0);
    if size == 0 {
        return bad("RT_RCDATA resource size");
    }
    let file_offset = h.file_offset(rva, size as usize)?;
    if slice(bytes, file_offset as usize, size as usize).is_none() {
        return bad("RT_RCDATA resource outside the file");
    }
    Ok(Some(RcdataSpan {
        file_offset,
        len: size,
    }))
}

/// Whether manifest bytes request `asInvoker` and set `longPathAware` to `true` (M7-D10). A text
/// check on the XML the linker embeds: the first `longPathAware` element's text must start with
/// `true`.
pub fn manifest_is_hardened(manifest: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(manifest.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(manifest))
    else {
        return false;
    };
    let long_paths = text
        .split("longPathAware")
        .nth(1)
        .and_then(|rest| rest.split_once('>'))
        .is_some_and(|(attrs, value)| {
            !attrs.contains('<') && value.trim_start().starts_with("true")
        });
    text.contains("asInvoker") && long_paths
}
