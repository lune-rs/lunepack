//! Deterministic synthetic executables: a minimal, valid-enough header of each format the packager
//! classifies, followed by filler shaped like the architecture's code. Not runnable programs; they
//! exist so tests and benchmarks can exercise header detection and the BCJ filters without
//! shipping binaries.

/// xorshift64*: a fixed-seed source, so every call gives the same bytes.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// Bytes shaped like x86 code: short runs of filler broken by `E8`/`E9` and a small little-endian
/// relative offset, which is what the x86 BCJ filter rewrites.
pub fn x86_like(len: usize) -> Vec<u8> {
    let mut rng = Rng(0x86_86_86_86_86_86_86_86);
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        let filler = (rng.next() >> 60) as usize + 1;
        for _ in 0..filler {
            out.push(0x48 + ((rng.next() >> 61) as u8));
        }
        out.push(if rng.next() & 1 == 0 { 0xE8 } else { 0xE9 });
        let rel = ((rng.next() >> 48) as i32 % 4096) - 2048;
        out.extend_from_slice(&rel.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Bytes shaped like ARM64 code: little-endian 4-byte words, every other one a `BL` with a small
/// word offset, which is what the ARM64 BCJ filter rewrites. `len` is rounded down to a multiple of
/// 4.
pub fn arm64_like(len: usize) -> Vec<u8> {
    let mut rng = Rng(0xA64A_64A6_4A64_A64A);
    let mut out = Vec::with_capacity(len + 4);
    let mut i = 0u64;
    while out.len() + 4 <= len {
        let word: u32 = if i & 1 == 0 {
            // BL: opcode 100101, imm26.
            0x9400_0000 | ((rng.next() >> 50) as u32 & 0x0003_FFFF)
        } else {
            // A data-processing-looking word.
            0x9100_0000 | ((rng.next() >> 40) as u32 & 0x00FF_FFFF)
        };
        out.extend_from_slice(&word.to_le_bytes());
        i += 1;
    }
    out
}

fn with_filler(mut header: Vec<u8>, len: usize, arm64: bool) -> Vec<u8> {
    let rest = len.saturating_sub(header.len());
    header.extend(if arm64 {
        arm64_like(rest)
    } else {
        x86_like(rest)
    });
    // `arm64_like` rounds down; top up so the total is exact.
    header.resize(len.max(header.len()), 0);
    header
}

/// Size of the PE header [`pe`] writes (DOS stub, `PE\0\0`, machine).
pub const PE_HEADER_LEN: usize = 0x88;
/// Size of the ELF header [`elf`] writes.
pub const ELF_HEADER_LEN: usize = 64;
/// Size of the Mach-O header [`macho`] writes.
pub const MACHO_HEADER_LEN: usize = 32;

/// A PE image: `MZ`, `e_lfanew = 0x80`, `PE\0\0` and `machine`, then filler of the matching
/// architecture. `len` is the total length, at least [`PE_HEADER_LEN`].
pub fn pe(machine: u16, len: usize) -> Vec<u8> {
    let mut h = vec![0u8; PE_HEADER_LEN];
    h[..2].copy_from_slice(b"MZ");
    h[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    h[0x80..0x84].copy_from_slice(b"PE\0\0");
    h[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
    with_filler(h, len, machine == 0xAA64)
}

/// A 64-bit ELF header with `e_machine = machine` in the given byte order, then filler. `len` is
/// the total length, at least [`ELF_HEADER_LEN`].
pub fn elf(machine: u16, big_endian: bool, len: usize) -> Vec<u8> {
    let mut h = vec![0u8; ELF_HEADER_LEN];
    h[..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    h[4] = 2; // ELFCLASS64
    h[5] = if big_endian { 2 } else { 1 };
    h[6] = 1; // EV_CURRENT
    let m = if big_endian {
        machine.to_be_bytes()
    } else {
        machine.to_le_bytes()
    };
    h[18..20].copy_from_slice(&m);
    with_filler(h, len, machine == 183)
}

/// A thin Mach-O header (64-bit magic when `cputype` has the 64-bit ABI flag) in the given byte
/// order, then filler. `len` is the total length, at least [`MACHO_HEADER_LEN`].
pub fn macho(cputype: u32, big_endian: bool, len: usize) -> Vec<u8> {
    let mut h = vec![0u8; MACHO_HEADER_LEN];
    let last = if cputype & 0x0100_0000 != 0 {
        0xCF
    } else {
        0xCE
    };
    let magic = if big_endian {
        [0xFE, 0xED, 0xFA, last]
    } else {
        [last, 0xFA, 0xED, 0xFE]
    };
    h[..4].copy_from_slice(&magic);
    let c = if big_endian {
        cputype.to_be_bytes()
    } else {
        cputype.to_le_bytes()
    };
    h[4..8].copy_from_slice(&c);
    with_filler(h, len, cputype == 0x0100_000C)
}

/// A fat (universal) Mach-O header listing `cputypes`, then filler. `len` is the total length, at
/// least the header (`8 + 20 * cputypes.len()`). Filler is ARM64-like unless a slice is x86.
pub fn fat(cputypes: &[u32], len: usize) -> Vec<u8> {
    let header_len = 8 + 20 * cputypes.len();
    let mut h = Vec::with_capacity(header_len);
    h.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    h.extend_from_slice(&(cputypes.len() as u32).to_be_bytes());
    let total = len.max(header_len);
    for &c in cputypes {
        h.extend_from_slice(&c.to_be_bytes());
        h.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
        h.extend_from_slice(&(header_len as u32).to_be_bytes()); // offset
        h.extend_from_slice(&((total - header_len) as u32).to_be_bytes()); // size
        h.extend_from_slice(&12u32.to_be_bytes()); // align 2^12
    }
    let x86 = cputypes.iter().any(|&c| c == 7 || c == 0x0100_0007);
    with_filler(h, len, !x86)
}

/// The manifest [`PeSpec::hardened`] embeds: `asInvoker` and `longPathAware`, as the shipped
/// binaries carry (M7-D10).
pub const HARDENED_MANIFEST: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
    "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">",
    "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges>",
    "<requestedExecutionLevel level='asInvoker' uiAccess='false'/>",
    "</requestedPrivileges></security></trustInfo>",
    "<application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings>",
    "<longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">true",
    "</longPathAware></windowsSettings></application></assembly>\n",
);

/// What [`pe_image`] writes into its image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeSpec {
    /// The optional header's subsystem (2 GUI, 3 console).
    pub subsystem: u16,
    /// DLL names of the import table, in order.
    pub imports: Vec<String>,
    /// DLL names of the delay-import table, in order.
    pub delay_imports: Vec<String>,
    /// The load config's `DependentLoadFlags`; `None` writes no load config.
    pub dependent_load_flags: Option<u16>,
    /// The `RT_MANIFEST` resource's bytes; `None` writes no resource section.
    pub manifest: Option<Vec<u8>>,
    /// The security directory entry (file offset, size); the caller appends the table itself.
    pub security_dir: Option<(u32, u32)>,
    /// A PE32 image (else PE32+).
    pub pe32: bool,
    /// Bytes of architecture-shaped filler in `.text`, rounded up to the file alignment.
    pub code_len: usize,
}

impl PeSpec {
    /// A shipped binary's shape (M7-D10): static CRT (imports `KERNEL32.dll` and `ntdll.dll`, a
    /// delay import of `USER32.dll`), `DependentLoadFlags` 0x800, [`HARDENED_MANIFEST`].
    pub fn hardened(subsystem: u16) -> PeSpec {
        PeSpec {
            subsystem,
            imports: vec!["KERNEL32.dll".to_owned(), "ntdll.dll".to_owned()],
            delay_imports: vec!["USER32.dll".to_owned()],
            dependent_load_flags: Some(0x800),
            manifest: Some(HARDENED_MANIFEST.as_bytes().to_vec()),
            security_dir: None,
            pe32: false,
            code_len: 0x400,
        }
    }
}

const FILE_ALIGN: usize = 0x200;
const SECTION_ALIGN: u32 = 0x1000;

fn align(n: usize, to: usize) -> usize {
    n.div_ceil(to) * to
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// `.rdata`'s content at section RVA `rva`: the import table, the delay-import table, the load
/// config. Returns the bytes and the directories `(import, delay import, load config)`.
fn rdata(spec: &PeSpec, rva: u32) -> (Vec<u8>, [(u32, u32); 3]) {
    let mut b = Vec::new();
    let at = |b: &Vec<u8>| rva + b.len() as u32;
    let name_rvas = |b: &mut Vec<u8>, names: &[String]| -> Vec<u32> {
        names
            .iter()
            .map(|n| {
                let r = at(b);
                b.extend_from_slice(n.as_bytes());
                b.push(0);
                b.resize(align(b.len(), 8), 0);
                r
            })
            .collect()
    };
    let import_names = name_rvas(&mut b, &spec.imports);
    let delay_names = name_rvas(&mut b, &spec.delay_imports);
    // One shared empty thunk array (just its terminator) as every descriptor's IAT.
    let thunk = at(&b);
    b.extend_from_slice(&[0u8; 16]);

    let mut dirs = [(0, 0); 3];
    if !spec.imports.is_empty() {
        let start = b.len();
        dirs[0] = (at(&b), ((spec.imports.len() + 1) * 20) as u32);
        b.resize(start + (spec.imports.len() + 1) * 20, 0);
        for (i, name) in import_names.iter().enumerate() {
            put32(&mut b, start + i * 20 + 12, *name);
            put32(&mut b, start + i * 20 + 16, thunk);
        }
    }
    if !spec.delay_imports.is_empty() {
        b.resize(align(b.len(), 8), 0);
        let start = b.len();
        dirs[1] = (at(&b), ((spec.delay_imports.len() + 1) * 32) as u32);
        b.resize(start + (spec.delay_imports.len() + 1) * 32, 0);
        for (i, name) in delay_names.iter().enumerate() {
            put32(&mut b, start + i * 32, 1); // RVA-based
            put32(&mut b, start + i * 32 + 4, *name);
            put32(&mut b, start + i * 32 + 12, thunk);
        }
    }
    if let Some(flags) = spec.dependent_load_flags {
        b.resize(align(b.len(), 8), 0);
        let start = b.len();
        let (size, at_flags) = if spec.pe32 { (0xC0, 54) } else { (0x140, 78) };
        dirs[2] = (at(&b), size as u32);
        b.resize(start + size, 0);
        put32(&mut b, start, size as u32);
        put16(&mut b, start + at_flags, flags);
    }
    (b, dirs)
}

/// `.rsrc`'s content at section RVA `rva`: type `RT_MANIFEST` (24), name 1, language 0x409.
fn rsrc(manifest: &[u8], rva: u32) -> Vec<u8> {
    // Three directories of one entry each (16 + 8 bytes), the data entry (16), the bytes.
    let dir = |b: &mut Vec<u8>, id: u32, target: u32| {
        let at = b.len();
        b.resize(at + 24, 0);
        put16(b, at + 14, 1);
        put32(b, at + 16, id);
        put32(b, at + 20, target);
    };
    let mut b = Vec::new();
    dir(&mut b, 24, 0x8000_0000 | 24);
    dir(&mut b, 1, 0x8000_0000 | 48);
    dir(&mut b, 0x409, 72);
    let data = 72 + 16;
    b.resize(data, 0);
    put32(&mut b, 72, rva + data as u32);
    put32(&mut b, 76, manifest.len() as u32);
    b.extend_from_slice(manifest);
    b
}

/// A minimal valid PE image (PE32+ unless [`PeSpec::pe32`]) of `machine`, laid out as a linker
/// does: DOS header, `PE\0\0`, COFF header, optional header with 16 data directories, a section
/// table, then `.text` (architecture-shaped filler), `.rdata` (import and delay-import tables, the
/// load config) and, with a manifest, `.rsrc` (an `RT_MANIFEST` resource), each aligned to 0x200
/// in the file and 0x1000 in memory. Deterministic; the reader in `lunepack_core::pe` reads every
/// field back.
pub fn pe_image(machine: u16, spec: &PeSpec) -> Vec<u8> {
    let nsections = if spec.manifest.is_some() { 3 } else { 2 };
    let opt_size: usize = if spec.pe32 { 96 + 128 } else { 112 + 128 };
    let coff = 0x84;
    let opt = coff + 20;
    let headers = align(opt + opt_size + 40 * nsections, FILE_ALIGN);

    let code = align(spec.code_len.max(1), FILE_ALIGN);
    let rdata_rva = SECTION_ALIGN * 2;
    let (rdata_bytes, dirs) = rdata(spec, rdata_rva);
    let rsrc_rva = rdata_rva + align(rdata_bytes.len().max(1), SECTION_ALIGN as usize) as u32;
    let rsrc_bytes = spec.manifest.as_deref().map(|m| rsrc(m, rsrc_rva));

    let mut sections: Vec<([u8; 8], u32, Vec<u8>)> = vec![
        (
            *b".text\0\0\0",
            SECTION_ALIGN,
            with_filler(Vec::new(), code, machine == 0xAA64),
        ),
        (*b".rdata\0\0", rdata_rva, rdata_bytes),
    ];
    if let Some(r) = rsrc_bytes {
        sections.push((*b".rsrc\0\0\0", rsrc_rva, r));
    }

    let mut out = vec![0u8; headers];
    out[..2].copy_from_slice(b"MZ");
    put32(&mut out, 0x3C, 0x80);
    out[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut out, coff, machine);
    put16(&mut out, coff + 2, nsections as u16);
    put16(&mut out, coff + 16, opt_size as u16);
    put16(&mut out, coff + 18, if spec.pe32 { 0x0102 } else { 0x0022 });
    put16(&mut out, opt, if spec.pe32 { 0x10b } else { 0x20b });
    put32(&mut out, opt + 16, SECTION_ALIGN); // entry point
    put32(&mut out, opt + 20, SECTION_ALIGN); // base of code
    if spec.pe32 {
        put32(&mut out, opt + 28, 0x0040_0000);
    } else {
        put64(&mut out, opt + 24, 0x1_4000_0000);
    }
    put32(&mut out, opt + 32, SECTION_ALIGN);
    put32(&mut out, opt + 36, FILE_ALIGN as u32);
    put16(&mut out, opt + 40, 6); // OS version
    put16(&mut out, opt + 48, 6); // subsystem version
    put32(&mut out, opt + 60, headers as u32);
    put16(&mut out, opt + 68, spec.subsystem);
    put16(&mut out, opt + 70, 0x8160);
    let dirs_at = opt + if spec.pe32 { 96 } else { 112 };
    put32(&mut out, dirs_at - 4, 16);
    let mut dir = |i: usize, (addr, size): (u32, u32)| {
        put32(&mut out, dirs_at + 8 * i, addr);
        put32(&mut out, dirs_at + 8 * i + 4, size);
    };
    dir(1, dirs[0]);
    dir(13, dirs[1]);
    dir(10, dirs[2]);
    if let Some((_, r)) = sections.get(2).map(|s| (s.1, s.2.len())) {
        dir(2, (rsrc_rva, r as u32));
    }
    if let Some(sec) = spec.security_dir {
        dir(4, sec);
    }

    let table = opt + opt_size;
    let mut raw = headers;
    let mut image_end = SECTION_ALIGN;
    for (i, (name, rva, bytes)) in sections.iter().enumerate() {
        let at = table + 40 * i;
        let raw_size = align(bytes.len().max(1), FILE_ALIGN);
        out[at..at + 8].copy_from_slice(name);
        put32(&mut out, at + 8, bytes.len() as u32);
        put32(&mut out, at + 12, *rva);
        put32(&mut out, at + 16, raw_size as u32);
        put32(&mut out, at + 20, raw as u32);
        put32(
            &mut out,
            at + 36,
            if i == 0 { 0x6000_0020 } else { 0x4000_0040 },
        );
        raw += raw_size;
        image_end = rva + align(bytes.len().max(1), SECTION_ALIGN as usize) as u32;
    }
    put32(&mut out, opt + 56, image_end); // SizeOfImage
    for (_, _, bytes) in &sections {
        let start = out.len();
        out.extend_from_slice(bytes);
        out.resize(start + align(bytes.len().max(1), FILE_ALIGN), 0);
    }
    out
}
