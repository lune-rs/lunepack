//! The UI's own PE image carries the Windows hardening (M7-D10, P6a): no C-runtime DLL
//! import, `DependentLoadFlags` of `LOAD_LIBRARY_SEARCH_SYSTEM32`, an embedded manifest with
//! `asInvoker` and `longPathAware`, and the GUI subsystem (M7-D6). The test reads the binary cargo
//! built for it (`CARGO_BIN_EXE_lunepack-ui`), so it fails when `.cargo/config.toml`'s
//! `+crt-static` is overridden by a `RUSTFLAGS` environment variable. Empty off Windows.
//!
//! The reader is a small test-local PE walker; the core's `pe` module replaces it (M7 step 3).

#![cfg(windows)]

const IMAGE: &str = env!("CARGO_BIN_EXE_lunepack-ui");

/// What the assertions need from one PE32+ file.
struct Pe {
    subsystem: u16,
    imports: Vec<String>,
    dependent_load_flags: u16,
    manifest: Option<String>,
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

struct Section {
    rva: u32,
    virtual_size: u32,
    raw_ptr: u32,
    raw_size: u32,
}

fn rva_to_offset(sections: &[Section], rva: u32) -> usize {
    let s = sections
        .iter()
        .find(|s| rva >= s.rva && rva < s.rva + s.virtual_size.max(s.raw_size))
        .unwrap_or_else(|| panic!("rva {rva:#x} is in no section"));
    (rva - s.rva + s.raw_ptr) as usize
}

fn c_string(b: &[u8], at: usize) -> String {
    let end = b[at..].iter().position(|&c| c == 0).expect("terminator");
    String::from_utf8_lossy(&b[at..at + end]).into_owned()
}

fn parse(b: &[u8]) -> Pe {
    assert_eq!(&b[..2], b"MZ");
    let pe = u32_at(b, 0x3c) as usize;
    assert_eq!(&b[pe..pe + 4], b"PE\0\0");
    let coff = pe + 4;
    let section_count = u16_at(b, coff + 2) as usize;
    let opt_size = u16_at(b, coff + 16) as usize;
    let opt = coff + 20;
    assert_eq!(u16_at(b, opt), 0x20b, "PE32+ expected");
    let subsystem = u16_at(b, opt + 68);
    let dirs = opt + 112;
    let dir = |i: usize| (u32_at(b, dirs + i * 8), u32_at(b, dirs + i * 8 + 4));
    let table = opt + opt_size;
    let sections: Vec<Section> = (0..section_count)
        .map(|i| {
            let at = table + i * 40;
            Section {
                virtual_size: u32_at(b, at + 8),
                rva: u32_at(b, at + 12),
                raw_size: u32_at(b, at + 16),
                raw_ptr: u32_at(b, at + 20),
            }
        })
        .collect();

    let mut imports = Vec::new();
    let (import_rva, _) = dir(1);
    if import_rva != 0 {
        let mut at = rva_to_offset(&sections, import_rva);
        while u32_at(b, at + 12) != 0 {
            imports.push(c_string(b, rva_to_offset(&sections, u32_at(b, at + 12))));
            at += 20;
        }
    }
    let (delay_rva, _) = dir(13);
    if delay_rva != 0 {
        let mut at = rva_to_offset(&sections, delay_rva);
        while u32_at(b, at + 4) != 0 {
            imports.push(c_string(b, rva_to_offset(&sections, u32_at(b, at + 4))));
            at += 32;
        }
    }

    let (load_rva, _) = dir(10);
    let dependent_load_flags = if load_rva == 0 {
        0
    } else {
        let at = rva_to_offset(&sections, load_rva);
        assert!(
            u32_at(b, at) >= 80,
            "load config too short for DependentLoadFlags"
        );
        u16_at(b, at + 78)
    };

    let (res_rva, _) = dir(2);
    let manifest = (res_rva != 0)
        .then(|| find_manifest(b, &sections, res_rva))
        .flatten();
    Pe {
        subsystem,
        imports,
        dependent_load_flags,
        manifest,
    }
}

/// The bytes of the first RT_MANIFEST (type 24) resource, as text.
fn find_manifest(b: &[u8], sections: &[Section], res_rva: u32) -> Option<String> {
    let base = rva_to_offset(sections, res_rva);
    // A directory: (id, offset, is_directory) entries.
    let entries = |dir_off: usize| -> Vec<(u32, usize, bool)> {
        let named = u16_at(b, dir_off + 12) as usize;
        let ids = u16_at(b, dir_off + 14) as usize;
        (0..named + ids)
            .map(|i| {
                let at = dir_off + 16 + i * 8;
                let off = u32_at(b, at + 4);
                (
                    u32_at(b, at),
                    base + (off & 0x7fff_ffff) as usize,
                    off & 0x8000_0000 != 0,
                )
            })
            .collect()
    };
    let (_, type_dir, is_dir) = entries(base).into_iter().find(|e| e.0 == 24)?;
    assert!(is_dir);
    let (_, lang_dir, is_dir) = *entries(type_dir).first()?;
    assert!(is_dir);
    let (_, data, is_dir) = *entries(lang_dir).first()?;
    assert!(!is_dir);
    let rva = u32_at(b, data);
    let size = u32_at(b, data + 4) as usize;
    let at = rva_to_offset(sections, rva);
    Some(String::from_utf8_lossy(&b[at..at + size]).into_owned())
}

fn is_c_runtime(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("vcruntime")
        || n.starts_with("msvcp")
        || n.starts_with("api-ms-win-crt-")
        || n.starts_with("ucrtbase")
}

#[test]
fn the_ui_image_is_hardened() {
    let bytes = std::fs::read(IMAGE).expect("read the UI binary");
    let pe = parse(&bytes);
    let crt: Vec<&String> = pe.imports.iter().filter(|n| is_c_runtime(n)).collect();
    assert!(
        crt.is_empty(),
        "C runtime imports: {crt:?} (all: {:?})",
        pe.imports
    );
    assert!(!pe.imports.is_empty(), "the reader found no imports at all");
    assert_eq!(pe.dependent_load_flags, 0x800, "DependentLoadFlags");
    assert_eq!(pe.subsystem, 2, "the UI is a GUI-subsystem binary");
    let manifest = pe.manifest.expect("an embedded RT_MANIFEST");
    assert!(manifest.contains("asInvoker"), "asInvoker");
    assert!(manifest.contains("longPathAware"), "longPathAware");
    let after = manifest.split("longPathAware").nth(1).unwrap_or("");
    assert!(
        after.trim_start_matches('>').starts_with("true"),
        "longPathAware is true"
    );
}

#[test]
fn the_reader_lists_the_imports_of_a_known_system_image() {
    // The control: a reader that found no imports would pass the test above for the wrong reason.
    // `kernel32.dll` is known to import `ntdll.dll`.
    let system = std::path::PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
        .join("System32")
        .join("kernel32.dll");
    let bytes = std::fs::read(system).expect("read kernel32.dll");
    let pe = parse(&bytes);
    assert!(
        pe.imports
            .iter()
            .any(|n| n.eq_ignore_ascii_case("ntdll.dll")),
        "kernel32.dll must import ntdll.dll, got {:?}",
        pe.imports
    );
}
