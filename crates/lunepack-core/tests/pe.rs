//! M7 step 3: the PE reader (`lunepack_core::pe`) and the packager's Windows binary checks
//! (`check_runtime_image`, `check_pe_stub`, M7-D10), over images the testkit builds.

use lunepack_core::pe::{
    MACHINE_ARM64, MACHINE_X86_64, PeError, PeHeaders, PeImage, SUBSYSTEM_CONSOLE, SUBSYSTEM_GUI,
    is_c_runtime, manifest_is_hardened,
};
use lunepack_core::{RuntimeImageError as E, Target, check_pe_stub, check_runtime_image};
use lunepack_core::{check_ui_image, pack::classify};
use lunepack_testkit::exe_headers::{self, HARDENED_MANIFEST, PeSpec, pe_image};

fn hardened(machine: u16, subsystem: u16) -> Vec<u8> {
    pe_image(machine, &PeSpec::hardened(subsystem))
}

#[test]
fn the_reader_reads_back_what_the_builder_wrote() {
    for pe32 in [false, true] {
        let spec = PeSpec {
            security_dir: Some((0x5000, 0x10)),
            pe32,
            ..PeSpec::hardened(SUBSYSTEM_CONSOLE)
        };
        let bytes = pe_image(MACHINE_X86_64, &spec);
        let img = PeImage::parse(&bytes).unwrap();
        assert_eq!(img.headers.machine, MACHINE_X86_64);
        assert_eq!(img.headers.pe32_plus, !pe32);
        assert_eq!(img.headers.subsystem, SUBSYSTEM_CONSOLE);
        assert_eq!(img.imports, ["KERNEL32.dll", "ntdll.dll"]);
        assert_eq!(img.delay_imports, ["USER32.dll"]);
        assert_eq!(img.dependent_load_flags, Some(0x800));
        assert_eq!(img.manifest.as_deref(), Some(HARDENED_MANIFEST.as_bytes()));
        let sec = img.headers.security();
        assert_eq!((sec.address, sec.size), (0x5000, 0x10));
        assert_eq!(img.headers.image_end(), bytes.len() as u64);
        // The headers alone read from a prefix (what the setup locator does).
        let head = PeHeaders::parse(&bytes[..0x400], bytes.len() as u64).unwrap();
        assert_eq!(head, img.headers);
    }
}

#[test]
fn absent_tables_read_as_absent() {
    let spec = PeSpec {
        imports: Vec::new(),
        delay_imports: Vec::new(),
        dependent_load_flags: None,
        manifest: None,
        ..PeSpec::hardened(SUBSYSTEM_GUI)
    };
    let img = PeImage::parse(&pe_image(MACHINE_ARM64, &spec)).unwrap();
    assert!(img.imports.is_empty() && img.delay_imports.is_empty());
    assert_eq!(img.dependent_load_flags, None);
    assert_eq!(img.manifest, None);
    assert!(img.headers.security().is_zero());
}

#[test]
fn not_a_pe_and_header_only_images() {
    assert_eq!(PeImage::parse(b""), Err(PeError::NotPe));
    assert_eq!(
        PeImage::parse(&exe_headers::elf(62, false, 4096)),
        Err(PeError::NotPe)
    );
    // The header-only image of `exe_headers::pe` has no optional header: malformed.
    assert!(matches!(
        PeImage::parse(&exe_headers::pe(MACHINE_X86_64, 4096)),
        Err(PeError::Malformed(_))
    ));
    // `e_lfanew` past the bytes.
    let mut b = hardened(MACHINE_X86_64, SUBSYSTEM_GUI);
    b[0x3C..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    assert!(matches!(PeImage::parse(&b), Err(PeError::Malformed(_))));
}

/// Every truncation and every single-byte flip (three masks at every position) of the builder's
/// images: an error or a value, never a panic. Exhaustive rather than sampled, since the images are
/// a few KiB.
#[test]
fn truncations_and_flips_never_panic() {
    for (machine, spec) in [
        (MACHINE_X86_64, PeSpec::hardened(SUBSYSTEM_GUI)),
        (
            MACHINE_ARM64,
            PeSpec {
                pe32: true,
                security_dir: Some((0x1000, 8)),
                ..PeSpec::hardened(SUBSYSTEM_CONSOLE)
            },
        ),
    ] {
        let full = pe_image(machine, &spec);
        for n in 0..full.len() {
            let cut = &full[..n];
            assert!(PeImage::parse(cut).is_err(), "truncated to {n} parsed");
            let _ = PeHeaders::parse(cut, full.len() as u64);
            let _ = check_runtime_image(cut, Target::WindowsX86_64);
        }
        for i in 0..full.len() {
            for mask in [0x01, 0x80, 0xFF] {
                let mut b = full.clone();
                b[i] ^= mask;
                let _ = PeImage::parse(&b);
                let _ = check_pe_stub(&b, Target::WindowsAarch64, true);
            }
        }
    }
}

#[test]
fn c_runtime_names() {
    for n in [
        "VCRUNTIME140.dll",
        "vcruntime140_1.dll",
        "MSVCP140.dll",
        "api-ms-win-crt-runtime-l1-1-0.dll",
        "ucrtbase.dll",
        "UCRTBASED.dll",
    ] {
        assert!(is_c_runtime(n), "{n}");
    }
    for n in [
        "KERNEL32.dll",
        "ntdll.dll",
        "api-ms-win-core-synch-l1-2-0.dll",
        "msvcrt.dll",
    ] {
        assert!(!is_c_runtime(n), "{n}");
    }
}

#[test]
fn manifest_text_check() {
    assert!(manifest_is_hardened(HARDENED_MANIFEST.as_bytes()));
    let mut bom = b"\xEF\xBB\xBF".to_vec();
    bom.extend_from_slice(HARDENED_MANIFEST.as_bytes());
    assert!(manifest_is_hardened(&bom));
    // link.exe's re-serialised form: a namespace prefix on the element.
    assert!(manifest_is_hardened(
        b"<requestedExecutionLevel level='asInvoker'/><ws:longPathAware xmlns:ws=\"x\">true</ws:longPathAware>"
    ));
    let off = HARDENED_MANIFEST.replace(">true", ">false");
    assert!(!manifest_is_hardened(off.as_bytes()));
    let admin = HARDENED_MANIFEST.replace("asInvoker", "requireAdministrator");
    assert!(!manifest_is_hardened(admin.as_bytes()));
    let no_long = HARDENED_MANIFEST.replace("longPathAware", "dpiAware");
    assert!(!manifest_is_hardened(no_long.as_bytes()));
    assert!(!manifest_is_hardened(b"\xFF\xFE"));
}

#[test]
fn windows_runtime_and_ui_checks() {
    let x64 = hardened(MACHINE_X86_64, SUBSYSTEM_GUI);
    let arm = hardened(MACHINE_ARM64, SUBSYSTEM_GUI);
    assert_eq!(check_runtime_image(&x64, Target::WindowsX86_64), Ok(()));
    assert_eq!(check_runtime_image(&arm, Target::WindowsAarch64), Ok(()));
    assert_eq!(check_ui_image(&x64, Target::WindowsX86_64), Ok(()));
    assert_eq!(
        check_runtime_image(&arm, Target::WindowsX86_64),
        Err(E::Machine)
    );
    // The header-only image of earlier milestones is refused now.
    assert_eq!(
        check_runtime_image(
            &exe_headers::pe(MACHINE_X86_64, 4096),
            Target::WindowsX86_64
        ),
        Err(E::PeMalformed)
    );
    // A console runtime (M7-D6: GUI).
    assert_eq!(
        check_runtime_image(
            &hardened(MACHINE_X86_64, SUBSYSTEM_CONSOLE),
            Target::WindowsX86_64
        ),
        Err(E::Subsystem)
    );
    let with = |f: &dyn Fn(&mut PeSpec)| {
        let mut spec = PeSpec::hardened(SUBSYSTEM_GUI);
        f(&mut spec);
        check_runtime_image(&pe_image(MACHINE_X86_64, &spec), Target::WindowsX86_64)
    };
    assert_eq!(
        with(&|s| s.imports.push("VCRUNTIME140.dll".to_owned())),
        Err(E::CRuntime)
    );
    assert_eq!(
        with(&|s| s
            .delay_imports
            .push("api-ms-win-crt-heap-l1-1-0.dll".to_owned())),
        Err(E::CRuntime)
    );
    // advapi32.dll statically (its forwarders load cryptbase.dll before main), in either case.
    assert_eq!(
        with(&|s| s.imports.push("ADVAPI32.dll".to_owned())),
        Err(E::StaticAdvapi32)
    );
    assert_eq!(
        with(&|s| s.imports.push("advapi32.dll".to_owned())),
        Err(E::StaticAdvapi32)
    );
    // Delay-loaded, it is accepted.
    assert_eq!(
        with(&|s| s.delay_imports.push("ADVAPI32.dll".to_owned())),
        Ok(())
    );
    assert_eq!(
        with(&|s| s.dependent_load_flags = None),
        Err(E::DependentLoadFlags)
    );
    assert_eq!(
        with(&|s| s.dependent_load_flags = Some(0)),
        Err(E::DependentLoadFlags)
    );
    assert_eq!(
        with(&|s| s.dependent_load_flags = Some(0x1800)),
        Err(E::DependentLoadFlags)
    );
    assert_eq!(with(&|s| s.manifest = None), Err(E::Manifest));
    assert_eq!(
        with(&|s| s.manifest = Some(b"<assembly/>".to_vec())),
        Err(E::Manifest)
    );
    // A runtime file is classified as x86 code still (the BCJ filters see it).
    assert_eq!(classify(&x64), lunepack_core::FileClass::X86);
}

#[test]
fn windows_stub_checks() {
    let gui = hardened(MACHINE_X86_64, SUBSYSTEM_GUI);
    let console = hardened(MACHINE_X86_64, SUBSYSTEM_CONSOLE);
    assert_eq!(check_pe_stub(&gui, Target::WindowsX86_64, false), Ok(()));
    assert_eq!(check_pe_stub(&console, Target::WindowsX86_64, true), Ok(()));
    assert_eq!(
        check_pe_stub(&gui, Target::WindowsX86_64, true),
        Err(E::Subsystem)
    );
    assert_eq!(
        check_pe_stub(&console, Target::WindowsX86_64, false),
        Err(E::Subsystem)
    );
    assert_eq!(
        check_pe_stub(&gui, Target::WindowsAarch64, false),
        Err(E::Machine)
    );
    assert_eq!(
        check_pe_stub(
            &hardened(MACHINE_ARM64, SUBSYSTEM_CONSOLE),
            Target::WindowsAarch64,
            true
        ),
        Ok(())
    );
    assert_eq!(
        check_pe_stub(&gui, Target::LinuxX86_64, false),
        Err(E::Format)
    );
    let spec = PeSpec {
        dependent_load_flags: None,
        ..PeSpec::hardened(SUBSYSTEM_GUI)
    };
    assert_eq!(
        check_pe_stub(
            &pe_image(MACHINE_X86_64, &spec),
            Target::WindowsX86_64,
            false
        ),
        Err(E::DependentLoadFlags)
    );
    assert_eq!(
        check_pe_stub(
            &exe_headers::pe(MACHINE_X86_64, 4096),
            Target::WindowsX86_64,
            false
        ),
        Err(E::PeMalformed)
    );
}
