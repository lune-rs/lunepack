//! OS code signing, the pure part (M9 step 1): the argv-template grammar (M9-D1), the sign plan
//! (M9-D4), the signed-form checks (M9-D3) and the update configuration's `publisher_check` member
//! (M9-D6, M9-R1-D1).

use std::ffi::OsString;
use std::path::Path;

use lunepack_core::codesign::PLAN_HEAD_BYTES;
use lunepack_core::pe::MACHINE_X86_64;
use lunepack_core::{
    ArgvTemplate, ExpandCtx, PlanEntry, PlanEntryKind, PublisherPolicy, RelPath, SignItem,
    SignKind, SignPlanError, Target, TemplateError, TemplateRole, UpdateConfig, UpdateConfigError,
    macho_slices_signed, pe_is_signed, sign_plan,
};
use lunepack_testkit::exe_headers::{PeSpec, pe_image};
use lunepack_testkit::{abs_path, sample_update_config};
use serde_json::{Map, Value, json};

// ---- argv templates ----------------------------------------------------------------------------

fn parse(role: TemplateRole, elements: &[&str]) -> Result<ArgvTemplate, TemplateError> {
    ArgvTemplate::parse(role, elements)
}

#[test]
fn a_template_of_literals_and_whole_placeholders_parses() {
    parse(TemplateRole::Sign, &["signtool", "sign", "{path}"]).unwrap();
    parse(TemplateRole::Sign, &["{env:SIGNTOOL}", "sign", "{path}"]).unwrap();
    parse(
        TemplateRole::Notarize,
        &["xcrun", "notarytool", "submit", "{zip}", "--wait"],
    )
    .unwrap();
    parse(TemplateRole::Notarize, &["tool", "{bundle}", "{path}"]).unwrap();
    parse(
        TemplateRole::Staple,
        &["xcrun", "stapler", "staple", "{path}"],
    )
    .unwrap();
    parse(TemplateRole::Verify, &["codesign", "--verify", "{path}"]).unwrap();
    parse(TemplateRole::Sign, &["t", "{env:_A1}", "{env:A_B_9}"]).unwrap();
}

#[test]
fn every_refusal_of_the_grammar_names_the_element() {
    use TemplateError as E;
    let cases: [(&[&str], TemplateError); 11] = [
        (&["tool", "--x={path}"], E::Brace { index: 1 }),
        (&["tool", "a{env:B}"], E::Brace { index: 1 }),
        (&["{path}", "x"], E::PathAsProgram { index: 0 }),
        (&["tool", "{pth}"], E::UnknownPlaceholder { index: 1 }),
        (&["tool", "{env:b}"], E::EnvName { index: 1 }),
        (&["tool", "{env:}"], E::EnvName { index: 1 }),
        (&["tool", "{env:1A}"], E::EnvName { index: 1 }),
        (&["tool", "}"], E::Brace { index: 1 }),
        (&["tool", "{{path}}"], E::Brace { index: 1 }),
        (&[""], E::EmptyElement { index: 0 }),
        (&["tool", "a", ""], E::EmptyElement { index: 2 }),
    ];
    for (elements, want) in cases {
        assert_eq!(
            parse(TemplateRole::Sign, elements).unwrap_err(),
            want,
            "{elements:?}"
        );
    }
    assert_eq!(
        parse(TemplateRole::Sign, &[]).unwrap_err(),
        TemplateError::Empty
    );
}

#[test]
fn bundle_and_zip_belong_to_notarize_only() {
    for role in [
        TemplateRole::Sign,
        TemplateRole::Verify,
        TemplateRole::Staple,
    ] {
        assert_eq!(
            parse(role, &["tool", "{zip}"]).unwrap_err(),
            TemplateError::NotInRole {
                index: 1,
                placeholder: "{zip}"
            }
        );
        assert_eq!(
            parse(role, &["tool", "{bundle}"]).unwrap_err(),
            TemplateError::NotInRole {
                index: 1,
                placeholder: "{bundle}"
            }
        );
    }
    for program in ["{zip}", "{bundle}"] {
        assert_eq!(
            parse(TemplateRole::Notarize, &[program, "x"]).unwrap_err(),
            TemplateError::PathAsProgram { index: 0 }
        );
    }
}

#[test]
fn refusals_never_echo_the_template() {
    let marker = "SECRETMARKER";
    let cases = [
        format!("--{marker}={{path}}"),
        format!("{{{marker}}}"),
        format!("{{env:{marker}x}}"),
        format!("{marker}}}"),
    ];
    for bad in &cases {
        let err = parse(TemplateRole::Sign, &["tool", bad]).unwrap_err();
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains(marker), "{shown}");
    }
}

fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
    move |name| {
        pairs
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| OsString::from(v))
    }
}

#[test]
fn expansion_fills_paths_and_env_and_lists_the_env_values() {
    let item = abs_path("/work/tree.app/Contents/MacOS/app");
    let bundle = abs_path("/work/tree.app");
    let zip = abs_path("/work/notarize.zip");
    let t = parse(
        TemplateRole::Notarize,
        &[
            "{env:TOOL}",
            "submit",
            "{zip}",
            "--key",
            "{env:KEY_ID}",
            "{bundle}",
            "{path}",
            "{env:KEY_ID}",
        ],
    )
    .unwrap();
    assert_eq!(t.env_names(), ["KEY_ID", "TOOL"]);
    let env = env_of(&[("TOOL", "/opt/tool"), ("KEY_ID", "abc123"), ("OTHER", "x")]);
    let out = t
        .expand(
            &ExpandCtx {
                path: &item,
                bundle: Some(&bundle),
                zip: Some(&zip),
            },
            &env,
        )
        .unwrap();
    let want: Vec<OsString> = vec![
        "/opt/tool".into(),
        "submit".into(),
        zip.clone().into_os_string(),
        "--key".into(),
        "abc123".into(),
        bundle.clone().into_os_string(),
        item.clone().into_os_string(),
        "abc123".into(),
    ];
    assert_eq!(out.argv, want);
    // Exactly the expanded env values, once per name; `OTHER` was not expanded.
    assert_eq!(
        out.redact,
        vec![
            ("KEY_ID".to_owned(), OsString::from("abc123")),
            ("TOOL".to_owned(), OsString::from("/opt/tool")),
        ]
    );

    let plain = parse(TemplateRole::Sign, &["signtool", "sign", "{path}"]).unwrap();
    let out = plain
        .expand(
            &ExpandCtx {
                path: &item,
                bundle: None,
                zip: None,
            },
            &env,
        )
        .unwrap();
    assert!(out.redact.is_empty());
}

#[test]
fn an_unset_or_empty_env_value_is_an_error_naming_it() {
    let item = abs_path("/x/a.exe");
    let ctx = ExpandCtx {
        path: &item,
        bundle: None,
        zip: None,
    };
    let t = parse(TemplateRole::Sign, &["tool", "{env:CERT_NAME}", "{path}"]).unwrap();
    for env in [env_of(&[]), env_of(&[("CERT_NAME", "")])] {
        let err = t.expand(&ctx, &env).unwrap_err();
        assert_eq!(
            err,
            TemplateError::EnvUnset {
                name: "CERT_NAME".to_owned()
            }
        );
        assert!(err.to_string().contains("CERT_NAME"));
    }
}

#[test]
fn path_values_must_be_given_and_absolute() {
    let item = abs_path("/x/a.app");
    let t = parse(TemplateRole::Notarize, &["tool", "{zip}"]).unwrap();
    let err = t
        .expand(
            &ExpandCtx {
                path: &item,
                bundle: Some(&item),
                zip: None,
            },
            &env_of(&[]),
        )
        .unwrap_err();
    assert_eq!(
        err,
        TemplateError::NoValue {
            index: 1,
            placeholder: "{zip}"
        }
    );
    let t = parse(TemplateRole::Sign, &["tool", "{path}"]).unwrap();
    let err = t
        .expand(
            &ExpandCtx {
                path: Path::new("-rf"),
                bundle: None,
                zip: None,
            },
            &env_of(&[]),
        )
        .unwrap_err();
    assert_eq!(
        err,
        TemplateError::NotAbsolute {
            index: 1,
            placeholder: "{path}"
        }
    );
}

// ---- executable fixtures ---------------------------------------------------------------------------

fn unsigned_pe() -> Vec<u8> {
    pe_image(MACHINE_X86_64, &PeSpec::hardened(2))
}

/// A PE with a 16-byte certificate table appended, its directory pointing at it.
fn signed_pe() -> Vec<u8> {
    let len = unsigned_pe().len() as u32;
    let mut spec = PeSpec::hardened(2);
    spec.security_dir = Some((len, 16));
    let mut bytes = pe_image(MACHINE_X86_64, &spec);
    assert_eq!(bytes.len() as u32, len);
    bytes.extend_from_slice(&[0xAB; 16]);
    bytes
}

/// A PE whose security directory points past the end of the file.
fn pe_with_dangling_security() -> Vec<u8> {
    let len = unsigned_pe().len() as u32;
    let mut spec = PeSpec::hardened(2);
    spec.security_dir = Some((len, 16));
    pe_image(MACHINE_X86_64, &spec)
}

fn put32(out: &mut Vec<u8>, v: u32, big: bool) {
    out.extend_from_slice(&if big {
        v.to_be_bytes()
    } else {
        v.to_le_bytes()
    });
}

const LC_SEGMENT_64: u32 = 0x19;
const LC_CODE_SIGNATURE: u32 = 0x1d;

/// A thin Mach-O slice of `len` bytes (64-bit when `wide`) with a dummy command and, when
/// `signature` is set, an `LC_CODE_SIGNATURE` covering `(dataoff, datasize)`.
fn thin(big: bool, wide: bool, signature: Option<(u32, u32)>, len: usize) -> Vec<u8> {
    let mut cmds = Vec::new();
    put32(&mut cmds, LC_SEGMENT_64, big);
    put32(&mut cmds, 16, big);
    cmds.extend_from_slice(&[0; 8]);
    let mut ncmds = 1;
    if let Some((off, size)) = signature {
        put32(&mut cmds, LC_CODE_SIGNATURE, big);
        put32(&mut cmds, 16, big);
        put32(&mut cmds, off, big);
        put32(&mut cmds, size, big);
        ncmds += 1;
    }
    let mut out = Vec::new();
    let last = if wide { 0xCF } else { 0xCE };
    if big {
        out.extend_from_slice(&[0xFE, 0xED, 0xFA, last]);
    } else {
        out.extend_from_slice(&[last, 0xFA, 0xED, 0xFE]);
    }
    put32(&mut out, 0x0100_000C, big); // cputype
    put32(&mut out, 0, big); // cpusubtype
    put32(&mut out, 2, big); // filetype MH_EXECUTE
    put32(&mut out, ncmds, big);
    put32(&mut out, cmds.len() as u32, big);
    put32(&mut out, 0, big); // flags
    if wide {
        put32(&mut out, 0, big); // reserved
    }
    out.extend_from_slice(&cmds);
    assert!(out.len() <= len);
    out.resize(len, 0x5A);
    out
}

fn thin_signed(big: bool, wide: bool) -> Vec<u8> {
    thin(big, wide, Some((0x100, 0x40)), 0x140)
}

/// A universal file of `slices` (64-bit arch entries when `wide`, header byte order `big`).
fn fat(big: bool, wide: bool, slices: &[Vec<u8>]) -> Vec<u8> {
    let stride = if wide { 32 } else { 20 };
    let mut out = Vec::new();
    let magic: [u8; 4] = [0xCA, 0xFE, 0xBA, if wide { 0xBF } else { 0xBE }];
    if big {
        out.extend_from_slice(&magic);
    } else {
        out.extend(magic.iter().rev());
    }
    put32(&mut out, slices.len() as u32, big);
    let mut offset = (8 + stride * slices.len()).next_multiple_of(0x100);
    let mut body = vec![0u8; offset - (8 + stride * slices.len())];
    for slice in slices {
        put32(&mut out, 0x0100_000C, big);
        put32(&mut out, 0, big);
        if wide {
            let (o, s) = (offset as u64, slice.len() as u64);
            out.extend_from_slice(&if big {
                o.to_be_bytes()
            } else {
                o.to_le_bytes()
            });
            out.extend_from_slice(&if big {
                s.to_be_bytes()
            } else {
                s.to_le_bytes()
            });
            put32(&mut out, 8, big);
            put32(&mut out, 0, big);
        } else {
            put32(&mut out, offset as u32, big);
            put32(&mut out, slice.len() as u32, big);
            put32(&mut out, 8, big);
        }
        body.extend_from_slice(slice);
        offset += slice.len();
    }
    out.extend_from_slice(&body);
    out
}

// ---- signed-form checks ----------------------------------------------------------------------------

#[test]
fn pe_is_signed_iff_the_certificate_table_is_present_and_inside_the_file() {
    let unsigned = unsigned_pe();
    assert!(!pe_is_signed(&unsigned, unsigned.len() as u64));
    let signed = signed_pe();
    assert!(pe_is_signed(&signed, signed.len() as u64));
    // From a prefix, with the real length.
    assert!(pe_is_signed(&signed[..0x400], signed.len() as u64));
    let dangling = pe_with_dangling_security();
    assert!(!pe_is_signed(&dangling, dangling.len() as u64));
    // A zero-sized table is no table.
    let mut spec = PeSpec::hardened(2);
    spec.security_dir = Some((unsigned.len() as u32, 0));
    let empty = pe_image(MACHINE_X86_64, &spec);
    assert!(!pe_is_signed(&empty, empty.len() as u64 + 16));
    assert!(!pe_is_signed(b"not a PE at all", 15));
    assert!(!pe_is_signed(&[], 0));
}

#[test]
fn macho_is_signed_iff_every_slice_has_a_signature_inside_it() {
    for big in [false, true] {
        for wide in [false, true] {
            assert!(macho_slices_signed(&thin_signed(big, wide)), "{big} {wide}");
            assert!(!macho_slices_signed(&thin(big, wide, None, 0x140)));
            // Ends one byte past the slice.
            assert!(!macho_slices_signed(&thin(
                big,
                wide,
                Some((0x100, 0x41)),
                0x140
            )));
            // Empty range.
            assert!(!macho_slices_signed(&thin(
                big,
                wide,
                Some((0x100, 0)),
                0x140
            )));
        }
    }
    for big in [false, true] {
        for wide in [false, true] {
            let both = fat(
                big,
                wide,
                &[thin_signed(false, true), thin_signed(true, true)],
            );
            assert!(macho_slices_signed(&both), "{big} {wide}");
            let one = fat(
                big,
                wide,
                &[thin_signed(false, true), thin(false, true, None, 0x140)],
            );
            assert!(!macho_slices_signed(&one), "{big} {wide}");
            // A slice whose signature lies inside the file but past the slice's own end.
            let past = fat(
                big,
                wide,
                &[
                    thin(false, true, Some((0x130, 0x20)), 0x140),
                    thin_signed(false, true),
                ],
            );
            assert!(!macho_slices_signed(&past), "{big} {wide}");
            // Truncated: the last slice runs past the file.
            let mut cut = both.clone();
            cut.truncate(cut.len() - 1);
            assert!(!macho_slices_signed(&cut), "{big} {wide}");
        }
    }
    assert!(!macho_slices_signed(&unsigned_pe()));
    assert!(!macho_slices_signed(&[]));
    // A Java class file shares the universal magic.
    assert!(!macho_slices_signed(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52]));
}

/// xorshift64*: a fixed-seed source, so every run sees the same inputs.
struct Rand(u64);

impl Rand {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn the_checks_and_the_plan_are_total_on_arbitrary_bytes() {
    let seeds = [
        unsigned_pe(),
        signed_pe(),
        thin_signed(false, true),
        thin_signed(true, false),
        fat(
            true,
            false,
            &[thin_signed(false, true), thin_signed(true, true)],
        ),
        fat(false, true, &[thin_signed(false, false)]),
    ];
    let mut rng = Rand(0x9E37_79B9_7F4A_7C15);
    for round in 0..20_000 {
        let mut bytes = if round % 4 == 0 {
            let len = rng.below(600);
            (0..len).map(|_| rng.next() as u8).collect()
        } else {
            let mut b = seeds[rng.below(seeds.len())].clone();
            for _ in 0..1 + rng.below(8) {
                let at = rng.below(b.len());
                b[at] = rng.next() as u8;
            }
            if rng.below(4) == 0 {
                let keep = rng.below(b.len() + 1);
                b.truncate(keep);
            }
            b
        };
        if round % 7 == 0 && bytes.len() >= 8 {
            // Large counts and offsets.
            let at = rng.below(bytes.len() - 3);
            bytes[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        let claimed = match rng.below(3) {
            0 => bytes.len() as u64,
            1 => rng.next(),
            _ => bytes.len() as u64 / 2,
        };
        let _ = pe_is_signed(&bytes, claimed);
        let _ = macho_slices_signed(&bytes);
        let entry = PlanEntry {
            path: RelPath::parse("Contents/MacOS/x").unwrap(),
            kind: PlanEntryKind::File {
                head: bytes.clone(),
                len: claimed,
            },
        };
        let main = RelPath::parse("Contents/MacOS/main").unwrap();
        for target in [Target::WindowsX86_64, Target::MacosAarch64] {
            let _ = sign_plan(target, std::slice::from_ref(&entry), Some(&main));
        }
        let text = String::from_utf8_lossy(&bytes);
        let _ = ArgvTemplate::parse(TemplateRole::Notarize, &["t", text.as_ref()]);
    }
}

// ---- the sign plan ---------------------------------------------------------------------------------

fn dir(path: &str) -> PlanEntry {
    PlanEntry {
        path: RelPath::parse(path).unwrap(),
        kind: PlanEntryKind::Dir,
    }
}

fn link(path: &str) -> PlanEntry {
    PlanEntry {
        path: RelPath::parse(path).unwrap(),
        kind: PlanEntryKind::Symlink,
    }
}

fn file(path: &str, bytes: &[u8]) -> PlanEntry {
    PlanEntry {
        path: RelPath::parse(path).unwrap(),
        kind: PlanEntryKind::File {
            head: bytes[..bytes.len().min(PLAN_HEAD_BYTES)].to_vec(),
            len: bytes.len() as u64,
        },
    }
}

fn shown(plan: &[SignItem]) -> Vec<(SignKind, String)> {
    plan.iter().map(|i| (i.kind, i.rel().to_owned())).collect()
}

fn reversed(entries: &[PlanEntry]) -> Vec<PlanEntry> {
    entries.iter().rev().cloned().collect()
}

#[test]
fn a_windows_plan_lists_unsigned_pe_files_deepest_first() {
    let pe = unsigned_pe();
    let entries = vec![
        file("app.exe", &pe),
        dir("sub"),
        file("sub/lib.dll", &pe),
        dir("sub/deep"),
        file("sub/deep/x.dll", &pe),
        file("sub/deep/a.node", &pe),
        file("signed.dll", &signed_pe()),
        file(
            "fake.exe",
            b"MZ but no PE header anywhere in here, just text",
        ),
        file("readme.txt", b"hello"),
        file("empty.exe", b""),
    ];
    let plan = sign_plan(Target::WindowsX86_64, &entries, None).unwrap();
    let want = [
        "sub/deep/a.node",
        "sub/deep/x.dll",
        "sub/lib.dll",
        "app.exe",
    ];
    assert_eq!(
        shown(&plan),
        want.map(|p| (SignKind::PeFile, p.to_owned())).to_vec()
    );
    assert_eq!(
        sign_plan(Target::WindowsAarch64, &reversed(&entries), None).unwrap(),
        plan
    );
}

#[test]
fn a_pe_with_a_signature_but_bad_headers_is_an_error() {
    let mut bad = unsigned_pe();
    // NumberOfSections = 0 behind a valid `PE\0\0`.
    bad[0x86..0x88].copy_from_slice(&0u16.to_le_bytes());
    let err = sign_plan(Target::WindowsX86_64, &[file("bad.dll", &bad)], None).unwrap_err();
    assert!(
        matches!(err, SignPlanError::MalformedPe { ref path, .. } if path.as_str() == "bad.dll")
    );
}

/// The M8 bundle shape plus a dylib, a framework with a `Versions/Current` symlink and an app
/// extension holding its own framework (two nesting levels).
fn mac_bundle() -> Vec<PlanEntry> {
    let m = thin(false, true, None, 0x140);
    let universal = fat(true, false, &[thin(false, true, None, 0x140)]);
    vec![
        dir("Contents"),
        file("Contents/Info.plist", b"<plist/>"),
        dir("Contents/MacOS"),
        file("Contents/MacOS/Hello", &m),
        file("Contents/MacOS/lunepack-runtime", &m),
        file("Contents/MacOS/readme.txt", b"text"),
        dir("Contents/Resources"),
        file("Contents/Resources/lunepack-update.json", b"{}"),
        dir("Contents/Helpers"),
        dir("Contents/Helpers/lunepack-update.app"),
        dir("Contents/Helpers/lunepack-update.app/Contents"),
        file(
            "Contents/Helpers/lunepack-update.app/Contents/Info.plist",
            b"<plist/>",
        ),
        dir("Contents/Helpers/lunepack-update.app/Contents/MacOS"),
        file(
            "Contents/Helpers/lunepack-update.app/Contents/MacOS/lunepack-ui",
            &m,
        ),
        dir("Contents/Frameworks"),
        file("Contents/Frameworks/libbar.dylib", &universal),
        link("Contents/Frameworks/Link.framework"),
        link("Contents/Frameworks/liblink.dylib"),
        dir("Contents/Frameworks/Foo.framework"),
        link("Contents/Frameworks/Foo.framework/Foo"),
        dir("Contents/Frameworks/Foo.framework/Versions"),
        link("Contents/Frameworks/Foo.framework/Versions/Current"),
        dir("Contents/Frameworks/Foo.framework/Versions/A"),
        file("Contents/Frameworks/Foo.framework/Versions/A/Foo", &m),
        dir("Contents/Frameworks/Foo.framework/Versions/A/Resources"),
        file(
            "Contents/Frameworks/Foo.framework/Versions/A/Resources/Info.plist",
            b"<plist/>",
        ),
        dir("Contents/PlugIns"),
        dir("Contents/PlugIns/P.appex"),
        dir("Contents/PlugIns/P.appex/Contents"),
        dir("Contents/PlugIns/P.appex/Contents/MacOS"),
        file("Contents/PlugIns/P.appex/Contents/MacOS/P", &m),
        dir("Contents/PlugIns/P.appex/Contents/Frameworks"),
        dir("Contents/PlugIns/P.appex/Contents/Frameworks/Inner.framework"),
        dir("Contents/PlugIns/P.appex/Contents/Frameworks/Inner.framework/Versions"),
        dir("Contents/PlugIns/P.appex/Contents/Frameworks/Inner.framework/Versions/A"),
        file(
            "Contents/PlugIns/P.appex/Contents/Frameworks/Inner.framework/Versions/A/Inner",
            &m,
        ),
    ]
}

#[test]
fn a_macos_plan_signs_inner_to_outer() {
    use SignKind::{MachOFile as F, NestedBundle as B, OuterBundle as O};
    let main = RelPath::parse("Contents/MacOS/Hello").unwrap();
    let entries = mac_bundle();
    let plan = sign_plan(Target::MacosAarch64, &entries, Some(&main)).unwrap();
    let want: Vec<(SignKind, &str)> = vec![
        (
            F,
            "Contents/PlugIns/P.appex/Contents/Frameworks/Inner.framework/Versions/A/Inner",
        ),
        (
            B,
            "Contents/PlugIns/P.appex/Contents/Frameworks/Inner.framework",
        ),
        (F, "Contents/Frameworks/Foo.framework/Versions/A/Foo"),
        (B, "Contents/Frameworks/Foo.framework"),
        (
            F,
            "Contents/Helpers/lunepack-update.app/Contents/MacOS/lunepack-ui",
        ),
        (B, "Contents/Helpers/lunepack-update.app"),
        (F, "Contents/PlugIns/P.appex/Contents/MacOS/P"),
        (B, "Contents/PlugIns/P.appex"),
        (F, "Contents/Frameworks/libbar.dylib"),
        (F, "Contents/MacOS/lunepack-runtime"),
        (O, ""),
    ];
    let want: Vec<(SignKind, String)> = want.into_iter().map(|(k, p)| (k, p.to_owned())).collect();
    assert_eq!(shown(&plan), want);
    assert_eq!(plan.last().unwrap().path, None);
    // Deterministic whatever the input order, and the same for every macOS target.
    for target in [
        Target::MacosX86_64,
        Target::MacosAarch64,
        Target::MacosUniversal,
    ] {
        assert_eq!(
            sign_plan(target, &reversed(&entries), Some(&main)).unwrap(),
            plan
        );
    }
}

#[test]
fn a_bare_macos_bundle_is_just_the_outer_bundle() {
    let main = RelPath::parse("Contents/MacOS/Hello").unwrap();
    let m = thin(false, true, None, 0x140);
    let entries = [
        dir("Contents"),
        dir("Contents/MacOS"),
        file("Contents/MacOS/Hello", &m),
    ];
    let plan = sign_plan(Target::MacosX86_64, &entries, Some(&main)).unwrap();
    assert_eq!(shown(&plan), [(SignKind::OuterBundle, String::new())]);
}

#[test]
fn a_macos_plan_needs_the_main_executable() {
    assert_eq!(
        sign_plan(Target::MacosAarch64, &mac_bundle(), None).unwrap_err(),
        SignPlanError::NoMainExecutable
    );
}

#[test]
fn a_linux_plan_is_empty() {
    let pe = unsigned_pe();
    let mut entries = mac_bundle();
    entries.push(file("tool.exe", &pe));
    let main = RelPath::parse("Contents/MacOS/Hello").unwrap();
    for target in [Target::LinuxX86_64, Target::LinuxAarch64] {
        assert!(sign_plan(target, &entries, Some(&main)).unwrap().is_empty());
        assert!(sign_plan(target, &entries, None).unwrap().is_empty());
    }
}

// ---- publisher_check -------------------------------------------------------------------------------

fn with_member(value: Option<Value>) -> Vec<u8> {
    let mut map: Map<String, Value> =
        serde_json::from_slice(&sample_update_config().to_bytes().unwrap()).unwrap();
    match value {
        Some(v) => map.insert("publisher_check".to_owned(), v),
        None => map.remove("publisher_check"),
    };
    serde_json::to_vec(&map).unwrap()
}

#[test]
fn warn_and_enforce_round_trip() {
    for (policy, text) in [
        (PublisherPolicy::Warn, "warn"),
        (PublisherPolicy::Enforce, "enforce"),
    ] {
        let mut config = sample_update_config();
        config.publisher_check = policy;
        let bytes = config.to_bytes().unwrap();
        let map: Map<String, Value> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(map["publisher_check"], json!(text));
        let back = UpdateConfig::parse(&bytes).unwrap();
        assert_eq!(back, config);
        assert_eq!(back.to_bytes().unwrap(), bytes);
        assert_eq!(PublisherPolicy::parse(text), Some(policy));
        assert_eq!(policy.as_str(), text);
    }
}

const GOLDEN_MARK: &str =
    "<!-- golden: update-config, generated by crates/lunepack-core/tests/update_config.rs -->";

/// The FORMAT.md 13 example: the writer's bytes from before `publisher_check` existed.
fn pre_m9_bytes() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/FORMAT.md");
    let text = std::fs::read_to_string(path).unwrap();
    let after = text.split_once(GOLDEN_MARK).unwrap().1;
    let body = after.trim_start().strip_prefix("```json\n").unwrap();
    format!("{}\n", body.split_once("\n```").unwrap().0).into_bytes()
}

#[test]
fn off_writes_the_bytes_of_a_config_without_the_member() {
    let old = pre_m9_bytes();
    assert!(!String::from_utf8_lossy(&old).contains("publisher_check"));
    let mut config = UpdateConfig::parse(&old).unwrap();
    assert_eq!(config.publisher_check, PublisherPolicy::Off);
    config.publisher_check = PublisherPolicy::Off;
    assert_eq!(config.to_bytes().unwrap(), old);
    // The instrument: a policy other than off changes those bytes.
    config.publisher_check = PublisherPolicy::Warn;
    assert_ne!(config.to_bytes().unwrap(), old);
}

#[test]
fn absent_and_explicit_off_read_as_off() {
    let absent = UpdateConfig::parse(&with_member(None)).unwrap();
    assert_eq!(absent.publisher_check, PublisherPolicy::Off);
    assert!(!absent.extra.contains_key("publisher_check"));
    let off = UpdateConfig::parse(&with_member(Some(json!("off")))).unwrap();
    assert_eq!(off.publisher_check, PublisherPolicy::Off);
    assert_eq!(off.to_bytes().unwrap(), absent.to_bytes().unwrap());
    assert_eq!(PublisherPolicy::default(), PublisherPolicy::Off);
}

#[test]
fn any_other_value_is_refused_naming_the_member_only() {
    let marker = "SECRETMARKER";
    for bad in [
        json!("Enforce"),
        json!("OFF"),
        json!(""),
        json!(marker),
        json!(" warn"),
    ] {
        let err = UpdateConfig::parse(&with_member(Some(bad.clone()))).unwrap_err();
        assert!(
            matches!(
                err,
                UpdateConfigError::Invalid {
                    field: "publisher_check",
                    ..
                }
            ),
            "{bad}: {err:?}"
        );
        assert!(!format!("{err} {err:?}").contains(marker));
    }
    for bad in [json!(1), json!(null), json!(true), json!(["warn"])] {
        assert!(matches!(
            UpdateConfig::parse(&with_member(Some(bad))),
            Err(UpdateConfigError::WrongType("publisher_check"))
        ));
    }
    // A defined member, so `extra` cannot carry it past the writer.
    let mut config = sample_update_config();
    config
        .extra
        .insert("publisher_check".to_owned(), json!("warn"));
    assert!(config.to_bytes().is_err());
}
