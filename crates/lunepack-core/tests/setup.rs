//! M6 step 7: the setup file's trailer (FORMAT.md 14), parsed fail-closed. M7 step 3: the
//! locator (M7-D11), which finds the trailer at the end of the file or before a signed PE's
//! certificate table and never refuses a file without the magic.

use std::path::Path;

use lunepack_core::pe::{SUBSYSTEM_CONSOLE, SUBSYSTEM_GUI};
use lunepack_core::setup::{
    FOOTER_SIZE, HEAD_SIZE, Located, SetupPart, SetupTrailer, TRAILER_MAGIC, TRAILER_SIZE,
    has_magic, locate, locate_file, parse_payload_file, table_candidate,
};
use lunepack_core::{Error, FsError, FsErrorKind, ReadAt, Target, Version};
use lunepack_testkit::exe_headers::{self, PeSpec, pe_image};
use lunepack_testkit::{ChainFixture, FakeHasher, FakeVerifier};

const FILE: u64 = 1 << 20;

fn trailer() -> SetupTrailer {
    let fx = ChainFixture::fake();
    SetupTrailer {
        root: fx.trusted_root(1, 1, &[0]),
        version: Version::parse("1.2.0").unwrap(),
        target: Target::LinuxX86_64,
        keys: SetupPart {
            offset: 1024,
            length: 600,
        },
        manifest: SetupPart {
            offset: 1632,
            length: 2000,
        },
        pack: SetupPart {
            offset: 3632,
            length: 9000,
        },
    }
}

fn parse(bytes: &[u8], file: u64) -> Result<SetupTrailer, Error> {
    SetupTrailer::parse(bytes, file, &FakeHasher, &FakeVerifier)
}

/// The footer's byte offset of part `i`'s offset (`+8`: its length).
fn part_at(i: usize) -> usize {
    TRAILER_SIZE as usize - FOOTER_SIZE + 16 + 16 * i
}

fn set_u64(bytes: &mut [u8], at: usize, v: u64) {
    bytes[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

#[test]
fn a_trailer_round_trips_and_ends_in_the_magic() {
    let t = trailer();
    let bytes = t.encode().unwrap();
    assert_eq!(bytes.len() as u64, TRAILER_SIZE);
    assert!(has_magic(&bytes));
    assert_eq!(bytes[bytes.len() - 16..], TRAILER_MAGIC);
    assert_eq!(parse(&bytes, FILE).unwrap(), t);
    // The body is canonical compact JSON with the root as the config writes it.
    let body_len = u32::from_le_bytes(
        bytes[TRAILER_SIZE as usize - FOOTER_SIZE + 4..TRAILER_SIZE as usize - FOOTER_SIZE + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    let body = std::str::from_utf8(&bytes[..body_len]).unwrap();
    assert!(
        body.starts_with("{\"app_id\":\"") && body.contains(",\"root\":{\"keys\":[\""),
        "{body}"
    );
    assert!(body.ends_with(",\"target\":\"linux-x86_64\",\"version\":\"1.2.0\"}"));
    // The same trailer encodes to the same bytes.
    assert_eq!(trailer().encode().unwrap(), bytes);
}

/// The trailer carries no signature of its own (its root is checked by verifying the payload
/// under it): a flipped byte is refused by the codec or parses to another trailer, never silently
/// to the same one.
#[test]
fn a_flipped_byte_in_the_trailer_is_refused_or_seen() {
    let t = trailer();
    let bytes = t.encode().unwrap();
    let mut refused = 0;
    for i in 0..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        match parse(&b, FILE) {
            Ok(other) => assert_ne!(other, t, "byte {i}"),
            Err(_) => refused += 1,
        }
    }
    // Every padding, reserved and magic byte, and most of the body, is refused.
    assert!(refused > bytes.len() - 200, "{refused} of {}", bytes.len());
}

#[test]
fn malformed_trailers_are_refused() {
    let bytes = trailer().encode().unwrap();
    let footer = TRAILER_SIZE as usize - FOOTER_SIZE;

    // Another format version.
    let mut b = bytes.clone();
    b[footer] = 2;
    assert!(matches!(
        parse(&b, FILE),
        Err(Error::FormatVersion { found: 2 })
    ));
    // Reserved bytes, padding, the body length.
    let mut b = bytes.clone();
    b[footer + 9] = 1;
    assert!(parse(&b, FILE).is_err(), "reserved");
    let mut b = bytes.clone();
    b[footer - 1] = 1;
    assert!(parse(&b, FILE).is_err(), "padding");
    for len in [0u32, 1, (footer + 1) as u32] {
        let mut b = bytes.clone();
        b[footer + 4..footer + 8].copy_from_slice(&len.to_le_bytes());
        assert!(parse(&b, FILE).is_err(), "body length {len}");
    }
    // A body that parses but is not canonical (a space after the first brace).
    let mut t = String::from_utf8(bytes[..footer].to_vec()).unwrap();
    let len = t.trim_end_matches('\0').len();
    t.insert(1, ' ');
    let mut b = t.into_bytes();
    b.truncate(footer);
    b.extend_from_slice(&bytes[footer..]);
    b[footer + 4..footer + 8].copy_from_slice(&((len + 1) as u32).to_le_bytes());
    assert!(
        matches!(parse(&b, FILE), Err(Error::Field(m)) if m.contains("canonical")),
        "{:?}",
        parse(&b, FILE)
    );
    // Too short, no magic.
    assert!(parse(&bytes[1..], FILE).is_err());
    let mut b = bytes.clone();
    let last = b.len() - 1;
    b[last] ^= 1;
    assert!(parse(&b, FILE).is_err());
}

#[test]
fn parts_must_be_inside_aligned_capped_and_apart() {
    let bytes = trailer().encode().unwrap();
    let with = |i: usize, offset: u64, length: u64| {
        let mut b = bytes.clone();
        set_u64(&mut b, part_at(i), offset);
        set_u64(&mut b, part_at(i) + 8, length);
        b
    };
    // Overlapping parts: the manifest starts inside the key set.
    assert!(
        matches!(parse(&with(1, 1600, 2000), FILE), Err(Error::Field(m)) if m.contains("overlap"))
    );
    // The pack overlapping the key set from below.
    assert!(parse(&with(2, 8, 1100), FILE).is_err());
    // Unaligned, empty, past the trailer, overflowing.
    assert!(parse(&with(2, 3633, 9000), FILE).is_err());
    assert!(parse(&with(2, 3632, 0), FILE).is_err());
    assert!(parse(&with(2, FILE - TRAILER_SIZE - 8, 16), FILE).is_err());
    assert!(parse(&with(2, u64::MAX - 7, 16), FILE).is_err());
    // Ending exactly at the trailer is allowed.
    parse(&with(2, FILE - TRAILER_SIZE - 16, 16), FILE).unwrap();
    // A key set or manifest over its document cap.
    assert!(parse(&with(0, 0, 64 * 1024 + 1), 1 << 30).is_err());
    assert!(parse(&with(1, 1 << 27, 64 * 1024 * 1024 + 8), 1 << 30).is_err());
    // A file too short for the parts it names (truncated).
    assert!(parse(&bytes, 3632 + 9000 + TRAILER_SIZE - 1).is_err());
    parse(&bytes, 3632 + 9000 + TRAILER_SIZE).unwrap();
    assert!(parse(&bytes, TRAILER_SIZE - 1).is_err());
}

// ---- the locator (M7-D11) ------------------------------------------------------------------------

struct Bytes(Vec<u8>);

impl ReadAt for Bytes {
    fn size(&self) -> Result<u64, FsError> {
        Ok(self.0.len() as u64)
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FsError> {
        let start = usize::try_from(offset).unwrap();
        match self.0.get(start..start + buf.len()) {
            Some(src) => {
                buf.copy_from_slice(src);
                Ok(())
            }
            None => Err(FsError::new(FsErrorKind::Other, Path::new("exe"), None)),
        }
    }
}

/// The locator over `file`, read through [`locate_file`]; checked against [`locate`] over slices.
fn located(file: &[u8]) -> Located {
    let through_file = locate_file(&Bytes(file.to_vec())).unwrap();
    let len = file.len() as u64;
    if len >= TRAILER_SIZE {
        let head = &file[..file.len().min(HEAD_SIZE as usize)];
        let tail = |end: u64| &file[(end - TRAILER_SIZE) as usize..end as usize];
        let direct = locate(head, tail(len), table_candidate(head, len).map(tail), len);
        assert_eq!(direct, through_file, "locate and locate_file disagree");
    }
    through_file
}

fn runtime(pe32: bool) -> Vec<u8> {
    pe_image(
        0x8664,
        &PeSpec {
            pe32,
            ..PeSpec::hardened(SUBSYSTEM_GUI)
        },
    )
}

fn pad8(file: &mut Vec<u8>) {
    file.resize(file.len().div_ceil(8) * 8, 0);
}

/// `exe` + an 8-aligned payload (zero bytes standing in for the key set, the manifest and the
/// pack) + the trailer naming them, as the setup writer lays it out.
fn setup_file(mut exe: Vec<u8>) -> (Vec<u8>, SetupTrailer) {
    let mut t = trailer();
    for (part, len) in [
        (&mut t.keys, 600),
        (&mut t.manifest, 2000),
        (&mut t.pack, 9000),
    ] {
        pad8(&mut exe);
        *part = SetupPart {
            offset: exe.len() as u64,
            length: len,
        };
        exe.resize(exe.len() + len as usize, 0);
    }
    exe.extend_from_slice(&t.encode().unwrap());
    (exe, t)
}

/// The byte offset of the security directory entry in an image from `pe_image`.
fn security_at(pe32: bool) -> usize {
    0x84 + 20 + if pe32 { 96 } else { 112 } + 4 * 8
}

fn set_security(file: &mut [u8], pe32: bool, offset: u64, size: u64) {
    let at = security_at(pe32);
    file[at..at + 4].copy_from_slice(&(offset as u32).to_le_bytes());
    file[at + 4..at + 8].copy_from_slice(&(size as u32).to_le_bytes());
}

/// Signs `file` the way signtool lays it out: pads to 8, points the security directory at the
/// end and appends a `len`-byte certificate table. Returns the table's offset.
fn sign(file: &mut Vec<u8>, pe32: bool, len: usize) -> u64 {
    pad8(file);
    let offset = file.len() as u64;
    set_security(file, pe32, offset, len as u64);
    file.extend((0..len).map(|i| (i % 251) as u8));
    offset
}

#[test]
fn files_without_the_magic_are_ordinary_runtimes() {
    // An ordinary runtime, and one with a well-formed certificate table at the end.
    let plain = runtime(false);
    assert_eq!(located(&plain), Located::None);
    let mut signed = runtime(false);
    sign(&mut signed, false, 1024);
    assert_eq!(located(&signed), Located::None);
    // Odd tables: never a refusal without the magic.
    let base = || {
        let mut f = runtime(false);
        f.resize(f.len() + 8192, 0x5A);
        f
    };
    let len = base().len() as u64;
    for (offset, size) in [
        (len - 1024 + 1, 1023),        // offset not 8-aligned
        (len - 2048, 1024),            // table not at the end
        (len - 1024, 1016),            // padding after the table
        (0, 64),                       // offset 0 with a size
        (len - 1024, 0),               // size 0
        (len - 4, 4),                  // shorter than 8
        (len - 1024, u32::MAX as u64), // past the end
        (len + 8, 8),                  // starts past the end
        (16, 8),                       // inside the headers
    ] {
        let mut f = base();
        set_security(&mut f, false, offset, size);
        assert_eq!(located(&f), Located::None, "table at {offset} size {size}");
    }
    // An ELF, a header-only PE, files shorter than a trailer, an empty file.
    assert_eq!(located(&exe_headers::elf(62, false, 9000)), Located::None);
    assert_eq!(located(&exe_headers::pe(0x8664, 9000)), Located::None);
    assert_eq!(located(&plain[..100]), Located::None);
    assert_eq!(located(b""), Located::None);
    // `e_lfanew` past the head, and truncated headers: no magic, so ordinary.
    let mut far = plain.clone();
    far.resize(20_000, 0);
    far[0x3C..0x40].copy_from_slice(&8000u32.to_le_bytes());
    assert_eq!(located(&far), Located::None);
    let mut cut = plain[..0x90].to_vec();
    cut.resize(9000, 0);
    assert_eq!(located(&cut), Located::None);
}

#[test]
fn a_trailer_before_a_certificate_table_at_the_end_is_a_setup() {
    for pe32 in [false, true] {
        let (mut file, t) = setup_file(runtime(pe32));
        let end = sign(&mut file, pe32, 1024);
        assert_eq!(located(&file), Located::Setup { end }, "pe32 {pe32}");
        let tail = &file[(end - TRAILER_SIZE) as usize..end as usize];
        assert_eq!(parse(tail, end).unwrap(), t);
    }
    // The minimal table (8 bytes).
    let (mut file, _) = setup_file(runtime(false));
    let end = sign(&mut file, false, 8);
    assert_eq!(located(&file), Located::Setup { end });
}

#[test]
fn the_directory_is_read_at_the_offset_of_each_optional_header_kind() {
    // A PE32 file whose table entry is written where PE32+ keeps it: the PE32 reader sees no
    // security directory, so the magic (hidden before the table) is not found.
    let (mut file, _) = setup_file(runtime(true));
    pad8(&mut file);
    let offset = file.len() as u64;
    set_security(&mut file, false, offset, 1024);
    file.resize(file.len() + 1024, 7);
    assert_eq!(located(&file), Located::None);
    // And the other way round.
    let (mut file, _) = setup_file(runtime(false));
    pad8(&mut file);
    let offset = file.len() as u64;
    set_security(&mut file, true, offset, 1024);
    file.resize(file.len() + 1024, 7);
    assert_eq!(located(&file), Located::None);
}

#[test]
fn a_trailer_at_the_end_of_an_unsigned_file_is_a_setup() {
    let (file, t) = setup_file(runtime(false));
    let len = file.len() as u64;
    assert_eq!(located(&file), Located::Setup { end: len });
    assert_eq!(
        parse(&file[file.len() - TRAILER_SIZE as usize..], len).unwrap(),
        t
    );
    // A Linux runtime (today's rule).
    let (file, _) = setup_file(exe_headers::elf(62, false, 8000));
    assert_eq!(
        located(&file),
        Located::Setup {
            end: file.len() as u64
        }
    );
    // A console PE32 image too.
    let console = pe_image(
        0x8664,
        &PeSpec {
            pe32: true,
            ..PeSpec::hardened(SUBSYSTEM_CONSOLE)
        },
    );
    let (file, _) = setup_file(console);
    assert_eq!(
        located(&file),
        Located::Setup {
            end: file.len() as u64
        }
    );
}

#[test]
fn malformed_layouts_with_the_magic_are_refused() {
    // One byte after the certificate table.
    let (mut file, _) = setup_file(runtime(false));
    sign(&mut file, false, 1024);
    file.push(0);
    assert_eq!(located(&file), Located::Malformed);

    // The table's size reaches past the end, or stops short of it.
    for delta in [8i64, -8] {
        let (mut file, _) = setup_file(runtime(false));
        let offset = sign(&mut file, false, 1024);
        set_security(&mut file, false, offset, (1024 + delta) as u64);
        assert_eq!(located(&file), Located::Malformed, "size delta {delta}");
    }

    // A table offset that is not 8-aligned, with the trailer right before it.
    let (mut odd, _) = setup_file(runtime(false));
    let trailer_bytes = odd.split_off(odd.len() - TRAILER_SIZE as usize);
    odd.push(0);
    odd.extend_from_slice(&trailer_bytes);
    let offset = odd.len() as u64;
    assert!(!offset.is_multiple_of(8));
    set_security(&mut odd, false, offset, 1024);
    odd.resize(odd.len() + 1024, 3);
    assert_eq!(located(&odd), Located::Malformed);

    // A table shorter than 8 bytes.
    let (mut file, _) = setup_file(runtime(false));
    let offset = sign(&mut file, false, 8);
    set_security(&mut file, false, offset, 4);
    file.truncate(file.len() - 4);
    assert_eq!(located(&file), Located::Malformed);

    // A trailer overlapping the PE's headers and sections: the table right after the image.
    let mut tiny = runtime(false);
    assert!((tiny.len() as u64) < TRAILER_SIZE);
    tiny.resize(TRAILER_SIZE as usize - TRAILER_MAGIC.len(), 0);
    tiny.extend_from_slice(&TRAILER_MAGIC);
    let end = tiny.len() as u64;
    set_security(&mut tiny, false, end, 64);
    tiny.resize(tiny.len() + 64, 1);
    assert_eq!(located(&tiny), Located::Malformed);

    // The magic at the end after a signature (a trailer appended to a signed file: unsigned
    // bytes), including a table that overlaps that trailer.
    let mut signed = runtime(false);
    sign(&mut signed, false, 1024);
    let (file, _) = setup_file(signed);
    assert_eq!(located(&file), Located::Malformed);
    let (mut file, _) = setup_file(runtime(false));
    let len = file.len() as u64;
    set_security(&mut file, false, len - 1024, 1024);
    assert_eq!(located(&file), Located::Malformed);
    // A security directory with offset 0 and a size, and the magic at the end.
    let (mut file, _) = setup_file(runtime(false));
    set_security(&mut file, false, 0, 64);
    assert_eq!(located(&file), Located::Malformed);

    // `e_lfanew` past the head, with the magic at the end.
    let mut far = runtime(false);
    far.resize(20_000, 0);
    far[0x3C..0x40].copy_from_slice(&8000u32.to_le_bytes());
    let (file, _) = setup_file(far);
    assert_eq!(located(&file), Located::Malformed);
    // Truncated headers (the optional header cut off), with the magic at the end.
    let mut cut = runtime(false)[..0x90].to_vec();
    cut.resize(4000, 0);
    let (file, _) = setup_file(cut);
    assert_eq!(located(&file), Located::Malformed);
    // The header-only PE of earlier milestones, with the magic at the end.
    let (file, _) = setup_file(exe_headers::pe(0x8664, 4000));
    assert_eq!(located(&file), Located::Malformed);
}

/// Every truncation of a signed setup and of an unsigned one: a value, never a panic; and a
/// truncated signed setup is never taken for one with its trailer elsewhere.
#[test]
fn truncated_setups_never_panic() {
    let (mut signed, _) = setup_file(runtime(false));
    let end = sign(&mut signed, false, 64);
    for n in 0..signed.len() {
        let got = located(&signed[..n]);
        assert!(
            got != Located::Setup { end } || n == signed.len(),
            "truncated to {n}"
        );
    }
}

// ---- the macOS installer's payload file (M8-D7) ---------------------------------------------------

/// A payload file as the installer carries it: the parts from offset 0, each 8-aligned, then the
/// trailer naming them (zero bytes stand in for the key set, the manifest and the pack).
fn payload_file() -> (Vec<u8>, SetupTrailer) {
    let (file, mut t) = setup_file(Vec::new());
    t.target = Target::MacosAarch64;
    let mut file = file[..file.len() - TRAILER_SIZE as usize].to_vec();
    file.extend_from_slice(&t.encode().unwrap());
    (file, t)
}

fn parse_payload(file: &[u8]) -> Result<SetupTrailer, Error> {
    parse_payload_file(&Bytes(file.to_vec()), &FakeHasher, &FakeVerifier)
}

#[test]
fn a_payload_file_round_trips() {
    let (file, t) = payload_file();
    assert_eq!(t.keys.offset, 0);
    assert!(file.len().is_multiple_of(8));
    assert_eq!(parse_payload(&file).unwrap(), t);
}

/// Every truncation is refused (never a panic, never the same trailer).
#[test]
fn every_truncation_of_a_payload_file_is_refused() {
    let (file, _) = payload_file();
    for n in 0..file.len() {
        assert!(parse_payload(&file[..n]).is_err(), "truncated to {n}");
    }
}

/// A flipped byte in the trailer is refused or parses to another trailer (whose parts then fail
/// verification); one in a part leaves the trailer and is the verification's to refuse.
#[test]
fn a_flipped_byte_in_a_payload_files_trailer_is_refused_or_seen() {
    let (file, t) = payload_file();
    let start = file.len() - TRAILER_SIZE as usize;
    for i in start..file.len() {
        let mut b = file.clone();
        b[i] ^= 0x01;
        if let Ok(other) = parse_payload(&b) {
            assert_ne!(other, t, "byte {i}");
        }
    }
}

#[test]
fn a_payload_file_must_be_aligned_start_at_zero_and_end_in_its_trailer() {
    let (file, t) = payload_file();
    // A byte after the trailer: not a multiple of 8, and no magic at the end.
    let mut longer = file.clone();
    longer.push(0);
    assert!(parse_payload(&longer).is_err());
    // Eight bytes after the trailer: aligned, but no magic at the end.
    let mut longer = file.clone();
    longer.extend_from_slice(&[0u8; 8]);
    assert!(parse_payload(&longer).is_err());
    // Eight bytes in front with the parts moved along: the payload no longer starts at 0.
    let mut moved = t.clone();
    for part in [&mut moved.keys, &mut moved.manifest, &mut moved.pack] {
        part.offset += 8;
    }
    let mut shifted = vec![0u8; 8];
    shifted.extend_from_slice(&file[..file.len() - TRAILER_SIZE as usize]);
    shifted.extend_from_slice(&moved.encode().unwrap());
    assert!(parse_payload(&shifted).is_err());
    // A Linux setup file (a runtime in front of the payload) is not a payload file.
    let (setup, _) = setup_file(vec![0x7f; 4000]);
    assert!(parse_payload(&setup).is_err());
}

// ---- The setup anchor (M10-D4, M10 step 14) -------------------------------------------------

mod anchor {
    use lunepack_core::pe::{PeError, PeHeaders, RT_RCDATA, rcdata};
    use lunepack_core::setup::{
        ANCHOR_MAGIC, ANCHOR_SIZE, SetupAnchor, SetupPart, SetupTrailer, TRAILER_SIZE,
        verify_setup_anchored,
    };
    use lunepack_core::{
        Channel, ClockReading, CodecId, Error, InstallMeta, PayloadKind, RelPath, Target,
        TrustedRoot, UPDATE_CONFIG_FILE, UpdateConfig, Version,
    };
    use lunepack_testkit::exe_headers::{PeSpec, pe_image};
    use lunepack_testkit::{
        ChainFixture, FakeClock, FakeCodec, FakeHasher, FakeVerifier, PackBuilder, SUITE_T0,
    };

    use super::Bytes as Mem;

    const TARGET: Target = Target::WindowsX86_64;

    fn meta() -> InstallMeta {
        InstallMeta {
            entry: RelPath::parse("app.exe").unwrap(),
            name: "Hello".into(),
            comment: None,
            icon: None,
            categories: Vec::new(),
            bin: None,
            terminal: false,
            publisher: None,
            file_types: Vec::new(),
            url_schemes: Vec::new(),
            autostart: false,
        }
    }

    /// A complete setup file: filler runtime, key set, manifest, pack and trailer, every part
    /// 8-aligned, signed under the root of `root_seed` (release key seed 5), of `version`.
    struct Built {
        file: Vec<u8>,
        trailer: SetupTrailer,
        keys: Vec<u8>,
        manifest: Vec<u8>,
    }

    impl Built {
        fn new(root_seed: u8, version: &str) -> Built {
            let fx = ChainFixture::fake();
            let root: TrustedRoot = fx.trusted_root(1, 1, &[root_seed]);
            let config = UpdateConfig::new(
                &root,
                Version::parse(version).unwrap(),
                TARGET,
                "https://updates.example.org/hello/",
                Channel::parse("stable").unwrap(),
                60,
                meta(),
            )
            .unwrap()
            .to_bytes()
            .unwrap();
            let mut pack = PackBuilder::new();
            pack.file(fx.hasher, "app.exe", b"entry", CodecId::Lzma2);
            pack.file(fx.hasher, UPDATE_CONFIG_FILE, &config, CodecId::Stored);
            let keys = fx.envelope(
                PayloadKind::Keys,
                &fx.keyset_document(1, 1, None, 1, &[5]).to_payload(),
                &[root_seed],
            );
            let manifest = fx.envelope(
                PayloadKind::Manifest,
                &fx.manifest_document(version, TARGET, &pack).to_payload(),
                &[5],
            );
            let mut file = vec![0x4du8; 1000];
            let place = |file: &mut Vec<u8>, bytes: &[u8]| {
                while !file.len().is_multiple_of(8) {
                    file.push(0);
                }
                let part = SetupPart {
                    offset: file.len() as u64,
                    length: bytes.len() as u64,
                };
                file.extend_from_slice(bytes);
                part
            };
            let k = place(&mut file, &keys);
            let m = place(&mut file, &manifest);
            let p = place(&mut file, &pack.bytes);
            while !file.len().is_multiple_of(8) {
                file.push(0);
            }
            let trailer = SetupTrailer {
                root,
                version: Version::parse(version).unwrap(),
                target: TARGET,
                keys: k,
                manifest: m,
                pack: p,
            };
            file.extend_from_slice(&trailer.encode().unwrap());
            Built {
                file,
                trailer,
                keys,
                manifest,
            }
        }

        fn block(&self) -> &[u8] {
            &self.file[self.file.len() - TRAILER_SIZE as usize..]
        }

        fn anchor(&self) -> SetupAnchor {
            SetupAnchor::of(self.block(), &self.keys, &self.manifest, &FakeHasher)
        }
    }

    fn check(
        anchor: &SetupAnchor,
        file: &[u8],
    ) -> Result<lunepack_core::setup::AnchoredSetup, Error> {
        let end = file.len() as u64;
        verify_setup_anchored(
            anchor,
            &file[file.len() - TRAILER_SIZE as usize..],
            &Mem(file.to_vec()),
            end,
            &ClockReading::read(&FakeClock::new(SUITE_T0), None),
            &FakeCodec::new(),
            &FakeHasher,
            &FakeVerifier,
        )
    }

    fn anchor_error(r: Result<lunepack_core::setup::AnchoredSetup, Error>) -> &'static str {
        match r {
            Err(Error::SetupAnchor(why)) => why,
            Err(e) => panic!("not an anchor error: {e}"),
            Ok(_) => panic!("verified"),
        }
    }

    #[test]
    fn a_matching_anchor_verifies_and_names_the_key_set_version() {
        let b = Built::new(0, "1.2.0");
        let a = b.anchor();
        let ok = check(&a, &b.file).expect("verifies");
        assert_eq!(ok.trailer, b.trailer);
        assert_eq!(ok.keyset_version, 1);
        assert_eq!(ok.setup.config.version.to_string(), "1.2.0");
        // The encoding round-trips and is the magic and three digests.
        let enc = a.encode();
        assert_eq!(enc.len(), ANCHOR_SIZE);
        assert_eq!(enc[..8], ANCHOR_MAGIC);
        assert_eq!(SetupAnchor::parse(&enc).unwrap(), a);
    }

    #[test]
    fn each_wrong_digest_fails() {
        let b = Built::new(0, "1.2.0");
        let good = b.anchor();
        for (i, why) in [(0, "trailer"), (1, "key set"), (2, "manifest")] {
            let mut enc = good.encode();
            enc[8 + 32 * i] ^= 1;
            let bad = SetupAnchor::parse(&enc).unwrap();
            assert_eq!(anchor_error(check(&bad, &b.file)), why);
        }
        // The same through the file: a byte flipped in the trailer's body, the key set or the
        // manifest.
        let t = &b.trailer;
        for (at, why) in [
            (b.file.len() - TRAILER_SIZE as usize + 2, "trailer"),
            ((t.keys.offset + t.keys.length / 2) as usize, "key set"),
            (
                (t.manifest.offset + t.manifest.length / 2) as usize,
                "manifest",
            ),
        ] {
            let mut f = b.file.clone();
            f[at] ^= 1;
            assert_eq!(anchor_error(check(&good, &f)), why);
        }
    }

    #[test]
    fn the_placeholder_and_malformed_encodings_are_refused() {
        let b = Built::new(0, "1.2.0");
        let placeholder = SetupAnchor::parse(&SetupAnchor::PLACEHOLDER).unwrap();
        assert!(placeholder.is_placeholder());
        assert_eq!(
            anchor_error(check(&placeholder, &b.file)),
            "the anchor was never written"
        );
        let enc = b.anchor().encode();
        for bad in [
            &enc[..ANCHOR_SIZE - 1],
            &[&enc[..], &[0u8][..]].concat()[..],
            &[][..],
        ] {
            assert!(matches!(
                SetupAnchor::parse(bad),
                Err(Error::SetupAnchor("malformed"))
            ));
        }
        let mut wrong_magic = enc;
        wrong_magic[0] ^= 1;
        assert!(matches!(
            SetupAnchor::parse(&wrong_magic),
            Err(Error::SetupAnchor("malformed"))
        ));
    }

    /// A whole payload (and its trailer) swapped for another validly signed one fails: another
    /// root, or the same root and another version.
    #[test]
    fn a_swapped_valid_payload_fails() {
        let a = Built::new(0, "1.2.0");
        let anchor = a.anchor();
        for other in [Built::new(9, "1.2.0"), Built::new(0, "1.1.0")] {
            check(&other.anchor(), &other.file).expect("the other setup is valid on its own");
            assert_eq!(anchor_error(check(&anchor, &other.file)), "trailer");
            // Even with the original trailer block kept over the other payload.
            let mut f = other.file[..other.file.len() - TRAILER_SIZE as usize].to_vec();
            f.extend_from_slice(a.block());
            assert!(check(&anchor, &f).is_err());
        }
    }

    /// The hardened test image with its `RT_MANIFEST` resource retyped as `RT_RCDATA` `id`.
    fn rcdata_image(id: u32) -> (Vec<u8>, usize) {
        let mut img = pe_image(0x8664, &PeSpec::hardened(2));
        let h = PeHeaders::parse(&img, img.len() as u64).unwrap();
        let rsrc = h.sections.last().unwrap().raw_ptr as usize;
        // Type entry id at +16, name entry id at +40 (testkit's `.rsrc` layout).
        img[rsrc + 16..rsrc + 20].copy_from_slice(&RT_RCDATA.to_le_bytes());
        img[rsrc + 40..rsrc + 44].copy_from_slice(&id.to_le_bytes());
        (img, rsrc)
    }

    #[test]
    fn rcdata_finds_the_span_or_nothing() {
        let (img, rsrc) = rcdata_image(1);
        let span = rcdata(&img, 1).unwrap().expect("found");
        assert_eq!(span.file_offset, (rsrc + 88) as u64);
        let manifest = lunepack_testkit::exe_headers::HARDENED_MANIFEST.as_bytes();
        assert_eq!(span.len as usize, manifest.len());
        assert_eq!(
            &img[span.file_offset as usize..span.file_offset as usize + manifest.len()],
            manifest
        );
        // Another id, an image with only a manifest, an image with no resources.
        assert_eq!(rcdata(&img, 2).unwrap(), None);
        let plain = pe_image(0x8664, &PeSpec::hardened(2));
        assert_eq!(rcdata(&plain, 1).unwrap(), None);
        let bare = pe_image(
            0x8664,
            &PeSpec {
                manifest: None,
                ..PeSpec::hardened(2)
            },
        );
        assert_eq!(rcdata(&bare, 1).unwrap(), None);
    }

    #[test]
    fn rcdata_refuses_a_truncated_or_ambiguous_directory() {
        let (img, rsrc) = rcdata_image(1);
        // The language directory claims more entries than its section holds.
        let mut many = img.clone();
        many[rsrc + 48 + 14..rsrc + 48 + 16].copy_from_slice(&0xffffu16.to_le_bytes());
        assert!(matches!(rcdata(&many, 1), Err(PeError::Malformed(_))));
        // Two language entries: which one the loader picks is not ours to guess.
        let mut two = img.clone();
        two[rsrc + 48 + 14..rsrc + 48 + 16].copy_from_slice(&2u16.to_le_bytes());
        assert!(rcdata(&two, 1).is_err());
        // The data entry's size runs past the section.
        let mut long = img.clone();
        long[rsrc + 76..rsrc + 80].copy_from_slice(&0x10_0000u32.to_le_bytes());
        assert!(rcdata(&long, 1).is_err());
        // The file cut inside the resource section.
        assert!(rcdata(&img[..rsrc + 20], 1).is_err());
        // Never a panic on any prefix.
        for n in (0..img.len()).step_by(7) {
            let _ = rcdata(&img[..n], 1);
        }
    }
}
