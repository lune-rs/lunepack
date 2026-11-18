//! M6 step 7: the setup file's trailer (FORMAT.md 14), parsed fail-closed.

use lunepack_core::setup::{
    FOOTER_SIZE, SetupPart, SetupTrailer, TRAILER_MAGIC, TRAILER_SIZE, has_magic,
};
use lunepack_core::{Error, Target, Version};
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
