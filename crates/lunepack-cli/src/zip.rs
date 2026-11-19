//! The `.zip` writer of `lunepack setup --zip` (M8-D9): the PKWARE container written by hand over
//! `flate2`'s deflate and CRC-32, so the bundle can be zipped on any host and the same bytes come
//! out of two runs.
//!
//! What it writes, and nothing else:
//! - one local header, the data and a central-directory record per entry, in the order the caller
//!   adds them, then the end-of-central-directory record;
//! - names as UTF-8 (general-purpose flag bit 11), directories with a trailing `/`;
//! - DOS time 00:00:00 and DOS date 1980-01-01 on every entry (no clock is read);
//! - "version made by" Unix (3), and the Unix mode in the high 16 bits of the external attributes:
//!   a regular file `0100644` or `0100755`, a directory `040755` (plus the DOS directory bit), a
//!   symlink `0120755` whose data is the link text;
//! - a file as deflate (method 8, level 9) when that is smaller than its bytes, else stored.
//!
//! No ZIP64: more than [`MAX_ENTRIES`] entries, an entry or the archive reaching 4 GiB, or an
//! offset that does, is an error and the writer stops (the file is then incomplete and must be
//! discarded by the caller). No data descriptors, encryption, extra fields or comments.

use std::io::Write;

use anyhow::{Result, bail};
use flate2::write::DeflateEncoder;
use flate2::{Compression, Crc};

/// Most entries an archive without ZIP64 can hold (a 16-bit count).
pub const MAX_ENTRIES: usize = 65_535;
/// Sizes and offsets at or above this are ZIP64's (a 32-bit field's all-ones value is its marker).
const LIMIT: u64 = 0xFFFF_FFFF;
/// Longest name the 16-bit length field holds.
const MAX_NAME_BYTES: usize = 0xFFFF;

const LOCAL_SIG: u32 = 0x0403_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const END_SIG: u32 = 0x0605_4b50;
/// Bit 11: names and comments are UTF-8.
const FLAG_UTF8: u16 = 0x0800;
/// 1980-01-01 as a DOS date (`(year - 1980) << 9 | month << 5 | day`).
const DOS_DATE: u16 = (1 << 5) | 1;
/// "Version made by": Unix (3), specification 2.0.
const MADE_BY: u16 = (3 << 8) | 20;

/// A regular file's, a directory's and a symlink's Unix file type bits.
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;
/// The MS-DOS directory attribute, in the low byte of the external attributes.
const DOS_DIR: u32 = 0x10;

/// What an entry is.
#[derive(Debug, Clone, Copy)]
pub enum Kind<'a> {
    /// A directory (its name gets the trailing `/`).
    Dir,
    /// A regular file.
    File {
        /// Its bytes.
        data: &'a [u8],
        /// The executable bits (`0755` instead of `0644`).
        exec: bool,
    },
    /// A symbolic link holding this text.
    Symlink {
        /// The link text.
        target: &'a str,
    },
}

/// A written entry, kept for the central directory.
struct Central {
    name: Vec<u8>,
    method: u16,
    needed: u16,
    crc: u32,
    compressed: u32,
    size: u32,
    external: u32,
    offset: u32,
}

/// Writes an archive to `out`, entry by entry.
pub struct Writer<W: Write> {
    out: W,
    pos: u64,
    entries: Vec<Central>,
}

impl<W: Write> Writer<W> {
    /// A writer at the start of `out`.
    pub fn new(out: W) -> Self {
        Writer {
            out,
            pos: 0,
            entries: Vec::new(),
        }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.out.write_all(bytes)?;
        self.pos += bytes.len() as u64;
        Ok(())
    }

    /// Adds the entry `name` (a `/`-separated path without a leading or trailing `/`).
    pub fn add(&mut self, name: &str, kind: Kind<'_>) -> Result<()> {
        if self.entries.len() >= MAX_ENTRIES {
            bail!("zip: more than {MAX_ENTRIES} entries (ZIP64 is not written)");
        }
        if name.is_empty() || name.starts_with('/') || name.ends_with('/') || name.contains('\0') {
            bail!("zip: {name:?} is not an entry name");
        }
        let mut full = name.as_bytes().to_vec();
        let (external, data, deflate): (u32, &[u8], bool) = match kind {
            Kind::Dir => {
                full.push(b'/');
                ((S_IFDIR | 0o755) << 16 | DOS_DIR, &[], false)
            }
            Kind::File { data, exec } => {
                let mode = S_IFREG | if exec { 0o755 } else { 0o644 };
                (mode << 16, data, true)
            }
            Kind::Symlink { target } => ((S_IFLNK | 0o755) << 16, target.as_bytes(), false),
        };
        if full.len() > MAX_NAME_BYTES {
            bail!("zip: the name {name:?} is longer than 65535 bytes");
        }
        let size = u32::try_from(data.len())
            .ok()
            .filter(|n| u64::from(*n) < LIMIT)
            .ok_or_else(|| {
                anyhow::anyhow!("zip: {name:?} is 4 GiB or more (ZIP64 is not written)")
            })?;
        let mut crc = Crc::new();
        crc.update(data);

        let (method, body) = match deflate && !data.is_empty() {
            true => {
                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
                encoder.write_all(data)?;
                let packed = encoder.finish()?;
                if packed.len() < data.len() {
                    (8u16, Some(packed))
                } else {
                    (0u16, None)
                }
            }
            false => (0u16, None),
        };
        let body: &[u8] = body.as_deref().unwrap_or(data);
        let compressed = u32::try_from(body.len())
            .ok()
            .filter(|n| u64::from(*n) < LIMIT)
            .ok_or_else(|| {
                anyhow::anyhow!("zip: {name:?} is 4 GiB or more (ZIP64 is not written)")
            })?;
        let needed: u16 = if method == 8 || matches!(kind, Kind::Dir) {
            20
        } else {
            10
        };
        let offset = u32::try_from(self.pos)
            .ok()
            .filter(|n| u64::from(*n) < LIMIT)
            .ok_or_else(|| {
                anyhow::anyhow!("zip: the archive is 4 GiB or more (ZIP64 is not written)")
            })?;

        let mut header = Vec::with_capacity(30 + full.len());
        header.extend_from_slice(&LOCAL_SIG.to_le_bytes());
        header.extend_from_slice(&needed.to_le_bytes());
        header.extend_from_slice(&FLAG_UTF8.to_le_bytes());
        header.extend_from_slice(&method.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&DOS_DATE.to_le_bytes());
        header.extend_from_slice(&crc.sum().to_le_bytes());
        header.extend_from_slice(&compressed.to_le_bytes());
        header.extend_from_slice(&size.to_le_bytes());
        header.extend_from_slice(&(full.len() as u16).to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&full);
        self.put(&header)?;
        self.put(body)?;
        self.entries.push(Central {
            name: full,
            method,
            needed,
            crc: crc.sum(),
            compressed,
            size,
            external,
            offset,
        });
        Ok(())
    }

    /// Writes the central directory and the end record, and returns the output.
    pub fn finish(mut self) -> Result<W> {
        let start = u32::try_from(self.pos)
            .ok()
            .filter(|n| u64::from(*n) < LIMIT)
            .ok_or_else(|| {
                anyhow::anyhow!("zip: the archive is 4 GiB or more (ZIP64 is not written)")
            })?;
        let entries = std::mem::take(&mut self.entries);
        for e in &entries {
            let mut record = Vec::with_capacity(46 + e.name.len());
            record.extend_from_slice(&CENTRAL_SIG.to_le_bytes());
            record.extend_from_slice(&MADE_BY.to_le_bytes());
            record.extend_from_slice(&e.needed.to_le_bytes());
            record.extend_from_slice(&FLAG_UTF8.to_le_bytes());
            record.extend_from_slice(&e.method.to_le_bytes());
            record.extend_from_slice(&0u16.to_le_bytes());
            record.extend_from_slice(&DOS_DATE.to_le_bytes());
            record.extend_from_slice(&e.crc.to_le_bytes());
            record.extend_from_slice(&e.compressed.to_le_bytes());
            record.extend_from_slice(&e.size.to_le_bytes());
            record.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            record.extend_from_slice(&0u16.to_le_bytes()); // extra
            record.extend_from_slice(&0u16.to_le_bytes()); // comment
            record.extend_from_slice(&0u16.to_le_bytes()); // disk
            record.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
            record.extend_from_slice(&e.external.to_le_bytes());
            record.extend_from_slice(&e.offset.to_le_bytes());
            record.extend_from_slice(&e.name);
            self.put(&record)?;
        }
        let size = u32::try_from(self.pos - u64::from(start))
            .ok()
            .filter(|n| u64::from(*n) < LIMIT)
            .ok_or_else(|| anyhow::anyhow!("zip: the central directory is 4 GiB or more"))?;
        if self.pos >= LIMIT {
            bail!("zip: the archive is 4 GiB or more (ZIP64 is not written)");
        }
        let count = entries.len() as u16;
        let mut end = Vec::with_capacity(22);
        end.extend_from_slice(&END_SIG.to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes());
        end.extend_from_slice(&count.to_le_bytes());
        end.extend_from_slice(&count.to_le_bytes());
        end.extend_from_slice(&size.to_le_bytes());
        end.extend_from_slice(&start.to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes());
        self.put(&end)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use flate2::read::DeflateDecoder;

    use super::*;

    fn u16_at(b: &[u8], at: usize) -> u16 {
        u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
    }

    fn u32_at(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    /// One entry as read back: name, Unix mode, method, data.
    #[derive(Debug, PartialEq)]
    struct Read1 {
        name: String,
        mode: u32,
        method: u16,
        data: Vec<u8>,
    }

    /// Reads `zip` through the central directory the way an unzipper does, checking every field
    /// the writer promises.
    fn read_back(zip: &[u8]) -> Vec<Read1> {
        let end = zip.len() - 22;
        assert_eq!(u32_at(zip, end), END_SIG);
        assert_eq!(u16_at(zip, end + 4), 0);
        assert_eq!(u16_at(zip, end + 6), 0);
        let count = usize::from(u16_at(zip, end + 8));
        assert_eq!(usize::from(u16_at(zip, end + 10)), count);
        let size = u32_at(zip, end + 12) as usize;
        let start = u32_at(zip, end + 16) as usize;
        assert_eq!(
            start + size,
            end,
            "the central directory ends at the end record"
        );
        assert_eq!(u16_at(zip, end + 20), 0, "no archive comment");
        let mut at = start;
        let mut out = Vec::new();
        for _ in 0..count {
            assert_eq!(u32_at(zip, at), CENTRAL_SIG);
            assert_eq!(u16_at(zip, at + 4), MADE_BY);
            assert_eq!(u16_at(zip, at + 8), FLAG_UTF8);
            let method = u16_at(zip, at + 10);
            assert_eq!(u16_at(zip, at + 12), 0, "DOS time");
            assert_eq!(u16_at(zip, at + 14), DOS_DATE, "DOS date");
            let crc = u32_at(zip, at + 16);
            let compressed = u32_at(zip, at + 20) as usize;
            let usize_ = u32_at(zip, at + 24) as usize;
            let name_len = usize::from(u16_at(zip, at + 28));
            assert_eq!(u16_at(zip, at + 30), 0, "no extra field");
            assert_eq!(u16_at(zip, at + 32), 0, "no comment");
            let external = u32_at(zip, at + 38);
            let local = u32_at(zip, at + 42) as usize;
            let name = String::from_utf8(zip[at + 46..at + 46 + name_len].to_vec()).unwrap();
            at += 46 + name_len;

            // The local header repeats the record.
            assert_eq!(u32_at(zip, local), LOCAL_SIG);
            assert_eq!(u16_at(zip, local + 6), FLAG_UTF8);
            assert_eq!(u16_at(zip, local + 8), method);
            assert_eq!(u32_at(zip, local + 14), crc);
            assert_eq!(u32_at(zip, local + 18) as usize, compressed);
            assert_eq!(u32_at(zip, local + 22) as usize, usize_);
            assert_eq!(usize::from(u16_at(zip, local + 26)), name_len);
            let body = local + 30 + name_len;
            let packed = &zip[body..body + compressed];
            let data = match method {
                0 => packed.to_vec(),
                8 => {
                    let mut v = Vec::new();
                    DeflateDecoder::new(packed).read_to_end(&mut v).unwrap();
                    v
                }
                m => panic!("method {m}"),
            };
            assert_eq!(data.len(), usize_);
            let mut check = Crc::new();
            check.update(&data);
            assert_eq!(check.sum(), crc, "{name}");
            out.push(Read1 {
                name,
                mode: external >> 16,
                method,
                data,
            });
        }
        assert_eq!(at, end);
        out
    }

    fn sample() -> Vec<u8> {
        let mut w = Writer::new(Vec::new());
        w.add("App.app", Kind::Dir).unwrap();
        w.add(
            "App.app/run",
            Kind::File {
                data: &b"#!/bin/sh\n".repeat(200),
                exec: true,
            },
        )
        .unwrap();
        w.add(
            "App.app/short",
            Kind::File {
                data: b"x",
                exec: false,
            },
        )
        .unwrap();
        w.add(
            "App.app/empty",
            Kind::File {
                data: b"",
                exec: false,
            },
        )
        .unwrap();
        w.add("App.app/link", Kind::Symlink { target: "run" })
            .unwrap();
        w.add(
            "App.app/\u{e9}t\u{e9}",
            Kind::File {
                data: b"utf-8 name",
                exec: false,
            },
        )
        .unwrap();
        w.finish().unwrap()
    }

    #[test]
    fn entries_read_back_with_their_modes_methods_and_bytes() {
        let zip = sample();
        let got = read_back(&zip);
        let names: Vec<&str> = got.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "App.app/",
                "App.app/run",
                "App.app/short",
                "App.app/empty",
                "App.app/link",
                "App.app/\u{e9}t\u{e9}"
            ]
        );
        assert_eq!(got[0].mode, 0o040_755);
        assert_eq!((got[1].mode, got[1].method), (0o100_755, 8));
        assert_eq!(got[1].data, b"#!/bin/sh\n".repeat(200));
        assert_eq!(
            (got[2].mode, got[2].method),
            (0o100_644, 0),
            "a byte that deflate cannot shrink is stored"
        );
        assert_eq!(
            (got[3].mode, got[3].method, got[3].data.len()),
            (0o100_644, 0, 0)
        );
        assert_eq!(
            (got[4].mode, got[4].data.as_slice()),
            (0o120_755, b"run".as_slice())
        );
        assert_eq!(got[5].data, b"utf-8 name");
    }

    #[test]
    fn the_same_entries_give_the_same_bytes() {
        assert_eq!(sample(), sample());
    }

    #[test]
    fn a_bad_name_is_refused() {
        for name in ["", "/abs", "dir/", "a\0b"] {
            let mut w = Writer::new(Vec::new());
            assert!(w.add(name, Kind::Dir).is_err(), "{name:?}");
        }
    }

    #[test]
    fn more_than_65535_entries_are_refused_and_exactly_65535_are_written() {
        let mut w = Writer::new(Vec::new());
        for i in 0..MAX_ENTRIES {
            w.add(&format!("d{i}"), Kind::Dir).unwrap();
        }
        let err = w.add("one-too-many", Kind::Dir).unwrap_err();
        assert!(format!("{err}").contains("65535"), "{err}");
        let zip = w.finish().unwrap();
        assert_eq!(read_back(&zip).len(), MAX_ENTRIES);
    }

    #[test]
    fn an_empty_archive_is_just_the_end_record() {
        let zip = Writer::new(Vec::new()).finish().unwrap();
        assert_eq!(zip.len(), 22);
        assert!(read_back(&zip).is_empty());
    }
}
