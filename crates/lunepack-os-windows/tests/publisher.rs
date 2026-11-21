//! `WinPublisherCheck` against real signed files (M9-D8, M9-R1-D2, M9-R1-D3).
//!
//! Throwaway code-signing certificates are created at test time in the current user's store, signed
//! with `signtool` (Windows SDK), and, where the session is elevated, trusted machine-wide for the
//! length of the test; every certificate is removed from every store when its guard drops, and
//! nothing is written to disk but the public certificate a trust import needs, in the temp
//! directory, removed straight after. Rows that need a missing tool or privilege are skipped with
//! their names printed, never silently (CI fails on a skip: `scripts/ci/windows-publisher-test.ps1`).
#![cfg(windows)]

use std::fs;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use lunepack_core::pe::PeHeaders;
use lunepack_core::{PublisherCheck, PublisherError, RelPath, SignedTree};
use lunepack_os_windows::WinPublisherCheck;
use lunepack_testkit::exe_headers::{PeSpec, pe_image};
use lunepack_testkit::{PublisherFixtures, PublisherSuite, run_publisher_suite};

fn pid() -> u32 {
    std::process::id()
}

fn powershell(script: &str) -> Option<String> {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn is_admin() -> bool {
    powershell(
        "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
    )
    .is_some_and(|t| t == "True")
}

fn find_signtool() -> Option<PathBuf> {
    let kits = PathBuf::from(std::env::var_os("ProgramFiles(x86)")?)
        .join("Windows Kits")
        .join("10")
        .join("bin");
    let mut found: Vec<PathBuf> = fs::read_dir(kits)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path().join("x64").join("signtool.exe"))
        .filter(|p| p.is_file())
        .collect();
    found.sort();
    found.pop()
}

/// A throwaway certificate; removed from every store on drop.
struct Cert {
    thumb: String,
}

impl Cert {
    /// A code-signing certificate of `subject`, valid from five minutes ago for `minutes` minutes.
    /// With `trust` (needs an elevated session) its self-signed root is trusted machine-wide.
    fn new(subject: &str, minutes: i64, trust: bool) -> Option<Cert> {
        let import = if trust {
            "$cer = Join-Path $env:TEMP ('lunepack-pub-' + [Guid]::NewGuid().ToString('N') + '.cer'); \
             Export-Certificate -Cert $c -FilePath $cer | Out-Null; \
             foreach ($s in 'Root','TrustedPublisher') { Import-Certificate -FilePath $cer -CertStoreLocation \"Cert:\\LocalMachine\\$s\" | Out-Null }; \
             Remove-Item $cer -Force; "
        } else {
            ""
        };
        let thumb = powershell(&format!(
            "$c = New-SelfSignedCertificate -Type CodeSigningCert -Subject '{subject}' \
             -CertStoreLocation Cert:\\CurrentUser\\My -NotBefore (Get-Date).AddMinutes(-5) \
             -NotAfter (Get-Date).AddMinutes({minutes}); {import}$c.Thumbprint"
        ))?;
        (thumb.len() == 40).then_some(Cert { thumb })
    }
}

impl Drop for Cert {
    fn drop(&mut self) {
        let t = &self.thumb;
        let _ = powershell(&format!(
            "foreach ($p in 'Cert:\\CurrentUser\\My','Cert:\\LocalMachine\\Root','Cert:\\LocalMachine\\TrustedPublisher') \
             {{ Remove-Item -Path \"$p\\{t}\" -Force -ErrorAction SilentlyContinue }}"
        ));
    }
}

struct Lab {
    signtool: PathBuf,
    scratch: PathBuf,
    next: std::cell::Cell<u32>,
}

impl Lab {
    fn new(tag: &str) -> Option<Lab> {
        let Some(signtool) = find_signtool() else {
            eprintln!("skipped: {tag}: no signtool.exe under Windows Kits\\10\\bin");
            return None;
        };
        let scratch = std::env::temp_dir().join(format!("lunepack-pubtest-{tag}-{}", pid()));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(&scratch).unwrap();
        Some(Lab {
            signtool,
            scratch,
            next: std::cell::Cell::new(0),
        })
    }

    /// A fresh tree directory.
    fn dir(&self, what: &str) -> PathBuf {
        self.next.set(self.next.get() + 1);
        let dir = self.scratch.join(format!("{}-{what}", self.next.get()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sign(&self, cert: &Cert, file: &Path) {
        let out = Command::new(&self.signtool)
            .args(["sign", "/fd", "sha256", "/sha1", &cert.thumb, "/s", "My"])
            .arg(file)
            .output()
            .expect("start signtool");
        assert!(
            out.status.success(),
            "signtool sign failed: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    /// A tree with `bin/app.exe` (the entry), signed by `cert` when given.
    fn tree(&self, what: &str, cert: Option<&Cert>, code_len: usize) -> SignedTree {
        let dir = self.dir(what);
        let exe = dir.join("bin").join("app.exe");
        fs::create_dir_all(exe.parent().unwrap()).unwrap();
        let mut spec = PeSpec::hardened(2);
        spec.code_len = code_len;
        fs::write(&exe, pe_image(0x8664, &spec)).unwrap();
        if let Some(cert) = cert {
            self.sign(cert, &exe);
        }
        SignedTree {
            root: dir,
            entry: RelPath::parse("bin/app.exe").unwrap(),
        }
    }

    /// Writes an extra PE whose `e_lfanew` lies past 64 KiB (unsigned, or signed by `cert`) at `rel`.
    fn add_far_pe(&self, tree: &SignedTree, rel: &str, cert: Option<&Cert>) {
        let path = tree.root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let image = with_far_headers(&pe_image(0x8664, &PeSpec::hardened(2)), 0x10000);
        let lfanew = u32::from_le_bytes(image[0x3C..0x40].try_into().unwrap());
        assert!(lfanew >= 0x10000, "the headers are past the 64 KiB head");
        fs::write(&path, image).unwrap();
        if let Some(cert) = cert {
            self.sign(cert, &path);
        }
    }

    /// Writes an extra PE (unsigned, or signed by `cert`) at `rel` in `tree`.
    fn add_pe(&self, tree: &SignedTree, rel: &str, cert: Option<&Cert>) {
        let path = tree.root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, pe_image(0x8664, &PeSpec::hardened(2))).unwrap();
        if let Some(cert) = cert {
            self.sign(cert, &path);
        }
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

/// `image` (a PE the core reader accepts) with its NT headers moved `delta` bytes up: `e_lfanew`,
/// `SizeOfHeaders` and every section's `PointerToRawData` grow by `delta` (a multiple of the file
/// alignment) and the gap is zeros. The result is the shape a linker writes for a large `/STUB`, and
/// a DLL the loader maps (checked on Windows 11 with a real linked DLL, `e_lfanew` 0x11870), but
/// whose signature a 64 KiB prefix of the file does not show.
fn with_far_headers(image: &[u8], delta: usize) -> Vec<u8> {
    assert_eq!(delta % 0x200, 0);
    let lfanew = u32::from_le_bytes(image[0x3C..0x40].try_into().unwrap()) as usize;
    let coff = lfanew + 4;
    let nsections = u16::from_le_bytes(image[coff + 2..coff + 4].try_into().unwrap()) as usize;
    let opt_size = u16::from_le_bytes(image[coff + 16..coff + 18].try_into().unwrap()) as usize;
    let opt = coff + 20;
    let table = opt + opt_size;
    let mut out = image[..lfanew].to_vec();
    out.resize(lfanew + delta, 0);
    out.extend_from_slice(&image[lfanew..]);
    let put = |out: &mut Vec<u8>, at: usize, add: usize| {
        let old = u32::from_le_bytes(out[at..at + 4].try_into().unwrap());
        out[at..at + 4].copy_from_slice(&(old + add as u32).to_le_bytes());
    };
    put(&mut out, 0x3C, delta);
    put(&mut out, opt + delta + 60, delta);
    for i in 0..nsections {
        let pointer = table + delta + 40 * i + 20;
        if u32::from_le_bytes(out[pointer..pointer + 4].try_into().unwrap()) != 0 {
            put(&mut out, pointer, delta);
        }
    }
    out
}

/// Flips one byte of the first section's raw data of the PE at `path`.
fn tamper(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let headers = PeHeaders::parse(&bytes[..bytes.len().min(65536)], bytes.len() as u64).unwrap();
    let at = headers.sections[0].raw_ptr as usize + 16;
    bytes[at] ^= 0x01;
    fs::write(path, bytes).unwrap();
}

struct Rows {
    skipped: Vec<&'static str>,
}

impl Rows {
    fn row(&mut self, name: &'static str, run: impl FnOnce()) {
        run();
        println!("row {name}: ok");
    }

    /// A row that may not be possible here: the closure says whether it ran.
    fn row_maybe(&mut self, name: &'static str, run: impl FnOnce() -> bool) {
        if run() {
            println!("row {name}: ok");
        } else {
            self.skipped.push(name);
        }
    }
}

fn ask(installed: &SignedTree, candidate: &SignedTree) -> Result<bool, PublisherError> {
    WinPublisherCheck.same_publisher(installed, candidate)
}

/// The fixtures of the contract suite: identity `a` and `b` are two certificates of two subjects.
struct WinFixtures<'a> {
    lab: &'a Lab,
    a: &'a Cert,
    b: &'a Cert,
}

impl PublisherFixtures for WinFixtures<'_> {
    fn signed(&self, dir: &Path, publisher: &str) -> Option<SignedTree> {
        let cert = if publisher == "a" { self.a } else { self.b };
        Some(self.build(dir, Some(cert)))
    }

    fn unsigned(&self, dir: &Path) -> Option<SignedTree> {
        Some(self.build(dir, None))
    }

    fn tampered(&self, dir: &Path) -> Option<SignedTree> {
        let tree = self.build(dir, Some(self.a));
        tamper(&tree.root.join("bin").join("app.exe"));
        Some(tree)
    }
}

impl WinFixtures<'_> {
    fn build(&self, dir: &Path, cert: Option<&Cert>) -> SignedTree {
        let exe = dir.join("bin").join("app.exe");
        fs::create_dir_all(exe.parent().unwrap()).unwrap();
        fs::write(&exe, pe_image(0x8664, &PeSpec::hardened(2))).unwrap();
        if let Some(cert) = cert {
            self.lab.sign(cert, &exe);
        }
        SignedTree {
            root: dir.to_path_buf(),
            entry: RelPath::parse("bin/app.exe").unwrap(),
        }
    }
}

#[test]
fn real_signed_files_give_the_closed_outcomes() {
    let Some(lab) = Lab::new("rows") else {
        return;
    };
    let mut rows = Rows {
        skipped: Vec::new(),
    };
    let subject_a = format!("CN=lunepack-publisher-test-a-{}", pid());
    let subject_b = format!("CN=lunepack-publisher-test-b-{}", pid());

    // Rows that need no trusted root.
    let cert_u = Cert::new(
        &format!("CN=lunepack-publisher-test-u-{}", pid()),
        60,
        false,
    )
    .expect("a certificate");
    rows.row("a file that cannot be opened is a local fault", || {
        let installed = lab.tree("i", None, 0x400);
        let candidate = lab.tree("c", None, 0x400);
        // Held open with no sharing: nothing can verify or read it.
        let _hold = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(candidate.root.join("bin").join("app.exe"))
            .unwrap();
        let result = ask(&installed, &candidate);
        // The installed tree is unsigned, so that is the first finding; the candidate is the one
        // held, so make the installed side readable by asking about the candidate as installed.
        assert_eq!(result, Err(PublisherError::InstalledUnsigned));
        assert_eq!(ask(&candidate, &installed), Err(PublisherError::Os));
    });

    if !is_admin() {
        eprintln!(
            "skipped: rows needing a trusted test root (the session is not elevated): \
             renewal, different subject, unsigned candidate, unsigned DLL, far-header DLL, tampered, unsigned installed, \
             untrusted root, held open, reparse point, renamed DLL, suite"
        );
        return;
    }
    let cert_a1 = Cert::new(&subject_a, 60, true).expect("cert a1");
    let cert_a2 = Cert::new(&subject_a, 60, true).expect("cert a2");
    let cert_b = Cert::new(&subject_b, 60, true).expect("cert b");

    rows.row(
        "a renewed certificate of the same subject is the same publisher",
        || {
            let (i, c) = (
                lab.tree("i", Some(&cert_a1), 0x400),
                lab.tree("c", Some(&cert_a2), 0x600),
            );
            assert_eq!(ask(&i, &c), Ok(true));
        },
    );
    rows.row("another subject is another publisher", || {
        let (i, c) = (
            lab.tree("i", Some(&cert_a1), 0x400),
            lab.tree("c", Some(&cert_b), 0x400),
        );
        assert_eq!(ask(&i, &c), Ok(false));
    });
    rows.row("an unsigned candidate entry", || {
        let (i, c) = (
            lab.tree("i", Some(&cert_a1), 0x400),
            lab.tree("c", None, 0x400),
        );
        assert_eq!(ask(&i, &c), Err(PublisherError::CandidateUnsigned));
    });
    rows.row("an unsigned DLL beside a correctly signed entry", || {
        let (i, c) = (
            lab.tree("i", Some(&cert_a1), 0x400),
            lab.tree("c", Some(&cert_a2), 0x400),
        );
        lab.add_pe(&c, "bin/helper.dll", None);
        assert_eq!(ask(&i, &c), Err(PublisherError::CandidateUnsigned));
        // The same DLL signed by any trusted publisher passes (M9-D8).
        let c2 = lab.tree("c2", Some(&cert_a2), 0x400);
        lab.add_pe(&c2, "bin/helper.dll", Some(&cert_b));
        assert_eq!(ask(&i, &c2), Ok(true));
    });
    rows.row(
        "a renamed unsigned PE is still a PE; a text file is not",
        || {
            let (i, c) = (
                lab.tree("i", Some(&cert_a1), 0x400),
                lab.tree("c", Some(&cert_a2), 0x400),
            );
            fs::write(c.root.join("readme.txt"), b"plain text").unwrap();
            assert_eq!(ask(&i, &c), Ok(true), "a non-PE file is not checked");
            lab.add_pe(&c, "data/library.dat", None);
            assert_eq!(ask(&i, &c), Err(PublisherError::CandidateUnsigned));
        },
    );
    // S1: the loader maps an image whose `e_lfanew` lies far past the first 64 KiB, so an unsigned
    // one is as dangerous as any other DLL, whatever a bounded prefix of the file shows.
    rows.row(
        "an unsigned DLL whose e_lfanew is past 64 KiB beside a correctly signed entry",
        || {
            let (i, c) = (
                lab.tree("i", Some(&cert_a1), 0x400),
                lab.tree("c", Some(&cert_a2), 0x400),
            );
            lab.add_far_pe(&c, "bin/far.dll", None);
            assert_eq!(ask(&i, &c), Err(PublisherError::CandidateUnsigned));
            // Signed by any trusted publisher it passes, and a far file with no `PE\0\0` where
            // `e_lfanew` points is not a PE at all.
            let c2 = lab.tree("c2", Some(&cert_a2), 0x400);
            lab.add_far_pe(&c2, "bin/far.dll", Some(&cert_b));
            assert_eq!(ask(&i, &c2), Ok(true));
            let c3 = lab.tree("c3", Some(&cert_a2), 0x400);
            let mut text = vec![0u8; 0x30000];
            text[..2].copy_from_slice(b"MZ");
            text[0x3C..0x40].copy_from_slice(&0x10000u32.to_le_bytes());
            fs::write(c3.root.join("bin").join("far.dat"), text).unwrap();
            assert_eq!(ask(&i, &c3), Ok(true));
        },
    );
    rows.row("one byte flipped in a signed candidate", || {
        let (i, c) = (
            lab.tree("i", Some(&cert_a1), 0x400),
            lab.tree("c", Some(&cert_a2), 0x400),
        );
        tamper(&c.root.join("bin").join("app.exe"));
        assert_eq!(ask(&i, &c), Err(PublisherError::CandidateInvalid));
        // And the same damage to the installed tree is a local fault that marks nothing.
        assert_eq!(ask(&c, &i), Err(PublisherError::InstalledInvalid));
    });
    rows.row("an unsigned installed tree has no baseline", || {
        let (i, c) = (
            lab.tree("i", None, 0x400),
            lab.tree("c", Some(&cert_a2), 0x400),
        );
        assert_eq!(ask(&i, &c), Err(PublisherError::InstalledUnsigned));
    });
    rows.row("a candidate signed by an untrusted root", || {
        let (i, c) = (
            lab.tree("i", Some(&cert_a1), 0x400),
            lab.tree("c", Some(&cert_u), 0x400),
        );
        assert_eq!(ask(&i, &c), Err(PublisherError::CandidateInvalid));
        assert_eq!(ask(&c, &i), Err(PublisherError::InstalledInvalid));
    });
    rows.row(
        "a candidate file held open with no sharing is a local fault",
        || {
            let (i, c) = (
                lab.tree("i", Some(&cert_a1), 0x400),
                lab.tree("c", Some(&cert_a2), 0x400),
            );
            lab.add_pe(&c, "bin/helper.dll", Some(&cert_a2));
            {
                let _hold = fs::OpenOptions::new()
                    .read(true)
                    .share_mode(0)
                    .open(c.root.join("bin").join("helper.dll"))
                    .unwrap();
                assert_eq!(ask(&i, &c), Err(PublisherError::Os));
            }
            let entry_hold = fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(c.root.join("bin").join("app.exe"))
                .unwrap();
            assert_eq!(ask(&i, &c), Err(PublisherError::Os));
            drop(entry_hold);
            // Once released the same question has its real answer: nothing was remembered.
            assert_eq!(ask(&i, &c), Ok(true));
        },
    );
    rows.row_maybe(
        "a reparse point in the candidate tree is a local fault",
        || {
            let (i, c) = (
                lab.tree("i", Some(&cert_a1), 0x400),
                lab.tree("c", Some(&cert_a2), 0x400),
            );
            let link = c.root.join("link.dll");
            match std::os::windows::fs::symlink_file(c.root.join("bin").join("app.exe"), &link) {
                Ok(()) => {
                    assert_eq!(ask(&i, &c), Err(PublisherError::Os));
                    true
                }
                Err(e) => {
                    eprintln!("skipped: reparse point row: cannot create a symlink ({e})");
                    false
                }
            }
        },
    );
    rows.row("a missing entry is a local fault", || {
        let (i, c) = (
            lab.tree("i", Some(&cert_a1), 0x400),
            lab.tree("c", Some(&cert_a2), 0x400),
        );
        fs::remove_file(c.root.join("bin").join("app.exe")).unwrap();
        assert_eq!(ask(&i, &c), Err(PublisherError::Os));
    });
    rows.row("the contract suite", || {
        let dir = lab.dir("suite");
        run_publisher_suite(
            &WinPublisherCheck,
            PublisherSuite::Signed(&WinFixtures {
                lab: &lab,
                a: &cert_a1,
                b: &cert_b,
            }),
            &dir,
        );
    });
    assert!(rows.skipped.is_empty(), "skipped rows: {:?}", rows.skipped);
}

/// M9-R1-D3: an installed entry signed without a timestamp, by a certificate that has since
/// expired, is not a permanent block: its subject is still the baseline, or, when Windows hands
/// out no provider data in that state, there is no baseline. Never `InstalledInvalid`. An expired
/// candidate is invalid. Waits past the certificate's end (about two minutes).
#[test]
fn an_expired_installed_signature_is_never_a_permanent_block() {
    let Some(lab) = Lab::new("expired") else {
        return;
    };
    if !is_admin() {
        eprintln!("skipped: expired-installed row (the session is not elevated)");
        return;
    }
    let subject = format!("CN=lunepack-publisher-test-e-{}", pid());
    // Valid for two minutes from now (five already behind it); signed at once, no timestamp.
    let Some(short) = Cert::new(&subject, 2, true) else {
        panic!("cannot create the short-lived certificate");
    };
    let renewed = Cert::new(&subject, 60, true).expect("the renewed certificate");
    let installed = lab.tree("installed", Some(&short), 0x400);
    let candidate = lab.tree("candidate", Some(&renewed), 0x400);
    let expired_candidate = lab.tree("expired-candidate", Some(&short), 0x400);
    assert_eq!(
        ask(&installed, &candidate),
        Ok(true),
        "before it expires the pair is the same publisher"
    );

    let waited = Instant::now();
    while waited.elapsed() < Duration::from_secs(135) {
        std::thread::sleep(Duration::from_secs(5));
    }
    let result = ask(&installed, &candidate);
    match result {
        Ok(true) => println!("expired installed signature: baseline taken from its subject"),
        Err(PublisherError::InstalledUnsigned) => {
            println!("expired installed signature: no provider data, no baseline")
        }
        other => panic!("an expired installed signature gave {other:?}"),
    }
    // The same expired signature on the candidate side is a packaging mistake.
    assert_eq!(
        ask(&candidate, &expired_candidate),
        Err(PublisherError::CandidateInvalid)
    );
}
