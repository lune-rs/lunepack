//! The named pipe's descriptors and owners against the real system (M10 step 8), and the rule that
//! the crate calls no impersonation API.
//!
//! The `Elevation` rows create a pipe owned by Administrators, which needs an administrator's
//! token; a run without one asserts the typed refusal instead of skipping. The LocalSystem
//! read-back and a standard user's refusal are step 11's rows (they need the service account and
//! a second user).

use std::path::Path;

/// Every API through which a process can act as another account's token. The crate's sources
/// must name none of them.
const IMPERSONATION_APIS: &[&str] = &[
    "ImpersonateNamedPipeClient",
    "ImpersonateLoggedOnUser",
    "ImpersonateSelf",
    "ImpersonateAnonymousToken",
    "ImpersonateDdeClientWindow",
    "DdeImpersonateClient",
    "RpcImpersonateClient",
    "CoImpersonateClient",
    "SetThreadToken",
    "RevertToSelf",
    "NtImpersonateThread",
];

fn sources(dir: &Path, out: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).expect("read src") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("read a source file");
            out.push((path.display().to_string(), text));
        }
    }
}

#[test]
fn the_pipe_crate_calls_no_impersonation_api() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&src, &mut files);
    // The instrument finds what it looks for: the pipe module is among the files and names the
    // client's identification flag.
    assert!(
        files
            .iter()
            .any(|(p, t)| p.ends_with("pipe.rs") && t.contains("SECURITY_IDENTIFICATION")),
        "the scan sees src/pipe.rs"
    );
    for (path, text) in &files {
        for api in IMPERSONATION_APIS {
            assert!(!text.contains(api), "{path} names {api}");
        }
        assert!(
            !text.contains("Impersonate"),
            "{path} names an impersonation function"
        );
    }
}

#[cfg(windows)]
mod real {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use lunepack_core::Standing;
    use lunepack_core::service::Duplex;
    use lunepack_os_windows::{
        ACE_ALLOWED, Ace, Descriptor, ExpectedOwner, FILE_CREATE_PIPE_INSTANCE, PEER_MASK,
        PipeAccess, PipeClient, PipeError, PipeServer, SID_ADMINISTRATORS, SID_SYSTEM, SID_USERS,
        current_user_sid, pipe_descriptor, standing,
    };

    /// `FILE_ALL_ACCESS`, what `FA` in the descriptor text stands for.
    const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
    /// `WRITE_DAC` and `WRITE_OWNER`.
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;

    fn unique() -> String {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        format!(
            "lunepack-itest-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn allow(sid: &str, mask: u32) -> Ace {
        Ace {
            kind: ACE_ALLOWED,
            sid: sid.to_string(),
            mask,
            flags: 0,
        }
    }

    /// The DACL both shapes carry, with `peer` in the third entry.
    fn expected(owner: &str, peer: &str) -> Descriptor {
        Descriptor {
            owner: owner.to_string(),
            entries: Some(vec![
                allow(SID_SYSTEM, FILE_ALL_ACCESS),
                allow(SID_ADMINISTRATORS, FILE_ALL_ACCESS),
                allow(peer, PEER_MASK),
            ]),
        }
    }

    fn no_foreign_create_or_rewrite(d: &Descriptor) {
        for ace in d.entries.as_ref().expect("a DACL") {
            if ace.sid != SID_SYSTEM && ace.sid != SID_ADMINISTRATORS {
                assert_eq!(
                    ace.mask & (FILE_CREATE_PIPE_INSTANCE | WRITE_DAC | WRITE_OWNER),
                    0,
                    "{ace:?}"
                );
            }
        }
    }

    fn is_admin() -> bool {
        standing() != Standing::Standard
    }

    #[test]
    fn the_service_pipe_descriptor_built_in_memory_is_owned_by_local_system() {
        let d = pipe_descriptor(&PipeAccess::Service).expect("descriptor");
        assert_eq!(d, expected(SID_SYSTEM, SID_USERS));
        no_foreign_create_or_rewrite(&d);
    }

    #[test]
    fn an_elevation_pipe_is_owned_by_administrators_and_only_read_by_its_user() {
        let me = current_user_sid().expect("the current user's SID");
        let name = unique();
        let created = PipeServer::create(&name, &PipeAccess::Elevation { sid: me.clone() });
        if !is_admin() {
            assert_eq!(created.err(), Some(PipeError::OwnerNotAssignable));
            println!("not an administrator: asserted the typed refusal");
            return;
        }
        let mut server = created.expect("create the elevation pipe");
        let d = server.descriptor().expect("read back");
        assert_eq!(d, expected(SID_ADMINISTRATORS, &me));
        no_foreign_create_or_rewrite(&d);

        // Opening it for writing is refused: the pipe is outbound only.
        let path = format!(r"\\.\pipe\{name}");
        let refused = std::fs::OpenOptions::new().write(true).open(&path);
        assert!(refused.is_err(), "a writer was let in");
        if let Err(e) = &refused {
            println!("open for writing: {:?} ({e})", e.kind());
        }

        // The reader that expects Administrators connects and reads.
        let listener = std::thread::spawn(move || {
            server
                .accept(Some(Duration::from_secs(10)))
                .expect("accept");
            server.write_all(b"result").expect("write");
            server
        });
        let mut client = PipeClient::connect(
            &name,
            ExpectedOwner::Administrators,
            Duration::from_secs(10),
        )
        .expect("connect");
        let server = listener.join().expect("listener");
        client
            .set_read_deadline(Some(Duration::from_secs(5)))
            .unwrap();
        let mut got = [0u8; 6];
        client.read_exact(&mut got).expect("read");
        assert_eq!(&got, b"result");
        // The reader cannot write back.
        assert!(client.write(b"x").is_err(), "the reader wrote");
        // A dropped server leaves nothing more to read: the end of the channel.
        drop(server);
        let mut rest = [0u8; 1];
        assert_eq!(client.read(&mut rest).expect("read"), 0);
    }

    #[test]
    fn written_bytes_stay_readable_after_the_elevation_pipe_server_closes() {
        if !is_admin() {
            println!("not an administrator: covered by the refusal row");
            return;
        }
        let me = current_user_sid().expect("the current user's SID");
        let name = unique();
        let mut server =
            PipeServer::create(&name, &PipeAccess::Elevation { sid: me }).expect("create");
        let listener = std::thread::spawn(move || {
            server
                .accept(Some(Duration::from_secs(10)))
                .expect("accept");
            server.write_all(b"done").expect("write");
            drop(server);
        });
        let mut client = PipeClient::connect(
            &name,
            ExpectedOwner::Administrators,
            Duration::from_secs(10),
        )
        .expect("connect");
        listener.join().expect("listener");
        client
            .set_read_deadline(Some(Duration::from_secs(5)))
            .unwrap();
        let mut all = Vec::new();
        client.read_to_end(&mut all).expect("read");
        assert_eq!(all, b"done");
    }

    #[test]
    fn a_service_pipe_from_this_process_is_refused_or_owned_by_local_system() {
        let name = unique();
        match PipeServer::create(&name, &PipeAccess::Service) {
            Err(PipeError::OwnerNotAssignable) => {
                println!("service pipe: OwnerNotAssignable (this token cannot assign LocalSystem)");
            }
            Ok(server) => {
                let d = server.descriptor().expect("read back");
                assert_eq!(d, expected(SID_SYSTEM, SID_USERS));
                println!("service pipe: created, owner reads back as LocalSystem");
            }
            Err(other) => panic!("unexpected: {other:?}"),
        }
    }
}
