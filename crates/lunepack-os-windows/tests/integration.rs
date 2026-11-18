//! `WindowsIntegration` against a running launcher: a console copy at `R\<entry name>` kept running
//! by a child while `apply` replaces it (renamed aside, P-W1), then the GC helper removes the aside
//! copy once it has exited. The registry entries go under a scratch `HKCU\Software\lunepack-test-*`
//! prefix that is removed afterwards, checked with `reg.exe` (an instrument independent of the
//! adapter's own registry code).

#[cfg(windows)]
mod windows {
    use std::io::Read as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use lunepack_core::{
        AppId, InstallMeta, IntegrationRequest, OsIntegration, RelPath, STUB_FILE, Scope, Version,
    };
    use lunepack_os_windows::{WinScope, WindowsIntegration, remove_stub_leftovers};

    /// The helper mode's switch: the copy of this test binary runs only the helper test.
    const HELPER_ENV: &str = "LUNEPACK_TEST_STUB_HELPER";

    /// Not a test: the running "stub". Reads stdin until the parent closes it, then exits.
    #[test]
    #[ignore = "helper process for running_stub_is_renamed_aside_and_collected_later"]
    fn helper_wait_for_stdin_eof() {
        if std::env::var_os(HELPER_ENV).is_none() {
            return;
        }
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
    }

    fn tag() -> String {
        use std::hash::{BuildHasher as _, Hasher as _};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u32(std::process::id());
        format!("{:016x}", h.finish())
    }

    fn reg_exists(key: &str) -> bool {
        Command::new("reg.exe")
            .args(["query", key])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("reg.exe")
            .success()
    }

    struct Cleanup {
        prefix: String,
        dir: PathBuf,
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = Command::new("reg.exe")
                .args(["delete", &format!(r"HKCU\{}", self.prefix), "/f"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(dir)
            .expect("list")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        out.sort();
        out
    }

    #[test]
    fn running_stub_is_renamed_aside_and_collected_later() {
        let t = tag();
        let cleanup = Cleanup {
            prefix: format!(r"Software\lunepack-test-{t}"),
            dir: std::env::temp_dir().join(format!("lp-run-{t}")),
        };
        let root = cleanup.dir.join("Running App");
        let tree = root.join("app").join("2.0.0").join("bin");
        std::fs::create_dir_all(&tree).expect("tree");
        std::fs::create_dir_all(root.join(".lunepack").join("state")).expect("state");
        let new_bytes = b"the new stub".to_vec();
        std::fs::write(tree.join(STUB_FILE), &new_bytes).expect("new stub");

        // The old stub: a copy of this test binary, running.
        let dst = root.join("app.exe");
        let me = std::env::current_exe().expect("current exe");
        std::fs::copy(&me, &dst).expect("copy");
        let mut child = Command::new(&dst)
            .args(["--ignored", "--exact", "windows::helper_wait_for_stdin_eof"])
            .env(HELPER_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start the running stub");
        // The image is mapped once the process has started; give it a moment.
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(
            child.try_wait().expect("poll").is_none(),
            "the helper ended early"
        );
        assert!(
            std::fs::remove_file(&dst).is_err(),
            "INVALID: a running image could be deleted, so the test proves nothing"
        );

        let scope = WinScope::with_registry_prefix(&cleanup.prefix).expect("prefix");
        let w = WindowsIntegration::new(scope);
        let req = IntegrationRequest {
            app_id: AppId::parse("test.running").expect("id"),
            install_root: root.clone(),
            version: Version::parse("2.0.0").expect("version"),
            meta: InstallMeta {
                entry: RelPath::parse("bin/app.exe").expect("entry"),
                name: "Running App".to_owned(),
                comment: None,
                icon: None,
                categories: Vec::new(),
                bin: None,
                terminal: false,
                publisher: None,
                file_types: Vec::new(),
                url_schemes: Vec::new(),
                autostart: false,
            },
            previous: None,
            stale_bins: Vec::new(),
        };
        let report = w
            .apply(Scope::User, &req)
            .expect("apply over a running stub");
        assert!(report.kept.is_empty());
        assert_eq!(std::fs::read(&dst).expect("dst"), new_bytes);
        let aside: Vec<String> = names(&root)
            .into_iter()
            .filter(|n| n.starts_with(".app.exe.old-"))
            .collect();
        assert_eq!(aside.len(), 1, "{:?}", names(&root));

        // Still running: the GC keeps it.
        assert_eq!(remove_stub_leftovers(&root).expect("gc"), 0);
        assert!(root.join(&aside[0]).is_file());

        drop(child.stdin.take());
        let status = child.wait().expect("wait");
        assert!(status.success(), "{status:?}");
        // The image can stay mapped for a moment after exit.
        let mut removed = 0;
        for _ in 0..50 {
            removed += remove_stub_leftovers(&root).expect("gc");
            if removed == 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(removed, 1);
        assert_eq!(names(&root), [".lunepack", "app", "app.exe"]);

        let key = format!(r"HKCU\{}", cleanup.prefix);
        assert!(
            reg_exists(&key),
            "INVALID: reg.exe does not see the test key"
        );
        w.remove(Scope::User, &req).expect("remove");
        drop(cleanup);
        assert!(!reg_exists(&key), "the test registry root is still there");
    }
}
