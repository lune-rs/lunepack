//! `WindowsIntegration` against a running launcher: a console copy at `R\<entry name>` kept running
//! by a child while `apply` replaces it (renamed aside, P-W1), then the GC helper removes the aside
//! copy once it has exited. The registry entries go under a scratch `HKCU\Software\lunepack-test-*`
//! prefix that is removed afterwards, checked with `reg.exe` (an instrument independent of the
//! adapter's own registry code).

#[cfg(windows)]
mod windows {
    use std::collections::BTreeMap;
    use std::io::Read as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use lunepack_core::{
        AppId, InstallMeta, IntegrationRequest, OsIntegration, RelPath, STUB_FILE, Scope, Version,
    };
    use lunepack_os_windows::{WinScope, WindowsIntegration, remove_stub_leftovers};
    use lunepack_testkit::{SuiteHooks, run_integration_suite_with};

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

    /// `reg.exe export` of `HKCU\<prefix>` as named lines, one per key that holds values (its
    /// value lines sorted): an instrument independent of the adapter's own registry code. A prefix
    /// that does not exist is an empty map.
    fn registry_state(prefix: &str) -> BTreeMap<String, String> {
        let out = std::env::temp_dir().join(format!("lp-export-{}.reg", tag()));
        let status = Command::new("reg.exe")
            .args(["export", &format!(r"HKCU\{prefix}")])
            .arg(&out)
            .arg("/y")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("reg.exe");
        if !status.success() {
            return BTreeMap::new();
        }
        let bytes = std::fs::read(&out).expect("export");
        let _ = std::fs::remove_file(&out);
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        let text = String::from_utf16_lossy(&units);
        let mut keys: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut current: Option<String> = None;
        for line in text.lines().map(|l| l.trim_start_matches('\u{feff}')) {
            if line.starts_with('[') {
                current = Some(line.to_owned());
            } else if let Some(key) = &current
                && !line.is_empty()
            {
                keys.entry(key.clone()).or_default().push(line.to_owned());
            }
        }
        keys.into_iter()
            .map(|(key, mut values)| {
                values.sort();
                (key, values.join("\n"))
            })
            .collect()
    }

    #[test]
    fn the_integration_suite_passes() {
        let t = tag();
        let cleanup = Cleanup {
            prefix: format!(r"Software\lunepack-test-{t}"),
            dir: std::env::temp_dir().join(format!("lp-suite-{t}")),
        };
        let sandbox = cleanup.dir.join("home");
        std::fs::create_dir_all(&sandbox).expect("sandbox");
        let prefix = cleanup.prefix.clone();

        // The instrument first: a key under the prefix must show up in the state, and must be
        // gone again before the suite starts.
        let probe = Command::new("reg.exe")
            .args([
                "add",
                &format!(r"HKCU\{prefix}\probe"),
                "/v",
                "x",
                "/d",
                "1",
                "/f",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("reg.exe");
        assert!(probe.success());
        assert_eq!(
            registry_state(&prefix).len(),
            1,
            "INVALID: the state dump misses a key"
        );
        let gone = Command::new("reg.exe")
            .args(["delete", &format!(r"HKCU\{prefix}"), "/f"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("reg.exe");
        assert!(gone.success());
        assert!(registry_state(&prefix).is_empty());

        let scope = WinScope::with_registry_prefix(&prefix)
            .expect("prefix")
            .with_start_menu(sandbox.join("Programs"));
        let w = WindowsIntegration::new(scope);

        // What the Windows adapter reads from the install tree: the version's stub.
        let stage = |req: &IntegrationRequest| {
            let tree = req
                .install_root
                .join("app")
                .join(req.version.to_string())
                .join("bin");
            std::fs::create_dir_all(&tree).expect("tree");
            std::fs::create_dir_all(req.install_root.join(".lunepack").join("state"))
                .expect("state");
            std::fs::write(tree.join(STUB_FILE), b"the suite's stub").expect("stub");
        };
        // The staged version tree is not state; a `.lnk` records its target's file times, so its
        // bytes differ whenever it is made again (its content is read back in the unit tests).
        // The Start-menu folder's shortcut names are state, listed by `state`.
        let ignore = |rel: &Path| {
            rel.components()
                .nth(1)
                .is_some_and(|c| c.as_os_str() == "app")
                || rel.extension().is_some_and(|e| e == "lnk")
        };
        let programs = sandbox.join("Programs");
        let state = || {
            let mut out = registry_state(&prefix);
            if let Ok(entries) = std::fs::read_dir(&programs) {
                for entry in entries {
                    let name = entry.expect("entry").file_name();
                    out.insert(
                        format!("shortcut {}", name.to_string_lossy()),
                        "present".to_owned(),
                    );
                }
            }
            out
        };
        let hooks = SuiteHooks {
            entry: "bin/app.exe",
            stage: Some(&stage),
            ignore: Some(&ignore),
            state: Some(&state),
            // The shortcut is named after the app; `bin`, categories, comment and mime types are
            // Linux's fields, which the Windows adapter never writes.
            rename_moves_entries: true,
            not_applicable: &[
                "a newline in the comment",
                "a semicolon in a category",
                "a newline in a category",
                "a slash in bin",
                "dot dot in bin",
                "a semicolon in a mime type",
                "a newline in a mime type",
            ],
        };
        run_integration_suite_with(&w, &sandbox, &hooks);

        drop(cleanup);
        assert!(
            registry_state(&prefix).is_empty(),
            "the test registry root is still there"
        );
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

        let scope = WinScope::with_registry_prefix(&cleanup.prefix)
            .expect("prefix")
            .with_start_menu(cleanup.dir.join("Programs"));
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
