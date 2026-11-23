//! The per-machine pieces of the Windows adapter against the real system (M10 step 10): the
//! all-users scope of `WindowsIntegration` (under a registry prefix and a temporary Start-menu
//! folder, and, as an administrator who opts in, the real `HKLM`), the policy reader, the
//! elevation hand-off for a process that cannot be prompted, and what a rename of a folder does
//! and does not tell about a program using it (a record of measured behaviour; M10-D20).
//!
//! Registry state is read with `reg.exe`, an instrument independent of the adapter's own registry
//! code. The rows that write the real `HKLM` need an administrator and say so when they do not
//! run: set `LUNEPACK_TEST_HKLM=1`.

#[cfg(windows)]
mod windows {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use lunepack_core::{
        AppId, Elevated, Elevation, ElevationError, FileType, InstallMeta, IntegrationError,
        IntegrationRequest, MachinePolicy, OsIntegration, PolicySource, RelPath, STUB_FILE, Scope,
        Standing, Version,
    };
    use lunepack_os_windows::{
        RegistryPolicy, WinScope, WindowsElevation, WindowsIntegration, standing,
    };

    fn tag() -> String {
        use std::hash::{BuildHasher as _, Hasher as _};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u32(std::process::id());
        format!("{:016x}", h.finish())
    }

    fn reg(args: &[&str]) -> (bool, String) {
        let out = Command::new("reg.exe")
            .args(args)
            .output()
            .expect("reg.exe");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }

    fn reg_exists(key: &str) -> bool {
        reg(&["query", key]).0
    }

    fn reg_value(key: &str, name: &str) -> Option<String> {
        let (ok, out) = reg(&["query", key, "/v", name]);
        ok.then_some(out)
    }

    fn reg_delete(key: &str) {
        let _ = reg(&["delete", key, "/f"]);
    }

    struct Cleanup {
        keys: Vec<String>,
        dir: PathBuf,
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            for key in &self.keys {
                reg_delete(key);
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn request(root: &Path, id: &str, ext: &str) -> IntegrationRequest {
        IntegrationRequest {
            app_id: AppId::parse(id).expect("id"),
            install_root: root.to_path_buf(),
            version: Version::parse("1.0.0").expect("version"),
            meta: InstallMeta {
                entry: RelPath::parse("bin/app.exe").expect("entry"),
                name: "Machine Test App".to_owned(),
                comment: None,
                icon: None,
                categories: Vec::new(),
                bin: None,
                terminal: false,
                publisher: Some("Test Publisher".to_owned()),
                file_types: vec![FileType {
                    ext: ext.to_owned(),
                    name: "Machine Test File".to_owned(),
                    mime: "application/x-lunepack-test".to_owned(),
                }],
                url_schemes: Vec::new(),
                autostart: true,
            },
            previous: None,
            stale_bins: Vec::new(),
        }
    }

    /// The tree the adapter reads: the version's stub and the state folder.
    fn stage(root: &Path) {
        let tree = root.join("app").join("1.0.0").join("bin");
        std::fs::create_dir_all(&tree).expect("tree");
        std::fs::create_dir_all(root.join(".lunepack").join("state")).expect("state");
        std::fs::write(tree.join(STUB_FILE), b"the test stub").expect("stub");
    }

    const UNINSTALL: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
    const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

    #[test]
    fn machine_scope_writes_its_own_tree_and_never_the_users() {
        let t = tag();
        let prefix = format!(r"Software\lunepack-test-m-{t}");
        let cleanup = Cleanup {
            keys: vec![format!(r"HKCU\{prefix}")],
            dir: std::env::temp_dir().join(format!("lp-m-{t}")),
        };
        let root = cleanup.dir.join("Machine App");
        let programs = cleanup.dir.join("CommonPrograms");
        stage(&root);
        let id = "test.machine";
        let req = request(&root, id, "lpmt");

        let user = WinScope::with_registry_prefix(&prefix)
            .expect("prefix")
            .with_start_menu(cleanup.dir.join("UserPrograms"));
        let machine = WinScope::machine_with_registry_prefix(&prefix)
            .expect("prefix")
            .with_start_menu(programs.clone());
        let w = WindowsIntegration::new(user)
            .with_machine(machine)
            .expect("a machine scope");

        w.check(Scope::Machine, &req).expect("check");
        let report = w.apply(Scope::Machine, &req).expect("apply");
        assert!(report.kept.is_empty(), "{report:?}");

        // The machine tree has the entry, the Run value, the class and the shortcut; the user
        // tree has nothing.
        let machine_root = format!(r"HKCU\{prefix}\Machine");
        let entry = format!(r"{machine_root}\{UNINSTALL}\{id}");
        assert!(reg_exists(&entry), "the uninstall entry");
        assert!(
            reg_value(&entry, "LunepackAppId")
                .expect("marker")
                .contains(id),
            "the marker names the app"
        );
        assert!(reg_value(&entry, "DisplayName").is_some());
        assert!(
            reg_value(&format!(r"{machine_root}\{RUN}"), id).is_some()
                || reg_exists(&format!(r"{machine_root}\{RUN}")),
            "the autostart value"
        );
        assert!(
            reg_exists(&format!(r"{machine_root}\Software\Classes\.lpmt")),
            "the file type"
        );
        assert!(
            programs.join("Machine Test App.lnk").exists(),
            "the shortcut is in the all-users folder"
        );
        assert!(
            !cleanup.dir.join("UserPrograms").exists(),
            "no user shortcut"
        );
        assert!(
            !reg_exists(&format!(r"HKCU\{prefix}\{UNINSTALL}")),
            "nothing in the user's uninstall tree"
        );
        assert!(
            !reg_exists(&format!(r"HKCU\{prefix}\Software\Classes")),
            "nothing in the user's classes"
        );
        assert!(root.join("app.exe").exists(), "the stub is at the root");

        // A second apply changes nothing it should not, and the conflict rules hold: a foreign
        // key at the entry's place is a conflict.
        w.apply(Scope::Machine, &req).expect("apply again");
        let report = w.remove(Scope::Machine, &req).expect("remove");
        assert!(report.kept.is_empty(), "{report:?}");
        assert!(!reg_exists(&entry), "the entry is gone");
        assert!(!programs.join("Machine Test App.lnk").exists());
        assert!(!reg_exists(&format!(
            r"{machine_root}\Software\Classes\.lpmt"
        )));
        w.remove(Scope::Machine, &req).expect("remove again");

        // A foreign key where our entry would go is a conflict, and is left.
        let (ok, _) = reg(&["add", &entry, "/v", "Other", "/d", "x", "/f"]);
        assert!(ok);
        assert!(matches!(
            w.apply(Scope::Machine, &req),
            Err(IntegrationError::Conflict(_))
        ));
        assert!(reg_exists(&entry), "the foreign key is untouched");
        drop(cleanup);
    }

    #[test]
    fn the_scopes_are_not_interchangeable() {
        let user = WinScope::with_registry_prefix(r"Software\lunepack-test-never-written")
            .expect("prefix");
        let machine =
            WinScope::machine_with_registry_prefix(r"Software\lunepack-test-never-written")
                .expect("prefix");
        // A per-user scope is no machine scope.
        assert!(
            WindowsIntegration::new(user.clone())
                .with_machine(user.clone())
                .is_none()
        );
        // A machine scope is no user scope: `Scope::User` is `Unsupported` on it.
        let root = std::env::temp_dir().join("lp-m-never-used");
        let req = request(&root, "test.never", "lpmx");
        let w = WindowsIntegration::new(machine.clone());
        assert!(matches!(
            w.apply(Scope::User, &req),
            Err(IntegrationError::Unsupported)
        ));
        // No machine scope was added: `Scope::Machine` is `Unsupported`, as before M10.
        let w = WindowsIntegration::new(user);
        for result in [
            w.check(Scope::Machine, &req),
            w.apply(Scope::Machine, &req).map(|_| ()),
            w.remove(Scope::Machine, &req).map(|_| ()),
        ] {
            assert!(matches!(result, Err(IntegrationError::Unsupported)));
        }
        assert!(!reg_exists(r"HKCU\Software\lunepack-test-never-written"));
        assert!(WinScope::machine_with_registry_prefix("").is_none());
        assert!(WinScope::machine_with_registry_prefix(r"a\\b").is_none());
    }

    fn hklm_opt_in() -> bool {
        if std::env::var("LUNEPACK_TEST_HKLM").as_deref() == Ok("1") {
            return true;
        }
        println!("  skipped: set LUNEPACK_TEST_HKLM=1 as an administrator to write the real HKLM");
        false
    }

    #[test]
    fn real_hklm_round_trip_leaves_the_users_hive_alone() {
        if !hklm_opt_in() {
            return;
        }
        assert!(
            matches!(standing(), Standing::Admin | Standing::UacElevated),
            "this row needs an administrator, got {:?}",
            standing()
        );
        let t = tag();
        let id = format!("lunepack-test-hklm-{}", std::process::id());
        let ext = format!("lpm{}", std::process::id());
        let entry = format!(r"HKLM\{UNINSTALL}\{id}");
        let cleanup = Cleanup {
            keys: vec![
                entry.clone(),
                format!(r"HKLM\Software\Classes\.{ext}"),
                format!(r"HKLM\Software\Classes\{id}.{ext}"),
            ],
            dir: std::env::temp_dir().join(format!("lp-hklm-{t}")),
        };
        assert!(!reg_exists(&entry), "the test entry is new");
        let root = cleanup.dir.join("Hklm App");
        let programs = cleanup.dir.join("CommonPrograms");
        stage(&root);
        let req = request(&root, &id, &ext);
        let user_entry = format!(r"HKCU\{UNINSTALL}\{id}");
        let w = WindowsIntegration::current_user()
            .with_machine(WinScope::machine().with_start_menu(programs.clone()))
            .expect("machine scope");
        w.apply(Scope::Machine, &req).expect("apply to HKLM");
        assert!(reg_exists(&entry), "the HKLM uninstall entry");
        assert!(
            reg_value(&format!(r"HKLM\{RUN}"), &id).is_some(),
            "the HKLM Run value"
        );
        assert!(
            reg_exists(&format!(r"HKLM\Software\Classes\.{ext}")),
            "the HKLM class"
        );
        assert!(!reg_exists(&user_entry), "nothing in HKCU uninstall");
        assert!(
            reg_value(&format!(r"HKCU\{RUN}"), &id).is_none(),
            "nothing in HKCU Run"
        );
        assert!(
            !reg_exists(&format!(r"HKCU\Software\Classes\.{ext}")),
            "nothing in HKCU classes"
        );
        assert!(programs.join("Machine Test App.lnk").exists());
        w.remove(Scope::Machine, &req).expect("remove from HKLM");
        assert!(!reg_exists(&entry));
        assert!(reg_value(&format!(r"HKLM\{RUN}"), &id).is_none());
        assert!(!reg_exists(&format!(r"HKLM\Software\Classes\.{ext}")));
        drop(cleanup);
    }

    #[test]
    fn real_hklm_policy_is_read_as_the_standing_says() {
        if !hklm_opt_in() {
            return;
        }
        assert!(
            matches!(standing(), Standing::Admin | Standing::UacElevated),
            "this row needs an administrator, got {:?}",
            standing()
        );
        let parent = r"HKLM\SOFTWARE\Policies\lunepack";
        let made_parent = !reg_exists(parent);
        let id = format!("lunepack-test-pol-{}", std::process::id());
        let leaf = format!(r"{parent}\{id}");
        let _cleanup = Cleanup {
            keys: if made_parent {
                vec![parent.to_owned()]
            } else {
                vec![leaf.clone()]
            },
            dir: std::env::temp_dir().join("lp-pol-unused"),
        };
        let app = AppId::parse(&id).expect("id");
        let policy = RegistryPolicy::new();
        assert_eq!(policy.read(&app), MachinePolicy::default(), "no key: off");
        assert!(
            reg(&[
                "add",
                &leaf,
                "/v",
                "DisableSelfUpdate",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f"
            ])
            .0
        );
        let read = policy.read(&app);
        assert!(read.self_update_disabled && !read.no_update_ui, "{read:?}");
        assert!(
            reg(&[
                "add",
                &leaf,
                "/v",
                "NoUpdateUi",
                "/t",
                "REG_SZ",
                "/d",
                "0",
                "/f"
            ])
            .0
        );
        let read = policy.read(&app);
        assert!(read.self_update_disabled && read.no_update_ui, "{read:?}");
    }

    #[test]
    fn elevation_hands_off_without_a_prompt_when_the_process_is_already_elevated() {
        let e = WindowsElevation;
        let who = e.standing();
        println!("  standing: {who:?}");
        assert_eq!(who, standing());
        if who == Standing::Standard {
            println!("  skipped: a standard user's runas would prompt");
            return;
        }
        // An administrator's full token starts the child without a prompt; the window is hidden.
        let cmd = Path::new(r"C:\Windows\System32\cmd.exe");
        let Elevated::Started(mut child) = e
            .run_elevated(cmd, &["/c".to_owned(), "exit 9".to_owned()])
            .expect("start")
        else {
            panic!("an elevated process was declined");
        };
        assert_eq!(child.wait(), Ok(9));
        // A missing program is an error, never `Declined`.
        let missing = Path::new(r"C:\Windows\System32\lunepack-no-such-program.exe");
        assert!(matches!(
            e.run_elevated(missing, &[]),
            Err(ElevationError::Failed(_))
        ));
    }

    /// What a folder rename does and does not tell on Windows, measured: it is not an in-use
    /// guard. A folder CAN be renamed while a program runs from an exe inside it (the running
    /// image itself cannot be deleted); it CANNOT be renamed while a child's working directory
    /// is inside it or while a file inside is held without delete sharing. This test exists
    /// because the engine's first design leaned on the rename as the check before a deletion
    /// (assumption A2, which was false); the removal guard is `tree_in_use_strict` (Revision 2,
    /// M10-D20), and this test keeps the premise visible so nobody leans on the rename again.
    #[test]
    fn a_folder_can_be_renamed_while_a_program_runs_from_it() {
        let t = tag();
        let base = std::env::temp_dir().join(format!("lp-a2-{t}"));
        let cleanup = Cleanup {
            keys: Vec::new(),
            dir: base.clone(),
        };
        let from = base.join("tree");
        let to = base.join("tree-renamed");
        std::fs::create_dir_all(&from).expect("tree");
        let exe = from.join("cmd.exe");
        std::fs::copy(r"C:\Windows\System32\cmd.exe", &exe).expect("copy a system executable");

        // 1. A program runs from an exe inside the folder: the folder renames, there and back;
        //    the running image cannot be deleted.
        let mut child = Command::new(&exe)
            .arg("/q")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start the copy");
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            child.try_wait().expect("poll").is_none(),
            "INVALID: the program ended early, so the test proves nothing"
        );
        assert!(
            std::fs::remove_file(&exe).is_err(),
            "INVALID: a running image could be deleted"
        );
        std::fs::rename(&from, &to).expect("renamed while a program runs from an exe inside");
        assert!(to.join("cmd.exe").exists() && !from.exists());
        std::fs::rename(&to, &from).expect("renamed back while it still runs");
        assert!(
            std::fs::remove_file(&exe).is_err(),
            "the running image still cannot be deleted after the renames"
        );
        drop(child.stdin.take());
        let _ = child.kill();
        let _ = child.wait();
        rename_eventually(&from, &to);
        rename_eventually(&to, &from);

        // 2. A child's working directory inside the folder: the rename fails; undone after.
        let mut child = Command::new(r"C:\Windows\System32\cmd.exe")
            .arg("/q")
            .current_dir(&from)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start a program in the folder");
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            child.try_wait().expect("poll").is_none(),
            "INVALID: the program ended early, so the test proves nothing"
        );
        assert!(
            std::fs::rename(&from, &to).is_err(),
            "a folder cannot be renamed while a child's working directory is inside it"
        );
        assert!(
            from.exists() && !to.exists(),
            "a failed rename changed nothing"
        );
        drop(child.stdin.take());
        let _ = child.kill();
        let _ = child.wait();
        rename_eventually(&from, &to);
        rename_eventually(&to, &from);

        // 3. A file inside held with share read only: the rename fails; undone after.
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1) // FILE_SHARE_READ
            .open(&exe)
            .expect("hold a file");
        assert!(
            std::fs::rename(&from, &to).is_err(),
            "a folder cannot be renamed while a file inside is held without delete sharing"
        );
        assert!(
            from.exists() && !to.exists(),
            "a failed rename changed nothing"
        );
        drop(held);
        rename_eventually(&from, &to);
        assert!(to.join("cmd.exe").exists());
        drop(cleanup);
    }

    /// Renames, allowing a moment for a just-ended program's handles to go.
    #[track_caller]
    fn rename_eventually(from: &Path, to: &Path) {
        for _ in 0..50 {
            if std::fs::rename(from, to).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("the folder can be renamed once nothing holds it");
    }
}

#[cfg(not(windows))]
#[test]
fn windows_only() {
    println!("lunepack-os-windows machine tests: Windows only, skipped");
}
