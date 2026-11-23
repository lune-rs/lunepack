//! The machine schemes, the uniform machine layout, the endpoint names, the per-user home of a
//! machine install and the unix protection rule (M11-D4, M11-D6, M11-D7, M11-D10).

use std::path::PathBuf;

use lunepack_core::endpoint;
use lunepack_core::layout::{current_target, service_path_in_tree, service_path_in_tree_for};
use lunepack_core::unix_protect::{self, DirFacts, Reason};
use lunepack_core::{
    AppId, DirClass, LayoutScheme, MachineLayout, MachineOs, MachineScheme, Projection, RelPath,
    RootNaming, SERVICE_FILE, SERVICE_FILE_UNIX, Target, UnixOs, Version, machine_user_home,
};
use lunepack_testkit::abs_path;

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn id(text: &str) -> AppId {
    AppId::parse(text).unwrap()
}

// ---- the schemes and the layout ------------------------------------------------------------------

#[test]
fn windows_machine_layout_is_unchanged() {
    let l = MachineLayout::new(&abs_path("/pf/Hello"));
    assert_eq!(l.scheme(), MachineScheme::WINDOWS);
    assert_eq!(SERVICE_FILE, "lunepack-service.exe");
    assert_eq!(l.app_dir(), abs_path("/pf/Hello/app"));
    assert_eq!(l.version_dir(&v("1.0.0")), abs_path("/pf/Hello/app/1.0.0"));
    assert_eq!(l.lunepack_dir(), abs_path("/pf/Hello/.lunepack"));
    assert_eq!(l.state_dir(), abs_path("/pf/Hello/.lunepack/state"));
    assert_eq!(l.logs_dir(), abs_path("/pf/Hello/.lunepack/logs"));
    assert_eq!(l.machine_dir(), abs_path("/pf/Hello/.lunepack/machine"));
    assert_eq!(l.lock_path(), abs_path("/pf/Hello/.lunepack/machine/lock"));
    assert_eq!(
        l.incoming_dir(),
        abs_path("/pf/Hello/.lunepack/machine/incoming")
    );
    assert_eq!(
        l.service_image(&v("2.0.0")),
        abs_path("/pf/Hello/.lunepack/machine/service/2.0.0/lunepack-service.exe")
    );
    assert_eq!(l.stable_service_link(), None);
    let (back, version) = MachineLayout::of_service_image(&l.service_image(&v("2.0.0"))).unwrap();
    assert_eq!(back, l);
    assert_eq!(version, v("2.0.0"));
    // A unix image is not a Windows one.
    assert!(
        MachineLayout::of_service_image(&abs_path(
            "/pf/Hello/.lunepack/machine/service/2.0.0/lunepack-service"
        ))
        .is_none()
    );
    assert_eq!(
        service_path_in_tree(&RelPath::parse("bin/app.exe").unwrap())
            .unwrap()
            .as_str(),
        "bin/lunepack-service.exe"
    );
}

#[test]
fn unix_machine_layouts_share_the_names_and_add_the_stable_link() {
    for (scheme, root) in [
        (MachineScheme::LINUX, "/opt/org.example.hello"),
        (
            MachineScheme::MACOS,
            "/Library/Application Support/lunepack/org.example.hello",
        ),
    ] {
        let r = abs_path(root);
        let l = MachineLayout::with_scheme(&r, scheme);
        assert_eq!(l.scheme(), scheme);
        assert_eq!(l.app_dir(), r.join("app"));
        assert_eq!(l.version_dir(&v("1.2.3")), r.join("app/1.2.3"));
        assert_eq!(l.state_dir(), r.join(".lunepack/state"));
        assert_eq!(l.logs_dir(), r.join(".lunepack/logs"));
        assert_eq!(l.lock_path(), r.join(".lunepack/machine/lock"));
        assert_eq!(l.incoming_dir(), r.join(".lunepack/machine/incoming"));
        let image = l.service_image(&v("1.2.3-beta.1"));
        assert_eq!(
            image,
            r.join(".lunepack/machine/service/1.2.3-beta.1/lunepack-service")
        );
        assert_eq!(
            l.stable_service_link(),
            Some(r.join(".lunepack/machine/lunepack-service"))
        );
        let (back, version) = MachineLayout::of_service_image_as(&image, scheme).unwrap();
        assert_eq!(back, l);
        assert_eq!(back.scheme(), scheme);
        assert_eq!(version.to_string(), "1.2.3-beta.1");
        let rel = |s: &str| r.join(s);
        for bad in [
            ".lunepack/machine/service/1.2.3/lunepack-service.exe",
            ".lunepack/machine/service/1.2.3/other",
            ".lunepack/machine/service/01.2.3/lunepack-service",
            ".lunepack/machine/service/v1.2.3/lunepack-service",
            ".lunepack/machine/other/1.2.3/lunepack-service",
            ".lunepack/admin/service/1.2.3/lunepack-service",
            "app/1.2.3/lunepack-service",
            ".lunepack/machine/lunepack-service",
        ] {
            assert!(
                MachineLayout::of_service_image_as(&rel(bad), scheme).is_none(),
                "{bad}"
            );
        }
    }
    assert_eq!(SERVICE_FILE_UNIX, "lunepack-service");
}

#[test]
fn schemes_name_projection_config_root_and_home() {
    assert_eq!(MachineScheme::WINDOWS.projection(), Projection::None);
    assert_eq!(MachineScheme::LINUX.projection(), Projection::CurrentLink);
    assert_eq!(MachineScheme::MACOS.projection(), Projection::Bundle);
    assert_eq!(
        MachineScheme::WINDOWS.root_naming(),
        RootNaming::DisplayName
    );
    assert_eq!(MachineScheme::LINUX.root_naming(), RootNaming::AppId);
    assert_eq!(MachineScheme::MACOS.root_naming(), RootNaming::AppId);
    assert_eq!(MachineScheme::LINUX.config(), "lunepack-update.json");
    assert_eq!(
        MachineScheme::MACOS.config(),
        "Contents/Resources/lunepack-update.json"
    );
    assert_eq!(MachineScheme::WINDOWS.home, None);
    assert_eq!(MachineScheme::LINUX.home, Some("/opt"));
    assert_eq!(
        MachineScheme::MACOS.home,
        Some("/Library/Application Support/lunepack")
    );
    assert!(!MachineScheme::WINDOWS.has_stable_link());
    assert!(MachineScheme::LINUX.has_stable_link());
    assert!(MachineScheme::MACOS.has_stable_link());
    for os in [MachineOs::Windows, MachineOs::Linux, MachineOs::Macos] {
        assert_eq!(MachineScheme::of_os(os).os, os);
    }
    assert_eq!(
        MachineOs::of_target(Target::WindowsAarch64),
        MachineOs::Windows
    );
    assert_eq!(MachineOs::of_target(Target::LinuxX86_64), MachineOs::Linux);
    assert_eq!(
        MachineOs::of_target(Target::MacosUniversal),
        MachineOs::Macos
    );
    assert_eq!(MachineOs::Windows.unix(), None);
    assert_eq!(MachineOs::Linux.unix(), Some(UnixOs::Linux));
    assert_eq!(MachineOs::Macos.unix(), Some(UnixOs::Macos));
    let entry = RelPath::parse("bin/app").unwrap();
    assert_eq!(
        service_path_in_tree_for(&entry, MachineOs::Linux)
            .unwrap()
            .as_str(),
        "bin/lunepack-service"
    );
    assert_eq!(
        service_path_in_tree_for(&RelPath::parse("app").unwrap(), MachineOs::Macos)
            .unwrap()
            .as_str(),
        "lunepack-service"
    );
}

#[test]
fn machine_views_project_from_the_app_directory() {
    let r = abs_path("/opt/org.example.hello");
    let view = MachineLayout::with_scheme(&r, MachineScheme::LINUX).view();
    assert_eq!(view.versions_dir(), r.join("app"));
    assert_eq!(view.state_dir(), r.join(".lunepack/state"));
    assert_eq!(view.current_link(), Some(r.join("current")));
    assert_eq!(
        LayoutScheme::MACHINE_LINUX.current_target(&v("1.2.0")),
        "app/1.2.0"
    );
    // The per-user XDG scheme keeps its link text.
    assert_eq!(
        LayoutScheme::XDG.current_target(&v("1.2.0-rc.1")),
        "versions/1.2.0-rc.1"
    );
    assert_eq!(current_target(&v("1.2.0-rc.1")), "versions/1.2.0-rc.1");

    let m = abs_path("/Library/Application Support/lunepack/org.example.hello");
    let view = MachineLayout::with_scheme(&m, MachineScheme::MACOS).view();
    assert_eq!(view.bundle_link(), Some(m.join("bundle")));
    assert_eq!(view.bundle_id_path(), Some(m.join("bundle.id")));
    assert_eq!(view.swap_slot(), m.join("app/.swap"));
    assert_eq!(view.out_slot(), m.join("app/.out"));
    assert_eq!(view.current_link(), None);
    assert_eq!(
        view.version_config_path(&v("1.0.0")),
        m.join("app/1.0.0/Contents/Resources/lunepack-update.json")
    );
}

#[test]
fn machine_views_are_never_recognised_from_directories() {
    // The Linux machine view names the Windows per-user directories: recognition finds WINDOWS.
    let r = abs_path("/opt/org.example.hello");
    let found =
        lunepack_core::UserLayout::from_dirs(&r.join(".lunepack/state"), &r.join("app")).unwrap();
    assert_eq!(found.scheme(), LayoutScheme::WINDOWS);
    assert_ne!(found.scheme(), LayoutScheme::MACHINE_LINUX);
    assert_ne!(found.scheme(), LayoutScheme::MACHINE_MACOS);
}

// ---- the per-user home of a machine install ------------------------------------------------------

#[test]
fn machine_user_home_is_under_the_dot_lunepack_of_the_data_home() {
    let home = machine_user_home(&abs_path("/home/u/.local/share"), &id("org.example.hello"));
    assert_eq!(
        home,
        abs_path("/home/u/.local/share/.lunepack/org.example.hello")
    );
    assert!(home.ends_with(PathBuf::from(".lunepack").join("org.example.hello")));
    // Never the per-user root of an app whose id is `lunepack`.
    let data = abs_path("/Users/u/Library/Application Support");
    assert_ne!(
        machine_user_home(&data, &id("lunepack")),
        data.join("lunepack")
    );
}

// ---- endpoints ----------------------------------------------------------------------------------

#[test]
fn endpoints_are_derived_from_the_app_id() {
    let a = id("org.example.hello");
    assert_eq!(
        endpoint::socket_path(UnixOs::Linux, &a),
        PathBuf::from("/run/lunepack/org.example.hello.sock")
    );
    assert_eq!(
        endpoint::socket_path(UnixOs::Macos, &a),
        PathBuf::from("/var/run/lunepack-org.example.hello.sock")
    );
    assert_eq!(endpoint::socket_dir(UnixOs::Linux), "/run/lunepack");
    assert_eq!(endpoint::socket_dir(UnixOs::Macos), "/var/run");
    assert_eq!(
        endpoint::systemd_socket_unit(&a),
        "lunepack-org.example.hello.socket"
    );
    assert_eq!(
        endpoint::systemd_service_unit(&a),
        "lunepack-org.example.hello.service"
    );
    assert_eq!(
        endpoint::systemd_socket_unit_path(&a),
        PathBuf::from("/etc/systemd/system/lunepack-org.example.hello.socket")
    );
    assert_eq!(
        endpoint::systemd_service_unit_path(&a),
        PathBuf::from("/etc/systemd/system/lunepack-org.example.hello.service")
    );
    assert_eq!(endpoint::launchd_label(&a), "lunepack-org.example.hello");
    assert_eq!(
        endpoint::launchd_plist_path(&a),
        PathBuf::from("/Library/LaunchDaemons/lunepack-org.example.hello.plist")
    );
    assert_eq!(endpoint::LAUNCHD_SOCKET_NAME, "lunepack");
}

#[test]
fn socket_paths_fit_sun_path_for_the_longest_app_id() {
    let longest = id(&"a".repeat(lunepack_core::ident::MAX_APP_ID_BYTES));
    assert_eq!(longest.as_str().len(), 64);
    let linux = endpoint::socket_path(UnixOs::Linux, &longest);
    let macos = endpoint::socket_path(UnixOs::Macos, &longest);
    assert!(linux.as_os_str().len() <= 107, "{}", linux.display());
    assert!(macos.as_os_str().len() <= 103, "{}", macos.display());
    assert_eq!(endpoint::max_socket_path(UnixOs::Linux), 107);
    assert_eq!(endpoint::max_socket_path(UnixOs::Macos), 103);
}

// ---- the unix protection rule -------------------------------------------------------------------

fn dir(uid: u32, gid: u32, mode: u32, os: UnixOs) -> DirFacts {
    DirFacts {
        uid,
        gid,
        mode: 0o040000 | mode,
        is_dir: true,
        is_link: false,
        has_acl: false,
        os,
    }
}

const BOTH: [UnixOs; 2] = [UnixOs::Linux, UnixOs::Macos];

#[test]
fn machine_tree_rule() {
    use DirClass::MachineTree as T;
    for os in BOTH {
        assert_eq!(unix_protect::check(&dir(0, 0, 0o755, os), T), Ok(()));
        assert_eq!(unix_protect::check(&dir(0, 0, 0o775, os), T), Ok(()));
        assert_eq!(unix_protect::check(&dir(0, 0, 0o555, os), T), Ok(()));
        assert_eq!(
            unix_protect::check(&dir(0, 0, 0o757, os), T),
            Err(Reason::OtherWritable)
        );
        // The sticky bit is no substitute.
        assert_eq!(
            unix_protect::check(&dir(0, 0, 0o1777, os), T),
            Err(Reason::OtherWritable)
        );
        assert_eq!(
            unix_protect::check(&dir(501, 0, 0o755, os), T),
            Err(Reason::Owner)
        );
        assert_eq!(
            unix_protect::check(&dir(0, 20, 0o775, os), T),
            Err(Reason::GroupWritable)
        );
        // A group that may only read is fine whatever it is.
        assert_eq!(unix_protect::check(&dir(0, 20, 0o755, os), T), Ok(()));
        let mut link = dir(0, 0, 0o755, os);
        link.is_link = true;
        assert_eq!(unix_protect::check(&link, T), Err(Reason::Link));
        let mut file = dir(0, 0, 0o755, os);
        file.is_dir = false;
        assert_eq!(unix_protect::check(&file, T), Err(Reason::NotADirectory));
        let mut acl = dir(0, 0, 0o755, os);
        acl.has_acl = true;
        assert_eq!(unix_protect::check(&acl, T), Err(Reason::Acl));
    }
    // gid 80 (`admin`) may write only on macOS.
    assert_eq!(
        unix_protect::check(&dir(0, 80, 0o775, UnixOs::Macos), T),
        Ok(())
    );
    assert_eq!(
        unix_protect::check(&dir(0, 80, 0o775, UnixOs::Linux), T),
        Err(Reason::GroupWritable)
    );
}

#[test]
fn admin_only_rule() {
    use DirClass::AdminOnly as A;
    for os in BOTH {
        assert_eq!(unix_protect::check(&dir(0, 0, 0o700, os), A), Ok(()));
        for mode in [0o750, 0o710, 0o701, 0o755, 0o770, 0o704] {
            assert_eq!(
                unix_protect::check(&dir(0, 0, mode, os), A),
                Err(Reason::NotAdminOnly),
                "{mode:o}"
            );
        }
        assert_eq!(
            unix_protect::check(&dir(501, 0, 0o700, os), A),
            Err(Reason::Owner)
        );
        let mut acl = dir(0, 0, 0o700, os);
        acl.has_acl = true;
        assert_eq!(unix_protect::check(&acl, A), Err(Reason::Acl));
        let mut link = dir(0, 0, 0o700, os);
        link.is_link = true;
        assert_eq!(unix_protect::check(&link, A), Err(Reason::Link));
    }
}

// ---- the policy file's bytes (M11-D11) ----------------------------------------------------------

#[test]
fn machine_policy_from_json_is_strict() {
    use lunepack_core::MachinePolicy;
    assert_eq!(
        MachinePolicy::from_json(b"{}"),
        Some(MachinePolicy::default())
    );
    assert_eq!(
        MachinePolicy::from_json(br#"{"disable_self_update": true, "no_update_ui": false}"#),
        Some(MachinePolicy {
            self_update_disabled: true,
            no_update_ui: false
        })
    );
    for bad in [
        &br#"{"disable_self_update": true, "disable_self_update": true}"#[..],
        br#"{"other": true}"#,
        br#"{"no_update_ui": "yes"}"#,
        br#"{"no_update_ui": null}"#,
        br#"{"no_update_ui": 0}"#,
        b"[]",
        b"true",
        b"",
        b"{",
    ] {
        assert_eq!(
            MachinePolicy::from_json(bad),
            None,
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    assert_eq!(
        MachinePolicy::FAIL_CLOSED,
        MachinePolicy {
            self_update_disabled: true,
            no_update_ui: true
        }
    );
}
