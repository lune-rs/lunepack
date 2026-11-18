//! The Windows stub launch contract v1 (M7-D7): `launch_target`'s read path over a fake `Fs`.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use lunepack_core::state::{commit, commit_raw_payload, load};
use lunepack_core::{
    AppId, CurrentRef, Fs, InstallState, LaunchTarget, LayoutScheme, PendingRef, PreviousRef,
    RelPath, STUB_CONTRACT_VERSION, STUB_FILE, Scope, StubError, Target, UpdateConfig, UserLayout,
    Version, launch_target,
};
use lunepack_testkit::{FakeHasher, MemFs, abs_path, sample_update_config};

const ENTRY: &str = "bin/hello.exe";

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn app() -> AppId {
    sample_update_config().app_id
}

fn root() -> PathBuf {
    abs_path("/Users/u/AppData/Local/Programs/Hello App")
}

fn layout(root: &Path) -> UserLayout {
    UserLayout::from_root(root.to_path_buf(), LayoutScheme::WINDOWS)
}

fn config(version: &str) -> UpdateConfig {
    let mut c = sample_update_config();
    c.install.entry = RelPath::parse(ENTRY).unwrap();
    c.version = v(version);
    c.target = Target::WindowsX86_64;
    c
}

fn put(fs: &MemFs, path: &Path, bytes: &[u8]) {
    fs.create_dir_all(path.parent().unwrap()).unwrap();
    let mut f = fs.create_new(path).unwrap();
    f.write_all(bytes).unwrap();
    f.sync().unwrap();
}

/// A version tree of `version` under `root` with its config and entry.
fn put_tree(fs: &MemFs, root: &Path, version: &str) {
    let tree = layout(root).version_dir(&v(version));
    put(
        fs,
        &tree.join("lunepack-update.json"),
        &config(version).to_bytes().unwrap(),
    );
    put(fs, &tree.join("bin").join("hello.exe"), b"MZ");
}

/// Commits `record` (any scope) as the newest record of `root`'s Windows state directory.
fn put_record(fs: &MemFs, root: &Path, record: &InstallState) {
    let dir = layout(root).state_dir();
    fs.create_dir_all(&dir).unwrap();
    let loaded = load::<InstallState>(fs, &dir, &record.app_id, &FakeHasher).unwrap();
    commit(fs, &dir, &loaded, record, &FakeHasher).unwrap();
}

fn record(current: Option<&str>) -> InstallState {
    let mut r = InstallState::new(1, app(), Scope::User, [5; 16], Target::WindowsX86_64);
    r.current = current.map(|c| CurrentRef {
        version: v(c),
        issued: 1,
    });
    r
}

/// An installed 1.0.0 under `root`.
fn installed(root: &Path) -> MemFs {
    let fs = MemFs::new();
    put_tree(&fs, root, "1.0.0");
    put_record(&fs, root, &record(Some("1.0.0")));
    fs
}

fn target(fs: &dyn Fs, root: &Path) -> Result<LaunchTarget, StubError> {
    launch_target(fs, &FakeHasher, root)
}

#[test]
fn the_constants_and_exit_codes_are_fixed() {
    assert_eq!(STUB_FILE, "lunepack-stub.exe");
    assert_eq!(STUB_CONTRACT_VERSION, 1);
    let all = [
        StubError::NotInstalled,
        StubError::State,
        StubError::Config,
        StubError::Entry,
        StubError::Link,
        StubError::Launch,
    ];
    let codes: Vec<u8> = all.iter().map(|e| e.code()).collect();
    assert_eq!(codes, vec![90, 91, 92, 93, 94, 95]);
    for e in all {
        // Fixed text: no path separator, no braces of a formatted value.
        assert!(!e.message().contains(['/', '\\', '{']), "{e:?}");
        assert!(!e.to_string().contains(['/', '\\']), "{e:?}");
    }
}

#[test]
fn an_installed_app_launches_its_current_versions_entry() {
    let fs = installed(&root());
    let tree = layout(&root()).version_dir(&v("1.0.0"));
    assert_eq!(
        target(&fs, &root()).unwrap(),
        LaunchTarget {
            version: v("1.0.0"),
            entry_path: tree.join("bin").join("hello.exe"),
            runtime_path: tree.join("bin").join("lunepack-runtime.exe"),
        }
    );
}

#[test]
fn the_current_version_is_launched_never_pending_or_previous() {
    let fs = MemFs::new();
    put_tree(&fs, &root(), "1.0.0");
    put_tree(&fs, &root(), "2.0.0");
    let mut r = record(Some("2.0.0"));
    r.pending = Some(PendingRef {
        version: v("2.0.0"),
        attempts: 0,
    });
    r.previous = Some(PreviousRef {
        version: v("1.0.0"),
    });
    put_record(&fs, &root(), &r);
    assert_eq!(target(&fs, &root()).unwrap().version, v("2.0.0"));
}

#[test]
fn the_newest_record_decides() {
    let fs = installed(&root());
    put_tree(&fs, &root(), "1.1.0");
    put_record(&fs, &root(), &record(Some("1.1.0")).with_seq(2));
    assert_eq!(target(&fs, &root()).unwrap().version, v("1.1.0"));
}

#[test]
fn the_folder_name_is_never_read() {
    let a = abs_path("/P/Hello App");
    let b = abs_path("/P/renamed by the user");
    let (fa, fb) = (installed(&a), installed(&b));
    let ta = target(&fa, &a).unwrap();
    let tb = target(&fb, &b).unwrap();
    assert_eq!(ta.version, tb.version);
    assert_eq!(
        ta.entry_path.strip_prefix(&a).unwrap(),
        tb.entry_path.strip_prefix(&b).unwrap()
    );
}

#[test]
fn no_record_or_no_current_version_is_not_installed() {
    let fs = MemFs::new();
    assert_eq!(target(&fs, &root()), Err(StubError::NotInstalled));
    fs.create_dir_all(&layout(&root()).state_dir()).unwrap();
    assert_eq!(target(&fs, &root()), Err(StubError::NotInstalled));
    // A torn record only (fails its integrity check) is no record.
    put(
        &fs,
        &layout(&root()).state_dir().join("00000000000000000001.rec"),
        b"torn",
    );
    assert_eq!(target(&fs, &root()), Err(StubError::NotInstalled));
    // A record before the first install completes.
    let fs = MemFs::new();
    put_tree(&fs, &root(), "1.0.0");
    put_record(&fs, &root(), &record(None));
    assert_eq!(target(&fs, &root()), Err(StubError::NotInstalled));
}

#[test]
fn an_xdg_layout_is_not_found_under_the_windows_contract() {
    let fs = MemFs::new();
    let xdg = UserLayout::from_root(root(), LayoutScheme::XDG);
    let tree = xdg.version_dir(&v("1.0.0"));
    put(
        &fs,
        &tree.join("lunepack-update.json"),
        &config("1.0.0").to_bytes().unwrap(),
    );
    put(&fs, &tree.join("bin").join("hello.exe"), b"MZ");
    fs.create_dir_all(&xdg.state_dir()).unwrap();
    let loaded = load::<InstallState>(&fs, &xdg.state_dir(), &app(), &FakeHasher).unwrap();
    commit(
        &fs,
        &xdg.state_dir(),
        &loaded,
        &record(Some("1.0.0")),
        &FakeHasher,
    )
    .unwrap();
    assert_eq!(target(&fs, &root()), Err(StubError::NotInstalled));
}

#[test]
fn an_unreadable_newer_or_machine_record_is_a_state_error() {
    // Whole (checksum passes) but invalid.
    let fs = installed(&root());
    commit_raw_payload(
        &fs,
        &layout(&root()).state_dir(),
        2,
        b"{\"seq\":2}",
        &FakeHasher,
    )
    .unwrap();
    assert_eq!(target(&fs, &root()), Err(StubError::State));
    // A newer format.
    let fs = installed(&root());
    commit_raw_payload(
        &fs,
        &layout(&root()).state_dir(),
        2,
        b"{\"format\":2,\"seq\":2}",
        &FakeHasher,
    )
    .unwrap();
    assert_eq!(target(&fs, &root()), Err(StubError::State));
    // A per-machine record.
    let fs = MemFs::new();
    put_tree(&fs, &root(), "1.0.0");
    let mut r = record(Some("1.0.0"));
    r.scope = Scope::Machine;
    put_record(&fs, &root(), &r);
    assert_eq!(target(&fs, &root()), Err(StubError::State));
}

#[test]
fn a_missing_invalid_or_mismatched_config_is_a_config_error() {
    let config_path = layout(&root())
        .version_dir(&v("1.0.0"))
        .join("lunepack-update.json");
    // The current version's tree is missing.
    let fs = MemFs::new();
    put_record(&fs, &root(), &record(Some("1.0.0")));
    assert_eq!(target(&fs, &root()), Err(StubError::Config));
    // The config is missing.
    let fs = installed(&root());
    fs.remove_file(&config_path).unwrap();
    assert_eq!(target(&fs, &root()), Err(StubError::Config));
    // Not JSON the reader accepts.
    let fs = installed(&root());
    fs.remove_file(&config_path).unwrap();
    put(&fs, &config_path, b"{}");
    assert_eq!(target(&fs, &root()), Err(StubError::Config));
    // Over 64 KiB.
    let fs = installed(&root());
    fs.remove_file(&config_path).unwrap();
    put(&fs, &config_path, &vec![b' '; 64 * 1024 + 1]);
    assert_eq!(target(&fs, &root()), Err(StubError::Config));
    // A directory.
    let fs = installed(&root());
    fs.remove_file(&config_path).unwrap();
    fs.create_dir_all(&config_path).unwrap();
    assert_eq!(target(&fs, &root()), Err(StubError::Config));
    // Another version's config in this version's tree.
    let fs = installed(&root());
    fs.remove_file(&config_path).unwrap();
    put(&fs, &config_path, &config("1.0.1").to_bytes().unwrap());
    assert_eq!(target(&fs, &root()), Err(StubError::Config));
    // Another app's config.
    let fs = installed(&root());
    fs.remove_file(&config_path).unwrap();
    let mut other = config("1.0.0");
    other.app_id = AppId::parse("com.other.app").unwrap();
    put(&fs, &config_path, &other.to_bytes().unwrap());
    assert_eq!(target(&fs, &root()), Err(StubError::Config));
}

#[test]
fn a_missing_entry_or_one_that_is_not_a_file_is_an_entry_error() {
    let tree = layout(&root()).version_dir(&v("1.0.0"));
    let fs = installed(&root());
    fs.remove_file(&tree.join("bin").join("hello.exe")).unwrap();
    assert_eq!(target(&fs, &root()), Err(StubError::Entry));
    fs.create_dir_all(&tree.join("bin").join("hello.exe"))
        .unwrap();
    assert_eq!(target(&fs, &root()), Err(StubError::Entry));
    // Its directory is a file.
    let fs = installed(&root());
    fs.remove_dir_all_nofollow(&tree.join("bin")).unwrap();
    put(&fs, &tree.join("bin"), b"x");
    assert_eq!(target(&fs, &root()), Err(StubError::Entry));
}

#[test]
fn a_link_anywhere_below_the_install_folder_is_refused_and_never_followed() {
    let elsewhere = abs_path("/elsewhere");
    let real = |fs: &MemFs| {
        // A complete, valid copy elsewhere, which a followed link would launch.
        put_tree(fs, &elsewhere, "1.0.0");
    };
    let link = |fs: &MemFs, at: &Path, to: &Path| {
        fs.symlink(to.to_str().unwrap(), at).unwrap();
    };
    let w = layout(&root());
    let other = layout(&elsewhere);
    let tree = w.version_dir(&v("1.0.0"));
    let other_tree = other.version_dir(&v("1.0.0"));

    // `app` is a link.
    let fs = installed(&root());
    real(&fs);
    fs.remove_dir_all_nofollow(&w.versions_dir()).unwrap();
    link(&fs, &w.versions_dir(), &other.versions_dir());
    assert_eq!(target(&fs, &root()), Err(StubError::Link));
    // `app\<v>` is a link.
    let fs = installed(&root());
    real(&fs);
    fs.remove_dir_all_nofollow(&tree).unwrap();
    link(&fs, &tree, &other_tree);
    assert_eq!(target(&fs, &root()), Err(StubError::Link));
    // The config is a link.
    let fs = installed(&root());
    real(&fs);
    fs.remove_file(&tree.join("lunepack-update.json")).unwrap();
    link(
        &fs,
        &tree.join("lunepack-update.json"),
        &other_tree.join("lunepack-update.json"),
    );
    assert_eq!(target(&fs, &root()), Err(StubError::Link));
    // A directory on the entry's path is a link.
    let fs = installed(&root());
    real(&fs);
    fs.remove_dir_all_nofollow(&tree.join("bin")).unwrap();
    link(&fs, &tree.join("bin"), &other_tree.join("bin"));
    assert_eq!(target(&fs, &root()), Err(StubError::Link));
    // The entry is a link.
    let fs = installed(&root());
    real(&fs);
    fs.remove_file(&tree.join("bin").join("hello.exe")).unwrap();
    link(
        &fs,
        &tree.join("bin").join("hello.exe"),
        &other_tree.join("bin").join("hello.exe"),
    );
    assert_eq!(target(&fs, &root()), Err(StubError::Link));
    // The state directory is a link.
    let fs = installed(&root());
    put_record(&fs, &elsewhere, &record(Some("1.0.0")));
    fs.remove_dir_all_nofollow(&w.state_dir()).unwrap();
    link(&fs, &w.state_dir(), &other.state_dir());
    assert_eq!(target(&fs, &root()), Err(StubError::Link));
}
