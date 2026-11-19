//! The facade on the macOS layout (M8 step 5): finding the bundle an executable belongs to,
//! refusing a place that is not updated, following a bundle the user moved, and the startup that
//! finishes a swap or rolls back through the bundle.
//!
//! The layout scheme is a value the platform picks, so every case but the last runs on a `MemFs`
//! on any Unix (and so in the Linux image); the last runs on the real disk and is macOS's own.
#![cfg(unix)]

mod common;

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{INSTALL_ID, TARGET, World, app_id, channel, sha, version};
use lunepack::{
    Error, Installation, Platform, StartupAction, UpdateConfigError, follow_move, startup_for,
};
use lunepack_core::state::{InstallState, Scope, StagedRef, UserScope};
use lunepack_core::{
    Fs, InstallMeta, IntegrationRequest, LayoutScheme, LocationReason, RelPath, UpdateConfig,
    UserLayout, set_bundle_pointer, write_bundle_identity,
};
use lunepack_testkit::{
    FakeHasher, FakeIntegration, FakeProcess, FakeRng, FakeVerifier, IntegrationOp, MemFs, MemPlace,
};

const V100: &str = "1.0.0";
const V110: &str = "1.1.0";
const FEED: &str = "https://fake.invalid/";
const TOKEN: [u8; 32] = [0x5c; 32];

fn meta() -> InstallMeta {
    InstallMeta {
        entry: RelPath::parse("Contents/MacOS/hello").expect("entry"),
        name: "Hello".to_owned(),
        comment: None,
        icon: None,
        categories: Vec::new(),
        bin: None,
        terminal: false,
        publisher: None,
        file_types: Vec::new(),
        url_schemes: Vec::new(),
        autostart: true,
    }
}

fn config(world: &World, v: &str) -> UpdateConfig {
    UpdateConfig::new(
        &world.root(),
        version(v),
        TARGET,
        FEED,
        channel(),
        60,
        meta(),
    )
    .expect("config")
}

fn write_file(fs: &dyn Fs, path: &Path, bytes: &[u8]) {
    fs.create_dir_all(path.parent().expect("parent"))
        .expect("dirs");
    let mut w = fs.create_new(path).expect("create");
    w.write_all(bytes).expect("write");
    w.sync().expect("sync");
}

/// A bundle tree at `tree`: the config at `Contents/Resources/lunepack-update.json` and the entry.
fn write_bundle(fs: &dyn Fs, tree: &Path, cfg: &UpdateConfig) {
    write_file(
        fs,
        &tree.join("Contents/Resources/lunepack-update.json"),
        &cfg.to_bytes().expect("bytes"),
    );
    write_file(
        fs,
        &tree.join("Contents/MacOS/hello"),
        cfg.version.to_string().as_bytes(),
    );
}

fn config_version(fs: &dyn Fs, tree: &Path) -> Option<String> {
    let bytes = fs
        .read_capped(
            &tree.join("Contents/Resources/lunepack-update.json"),
            1 << 16,
        )
        .ok()?;
    Some(UpdateConfig::parse(&bytes).ok()?.version.to_string())
}

fn commit(fs: &dyn Fs, layout: &UserLayout, record: &InstallState) -> InstallState {
    let store = UserScope {
        dir: layout.state_dir(),
        app_id: app_id(),
    };
    let loaded = store.load(fs, &FakeHasher).expect("load");
    store
        .commit(fs, &loaded, record, &FakeHasher)
        .expect("commit")
}

fn installed(v: &str) -> InstallState {
    InstallState::new(1, app_id(), Scope::User, INSTALL_ID, TARGET).install(
        version(v),
        10,
        TARGET,
        INSTALL_ID,
    )
}

/// 1.0.0 current, 1.1.0 applied and pending its health check.
fn pending_110() -> InstallState {
    let staged = installed(V100).set_staged(Some((
        StagedRef::new(version(V110), TARGET, sha(b"manifest 1.1.0")),
        20,
    )));
    lunepack_core::apply(&staged, &version(V110), sha(&TOKEN)).expect("apply")
}

/// One macOS install on a `MemFs`, with fakes for everything else.
struct Mac {
    world: World,
    fs: MemFs,
    process: FakeProcess,
    integration: FakeIntegration,
}

impl Mac {
    fn new() -> Mac {
        let world = World::new();
        let fs = world.fs.clone();
        Mac {
            world,
            fs,
            process: FakeProcess::new("/unused"),
            integration: FakeIntegration::new(),
        }
    }

    fn home(&self) -> PathBuf {
        PathBuf::from("/Users/u")
    }

    fn data_home(&self) -> PathBuf {
        self.home().join("Library/Application Support")
    }

    fn apps(&self) -> PathBuf {
        self.home().join("Applications")
    }

    fn bundle(&self) -> PathBuf {
        self.apps().join("Hello.app")
    }

    fn layout(&self) -> UserLayout {
        UserLayout::from_root(
            self.data_home().join(app_id().as_str()),
            LayoutScheme::MACOS,
        )
    }

    fn platform(&self, token: Option<OsString>) -> Platform {
        Platform::native()
            .with_fs(Arc::new(self.fs.clone()))
            .with_hasher(Arc::new(FakeHasher))
            .with_verifier(Arc::new(FakeVerifier))
            .with_process(Arc::new(self.process.clone()))
            .with_integration(Arc::new(self.integration.clone()))
            .with_rng(Arc::new(FakeRng::new(9)))
            .with_health_token(token)
            .with_data_home(self.data_home())
            .with_home(self.home())
            .with_layout_scheme(LayoutScheme::MACOS)
            .with_busy_wait(Duration::from_millis(300))
    }

    /// `R` with its state, the live bundle holding `live`, `R/bundle` and its identity, a version
    /// tree for each of `kept`, and `record` committed.
    fn install(&self, live: &str, kept: &[&str], record: &InstallState) {
        let layout = self.layout();
        self.fs
            .create_dir_all(&layout.versions_dir())
            .expect("versions");
        self.fs.create_dir_all(&layout.state_dir()).expect("state");
        self.fs.create_dir_all(&self.apps()).expect("apps");
        write_bundle(&self.fs, &self.bundle(), &config(&self.world, live));
        for v in kept {
            write_bundle(
                &self.fs,
                &layout.version_dir(&version(v)),
                &config(&self.world, v),
            );
        }
        set_bundle_pointer(&self.fs, &layout, &self.bundle()).expect("pointer");
        write_bundle_identity(&self.fs, &layout, &self.bundle()).expect("identity");
        commit(&self.fs, &layout, record);
    }

    fn open(&self, tree: &Path, token: Option<OsString>) -> Result<Installation, Error> {
        Installation::from_exe_with(&tree.join("Contents/MacOS/hello"), self.platform(token))
    }

    fn record(&self) -> InstallState {
        UserScope {
            dir: self.layout().state_dir(),
            app_id: app_id(),
        }
        .load(&self.fs, &FakeHasher)
        .expect("load")
        .record
        .expect("record")
    }

    fn pointer(&self) -> String {
        self.fs
            .read_link(&self.layout().root().join("bundle"))
            .expect("pointer")
    }
}

fn token_hex() -> OsString {
    TOKEN
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        .into()
}

// ---- discovery -----------------------------------------------------------------------------------

#[test]
fn the_bundle_the_pointer_names_is_the_installed_tree() {
    let mac = Mac::new();
    mac.install(V100, &[], &installed(V100));
    let inst = mac.open(&mac.bundle(), None).expect("installation");
    assert!(inst.is_installed() && !inst.moved());
    assert_eq!(inst.tree_root(), mac.bundle());
    assert_eq!(inst.tree_version(), &version(V100));
    let layout = inst.layout().expect("layout");
    assert_eq!(layout.root(), mac.layout().root());
    assert_eq!(layout.scheme(), LayoutScheme::MACOS);
    assert_eq!(inst.entry_path(), mac.bundle().join("Contents/MacOS/hello"));
    assert_eq!(
        inst.runtime_path(),
        mac.bundle().join("Contents/MacOS/lunepack-runtime")
    );
    inst.updater_builder().expect("builder");
}

#[test]
fn an_old_instance_in_its_version_tree_is_installed() {
    let mac = Mac::new();
    mac.install(V110, &[V100], &installed(V110));
    let tree = mac.layout().version_dir(&version(V100));
    let inst = mac.open(&tree, None).expect("installation");
    assert!(inst.is_installed() && !inst.moved());
    assert_eq!(inst.tree_root(), tree);
}

#[test]
fn a_stray_copy_at_a_normal_place_is_not_installed() {
    let mac = Mac::new();
    mac.install(V100, &[], &installed(V100));
    // Another copy of the same app, in Downloads, while the install is live.
    let stray = mac.home().join("Downloads/Hello.app");
    write_bundle(&mac.fs, &stray, &config(&mac.world, V100));
    let inst = mac.open(&stray, None).expect("installation");
    assert!(!inst.is_installed() && !inst.moved());
    assert!(inst.layout().is_none());
    // A development run starts with nothing to do.
    let start = startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(start.action, StartupAction::Continue);
    assert!(start.events.is_empty());

    // And a copy of an app that was never installed.
    let fresh = Mac::new();
    let tree = fresh.home().join("Downloads/Hello.app");
    write_bundle(&fresh.fs, &tree, &config(&fresh.world, V100));
    let inst = fresh.open(&tree, None).expect("installation");
    assert!(!inst.is_installed());
    assert_eq!(
        inst.install_root().expect("root"),
        fresh.layout().root().to_path_buf()
    );
}

#[test]
fn a_place_lunepack_does_not_update_is_refused_first() {
    for (what, reason, tree, place) in [
        (
            "read-only volume",
            LocationReason::ReadOnly,
            PathBuf::from("/Volumes/Hello/Hello.app"),
            MemPlace {
                read_only: true,
                ..MemPlace::default()
            },
        ),
        (
            "nullfs volume",
            LocationReason::Translocated,
            PathBuf::from("/private/var/folders/xx/T/Hello.app"),
            MemPlace {
                fs_type: "nullfs".to_owned(),
                ..MemPlace::default()
            },
        ),
        (
            "translocation folder",
            LocationReason::Translocated,
            PathBuf::from("/private/var/folders/xx/AppTranslocation/ID/d/Hello.app"),
            MemPlace::default(),
        ),
    ] {
        let mac = Mac::new();
        write_bundle(&mac.fs, &tree, &config(&mac.world, V100));
        mac.fs.set_place(&tree, place);
        let got = mac.open(&tree, None);
        assert!(
            matches!(&got, Err(Error::UnsupportedLocation { reason: r }) if *r == reason),
            "{what}: {got:?}"
        );
    }
}

#[test]
fn an_installed_app_on_a_read_only_volume_is_refused_before_its_state_is_read() {
    let mac = Mac::new();
    mac.install(V100, &[], &installed(V100));
    // The same app, as a disk image holds it: the pointer exists, but the copy is the image's.
    let image = PathBuf::from("/Volumes/Hello/Hello.app");
    write_bundle(&mac.fs, &image, &config(&mac.world, V100));
    mac.fs.set_place(
        &image,
        MemPlace {
            read_only: true,
            device: 7,
            ..MemPlace::default()
        },
    );
    let got = mac.open(&image, None);
    assert!(
        matches!(
            got,
            Err(Error::UnsupportedLocation {
                reason: LocationReason::ReadOnly
            })
        ),
        "{got:?}"
    );
}

#[test]
fn an_executable_outside_the_entry_directory_is_a_config_error() {
    let mac = Mac::new();
    mac.install(V100, &[], &installed(V100));
    let exe = mac.bundle().join("Contents/Resources/other");
    write_file(&mac.fs, &exe, b"x");
    let got = Installation::from_exe_with(&exe, mac.platform(None));
    assert!(
        matches!(
            got,
            Err(Error::UpdateConfig(UpdateConfigError::Invalid {
                field: "install.entry",
                ..
            }))
        ),
        "{got:?}"
    );
}

// ---- a moved bundle ------------------------------------------------------------------------------

#[test]
fn a_bundle_moved_on_its_volume_is_followed_under_the_lock() {
    let mac = Mac::new();
    mac.install(V100, &[], &installed(V100));
    let moved = mac.home().join("Documents/Hello.app");
    mac.fs
        .create_dir_all(moved.parent().expect("parent"))
        .expect("dirs");
    mac.fs.rename(&mac.bundle(), &moved).expect("move");

    let inst = mac.open(&moved, None).expect("installation");
    assert!(inst.is_installed() && inst.moved());
    // Opening changed nothing: the pointer is followed only under the lock.
    assert_eq!(mac.pointer(), mac.bundle().to_str().expect("utf-8"));

    let start = startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(start.action, StartupAction::Continue);
    assert_eq!(mac.pointer(), moved.to_str().expect("utf-8"));
    assert_eq!(config_version(&mac.fs, &moved).as_deref(), Some(V100));
    // The record is untouched by the move, and the desktop entry follows the app.
    assert_eq!(
        mac.record().current.expect("current").version,
        version(V100)
    );
    let applied: Vec<_> = mac
        .integration
        .calls()
        .into_iter()
        .filter(|c| c.op == IntegrationOp::Apply)
        .collect();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].install_root, moved);
    // A second open finds it installed in the ordinary way.
    let again = mac.open(&moved, None).expect("installation");
    assert!(again.is_installed() && !again.moved());
}

#[test]
fn follow_move_is_the_same_step_for_a_caller_that_is_not_startup() {
    let mac = Mac::new();
    mac.install(V100, &[], &installed(V100));
    let moved = mac.home().join("Desktop/Hello.app");
    mac.fs
        .create_dir_all(moved.parent().expect("parent"))
        .expect("dirs");
    mac.fs.rename(&mac.bundle(), &moved).expect("move");
    let inst = mac.open(&moved, None).expect("installation");
    assert!(follow_move(&inst).expect("follow"));
    assert_eq!(mac.pointer(), moved.to_str().expect("utf-8"));
    // Following twice is the same as once.
    assert!(follow_move(&mac.open(&moved, None).expect("again")).expect("follow"));
}

#[test]
fn a_copy_with_another_inode_is_not_adopted_even_when_the_pointer_dangles() {
    let mac = Mac::new();
    mac.install(V100, &[], &installed(V100));
    // The bundle is gone (trashed), and the app is extracted again elsewhere: a new directory.
    let again = mac.home().join("Downloads/Hello.app");
    write_bundle(&mac.fs, &again, &config(&mac.world, V100));
    mac.fs
        .remove_dir_all_nofollow(&mac.bundle())
        .expect("trash");
    let inst = mac.open(&again, None).expect("installation");
    assert!(!inst.is_installed() && !inst.moved());
    startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(
        mac.pointer(),
        mac.bundle().to_str().expect("utf-8"),
        "the pointer was not moved to a copy"
    );
    assert_eq!(
        mac.record().current.expect("current").version,
        version(V100)
    );
}

#[test]
fn a_move_that_stopped_being_one_is_not_followed() {
    let mac = Mac::new();
    mac.install(V100, &[], &installed(V100));
    let moved = mac.home().join("Documents/Hello.app");
    mac.fs
        .create_dir_all(moved.parent().expect("parent"))
        .expect("dirs");
    mac.fs.rename(&mac.bundle(), &moved).expect("move");
    let inst = mac.open(&moved, None).expect("installation");
    assert!(inst.moved());
    // Before the lock is taken the user put another bundle back at the old place.
    write_bundle(&mac.fs, &mac.bundle(), &config(&mac.world, V100));
    assert!(!follow_move(&inst).expect("follow"));
    assert_eq!(mac.pointer(), mac.bundle().to_str().expect("utf-8"));
    let start = startup_for(&inst, Vec::new()).expect("startup");
    assert!(start.events.is_empty() && !start.pending);
    assert_eq!(mac.pointer(), mac.bundle().to_str().expect("utf-8"));
}

// ---- startup through the bundle ------------------------------------------------------------------

#[test]
fn startup_finishes_a_swap_the_record_already_made() {
    let mac = Mac::new();
    // The record says 1.1.0 is current (pending); the bundle still holds 1.0.0 and 1.1.0 waits in
    // `versions`, where the applier put it before it was cut off.
    mac.install(V100, &[V110], &pending_110());
    let tree = mac.layout().version_dir(&version(V110));
    let inst = mac.open(&tree, Some(token_hex())).expect("installation");
    assert!(inst.is_installed());

    let start = startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(start.action, StartupAction::Continue);
    assert!(start.pending);
    // The bundle holds 1.1.0, 1.0.0 is parked under its version, no slot is left.
    assert_eq!(
        config_version(&mac.fs, &mac.bundle()).as_deref(),
        Some(V110)
    );
    assert_eq!(
        config_version(&mac.fs, &mac.layout().version_dir(&version(V100))).as_deref(),
        Some(V100)
    );
    assert!(
        mac.fs
            .symlink_metadata(&mac.layout().version_dir(&version(V110)))
            .expect("lstat")
            .is_none()
    );
    for slot in [mac.layout().swap_slot(), mac.layout().out_slot()] {
        assert!(mac.fs.symlink_metadata(&slot).expect("lstat").is_none());
    }
    // Starting again changes nothing on disk.
    let ops = mac.fs.op_count();
    let inst = mac
        .open(&mac.bundle(), Some(token_hex()))
        .expect("installation");
    startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(
        mac.fs.op_count(),
        ops + 1,
        "only the delivered events' commit"
    );
}

#[test]
fn a_rollback_starts_the_previous_version_from_the_live_bundle() {
    let mac = Mac::new();
    mac.install(V110, &[V100], &pending_110());
    let args: Vec<OsString> = vec!["--open".into()];
    let tree = mac.bundle();
    for n in 1..=3 {
        let inst = mac.open(&tree, None).expect("installation");
        let got = startup_for(&inst, args.clone()).expect("startup");
        assert_eq!(got.action, StartupAction::Continue, "start {n}");
    }
    let inst = mac.open(&tree, None).expect("installation");
    let got = startup_for(&inst, args.clone()).expect("startup");
    assert_eq!(got.action, StartupAction::Exit);

    assert_eq!(
        mac.record().current.expect("current").version,
        version(V100)
    );
    // 1.0.0 is the bundle now and the bad 1.1.0 is parked.
    assert_eq!(
        config_version(&mac.fs, &mac.bundle()).as_deref(),
        Some(V100)
    );
    assert_eq!(
        config_version(&mac.fs, &mac.layout().version_dir(&version(V110))).as_deref(),
        Some(V110)
    );
    let spawns = mac.process.spawns();
    assert_eq!(spawns.len(), 1);
    assert!(spawns[0].detached);
    assert_eq!(
        spawns[0].program,
        mac.bundle().join("Contents/MacOS/hello"),
        "the previous version starts from the live bundle, not from its old tree"
    );
    assert_eq!(spawns[0].args, args);
    let applied: Vec<IntegrationRequest> = mac
        .integration
        .calls()
        .into_iter()
        .filter(|c| c.op == IntegrationOp::Apply)
        .map(|c| IntegrationRequest {
            app_id: app_id(),
            install_root: c.install_root,
            version: c.version,
            meta: c.meta,
            previous: c.previous,
            stale_bins: c.stale_bins,
        })
        .collect();
    assert_eq!(applied.len(), 1);
    assert_eq!(
        applied[0].install_root,
        mac.bundle(),
        "the desktop integration is rooted at the bundle (M8-D12)"
    );
}

#[test]
fn an_install_whose_bundle_is_gone_is_not_installed_for_the_app() {
    let mac = Mac::new();
    mac.install(V100, &[V110], &installed(V110));
    // 1.1.0 is current in the record but no tree holds it, and the bundle was thrown away.
    mac.fs
        .remove_dir_all_nofollow(&mac.layout().version_dir(&version(V110)))
        .expect("remove");
    mac.fs
        .remove_dir_all_nofollow(&mac.bundle())
        .expect("trash");
    write_bundle(
        &mac.fs,
        &mac.layout().version_dir(&version(V100)),
        &config(&mac.world, V100),
    );
    let inst = mac
        .open(&mac.layout().version_dir(&version(V100)), None)
        .expect("installation");
    let got = startup_for(&inst, Vec::new());
    assert!(matches!(got, Err(Error::NotInstalled)), "{:?}", got.err());
}

// ---- the real disk -------------------------------------------------------------------------------

/// The same install on the real file system, found through the real adapters (`StdFs`'s `place`),
/// in a temporary home that is canonical here. `installed()` is `Some`. (`HOME` read through a
/// symlink is the unit test `home_is_canonicalised_once` in the facade.)
#[test]
fn a_real_install_is_found_and_reports_its_version() {
    let tmp = tempfile::tempdir().expect("tmp");
    let home = std::fs::canonicalize(tmp.path()).expect("canonical");
    let world = World::new();
    let fs = lunepack_fs::StdFs::new();
    let layout = UserLayout::from_root(
        home.join("Library/Application Support")
            .join(app_id().as_str()),
        LayoutScheme::MACOS,
    );
    let bundle = home.join("Applications/Hello.app");
    fs.create_dir_all(&layout.versions_dir()).expect("versions");
    fs.create_dir_all(&layout.state_dir()).expect("state");
    write_bundle(&fs, &bundle, &config(&world, V100));
    set_bundle_pointer(&fs, &layout, &bundle).expect("pointer");
    write_bundle_identity(&fs, &layout, &bundle).expect("identity");
    commit(&fs, &layout, &installed(V100));

    let platform = Platform::native()
        .with_hasher(Arc::new(FakeHasher))
        .with_verifier(Arc::new(FakeVerifier))
        .with_data_home(home.join("Library/Application Support"))
        .with_home(home.clone())
        .with_layout_scheme(LayoutScheme::MACOS);
    let inst = Installation::from_exe_with(&bundle.join("Contents/MacOS/hello"), platform)
        .expect("installation");
    assert!(inst.is_installed() && !inst.moved());
    let updater = inst
        .updater_builder()
        .expect("builder")
        .transport(Arc::clone(&world.transport))
        .codec(Arc::new(lunepack_testkit::FakeCodec::new()))
        .clock(Arc::clone(&world.clock) as Arc<dyn lunepack_core::Clock>)
        .build()
        .expect("build");
    let got = updater.installed().expect("installed").expect("an install");
    assert_eq!(got.version(), &version(V100));
}
