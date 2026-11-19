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
    CheckOptions, CheckOutcome, DownloadOptions, Error, Installation, Platform, StartupAction,
    UpdateConfigError, block_on, follow_move, startup_for,
};
use lunepack_core::state::{InstallState, LifecycleEvent, Scope, StagedRef, UserScope};
use lunepack_core::{
    CodecId, FileKind, Fs, InstallMeta, IntegrationRequest, LayoutScheme, LocationReason,
    PayloadKind, Phase, RelPath, UpdateConfig, UserLayout, read_bundle_identity,
    set_bundle_pointer, write_bundle_identity,
};
use lunepack_testkit::{
    FakeCodec, FakeHasher, FakeIntegration, FakeProcess, FakeRng, FakeVerifier, IntegrationOp,
    MemFs, MemPlace, PackBuilder, RecoverMode, SUITE_CHANNEL, TransportFault,
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
    /// Each platform gets its own random seed, so two installs draw different install ids.
    seed: std::cell::Cell<u8>,
}

impl Mac {
    fn new() -> Mac {
        let world = World::new();
        let fs = world.fs.clone();
        // The user's home exists; the Library and the apps folders do not until something makes
        // them.
        fs.create_dir_all(Path::new("/Users/u")).expect("home");
        Mac {
            world,
            fs,
            process: FakeProcess::new("/unused"),
            integration: FakeIntegration::new(),
            seed: std::cell::Cell::new(9),
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
        self.seed.set(self.seed.get().wrapping_add(1));
        Platform::native()
            .with_fs(Arc::new(self.fs.clone()))
            .with_hasher(Arc::new(FakeHasher))
            .with_verifier(Arc::new(FakeVerifier))
            .with_process(Arc::new(self.process.clone()))
            .with_integration(Arc::new(self.integration.clone()))
            .with_rng(Arc::new(FakeRng::new(u64::from(self.seed.get()))))
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

    /// The same install after a restart: `fs` is the disk a crash left.
    fn with_fs(self, fs: MemFs) -> Mac {
        Mac { fs, ..self }
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

// ---- the first install ---------------------------------------------------------------------------

/// The files of release `v` as a bundle: the entry, a file and the config.
fn release_files(mac: &Mac, v: &str) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("Contents/MacOS/hello", format!("app {v}").into_bytes()),
        ("Contents/Resources/share.txt", b"shared".repeat(20)),
        (
            "Contents/Resources/lunepack-update.json",
            config(&mac.world, v).to_bytes().expect("bytes"),
        ),
    ]
}

fn release_pack(mac: &Mac, v: &str) -> PackBuilder {
    let mut pack = PackBuilder::new();
    for (path, bytes) in release_files(mac, v) {
        pack.file(&FakeHasher, path, &bytes, CodecId::Lzma2);
    }
    pack
}

/// Publishes release `v` (feed `seq`) as a bundle: the entry, a file and the config in the pack.
fn publish(mac: &Mac, seq: u64, v: &str) {
    mac.world.publish_pack(seq, v, &release_pack(mac, v));
}

/// A bootstrap bundle of `v` outside the install.
fn bootstrap(mac: &Mac, v: &str) -> Installation {
    let tree = PathBuf::from("/media/boot").join(format!("{v}/Hello.app"));
    write_bundle(&mac.fs, &tree, &config(&mac.world, v));
    mac.open(&tree, None).expect("bootstrap")
}

fn install(mac: &Mac, boot: &Installation) -> Result<lunepack::InstalledVersion, Error> {
    let updater = boot
        .updater_builder()?
        .transport(Arc::clone(&mac.world.transport))
        .codec(Arc::new(FakeCodec::new()))
        .clock(Arc::clone(&mac.world.clock) as Arc<dyn lunepack_core::Clock>)
        .workers(2)
        .build()?;
    block_on(updater.install(DownloadOptions::default()))
}

#[test]
fn install_puts_the_live_bundle_in_the_apps_folder_and_follows_the_order() {
    let _serial = common::serial();
    let mac = Mac::new();
    publish(&mac, 1, V100);
    let boot = bootstrap(&mac, V100);
    let got = install(&mac, &boot).expect("install");
    assert_eq!(got.version(), &version(V100));

    // The apps folder was made private, the bundle holds the release, the pointer and the
    // identity name it, and the staged tree is gone from `versions` (placed, not copied).
    assert!(mac.fs.is_private_dir(&mac.apps()));
    assert_eq!(
        config_version(&mac.fs, &mac.bundle()).as_deref(),
        Some(V100)
    );
    assert_eq!(mac.pointer(), mac.bundle().to_str().expect("utf-8"));
    assert!(
        mac.fs
            .symlink_metadata(&mac.layout().version_dir(&version(V100)))
            .expect("lstat")
            .is_none()
    );
    assert!(
        lunepack_core::read_bundle_identity(&mac.fs, &mac.layout())
            .expect("identity")
            .is_some()
    );
    let rec = mac.record();
    assert_eq!(rec.current.expect("current").version, version(V100));
    // The desktop integration is rooted at the bundle, before the record names the version.
    let applied = mac
        .integration
        .calls()
        .into_iter()
        .rfind(|c| c.op == IntegrationOp::Apply)
        .expect("apply");
    assert_eq!(applied.install_root, mac.bundle());

    // The installed bundle finds itself and its first start gets the install events.
    let inst = mac.open(&mac.bundle(), None).expect("installation");
    assert!(inst.is_installed());
    let start = startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(start.events.len(), 2);
    // A second install is the answer for a live install.
    let again = install(&mac, &boot);
    assert!(matches!(again, Err(Error::AlreadyInstalled)), "{again:?}");
    common::workers_stopped();
}

#[test]
fn a_name_taken_in_the_apps_folder_falls_back_to_the_name_with_the_app_id() {
    let _serial = common::serial();
    let mac = Mac::new();
    publish(&mac, 1, V100);
    // Somebody else's Hello.app is there already.
    write_bundle(&mac.fs, &mac.bundle(), &config(&mac.world, "9.9.9"));
    let boot = bootstrap(&mac, V100);
    install(&mac, &boot).expect("install");
    let taken = mac
        .apps()
        .join(format!("Hello ({}).app", app_id().as_str()));
    assert_eq!(config_version(&mac.fs, &taken).as_deref(), Some(V100));
    assert_eq!(
        config_version(&mac.fs, &mac.bundle()).as_deref(),
        Some("9.9.9")
    );
    assert_eq!(mac.pointer(), taken.to_str().expect("utf-8"));
    common::workers_stopped();
}

#[test]
fn an_apps_folder_on_another_volume_or_that_cannot_be_written_writes_nothing() {
    let _serial = common::serial();
    for (what, reason, edit) in [
        (
            "another volume",
            LocationReason::OtherVolume,
            Box::new(|place: &mut MemPlace| place.device = 5) as Box<dyn Fn(&mut MemPlace)>,
        ),
        (
            "read only",
            LocationReason::ReadOnly,
            Box::new(|place: &mut MemPlace| place.read_only = true),
        ),
        (
            "not writable",
            LocationReason::NotWritable,
            Box::new(|place: &mut MemPlace| place.writable = false),
        ),
    ] {
        let mac = Mac::new();
        publish(&mac, 1, V100);
        let boot = bootstrap(&mac, V100);
        // `~` and the data home exist; the apps folder and the install root do not yet.
        mac.fs.create_dir_all(&mac.data_home()).expect("data home");
        let mut place = MemPlace::default();
        edit(&mut place);
        let home_place = MemPlace::default();
        mac.fs.set_place(&mac.home(), place);
        mac.fs.set_place(&mac.data_home(), home_place);
        let got = install(&mac, &boot);
        assert!(
            matches!(&got, Err(Error::UnsupportedLocation { reason: r }) if *r == reason),
            "{what}: {got:?}"
        );
        assert!(
            mac.fs
                .symlink_metadata(&mac.apps())
                .expect("lstat")
                .is_none(),
            "{what}: the apps folder was made"
        );
        assert!(
            mac.fs
                .symlink_metadata(mac.layout().root())
                .expect("lstat")
                .is_none(),
            "{what}: the install root was made"
        );
        common::workers_stopped();
    }
}

#[test]
fn an_install_whose_bundle_was_trashed_installs_again_and_keeps_the_floors() {
    let _serial = common::serial();
    let mac = Mac::new();
    publish(&mac, 1, V100);
    let boot = bootstrap(&mac, V100);
    install(&mac, &boot).expect("install");
    let before = mac.record();
    // The user drags the app to the Trash: the pointer dangles and no tree holds 1.0.0.
    mac.fs
        .remove_dir_all_nofollow(&mac.bundle())
        .expect("trash");

    publish(&mac, 2, V110);
    let boot = bootstrap(&mac, V110);
    let got = install(&mac, &boot).expect("reinstall");
    assert_eq!(got.version(), &version(V110));
    let rec = mac.record();
    assert_eq!(
        rec.current.as_ref().expect("current").version,
        version(V110)
    );
    assert_ne!(rec.install_id, before.install_id, "a new install id");
    assert!(rec.previous.is_none() && rec.pending.is_none() && rec.bad.is_empty());
    // Floors never go down: the old ones carry over and the new feed (seq 2) raised its own.
    assert_eq!(rec.floors.root, before.floors.root);
    assert_eq!(rec.floors.keyset_version, before.floors.keyset_version);
    for (channel, seq) in &before.floors.feed_seq {
        assert!(
            rec.floors
                .feed_seq
                .get(channel)
                .is_some_and(|now| now >= seq),
            "the feed seq floor went down"
        );
    }
    assert_eq!(
        config_version(&mac.fs, &mac.bundle()).as_deref(),
        Some(V110)
    );
    common::workers_stopped();
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

// ---- adoption of a dragged bundle (M8-D9 (b)) -----------------------------------------------------

/// Publishes each release of `versions` (manifest and pack) and a feed `seq` listing them all.
fn publish_all(mac: &Mac, seq: u64, versions: &[&str]) {
    let mut releases = Vec::new();
    for v in versions {
        let pack = release_pack(mac, v);
        let fx = &mac.world.fx;
        let manifest = fx.manifest_document(v, TARGET, &pack);
        let bytes = fx.envelope(PayloadKind::Manifest, &manifest.to_payload(), &[1]);
        let origin = &mac.world.origin;
        origin.put(
            &format!("{v}/{}.manifest.json", TARGET.as_str()),
            bytes.clone(),
        );
        origin.put(&format!("{v}/{}.pack", TARGET.as_str()), pack.bytes.clone());
        releases.push(fx.release(v, &[(TARGET, &bytes)], None));
    }
    mac.world.publish_feed(seq, releases);
}

/// Release `v` dragged to `at` exactly as released (a `.zip` extracted into an apps folder),
/// durably: every folder from the root down is synced, so a crash test's recovered disk has it.
fn drag(mac: &Mac, at: &Path, v: &str) {
    for (path, bytes) in release_files(mac, v) {
        let file = at.join(path);
        write_file(&mac.fs, &file, &bytes);
        for dir in file.ancestors().skip(1) {
            mac.fs.sync_dir(dir).expect("sync");
        }
    }
}

/// Everything under `dir` by relative path: its kind, and a file's bytes (nothing followed).
fn dump(fs: &dyn Fs, dir: &Path) -> Vec<(String, FileKind, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), String::new())];
    while let Some((d, prefix)) = stack.pop() {
        for e in fs.list_dir(&d).expect("list") {
            let name = e.name.to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let path = d.join(&e.name);
            let bytes = match e.kind {
                FileKind::File => fs.read_capped(&path, 1 << 20).expect("read"),
                FileKind::Dir => {
                    stack.push((path, rel.clone()));
                    Vec::new()
                }
                _ => Vec::new(),
            };
            out.push((rel, e.kind, bytes));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn updater_of(mac: &Mac, inst: &Installation) -> lunepack::Updater {
    inst.updater_builder()
        .expect("builder")
        .transport(Arc::clone(&mac.world.transport))
        .codec(Arc::new(FakeCodec::new()))
        .clock(Arc::clone(&mac.world.clock) as Arc<dyn lunepack_core::Clock>)
        .workers(2)
        .build()
        .expect("build")
}

fn check_with(
    mac: &Mac,
    inst: &Installation,
    options: CheckOptions,
) -> Result<CheckOutcome, Error> {
    block_on(updater_of(mac, inst).check_with(options))
}

fn record_at(fs: &MemFs, layout: &UserLayout) -> Option<InstallState> {
    UserScope {
        dir: layout.state_dir(),
        app_id: app_id(),
    }
    .load(fs, &FakeHasher)
    .expect("load")
    .record
}

fn pointer_at(fs: &MemFs, layout: &UserLayout) -> Option<String> {
    fs.read_link(&layout.root().join("bundle")).ok()
}

/// The end state of an adoption of `v` at `bundle` (M8-D9): the record names `v` current, the
/// pointer and the identity name `bundle`, the integration was applied to it, the bundle is
/// exactly the release, and the bundle is found installed. `events` are the lifecycle events
/// still queued or already delivered by a start.
fn assert_adopted(mac: &Mac, bundle: &Path, v: &str, events: &[LifecycleEvent]) {
    let layout = mac.layout();
    let rec = record_at(&mac.fs, &layout).expect("record");
    assert_eq!(rec.current.as_ref().expect("current").version, version(v));
    assert_eq!(
        events,
        [
            LifecycleEvent::Installed {
                version: version(v)
            },
            LifecycleEvent::FirstRun {
                version: version(v)
            },
        ]
    );
    assert_eq!(
        pointer_at(&mac.fs, &layout).as_deref(),
        bundle.to_str(),
        "the pointer names the bundle"
    );
    let facts = mac.fs.place(bundle).expect("place");
    assert_eq!(
        read_bundle_identity(&mac.fs, &layout).expect("identity"),
        Some((facts.device, facts.inode))
    );
    assert!(
        mac.integration
            .calls()
            .iter()
            .any(|c| c.op == IntegrationOp::Apply && c.install_root == bundle),
        "the integration is rooted at the bundle"
    );
    let mut want: Vec<(String, FileKind, Vec<u8>)> = release_files(mac, v)
        .into_iter()
        .map(|(p, b)| (p.to_owned(), FileKind::File, b))
        .collect();
    for d in ["Contents", "Contents/MacOS", "Contents/Resources"] {
        want.push((d.to_owned(), FileKind::Dir, Vec::new()));
    }
    want.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        dump(&mac.fs, bundle),
        want,
        "the bundle is the release, untouched"
    );
    let inst = mac.open(bundle, None).expect("installation");
    assert!(inst.is_installed() && !inst.adoptable() && !inst.moved());
}

fn queued(mac: &Mac) -> Vec<LifecycleEvent> {
    record_at(&mac.fs, &mac.layout())
        .and_then(|r| r.lifecycle)
        .map(|l| l.events)
        .unwrap_or_default()
}

#[test]
fn a_dragged_bundle_is_adopted_by_its_first_check_which_then_finds_the_update() {
    let _serial = common::serial();
    let mac = Mac::new();
    publish_all(&mac, 1, &[V100, V110]);
    drag(&mac, &mac.bundle(), V100);
    let inst = mac.open(&mac.bundle(), None).expect("installation");
    assert!(!inst.is_installed() && inst.adoptable());
    // Nothing was written by finding it.
    assert!(
        mac.fs
            .symlink_metadata(&mac.data_home())
            .unwrap_or(None)
            .is_none()
    );

    let phases = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = Arc::clone(&phases);
    let options = CheckOptions {
        progress: Some(Box::new(move |p| {
            seen.lock().expect("phases").push(p.clone())
        })),
        cancel: None,
    };
    let outcome = check_with(&mac, &inst, options).expect("check");
    assert!(outcome.adopted);
    assert_eq!(
        outcome.update.as_ref().map(|u| u.version().clone()),
        Some(version(V110)),
        "the same check reports the newer release"
    );
    let phases = phases.lock().expect("phases").clone();
    assert!(!phases.is_empty() && phases.iter().all(|p| p.phase == Phase::Adopt));
    let last = phases.last().expect("last");
    assert_eq!(last.done, last.total);
    assert_adopted(&mac, &mac.bundle(), V100, &queued(&mac));
    let rec = mac.record();
    assert!(rec.previous.is_none() && rec.pending.is_none());
    assert_eq!(rec.floors.feed_seq.get(&channel()), Some(&1));

    // The next start is an installed one and gets the install events; a later check is plain.
    let inst = mac.open(&mac.bundle(), None).expect("installation");
    let start = startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(start.events.len(), 2);
    let again = check_with(&mac, &inst, CheckOptions::default()).expect("check");
    assert!(!again.adopted);
    assert_eq!(
        again.update.map(|u| u.version().clone()),
        Some(version(V110))
    );
    common::workers_stopped();
}

#[test]
fn a_failed_adoption_leaves_the_bundle_alone_and_records_no_current_version() {
    let _serial = common::serial();
    type Setup = Box<dyn Fn(&Mac)>;
    type Want = Box<dyn Fn(&Error) -> bool>;
    let cases: Vec<(&str, Setup, Want)> = vec![
        (
            "transport failure",
            Box::new(|mac: &Mac| {
                publish_all(mac, 1, &[V100]);
                mac.world
                    .origin
                    .set_faults(vec![TransportFault::ErrorAfter(0)]);
            }),
            Box::new(|e| matches!(e, Error::Transport(_))),
        ),
        (
            "the bundle's version is not in the feed",
            Box::new(|mac: &Mac| publish_all(mac, 1, &[V110])),
            Box::new(|e| matches!(e, Error::NoRelease)),
        ),
        (
            "one file tampered with",
            Box::new(|mac: &Mac| {
                publish_all(mac, 1, &[V100]);
                let path = mac.bundle().join("Contents/Resources/share.txt");
                let mut bytes = b"shared".repeat(20);
                bytes[7] ^= 1;
                mac.fs.remove_file(&path).expect("remove");
                write_file(&mac.fs, &path, &bytes);
            }),
            Box::new(|e| matches!(e, Error::Verify(_))),
        ),
    ];
    for (what, setup, want) in cases {
        let mac = Mac::new();
        drag(&mac, &mac.bundle(), V100);
        setup(&mac);
        let before = dump(&mac.fs, &mac.bundle());
        let inst = mac.open(&mac.bundle(), None).expect("installation");
        assert!(inst.adoptable(), "{what}");
        let got = check_with(&mac, &inst, CheckOptions::default());
        assert!(got.as_ref().is_err_and(&want), "{what}: {got:?}");
        assert_eq!(
            dump(&mac.fs, &mac.bundle()),
            before,
            "{what}: the bundle changed"
        );
        let layout = mac.layout();
        assert!(
            record_at(&mac.fs, &layout).is_none_or(|r| r.current.is_none()),
            "{what}: a current version was recorded"
        );
        assert_eq!(pointer_at(&mac.fs, &layout), None, "{what}");
        assert_eq!(
            read_bundle_identity(&mac.fs, &layout).expect("id"),
            None,
            "{what}"
        );
        assert!(
            !mac.integration
                .calls()
                .iter()
                .any(|c| c.op == IntegrationOp::Apply),
            "{what}: the integration was applied"
        );
        // A development run, still adoptable by the next check.
        let again = mac.open(&mac.bundle(), None).expect("installation");
        assert!(!again.is_installed() && again.adoptable(), "{what}");
        common::workers_stopped();
    }
}

#[test]
fn an_orphaned_install_is_adopted_with_its_floors_and_a_new_install_id() {
    let _serial = common::serial();
    let mac = Mac::new();
    publish_all(&mac, 1, &[V100]);
    let boot = bootstrap(&mac, V100);
    install(&mac, &boot).expect("install");
    let before = mac.record();
    // The app goes to the Trash; a newer one is dragged into /Applications.
    mac.fs
        .remove_dir_all_nofollow(&mac.bundle())
        .expect("trash");
    publish_all(&mac, 2, &[V100, V110]);
    let other = PathBuf::from("/Applications/Hello.app");
    drag(&mac, &other, V110);
    let inst = mac.open(&other, None).expect("installation");
    assert!(inst.adoptable());
    let outcome = check_with(&mac, &inst, CheckOptions::default()).expect("check");
    assert!(outcome.adopted && outcome.update.is_none());
    assert_adopted(&mac, &other, V110, &queued(&mac));
    let rec = mac.record();
    assert_ne!(rec.install_id, before.install_id, "a new install id");
    assert!(rec.previous.is_none() && rec.pending.is_none() && rec.bad.is_empty());
    assert_eq!(rec.floors.root, before.floors.root);
    assert_eq!(rec.floors.keyset_version, before.floors.keyset_version);
    assert_eq!(rec.floors.feed_seq.get(&channel()), Some(&2));
    common::workers_stopped();
}

#[test]
fn an_orphaned_install_refuses_a_replayed_older_feed() {
    let _serial = common::serial();
    let mac = Mac::new();
    publish_all(&mac, 1, &[V100]);
    let old_feed = mac.world.feed_bytes();
    publish_all(&mac, 2, &[V100]);
    let boot = bootstrap(&mac, V100);
    install(&mac, &boot).expect("install");
    let before = mac.record();
    mac.fs
        .remove_dir_all_nofollow(&mac.bundle())
        .expect("trash");
    // A mirror replays the older feed, which still lists the dragged release.
    mac.world
        .origin
        .put(&format!("feed-{SUITE_CHANNEL}.json"), old_feed);
    let other = PathBuf::from("/Applications/Hello.app");
    drag(&mac, &other, V100);
    let inst = mac.open(&other, None).expect("installation");
    assert!(inst.adoptable());
    let got = check_with(&mac, &inst, CheckOptions::default());
    assert!(matches!(got, Err(Error::Verify(_))), "{got:?}");
    assert_eq!(mac.record(), before, "the orphaned record is untouched");
    assert_eq!(mac.pointer(), mac.bundle().to_str().expect("utf-8"));
    common::workers_stopped();
}

#[test]
fn a_live_install_makes_an_adoptable_copy_not_installed_with_no_request() {
    let _serial = common::serial();
    let mac = Mac::new();
    publish_all(&mac, 1, &[V100]);
    drag(&mac, &mac.bundle(), V100);
    let inst = mac.open(&mac.bundle(), None).expect("installation");
    assert!(inst.adoptable());
    // Meanwhile the app is installed by its installer (the dragged name is taken, so the live
    // bundle gets the other name).
    let boot = bootstrap(&mac, V100);
    install(&mac, &boot).expect("install");
    let live = mac
        .apps()
        .join(format!("Hello ({}).app", app_id().as_str()));
    assert_eq!(mac.pointer(), live.to_str().expect("utf-8"));
    let before = mac.record();
    let requests = mac.world.origin.requests().len();
    let dragged = dump(&mac.fs, &mac.bundle());

    let got = check_with(&mac, &inst, CheckOptions::default());
    assert!(matches!(got, Err(Error::NotInstalled)), "{got:?}");
    assert_eq!(mac.world.origin.requests().len(), requests, "no request");
    assert_eq!(mac.record(), before);
    assert_eq!(mac.pointer(), live.to_str().expect("utf-8"));
    assert_eq!(dump(&mac.fs, &mac.bundle()), dragged);
    // A new look finds the copy not installed and not adoptable.
    let again = mac.open(&mac.bundle(), None).expect("installation");
    assert!(!again.is_installed() && !again.adoptable());
    common::workers_stopped();
}

#[test]
fn an_install_committed_while_the_bundle_is_hashed_is_never_overwritten() {
    let _serial = common::serial();
    let mac = Mac::new();
    publish_all(&mac, 1, &[V100]);
    drag(&mac, &mac.bundle(), V100);
    let inst = mac.open(&mac.bundle(), None).expect("installation");
    // Another writer commits a live install while the proof runs (between the hashing and the
    // commit; the progress callback runs on the polling thread in between).
    let fs = mac.fs.clone();
    let layout = mac.layout();
    let injected = Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&injected);
    let options = CheckOptions {
        progress: Some(Box::new(move |_| {
            let mut slot = slot.lock().expect("slot");
            if slot.is_none() {
                let store = UserScope {
                    dir: layout.state_dir(),
                    app_id: app_id(),
                };
                let loaded = store.load(&fs, &FakeHasher).expect("load");
                let now = loaded.record.clone().expect("record");
                let live = lunepack_core::install_first(&now, version(V100), 10, INSTALL_ID)
                    .expect("install");
                *slot = Some(commit(&fs, &layout, &live));
            }
        })),
        cancel: None,
    };
    let got = check_with(&mac, &inst, options);
    assert!(matches!(got, Err(Error::NotInstalled)), "{got:?}");
    let injected = injected.lock().expect("slot").clone().expect("injected");
    assert_eq!(mac.record(), injected, "the other install's record stands");
    let layout = mac.layout();
    assert_eq!(pointer_at(&mac.fs, &layout), None);
    assert_eq!(read_bundle_identity(&mac.fs, &layout).expect("id"), None);
    assert!(
        !mac.integration
            .calls()
            .iter()
            .any(|c| c.op == IntegrationOp::Apply)
    );
    common::workers_stopped();
}

/// A crash at every write of the adopting check, under both recovery modes: the next start (an
/// install committed but not yet pointed at, found by its identity as moved) or the next check
/// (anything earlier: still adoptable) reaches the end state.
#[test]
fn a_crash_at_any_write_of_an_adoption_ends_adopted_after_the_next_start_or_check() {
    let _serial = common::serial();
    let world = |mac: &Mac| {
        publish_all(mac, 1, &[V100]);
        drag(mac, &mac.bundle(), V100);
    };
    // One clean run to learn how many writes it makes.
    let mac = Mac::new();
    world(&mac);
    let inst = mac.open(&mac.bundle(), None).expect("installation");
    let base = mac.fs.op_count();
    check_with(&mac, &inst, CheckOptions::default()).expect("check");
    let writes = mac.fs.op_count() - base;
    assert!(writes > 4, "{writes}");
    common::workers_stopped();

    let mut seen = std::collections::BTreeSet::new();
    for mode in [RecoverMode::DropVolatile, RecoverMode::KeepVolatile] {
        for n in 0..writes {
            let mac = Mac::new();
            world(&mac);
            let inst = mac.open(&mac.bundle(), None).expect("installation");
            mac.fs.crash_after(mac.fs.op_count() + n);
            let crashed = check_with(&mac, &inst, CheckOptions::default());
            assert!(crashed.is_err(), "write {n}: the crashed check succeeded");
            common::workers_stopped();
            let disk = mac.fs.recover(mode);
            let mac = mac.with_fs(disk);

            let inst = mac.open(&mac.bundle(), None).expect("installation");
            let (how, events) = if inst.moved() {
                let start = startup_for(&inst, Vec::new()).expect("next start");
                ("start", start.events)
            } else if inst.adoptable() {
                let outcome = check_with(&mac, &inst, CheckOptions::default())
                    .unwrap_or_else(|e| panic!("write {n}: next check: {e:?}"));
                assert!(outcome.adopted, "write {n}");
                ("check", queued(&mac))
            } else {
                assert!(inst.is_installed(), "write {n}");
                let start = startup_for(&inst, Vec::new()).expect("next start");
                ("installed", start.events)
            };
            seen.insert(how);
            assert_adopted(&mac, &mac.bundle(), V100, &events);
            common::workers_stopped();
        }
    }
    // Every path was taken: cut before the record (check), after it (start).
    assert!(seen.contains("check") && seen.contains("start"), "{seen:?}");
}

// ---- a bundle replaced at the live bundle's own path (M8-D16 amended, Revision 4) ----------------

const V120: &str = "1.2.0";

/// A live install of 1.0.0 (installed through the installer path), whose bundle the user then
/// replaced at its own path by release `v` (Finder's Replace: a new directory). Returns the
/// record before the replacement.
fn replaced_install(mac: &Mac, v: &str) -> InstallState {
    publish_all(mac, 1, &[V100]);
    let boot = bootstrap(mac, V100);
    install(mac, &boot).expect("install");
    let before = mac.record();
    mac.fs
        .remove_dir_all_nofollow(&mac.bundle())
        .expect("replace");
    drag(mac, &mac.bundle(), v);
    before
}

fn applies(mac: &Mac) -> usize {
    mac.integration
        .calls()
        .iter()
        .filter(|c| c.op == IntegrationOp::Apply)
        .count()
}

#[test]
fn a_bundle_replaced_by_a_newer_release_starts_and_is_adopted_by_its_first_check() {
    let _serial = common::serial();
    let mac = Mac::new();
    let before = replaced_install(&mac, V110);
    let pointer = mac.pointer();
    publish_all(&mac, 2, &[V100, V110, V120]);
    let inst = mac.open(&mac.bundle(), None).expect("installation");
    assert!(!inst.is_installed() && inst.adoptable());
    // The start no longer fails: a development run until the check adopts it.
    let start = startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(start.action, StartupAction::Continue);
    assert!(start.events.is_empty());
    assert_eq!(
        updater_of(&mac, &inst).installed().expect("installed"),
        None
    );

    let applied_before = applies(&mac);
    let outcome = check_with(&mac, &inst, CheckOptions::default()).expect("check");
    assert!(outcome.adopted);
    assert_eq!(
        outcome.update.map(|u| u.version().clone()),
        Some(version(V120)),
        "the same check finds the newer release"
    );
    assert_adopted(&mac, &mac.bundle(), V110, &queued(&mac));
    assert!(
        applies(&mac) > applied_before,
        "the integration was applied"
    );
    let rec = mac.record();
    assert_ne!(rec.install_id, before.install_id, "a new install id");
    assert_eq!(rec.floors.root, before.floors.root);
    assert_eq!(rec.floors.keyset_version, before.floors.keyset_version);
    assert_eq!(rec.floors.feed_seq.get(&channel()), Some(&2));
    assert_eq!(mac.pointer(), pointer, "R/bundle unchanged");

    let inst = mac.open(&mac.bundle(), None).expect("installation");
    assert!(inst.is_installed());
    let again = check_with(&mac, &inst, CheckOptions::default()).expect("check");
    assert!(!again.adopted);
    assert_eq!(
        again.update.map(|u| u.version().clone()),
        Some(version(V120))
    );
    common::workers_stopped();
}

#[test]
fn a_replaced_bundle_that_does_not_verify_is_left_alone() {
    let _serial = common::serial();
    let mac = Mac::new();
    let before = replaced_install(&mac, V110);
    let path = mac.bundle().join("Contents/Resources/share.txt");
    let mut bytes = b"shared".repeat(20);
    bytes[3] ^= 1;
    mac.fs.remove_file(&path).expect("remove");
    write_file(&mac.fs, &path, &bytes);
    publish_all(&mac, 2, &[V100, V110]);
    let dragged = dump(&mac.fs, &mac.bundle());
    let inst = mac.open(&mac.bundle(), None).expect("installation");
    let got = check_with(&mac, &inst, CheckOptions::default());
    assert!(matches!(got, Err(Error::Verify(_))), "{got:?}");
    let rec = mac.record();
    assert_eq!(rec.current, before.current, "the old current stands");
    assert_eq!(rec.install_id, before.install_id);
    assert_eq!(
        dump(&mac.fs, &mac.bundle()),
        dragged,
        "the bundle is untouched"
    );
    // Still a development run that starts.
    let inst = mac.open(&mac.bundle(), None).expect("installation");
    assert!(!inst.is_installed() && inst.adoptable());
    let start = startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(start.action, StartupAction::Continue);
    common::workers_stopped();
}

#[test]
fn a_same_version_copy_dragged_back_is_installed_with_no_request() {
    let _serial = common::serial();
    let mac = Mac::new();
    let before = replaced_install(&mac, V100);
    let requests = mac.world.origin.requests().len();
    let inst = mac.open(&mac.bundle(), None).expect("installation");
    assert!(inst.is_installed() && !inst.adoptable());
    startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(mac.world.origin.requests().len(), requests, "no request");
    let rec = mac.record();
    assert_eq!(rec.install_id, before.install_id, "no adoption");
    assert_eq!(rec.current, before.current);
    // The start's reconcile recorded the new directory.
    let facts = mac.fs.place(&mac.bundle()).expect("place");
    assert_eq!(
        read_bundle_identity(&mac.fs, &mac.layout()).expect("identity"),
        Some((facts.device, facts.inode))
    );
    common::workers_stopped();
}

#[test]
fn a_replaced_bundle_whose_install_finishes_meanwhile_is_never_overwritten() {
    let _serial = common::serial();
    let mac = Mac::new();
    replaced_install(&mac, V110);
    // The same feed sequence: no floor rises, so the record is byte for byte what it was.
    publish_all(&mac, 1, &[V100, V110]);
    let before = mac.record();
    let dragged = dump(&mac.fs, &mac.bundle());
    let inst = mac.open(&mac.bundle(), None).expect("installation");
    assert!(inst.adoptable());
    // While the bundle is hashed, a tree holding the record's current version appears in
    // `versions` (an update of the install finishing its swap): the install is not replaced any
    // more.
    let fs = mac.fs.clone();
    let tree = mac.layout().version_dir(&version(V100));
    let cfg = config(&mac.world, V100);
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&done);
    let options = CheckOptions {
        progress: Some(Box::new(move |_| {
            if !flag.swap(true, std::sync::atomic::Ordering::SeqCst) {
                write_bundle(&fs, &tree, &cfg);
            }
        })),
        cancel: None,
    };
    let got = check_with(&mac, &inst, options);
    assert!(
        done.load(std::sync::atomic::Ordering::SeqCst),
        "the hook ran"
    );
    assert!(matches!(got, Err(Error::NotInstalled)), "{got:?}");
    assert_eq!(mac.record(), before, "the record is unchanged");
    assert_eq!(
        dump(&mac.fs, &mac.bundle()),
        dragged,
        "the bundle is unchanged"
    );
    common::workers_stopped();
}

/// A crash at every write of the adopting check of a replaced bundle, under both recovery modes:
/// the next check (cuts before the record) or the next start (after it: `Installed` by version)
/// reaches the end state.
#[test]
fn a_crash_at_any_write_of_a_replaced_bundles_adoption_ends_adopted() {
    let _serial = common::serial();
    let world = |mac: &Mac| {
        let before = replaced_install(mac, V110);
        publish_all(mac, 2, &[V100, V110]);
        before
    };
    let mac = Mac::new();
    world(&mac);
    let inst = mac.open(&mac.bundle(), None).expect("installation");
    let base = mac.fs.op_count();
    check_with(&mac, &inst, CheckOptions::default()).expect("check");
    let writes = mac.fs.op_count() - base;
    assert!(writes > 4, "{writes}");
    common::workers_stopped();

    let mut seen = std::collections::BTreeSet::new();
    for mode in [RecoverMode::DropVolatile, RecoverMode::KeepVolatile] {
        for n in 0..writes {
            let mac = Mac::new();
            let before = world(&mac);
            let inst = mac.open(&mac.bundle(), None).expect("installation");
            assert!(inst.adoptable(), "write {n}");
            mac.fs.crash_after(mac.fs.op_count() + n);
            let crashed = check_with(&mac, &inst, CheckOptions::default());
            assert!(crashed.is_err(), "write {n}: the crashed check succeeded");
            common::workers_stopped();
            let disk = mac.fs.recover(mode);
            let mac = mac.with_fs(disk);

            let inst = mac.open(&mac.bundle(), None).expect("installation");
            let (how, events) = if inst.adoptable() {
                let outcome = check_with(&mac, &inst, CheckOptions::default())
                    .unwrap_or_else(|e| panic!("write {n}: next check: {e:?}"));
                assert!(outcome.adopted, "write {n}");
                ("check", queued(&mac))
            } else {
                assert!(inst.is_installed() && !inst.moved(), "write {n}");
                let start = startup_for(&inst, Vec::new())
                    .unwrap_or_else(|e| panic!("write {n}: next start: {e:?}"));
                ("start", start.events)
            };
            seen.insert(how);
            assert_adopted(&mac, &mac.bundle(), V110, &events);
            assert_ne!(mac.record().install_id, before.install_id, "write {n}");
            common::workers_stopped();
        }
    }
    assert!(seen.contains("check") && seen.contains("start"), "{seen:?}");
}
