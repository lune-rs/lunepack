//! The app-facing lifecycle (M5 step 7): finding the installation from an executable, the feed
//! rule at use, `startup`, `confirm`, `apply_and_restart` and the first install.
//!
//! Records are written by the core's real writer and transitions (`install`, `set_staged`,
//! `apply`), trees and configs by the real update-config writer, on a `MemFs` (or a real
//! temporary directory) with the testkit's fake process, integration, hasher, verifier and RNG.
//! The http cases re-run this test binary as a child process whose environment names proxies, so
//! the parent's environment is never touched.

mod common;

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use common::{INSTALL_ID, TARGET, World, app_id, channel, files, sha, version};
use lunepack::{
    ApplyOptions, ConfirmOutcome, DownloadOptions, Error, HEALTH_TOKEN_VAR, Installation, Layout,
    LifecycleEvent, Platform, StartupAction, UpdateConfigError, apply_and_restart_for, block_on,
    confirm_for, startup_for,
};
use lunepack_core::state::{InstallState, Scope, StagedIssued, StagedRef, UserScope};
use lunepack_core::{
    CodecId, FeedRule, Fs, InstallMeta, ProcessId, RelPath, TrustedRoot, UpdateConfig,
};
use lunepack_testkit::{
    FakeCodec, FakeHasher, FakeIntegration, FakeProcess, FakeRng, FakeVerifier, IntegrationOp,
    MemFs, PackBuilder, abs_path,
};

const DATA_HOME: &str = "/home/u/.local/share";
const V100: &str = "1.0.0";
const V110: &str = "1.1.0";
/// The update config's feed: the fake origin serves any host, and the config rule wants https.
const FEED: &str = "https://fake.invalid/";
const TOKEN: [u8; 32] = [0x5c; 32];

fn token_hex(raw: &[u8; 32]) -> OsString {
    raw.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        .into()
}

/// Test paths are written in POSIX form and made absolute on this platform with `abs_path` (on
/// Windows `/a` has no drive and is not absolute, so discovery would find no candidate).
fn root_dir() -> PathBuf {
    abs_path(DATA_HOME).join(app_id().as_str())
}

fn meta(entry: &str, bin: Option<&str>, name: &str) -> InstallMeta {
    InstallMeta {
        entry: RelPath::parse(entry).expect("entry"),
        name: name.to_owned(),
        comment: None,
        icon: None,
        categories: Vec::new(),
        bin: bin.map(str::to_owned),
        terminal: false,
    }
}

fn config(root: &TrustedRoot, v: &str, feed: &str, install: InstallMeta) -> UpdateConfig {
    UpdateConfig::new(root, version(v), TARGET, feed, channel(), 60, install).expect("config")
}

fn write_file(fs: &dyn Fs, path: &Path, bytes: &[u8]) {
    fs.create_dir_all(path.parent().expect("parent"))
        .expect("dirs");
    let mut w = fs.create_new(path).expect("create");
    w.write_all(bytes).expect("write");
    w.sync().expect("sync");
}

/// A version tree at `dir`: the release files and the config.
fn write_tree(fs: &dyn Fs, dir: &Path, cfg: &UpdateConfig) {
    for (path, bytes) in files(&cfg.version.to_string()) {
        write_file(fs, &dir.join(path), &bytes);
    }
    write_file(
        fs,
        &dir.join("lunepack-update.json"),
        &cfg.to_bytes().expect("bytes"),
    );
}

/// Commits `f(the loaded record)` into `root/state` with the core's writer.
fn commit(
    fs: &dyn Fs,
    root: &Path,
    f: impl FnOnce(Option<&InstallState>) -> InstallState,
) -> InstallState {
    let store = UserScope {
        dir: root.join("state"),
        app_id: app_id(),
    };
    let loaded = store.load(fs, &FakeHasher).expect("load");
    let next = f(loaded.record.as_ref());
    store
        .commit(fs, &loaded, &next, &FakeHasher)
        .expect("commit")
}

fn record(fs: &dyn Fs, root: &Path) -> Option<InstallState> {
    UserScope {
        dir: root.join("state"),
        app_id: app_id(),
    }
    .load(fs, &FakeHasher)
    .expect("load")
    .record
}

fn installed_100() -> InstallState {
    InstallState::new(1, app_id(), Scope::User, INSTALL_ID, TARGET).install(
        version(V100),
        10,
        TARGET,
        INSTALL_ID,
    )
}

fn staged_ref(v: &str) -> StagedRef {
    StagedRef::new(version(v), TARGET, sha(format!("manifest {v}").as_bytes()))
}

/// An install with 1.0.0 current and 1.1.0 applied (pending, its token's digest recorded).
fn pending_110() -> InstallState {
    let staged = installed_100().set_staged(Some((staged_ref(V110), 20)));
    lunepack_core::apply(&staged, &version(V110), sha(&TOKEN)).expect("apply")
}

/// One install under `R` on a `MemFs`, with fakes for everything else.
struct Lab {
    world: World,
    fs: MemFs,
    process: FakeProcess,
    integration: FakeIntegration,
}

impl Lab {
    fn new() -> Lab {
        let world = World::new();
        let fs = world.fs.clone();
        Lab {
            world,
            fs,
            process: FakeProcess::new("/unused"),
            integration: FakeIntegration::new(),
        }
    }

    fn root(&self) -> TrustedRoot {
        self.world.root()
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
            .with_data_home(abs_path(DATA_HOME))
            .with_busy_wait(Duration::from_millis(300))
    }

    /// Writes `R/versions/<v>` with entry `bin/app` and command link `bin`.
    fn version_tree(&self, v: &str, bin: &str) -> PathBuf {
        let dir = root_dir().join("versions").join(v);
        let cfg = config(
            &self.root(),
            v,
            FEED,
            meta("bin/app", Some(bin), &format!("App {v}")),
        );
        write_tree(&self.fs, &dir, &cfg);
        dir
    }

    fn open(&self, v: &str, token: Option<OsString>) -> Installation {
        let exe = root_dir().join("versions").join(v).join("bin/app");
        Installation::from_exe_with(&exe, self.platform(token)).expect("installation")
    }

    fn record(&self) -> InstallState {
        record(&self.fs, &root_dir()).expect("record")
    }

    fn current_link(&self) -> String {
        self.fs
            .read_link(&root_dir().join("current"))
            .expect("current link")
    }
}

// ---- discovery -----------------------------------------------------------------------------------

#[test]
fn an_installed_tree_is_found_from_its_entry_with_its_layout() {
    let lab = Lab::new();
    lab.version_tree(V100, "app");
    commit(&lab.fs, &root_dir(), |_| installed_100());
    let inst = lab.open(V100, None);
    assert!(inst.is_installed());
    assert_eq!(inst.app_id(), &app_id());
    assert_eq!(inst.tree_version(), &version(V100));
    let tree = root_dir().join("versions").join(V100);
    assert_eq!(inst.tree_root(), tree);
    assert_eq!(inst.layout().expect("layout").root(), root_dir());
    assert_eq!(inst.install_root().expect("root"), root_dir());
    assert_eq!(inst.entry_path(), tree.join("bin/app"));
    assert_eq!(inst.runtime_path(), tree.join("bin/lunepack-runtime"));
    assert_eq!(inst.meta().name, "App 1.0.0");
}

#[test]
fn a_tree_outside_an_install_is_not_installed_and_installs_under_the_data_home() {
    let lab = Lab::new();
    let tree = abs_path("/media/boot/app-1.0.0");
    let cfg = config(&lab.root(), V100, FEED, meta("bin/app", None, "App"));
    write_tree(&lab.fs, &tree, &cfg);
    let inst = Installation::from_exe_with(&tree.join("bin/app"), lab.platform(None))
        .expect("installation");
    assert!(!inst.is_installed());
    assert!(inst.layout().is_none());
    assert_eq!(inst.install_root().expect("root"), root_dir());
}

#[test]
fn no_config_up_the_tree_is_no_update_config() {
    let lab = Lab::new();
    let exe = abs_path("/opt/dev/bin/app");
    write_file(&lab.fs, &exe, b"app");
    let got = Installation::from_exe_with(&exe, lab.platform(None));
    assert!(matches!(got, Err(Error::NoUpdateConfig)), "{got:?}");
}

#[test]
fn the_entry_and_the_runtime_beside_it_find_the_same_tree() {
    let lab = Lab::new();
    for (entry, dir) in [("app", ""), ("bin/app", "bin")] {
        let tree = abs_path(&format!("/t/{}", entry.replace('/', "-")));
        let cfg = config(&lab.root(), V100, FEED, meta(entry, None, "App"));
        write_tree(&lab.fs, &tree, &cfg);
        for exe in [entry.to_owned(), format!("{dir}/lunepack-runtime")] {
            let exe = tree.join(exe.trim_start_matches('/'));
            let inst = Installation::from_exe_with(&exe, lab.platform(None))
                .unwrap_or_else(|e| panic!("{entry} from {exe:?}: {e}"));
            assert_eq!(inst.tree_root(), tree, "{entry}");
            assert_eq!(inst.runtime_path(), tree.join(dir).join("lunepack-runtime"));
        }
    }
}

#[test]
fn a_config_that_is_a_directory_or_a_symlink_is_refused_where_it_is_found() {
    let lab = Lab::new();
    let tree = abs_path("/t/dir");
    lab.fs
        .create_dir_all(&tree.join("lunepack-update.json"))
        .expect("dir");
    write_file(&lab.fs, &tree.join("app"), b"app");
    let got = Installation::from_exe_with(&tree.join("app"), lab.platform(None));
    assert!(matches!(got, Err(Error::UpdateConfig(_))), "{got:?}");

    let tree = abs_path("/t/link");
    let cfg = config(&lab.root(), V100, FEED, meta("app", None, "App"));
    write_file(
        &lab.fs,
        &abs_path("/elsewhere/cfg.json"),
        &cfg.to_bytes().expect("bytes"),
    );
    lab.fs.create_dir_all(&tree).expect("dir");
    lab.fs
        .replace_symlink("/elsewhere/cfg.json", &tree.join("lunepack-update.json"))
        .expect("link");
    let got = Installation::from_exe_with(&tree.join("app"), lab.platform(None));
    assert!(matches!(got, Err(Error::UpdateConfig(_))), "{got:?}");
}

#[test]
fn a_nested_config_found_first_decides_and_the_outer_one_is_never_used() {
    let lab = Lab::new();
    let outer = abs_path("/t/outer");
    let cfg = config(&lab.root(), V100, FEED, meta("bin/app", None, "App"));
    write_tree(&lab.fs, &outer, &cfg);
    // A foreign config beside the entry: it names an entry the exe is not in.
    write_file(
        &lab.fs,
        &outer.join("bin/lunepack-update.json"),
        &cfg.to_bytes().expect("bytes"),
    );
    let got = Installation::from_exe_with(&outer.join("bin/app"), lab.platform(None));
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
    // And one the reader refuses.
    lab.fs
        .remove_file(&outer.join("bin/lunepack-update.json"))
        .expect("remove");
    write_file(&lab.fs, &outer.join("bin/lunepack-update.json"), b"{}");
    let got = Installation::from_exe_with(&outer.join("bin/app"), lab.platform(None));
    assert!(matches!(got, Err(Error::UpdateConfig(_))), "{got:?}");
}

#[test]
fn an_installed_tree_whose_state_belongs_to_another_app_is_refused() {
    let lab = Lab::new();
    lab.version_tree(V100, "app");
    let other = lunepack_core::AppId::parse("org.example.other").expect("id");
    let store = UserScope {
        dir: root_dir().join("state"),
        app_id: other.clone(),
    };
    let loaded = store.load(&lab.fs, &FakeHasher).expect("load");
    let rec = InstallState::new(1, other, Scope::User, INSTALL_ID, TARGET);
    store
        .commit(&lab.fs, &loaded, &rec, &FakeHasher)
        .expect("commit");
    let exe = root_dir().join("versions").join(V100).join("bin/app");
    assert!(Installation::from_exe_with(&exe, lab.platform(None)).is_err());
}

#[test]
fn another_version_is_opened_from_its_own_config() {
    let lab = Lab::new();
    lab.version_tree(V100, "app");
    lab.version_tree(V110, "app");
    commit(&lab.fs, &root_dir(), |_| installed_100());
    let inst = lab.open(V100, None);
    let other = inst.version_installation(&version(V110)).expect("1.1.0");
    assert_eq!(other.tree_version(), &version(V110));
    assert_eq!(
        other.entry_path(),
        root_dir().join("versions/1.1.0/bin/app")
    );
    assert!(matches!(
        inst.version_installation(&version("2.0.0")),
        Err(Error::NoUpdateConfig)
    ));
}

// ---- the feed rule at use ------------------------------------------------------------------------

#[test]
fn a_config_whose_feed_was_edited_to_a_plain_http_host_is_refused_before_any_request() {
    let lab = Lab::new();
    let tree = abs_path("/t/edited");
    let cfg = config(&lab.root(), V100, FEED, meta("app", None, "App"));
    write_tree(&lab.fs, &tree, &cfg);
    // The written document, with its feed member edited.
    let mut doc: serde_json::Value =
        serde_json::from_slice(&cfg.to_bytes().expect("bytes")).expect("json");
    doc["feed"] = serde_json::Value::String("http://10.0.0.1/".to_owned());
    lab.fs
        .remove_file(&tree.join("lunepack-update.json"))
        .expect("remove");
    write_file(
        &lab.fs,
        &tree.join("lunepack-update.json"),
        &serde_json::to_vec(&doc).expect("json"),
    );
    lab.world.origin.clear_requests();
    let got = Installation::from_exe_with(&tree.join("app"), lab.platform(None))
        .and_then(|inst| inst.updater_builder());
    assert!(
        matches!(
            got,
            Err(Error::UpdateConfig(UpdateConfigError::Feed(
                FeedRule::HttpNotLoopback
            )))
        ),
        "{:?}",
        got.err()
    );
    assert!(lab.world.origin.requests().is_empty(), "no request");
}

#[test]
fn the_builder_takes_root_feed_and_channel_from_the_config() {
    let lab = Lab::new();
    lab.version_tree(V100, "app");
    commit(&lab.fs, &root_dir(), |_| installed_100());
    let updater = lab
        .open(V100, None)
        .updater_builder()
        .expect("builder")
        .transport(Arc::clone(&lab.world.transport))
        .clock(Arc::clone(&lab.world.clock) as Arc<dyn lunepack_core::Clock>)
        .build()
        .expect("build");
    lab.world.publish(1, V110);
    lab.world.origin.clear_requests();
    let info = block_on(updater.check()).expect("check").expect("update");
    assert_eq!(info.version(), &version(V110));
    let urls: Vec<String> = lab
        .world
        .origin
        .requests()
        .into_iter()
        .map(|r| r.url)
        .collect();
    assert!(urls.contains(&"/feed-stable.json".to_owned()), "{urls:?}");
}

// ---- the http feed: no proxy, no redirect (child processes) --------------------------------------

const CHILD_VAR: &str = "LUNEPACK_LIFECYCLE_CHILD";
const PROXY_VARS: &[&str] = &[
    "ALL_PROXY",
    "all_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// A loopback HTTP server answering `response` to every request until `stop`; returns the
/// number of requests it saw.
fn serve(response: String) -> (u16, Arc<AtomicBool>, thread::JoinHandle<usize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut seen = 0;
        while !flag.load(Ordering::SeqCst) && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).expect("blocking");
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .expect("timeout");
                    let mut head = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    seen += 1;
                    let _ = stream.write_all(response.as_bytes());
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept: {e}"),
            }
        }
        seen
    });
    (port, stop, handle)
}

fn closed_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

/// On a real temporary directory: an installed 1.0.0 whose config feed is `feed`. Returns the
/// entry's path.
fn real_install(dir: &Path, feed: &str) -> PathBuf {
    let fs = lunepack_fs::StdFs::new();
    let root = dir.join("data").join(app_id().as_str());
    let world_root = World::new().root();
    let tree = root.join("versions").join(V100);
    write_tree(
        &fs,
        &tree,
        &config(&world_root, V100, feed, meta("bin/app", None, "App")),
    );
    commit(&fs, &root, |_| installed_100());
    tree.join("bin/app")
}

/// The child half: opens the installation at `$LUNEPACK_LIFECYCLE_CHILD`'s path and checks.
fn child_check(exe: &str) {
    let platform = Platform::native()
        .with_hasher(Arc::new(FakeHasher))
        .with_verifier(Arc::new(FakeVerifier));
    let inst = Installation::from_exe_with(Path::new(exe), platform).expect("installation");
    let updater = inst
        .updater_builder()
        .expect("builder")
        .build()
        .expect("build");
    let got = block_on(updater.check());
    println!("child-check-done ok={}", got.is_ok());
}

/// Runs `test` of this binary as a child with `exe` to open and every proxy variable naming a
/// closed port.
fn run_child(test: &str, exe: &Path) -> String {
    let dead = format!("http://127.0.0.1:{}", closed_port());
    let mut cmd = Command::new(std::env::current_exe().expect("exe"));
    cmd.args([test, "--exact", "--nocapture", "--test-threads=1"]);
    for var in PROXY_VARS {
        cmd.env_remove(var);
    }
    for var in ["ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "http_proxy"] {
        cmd.env(var, &dead);
    }
    cmd.env(CHILD_VAR, exe);
    let out = cmd.output().expect("child");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success(), "child failed");
    assert!(stdout.contains("child-check-done"), "child did not check");
    stdout
}

#[test]
fn an_http_loopback_feed_is_fetched_with_no_proxy() {
    if let Some(exe) = std::env::var_os(CHILD_VAR) {
        return child_check(exe.to_str().expect("utf-8"));
    }
    let tmp = tempfile::tempdir().expect("tmp");
    let dir = std::fs::canonicalize(tmp.path()).expect("canonical");
    let (port, stop, server) = serve(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
    );
    let exe = real_install(&dir, &format!("http://127.0.0.1:{port}/r/"));
    run_child("an_http_loopback_feed_is_fetched_with_no_proxy", &exe);
    stop.store(true, Ordering::SeqCst);
    // root-2.json (404 ends the root walk), then keys.json (404 fails the check).
    assert_eq!(
        server.join().expect("server"),
        2,
        "the requests reached the feed"
    );
}

#[test]
fn an_http_loopback_feed_follows_no_redirect() {
    if let Some(exe) = std::env::var_os(CHILD_VAR) {
        return child_check(exe.to_str().expect("utf-8"));
    }
    let tmp = tempfile::tempdir().expect("tmp");
    let dir = std::fs::canonicalize(tmp.path()).expect("canonical");
    let (target, stop_target, target_server) = serve(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
    );
    let (port, stop, server) = serve(format!(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{target}/r/root-2.json\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    ));
    let exe = real_install(&dir, &format!("http://127.0.0.1:{port}/r/"));
    let out = run_child("an_http_loopback_feed_follows_no_redirect", &exe);
    stop.store(true, Ordering::SeqCst);
    stop_target.store(true, Ordering::SeqCst);
    assert!(out.contains("ok=false"), "a 302 fails the check");
    assert_eq!(server.join().expect("server"), 1);
    assert_eq!(
        target_server.join().expect("target"),
        0,
        "no redirect followed"
    );
}

// ---- startup -------------------------------------------------------------------------------------

#[test]
fn unsupervised_starts_count_attempts_and_the_fourth_rolls_back() {
    let lab = Lab::new();
    lab.version_tree(V100, "app");
    lab.version_tree(V110, "app2");
    commit(&lab.fs, &root_dir(), |_| pending_110());
    let args: Vec<OsString> = vec!["--open".into(), "a file.txt".into()];
    for n in 1..=3u64 {
        let got = startup_for(&lab.open(V110, None), args.clone()).expect("startup");
        assert_eq!(got.action, StartupAction::Continue, "start {n}");
        assert!(got.pending);
        assert_eq!(lab.record().pending.expect("pending").attempts, n);
        assert_eq!(lab.current_link(), "versions/1.1.0");
    }
    assert!(lab.process.spawns().is_empty());

    let got = startup_for(&lab.open(V110, None), args.clone()).expect("startup");
    assert_eq!(got.action, StartupAction::Exit);
    assert!(got.events.is_empty());
    let rec = lab.record();
    assert_eq!(rec.current.expect("current").version, version(V100));
    assert!(rec.pending.is_none() && rec.health.is_none());
    assert_eq!(rec.bad, vec![version(V110)]);
    assert_eq!(lab.current_link(), "versions/1.0.0");

    let spawns = lab.process.spawns();
    assert_eq!(spawns.len(), 1);
    let spawn = &spawns[0];
    assert!(spawn.detached);
    assert_eq!(spawn.program, root_dir().join("versions/1.0.0/bin/app"));
    assert_eq!(spawn.args, args);
    assert!(spawn.env_set.is_empty(), "no token is set");
    assert_eq!(spawn.env_remove, vec![OsString::from(HEALTH_TOKEN_VAR)]);

    let applied: Vec<_> = lab
        .integration
        .calls()
        .into_iter()
        .filter(|c| c.op == IntegrationOp::Apply)
        .collect();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].meta.name, "App 1.0.0");
    assert_eq!(applied[0].install_root, root_dir());
    assert_eq!(applied[0].stale_bins, vec!["app2".to_owned()]);
}

/// Three unsupervised starts of 1.1.0, so the next one rolls back.
fn three_attempts(lab: &Lab) {
    for _ in 1..=3u64 {
        startup_for(&lab.open(V110, None), Vec::new()).expect("startup");
    }
}

#[test]
fn a_rollback_to_a_previous_version_whose_config_is_gone_commits_nothing() {
    let lab = Lab::new();
    let old = lab.version_tree(V100, "app");
    lab.version_tree(V110, "app");
    commit(&lab.fs, &root_dir(), |_| pending_110());
    three_attempts(&lab);
    let before = lab.record();
    lab.fs
        .remove_file(&old.join("lunepack-update.json"))
        .expect("remove config");

    let got = startup_for(&lab.open(V110, None), Vec::new());
    assert!(
        matches!(got, Err(Error::RollbackUnavailable)),
        "{:?}",
        got.map(|s| s.action)
    );
    assert_eq!(lab.record(), before, "nothing committed, still pending");
    assert_eq!(lab.current_link(), "versions/1.1.0");
    assert!(lab.process.spawns().is_empty());
    assert!(
        lab.integration
            .calls()
            .iter()
            .all(|c| c.op != IntegrationOp::Apply)
    );
}

#[test]
fn a_rollback_whose_relaunch_and_refresh_fail_still_exits_rolled_back() {
    let lab = Lab::new();
    lab.version_tree(V100, "app");
    lab.version_tree(V110, "app");
    commit(&lab.fs, &root_dir(), |_| pending_110());
    three_attempts(&lab);
    lab.process
        .fail_spawns(Some(lunepack_core::ProcessErrorKind::SpawnFailed));
    lab.integration.script_failure(Some("disk"));

    let got = startup_for(&lab.open(V110, None), Vec::new()).expect("startup");
    assert_eq!(got.action, StartupAction::Exit);
    let rec = lab.record();
    assert_eq!(rec.current.expect("current").version, version(V100));
    assert_eq!(rec.bad, vec![version(V110)]);
    assert_eq!(lab.current_link(), "versions/1.0.0");
}

#[test]
fn a_supervised_start_counts_nothing_and_a_malformed_token_counts() {
    let lab = Lab::new();
    lab.version_tree(V100, "app");
    lab.version_tree(V110, "app");
    commit(&lab.fs, &root_dir(), |_| pending_110());
    let got = startup_for(&lab.open(V110, Some(token_hex(&TOKEN))), Vec::new()).expect("start");
    assert!(got.pending);
    assert_eq!(lab.record().pending.expect("pending").attempts, 0);
    for bad in ["nothex", &"A".repeat(64)] {
        startup_for(&lab.open(V110, Some(bad.into())), Vec::new()).expect("start");
    }
    assert_eq!(lab.record().pending.expect("pending").attempts, 2);
}

#[test]
fn startup_delivers_this_versions_events_once() {
    let lab = Lab::new();
    lab.version_tree(V100, "app");
    lab.version_tree(V110, "app");
    commit(&lab.fs, &root_dir(), |_| pending_110());
    // The old version gets none of the new one's events.
    let old = startup_for(&lab.open(V100, None), Vec::new()).expect("old start");
    assert!(old.events.is_empty() && !old.pending);

    let first = startup_for(&lab.open(V110, Some(token_hex(&TOKEN))), Vec::new()).expect("start");
    assert_eq!(
        first.events,
        vec![
            LifecycleEvent::Updated {
                from: version(V100),
                to: version(V110),
            },
            LifecycleEvent::FirstRun {
                version: version(V110),
            },
        ]
    );
    let again = startup_for(&lab.open(V110, Some(token_hex(&TOKEN))), Vec::new()).expect("start");
    assert!(again.events.is_empty());
    assert!(lab.record().lifecycle.is_none());
}

#[test]
fn a_tree_that_is_not_installed_continues_with_nothing() {
    let lab = Lab::new();
    let tree = abs_path("/media/boot/app");
    write_tree(
        &lab.fs,
        &tree,
        &config(&lab.root(), V100, FEED, meta("bin/app", None, "App")),
    );
    let inst =
        Installation::from_exe_with(&tree.join("bin/app"), lab.platform(None)).expect("inst");
    let got = startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(got.action, StartupAction::Continue);
    assert!(got.events.is_empty() && !got.pending);
    assert_eq!(
        confirm_for(&inst).expect("confirm"),
        ConfirmOutcome::NothingPending
    );
}

#[test]
fn a_held_lock_is_retried_for_the_busy_wait_then_busy() {
    let lab = Lab::new();
    lab.version_tree(V100, "app");
    commit(&lab.fs, &root_dir(), |_| installed_100());
    let other = lab.fs.process();
    let guard = other
        .try_lock(&root_dir().join("state/lock"))
        .expect("lock")
        .expect("free");
    let started = Instant::now();
    let got = startup_for(&lab.open(V100, None), Vec::new());
    let waited = started.elapsed();
    assert!(matches!(got, Err(Error::Busy)), "{got:?}");
    assert!(waited >= Duration::from_millis(300), "{waited:?}");
    assert!(waited < Duration::from_secs(2), "{waited:?}");

    // Released while it retries: the call goes through.
    let release = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        drop(guard);
    });
    startup_for(&lab.open(V100, None), Vec::new()).expect("after release");
    release.join().expect("release");
}

// ---- confirm -------------------------------------------------------------------------------------

#[test]
fn confirm_with_a_matching_token_or_none_confirms_and_a_mismatch_changes_nothing() {
    let cases: [(Option<OsString>, bool); 2] = [(Some(token_hex(&TOKEN)), true), (None, true)];
    for (token, _) in cases {
        let lab = Lab::new();
        lab.version_tree(V100, "app");
        lab.version_tree(V110, "app");
        commit(&lab.fs, &root_dir(), |_| pending_110());
        let got = confirm_for(&lab.open(V110, token)).expect("confirm");
        assert_eq!(got, ConfirmOutcome::Confirmed);
        let rec = lab.record();
        assert!(rec.pending.is_none() && rec.health.is_none());
        assert_eq!(rec.current.expect("current").version, version(V110));
    }

    let lab = Lab::new();
    lab.version_tree(V100, "app");
    lab.version_tree(V110, "app");
    let before = commit(&lab.fs, &root_dir(), |_| pending_110());
    for token in [token_hex(&[0x11; 32]), OsString::from("zz")] {
        let got = confirm_for(&lab.open(V110, Some(token)));
        assert!(matches!(got, Err(Error::TokenMismatch)), "{got:?}");
    }
    assert_eq!(lab.record(), before, "nothing changed");
    // The old version confirms nothing of the new one.
    assert_eq!(
        confirm_for(&lab.open(V100, None)).expect("confirm"),
        ConfirmOutcome::NothingPending
    );
    assert_eq!(lab.record(), before);
}

#[test]
fn confirm_with_nothing_pending_is_nothing_pending() {
    let lab = Lab::new();
    lab.version_tree(V100, "app");
    let before = commit(&lab.fs, &root_dir(), |_| installed_100());
    assert_eq!(
        confirm_for(&lab.open(V100, Some(token_hex(&TOKEN)))).expect("confirm"),
        ConfirmOutcome::NothingPending
    );
    assert_eq!(lab.record(), before);
}

// ---- apply_and_restart ---------------------------------------------------------------------------

#[test]
fn apply_and_restart_with_nothing_staged_is_nothing_staged() {
    let lab = Lab::new();
    lab.version_tree(V100, "app");
    commit(&lab.fs, &root_dir(), |_| installed_100());
    let got = apply_and_restart_for(&lab.open(V100, None), ApplyOptions::default());
    assert!(matches!(got, Err(Error::NothingStaged)), "{got:?}");
    assert!(lab.process.spawns().is_empty());
}

#[test]
fn an_unbound_or_missing_staged_issued_is_nothing_staged() {
    let edits: [fn(&mut InstallState); 2] = [
        |r| {
            r.staged_issued = Some(StagedIssued {
                version: version(V110),
                manifest_sha256: sha(b"another manifest"),
                issued: 20,
            });
        },
        |r| r.staged_issued = None,
    ];
    for edit in edits {
        let lab = Lab::new();
        lab.version_tree(V100, "app");
        lab.version_tree(V110, "app");
        commit(&lab.fs, &root_dir(), |_| {
            // The real writer, then the field edited through the typed record.
            let mut r = installed_100().set_staged(Some((staged_ref(V110), 20)));
            edit(&mut r);
            r
        });
        let got = apply_and_restart_for(&lab.open(V100, None), ApplyOptions::default());
        assert!(matches!(got, Err(Error::NothingStaged)), "{got:?}");
        assert!(lab.process.spawns().is_empty());
    }
}

#[test]
fn a_staged_version_starts_the_own_runtime_detached_with_exactly_this_argv() {
    let lab = Lab::new();
    lab.version_tree(V100, "app");
    lab.version_tree(V110, "app");
    commit(&lab.fs, &root_dir(), |_| {
        installed_100().set_staged(Some((staged_ref(V110), 20)))
    });
    let inst = lab.open(V100, Some(token_hex(&TOKEN)));

    let wrong = ApplyOptions {
        expect_version: Some(version("1.2.0")),
        ..ApplyOptions::default()
    };
    assert!(matches!(
        apply_and_restart_for(&inst, wrong),
        Err(Error::UnexpectedVersion)
    ));
    assert!(lab.process.spawns().is_empty());

    let got = apply_and_restart_for(
        &inst,
        ApplyOptions {
            expect_version: Some(version(V110)),
            wait_for: None,
            restart_args: vec!["--flag".into(), "two words".into()],
        },
    )
    .expect("scheduled");
    assert_eq!(got.version(), &version(V110));
    let spawns = lab.process.spawns();
    assert_eq!(spawns.len(), 1);
    let spawn = &spawns[0];
    assert!(spawn.detached);
    assert_eq!(
        spawn.program,
        root_dir().join("versions/1.0.0/bin/lunepack-runtime")
    );
    let argv: Vec<OsString> = [
        "apply",
        "--wait-pid",
        "100",
        "--wait-start",
        "1000",
        "--version",
        "1.1.0",
        "--",
        "--flag",
        "two words",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    assert_eq!(spawn.args, argv);
    assert!(spawn.env_set.is_empty());
    assert_eq!(spawn.env_remove, vec![OsString::from(HEALTH_TOKEN_VAR)]);

    // An explicit wait target.
    apply_and_restart_for(
        &inst,
        ApplyOptions {
            wait_for: Some(ProcessId {
                pid: 7,
                start_ticks: 77,
            }),
            ..ApplyOptions::default()
        },
    )
    .expect("scheduled");
    let args = &lab.process.spawns()[1].args;
    assert_eq!(
        &args[1..5],
        &["--wait-pid", "7", "--wait-start", "77"].map(OsString::from)
    );
}

#[test]
fn a_staged_tree_that_is_missing_is_nothing_staged() {
    let lab = Lab::new();
    lab.version_tree(V100, "app");
    commit(&lab.fs, &root_dir(), |_| {
        installed_100().set_staged(Some((staged_ref(V110), 20)))
    });
    let got = apply_and_restart_for(&lab.open(V100, None), ApplyOptions::default());
    assert!(matches!(got, Err(Error::NothingStaged)), "{got:?}");
}

// ---- install -------------------------------------------------------------------------------------

/// Publishes `v` with its config inside the pack (a feed `seq`).
fn publish_with_config(lab: &Lab, seq: u64, v: &str) {
    let mut pack = PackBuilder::new();
    for (path, bytes) in files(v) {
        pack.file(&FakeHasher, &path, &bytes, CodecId::Lzma2);
    }
    let cfg = config(
        &lab.root(),
        v,
        FEED,
        meta("bin/app", Some("app"), &format!("App {v}")),
    );
    pack.file(
        &FakeHasher,
        "lunepack-update.json",
        &cfg.to_bytes().expect("bytes"),
        CodecId::Lzma2,
    );
    lab.world.publish_pack(seq, v, &pack);
}

/// A bootstrap tree of `v` outside the install.
fn bootstrap(lab: &Lab, v: &str) -> Installation {
    let tree = abs_path(&format!("/media/boot/{v}"));
    let cfg = config(
        &lab.root(),
        v,
        FEED,
        meta("bin/app", Some("app"), &format!("App {v}")),
    );
    write_tree(&lab.fs, &tree, &cfg);
    Installation::from_exe_with(&tree.join("bin/app"), lab.platform(None)).expect("bootstrap")
}

fn install(lab: &Lab, boot: &Installation) -> Result<lunepack::InstalledVersion, Error> {
    let updater = boot
        .updater_builder()?
        .transport(Arc::clone(&lab.world.transport))
        .codec(Arc::new(FakeCodec::new()))
        .clock(Arc::clone(&lab.world.clock) as Arc<dyn lunepack_core::Clock>)
        .workers(2)
        .build()?;
    block_on(updater.install(DownloadOptions::default()))
}

#[test]
fn install_from_an_empty_root_installs_the_newest_release() {
    let _serial = common::serial();
    let lab = Lab::new();
    publish_with_config(&lab, 1, V100);
    let boot = bootstrap(&lab, V100);
    let got = install(&lab, &boot).expect("install");
    assert_eq!(got.version(), &version(V100));

    let rec = lab.record();
    assert_eq!(
        rec.current.as_ref().expect("current").version,
        version(V100)
    );
    assert!(rec.staged.is_none() && rec.staged_issued.is_none());
    assert_eq!(rec.target, TARGET);
    assert_eq!(lab.current_link(), "versions/1.0.0");
    let tree = root_dir().join("versions/1.0.0");
    for (path, bytes) in files(V100) {
        assert_eq!(
            lab.fs.read_capped(&tree.join(path), 1 << 20).expect("file"),
            bytes
        );
    }
    let ops: Vec<IntegrationOp> = lab.integration.calls().iter().map(|c| c.op).collect();
    assert_eq!(
        ops,
        vec![
            IntegrationOp::Check,
            IntegrationOp::Check,
            IntegrationOp::Apply
        ]
    );
    let applied = lab.integration.calls().pop().expect("apply");
    assert_eq!(applied.install_root, root_dir());
    assert_eq!(applied.meta.name, "App 1.0.0");

    // The installed tree finds itself, and its first start gets the install events.
    let inst = lab.open(V100, None);
    let start = startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(
        start.events,
        vec![
            LifecycleEvent::Installed {
                version: version(V100),
            },
            LifecycleEvent::FirstRun {
                version: version(V100),
            },
        ]
    );
    common::workers_stopped();
}

#[test]
fn install_resumes_a_record_created_before_a_crash_and_keeps_its_install_id() {
    let _serial = common::serial();
    let lab = Lab::new();
    publish_with_config(&lab, 1, V100);
    let boot = bootstrap(&lab, V100);
    let made = commit(&lab.fs, &root_dir(), |_| {
        InstallState::new(1, app_id(), Scope::User, [3; 16], TARGET)
    });
    install(&lab, &boot).expect("install");
    let rec = lab.record();
    assert_eq!(rec.install_id, made.install_id);
    assert_eq!(rec.current.expect("current").version, version(V100));
    common::workers_stopped();
}

#[test]
fn install_over_an_installed_record_is_already_installed() {
    let _serial = common::serial();
    let lab = Lab::new();
    publish_with_config(&lab, 1, V100);
    let boot = bootstrap(&lab, V100);
    install(&lab, &boot).expect("first");
    let before = lab.record();
    let got = install(&lab, &boot);
    assert!(matches!(got, Err(Error::AlreadyInstalled)), "{got:?}");
    assert_eq!(lab.record(), before);
    common::workers_stopped();
}

#[test]
fn an_integration_conflict_stops_install_before_anything_is_written() {
    let _serial = common::serial();
    let lab = Lab::new();
    publish_with_config(&lab, 1, V100);
    let boot = bootstrap(&lab, V100);
    lab.integration
        .script_conflict(Some(lunepack_core::IntegrationItem::BinLink));
    let got = install(&lab, &boot);
    assert!(matches!(got, Err(Error::Integration(_))), "{got:?}");
    // Neither R nor its parent exists.
    assert!(
        matches!(
            lab.fs.symlink_metadata(&root_dir()),
            Ok(None)
                | Err(lunepack_core::FsError {
                    kind: lunepack_core::FsErrorKind::NotFound,
                    ..
                })
        ),
        "R was not created"
    );
    common::workers_stopped();
}

#[test]
fn an_integration_that_fails_once_leaves_install_resumable() {
    let _serial = common::serial();
    let lab = Lab::new();
    publish_with_config(&lab, 1, V100);
    let boot = bootstrap(&lab, V100);
    lab.integration.script_failure(Some("disk"));
    let got = install(&lab, &boot);
    assert!(matches!(got, Err(Error::Integration(_))), "{got:?}");
    let rec = lab.record();
    assert!(rec.current.is_none(), "committed before the integration");
    assert!(lab.integration.applied().is_empty());

    lab.integration.script_failure(None);
    install(&lab, &boot).expect("rerun");
    assert_eq!(
        lab.record().current.expect("current").version,
        version(V100)
    );
    assert_eq!(lab.current_link(), "versions/1.0.0");
    assert_eq!(lab.integration.applied().len(), 1);
    common::workers_stopped();
}

/// A [`FakeIntegration`] whose successful `apply` arms `fs` to fail its next operation: the
/// install commit that follows it.
struct CommitFailsAfterApply {
    inner: FakeIntegration,
    fs: MemFs,
}

impl lunepack_core::OsIntegration for CommitFailsAfterApply {
    fn check(
        &self,
        scope: lunepack_core::Scope,
        req: &lunepack_core::IntegrationRequest,
    ) -> Result<(), lunepack_core::IntegrationError> {
        self.inner.check(scope, req)
    }

    fn apply(
        &self,
        scope: lunepack_core::Scope,
        req: &lunepack_core::IntegrationRequest,
    ) -> Result<lunepack_core::IntegrationReport, lunepack_core::IntegrationError> {
        let report = self.inner.apply(scope, req)?;
        self.fs.crash_after(self.fs.op_count());
        Ok(report)
    }

    fn remove(
        &self,
        scope: lunepack_core::Scope,
        req: &lunepack_core::IntegrationRequest,
    ) -> Result<lunepack_core::IntegrationReport, lunepack_core::IntegrationError> {
        self.inner.remove(scope, req)
    }
}

#[test]
fn a_commit_that_fails_after_the_integration_leaves_install_resumable() {
    let _serial = common::serial();
    let lab = Lab::new();
    publish_with_config(&lab, 1, V100);
    let tree = abs_path(&format!("/media/boot/{V100}"));
    let cfg = config(
        &lab.root(),
        V100,
        FEED,
        meta("bin/app", Some("app"), &format!("App {V100}")),
    );
    write_tree(&lab.fs, &tree, &cfg);
    let failing = CommitFailsAfterApply {
        inner: lab.integration.clone(),
        fs: lab.fs.clone(),
    };
    let platform = lab.platform(None).with_integration(Arc::new(failing));
    let boot = Installation::from_exe_with(&tree.join("bin/app"), platform).expect("bootstrap");
    let got = install(&lab, &boot);
    assert!(got.is_err(), "the commit did not fail");
    assert!(lab.fs.is_crashed());
    // The integration went in before the commit; the record has no current version.
    assert_eq!(lab.integration.applied().len(), 1);

    let after = Lab {
        fs: lab.fs.recover(lunepack_testkit::RecoverMode::KeepVolatile),
        world: lab.world,
        process: lab.process,
        integration: lab.integration,
    };
    assert!(after.record().current.is_none(), "the commit went through");
    let boot = Installation::from_exe_with(&tree.join("bin/app"), after.platform(None))
        .expect("bootstrap after the crash");
    install(&after, &boot).expect("rerun");
    assert_eq!(
        after.record().current.expect("current").version,
        version(V100)
    );
    assert_eq!(after.current_link(), "versions/1.0.0");
    let applies = after
        .integration
        .calls()
        .iter()
        .filter(|c| c.op == IntegrationOp::Apply)
        .count();
    assert_eq!(applies, 2, "the rerun applies the integration again");
    common::workers_stopped();
}

#[test]
fn a_channel_with_no_release_for_this_install_is_no_release_and_resumable() {
    let _serial = common::serial();
    let lab = Lab::new();
    lab.world.publish_feed(1, Vec::new());
    let boot = bootstrap(&lab, V100);
    let got = install(&lab, &boot);
    assert!(matches!(got, Err(Error::NoRelease)), "{got:?}");
    assert!(lab.record().current.is_none(), "nothing installed");
    assert!(lab.integration.applied().is_empty());

    publish_with_config(&lab, 2, V100);
    install(&lab, &boot).expect("a later try");
    assert_eq!(
        lab.record().current.expect("current").version,
        version(V100)
    );
    common::workers_stopped();
}

#[test]
fn install_into_a_machine_layout_is_machine_scope() {
    let lab = Lab::new();
    let layout = Layout::Machine {
        machine_state_dir: "/machine/state".into(),
        user_state_dir: "/user/state".into(),
        cache_dir: "/user/cache".into(),
        versions_dir: None,
        current_tree: None,
    };
    let updater = lab
        .world
        .builder(layout, Arc::new(lab.fs.clone()))
        .integration(Arc::new(lab.integration.clone()))
        .build()
        .expect("build");
    let got = block_on(updater.install(DownloadOptions::default()));
    assert!(matches!(got, Err(Error::MachineScope)), "{got:?}");
}

// ---- on a real directory -------------------------------------------------------------------------

#[test]
fn discovery_and_startup_work_on_a_real_directory() {
    let tmp = tempfile::tempdir().expect("tmp");
    let dir = std::fs::canonicalize(tmp.path()).expect("canonical");
    let exe = real_install(&dir, FEED);
    // The native filesystem; the exe reached through a symlink resolves to its tree.
    #[cfg(unix)]
    let link = {
        let link = dir.join("app-link");
        std::os::unix::fs::symlink(&exe, &link).expect("symlink");
        link
    };
    #[cfg(not(unix))]
    let link = exe.clone();
    let platform = Platform::native()
        .with_hasher(Arc::new(FakeHasher))
        .with_verifier(Arc::new(FakeVerifier))
        .with_process(Arc::new(FakeProcess::new("/unused")))
        .with_health_token(None);
    let inst = Installation::from_exe_with(&link, platform).expect("installation");
    assert!(inst.is_installed());
    assert_eq!(inst.entry_path(), exe);
    let got = startup_for(&inst, Vec::new()).expect("startup");
    assert_eq!(got.action, StartupAction::Continue);
    let root = dir.join("data").join(app_id().as_str());
    let current = std::fs::read_link(root.join("current")).expect("current");
    assert_eq!(current, Path::new("versions/1.0.0"));
    assert!(
        std::fs::symlink_metadata(root.join("current"))
            .expect("meta")
            .file_type()
            .is_symlink()
    );
}

/// A `file:` config feed names the release directory; the default directory source serves it
/// (rooted at that directory's parent, FORMAT.md 13.3 / R2-3), and a check reads the documents.
#[test]
fn a_file_feed_from_the_config_is_served_by_the_directory_source() {
    let tmp = tempfile::tempdir().expect("tmp");
    let dir = std::fs::canonicalize(tmp.path()).expect("canonical");
    let world = World::new();
    world.publish(1, V110);
    let release = dir.join("rel");
    let target = TARGET.as_str();
    for name in [
        "keys.json".to_owned(),
        "feed-stable.json".to_owned(),
        format!("1.1.0/{target}.manifest.json"),
        format!("1.1.0/{target}.pack"),
    ] {
        let path = release.join(&name);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
        std::fs::write(&path, world.served(&name)).expect("write");
    }
    // The feed URL of the directory (on Windows `file:///C:/…/rel/`, never the path's own text).
    let feed = url::Url::from_directory_path(&release)
        .expect("file url")
        .to_string();
    let exe = real_install(&dir.join("install"), &feed);
    let platform = Platform::native()
        .with_hasher(Arc::new(FakeHasher))
        .with_verifier(Arc::new(FakeVerifier));
    let updater = Installation::from_exe_with(&exe, platform)
        .expect("installation")
        .updater_builder()
        .expect("builder")
        .codec(Arc::new(FakeCodec::new()))
        .clock(Arc::clone(&world.clock) as Arc<dyn lunepack_core::Clock>)
        .build()
        .expect("build");
    let info = block_on(updater.check()).expect("check").expect("update");
    assert_eq!(info.version(), &version(V110));
}

/// The native composition: on Linux the process adapter finds the test binary, whose tree holds no
/// update config; elsewhere processes are unsupported.
#[test]
fn the_native_platform_wires_the_process_adapter_on_linux_only() {
    let got = Installation::from_current_exe_with(Platform::native());
    if cfg!(target_os = "linux") {
        assert!(matches!(got, Err(Error::NoUpdateConfig)), "{got:?}");
    } else {
        assert!(matches!(got, Err(Error::Unsupported)), "{got:?}");
    }
}
