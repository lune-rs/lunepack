//! A published release world for the C binding's tests: signed documents written by the testkit's
//! builders, served by a fake transport, an install state committed by the core's real writer, and
//! every capability faked. The updater under test is the facade's own `UpdaterBuilder` output,
//! handed to the binding through its test seam.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use lunepack::unstable_internals::live_workers;
use lunepack::{Layout, Updater, UpdaterBuilder};
use lunepack_core::state::{InstallState, Scope, UserScope};
use lunepack_core::{
    AppId, BoxFuture, Channel, CodecId, Fs, PayloadKind, Request, Response, Target, Transport,
    TransportError, TrustedRoot, Version,
};
use lunepack_testkit::{
    ChainFixture, FAKE_BASE_URL, FakeClock, FakeCodec, FakeHasher, FakeOrigin, FakeTransport,
    FakeVerifier, MemFs, PackBuilder, SUITE_APP_ID, SUITE_CHANNEL, SUITE_T0,
};

pub const DAY: u64 = 86_400;
pub const TARGET: Target = Target::LinuxX86_64;
pub const INSTALL_ID: [u8; 16] = [7; 16];

static SERIAL: Mutex<()> = Mutex::new(());

/// The tests count process-wide workers; each takes this.
pub fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn wait_until(limit: Duration, cond: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(2));
    }
}

/// Every worker thread of every updater is gone (the facade's own check).
pub fn workers_stopped() {
    assert!(
        wait_until(Duration::from_secs(5), || live_workers() == 0),
        "workers still alive: {}",
        live_workers()
    );
}

pub fn app_id() -> AppId {
    AppId::parse(SUITE_APP_ID).expect("app id")
}

pub fn channel() -> Channel {
    Channel::parse(SUITE_CHANNEL).expect("channel")
}

pub fn version(text: &str) -> Version {
    Version::parse(text).expect("version")
}

/// The files of a release: `(path, bytes)`, all regular files.
pub fn files(version: &str) -> Vec<(String, Vec<u8>)> {
    vec![
        (
            "bin/app".to_owned(),
            format!("app {version}").repeat(40).into_bytes(),
        ),
        (
            "lib/common.so".to_owned(),
            b"shared library bytes".repeat(30),
        ),
        ("share/readme.txt".to_owned(), b"read me".repeat(10)),
        ("share/big.dat".to_owned(), vec![0x5a; 9000]),
    ]
}

pub struct World {
    pub fx: ChainFixture<'static>,
    pub origin: FakeOrigin,
    pub transport: Arc<dyn Transport>,
    pub fs: MemFs,
    pub clock: Arc<FakeClock>,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub versions_dir: PathBuf,
}

impl World {
    pub fn new() -> World {
        let fake = FakeTransport::new(FakeOrigin::new());
        let origin = fake.origin().clone();
        World::with_transport(origin, Arc::new(fake))
    }

    pub fn with_transport(origin: FakeOrigin, transport: Arc<dyn Transport>) -> World {
        let world = World {
            fx: ChainFixture::fake(),
            origin,
            transport,
            fs: MemFs::new(),
            clock: Arc::new(FakeClock::new(SUITE_T0 + 3600)),
            state_dir: PathBuf::from("/user/state"),
            cache_dir: PathBuf::from("/user/cache"),
            versions_dir: PathBuf::from("/user/versions"),
        };
        world.publish_keys();
        world
    }

    pub fn root(&self) -> TrustedRoot {
        self.fx.trusted_root(1, 1, &[0])
    }

    pub fn feed_url(&self) -> String {
        format!("{FAKE_BASE_URL}/feed-{SUITE_CHANNEL}.json")
    }

    /// `keys.json`: version 1 under root 1, release key seed 1, threshold 1.
    pub fn publish_keys(&self) {
        let ks = self.fx.keyset_document(1, 1, None, 1, &[1]);
        let bytes = self.fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);
        self.origin.put("keys.json", bytes);
    }

    /// The pack of `version` (each file one FakeCodec LZMA2 frame).
    pub fn pack(&self, version: &str) -> PackBuilder {
        let mut pack = PackBuilder::new();
        for (path, bytes) in files(version) {
            pack.file(&FakeHasher, &path, &bytes, CodecId::Lzma2);
        }
        pack
    }

    /// Publishes `version`'s manifest and pack, and a feed `seq` listing it (expires in 30 days).
    pub fn publish(&self, seq: u64, version: &str) -> PackBuilder {
        let pack = self.pack(version);
        let manifest = self.fx.manifest_document(version, TARGET, &pack);
        let manifest_bytes = self
            .fx
            .envelope(PayloadKind::Manifest, &manifest.to_payload(), &[1]);
        self.origin.put(
            &format!("{version}/{}.manifest.json", TARGET.as_str()),
            manifest_bytes.clone(),
        );
        self.origin.put(
            &format!("{version}/{}.pack", TARGET.as_str()),
            pack.bytes.clone(),
        );
        let release = self.fx.release(version, &[(TARGET, &manifest_bytes)], None);
        let feed = self
            .fx
            .feed_document(seq, Some(SUITE_T0 + 30 * DAY), vec![release]);
        let bytes = self
            .fx
            .envelope(PayloadKind::Feed, &feed.to_payload(), &[1]);
        self.origin
            .put(&format!("feed-{SUITE_CHANNEL}.json"), bytes);
        pack
    }

    /// A user install of `current` (issued at `issued`), committed by the core's writer.
    pub fn install(&self, current: &str, issued: u64) {
        let record = InstallState::new(1, app_id(), Scope::User, INSTALL_ID, TARGET).install(
            version(current),
            issued,
            TARGET,
            INSTALL_ID,
        );
        let store = UserScope {
            dir: self.state_dir.clone(),
            app_id: app_id(),
        };
        let loaded = store.load(&self.fs, &FakeHasher).expect("load");
        store
            .commit(&self.fs, &loaded, &record, &FakeHasher)
            .expect("commit");
    }

    pub fn user_layout(&self) -> Layout {
        Layout::User {
            state_dir: self.state_dir.clone(),
            cache_dir: self.cache_dir.clone(),
            versions_dir: self.versions_dir.clone(),
            current_tree: None,
        }
    }

    pub fn builder(&self, fs: Arc<dyn Fs>) -> UpdaterBuilder {
        UpdaterBuilder::new(
            app_id(),
            self.root(),
            &self.feed_url(),
            channel(),
            self.user_layout(),
        )
        .transport(Arc::clone(&self.transport))
        .fs(fs)
        .hasher(Arc::new(FakeHasher))
        .verifier(Arc::new(FakeVerifier))
        .codec(Arc::new(FakeCodec::new()))
        .clock(Arc::clone(&self.clock) as Arc<dyn lunepack_core::Clock>)
        .workers(2)
    }

    pub fn updater(&self) -> Updater {
        self.builder(Arc::new(self.fs.clone()))
            .build()
            .expect("build")
    }

    /// The bytes of the file at `path` on the world's disk.
    pub fn read(&self, path: &std::path::Path) -> Vec<u8> {
        self.fs.read_capped(path, 1 << 30).expect("read")
    }
}

impl Default for World {
    fn default() -> Self {
        World::new()
    }
}

/// A transport whose `get` waits at a gate until released (to hold an operation inside its lock).
pub struct GateTransport {
    pub inner: Arc<dyn Transport>,
    pub entered: Arc<AtomicBool>,
    pub open: Arc<AtomicBool>,
}

impl Transport for GateTransport {
    fn get(&self, request: Request) -> BoxFuture<'static, Result<Response, TransportError>> {
        let inner = Arc::clone(&self.inner);
        let entered = Arc::clone(&self.entered);
        let open = Arc::clone(&self.open);
        Box::pin(async move {
            entered.store(true, Ordering::SeqCst);
            // Pending until the gate opens; a helper thread re-wakes the task every 5 ms.
            std::future::poll_fn(|cx| {
                if open.load(Ordering::SeqCst) {
                    return std::task::Poll::Ready(());
                }
                let waker = cx.waker().clone();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(5));
                    waker.wake();
                });
                std::task::Poll::Pending
            })
            .await;
            inner.get(request).await
        })
    }
}

/// A transport that yields once before every request, so an operation takes several polls and the
/// caller's cancel token is looked at between them.
pub struct YieldTransport {
    pub inner: Arc<dyn Transport>,
}

impl Transport for YieldTransport {
    fn get(&self, request: Request) -> BoxFuture<'static, Result<Response, TransportError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let mut yielded = false;
            std::future::poll_fn(|cx| {
                if yielded {
                    return std::task::Poll::Ready(());
                }
                yielded = true;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            })
            .await;
            inner.get(request).await
        })
    }
}
