//! Per-user delta updates (M12 step 5, M12-D5): choosing patches, fetching them by Range runs or
//! as the whole delta file, staging them, and the D27 ladder when a patch fails. Releases are laid
//! out by the core's real writer (`ReleaseLayout`) with the real LZMA codec, so a patch is much
//! shorter than its frame; documents, hashing and the transport are the testkit fakes, the disk a
//! `MemFs`.

mod common;

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use common::*;
use lunepack::{DownloadOptions, Error, Updater, block_on};
use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::fetch::FetchPolicy;
use lunepack_core::{
    BoxFuture, CodecId, DeltaPatch, Fs, PayloadKind, Phase, Progress, RelPath, ReleaseLayout,
    Request, Response, Source, Transport, TransportError, encode_patch_checked, pack_file,
};
use lunepack_testkit::{FAKE_BASE_URL, FakeHasher, FakeOrigin, FakeTransport, SUITE_T0};

const FROM: &str = "1.0.0";
const TO: &str = "1.1.0";

type Files = Vec<(&'static str, Vec<u8>)>;

/// `base` with a few bytes changed in place.
fn edit(base: &[u8], salt: u8) -> Vec<u8> {
    let mut v = base.to_vec();
    for k in 1..6 {
        let at = v.len() / 7 * k;
        v[at] ^= salt | 1;
    }
    v
}

/// The installed release: three incompressible files a patch release edits and a text file it
/// keeps.
fn old_files() -> Files {
    vec![
        ("a.bin", noise(20_000, 1)),
        ("b.bin", noise(20_000, 2)),
        ("c.txt", text(8_000, 3)),
        ("d.bin", noise(20_000, 4)),
    ]
}

fn new_files() -> Files {
    old_files()
        .into_iter()
        .map(|(p, b)| {
            if p == "c.txt" {
                (p, b)
            } else {
                (p, edit(&b, 7))
            }
        })
        .collect()
}

fn get<'a>(files: &'a Files, path: &str) -> Option<&'a Vec<u8>> {
    files.iter().find(|(p, _)| *p == path).map(|(_, b)| b)
}

/// Publishes release `to` of `new` with one delta from `from` against `base` (a patch for every
/// file whose bytes changed), and a feed `seq` listing it; the delta file is served only with
/// `serve_delta`. Returns the pack's size and the delta file's name under the base URL.
fn publish(
    w: &World,
    seq: u64,
    to: &str,
    new: &Files,
    from: &str,
    base: &Files,
    serve_delta: bool,
) -> (u64, String) {
    let mut layout = ReleaseLayout::new(app_id(), to, TARGET).expect("layout");
    let mut patches: Vec<(RelPath, DeltaPatch)> = Vec::new();
    for (path, bytes) in new {
        let rel = RelPath::parse(path).expect("path");
        let packed = pack_file(bytes, &LzmaCodec, &LzmaCodec, &FakeHasher).expect("pack");
        layout.add_file(rel.clone(), false, &packed).expect("add");
        if let Some(old) = get(base, path).filter(|old| *old != bytes) {
            let patch = encode_patch_checked(
                &rel,
                CodecId::Lzma2,
                old,
                bytes,
                &LzmaCodec,
                &LzmaCodec,
                &FakeHasher,
            )
            .expect("patch");
            patches.push((rel, patch));
        }
    }
    layout.add_delta(from, patches).expect("delta");
    let rel = layout
        .finish_release(SUITE_T0, &FakeHasher)
        .expect("finish");
    let manifest =
        w.fx.envelope(PayloadKind::Manifest, &rel.manifest.to_payload(), &[1]);
    w.origin.put(&manifest_path(to), manifest.clone());
    w.origin.put(&pack_path(to), rel.pack.clone());
    let delta = rel.deltas[0].path.clone();
    if serve_delta {
        w.origin.put(&delta, rel.deltas[0].bytes.clone());
    }
    let release = w.fx.release(to, &[(TARGET, &manifest)], None);
    w.publish_feed(seq, vec![release]);
    (rel.pack.len() as u64, delta)
}

/// A user install of `version` whose tree holds `files`.
fn install(w: &World, version: &str, files: &Files) {
    w.install(version, SUITE_T0 - 10 * DAY);
    let dir = w.versions_dir.join(version);
    for (path, bytes) in files {
        let full = dir.join(path);
        w.fs.create_dir_all(full.parent().expect("parent"))
            .expect("dirs");
        let mut f = w.fs.create_new(&full).expect("create");
        f.write_all(bytes).expect("write");
        f.sync().expect("sync");
    }
}

fn updater(w: &World, policy: FetchPolicy) -> Updater {
    w.builder(w.user_layout(None), Arc::new(w.fs.clone()))
        .codec(Arc::new(LzmaCodec))
        .fetch_policy(policy)
        .build()
        .expect("build")
}

/// The requests since `from`: the name under the base URL and the `Range` header.
fn requests(w: &World, from: usize) -> Vec<(String, Option<String>)> {
    w.origin.requests()[from..]
        .iter()
        .map(|r| {
            (
                r.url
                    .strip_prefix(FAKE_BASE_URL)
                    .unwrap_or(&r.url)
                    .trim_start_matches('/')
                    .to_owned(),
                r.range_header.clone(),
            )
        })
        .collect()
}

fn recorder() -> (Arc<Mutex<Vec<Progress>>>, DownloadOptions) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&events);
    let options = DownloadOptions {
        progress: Some(Box::new(move |p| {
            seen.lock().expect("events").push(p.clone())
        })),
        cancel: None,
    };
    (events, options)
}

fn assert_staged(w: &World, tree: &std::path::Path, files: &Files) {
    for (path, bytes) in files {
        assert_eq!(&w.read(&tree.join(path)), bytes, "{path}");
    }
}

fn file_sources(events: &[Progress], phase: Phase) -> Vec<(String, Source)> {
    let mut out: Vec<(String, Source)> = events
        .iter()
        .filter(|p| p.phase == phase)
        .filter_map(|p| p.file.as_ref())
        .map(|f| (f.path.as_str().to_owned(), f.source))
        .collect();
    out.dedup();
    out
}

/// With a policy that never prefers whole files, the patches of the changed files come by Range
/// runs of the delta file; the pack is never requested; the stage reports `Source::Patch` for
/// them; the download's total is what was requested and ends done; the cache is empty after the
/// stage.
#[test]
fn an_update_by_patches() {
    let _s = serial();
    let w = World::new();
    install(&w, FROM, &old_files());
    let (_, delta) = publish(&w, 1, TO, &new_files(), FROM, &old_files(), true);
    let ranges = FetchPolicy {
        full_ratio: 101,
        ..FetchPolicy::default()
    };
    let u = updater(&w, ranges);
    let info = block_on(u.check()).expect("check").expect("update");
    let before = w.origin.requests().len();
    let (events, options) = recorder();
    let downloaded = block_on(u.download(&info, options)).expect("download");
    let reqs = requests(&w, before);
    assert!(
        reqs.iter()
            .all(|(name, range)| *name == delta && range.is_some()),
        "only ranges of the delta file: {reqs:?}"
    );
    assert!(!reqs.is_empty());
    let (stage_events, stage_options) = recorder();
    let staged = block_on(u.stage(downloaded.with_options(stage_options))).expect("stage");
    assert_staged(&w, staged.tree(), &new_files());
    let sources = file_sources(&stage_events.lock().expect("events"), Phase::Stage);
    // Events are coalesced, so not every file shows; every one shown is a patch or unchanged.
    assert!(
        sources.iter().any(|(_, s)| *s == Source::Patch),
        "{sources:?}"
    );
    for (path, source) in &sources {
        let want = if path == "c.txt" {
            Source::Unchanged
        } else {
            Source::Patch
        };
        assert_eq!(*source, want, "{path}: {sources:?}");
    }
    let events = events.lock().expect("events");
    let last = events
        .iter()
        .rev()
        .find(|p| p.phase == Phase::Download)
        .expect("a download event");
    assert!(last.total > 0 && last.done == last.total, "{last:?}");
    drop(events);
    for dir in ["frames", "packs", "patches", "deltas"] {
        assert!(names(&w, dir).is_empty(), "{dir}");
    }
    workers_stopped();
}

fn names(w: &World, dir: &str) -> Vec<String> {
    match w.fs.list_dir(&w.cache_dir.join(dir)) {
        Ok(entries) => entries
            .into_iter()
            .map(|e| e.name.to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// With every patch wanted and a policy that prefers whole files, the delta file is fetched whole
/// (no `Range`) and split into one cache file per patch.
#[test]
fn the_whole_delta_file_when_the_plan_says_so() {
    let _s = serial();
    let w = World::new();
    install(&w, FROM, &old_files());
    let (_, delta) = publish(&w, 1, TO, &new_files(), FROM, &old_files(), true);
    let whole = FetchPolicy {
        full_ratio: 1,
        ..FetchPolicy::default()
    };
    let u = updater(&w, whole);
    let info = block_on(u.check()).expect("check").expect("update");
    let before = w.origin.requests().len();
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");
    assert_eq!(requests(&w, before), [(delta, None)]);
    assert_eq!(names(&w, "patches").len(), 3, "one cache file per patch");
    let staged = block_on(u.stage(downloaded)).expect("stage");
    assert_staged(&w, staged.tree(), &new_files());
    assert!(names(&w, "deltas").is_empty() && names(&w, "patches").is_empty());
    workers_stopped();
}

/// A changed local base (same size, other bytes) gets its frame by Range; the others patches.
#[test]
fn a_modified_base_gets_its_frame_and_the_others_patches() {
    let _s = serial();
    let w = World::new();
    let mut local = old_files();
    local[0].1 = edit(&local[0].1, 9);
    install(&w, FROM, &local);
    let (_, delta) = publish(&w, 1, TO, &new_files(), FROM, &old_files(), true);
    let u = updater(&w, FetchPolicy::default());
    let info = block_on(u.check()).expect("check").expect("update");
    let before = w.origin.requests().len();
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");
    let reqs = requests(&w, before);
    // Two of the three patches are most of the delta file: it comes whole.
    assert!(reqs.iter().any(|(n, _)| *n == delta), "{reqs:?}");
    assert!(
        reqs.iter().any(|(n, r)| *n == pack_path(TO) && r.is_some()),
        "a.bin's frame by Range: {reqs:?}"
    );
    let (stage_events, options) = recorder();
    let staged = block_on(u.stage(downloaded.with_options(options))).expect("stage");
    assert_staged(&w, staged.tree(), &new_files());
    let sources = file_sources(&stage_events.lock().expect("events"), Phase::Stage);
    assert!(
        !sources.contains(&("a.bin".to_owned(), Source::Patch)),
        "{sources:?}"
    );
    assert!(
        sources.contains(&("b.bin".to_owned(), Source::Patch)),
        "{sources:?}"
    );
    workers_stopped();
}

/// A delta file the server does not have (404) costs one request; the files come as frames.
#[test]
fn a_missing_delta_file_falls_back_to_frames() {
    let _s = serial();
    let w = World::new();
    install(&w, FROM, &old_files());
    let (_, delta) = publish(&w, 1, TO, &new_files(), FROM, &old_files(), false);
    let u = updater(&w, FetchPolicy::default());
    let info = block_on(u.check()).expect("check").expect("update");
    let before = w.origin.requests().len();
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");
    let reqs = requests(&w, before);
    assert_eq!(
        reqs.iter().filter(|(n, _)| *n == delta).count(),
        1,
        "{reqs:?}"
    );
    assert!(reqs.iter().any(|(n, _)| *n == pack_path(TO)), "{reqs:?}");
    let staged = block_on(u.stage(downloaded)).expect("stage");
    assert_staged(&w, staged.tree(), &new_files());
    workers_stopped();
}

/// Replaces the bytes of the first cache file in `dir` with as many other bytes.
fn damage_first(w: &World, dir: &str) {
    let path = w.cache_dir.join(dir).join(&names(w, dir)[0]);
    let len = w.read(&path).len();
    w.fs.remove_file(&path).expect("remove");
    let mut f = w.fs.create_new(&path).expect("create");
    f.write_all(&vec![0xAB; len]).expect("write");
    f.sync().expect("sync");
}

/// A cached patch that fails its hash at stage time: that file's frame by Range (rung 2), and the
/// patch is not tried again.
#[test]
fn a_corrupt_patch_gets_its_frame_by_range() {
    let _s = serial();
    let w = World::new();
    install(&w, FROM, &old_files());
    publish(&w, 1, TO, &new_files(), FROM, &old_files(), true);
    let u = updater(&w, FetchPolicy::default());
    let info = block_on(u.check()).expect("check").expect("update");
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");
    damage_first(&w, "patches");
    let before = w.origin.requests().len();
    let staged = block_on(u.stage(downloaded)).expect("stage");
    let reqs = requests(&w, before);
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    assert_eq!(reqs[0].0, pack_path(TO));
    assert!(reqs[0].1.is_some(), "rung 2 is a range: {reqs:?}");
    assert_staged(&w, staged.tree(), &new_files());
    workers_stopped();
}

/// Corrupts the first byte of every `206` body of one file.
struct BadRangesOf {
    inner: FakeTransport,
    name: String,
}

impl Transport for BadRangesOf {
    fn get(&self, request: Request) -> BoxFuture<'static, Result<Response, TransportError>> {
        let hit = request.url.ends_with(&self.name);
        let future = self.inner.get(request);
        Box::pin(async move {
            let response = future.await?;
            if !hit || response.head.status != 206 {
                return Ok(response);
            }
            Ok(Response {
                head: response.head,
                body: Box::new(Mangle {
                    inner: response.body,
                    left: 1,
                    cut_after: None,
                }),
            })
        })
    }
}

/// Flips the first byte, or ends the body early after `cut_after` bytes.
struct Mangle {
    inner: Box<dyn lunepack_core::Body>,
    left: u8,
    cut_after: Option<usize>,
}

impl lunepack_core::Body for Mangle {
    fn next_chunk(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move {
            if self.cut_after == Some(0) {
                return Ok(None);
            }
            let mut chunk = self.inner.next_chunk().await?;
            if let Some(c) = chunk.as_mut() {
                if self.left > 0 && self.cut_after.is_none() {
                    c[0] ^= 0xFF;
                    self.left = 0;
                }
                if let Some(n) = self.cut_after.as_mut() {
                    if c.len() >= *n {
                        c.truncate(*n);
                        *n = 0;
                    } else {
                        *n -= c.len();
                    }
                }
            }
            Ok(chunk)
        })
    }
}

/// A failed patch, then a bad frame by Range: the full pack (rung 3) heals it.
#[test]
fn a_corrupt_frame_after_a_failed_patch_gets_the_full_pack() {
    let _s = serial();
    let fake = FakeTransport::new(FakeOrigin::new());
    let origin = fake.origin().clone();
    let w = World::with_transport(
        origin,
        Arc::new(BadRangesOf {
            inner: fake,
            name: pack_path(TO),
        }),
    );
    install(&w, FROM, &old_files());
    publish(&w, 1, TO, &new_files(), FROM, &old_files(), true);
    let u = updater(&w, FetchPolicy::default());
    let info = block_on(u.check()).expect("check").expect("update");
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");
    damage_first(&w, "patches");
    let before = w.origin.requests().len();
    let staged = block_on(u.stage(downloaded)).expect("stage");
    let reqs = requests(&w, before);
    assert_eq!(reqs.len(), 2, "{reqs:?}");
    assert!(reqs[0].1.is_some(), "rung 2 is a range: {reqs:?}");
    assert_eq!(reqs[1], (pack_path(TO), None), "rung 3 is the full pack");
    assert_staged(&w, staged.tree(), &new_files());
    workers_stopped();
}

/// When the files left for frames need the full pack anyway, patches would only add bytes: the
/// plan without patches wins and the delta file is never requested.
#[test]
fn the_cost_choice_uses_no_patch_when_patches_cost_more() {
    let _s = serial();
    let w = World::new();
    // b.bin's local base differs, so b.bin needs its frame, and that frame is most of the pack.
    let mut old = old_files();
    old[1].1 = noise(200_000, 2);
    let mut new = new_files();
    new[1].1 = edit(&old[1].1, 7);
    let mut local = old.clone();
    local[1].1 = edit(&local[1].1, 9);
    install(&w, FROM, &local);
    let (_, delta) = publish(&w, 1, TO, &new, FROM, &old, true);
    let u = updater(&w, FetchPolicy::default());
    let info = block_on(u.check()).expect("check").expect("update");
    let before = w.origin.requests().len();
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");
    let reqs = requests(&w, before);
    assert!(reqs.iter().all(|(n, _)| *n != delta), "{reqs:?}");
    assert_eq!(reqs, [(pack_path(TO), None)], "the full pack alone");
    let staged = block_on(u.stage(downloaded)).expect("stage");
    assert_staged(&w, staged.tree(), &new);
    workers_stopped();
}

/// A delta whose `from` differs from the installed version only in build metadata is not used
/// (FORMAT 10.3: the text is compared byte for byte), and no base is hashed for it.
#[test]
fn a_delta_from_other_build_metadata_is_not_used() {
    let _s = serial();
    let w = World::new();
    install(&w, "1.0.0+build.1", &old_files());
    let (_, delta) = publish(&w, 1, TO, &new_files(), FROM, &old_files(), true);
    let u = updater(&w, FetchPolicy::default());
    let info = block_on(u.check()).expect("check").expect("update");
    let before = w.origin.requests().len();
    let (events, options) = recorder();
    let downloaded = block_on(u.download(&info, options)).expect("download");
    let reqs = requests(&w, before);
    assert!(reqs.iter().all(|(n, _)| *n != delta), "{reqs:?}");
    let scanned = file_sources(&events.lock().expect("events"), Phase::Scan);
    assert!(
        scanned.iter().all(|(_, s)| *s != Source::Patch),
        "no base digest pass: {scanned:?}"
    );
    let staged = block_on(u.stage(downloaded)).expect("stage");
    assert_staged(&w, staged.tree(), &new_files());
    workers_stopped();
}

/// Ends the first body of the delta file after `cut` bytes (a dropped connection).
struct CutDeltaOnce {
    inner: FakeTransport,
    cut: usize,
    done: AtomicBool,
}

impl Transport for CutDeltaOnce {
    fn get(&self, request: Request) -> BoxFuture<'static, Result<Response, TransportError>> {
        let hit = request.url.ends_with(".delta") && !self.done.swap(true, Ordering::SeqCst);
        let cut = self.cut;
        let future = self.inner.get(request);
        Box::pin(async move {
            let response = future.await?;
            if !hit {
                return Ok(response);
            }
            Ok(Response {
                head: response.head,
                body: Box::new(Mangle {
                    inner: response.body,
                    left: 0,
                    cut_after: Some(cut),
                }),
            })
        })
    }
}

/// An interrupted whole-delta download is `Incomplete`; the next download resumes it from the
/// part's length with `If-Range`, and the update completes by patches.
#[test]
fn an_interrupted_delta_download_resumes() {
    let _s = serial();
    let fake = FakeTransport::new(FakeOrigin::new());
    let origin = fake.origin().clone();
    let w = World::with_transport(
        origin,
        Arc::new(CutDeltaOnce {
            inner: fake,
            cut: 100,
            done: AtomicBool::new(false),
        }),
    );
    install(&w, FROM, &old_files());
    let (_, delta) = publish(&w, 1, TO, &new_files(), FROM, &old_files(), true);
    let whole = FetchPolicy {
        full_ratio: 1,
        ..FetchPolicy::default()
    };
    let u = updater(&w, whole);
    let info = block_on(u.check()).expect("check").expect("update");
    let first = block_on(u.download(&info, DownloadOptions::default()));
    assert!(matches!(first, Err(Error::Incomplete)), "{first:?}");
    let before = w.origin.requests().len();
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");
    let reqs = requests(&w, before);
    assert_eq!(reqs, [(delta, Some("bytes=100-".to_owned()))], "a resume");
    assert!(
        w.origin.requests()[before].if_range.is_some(),
        "the resume carries If-Range"
    );
    let staged = block_on(u.stage(downloaded)).expect("stage");
    assert_staged(&w, staged.tree(), &new_files());
    workers_stopped();
}
