//! The publisher check at stage (M9 step 8, M9-D9): the installed tree's policy decides, a refusal
//! records nothing staged and marks the version bad only on a finding about the candidate, a local
//! fault is retried, a warning reaches the result and a `tracing` event, and a first install runs
//! no check. Every case runs over MemFs with the testkit's fake check, through the facade's
//! [`Installation`] and [`Platform`] (the runtime's own path) unless it needs a tree with no config.

mod common;

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use common::{INSTALL_ID, TARGET, World, app_id, channel, files, serial, version, workers_stopped};
use lunepack::{
    DownloadOptions, Error, Installation, Layout, Platform, PublisherError, PublisherOutcome,
    PublisherPolicy, StagedVersion, Updater, UpdaterBuilder, block_on,
};
use lunepack_core::state::{InstallState, Scope, UserScope};
use lunepack_core::{CodecId, Fs, InstallMeta, LayoutScheme, RelPath, UpdateConfig};
use lunepack_testkit::{
    FakeCodec, FakeHasher, FakeIntegration, FakeProcess, FakePublisherCheck, FakeRng, FakeVerifier,
    PackBuilder, SUITE_T0, abs_path,
};

const DATA_HOME: &str = "/home/u/.local/share";
const FEED: &str = "https://fake.invalid/";
const V100: &str = "1.0.0";
const V110: &str = "1.1.0";
const CONFIG: &str = "lunepack-update.json";
const DAY: u64 = 86_400;

fn root_dir() -> PathBuf {
    abs_path(DATA_HOME).join(app_id().as_str())
}

fn tree_dir(v: &str) -> PathBuf {
    root_dir().join("versions").join(v)
}

fn meta() -> InstallMeta {
    InstallMeta {
        entry: RelPath::parse("bin/app").expect("entry"),
        name: "App".to_owned(),
        comment: None,
        icon: None,
        categories: Vec::new(),
        bin: None,
        terminal: false,
        publisher: None,
        file_types: Vec::new(),
        url_schemes: Vec::new(),
        autostart: false,
    }
}

fn write_file(fs: &dyn Fs, path: &std::path::Path, bytes: &[u8]) {
    fs.create_dir_all(path.parent().expect("parent"))
        .expect("dirs");
    let mut w = fs.create_new(path).expect("create");
    std::io::Write::write_all(&mut w, bytes).expect("write");
    w.sync().expect("sync");
}

/// An installed 1.0.0 (record and tree) and a published 1.1.0, with a fake publisher check.
struct Lab {
    w: World,
    fake: Arc<FakePublisherCheck>,
}

impl Lab {
    /// `installed` and `candidate` are the policies written into each tree's config (`None`: no
    /// config at all); the fake answers `script`.
    fn new(
        installed: Option<PublisherPolicy>,
        candidate: Option<PublisherPolicy>,
        script: Vec<Result<bool, PublisherError>>,
    ) -> Lab {
        let lab = Lab {
            w: World::new(),
            fake: Arc::new(FakePublisherCheck::new(script)),
        };
        let fs = &lab.w.fs;
        for (path, bytes) in files(V100) {
            write_file(fs, &tree_dir(V100).join(path), &bytes);
        }
        if let Some(policy) = installed {
            let cfg = lab.config(V100, policy).to_bytes().expect("bytes");
            write_file(fs, &tree_dir(V100).join(CONFIG), &cfg);
        }
        let store = UserScope {
            dir: root_dir().join("state"),
            app_id: app_id(),
        };
        let loaded = store.load(fs, &FakeHasher).expect("load");
        let record = InstallState::new(1, app_id(), Scope::User, INSTALL_ID, TARGET).install(
            version(V100),
            SUITE_T0 - 10 * DAY,
            TARGET,
            INSTALL_ID,
        );
        store
            .commit(fs, &loaded, &record, &FakeHasher)
            .expect("commit");
        lab.publish(V110, candidate);
        lab
    }

    fn config(&self, v: &str, policy: PublisherPolicy) -> UpdateConfig {
        let mut cfg = UpdateConfig::new(
            &self.w.root(),
            version(v),
            TARGET,
            FEED,
            channel(),
            60,
            meta(),
        )
        .expect("config");
        cfg.publisher_check = policy;
        cfg
    }

    /// Publishes `v` (feed `seq` 1) with its config inside the pack when `policy` is given.
    fn publish(&self, v: &str, policy: Option<PublisherPolicy>) {
        let mut pack = PackBuilder::new();
        for (path, bytes) in files(v) {
            pack.file(&FakeHasher, &path, &bytes, CodecId::Lzma2);
        }
        if let Some(policy) = policy {
            let cfg = self.config(v, policy).to_bytes().expect("bytes");
            pack.file(&FakeHasher, CONFIG, &cfg, CodecId::Lzma2);
        }
        self.w.publish_pack(1, v, &pack);
    }

    fn platform(&self) -> Platform {
        Platform::native()
            .with_fs(Arc::new(self.w.fs.clone()))
            .with_hasher(Arc::new(FakeHasher))
            .with_verifier(Arc::new(FakeVerifier))
            .with_process(Arc::new(FakeProcess::new("/unused")))
            .with_integration(Arc::new(FakeIntegration::new()))
            .with_rng(Arc::new(FakeRng::new(9)))
            .with_data_home(abs_path(DATA_HOME))
            .with_layout_scheme(LayoutScheme::XDG)
            .with_publisher_check(Arc::clone(&self.fake) as Arc<dyn lunepack::PublisherCheck>)
    }

    fn finish(&self, builder: UpdaterBuilder) -> Updater {
        builder
            .transport(Arc::clone(&self.w.transport))
            .codec(Arc::new(FakeCodec::new()))
            .clock(Arc::clone(&self.w.clock) as Arc<dyn lunepack_core::Clock>)
            .workers(2)
            .build()
            .expect("build")
    }

    /// The updater of the installed 1.0.0, as an app (or the runtime) gets it: from its tree's
    /// entry, through the platform.
    fn updater(&self) -> Updater {
        let exe = tree_dir(V100).join("bin/app");
        let inst = Installation::from_exe_with(&exe, self.platform()).expect("installation");
        self.finish(inst.updater_builder().expect("builder"))
    }

    /// The updater built directly over the install's layout (a tree with no config cannot be
    /// opened as an [`Installation`]).
    fn bare_updater(&self) -> Updater {
        let root = root_dir();
        let layout = Layout::User {
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
            versions_dir: root.join("versions"),
            current_tree: None,
        };
        let builder = UpdaterBuilder::new(app_id(), self.w.root(), FEED, channel(), layout)
            .fs(Arc::new(self.w.fs.clone()))
            .hasher(Arc::new(FakeHasher))
            .verifier(Arc::new(FakeVerifier))
            .publisher_check(Arc::clone(&self.fake) as Arc<dyn lunepack::PublisherCheck>);
        self.finish(builder)
    }

    fn record(&self) -> InstallState {
        UserScope {
            dir: root_dir().join("state"),
            app_id: app_id(),
        }
        .load(&self.w.fs, &FakeHasher)
        .expect("load")
        .record
        .expect("record")
    }
}

/// Check, download and stage the update `u` finds (there must be one).
fn stage(u: &Updater) -> Result<StagedVersion, Error> {
    let info = block_on(u.check()).expect("check").expect("an update");
    let downloaded = block_on(u.download(&info, DownloadOptions::default())).expect("download");
    block_on(u.stage(downloaded))
}

fn refused(got: Result<StagedVersion, Error>) -> PublisherOutcome {
    match got {
        Err(Error::PublisherMismatch { reason }) => reason,
        other => panic!("expected a publisher refusal, got {other:?}"),
    }
}

/// The installed tree's `enforce` governs even when the candidate's own config says `off`: the
/// check runs on the two trees, `different` is refused, nothing is staged, the version is bad, and
/// the next check offers nothing.
#[test]
fn enforce_refuses_a_different_publisher_even_when_the_candidate_says_off() {
    let _s = serial();
    let lab = Lab::new(
        Some(PublisherPolicy::Enforce),
        Some(PublisherPolicy::Off),
        vec![Ok(false)],
    );
    let u = lab.updater();
    assert_eq!(refused(stage(&u)), PublisherOutcome::Different);

    let calls = lab.fake.calls();
    assert_eq!(calls.len(), 1);
    let (installed, candidate) = &calls[0];
    assert_eq!(installed.root, tree_dir(V100));
    assert_eq!(installed.entry.as_str(), "bin/app");
    assert_eq!(candidate.root, tree_dir(V110));
    assert_eq!(candidate.entry.as_str(), "bin/app");

    let rec = lab.record();
    assert_eq!(rec.bad, vec![version(V110)]);
    assert!(rec.staged.is_none() && rec.staged_issued.is_none());
    assert_eq!(u.staged().expect("staged"), None);
    assert!(block_on(u.check()).expect("check").is_none());
    assert_eq!(lab.fake.calls().len(), 1, "no second check ran");
    workers_stopped();
}

/// The other findings about the candidate's own signature are marked bad the same way.
#[test]
fn an_unsigned_or_invalid_candidate_is_refused_and_marked_bad() {
    let _s = serial();
    for (answer, want) in [
        (
            PublisherError::CandidateUnsigned,
            PublisherOutcome::CandidateUnsigned,
        ),
        (
            PublisherError::CandidateInvalid,
            PublisherOutcome::CandidateInvalid,
        ),
    ] {
        let lab = Lab::new(
            Some(PublisherPolicy::Enforce),
            Some(PublisherPolicy::Enforce),
            vec![Err(answer)],
        );
        let u = lab.updater();
        assert_eq!(refused(stage(&u)), want);
        let rec = lab.record();
        assert_eq!(rec.bad, vec![version(V110)], "{want:?}");
        assert!(rec.staged.is_none());
        assert!(block_on(u.check()).expect("check").is_none(), "{want:?}");
        workers_stopped();
    }
}

/// A local fault (`os`) and a broken installed signature (`installed_invalid`) are refused under
/// `enforce` but mark nothing: the next call checks the same version again and, when the check
/// then says "same publisher", stages it (over the tree the refused call left behind).
#[test]
fn a_local_fault_marks_nothing_and_a_later_call_checks_again() {
    let _s = serial();
    for (answer, want) in [
        (PublisherError::Os, PublisherOutcome::Os),
        (
            PublisherError::InstalledInvalid,
            PublisherOutcome::InstalledInvalid,
        ),
    ] {
        let lab = Lab::new(
            Some(PublisherPolicy::Enforce),
            Some(PublisherPolicy::Enforce),
            vec![Err(answer), Ok(true)],
        );
        let u = lab.updater();
        assert_eq!(refused(stage(&u)), want);
        let rec = lab.record();
        assert!(rec.bad.is_empty(), "{want:?}");
        assert!(rec.staged.is_none(), "{want:?}");
        assert_eq!(u.staged().expect("staged"), None);

        let staged = stage(&u).expect("the retry stages");
        assert_eq!(staged.version(), &version(V110));
        assert_eq!(staged.publisher(), None);
        assert_eq!(lab.fake.calls().len(), 2);
        let rec = lab.record();
        assert_eq!(
            rec.staged.as_ref().map(|s| s.version.clone()),
            Some(version(V110))
        );
        assert!(rec.bad.is_empty());
        workers_stopped();
    }
}

/// `warn` stages whatever the check says and reports the finding on the result; the re-opened
/// staged version does not carry it (it is not recorded).
#[test]
fn warn_proceeds_and_reports_the_finding() {
    let _s = serial();
    for (answer, want) in [
        (Ok(false), PublisherOutcome::Different),
        (
            Err(PublisherError::CandidateUnsigned),
            PublisherOutcome::CandidateUnsigned,
        ),
        (Err(PublisherError::Os), PublisherOutcome::Os),
    ] {
        let lab = Lab::new(
            Some(PublisherPolicy::Warn),
            Some(PublisherPolicy::Warn),
            vec![answer],
        );
        let u = lab.updater();
        let staged = stage(&u).expect("stage");
        assert_eq!(staged.publisher(), Some(want));
        let rec = lab.record();
        assert!(rec.bad.is_empty());
        assert_eq!(
            rec.staged.as_ref().map(|s| s.version.clone()),
            Some(version(V110))
        );
        let reopened = u.staged().expect("staged").expect("a staged version");
        assert_eq!(reopened.version(), staged.version());
        assert_eq!(reopened.publisher(), None);
        workers_stopped();
    }
}

/// `enforce` lets through the same publisher and a platform with no check silently, and an
/// unsigned installed version (no baseline yet) with the finding reported.
#[test]
fn enforce_proceeds_on_same_not_applicable_and_no_baseline() {
    let _s = serial();
    for (answer, want) in [
        (Ok(true), None),
        (Err(PublisherError::NotApplicable), None),
        (
            Err(PublisherError::InstalledUnsigned),
            Some(PublisherOutcome::InstalledUnsigned),
        ),
    ] {
        let lab = Lab::new(
            Some(PublisherPolicy::Enforce),
            Some(PublisherPolicy::Enforce),
            vec![answer],
        );
        let staged = stage(&lab.updater()).expect("stage");
        assert_eq!(staged.publisher(), want);
        assert!(lab.record().bad.is_empty());
        assert_eq!(lab.fake.calls().len(), 1);
        workers_stopped();
    }
}

/// `off` (a config without the member) runs no check, whatever the candidate's config says; so
/// does an installed tree with no config at all.
#[test]
fn off_or_no_installed_config_runs_no_check() {
    let _s = serial();
    let lab = Lab::new(
        Some(PublisherPolicy::Off),
        Some(PublisherPolicy::Enforce),
        vec![Ok(false)],
    );
    let staged = stage(&lab.updater()).expect("stage");
    assert_eq!(staged.publisher(), None);
    assert!(lab.fake.calls().is_empty());
    workers_stopped();

    let lab = Lab::new(None, Some(PublisherPolicy::Enforce), vec![Ok(false)]);
    let staged = stage(&lab.bare_updater()).expect("stage");
    assert_eq!(staged.publisher(), None);
    assert!(lab.fake.calls().is_empty());
    workers_stopped();
}

/// An installed config that is there but cannot be read fails the stage closed: nothing staged,
/// nothing marked, no check.
#[test]
fn an_unreadable_installed_config_fails_closed() {
    let _s = serial();
    let lab = Lab::new(None, Some(PublisherPolicy::Enforce), vec![Ok(true)]);
    write_file(&lab.w.fs, &tree_dir(V100).join(CONFIG), b"{ not json");
    let got = stage(&lab.bare_updater());
    assert!(matches!(got, Err(Error::UpdateConfig(_))), "{got:?}");
    let rec = lab.record();
    assert!(rec.bad.is_empty() && rec.staged.is_none());
    assert!(lab.fake.calls().is_empty());
    workers_stopped();
}

/// Under a policy that runs the check, a candidate with no config of its own (no entry to judge)
/// fails closed: nothing staged, nothing marked.
#[test]
fn a_candidate_without_a_config_fails_closed_under_a_policy() {
    let _s = serial();
    let lab = Lab::new(Some(PublisherPolicy::Enforce), None, vec![Ok(true)]);
    let got = stage(&lab.updater());
    assert!(matches!(got, Err(Error::NoUpdateConfig)), "{got:?}");
    let rec = lab.record();
    assert!(rec.bad.is_empty() && rec.staged.is_none());
    assert!(lab.fake.calls().is_empty());
    workers_stopped();
}

/// A first install has no installed publisher: the bootstrap's `enforce` runs no check.
#[test]
fn a_first_install_runs_no_check() {
    let _s = serial();
    let w = World::new();
    let fake = Arc::new(FakePublisherCheck::new(vec![Ok(false)]));
    let lab = Lab {
        w,
        fake: Arc::clone(&fake),
    };
    lab.publish(V100, Some(PublisherPolicy::Enforce));
    let boot = abs_path("/media/boot/1.0.0");
    for (path, bytes) in files(V100) {
        write_file(&lab.w.fs, &boot.join(path), &bytes);
    }
    let cfg = lab
        .config(V100, PublisherPolicy::Enforce)
        .to_bytes()
        .expect("bytes");
    write_file(&lab.w.fs, &boot.join(CONFIG), &cfg);
    let inst =
        Installation::from_exe_with(&boot.join("bin/app"), lab.platform()).expect("bootstrap");
    let u = lab.finish(inst.updater_builder().expect("builder"));
    let got = block_on(u.install(DownloadOptions::default())).expect("install");
    assert_eq!(got.version(), &version(V100));
    assert!(fake.calls().is_empty());
    workers_stopped();
}

/// The refusal's text is the closed code only: no path, no certificate text.
#[test]
fn the_refusal_names_only_its_code() {
    for reason in [
        PublisherOutcome::Different,
        PublisherOutcome::InstalledInvalid,
        PublisherOutcome::CandidateUnsigned,
        PublisherOutcome::CandidateInvalid,
        PublisherOutcome::Os,
    ] {
        let text = Error::PublisherMismatch { reason }.to_string();
        assert_eq!(
            text,
            format!(
                "the update's code-signing publisher was refused: {}",
                reason.code()
            )
        );
    }
}

// ---- the `tracing` warning -----------------------------------------------------------------------

/// A subscriber that keeps every event's fields as `name=value` text.
#[derive(Default)]
struct Capture(Mutex<Vec<String>>);

struct Fields<'a>(&'a mut Vec<String>);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.0.push(format!("{}={value:?}", field.name()));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push(format!("{}={value}", field.name()));
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Vec::new();
        event.record(&mut Fields(&mut fields));
        let level = *event.metadata().level();
        let mut line = format!("{level}");
        for f in fields {
            line.push(' ');
            line.push_str(&f);
        }
        self.0.lock().expect("capture").push(line);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// A finding is one `tracing` warning that names the code and nothing else: no path, no version
/// tree, no subject.
#[test]
fn a_finding_is_a_warning_with_the_code_only() {
    let _s = serial();
    let capture = Arc::new(Capture::default());
    for (policy, answer, code) in [
        (
            PublisherPolicy::Warn,
            Err(PublisherError::CandidateUnsigned),
            "candidate_unsigned",
        ),
        (PublisherPolicy::Enforce, Ok(false), "different"),
    ] {
        let lab = Lab::new(Some(policy), Some(policy), vec![answer]);
        let u = lab.updater();
        let _ = tracing::subscriber::with_default(Arc::clone(&capture), || stage(&u));
        let lines = capture.0.lock().expect("capture").clone();
        let warnings: Vec<&String> = lines
            .iter()
            .filter(|l| l.starts_with("WARN") && l.contains("publisher="))
            .collect();
        assert_eq!(warnings.len(), 1, "{lines:?}");
        assert!(
            warnings[0].contains(&format!("publisher={code}")),
            "{lines:?}"
        );
        let root = root_dir().to_string_lossy().into_owned();
        for line in &lines {
            assert!(!line.contains(&root), "a path in {line}");
        }
        capture.0.lock().expect("capture").clear();
        workers_stopped();
    }
}
