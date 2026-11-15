//! A recording [`OsIntegration`] and the contract suite for the real ones.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lunepack_core::{
    AppId, InstallMeta, IntegrationError, IntegrationItem, IntegrationReport, IntegrationRequest,
    OsIntegration, RelPath, Scope,
};

/// Which operation a [`IntegrationCall`] was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrationOp {
    /// `OsIntegration::check`.
    Check,
    /// `OsIntegration::apply`.
    Apply,
    /// `OsIntegration::remove`.
    Remove,
}

/// One call the fake saw.
#[derive(Debug, Clone)]
pub struct IntegrationCall {
    /// The operation.
    pub op: IntegrationOp,
    /// The scope it was called with.
    pub scope: Scope,
    /// The app id.
    pub app_id: String,
    /// The install root.
    pub install_root: PathBuf,
    /// The metadata.
    pub meta: InstallMeta,
    /// The stale command-link names the request carried.
    pub stale_bins: Vec<String>,
}

#[derive(Default)]
struct Inner {
    calls: Vec<IntegrationCall>,
    applied: BTreeMap<String, InstallMeta>,
    conflict: Option<IntegrationItem>,
    failure: Option<&'static str>,
}

/// An [`OsIntegration`] that creates nothing: it records every call, remembers which app ids are
/// applied (with the metadata of the last apply), and fails where a test scripts it to. Machine
/// scope is `Unsupported`, as in the real adapters. Clones share one state.
#[derive(Clone, Default)]
pub struct FakeIntegration {
    inner: Arc<Mutex<Inner>>,
}

fn lock(m: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FakeIntegration {
    /// A fake with nothing applied.
    pub fn new() -> FakeIntegration {
        FakeIntegration::default()
    }

    /// Makes `check` and `apply` fail with `Conflict(item)` until cleared with `None`.
    pub fn script_conflict(&self, item: Option<IntegrationItem>) {
        lock(&self.inner).conflict = item;
    }

    /// Makes `apply` fail with `Failed(what)` until cleared with `None`.
    pub fn script_failure(&self, what: Option<&'static str>) {
        lock(&self.inner).failure = what;
    }

    /// Every call so far, in order.
    pub fn calls(&self) -> Vec<IntegrationCall> {
        lock(&self.inner).calls.clone()
    }

    /// The app ids that are applied now.
    pub fn applied(&self) -> BTreeSet<String> {
        lock(&self.inner).applied.keys().cloned().collect()
    }

    /// The metadata of the last successful `apply` for `app_id`.
    pub fn applied_meta(&self, app_id: &str) -> Option<InstallMeta> {
        lock(&self.inner).applied.get(app_id).cloned()
    }

    fn enter(
        &self,
        op: IntegrationOp,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<MutexGuard<'_, Inner>, IntegrationError> {
        let mut inner = lock(&self.inner);
        inner.calls.push(IntegrationCall {
            op,
            scope,
            app_id: req.app_id.as_str().to_owned(),
            install_root: req.install_root.clone(),
            meta: req.meta.clone(),
            stale_bins: req.stale_bins.clone(),
        });
        if scope != Scope::User {
            return Err(IntegrationError::Unsupported);
        }
        Ok(inner)
    }
}

impl OsIntegration for FakeIntegration {
    fn check(&self, scope: Scope, req: &IntegrationRequest) -> Result<(), IntegrationError> {
        let inner = self.enter(IntegrationOp::Check, scope, req)?;
        match inner.conflict {
            Some(item) => Err(IntegrationError::Conflict(item)),
            None => Ok(()),
        }
    }

    fn apply(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        let mut inner = self.enter(IntegrationOp::Apply, scope, req)?;
        if let Some(item) = inner.conflict {
            return Err(IntegrationError::Conflict(item));
        }
        if let Some(what) = inner.failure {
            return Err(IntegrationError::Failed(what));
        }
        inner
            .applied
            .insert(req.app_id.as_str().to_owned(), req.meta.clone());
        Ok(IntegrationReport::default())
    }

    fn remove(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        let mut inner = self.enter(IntegrationOp::Remove, scope, req)?;
        inner.applied.remove(req.app_id.as_str());
        Ok(IntegrationReport::default())
    }
}

// ---- the contract suite ----

/// What the sandbox holds, for comparing before and after: every file (its bytes) and symlink (its
/// target) below `root`, by relative path. Directories are not listed, so an adapter may leave the
/// empty directories it made.
fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let entry = entry.expect("read the sandbox");
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .expect("inside the sandbox")
                .to_string_lossy()
                .into_owned();
            let kind = entry.file_type().expect("file type");
            if kind.is_symlink() {
                let target = std::fs::read_link(&path).expect("read a link");
                out.insert(rel, format!("-> {}", target.to_string_lossy()));
            } else if kind.is_dir() {
                walk(&path, root, out);
            } else {
                let bytes = std::fs::read(&path).expect("read a file");
                out.insert(rel, format!("file {}", String::from_utf8_lossy(&bytes)));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn suite_request(sandbox: &Path, id: &str, name: &str, bin: &str) -> IntegrationRequest {
    IntegrationRequest {
        app_id: AppId::parse(id).expect("suite app id"),
        install_root: sandbox.join(format!("suite-install-{id}")),
        meta: InstallMeta {
            entry: RelPath::parse("bin/app").expect("suite entry"),
            name: name.to_owned(),
            comment: Some("A suite app".to_owned()),
            icon: Some(RelPath::parse("share/icon.png").expect("suite icon")),
            categories: vec!["Utility".to_owned(), "Development".to_owned()],
            bin: Some(bin.to_owned()),
            terminal: false,
        },
        stale_bins: Vec::new(),
    }
}

/// The contract suite for a real [`OsIntegration`]. `sandbox` is an empty directory that the
/// adapter under test has been configured to treat as the user's whole home (its data home and
/// its bin directory are below it), so nothing leaves it; the caller removes it afterwards.
///
/// The suite checks, by comparing what the sandbox holds before and after each call (files and
/// links, not directories): `check` writes nothing; `apply` creates something, is idempotent, and
/// refreshes from changed metadata and back; two apps coexist and `remove` takes only its own
/// app's entries; `remove` is repeatable and leaves the sandbox as it found it; per-machine scope
/// is `Unsupported` for all three operations and writes nothing; unsafe metadata (a newline or a
/// separator in a text field, a path separator or `..` in `bin`, a quote or `%` in the install
/// root) is refused by `check` and `apply`, writes nothing, and the error does not show the
/// value; `apply` and `remove` report nothing kept on a clean run. The install root of a request
/// need not exist.
pub fn run_integration_suite(integration: &dyn OsIntegration, sandbox: &Path) {
    let empty = snapshot(sandbox);
    assert!(empty.is_empty(), "the sandbox must start empty");
    let a = suite_request(sandbox, "suite.app-a", "Suite App A", "suite-app-a");
    let b = suite_request(sandbox, "suite.app-b", "Suite App B", "suite-app-b");

    // check writes nothing.
    integration.check(Scope::User, &a).expect("check");
    assert_eq!(snapshot(sandbox), empty, "check wrote something");

    // remove before apply: nothing to do, not an error.
    integration
        .remove(Scope::User, &a)
        .expect("remove with nothing applied");
    assert_eq!(
        snapshot(sandbox),
        empty,
        "remove of nothing changed the sandbox"
    );

    // apply creates, and is idempotent.
    let report = integration.apply(Scope::User, &a).expect("apply");
    assert!(
        report.kept.is_empty(),
        "apply left something on a clean run"
    );
    let applied = snapshot(sandbox);
    assert_ne!(applied, empty, "apply created nothing");
    integration.apply(Scope::User, &a).expect("apply again");
    assert_eq!(
        snapshot(sandbox),
        applied,
        "a second apply changed something"
    );

    // A refresh from changed metadata changes content, not the set of entries; refreshing back
    // restores the first state exactly.
    let renamed = suite_request(sandbox, "suite.app-a", "Suite App Renamed", "suite-app-a");
    integration.apply(Scope::User, &renamed).expect("refresh");
    let refreshed = snapshot(sandbox);
    assert_ne!(
        refreshed, applied,
        "a refresh with a new name changed nothing"
    );
    assert_eq!(
        refreshed.keys().collect::<Vec<_>>(),
        applied.keys().collect::<Vec<_>>(),
        "a refresh changed which entries exist"
    );
    integration.apply(Scope::User, &a).expect("refresh back");
    assert_eq!(
        snapshot(sandbox),
        applied,
        "refreshing back did not restore"
    );

    // remove takes it all away.
    let report = integration.remove(Scope::User, &a).expect("remove");
    assert!(report.kept.is_empty(), "remove kept what it made");
    assert_eq!(snapshot(sandbox), empty, "remove left something behind");
    integration.remove(Scope::User, &a).expect("remove again");
    assert_eq!(
        snapshot(sandbox),
        empty,
        "a second remove changed something"
    );

    // Two apps coexist; removing one leaves the other exactly as it was.
    integration.apply(Scope::User, &b).expect("apply b");
    let only_b = snapshot(sandbox);
    integration
        .apply(Scope::User, &a)
        .expect("apply a next to b");
    assert_ne!(snapshot(sandbox), only_b, "the second app added nothing");
    integration.remove(Scope::User, &a).expect("remove a");
    assert_eq!(snapshot(sandbox), only_b, "removing a touched b");
    integration.remove(Scope::User, &b).expect("remove b");
    assert_eq!(snapshot(sandbox), empty, "removing b left something behind");

    // Per-machine scope is unsupported, for every operation.
    for (what, result) in [
        ("check", integration.check(Scope::Machine, &a)),
        ("apply", integration.apply(Scope::Machine, &a).map(|_| ())),
        ("remove", integration.remove(Scope::Machine, &a).map(|_| ())),
    ] {
        assert!(
            matches!(result, Err(IntegrationError::Unsupported)),
            "machine scope {what}: {result:?}"
        );
    }
    assert_eq!(snapshot(sandbox), empty, "machine scope wrote something");

    unsafe_cases(integration, sandbox, &a, &empty);
}

fn unsafe_cases(
    integration: &dyn OsIntegration,
    sandbox: &Path,
    good: &IntegrationRequest,
    empty: &BTreeMap<String, String>,
) {
    const MARK: &str = "SUITE-MARKER";
    let mut cases: Vec<(&str, IntegrationRequest)> = Vec::new();
    let mut with = |what: &'static str, edit: &dyn Fn(&mut IntegrationRequest)| {
        let mut req = good.clone();
        edit(&mut req);
        cases.push((what, req));
    };
    with("a newline in the name", &|r| {
        r.meta.name = format!("{MARK}\nExec=evil");
    });
    with("a newline in the comment", &|r| {
        r.meta.comment = Some(format!("{MARK}\nExec=evil"));
    });
    with("a semicolon in a category", &|r| {
        r.meta.categories = vec![format!("{MARK};Evil")];
    });
    with("a newline in a category", &|r| {
        r.meta.categories = vec![format!("{MARK}\nExec=evil")];
    });
    with("a slash in bin", &|r| {
        r.meta.bin = Some(format!("{MARK}/x"));
    });
    with("dot dot in bin", &|r| {
        r.meta.bin = Some(format!("../{MARK}"));
    });
    with("a quote in the install root", &|r| {
        r.install_root = sandbox.join(format!("{MARK}\"quoted"));
    });
    with("a percent sign in the install root", &|r| {
        r.install_root = sandbox.join(format!("{MARK}%f"));
    });
    for (what, req) in &cases {
        for (op, result) in [
            ("check", integration.check(Scope::User, req)),
            ("apply", integration.apply(Scope::User, req).map(|_| ())),
        ] {
            let err = result.expect_err(what);
            let shown = format!("{err} / {err:?}");
            assert!(
                !shown.contains(MARK),
                "{what}, {op}: shows the value: {shown}"
            );
            assert_eq!(&snapshot(sandbox), empty, "{what}, {op}: wrote something");
        }
    }
}
