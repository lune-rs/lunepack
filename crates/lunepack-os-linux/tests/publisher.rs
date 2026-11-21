//! `NoPublisherCheck` against the shared publisher suite: Linux has no check, so every pair is
//! `NotApplicable` (and every policy lets the update through).

use lunepack_core::{
    Decision, PublisherCheck, PublisherError, PublisherPolicy, RelPath, SignedTree, decide,
};
use lunepack_os_linux::NoPublisherCheck;
use lunepack_testkit::{PublisherSuite, run_publisher_suite};

#[test]
fn linux_has_no_publisher_check() {
    let dir = std::env::temp_dir().join(format!("lunepack-linux-publisher-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    run_publisher_suite(&NoPublisherCheck, PublisherSuite::NotApplicable, &dir);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn not_applicable_lets_every_policy_through_unreported() {
    let tree = SignedTree {
        root: std::env::temp_dir(),
        entry: RelPath::parse("bin/app").unwrap(),
    };
    let result = NoPublisherCheck.same_publisher(&tree, &tree);
    assert_eq!(result, Err(PublisherError::NotApplicable));
    for policy in [
        PublisherPolicy::Off,
        PublisherPolicy::Warn,
        PublisherPolicy::Enforce,
    ] {
        assert_eq!(
            decide(policy, result),
            Decision::Proceed(None),
            "{policy:?}"
        );
    }
}
