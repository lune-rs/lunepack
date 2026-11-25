//! `prebuilt list` through the built binary, in the state this CLI ships with. The other states are
//! decided by a function that takes the key sets and the two list files as parameters; its tests
//! (`src/prebuilt.rs`) build keys, lists and envelopes at test time.

mod common;

use common::*;

const KNOWN: [&str; 6] = [
    "no-key",
    "none",
    "pinned",
    "rehearsal",
    "other-version",
    "inconsistent",
];

#[test]
fn prebuilt_list_shows_the_shipped_state() {
    let out = run(&["prebuilt", "list"], &[]);
    assert_ok(&out, "prebuilt list");
    let text = stdout(&out);
    let state = field(&text, "state:");
    // The committed constants and files: no-key until the key ceremony, none or pinned after it.
    assert!(
        ["no-key", "none", "pinned"].contains(&state.as_str()),
        "{text}"
    );
    if state == "no-key" {
        assert!(
            text.contains("key sets: none (no project key has been published)"),
            "{text}"
        );
        assert!(!text.contains("binary:"), "{text}");
    }
}

#[test]
fn prebuilt_list_json_is_one_stable_object() {
    let out = run(&["prebuilt", "list", "--json"], &[]);
    assert_ok(&out, "prebuilt list --json");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
    let obj = v.as_object().expect("an object");
    for member in ["state", "reason", "roots", "list", "binaries"] {
        assert!(obj.contains_key(member), "no {member}: {v}");
    }
    assert!(KNOWN.contains(&v["state"].as_str().unwrap()), "{v}");
    assert!(v["roots"].is_array() && v["binaries"].is_array(), "{v}");
    if v["state"] == "no-key" {
        assert_eq!(v["roots"], serde_json::json!([]));
        assert_eq!(v["binaries"], serde_json::json!([]));
        assert!(v["list"].is_null(), "{v}");
    }
    for root in v["roots"].as_array().unwrap() {
        for key in root["keys"].as_array().unwrap() {
            assert_eq!(key["public"].as_str().unwrap().len(), 64, "{v}");
            assert_eq!(key["id"].as_str().unwrap().len(), 64, "{v}");
        }
    }
}

#[test]
fn prebuilt_list_target_must_be_a_target_id() {
    let out = run(&["prebuilt", "list", "--target", "linux-x86_64"], &[]);
    assert_ok(&out, "a known target");
    let out = run(&["prebuilt", "list", "--target", "plan9-mips"], &[]);
    let err = assert_fails(&out, 1, "an unknown target");
    assert!(err.contains("--target"), "{err}");
}
