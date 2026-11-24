//! Stable-toolchain replay of the fuzz harnesses (M2-D8, M2-D9): the committed seeds under
//! `fuzz/seeds/` are exactly what the real writers produce, every seed runs through its harness as
//! expected, and random and mutated inputs never panic. The libFuzzer targets in `fuzz/` call the
//! same harnesses (`lunepack_core::fuzz`).
//!
//! To rewrite the committed seeds after a writer change:
//! `LUNEPACK_WRITE_SEEDS=1 cargo test -p lunepack-testkit --test fuzz_replay committed_seeds`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use lunepack_core::fuzz::{HARNESSES, accepts, deltas_verdict};
use lunepack_testkit::replay::{mutated_seeds, random_inputs, seed_neighbourhood};
use lunepack_testkit::{Seed, fuzz_seeds};

fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz")
}

fn seed_dir(harness: &str) -> PathBuf {
    fuzz_dir().join("seeds").join(harness)
}

fn seeds_of(harness: &str) -> Vec<Seed> {
    fuzz_seeds()
        .into_iter()
        .filter(|s| s.harness == harness)
        .collect()
}

fn run(harness: &str, data: &[u8]) -> bool {
    accepts(harness, data).unwrap_or_else(|| panic!("no harness named {harness}"))
}

#[test]
fn committed_seeds_match_the_writer() {
    let write = std::env::var_os("LUNEPACK_WRITE_SEEDS").is_some();
    let seeds = fuzz_seeds();
    let mut problems = Vec::new();
    let mut expected: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for seed in &seeds {
        expected
            .entry(seed.harness)
            .or_default()
            .insert(seed.name.clone());
        let path = seed_dir(seed.harness).join(&seed.name);
        if write {
            fs::create_dir_all(seed_dir(seed.harness)).expect("create seed dir");
            fs::write(&path, &seed.bytes).expect("write seed");
            continue;
        }
        match fs::read(&path) {
            Ok(committed) if committed == seed.bytes => {}
            Ok(_) => problems.push(format!(
                "{}/{} differs from the writer",
                seed.harness, seed.name
            )),
            Err(_) => problems.push(format!("{}/{} is not committed", seed.harness, seed.name)),
        }
    }
    for (harness, _) in HARNESSES {
        let names = expected.get(harness).cloned().unwrap_or_default();
        assert!(!names.is_empty(), "harness {harness} has no seeds");
        if let Ok(dir) = fs::read_dir(seed_dir(harness)) {
            for entry in dir.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !names.contains(&name) {
                    problems.push(format!(
                        "{harness}/{name} is committed but no writer makes it"
                    ));
                }
            }
        }
    }
    assert!(
        problems.is_empty(),
        "seeds out of date (rerun with LUNEPACK_WRITE_SEEDS=1):\n{}",
        problems.join("\n")
    );
}

#[test]
fn every_harness_has_a_fuzz_target_and_both_kinds_of_seed() {
    for (harness, _) in HARNESSES {
        let target = fuzz_dir()
            .join("fuzz_targets")
            .join(format!("{harness}.rs"));
        let source = fs::read_to_string(&target).unwrap_or_else(|e| {
            panic!("no fuzz target for {harness} at {}: {e}", target.display())
        });
        assert!(
            source.contains(&format!("lunepack_core::fuzz::{harness}(")),
            "{} does not call lunepack_core::fuzz::{harness}",
            target.display()
        );
        let seeds = seeds_of(harness);
        assert!(
            seeds.iter().any(|s| s.accepted),
            "{harness}: no accepted seed"
        );
        assert!(
            seeds.iter().any(|s| !s.accepted),
            "{harness}: no rejected seed"
        );
    }
    let targets = fs::read_dir(fuzz_dir().join("fuzz_targets"))
        .expect("fuzz_targets dir")
        .flatten()
        .count();
    // `codec` and `patch` are the codec crate's harnesses (its own replay test covers them).
    assert_eq!(
        targets,
        HARNESSES.len() + 2,
        "a fuzz target without a harness"
    );
}

#[test]
fn committed_seeds_run_as_expected() {
    for (harness, _) in HARNESSES {
        let expected: BTreeMap<String, bool> = seeds_of(harness)
            .into_iter()
            .map(|s| (s.name, s.accepted))
            .collect();
        let mut seen = 0;
        for entry in fs::read_dir(seed_dir(harness)).expect("seed dir").flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let bytes = fs::read(entry.path()).expect("read seed");
            let got = run(harness, &bytes);
            if let Some(&want) = expected.get(&name) {
                assert_eq!(
                    got, want,
                    "{harness}/{name}: accepted = {got}, expected {want}"
                );
            }
            seen += 1;
        }
        assert!(seen > 0, "{harness}: no committed seeds");
    }
}

/// Every single-byte change, every truncation and every one-byte insertion of every seed (strided
/// for the largest seeds so the whole test stays quick).
#[test]
fn seed_neighbourhoods_do_not_panic() {
    for (harness, _) in HARNESSES {
        for seed in seeds_of(harness) {
            seed_neighbourhood(&seed.bytes, |data| {
                run(harness, data);
            });
        }
    }
}

fn replay_harness(harness: &str) {
    random_inputs(harness, |data| {
        run(harness, data);
    });
    mutated_seeds(
        harness,
        seeds_of(harness).into_iter().map(|s| s.bytes).collect(),
        |data| {
            run(harness, data);
        },
    );
}

macro_rules! replay {
    ($($name:ident),* $(,)?) => {$(
        #[test]
        fn $name() {
            replay_harness(stringify!($name));
        }
    )*};
}

replay!(
    envelope,
    root,
    keys,
    feed,
    manifest,
    deltas,
    path,
    tree,
    rules,
    json,
    frame,
    http,
    state,
    update_config,
    setup,
    service,
    ui
);

#[test]
fn the_replay_list_covers_every_harness() {
    let named: BTreeSet<&str> = [
        "envelope",
        "root",
        "keys",
        "feed",
        "manifest",
        "deltas",
        "path",
        "tree",
        "rules",
        "json",
        "frame",
        "http",
        "state",
        "update_config",
        "setup",
        "service",
        "ui",
    ]
    .into_iter()
    .collect();
    let all: BTreeSet<&str> = HARNESSES.iter().map(|(n, _)| *n).collect();
    assert_eq!(named, all);
}

/// A `deltas` seed is refused for the reason its name gives, not for another one (the fixture is
/// valid, so the input is the only thing that can be wrong).
#[test]
fn deltas_seeds_are_refused_for_their_reason() {
    let seeds = seeds_of("deltas");
    let ok = seeds.iter().filter(|s| s.accepted).count();
    assert!(ok >= 3, "deltas: {ok} accepted seeds, at least 3");
    for seed in &seeds {
        let verdict = deltas_verdict(&seed.bytes);
        if seed.accepted {
            assert_eq!(verdict, Ok(()), "deltas/{}", seed.name);
            assert_eq!(seed.reason, None, "deltas/{}", seed.name);
        } else {
            let reason = seed
                .reason
                .unwrap_or_else(|| panic!("deltas/{} names no reason", seed.name));
            let err = verdict.expect_err(&seed.name);
            assert!(
                err.contains(reason),
                "deltas/{}: refused with {err:?}, expected a reason containing {reason:?}",
                seed.name
            );
        }
    }
}

/// More than 200,000 patches in one delta (FORMAT.md 9.3): built here and not committed, since it
/// is some 45 MB of JSON.
#[test]
fn deltas_with_too_many_patches_are_refused_for_it() {
    let seeds = seeds_of("deltas");
    let one = seeds
        .iter()
        .find(|s| s.name == "ok-one-delta")
        .expect("the one-delta seed");
    let text = std::str::from_utf8(&one.bytes).expect("utf-8");
    // `[{"from":..,"patches":[ P ]}]` with P the writer's one patch object repeated.
    let start = text.find("\"patches\":[").expect("patches") + "\"patches\":[".len();
    let end = text.rfind("]}]").expect("patches end");
    let patch = &text[start..end];
    assert!(patch.starts_with('{') && patch.ends_with('}'), "{patch}");
    let many = format!(
        "{}{}{}",
        &text[..start],
        vec![patch; 200_001].join(","),
        &text[end..]
    );
    let err = deltas_verdict(many.as_bytes()).expect_err("too many patches");
    assert!(
        err.contains("200001 patches, at most 200000"),
        "refused with {err:?}"
    );
}
