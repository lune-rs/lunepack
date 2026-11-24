//! Stable-toolchain replay generators for fuzz harnesses (M2-D8, M2-D9): random inputs, mutations
//! of seeds, and the neighbourhood of one seed. Each takes a `run` closure that feeds an input to
//! a harness and must return for every input; a panic in it fails the calling test, with the
//! `label` in the message. Shared by the core's replay test (`fuzz_replay`) and the codec crate's.

use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};

/// Random inputs per harness (M2 step 11 contract).
pub const RANDOM_CASES: u32 = 10_000;
/// Mutated-seed inputs per harness.
pub const MUTATED_CASES: u32 = 10_000;
/// Longest random input.
pub const MAX_RANDOM_LEN: usize = 1024;

fn runner(cases: u32) -> TestRunner {
    TestRunner::new(Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    })
}

/// [`RANDOM_CASES`] random inputs of up to [`MAX_RANDOM_LEN`] bytes through `run`.
pub fn random_inputs(label: &str, run: impl Fn(&[u8])) {
    let strategy = prop::collection::vec(any::<u8>(), 0..MAX_RANDOM_LEN);
    runner(RANDOM_CASES)
        .run(&strategy, |data| {
            run(&data);
            Ok(())
        })
        .unwrap_or_else(|e| panic!("{label}: random input: {e}"));
}

/// [`MUTATED_CASES`] inputs, each a seed of `seeds` with one to seven edits (a flipped byte, an
/// inserted byte or a removed byte), through `run`. `seeds` must not be empty.
pub fn mutated_seeds(label: &str, seeds: Vec<Vec<u8>>, run: impl Fn(&[u8])) {
    let strategy = (
        prop::sample::select(seeds),
        prop::collection::vec((any::<u16>(), any::<u8>(), 0u8..3), 1..8),
    );
    runner(MUTATED_CASES)
        .run(&strategy, |(mut data, edits)| {
            for (at, byte, op) in edits {
                let at = usize::from(at) % (data.len() + 1);
                match op {
                    0 if at < data.len() => data[at] ^= byte | 1,
                    1 => data.insert(at, byte),
                    _ if at < data.len() => {
                        data.remove(at);
                    }
                    _ => {}
                }
            }
            run(&data);
            Ok(())
        })
        .unwrap_or_else(|e| panic!("{label}: mutated seed: {e}"));
}

/// Every single-byte change, every truncation and every one-byte insertion of `bytes` (strided for
/// the largest seeds so the whole test stays quick) through `run`.
pub fn seed_neighbourhood(bytes: &[u8], run: impl Fn(&[u8])) {
    let stride = (bytes.len() / 250).max(1);
    for i in (0..=bytes.len()).step_by(stride) {
        run(&bytes[..i]);
        if i < bytes.len() {
            for flip in [0x01u8, 0xff] {
                let mut m = bytes.to_vec();
                m[i] ^= flip;
                run(&m);
            }
            let mut dropped = bytes.to_vec();
            dropped.remove(i);
            run(&dropped);
        }
        let mut inserted = bytes.to_vec();
        inserted.insert(i, b'"');
        run(&inserted);
    }
}
