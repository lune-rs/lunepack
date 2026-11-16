//! A seeded, deterministic random source.

use std::sync::{Mutex, PoisonError};

use lunepack_core::{Error, Rng};

/// xorshift64*: the same seed gives the same byte sequence, so a test that draws a token, a
/// nonce or a sample sees the same one on every run. It is not random and must never stand in for
/// the real source outside tests.
#[derive(Debug)]
pub struct FakeRng {
    state: Mutex<u64>,
    fail: bool,
}

impl FakeRng {
    /// A source seeded with `seed` (any value; 0 is mapped to a fixed non-zero state).
    pub fn new(seed: u64) -> FakeRng {
        FakeRng {
            state: Mutex::new(if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            }),
            fail: false,
        }
    }

    /// A source whose every `fill` fails with [`Error::Random`], for testing callers' error
    /// paths.
    pub fn failing() -> FakeRng {
        FakeRng {
            state: Mutex::new(1),
            fail: true,
        }
    }
}

impl Rng for FakeRng {
    fn fill(&self, buf: &mut [u8]) -> Result<(), Error> {
        if self.fail {
            return Err(Error::Random);
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        for byte in buf {
            *state ^= *state >> 12;
            *state ^= *state << 25;
            *state ^= *state >> 27;
            *byte = (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
        }
        Ok(())
    }
}
