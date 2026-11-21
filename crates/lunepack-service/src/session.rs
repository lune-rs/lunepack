//! The pieces of the service loop that need no operating system: the cap on one connection's
//! length and the idle rule.

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use lunepack_core::Duplex;

/// A connection is cut after this long, whatever it is doing (M10-D11).
pub const CONNECTION_LIMIT: Duration = Duration::from_secs(30 * 60);
/// The service exits after this long without a connection while no lease runs (M10-D11).
pub const IDLE_EXIT: Duration = Duration::from_secs(60);

/// A [`Duplex`] that stops working `limit` after it was made: a read or a write after that fails
/// with `TimedOut`, and no read deadline set through it reaches past that moment.
pub struct Capped<D: Duplex> {
    inner: D,
    end: Instant,
}

impl<D: Duplex> Capped<D> {
    /// Wraps `inner`; the clock starts now.
    pub fn new(inner: D, limit: Duration) -> Capped<D> {
        Capped {
            inner,
            end: Instant::now() + limit,
        }
    }

    fn left(&self) -> Option<Duration> {
        let left = self.end.saturating_duration_since(Instant::now());
        (!left.is_zero()).then_some(left)
    }
}

fn expired() -> io::Error {
    io::Error::from(io::ErrorKind::TimedOut)
}

impl<D: Duplex> Read for Capped<D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left().is_none() {
            return Err(expired());
        }
        self.inner.read(buf)
    }
}

impl<D: Duplex> Write for Capped<D> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.left().is_none() {
            return Err(expired());
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<D: Duplex> Duplex for Capped<D> {
    fn set_read_deadline(&mut self, deadline: Option<Duration>) -> io::Result<()> {
        let left = self.left().ok_or_else(expired)?;
        self.inner
            .set_read_deadline(Some(deadline.map_or(left, |d| d.min(left))))
    }
}

/// Whether the service has been idle long enough to exit: nothing connected for [`IDLE_EXIT`] and
/// no supervision lease running (a lease means an applied version is still inside its health
/// window, and a later `attempt` or `confirm` will need the same engine memory).
pub fn idle_exit(idle_for: Duration, lease_running: bool) -> bool {
    idle_for >= IDLE_EXIT && !lease_running
}
