//! The service's log (M10-D7): a capped file under `R\.lunepack\logs`, readable by every user of
//! the machine, so it can say very little. A line is a time, a level, one fixed message and, at
//! most, one number (a closed error code or a count). The message type is `&'static str`: a token,
//! an install id, a user name, a path or raw OS text cannot reach it, because none of them is a
//! compile-time constant. Logging never fails the service: an error here is dropped.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;

/// The file is moved aside when it passes this size, so the log never holds more than twice this.
pub const CAP: u64 = 256 * 1024;

/// How serious a line is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Something the service did or saw that is expected.
    Info,
    /// Something refused or failed.
    Error,
}

/// The log file.
#[derive(Debug)]
pub struct Log {
    path: PathBuf,
    cap: u64,
    now: fn() -> u64,
}

impl Log {
    /// A log at `path`, stamping lines with `now()` (seconds since the Unix epoch).
    pub fn new(path: PathBuf, now: fn() -> u64) -> Log {
        Log::with_cap(path, now, CAP)
    }

    /// As [`Log::new`] with another size cap (tests).
    pub fn with_cap(path: PathBuf, now: fn() -> u64, cap: u64) -> Log {
        Log { path, cap, now }
    }

    /// Appends `<seconds> <LEVEL> <what>[ <code>]`.
    pub fn line(&self, level: Level, what: &'static str, code: Option<u32>) {
        let _ = self.append(level, what, code);
    }

    /// An expected event.
    pub fn info(&self, what: &'static str) {
        self.line(Level::Info, what, None);
    }

    /// A refusal or failure with its closed code.
    pub fn error(&self, what: &'static str, code: u32) {
        self.line(Level::Error, what, Some(code));
    }

    fn append(&self, level: Level, what: &'static str, code: Option<u32>) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        if fs::metadata(&self.path).is_ok_and(|m| m.len() >= self.cap) {
            let mut aside = self.path.clone().into_os_string();
            aside.push(".1");
            let aside = PathBuf::from(aside);
            let _ = fs::remove_file(&aside);
            fs::rename(&self.path, &aside)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let level = match level {
            Level::Info => "INFO",
            Level::Error => "ERROR",
        };
        match code {
            Some(code) => writeln!(file, "{} {level} {what} {code}", (self.now)()),
            None => writeln!(file, "{} {level} {what}", (self.now)()),
        }
    }
}
