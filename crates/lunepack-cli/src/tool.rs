//! The bounded runner for every external tool the packager starts (M9-D3): the developer's signing
//! templates, notarization, stapling, `hdiutil` and the `.pkg` builders `pkgbuild` and `productbuild`.
//!
//! One rule set for all of them: the program is started directly with an argv (never a shell; on
//! Windows a `.bat` or `.cmd` program is refused, because `cmd.exe` would re-parse the arguments),
//! standard input is null, standard output and standard error each keep at most [`OUTPUT_CAP`]
//! bytes (the rest is read and thrown away, so a chatty tool cannot block on a full pipe or fill
//! memory), and the child is killed and reaped when it outlives its timeout. The child's
//! environment is inherited unchanged.
//!
//! What this module may show: the program's file name, the exit status or "timed out", and the tail
//! (at most [`STDERR_TAIL`] bytes) of the tool's standard error with every `{env:}` value of the call
//! replaced by `<NAME>`. It never shows or logs the expanded argv or any environment variable.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Most bytes of each of a tool's standard output and standard error kept.
pub const OUTPUT_CAP: usize = 64 * 1024;
/// Most bytes of a failed tool's standard error shown.
pub const STDERR_TAIL: usize = 4 * 1024;
/// How long to wait for a pipe reader to see end-of-file once the child has exited (a grandchild
/// that inherited the pipe can hold it open; the reader is then left behind with what it has).
const READER_GRACE: Duration = Duration::from_secs(2);
/// How often a running child is polled.
const POLL: Duration = Duration::from_millis(20);

/// What a tool wrote, capped.
#[derive(Debug)]
pub struct Captured {
    /// The exit status.
    pub status: ExitStatus,
    /// The first [`OUTPUT_CAP`] bytes of standard output.
    pub stdout: Vec<u8>,
    /// The first [`OUTPUT_CAP`] bytes of standard error.
    pub stderr: Vec<u8>,
    /// Whether standard output had more than the cap.
    #[allow(dead_code)] // the runner's tests read it
    pub stdout_truncated: bool,
    /// Whether standard error had more than the cap.
    pub stderr_truncated: bool,
}

/// What a tool that succeeded wrote, capped.
#[derive(Debug)]
#[allow(dead_code)] // the sign stage keeps only the verdict; the runner's tests read the bytes
pub struct ToolOutput {
    /// The first [`OUTPUT_CAP`] bytes of standard output.
    pub stdout: Vec<u8>,
    /// The first [`OUTPUT_CAP`] bytes of standard error.
    pub stderr: Vec<u8>,
}

/// Why a tool run failed. Every text names the program's file name only.
#[derive(Debug)]
pub enum ToolError {
    /// The argv has no program.
    EmptyArgv,
    /// A Windows batch script was named as the program.
    BatchScript {
        /// The program's file name.
        program: String,
    },
    /// The program could not be started.
    Spawn {
        /// The program's file name.
        program: String,
        /// The operating system's reason.
        source: io::Error,
    },
    /// Waiting for the program failed.
    Wait {
        /// The program's file name.
        program: String,
        /// The operating system's reason.
        source: io::Error,
    },
    /// The program outlived its timeout and was killed.
    TimedOut {
        /// The program's file name.
        program: String,
        /// The timeout, in whole seconds.
        secs: u64,
    },
    /// The program exited unsuccessfully.
    Failed {
        /// The program's file name.
        program: String,
        /// The exit status, as text.
        status: String,
        /// The tail of its standard error, with the call's environment values replaced.
        stderr_tail: String,
    },
}

impl ToolError {
    /// Whether the program ran past its timeout.
    pub fn is_timeout(&self) -> bool {
        matches!(self, ToolError::TimedOut { .. })
    }

    /// The error with `redact`'s values replaced in the program name.
    fn redacted(self, redact: &[(String, OsString)]) -> ToolError {
        let name = |program: String| redact_text(&program, redact);
        match self {
            ToolError::BatchScript { program } => ToolError::BatchScript {
                program: name(program),
            },
            ToolError::Spawn { program, source } => ToolError::Spawn {
                program: name(program),
                source,
            },
            ToolError::Wait { program, source } => ToolError::Wait {
                program: name(program),
                source,
            },
            ToolError::TimedOut { program, secs } => ToolError::TimedOut {
                program: name(program),
                secs,
            },
            other => other,
        }
    }
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ToolError::EmptyArgv => f.write_str("no program to run"),
            ToolError::BatchScript { program } => write!(
                f,
                "{program}: a .bat or .cmd file cannot be run as a signing tool (cmd.exe would re-read its arguments)"
            ),
            ToolError::Spawn { program, source } => {
                write!(f, "cannot start {program}: {source}")
            }
            ToolError::Wait { program, source } => {
                write!(f, "cannot wait for {program}: {source}")
            }
            ToolError::TimedOut { program, secs } => {
                write!(
                    f,
                    "{program} timed out after {secs} seconds and was stopped"
                )
            }
            ToolError::Failed {
                program,
                status,
                stderr_tail,
            } => {
                write!(f, "{program} failed ({status})")?;
                if !stderr_tail.is_empty() {
                    write!(f, ": {stderr_tail}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ToolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ToolError::Spawn { source, .. } | ToolError::Wait { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Whether `program` names a Windows batch script (`.bat` or `.cmd`, in any case), after dropping
/// the trailing dots and spaces Win32 ignores in a file name. Pure text; [`run_tool`] enforces it
/// on Windows only.
pub fn is_batch_script(program: &OsStr) -> bool {
    let text = program.to_string_lossy();
    let name = text.rsplit(['/', '\\']).next().unwrap_or("");
    let name = name.trim_end_matches(['.', ' ']).to_ascii_lowercase();
    name.ends_with(".bat") || name.ends_with(".cmd")
}

/// The program's file name, as shown in an error.
fn display_name(program: &OsStr) -> String {
    Path::new(program)
        .file_name()
        .unwrap_or(program)
        .to_string_lossy()
        .into_owned()
}

/// The bytes read from one pipe, at most [`OUTPUT_CAP`].
#[derive(Default)]
struct Capture {
    bytes: Vec<u8>,
    truncated: bool,
}

/// A thread draining one pipe into a [`Capture`].
struct Reader {
    capture: Arc<Mutex<Capture>>,
    handle: thread::JoinHandle<()>,
}

impl Reader {
    fn start<R: Read + Send + 'static>(mut pipe: R) -> Reader {
        let capture = Arc::new(Mutex::new(Capture::default()));
        let shared = Arc::clone(&capture);
        let handle = thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut c = shared.lock().unwrap_or_else(|p| p.into_inner());
                        let room = OUTPUT_CAP.saturating_sub(c.bytes.len());
                        let take = n.min(room);
                        c.bytes.extend_from_slice(&chunk[..take]);
                        if take < n {
                            c.truncated = true;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        });
        Reader { capture, handle }
    }

    /// What the pipe held once the child exited. A grandchild that keeps the pipe open is not
    /// waited for beyond [`READER_GRACE`]: its reader is left to end on its own.
    fn finish(self) -> (Vec<u8>, bool) {
        let started = Instant::now();
        while !self.handle.is_finished() && started.elapsed() < READER_GRACE {
            thread::sleep(Duration::from_millis(5));
        }
        let c = self.capture.lock().unwrap_or_else(|p| p.into_inner());
        (c.bytes.clone(), c.truncated)
    }
}

/// Runs `argv` (program first) to completion or `timeout`, keeping capped output. A nonzero exit
/// is not an error here; see [`run_tool`].
pub fn run_captured(argv: &[OsString], timeout: Duration) -> Result<Captured, ToolError> {
    let Some(program) = argv.first() else {
        return Err(ToolError::EmptyArgv);
    };
    let name = display_name(program);
    if cfg!(windows) && is_batch_script(program) {
        return Err(ToolError::BatchScript { program: name });
    }
    let mut child = Command::new(program)
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| ToolError::Spawn {
            program: name.clone(),
            source,
        })?;
    // Both pipes were requested above, so both handles exist.
    let stdout = child.stdout.take().map(Reader::start);
    let stderr = child.stderr.take().map(Reader::start);
    let deadline = Instant::now().checked_add(timeout);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(source) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ToolError::Wait {
                    program: name,
                    source,
                });
            }
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ToolError::TimedOut {
                program: name,
                secs: timeout.as_secs(),
            });
        }
        thread::sleep(POLL);
    };
    let (stdout, stdout_truncated) = stdout.map_or((Vec::new(), false), Reader::finish);
    let (stderr, stderr_truncated) = stderr.map_or((Vec::new(), false), Reader::finish);
    Ok(Captured {
        status,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

/// Runs `argv` to completion or `timeout`. `redact` lists the `{env:}` values the argv holds (name,
/// value): each is replaced by `<NAME>` in the error text. A nonzero exit is an error carrying the
/// status and the redacted tail of standard error.
pub fn run_tool(
    argv: &[OsString],
    timeout: Duration,
    redact: &[(String, OsString)],
) -> Result<ToolOutput, ToolError> {
    let c = run_captured(argv, timeout).map_err(|e| e.redacted(redact))?;
    if c.status.success() {
        return Ok(ToolOutput {
            stdout: c.stdout,
            stderr: c.stderr,
        });
    }
    let program = argv
        .first()
        .map(|p| redact_text(&display_name(p), redact))
        .unwrap_or_default();
    Err(ToolError::Failed {
        program,
        status: c.status.to_string(),
        stderr_tail: stderr_tail(c.stderr, c.stderr_truncated, redact),
    })
}

/// The shown tail of a failed tool's standard error.
fn stderr_tail(mut bytes: Vec<u8>, truncated: bool, redact: &[(String, OsString)]) -> String {
    let longest = redact
        .iter()
        .map(|(_, value)| os_bytes(value).len())
        .max()
        .unwrap_or(0);
    if truncated && longest > 1 {
        // A value cut by the cap would leave its first bytes visible; drop what could be one.
        bytes.truncate(bytes.len().saturating_sub(longest - 1));
    }
    // Replaced on the whole captured text, before the tail is cut, so no value is half shown.
    let bytes = redact_bytes(bytes, redact);
    let start = bytes.len().saturating_sub(STDERR_TAIL);
    let text = String::from_utf8_lossy(&bytes[start..]);
    text.trim()
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '?'
            } else {
                c
            }
        })
        .collect()
}

fn os_bytes(value: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        value.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        value.to_string_lossy().into_owned().into_bytes()
    }
}

fn redact_text(text: &str, redact: &[(String, OsString)]) -> String {
    String::from_utf8_lossy(&redact_bytes(text.as_bytes().to_vec(), redact)).into_owned()
}

/// Replaces every occurrence of each value with `<NAME>`, longest value first.
fn redact_bytes(mut bytes: Vec<u8>, redact: &[(String, OsString)]) -> Vec<u8> {
    let mut values: Vec<(Vec<u8>, Vec<u8>)> = redact
        .iter()
        .map(|(name, value)| (os_bytes(value), format!("<{name}>").into_bytes()))
        .filter(|(value, _)| !value.is_empty())
        .collect();
    values.sort_by_key(|(value, _)| std::cmp::Reverse(value.len()));
    for (value, with) in &values {
        bytes = replace_all(&bytes, value, with);
    }
    bytes
}

fn replace_all(haystack: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}
