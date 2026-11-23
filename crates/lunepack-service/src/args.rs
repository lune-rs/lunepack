//! The command line: nothing, or exactly `--self-test`.

use std::ffi::OsString;

/// What the process was asked to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No argument: the update service, started by the service control manager.
    Service,
    /// `--self-test`: what opening the engine verifies, without its lock (`Engine::check`), then
    /// exit 0 (the registrar's check of a new binary before the registration points at it).
    SelfTest,
}

/// The command line is anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageError;

/// Reads the arguments after the program name.
pub fn parse(args: &[OsString]) -> Result<Mode, UsageError> {
    match args {
        [] => Ok(Mode::Service),
        [one] if one == "--self-test" => Ok(Mode::SelfTest),
        _ => Err(UsageError),
    }
}
