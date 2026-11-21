//! The UI port (M6): the messages between the engine (the runtime) and the separate `lunepack-ui`
//! process, a capped and fail-closed frame codec, and the flow reducers that say which message is
//! valid when. Pure: no pipe, process or clock is touched here; the codec works over any
//! `Read` and `Write`. The UI never decides anything: it shows what the engine sends and returns
//! choices, and the engine validates every choice against the reducer ([`FlowState::accepts`]).
//!
//! Frame (M6-D2): a `u32` little-endian length, then a body of at most [`MAX_FRAME`] bytes, which is
//! strict JSON (duplicate keys rejected) with `"v":1` and a `"type"` from a closed set. A message
//! with a missing or an extra field, an unknown name or a value out of range is refused with a
//! typed [`ProtocolError`]; nothing here panics on input.

use std::io::{ErrorKind, Read, Write};

use serde_json::{Map, Value};

use crate::encoding::{base64_decode, base64_encode};
use crate::json::check_strict;
use crate::limits::MAX_JSON_INT;
use crate::progress::Phase;
use crate::update_config::MAX_NAME_CHARS;

/// The frame protocol version, the `"v"` member of every frame.
pub const PROTOCOL: u32 = 1;
/// The build id of this build without a release suffix: `<workspace version>+ui<PROTOCOL>`. The
/// engine and the UI must carry the same one (same-build only, C10 and D28).
pub const BUILD_ID: &str = concat!(env!("CARGO_PKG_VERSION"), "+ui1");
/// Largest frame body in bytes; a longer length prefix is refused before any allocation.
pub const MAX_FRAME: usize = 1024 * 1024;
/// Largest icon in raw PNG bytes (it travels as base64 in hello).
pub const MAX_ICON_BYTES: usize = 512 * 1024;
/// Longest app name or publisher in Unicode scalars: the update config's own limit for `install.name`.
pub const MAX_NAME: usize = MAX_NAME_CHARS;
/// Longest version string in Unicode scalars.
pub const MAX_VERSION: usize = 128;
/// Longest install location in bytes.
pub const MAX_LOCATION: usize = 4096;
/// Most leftover paths an uninstall outcome carries.
pub const MAX_LEFTOVERS: usize = 64;
/// Longest leftover path in bytes.
pub const MAX_LEFTOVER: usize = 4096;
/// Longest build id in bytes.
pub const MAX_BUILD_ID: usize = 256;

/// The build id of this build: [`BUILD_ID`], plus `.<id>` when the release build sets
/// `LUNEPACK_BUILD_ID` while compiling the core (M13).
pub fn build_id() -> String {
    match option_env!("LUNEPACK_BUILD_ID") {
        Some(id) if !id.is_empty() => format!("{BUILD_ID}.{id}"),
        _ => BUILD_ID.to_string(),
    }
}

/// Accepts the peer's hello only when its build id equals this build's (a mismatch is refused).
pub fn check_hello(peer_build_id: &str) -> Result<(), ProtocolError> {
    if peer_build_id == build_id() {
        Ok(())
    } else {
        Err(ProtocolError::BuildIdMismatch)
    }
}

/// Why a frame or a message was refused. Carries no untrusted text beyond the strict-JSON reason,
/// which is already escaped and truncated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// The peer closed the channel between two frames.
    #[error("the channel is closed")]
    Closed,
    /// The channel ended inside a frame.
    #[error("the channel ended inside a frame")]
    Truncated,
    /// Reading or writing the channel failed.
    #[error("channel i/o failed: {0:?}")]
    Io(ErrorKind),
    /// A frame is over the cap (found length, or the encoded size on the way out).
    #[error("a frame of {len} bytes is over the {MAX_FRAME} byte cap")]
    FrameTooLarge {
        /// The length found or produced.
        len: u64,
    },
    /// The body is not strict JSON.
    #[error("the frame body is not strict JSON: {0}")]
    NotStrictJson(String),
    /// `v` is not 1.
    #[error("unsupported protocol version")]
    BadVersion,
    /// The `type` is not in the closed set for this direction.
    #[error("unknown message type")]
    UnknownType,
    /// A member the message needs is absent.
    #[error("missing field `{0}`")]
    MissingField(&'static str),
    /// A member the message does not have is present.
    #[error("unexpected field")]
    ExtraField,
    /// A member has the wrong JSON type.
    #[error("field `{0}` has the wrong type")]
    WrongType(&'static str),
    /// A number is outside its range.
    #[error("field `{0}` is out of range")]
    OutOfRange(&'static str),
    /// A name is not in the closed set for this field.
    #[error("field `{0}` has an unknown value")]
    UnknownValue(&'static str),
    /// A string or list is over its cap.
    #[error("{what} is over its cap of {cap}")]
    TooLong {
        /// What was measured.
        what: &'static str,
        /// The cap (in the unit the constant names).
        cap: usize,
    },
    /// The icon is over its cap or is not canonical base64.
    #[error("the icon is too large or not canonical base64")]
    BadIcon,
    /// The peer's build id is not this build's.
    #[error("the build ids differ")]
    BuildIdMismatch,
    /// The message is not valid in the current state.
    #[error("{0}")]
    OutOfOrder(&'static str),
    /// The value has no wire form (a phase added after this codec).
    #[error("{0} has no wire form")]
    Unencodable(&'static str),
}

/// Which operation a UI process shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// The first install.
    Install,
    /// Applying an update.
    Update,
    /// Removing an install.
    Uninstall,
}

/// The app the screens are about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppCard {
    /// The app's display name (at most [`MAX_NAME`] scalars).
    pub name: String,
    /// The version shown (at most [`MAX_VERSION`] scalars).
    pub version: String,
    /// The version being updated from, in an update.
    pub from_version: Option<String>,
    /// The publisher, from the signed install metadata; absent when the package names none.
    pub publisher: Option<String>,
    /// The app icon as PNG bytes (at most [`MAX_ICON_BYTES`]).
    pub icon_png: Option<Vec<u8>>,
}

/// What the install is about to touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Details {
    /// Where the app is, or will be, installed (at most [`MAX_LOCATION`] bytes).
    pub location: Option<String>,
    /// How much space the install takes, in bytes.
    pub size_bytes: Option<u64>,
    /// Where the app would be installed for all users (at most [`MAX_LOCATION`] bytes). The
    /// install welcome screen offers the choice exactly when this is present; only an install
    /// hello may carry it.
    pub all_users_location: Option<String>,
}

/// One item of work the engine reports as done. Which items belong to which flow is fixed by
/// [`StepItem::belongs_to`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepItem {
    /// The package's signatures and hashes checked.
    Verify,
    /// The version tree built.
    Stage,
    /// The install recorded and made current.
    Commit,
    /// The desktop entry and command link created or removed.
    Integrate,
    /// The running app has exited.
    WaitApp,
    /// The staged version committed and made current.
    Apply,
    /// The new version started.
    Launch,
    /// The new version confirmed its health.
    Confirm,
    /// The previous version restored.
    Rollback,
    /// The install's files removed.
    Remove,
}

impl StepItem {
    /// Whether `self` can be reported in `flow`.
    pub fn belongs_to(self, flow: Flow) -> bool {
        match flow {
            Flow::Install => matches!(
                self,
                StepItem::Verify | StepItem::Stage | StepItem::Commit | StepItem::Integrate
            ),
            Flow::Update => matches!(
                self,
                StepItem::WaitApp
                    | StepItem::Apply
                    | StepItem::Launch
                    | StepItem::Confirm
                    | StepItem::Rollback
            ),
            Flow::Uninstall => matches!(self, StepItem::Integrate | StepItem::Remove),
        }
    }
}

/// A question the engine asks. The set of valid answers depends on the flow ([`ChoiceValue`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    /// Install: proceed or cancel.
    Welcome,
    /// Uninstall: proceed or cancel.
    Confirm,
    /// Install: finish (launch or not). Uninstall: close, or show a leftover.
    Done,
    /// Install: retry or close. Update and uninstall: close.
    Failed,
    /// Update: acknowledge that the previous version was restored.
    RolledBack,
}

/// An answer to a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChoiceValue {
    /// Go ahead.
    Proceed,
    /// Go ahead and install for all users; valid only on the install welcome prompt, and only
    /// when the hello offered it ([`Details::all_users_location`]).
    ProceedAllUsers,
    /// Do not.
    Cancel,
    /// Leave the done screen; `launch` starts the app.
    Finish {
        /// Whether to start the app.
        launch: bool,
    },
    /// Try the install again.
    Retry,
    /// Close the window.
    Close,
    /// Show where the leftover with this index (in the order the outcome listed them) is.
    Reveal {
        /// Index into the outcome's leftovers.
        index: u32,
    },
    /// Acknowledge.
    Acknowledge,
}

/// How an operation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The install is in place.
    Installed,
    /// An install or update failed with this exit code.
    Failed {
        /// The runtime's exit code.
        code: u32,
    },
    /// The user cancelled; nothing was changed.
    Cancelled,
    /// The update is applied and the app started.
    Updated,
    /// The new version did not confirm; the previous one runs again.
    RolledBack {
        /// The version that failed.
        from: String,
        /// The version restored.
        to: String,
    },
    /// The install is removed.
    Uninstalled {
        /// Paths the uninstall left behind, at most [`MAX_LEFTOVERS`] of at most [`MAX_LEFTOVER`] bytes.
        leftovers: Vec<String>,
    },
    /// The uninstall failed with this exit code.
    UninstallFailed {
        /// The runtime's exit code.
        code: u32,
    },
}

/// A message from the engine to the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineMsg {
    /// The first message: what to show.
    Hello {
        /// The engine's build id; the UI refuses a different one ([`check_hello`]).
        build_id: String,
        /// The operation.
        flow: Flow,
        /// The app.
        app: AppCard,
        /// The install details.
        details: Details,
    },
    /// Progress of a phase.
    Progress {
        /// The phase.
        phase: Phase,
        /// Bytes done.
        done: u64,
        /// Bytes needed; 0 when unknown.
        total: u64,
    },
    /// An item finished.
    Step {
        /// The item.
        item: StepItem,
    },
    /// Open a prompt. Ids strictly increase.
    Prompt {
        /// The prompt's id.
        id: u32,
        /// What it asks.
        kind: PromptKind,
    },
    /// Whether the user may cancel the running operation now.
    Cancellable(bool),
    /// The operation ended.
    Outcome(Outcome),
    /// A liveness probe; the UI answers with `Pong` of the same `n`.
    Ping {
        /// The probe's number.
        n: u32,
    },
    /// The window should close.
    Close,
}

/// A message from the UI to the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiMsg {
    /// The first message: the UI's build id.
    Hello {
        /// The UI's build id; the engine refuses a different one ([`check_hello`]).
        build_id: String,
    },
    /// An answer to the open prompt.
    Choice {
        /// The prompt's id.
        id: u32,
        /// The answer.
        value: ChoiceValue,
    },
    /// The user asked to cancel the running operation.
    Cancel,
    /// The answer to a `Ping`.
    Pong {
        /// The probe's number.
        n: u32,
    },
}

// ---- validation (caps), shared by encode and decode ----

fn check_scalars(text: &str, what: &'static str, cap: usize) -> Result<(), ProtocolError> {
    // Bytes bound the scalar count from above, so most strings skip the count.
    if text.len() <= cap || text.chars().count() <= cap {
        Ok(())
    } else {
        Err(ProtocolError::TooLong { what, cap })
    }
}

fn check_bytes(text: &str, what: &'static str, cap: usize) -> Result<(), ProtocolError> {
    if text.len() <= cap {
        Ok(())
    } else {
        Err(ProtocolError::TooLong { what, cap })
    }
}

fn check_int(n: u64, what: &'static str) -> Result<(), ProtocolError> {
    if n <= MAX_JSON_INT {
        Ok(())
    } else {
        Err(ProtocolError::OutOfRange(what))
    }
}

fn validate_engine(msg: &EngineMsg) -> Result<(), ProtocolError> {
    match msg {
        EngineMsg::Hello {
            build_id,
            flow,
            app,
            details,
        } => {
            check_bytes(build_id, "build_id", MAX_BUILD_ID)?;
            check_scalars(&app.name, "app name", MAX_NAME)?;
            check_scalars(&app.version, "app version", MAX_VERSION)?;
            if let Some(v) = &app.from_version {
                check_scalars(v, "from_version", MAX_VERSION)?;
            }
            if let Some(p) = &app.publisher {
                check_scalars(p, "publisher", MAX_NAME)?;
            }
            if app
                .icon_png
                .as_ref()
                .is_some_and(|i| i.len() > MAX_ICON_BYTES)
            {
                return Err(ProtocolError::BadIcon);
            }
            if let Some(l) = &details.location {
                check_bytes(l, "location", MAX_LOCATION)?;
            }
            if let Some(l) = &details.all_users_location {
                check_bytes(l, "all_users_location", MAX_LOCATION)?;
                if *flow != Flow::Install {
                    return out_of_order("an all-users location outside the install flow");
                }
            }
            if let Some(n) = details.size_bytes {
                check_int(n, "size_bytes")?;
            }
        }
        EngineMsg::Progress { done, total, .. } => {
            check_int(*done, "done")?;
            check_int(*total, "total")?;
        }
        EngineMsg::Outcome(Outcome::RolledBack { from, to }) => {
            check_scalars(from, "rolled back from", MAX_VERSION)?;
            check_scalars(to, "rolled back to", MAX_VERSION)?;
        }
        EngineMsg::Outcome(Outcome::Uninstalled { leftovers }) => {
            if leftovers.len() > MAX_LEFTOVERS {
                return Err(ProtocolError::TooLong {
                    what: "leftovers",
                    cap: MAX_LEFTOVERS,
                });
            }
            for path in leftovers {
                check_bytes(path, "leftover", MAX_LEFTOVER)?;
            }
        }
        EngineMsg::Step { .. }
        | EngineMsg::Prompt { .. }
        | EngineMsg::Cancellable(_)
        | EngineMsg::Outcome(_)
        | EngineMsg::Ping { .. }
        | EngineMsg::Close => {}
    }
    Ok(())
}

fn validate_ui(msg: &UiMsg) -> Result<(), ProtocolError> {
    if let UiMsg::Hello { build_id } = msg {
        check_bytes(build_id, "build_id", MAX_BUILD_ID)?;
    }
    Ok(())
}

// ---- names on the wire ----

const FLOWS: &[(&str, Flow)] = &[
    ("install", Flow::Install),
    ("update", Flow::Update),
    ("uninstall", Flow::Uninstall),
];

const STEPS: &[(&str, StepItem)] = &[
    ("verify", StepItem::Verify),
    ("stage", StepItem::Stage),
    ("commit", StepItem::Commit),
    ("integrate", StepItem::Integrate),
    ("wait_app", StepItem::WaitApp),
    ("apply", StepItem::Apply),
    ("launch", StepItem::Launch),
    ("confirm", StepItem::Confirm),
    ("rollback", StepItem::Rollback),
    ("remove", StepItem::Remove),
];

const PROMPTS: &[(&str, PromptKind)] = &[
    ("welcome", PromptKind::Welcome),
    ("confirm", PromptKind::Confirm),
    ("done", PromptKind::Done),
    ("failed", PromptKind::Failed),
    ("rolled_back", PromptKind::RolledBack),
];

/// Phase names, as the runtime's JSON writes them (`events.rs`); `Phase` carries no serde.
const PHASES: &[(&str, Phase)] = &[
    ("check", Phase::Check),
    ("scan", Phase::Scan),
    ("download", Phase::Download),
    ("stage", Phase::Stage),
    ("install", Phase::Install),
    ("wait", Phase::Wait),
    ("apply", Phase::Apply),
    ("launch", Phase::Launch),
    ("confirm", Phase::Confirm),
    ("rollback", Phase::Rollback),
    ("uninstall", Phase::Uninstall),
];

fn name_of<T: Copy + PartialEq>(table: &[(&'static str, T)], value: T) -> Option<&'static str> {
    table.iter().find(|(_, v)| *v == value).map(|(n, _)| *n)
}

fn value_of<T: Copy>(
    table: &[(&'static str, T)],
    name: &str,
    field: &'static str,
) -> Result<T, ProtocolError> {
    table
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| *v)
        .ok_or(ProtocolError::UnknownValue(field))
}

// ---- JSON building and reading ----

fn base(ty: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("v".into(), Value::from(PROTOCOL));
    m.insert("type".into(), Value::from(ty));
    m
}

fn finish(map: Map<String, Value>) -> Result<Vec<u8>, ProtocolError> {
    let body = serde_json::to_vec(&Value::Object(map))
        .map_err(|_| ProtocolError::Unencodable("a message"))?;
    if body.len() > MAX_FRAME {
        return Err(ProtocolError::FrameTooLarge {
            len: body.len() as u64,
        });
    }
    Ok(body)
}

/// The members of one JSON object, taken one by one; [`Fields::done`] refuses what is left.
struct Fields(Map<String, Value>);

impl Fields {
    fn of(value: Value, field: &'static str) -> Result<Fields, ProtocolError> {
        match value {
            Value::Object(m) => Ok(Fields(m)),
            _ => Err(ProtocolError::WrongType(field)),
        }
    }

    fn take(&mut self, key: &'static str) -> Result<Value, ProtocolError> {
        self.0.remove(key).ok_or(ProtocolError::MissingField(key))
    }

    fn string(&mut self, key: &'static str) -> Result<String, ProtocolError> {
        match self.take(key)? {
            Value::String(s) => Ok(s),
            _ => Err(ProtocolError::WrongType(key)),
        }
    }

    fn opt_string(&mut self, key: &'static str) -> Result<Option<String>, ProtocolError> {
        match self.0.remove(key) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(ProtocolError::WrongType(key)),
        }
    }

    fn uint(&mut self, key: &'static str, max: u64) -> Result<u64, ProtocolError> {
        Self::uint_of(self.take(key)?, key, max)
    }

    fn uint_of(value: Value, key: &'static str, max: u64) -> Result<u64, ProtocolError> {
        let Value::Number(n) = value else {
            return Err(ProtocolError::WrongType(key));
        };
        let n = n.as_u64().ok_or(ProtocolError::OutOfRange(key))?;
        if n > max {
            return Err(ProtocolError::OutOfRange(key));
        }
        Ok(n)
    }

    fn u32(&mut self, key: &'static str) -> Result<u32, ProtocolError> {
        Ok(self.uint(key, u64::from(u32::MAX))? as u32)
    }

    fn boolean(&mut self, key: &'static str) -> Result<bool, ProtocolError> {
        match self.take(key)? {
            Value::Bool(b) => Ok(b),
            _ => Err(ProtocolError::WrongType(key)),
        }
    }

    fn done(self) -> Result<(), ProtocolError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::ExtraField)
        }
    }
}

/// Strict-JSON parse of a frame body into its members, with the version checked and the type
/// returned.
fn open(body: &[u8]) -> Result<(String, Fields), ProtocolError> {
    check_strict(body).map_err(|e| ProtocolError::NotStrictJson(e.to_string()))?;
    let value: Value =
        serde_json::from_slice(body).map_err(|e| ProtocolError::NotStrictJson(e.to_string()))?;
    let mut fields = Fields::of(value, "frame")?;
    let v = match fields.take("v")? {
        Value::Number(n) => n.as_u64(),
        _ => None,
    };
    if v != Some(u64::from(PROTOCOL)) {
        return Err(ProtocolError::BadVersion);
    }
    let ty = fields.string("type")?;
    Ok((ty, fields))
}

fn insert_opt(map: &mut Map<String, Value>, key: &str, value: Option<&String>) {
    if let Some(v) = value {
        map.insert(key.into(), Value::from(v.as_str()));
    }
}

fn outcome_json(map: &mut Map<String, Value>, outcome: &Outcome) {
    let (name, extra): (&str, Vec<(&str, Value)>) = match outcome {
        Outcome::Installed => ("installed", vec![]),
        Outcome::Failed { code } => ("failed", vec![("code", Value::from(*code))]),
        Outcome::Cancelled => ("cancelled", vec![]),
        Outcome::Updated => ("updated", vec![]),
        Outcome::RolledBack { from, to } => (
            "rolled_back",
            vec![
                ("from", Value::from(from.as_str())),
                ("to", Value::from(to.as_str())),
            ],
        ),
        Outcome::Uninstalled { leftovers } => (
            "uninstalled",
            vec![(
                "leftovers",
                Value::Array(leftovers.iter().map(|l| Value::from(l.as_str())).collect()),
            )],
        ),
        Outcome::UninstallFailed { code } => {
            ("uninstall_failed", vec![("code", Value::from(*code))])
        }
    };
    map.insert("outcome".into(), Value::from(name));
    for (k, v) in extra {
        map.insert(k.into(), v);
    }
}

fn read_outcome(f: &mut Fields) -> Result<Outcome, ProtocolError> {
    let name = f.string("outcome")?;
    Ok(match name.as_str() {
        "installed" => Outcome::Installed,
        "failed" => Outcome::Failed {
            code: f.u32("code")?,
        },
        "cancelled" => Outcome::Cancelled,
        "updated" => Outcome::Updated,
        "rolled_back" => Outcome::RolledBack {
            from: f.string("from")?,
            to: f.string("to")?,
        },
        "uninstalled" => {
            let Value::Array(items) = f.take("leftovers")? else {
                return Err(ProtocolError::WrongType("leftovers"));
            };
            if items.len() > MAX_LEFTOVERS {
                return Err(ProtocolError::TooLong {
                    what: "leftovers",
                    cap: MAX_LEFTOVERS,
                });
            }
            let mut leftovers = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(s) => leftovers.push(s),
                    _ => return Err(ProtocolError::WrongType("leftovers")),
                }
            }
            Outcome::Uninstalled { leftovers }
        }
        "uninstall_failed" => Outcome::UninstallFailed {
            code: f.u32("code")?,
        },
        _ => return Err(ProtocolError::UnknownValue("outcome")),
    })
}

/// A message that has a frame body. Implemented for [`EngineMsg`] and [`UiMsg`] only.
pub trait Message: Sized {
    /// The strict-JSON body of this message, caps checked.
    fn encode(&self) -> Result<Vec<u8>, ProtocolError>;
    /// The message in `body`, or why it is refused.
    fn decode(body: &[u8]) -> Result<Self, ProtocolError>;
}

impl Message for EngineMsg {
    fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        validate_engine(self)?;
        let mut m;
        match self {
            EngineMsg::Hello {
                build_id,
                flow,
                app,
                details,
            } => {
                m = base("hello");
                m.insert("build_id".into(), Value::from(build_id.as_str()));
                m.insert(
                    "flow".into(),
                    Value::from(name_of(FLOWS, *flow).ok_or(ProtocolError::Unencodable("flow"))?),
                );
                let mut a = Map::new();
                a.insert("name".into(), Value::from(app.name.as_str()));
                a.insert("version".into(), Value::from(app.version.as_str()));
                insert_opt(&mut a, "from_version", app.from_version.as_ref());
                insert_opt(&mut a, "publisher", app.publisher.as_ref());
                if let Some(icon) = &app.icon_png {
                    a.insert("icon_png".into(), Value::from(base64_encode(icon)));
                }
                m.insert("app".into(), Value::Object(a));
                let mut d = Map::new();
                insert_opt(&mut d, "location", details.location.as_ref());
                insert_opt(
                    &mut d,
                    "all_users_location",
                    details.all_users_location.as_ref(),
                );
                if let Some(n) = details.size_bytes {
                    d.insert("size_bytes".into(), Value::from(n));
                }
                m.insert("details".into(), Value::Object(d));
            }
            EngineMsg::Progress { phase, done, total } => {
                m = base("progress");
                m.insert(
                    "phase".into(),
                    Value::from(
                        name_of(PHASES, *phase).ok_or(ProtocolError::Unencodable("phase"))?,
                    ),
                );
                m.insert("done".into(), Value::from(*done));
                m.insert("total".into(), Value::from(*total));
            }
            EngineMsg::Step { item } => {
                m = base("step");
                m.insert(
                    "item".into(),
                    Value::from(name_of(STEPS, *item).ok_or(ProtocolError::Unencodable("item"))?),
                );
            }
            EngineMsg::Prompt { id, kind } => {
                m = base("prompt");
                m.insert("id".into(), Value::from(*id));
                m.insert(
                    "kind".into(),
                    Value::from(name_of(PROMPTS, *kind).ok_or(ProtocolError::Unencodable("kind"))?),
                );
            }
            EngineMsg::Cancellable(on) => {
                m = base("cancellable");
                m.insert("value".into(), Value::Bool(*on));
            }
            EngineMsg::Outcome(outcome) => {
                m = base("outcome");
                outcome_json(&mut m, outcome);
            }
            EngineMsg::Ping { n } => {
                m = base("ping");
                m.insert("n".into(), Value::from(*n));
            }
            EngineMsg::Close => m = base("close"),
        }
        finish(m)
    }

    fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let (ty, mut f) = open(body)?;
        let msg = match ty.as_str() {
            "hello" => {
                let build_id = f.string("build_id")?;
                let flow = value_of(FLOWS, &f.string("flow")?, "flow")?;
                let mut a = Fields::of(f.take("app")?, "app")?;
                let app = AppCard {
                    name: a.string("name")?,
                    version: a.string("version")?,
                    from_version: a.opt_string("from_version")?,
                    publisher: a.opt_string("publisher")?,
                    icon_png: match a.opt_string("icon_png")? {
                        None => None,
                        Some(text) => Some(
                            base64_decode(&text, MAX_ICON_BYTES)
                                .map_err(|_| ProtocolError::BadIcon)?,
                        ),
                    },
                };
                a.done()?;
                let mut d = Fields::of(f.take("details")?, "details")?;
                let location = d.opt_string("location")?;
                let all_users_location = d.opt_string("all_users_location")?;
                let size_bytes = match d.0.remove("size_bytes") {
                    None => None,
                    Some(v) => Some(Fields::uint_of(v, "size_bytes", MAX_JSON_INT)?),
                };
                d.done()?;
                EngineMsg::Hello {
                    build_id,
                    flow,
                    app,
                    details: Details {
                        location,
                        size_bytes,
                        all_users_location,
                    },
                }
            }
            "progress" => EngineMsg::Progress {
                phase: value_of(PHASES, &f.string("phase")?, "phase")?,
                done: f.uint("done", MAX_JSON_INT)?,
                total: f.uint("total", MAX_JSON_INT)?,
            },
            "step" => EngineMsg::Step {
                item: value_of(STEPS, &f.string("item")?, "item")?,
            },
            "prompt" => EngineMsg::Prompt {
                id: f.u32("id")?,
                kind: value_of(PROMPTS, &f.string("kind")?, "kind")?,
            },
            "cancellable" => EngineMsg::Cancellable(f.boolean("value")?),
            "outcome" => EngineMsg::Outcome(read_outcome(&mut f)?),
            "ping" => EngineMsg::Ping { n: f.u32("n")? },
            "close" => EngineMsg::Close,
            _ => return Err(ProtocolError::UnknownType),
        };
        f.done()?;
        validate_engine(&msg)?;
        Ok(msg)
    }
}

impl Message for UiMsg {
    fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        validate_ui(self)?;
        let mut m;
        match self {
            UiMsg::Hello { build_id } => {
                m = base("hello");
                m.insert("build_id".into(), Value::from(build_id.as_str()));
            }
            UiMsg::Choice { id, value } => {
                m = base("choice");
                m.insert("id".into(), Value::from(*id));
                let (name, extra): (&str, Option<(&str, Value)>) = match value {
                    ChoiceValue::Proceed => ("proceed", None),
                    ChoiceValue::ProceedAllUsers => ("proceed_all_users", None),
                    ChoiceValue::Cancel => ("cancel", None),
                    ChoiceValue::Finish { launch } => {
                        ("finish", Some(("launch", Value::Bool(*launch))))
                    }
                    ChoiceValue::Retry => ("retry", None),
                    ChoiceValue::Close => ("close", None),
                    ChoiceValue::Reveal { index } => {
                        ("reveal", Some(("index", Value::from(*index))))
                    }
                    ChoiceValue::Acknowledge => ("ack", None),
                };
                m.insert("value".into(), Value::from(name));
                if let Some((k, v)) = extra {
                    m.insert(k.into(), v);
                }
            }
            UiMsg::Cancel => m = base("cancel"),
            UiMsg::Pong { n } => {
                m = base("pong");
                m.insert("n".into(), Value::from(*n));
            }
        }
        finish(m)
    }

    fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let (ty, mut f) = open(body)?;
        let msg = match ty.as_str() {
            "hello" => UiMsg::Hello {
                build_id: f.string("build_id")?,
            },
            "choice" => {
                let id = f.u32("id")?;
                let value = match f.string("value")?.as_str() {
                    "proceed" => ChoiceValue::Proceed,
                    "proceed_all_users" => ChoiceValue::ProceedAllUsers,
                    "cancel" => ChoiceValue::Cancel,
                    "finish" => ChoiceValue::Finish {
                        launch: f.boolean("launch")?,
                    },
                    "retry" => ChoiceValue::Retry,
                    "close" => ChoiceValue::Close,
                    "reveal" => ChoiceValue::Reveal {
                        index: f.u32("index")?,
                    },
                    "ack" => ChoiceValue::Acknowledge,
                    _ => return Err(ProtocolError::UnknownValue("value")),
                };
                UiMsg::Choice { id, value }
            }
            "cancel" => UiMsg::Cancel,
            "pong" => UiMsg::Pong { n: f.u32("n")? },
            _ => return Err(ProtocolError::UnknownType),
        };
        f.done()?;
        validate_ui(&msg)?;
        Ok(msg)
    }
}

/// Reads until `buf` is full. `Ok(n)` with `n < buf.len()` means the channel ended after `n` bytes.
fn fill<R: Read>(input: &mut R, buf: &mut [u8]) -> Result<usize, ProtocolError> {
    let mut got = 0;
    while got < buf.len() {
        match input.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(ProtocolError::Io(e.kind())),
        }
    }
    Ok(got)
}

/// Writes one frame: the little-endian length, then the body, in one `write_all`, then a flush.
/// A message whose body is over [`MAX_FRAME`] or over a field cap is refused and nothing is written.
pub fn write_frame<W: Write, M: Message>(out: &mut W, msg: &M) -> Result<(), ProtocolError> {
    let body = msg.encode()?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    out.write_all(&frame)
        .and_then(|()| out.flush())
        .map_err(|e| ProtocolError::Io(e.kind()))
}

/// Reads one frame. A length over [`MAX_FRAME`] is refused before the body is allocated; the end
/// of the channel between frames is [`ProtocolError::Closed`] and inside one is
/// [`ProtocolError::Truncated`].
pub fn read_frame<R: Read, M: Message>(input: &mut R) -> Result<M, ProtocolError> {
    let mut len = [0u8; 4];
    match fill(input, &mut len)? {
        0 => return Err(ProtocolError::Closed),
        4 => {}
        _ => return Err(ProtocolError::Truncated),
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(ProtocolError::FrameTooLarge { len: len as u64 });
    }
    let mut body = vec![0u8; len];
    if fill(input, &mut body)? < len {
        return Err(ProtocolError::Truncated);
    }
    M::decode(&body)
}

// ---- flow reducers ----

/// What a UI shows. Which ones a flow passes through is fixed by [`FlowState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// No hello yet.
    Idle,
    /// Install: the welcome screen.
    InstallWelcome,
    /// Install: copying.
    Installing,
    /// Install: done.
    InstallDone,
    /// Install: failed.
    InstallFailed,
    /// Update: waiting for the app to exit.
    UpdateWaiting,
    /// Update: applying.
    UpdateApplying,
    /// Update: starting the new version.
    UpdateStarting,
    /// Update: the previous version was restored.
    UpdateRolledBack,
    /// Update: failed.
    UpdateFailed,
    /// Uninstall: the confirmation.
    UninstallConfirm,
    /// Uninstall: removing.
    Uninstalling,
    /// Uninstall: done.
    UninstallDone,
    /// Uninstall: failed.
    UninstallFailed,
    /// The window is closed.
    Closed,
}

impl Screen {
    fn running(self) -> bool {
        matches!(
            self,
            Screen::Installing
                | Screen::UpdateWaiting
                | Screen::UpdateApplying
                | Screen::UpdateStarting
                | Screen::Uninstalling
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpenPrompt {
    id: u32,
    kind: PromptKind,
}

/// The state of one conversation, kept by both ends: the engine applies what it sends, the UI what
/// it receives. One reducer per flow, selected by the hello. The engine asks
/// [`FlowState::accepts`] about every message from the UI and refuses what it does not accept.
///
/// - Install: welcome prompt, then `proceed` or `cancel` (or `proceed_all_users`, when the hello
///   offered it); installing (progress and steps); then
///   `Installed` and the done prompt (`finish`), or `Failed` and the failed prompt (`retry`, which
///   goes back to installing, or `close`).
/// - Update: waiting, applying, starting; then `Updated` (the window closes), or `RolledBack` and
///   the acknowledge prompt, or `Failed` and the failed prompt (`close`).
/// - Uninstall: the confirm prompt; removing; `Uninstalled` and the done prompt (`close`, or
///   `reveal` of a leftover the outcome listed) or `UninstallFailed` and the failed prompt.
///
/// `Ping` is valid in every state after the hello and changes no screen. A cancel before an
/// outcome (the `cancel` choice of a prompt, or `Cancel` while cancellable) is the only way
/// `Cancelled` can follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowState {
    expect: Option<Flow>,
    flow: Option<Flow>,
    screen: Screen,
    prompt: Option<OpenPrompt>,
    last_prompt: Option<u32>,
    answered: bool,
    cancellable: bool,
    cancel_requested: bool,
    ping: Option<u32>,
    outcome: Option<Outcome>,
    leftovers: usize,
    all_users_offered: bool,
}

impl Default for FlowState {
    fn default() -> Self {
        FlowState::new()
    }
}

fn out_of_order<T>(why: &'static str) -> Result<T, ProtocolError> {
    Err(ProtocolError::OutOfOrder(why))
}

impl FlowState {
    /// A state that learns its flow from the hello (the UI's side).
    pub fn new() -> FlowState {
        FlowState {
            expect: None,
            flow: None,
            screen: Screen::Idle,
            prompt: None,
            last_prompt: None,
            answered: false,
            cancellable: false,
            cancel_requested: false,
            ping: None,
            outcome: None,
            leftovers: 0,
            all_users_offered: false,
        }
    }

    /// A state whose hello must name `flow` (the engine's side).
    pub fn expecting(flow: Flow) -> FlowState {
        FlowState {
            expect: Some(flow),
            ..FlowState::new()
        }
    }

    /// The flow, once the hello is applied.
    pub fn flow(&self) -> Option<Flow> {
        self.flow
    }

    /// What to show now.
    pub fn screen(&self) -> Screen {
        self.screen
    }

    /// The open prompt's id and kind.
    pub fn open_prompt(&self) -> Option<(u32, PromptKind)> {
        self.prompt.map(|p| (p.id, p.kind))
    }

    /// Whether a `Cancel` is accepted now.
    pub fn cancellable(&self) -> bool {
        self.cancellable && self.outcome.is_none() && self.flow.is_some()
    }

    /// Whether the hello offered the all-users install (an install flow with a
    /// [`Details::all_users_location`]).
    pub fn all_users_offered(&self) -> bool {
        self.all_users_offered
    }

    /// How the operation ended, once it did.
    pub fn outcome(&self) -> Option<&Outcome> {
        self.outcome.as_ref()
    }

    fn is_running(&self) -> bool {
        self.screen.running() && self.prompt.is_none() && self.outcome.is_none()
    }

    fn set_screen(&mut self, screen: Screen) {
        self.screen = screen;
        self.answered = false;
    }

    /// The prompt the engine may open on this screen.
    fn expected_prompt(&self) -> Option<PromptKind> {
        match (self.flow?, self.screen) {
            (Flow::Install, Screen::InstallWelcome) if self.outcome.is_none() => {
                Some(PromptKind::Welcome)
            }
            (Flow::Install, Screen::InstallDone) => Some(PromptKind::Done),
            (Flow::Install, Screen::InstallFailed) => Some(PromptKind::Failed),
            (Flow::Update, Screen::UpdateRolledBack) => Some(PromptKind::RolledBack),
            (Flow::Update, Screen::UpdateFailed) => Some(PromptKind::Failed),
            (Flow::Uninstall, Screen::UninstallConfirm) if self.outcome.is_none() => {
                Some(PromptKind::Confirm)
            }
            (Flow::Uninstall, Screen::UninstallDone) => Some(PromptKind::Done),
            (Flow::Uninstall, Screen::UninstallFailed) => Some(PromptKind::Failed),
            _ => None,
        }
    }

    /// Applies a message the engine sends (or the UI receives).
    pub fn apply(&mut self, msg: &EngineMsg) -> Result<(), ProtocolError> {
        if let EngineMsg::Hello { flow, details, .. } = msg {
            if self.flow.is_some() {
                return out_of_order("a second hello");
            }
            if self.expect.is_some_and(|e| e != *flow) {
                return out_of_order("the hello names another flow");
            }
            self.flow = Some(*flow);
            self.all_users_offered = *flow == Flow::Install && details.all_users_location.is_some();
            self.screen = match flow {
                Flow::Install => Screen::InstallWelcome,
                Flow::Update => Screen::UpdateWaiting,
                Flow::Uninstall => Screen::UninstallConfirm,
            };
            return Ok(());
        }
        let Some(flow) = self.flow else {
            return out_of_order("a message before the hello");
        };
        if let EngineMsg::Ping { n } = msg {
            self.ping = Some(*n);
            return Ok(());
        }
        if self.screen == Screen::Closed {
            return out_of_order("a message after the window closed");
        }
        match msg {
            EngineMsg::Hello { .. } | EngineMsg::Ping { .. } => Ok(()),
            EngineMsg::Close => {
                self.set_screen(Screen::Closed);
                self.prompt = None;
                self.cancellable = false;
                Ok(())
            }
            EngineMsg::Cancellable(on) => {
                if self.outcome.is_some() {
                    return out_of_order("cancellable after the outcome");
                }
                self.cancellable = *on;
                Ok(())
            }
            EngineMsg::Progress { phase, .. } => {
                if !self.is_running() {
                    return out_of_order("progress while not running");
                }
                self.progress(flow, *phase)
            }
            EngineMsg::Step { item } => {
                if !self.is_running() {
                    return out_of_order("a step while not running");
                }
                if !item.belongs_to(flow) {
                    return out_of_order("a step of another flow");
                }
                Ok(())
            }
            EngineMsg::Prompt { id, kind } => {
                if self.prompt.is_some() || self.answered {
                    return out_of_order("a prompt while one is open or answered");
                }
                if self.expected_prompt() != Some(*kind) {
                    return out_of_order("a prompt that does not fit the screen");
                }
                if self.last_prompt.is_some_and(|last| *id <= last) {
                    return out_of_order("a prompt id that does not increase");
                }
                self.last_prompt = Some(*id);
                self.prompt = Some(OpenPrompt {
                    id: *id,
                    kind: *kind,
                });
                Ok(())
            }
            EngineMsg::Outcome(outcome) => self.finish_with(flow, outcome),
        }
    }

    fn progress(&mut self, flow: Flow, phase: Phase) -> Result<(), ProtocolError> {
        match flow {
            Flow::Install => match phase {
                Phase::Check | Phase::Scan | Phase::Download | Phase::Stage | Phase::Install => {
                    Ok(())
                }
                _ => out_of_order("a phase that is not an install phase"),
            },
            Flow::Uninstall => match phase {
                Phase::Uninstall => Ok(()),
                _ => out_of_order("a phase that is not the uninstall phase"),
            },
            Flow::Update => {
                let target = match phase {
                    Phase::Wait => Screen::UpdateWaiting,
                    Phase::Apply => Screen::UpdateApplying,
                    Phase::Launch | Phase::Confirm | Phase::Rollback => Screen::UpdateStarting,
                    _ => return out_of_order("a phase that is not an update phase"),
                };
                let rank = |s: Screen| match s {
                    Screen::UpdateWaiting => 0,
                    Screen::UpdateApplying => 1,
                    _ => 2,
                };
                if rank(target) < rank(self.screen) {
                    return out_of_order("an update phase that goes back");
                }
                if target != self.screen {
                    self.set_screen(target);
                }
                Ok(())
            }
        }
    }

    fn finish_with(&mut self, flow: Flow, outcome: &Outcome) -> Result<(), ProtocolError> {
        if self.outcome.is_some() || self.prompt.is_some() {
            return out_of_order("an outcome after one, or with a prompt open");
        }
        let screen = match (flow, outcome) {
            (_, Outcome::Cancelled) => {
                if !self.cancel_requested {
                    return out_of_order("cancelled without a cancel");
                }
                self.screen
            }
            (Flow::Install, Outcome::Installed) if self.screen == Screen::Installing => {
                Screen::InstallDone
            }
            (Flow::Install, Outcome::Failed { .. }) => Screen::InstallFailed,
            (Flow::Update, Outcome::Updated) if self.is_running() => self.screen,
            (Flow::Update, Outcome::RolledBack { .. }) if self.is_running() => {
                Screen::UpdateRolledBack
            }
            (Flow::Update, Outcome::Failed { .. }) => Screen::UpdateFailed,
            (Flow::Uninstall, Outcome::Uninstalled { .. })
                if self.screen == Screen::Uninstalling =>
            {
                Screen::UninstallDone
            }
            (Flow::Uninstall, Outcome::UninstallFailed { .. }) => Screen::UninstallFailed,
            _ => return out_of_order("an outcome that does not fit the flow or the screen"),
        };
        if let Outcome::Uninstalled { leftovers } = outcome {
            self.leftovers = leftovers.len();
        }
        if screen != self.screen {
            self.set_screen(screen);
        }
        self.outcome = Some(outcome.clone());
        self.cancellable = false;
        Ok(())
    }

    /// Whether `msg` is a valid message from the UI now: a choice answering the open prompt's id
    /// with a value in that prompt's set (a `reveal` only for an index the outcome listed), a
    /// `Cancel` while cancellable, or a `Pong` answering the latest `Ping`. The UI's `Hello` is
    /// checked by the caller with [`check_hello`], before this state exists, and is not accepted.
    pub fn accepts(&self, msg: &UiMsg) -> bool {
        let Some(flow) = self.flow else {
            return false;
        };
        if self.screen == Screen::Closed {
            return matches!(msg, UiMsg::Pong { n } if self.ping == Some(*n));
        }
        match msg {
            UiMsg::Hello { .. } => false,
            UiMsg::Cancel => self.cancellable(),
            UiMsg::Pong { n } => self.ping == Some(*n),
            UiMsg::Choice { id, value } => {
                let Some(open) = self.prompt else {
                    return false;
                };
                open.id == *id && self.choice_fits(flow, open.kind, *value)
            }
        }
    }

    fn choice_fits(&self, flow: Flow, kind: PromptKind, value: ChoiceValue) -> bool {
        use ChoiceValue as C;
        match (flow, kind, value) {
            (Flow::Install, PromptKind::Welcome, C::Proceed | C::Cancel) => true,
            (Flow::Install, PromptKind::Welcome, C::ProceedAllUsers) => self.all_users_offered,
            (Flow::Uninstall, PromptKind::Confirm, C::Proceed | C::Cancel) => true,
            (Flow::Install, PromptKind::Done, C::Finish { .. }) => true,
            (Flow::Install, PromptKind::Failed, C::Retry | C::Close) => true,
            (Flow::Uninstall, PromptKind::Done, C::Close) => true,
            (Flow::Uninstall, PromptKind::Done, C::Reveal { index }) => {
                (index as usize) < self.leftovers
            }
            (Flow::Uninstall | Flow::Update, PromptKind::Failed, C::Close) => true,
            (Flow::Update, PromptKind::RolledBack, C::Acknowledge) => true,
            _ => false,
        }
    }

    /// Records a message from the UI after [`FlowState::accepts`] said yes; a message that is not
    /// accepted is an error and changes nothing. A `Pong` consumes the ping it answers, a
    /// `Cancel` and a `cancel` choice allow a `Cancelled` outcome, `proceed` and `retry` move to
    /// the running screen, and the other choices close their prompt.
    pub fn answer(&mut self, msg: &UiMsg) -> Result<(), ProtocolError> {
        if !self.accepts(msg) {
            return out_of_order("a message from the UI that is not valid now");
        }
        match msg {
            UiMsg::Hello { .. } => {}
            UiMsg::Pong { .. } => self.ping = None,
            UiMsg::Cancel => self.cancel_requested = true,
            UiMsg::Choice { value, .. } => match value {
                ChoiceValue::Reveal { .. } => {}
                ChoiceValue::Cancel => {
                    self.prompt = None;
                    self.answered = true;
                    self.cancel_requested = true;
                }
                ChoiceValue::Proceed | ChoiceValue::ProceedAllUsers => {
                    self.prompt = None;
                    let next = if self.flow == Some(Flow::Install) {
                        Screen::Installing
                    } else {
                        Screen::Uninstalling
                    };
                    self.set_screen(next);
                }
                ChoiceValue::Retry => {
                    self.prompt = None;
                    self.outcome = None;
                    self.cancel_requested = false;
                    self.set_screen(Screen::Installing);
                }
                ChoiceValue::Finish { .. } | ChoiceValue::Close | ChoiceValue::Acknowledge => {
                    self.prompt = None;
                    self.answered = true;
                }
            },
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_id_carries_the_protocol() {
        assert!(BUILD_ID.ends_with(&format!("+ui{PROTOCOL}")));
        assert!(build_id().starts_with(BUILD_ID));
    }

    #[test]
    fn every_phase_name_round_trips() {
        for (name, phase) in PHASES {
            assert_eq!(name_of(PHASES, *phase), Some(*name));
            assert_eq!(value_of(PHASES, name, "phase"), Ok(*phase));
        }
    }

    #[test]
    fn frame_caps_fit_one_frame() {
        // The icon in base64 and the other hello members stay under the frame cap.
        let icon = MAX_ICON_BYTES.div_ceil(3) * 4;
        assert!(icon + 8 * 1024 < MAX_FRAME);
    }
}
