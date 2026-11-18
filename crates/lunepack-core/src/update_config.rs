//! The update configuration (FORMAT.md 13, D44 (a), M5-D3, M5-D4, M5-D16, M5-D17): a strict-JSON
//! file at a fixed place in every version tree, covered by the manifest's file hash, that tells
//! the runtime and the facade which root, feed and channel the tree updates from and how the app is
//! installed (entry, name, icon, ...).
//!
//! The reader ([`UpdateConfig::parse`]) and the writer ([`UpdateConfig::to_bytes`]) share every
//! rule: the writer runs the reader over the bytes it is about to return. Every refusal is an
//! [`UpdateConfigError`] naming the field or rule; no value from the document is ever shown.
//!
//! [`check_feed`] is the core's feed rule. It is a pre-filter: the facade's `check_config_feed`
//! runs it, then the URL parser the transport uses, and is the authoritative check.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::{DesktopPathError, FeedRule, UpdateConfigError};
use crate::ident::{AppId, Channel};
use crate::limits::{Limits, MAX_JSON_INT};
use crate::path::{RelPath, validate_path};
use crate::root::TrustedRoot;
use crate::state::RootParts;
use crate::target::Target;
use crate::trust::PublicKey;
use crate::version::Version;

/// The config's file name, at the version tree's root on Linux and Windows (FORMAT.md 13.1). Fixed
/// for format 1, so any version's runtime finds another version's config at the same place.
pub const UPDATE_CONFIG_FILE: &str = "lunepack-update.json";
/// The config's path inside a macOS bundle tree (assumed until M8).
pub const UPDATE_CONFIG_PATH_MACOS: &str = "Contents/Resources/lunepack-update.json";
/// The runtime's file name on Linux and macOS targets, in the directory of `install.entry` (C4).
pub const RUNTIME_FILE: &str = "lunepack-runtime";
/// The runtime's file name on Windows targets.
pub const RUNTIME_FILE_WINDOWS: &str = "lunepack-runtime.exe";
/// The UI binary's file name on Linux and macOS targets, beside the runtime (M6-D1).
pub const UI_FILE: &str = "lunepack-ui";
/// The UI binary's file name on Windows targets.
pub const UI_FILE_WINDOWS: &str = "lunepack-ui.exe";
/// Largest config document in bytes.
pub const MAX_UPDATE_CONFIG_BYTES: u64 = 64 * 1024;
/// Longest feed string in bytes.
pub const MAX_FEED_BYTES: usize = 2048;
/// Allowed range of `health_timeout_secs`.
pub const HEALTH_TIMEOUT_SECS: std::ops::RangeInclusive<u64> = 5..=3600;
/// The `health_timeout_secs` the packager writes when `lunepack.toml` names none (M5-D5).
pub const DEFAULT_HEALTH_TIMEOUT_SECS: u64 = 60;
/// Longest `install.name`, in Unicode scalar values.
pub const MAX_NAME_CHARS: usize = 128;
/// Longest `install.publisher`, in Unicode scalar values (as `install.name`).
pub const MAX_PUBLISHER_CHARS: usize = MAX_NAME_CHARS;
/// Longest `install.comment`, in Unicode scalar values.
pub const MAX_COMMENT_CHARS: usize = 512;
/// Most `install.categories`.
pub const MAX_CATEGORIES: usize = 16;
/// Longest category, and longest `install.bin`, in bytes.
pub const MAX_TOKEN_BYTES: usize = 64;

const KIND: &str = "update-config";
const TOP_KEYS: [&str; 11] = [
    "app_id",
    "channel",
    "critical",
    "feed",
    "format",
    "health_timeout_secs",
    "install",
    "kind",
    "root",
    "target",
    "version",
];
const ROOT_KEYS: [&str; 3] = ["keys", "threshold", "version"];
const INSTALL_KEYS: [&str; 8] = [
    "bin",
    "categories",
    "comment",
    "entry",
    "icon",
    "name",
    "publisher",
    "terminal",
];

/// The config's path relative to a version tree of `target`.
pub fn config_path(target: Target) -> &'static str {
    match target {
        Target::MacosX86_64 | Target::MacosAarch64 | Target::MacosUniversal => {
            UPDATE_CONFIG_PATH_MACOS
        }
        _ => UPDATE_CONFIG_FILE,
    }
}

/// The runtime's file name on `target`.
pub fn runtime_file(target: Target) -> &'static str {
    if target.is_windows() {
        RUNTIME_FILE_WINDOWS
    } else {
        RUNTIME_FILE
    }
}

/// The UI binary's file name on `target`.
pub fn ui_file(target: Target) -> &'static str {
    if target.is_windows() {
        UI_FILE_WINDOWS
    } else {
        UI_FILE
    }
}

/// How the app is installed (FORMAT.md 13.4, M5-D4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallMeta {
    /// The executable the runtime launches, relative to the tree.
    pub entry: RelPath,
    /// The app's display name.
    pub name: String,
    /// A one-line description.
    pub comment: Option<String>,
    /// A PNG or SVG file in the tree.
    pub icon: Option<RelPath>,
    /// freedesktop main and additional category names.
    pub categories: Vec<String>,
    /// The name of the command-line link (`~/.local/bin/<bin>` on Linux).
    pub bin: Option<String>,
    /// Whether the app runs in a terminal.
    pub terminal: bool,
    /// The publisher's display name, shown by the installer beside "verified" (M6-D3). Optional;
    /// absent stays absent in the canonical bytes (FORMAT.md 13.4).
    pub publisher: Option<String>,
}

/// What kind of feed a feed string passed [`check_feed`] as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FeedKind {
    /// `https://`.
    Https,
    /// `file:///`.
    File,
    /// `http://` to a loopback IP literal; fetched with no proxy and no redirect (M5-D16).
    HttpLoopback,
}

/// An update-config document (FORMAT.md 13.2). Build one with [`UpdateConfig::new`]; the fields are
/// public, and [`UpdateConfig::to_bytes`] checks them all again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateConfig {
    /// The app id; equal to the root's.
    pub app_id: AppId,
    /// This tree's own version.
    pub version: Version,
    /// This tree's target.
    pub target: Target,
    /// The trusted root the tree updates under, as its parts (5.2).
    pub root: RootParts,
    /// The feed directory URL (13.3), ending in `/`.
    pub feed: String,
    /// The channel the tree follows.
    pub channel: Channel,
    /// How long a supervised start may take to confirm its health.
    pub health_timeout_secs: u64,
    /// The install metadata.
    pub install: InstallMeta,
    /// Unknown top-level members a reader found (13.7); written back unchanged.
    pub extra: BTreeMap<String, Value>,
}

impl UpdateConfig {
    /// A config for `root` (the app id and root parts come from it). `feed` gets a trailing `/`
    /// when it has none. Every rule of the reader is checked.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root: &TrustedRoot,
        version: Version,
        target: Target,
        feed: &str,
        channel: Channel,
        health_timeout_secs: u64,
        install: InstallMeta,
    ) -> Result<UpdateConfig, UpdateConfigError> {
        let config = UpdateConfig {
            app_id: root.app_id().clone(),
            version,
            target,
            root: RootParts::from_trusted(root),
            feed: with_trailing_slash(feed),
            channel,
            health_timeout_secs,
            install,
            extra: BTreeMap::new(),
        };
        config.to_bytes()?;
        Ok(config)
    }

    /// Fails unless the app id and root parts are `root`'s.
    pub fn check_root(&self, root: &TrustedRoot) -> Result<(), UpdateConfigError> {
        if self.app_id != *root.app_id() {
            return Err(UpdateConfigError::RootMismatch("app_id"));
        }
        if self.root != RootParts::from_trusted(root) {
            return Err(UpdateConfigError::RootMismatch("root"));
        }
        Ok(())
    }

    /// The feed's kind under the core rule.
    pub fn feed_kind(&self) -> Result<FeedKind, UpdateConfigError> {
        check_feed(&self.feed)
    }

    /// The canonical bytes (13.2): pretty-printed strict JSON with every object's members in byte
    /// order of their names and a final newline. The reader is run over them before they are
    /// returned, so the writer never produces a document the reader refuses.
    pub fn to_bytes(&self) -> Result<Vec<u8>, UpdateConfigError> {
        let mut top: BTreeMap<String, Value> = BTreeMap::new();
        for (key, value) in &self.extra {
            if TOP_KEYS.contains(&key.as_str()) {
                return Err(invalid("extra", "uses a defined member name"));
            }
            top.insert(key.clone(), sorted(value.clone()));
        }
        let root = obj([
            (
                "keys",
                Value::Array(
                    self.root
                        .keys
                        .iter()
                        .map(|k| Value::String(k.to_hex()))
                        .collect(),
                ),
            ),
            ("threshold", Value::from(self.root.threshold)),
            ("version", Value::from(self.root.version)),
        ]);
        let i = &self.install;
        let mut install = obj([
            ("bin", opt_string(i.bin.as_deref())),
            (
                "categories",
                Value::Array(i.categories.iter().cloned().map(Value::String).collect()),
            ),
            ("comment", opt_string(i.comment.as_deref())),
            ("entry", Value::String(i.entry.as_str().to_owned())),
            ("icon", opt_string(i.icon.as_ref().map(RelPath::as_str))),
            ("name", Value::String(i.name.clone())),
            ("terminal", Value::Bool(i.terminal)),
        ]);
        // Left out when absent, so the bytes of a config without a publisher are the M5 bytes.
        if let (Some(p), Value::Object(members)) = (&i.publisher, &mut install) {
            members.insert("publisher".to_owned(), Value::String(p.clone()));
        }
        let defined = [
            ("app_id", Value::String(self.app_id.as_str().to_owned())),
            ("channel", Value::String(self.channel.as_str().to_owned())),
            ("critical", Value::Array(Vec::new())),
            ("feed", Value::String(with_trailing_slash(&self.feed))),
            ("format", Value::from(1u64)),
            ("health_timeout_secs", Value::from(self.health_timeout_secs)),
            ("install", install),
            ("kind", Value::String(KIND.to_owned())),
            ("root", root),
            ("target", Value::String(self.target.as_str().to_owned())),
            ("version", Value::String(self.version.to_string())),
        ];
        for (key, value) in defined {
            top.insert(key.to_owned(), value);
        }
        let mut bytes = serde_json::to_vec_pretty(&top)
            .map_err(|_| invalid("document", "does not serialise"))?;
        bytes.push(b'\n');
        UpdateConfig::parse(&bytes)?;
        Ok(bytes)
    }

    /// Reads a config document: at most 64 KiB, strict JSON (3.1), `format` 1, no `critical` name,
    /// `kind` `update-config`, then every member's rule (13.2 to 13.4). Unknown top-level members
    /// are kept in [`UpdateConfig::extra`]; an unknown member inside `root` or `install` is refused.
    pub fn parse(bytes: &[u8]) -> Result<UpdateConfig, UpdateConfigError> {
        if bytes.len() as u64 > MAX_UPDATE_CONFIG_BYTES {
            return Err(UpdateConfigError::TooLarge {
                size: bytes.len() as u64,
                cap: MAX_UPDATE_CONFIG_BYTES,
            });
        }
        crate::json::check_strict(bytes).map_err(|e| match e {
            crate::Error::Json(j) => UpdateConfigError::Json(j),
            _ => invalid("document", "is not strict JSON"),
        })?;
        let mut top: BTreeMap<String, Value> =
            serde_json::from_slice(bytes).map_err(|_| invalid("document", "is not an object"))?;

        match int(take(&mut top, "format")?, "format")? {
            1 => {}
            0 => return Err(invalid("format", "is 0")),
            _ => return Err(UpdateConfigError::NewerFormat),
        }
        let Value::Array(critical) = take(&mut top, "critical")? else {
            return Err(UpdateConfigError::WrongType("critical"));
        };
        if critical.iter().any(|c| !c.is_string()) {
            return Err(UpdateConfigError::WrongType("critical"));
        }
        if !critical.is_empty() {
            // Format 1 implements no critical name, so every name is unknown (13.7).
            return Err(UpdateConfigError::NewerFormat);
        }
        if string(take(&mut top, "kind")?, "kind")? != KIND {
            return Err(invalid("kind", "is not update-config"));
        }

        let app_id = AppId::parse(&string(take(&mut top, "app_id")?, "app_id")?)
            .map_err(|_| invalid("app_id", "is not an app id (10.6)"))?;
        let version = Version::parse(&string(take(&mut top, "version")?, "version")?)
            .map_err(|_| invalid("version", "is not a version (10.3)"))?;
        let target = Target::parse(&string(take(&mut top, "target")?, "target")?)
            .map_err(|_| invalid("target", "is not a target id (10.4)"))?;
        let root = read_root(take(&mut top, "root")?)?;
        let feed = string(take(&mut top, "feed")?, "feed")?;
        check_feed(&feed)?;
        let channel = Channel::parse(&string(take(&mut top, "channel")?, "channel")?)
            .map_err(|_| invalid("channel", "is not a channel id (10.5)"))?;
        let health_timeout_secs = int(
            take(&mut top, "health_timeout_secs")?,
            "health_timeout_secs",
        )?;
        if !HEALTH_TIMEOUT_SECS.contains(&health_timeout_secs) {
            return Err(invalid("health_timeout_secs", "is outside 5..=3600"));
        }
        let install = read_install(take(&mut top, "install")?)?;

        Ok(UpdateConfig {
            app_id,
            version,
            target,
            root,
            feed,
            channel,
            health_timeout_secs,
            install,
            extra: top,
        })
    }
}

// ---- members ---------------------------------------------------------------------------------------

fn read_root(value: Value) -> Result<RootParts, UpdateConfigError> {
    let mut map = object(value, "root", &ROOT_KEYS)?;
    let version = int(take(&mut map, "root.version")?, "root.version")?;
    if version == 0 {
        return Err(invalid("root.version", "is 0"));
    }
    let threshold = int(take(&mut map, "root.threshold")?, "root.threshold")?;
    let Value::Array(items) = take(&mut map, "root.keys")? else {
        return Err(UpdateConfigError::WrongType("root.keys"));
    };
    let max = Limits::V1.root_keys;
    if items.is_empty() || items.len() > max {
        return Err(invalid("root.keys", "holds 0 or more than 16 keys"));
    }
    let mut keys: Vec<PublicKey> = Vec::with_capacity(items.len());
    for item in items {
        let text = string(item, "root.keys")?;
        let bytes = crate::encoding::hex_decode_array::<32>(&text)
            .map_err(|_| invalid("root.keys", "a key is not 64 lowercase hex characters"))?;
        let key = PublicKey::from_bytes(bytes);
        if keys.contains(&key) {
            return Err(invalid("root.keys", "a key is listed twice"));
        }
        keys.push(key);
    }
    if threshold == 0 || threshold > keys.len() as u64 {
        return Err(invalid("root.threshold", "is outside 1..=len(keys)"));
    }
    Ok(RootParts {
        version,
        threshold,
        keys,
    })
}

fn read_install(value: Value) -> Result<InstallMeta, UpdateConfigError> {
    let mut map = object(value, "install", &INSTALL_KEYS)?;
    let entry = string(take(&mut map, "install.entry")?, "install.entry")?;
    let entry = check_entry(&entry)?;
    let name = string(take(&mut map, "install.name")?, "install.name")?;
    check_text(&name, "install.name", 1, MAX_NAME_CHARS)?;
    let comment = opt(take(&mut map, "install.comment")?, "install.comment")?;
    if let Some(c) = &comment {
        check_text(c, "install.comment", 0, MAX_COMMENT_CHARS)?;
    }
    let publisher = match map.remove("publisher") {
        None => None,
        Some(Value::Null) => return Err(UpdateConfigError::WrongType("install.publisher")),
        Some(v) => {
            let p = string(v, "install.publisher")?;
            check_text(&p, "install.publisher", 1, MAX_PUBLISHER_CHARS)?;
            Some(p)
        }
    };
    let icon = opt(take(&mut map, "install.icon")?, "install.icon")?
        .map(|i| check_icon(&i))
        .transpose()?;
    let Value::Array(items) = take(&mut map, "install.categories")? else {
        return Err(UpdateConfigError::WrongType("install.categories"));
    };
    if items.len() > MAX_CATEGORIES {
        return Err(invalid("install.categories", "holds more than 16 names"));
    }
    let mut categories: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let c = string(item, "install.categories")?;
        check_category(&c)?;
        if categories.contains(&c) {
            return Err(invalid("install.categories", "a name is listed twice"));
        }
        categories.push(c);
    }
    let bin = opt(take(&mut map, "install.bin")?, "install.bin")?;
    if let Some(b) = &bin {
        check_bin(b)?;
    }
    let Value::Bool(terminal) = take(&mut map, "install.terminal")? else {
        return Err(UpdateConfigError::WrongType("install.terminal"));
    };
    Ok(InstallMeta {
        entry,
        name,
        comment,
        icon,
        categories,
        bin,
        terminal,
        publisher,
    })
}

/// `install.entry`: a path (10.1) whose file name is not the runtime's or the UI's (either target's
/// form) and with no component named like the config file. Names are compared ignoring ASCII case,
/// since a case-insensitive file system would make them the same file.
fn check_entry(text: &str) -> Result<RelPath, UpdateConfigError> {
    let path =
        validate_path(text).map_err(|_| invalid("install.entry", "is not a tree path (10.1)"))?;
    check_reserved(&path, "install.entry")?;
    let file = path.components().last().unwrap_or_default();
    let reserved = [RUNTIME_FILE, RUNTIME_FILE_WINDOWS, UI_FILE, UI_FILE_WINDOWS];
    if reserved.iter().any(|r| file.eq_ignore_ascii_case(r)) {
        return Err(invalid(
            "install.entry",
            "is the runtime's or the UI's file name",
        ));
    }
    Ok(path)
}

/// `install.icon`: a path (10.1) to a `.png` or `.svg` file.
fn check_icon(text: &str) -> Result<RelPath, UpdateConfigError> {
    let path =
        validate_path(text).map_err(|_| invalid("install.icon", "is not a tree path (10.1)"))?;
    check_reserved(&path, "install.icon")?;
    let file = path.components().last().unwrap_or_default();
    let ext = file.rsplit_once('.').map(|(_, e)| e).unwrap_or_default();
    if !(ext.eq_ignore_ascii_case("png") || ext.eq_ignore_ascii_case("svg")) {
        return Err(invalid("install.icon", "is not a .png or .svg file"));
    }
    Ok(path)
}

fn check_reserved(path: &RelPath, field: &'static str) -> Result<(), UpdateConfigError> {
    if path
        .components()
        .any(|c| c.eq_ignore_ascii_case(UPDATE_CONFIG_FILE))
    {
        return Err(invalid(field, "names the update config file"));
    }
    Ok(())
}

/// `install.name` and `install.comment`: a length in Unicode scalars, no C0 or C1 control, DEL,
/// U+2028 or U+2029, no `\`, and no leading or trailing whitespace.
fn check_text(
    text: &str,
    field: &'static str,
    min: usize,
    max: usize,
) -> Result<(), UpdateConfigError> {
    let count = text.chars().count();
    if count < min || count > max {
        return Err(invalid(field, "has a length outside its range"));
    }
    if text
        .chars()
        .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\\'))
    {
        return Err(invalid(
            field,
            "has a control character, line separator or \\",
        ));
    }
    let edge = |c: Option<char>| c.is_some_and(char::is_whitespace);
    if edge(text.chars().next()) || edge(text.chars().next_back()) {
        return Err(invalid(field, "has leading or trailing whitespace"));
    }
    Ok(())
}

fn check_category(text: &str) -> Result<(), UpdateConfigError> {
    let ok = (1..=MAX_TOKEN_BYTES).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(invalid(
            "install.categories",
            "a name is not [A-Za-z0-9-]{1,64}",
        ))
    }
}

fn check_bin(text: &str) -> Result<(), UpdateConfigError> {
    let ok = (1..=MAX_TOKEN_BYTES).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !text.starts_with(['-', '.']);
    if ok {
        Ok(())
    } else {
        Err(invalid(
            "install.bin",
            "is not [A-Za-z0-9._-]{1,64} starting with a letter, digit or _",
        ))
    }
}

/// Fails unless `path` can go into a desktop entry's `Exec` or `Icon` value as is: not empty, and
/// every character printable and none of `" ` $ \ % '` (FORMAT.md 13.5). Controls, U+2028/2029
/// and invisible format characters are refused. Shared by the writer's callers and the Linux
/// integration, so both apply one rule.
pub fn desktop_safe_path(path: &str) -> Result<(), DesktopPathError> {
    if path.is_empty() {
        return Err(DesktopPathError::Empty);
    }
    let bad = |c: char| {
        c.is_control()
            || matches!(c, '"' | '`' | '$' | '\\' | '%' | '\'')
            || matches!(
                c,
                '\u{00AD}'
                    | '\u{200B}'..='\u{200F}'
                    | '\u{2028}'..='\u{202E}'
                    | '\u{2060}'..='\u{2064}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{FEFF}'
            )
    };
    if path.chars().any(bad) {
        return Err(DesktopPathError::Char);
    }
    Ok(())
}

// ---- the feed rule ---------------------------------------------------------------------------------

/// Bytes refused anywhere in a feed: no userinfo, query, fragment, percent-encoding, backslash
/// (WHATWG reads it as `/`) or characters WHATWG would encode.
const FEED_FORBIDDEN: &[u8] = b"\\%?#@\"<>^`{|}";

/// The core's feed rule (FORMAT.md 13.3, M5-D16), shared by the writer and the reader. Pure and
/// fail closed; a string it accepts is in the canonical form of the WHATWG URL parser, so a parse
/// never changes it. The facade's `check_config_feed` runs this, then the parser, and is the
/// authoritative check.
pub fn check_feed(feed: &str) -> Result<FeedKind, UpdateConfigError> {
    feed_rule(feed).map_err(UpdateConfigError::Feed)
}

fn feed_rule(feed: &str) -> Result<FeedKind, FeedRule> {
    let bytes = feed.as_bytes();
    if bytes.len() > MAX_FEED_BYTES {
        return Err(FeedRule::TooLong);
    }
    if !bytes.iter().all(|b| (0x21..=0x7E).contains(b)) {
        return Err(FeedRule::Byte);
    }
    if bytes.iter().any(|b| FEED_FORBIDDEN.contains(b)) {
        return Err(FeedRule::Forbidden);
    }
    if let Some(path) = feed.strip_prefix("file://") {
        if !path.starts_with('/') {
            return Err(FeedRule::Scheme);
        }
        check_feed_path(path, true)?;
        return Ok(FeedKind::File);
    }
    let (kind, rest) = if let Some(rest) = feed.strip_prefix("https://") {
        (FeedKind::Https, rest)
    } else if let Some(rest) = feed.strip_prefix("http://") {
        (FeedKind::HttpLoopback, rest)
    } else {
        return Err(FeedRule::Scheme);
    };
    let Some(slash) = rest.find('/') else {
        return Err(FeedRule::Path);
    };
    let (authority, path) = rest.split_at(slash);
    let host_error = match kind {
        FeedKind::HttpLoopback => FeedRule::HttpNotLoopback,
        _ => FeedRule::Host,
    };
    let (host, port) = split_host_port(authority).ok_or(host_error)?;
    match kind {
        FeedKind::Https => check_https_host(host)?,
        _ => {
            let loopback =
                host == "[::1]" || dotted_quad(host).is_some_and(|parts| parts[0] == 127);
            if !loopback {
                return Err(FeedRule::HttpNotLoopback);
            }
        }
    }
    if let Some(port) = port {
        let default = if kind == FeedKind::Https { 443 } else { 80 };
        check_port(port, default)?;
    }
    check_feed_path(path, false)?;
    Ok(kind)
}

/// `host[:port]` or `[v6][:port]`; `None` when the shape is wrong (an empty host, two colons).
fn split_host_port(authority: &str) -> Option<(&str, Option<&str>)> {
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let (host, after) = authority.split_at(end + 1);
        return match after {
            "" => Some((host, None)),
            _ => Some((host, Some(after.strip_prefix(':')?))),
        };
    }
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if host.is_empty() || host.contains(['[', ']']) || port.is_some_and(|p| p.contains(':')) {
        return None;
    }
    Some((host, port))
}

/// Lowercase LDH labels, or a canonical dotted-quad when the last label is all digits or starts
/// with `0x` (WHATWG reads those as IPv4). No IPv6 in v1.
fn check_https_host(host: &str) -> Result<(), FeedRule> {
    if host.starts_with('[') {
        return Err(FeedRule::Ipv6Host);
    }
    if host.len() > 253 {
        return Err(FeedRule::Host);
    }
    let last = host.rsplit('.').next().unwrap_or_default();
    if last.is_empty() {
        return Err(FeedRule::Host);
    }
    if last.bytes().all(|b| b.is_ascii_digit()) || last.starts_with("0x") {
        return dotted_quad(host).map(|_| ()).ok_or(FeedRule::Host);
    }
    let label_ok = |label: &str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    if host.split('.').all(label_ok) {
        Ok(())
    } else {
        Err(FeedRule::Host)
    }
}

/// Four decimal parts `0..=255` with no leading zero.
fn dotted_quad(host: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = host.split('.');
    for slot in &mut out {
        let part = parts.next()?;
        let canonical = !part.is_empty()
            && part.len() <= 3
            && part.bytes().all(|b| b.is_ascii_digit())
            && (part == "0" || !part.starts_with('0'));
        if !canonical {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

fn check_port(port: &str, default: u32) -> Result<(), FeedRule> {
    let ok = !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && !port.starts_with('0')
        && port
            .parse::<u32>()
            .is_ok_and(|p| (1..=65535).contains(&p) && p != default);
    if ok { Ok(()) } else { Err(FeedRule::Port) }
}

/// `/`, or `/seg/.../` with segments of `[A-Za-z0-9._~-]+` that are not `.` or `..`; a `file:`
/// path may start with one drive segment `[A-Z]:`.
fn check_feed_path(path: &str, file: bool) -> Result<(), FeedRule> {
    if !path.starts_with('/') || !path.ends_with('/') {
        return Err(FeedRule::Path);
    }
    if path == "/" {
        return Ok(());
    }
    for (i, segment) in path[1..path.len() - 1].split('/').enumerate() {
        let drive = file
            && i == 0
            && segment.len() == 2
            && segment.as_bytes()[0].is_ascii_uppercase()
            && segment.as_bytes()[1] == b':';
        if drive {
            continue;
        }
        let ok = !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'));
        if !ok {
            return Err(FeedRule::Path);
        }
    }
    Ok(())
}

fn with_trailing_slash(feed: &str) -> String {
    if feed.ends_with('/') {
        feed.to_owned()
    } else {
        format!("{feed}/")
    }
}

// ---- JSON helpers ----------------------------------------------------------------------------------

fn invalid(field: &'static str, rule: &'static str) -> UpdateConfigError {
    UpdateConfigError::Invalid { field, rule }
}

fn take(
    map: &mut BTreeMap<String, Value>,
    field: &'static str,
) -> Result<Value, UpdateConfigError> {
    let key = field.rsplit('.').next().unwrap_or(field);
    map.remove(key).ok_or(UpdateConfigError::Missing(field))
}

fn object(
    value: Value,
    field: &'static str,
    keys: &[&str],
) -> Result<BTreeMap<String, Value>, UpdateConfigError> {
    let Value::Object(map) = value else {
        return Err(UpdateConfigError::WrongType(field));
    };
    if map.keys().any(|k| !keys.contains(&k.as_str())) {
        return Err(UpdateConfigError::Unknown(field));
    }
    Ok(map.into_iter().collect())
}

fn string(value: Value, field: &'static str) -> Result<String, UpdateConfigError> {
    match value {
        Value::String(s) => Ok(s),
        _ => Err(UpdateConfigError::WrongType(field)),
    }
}

fn opt(value: Value, field: &'static str) -> Result<Option<String>, UpdateConfigError> {
    match value {
        Value::Null => Ok(None),
        other => string(other, field).map(Some),
    }
}

fn int(value: Value, field: &'static str) -> Result<u64, UpdateConfigError> {
    match value.as_u64() {
        Some(n) if n <= MAX_JSON_INT => Ok(n),
        Some(_) => Err(invalid(field, "is above 2^53 - 1")),
        None => Err(UpdateConfigError::WrongType(field)),
    }
}

fn opt_string(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |s| Value::String(s.to_owned()))
}

fn obj<const N: usize>(members: [(&str, Value); N]) -> Value {
    let map: BTreeMap<String, Value> = members
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
    Value::Object(map.into_iter().collect())
}

/// `value` with every object's members in key order, whatever map type `serde_json` was built
/// with.
fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let members: BTreeMap<String, Value> =
                map.into_iter().map(|(k, v)| (k, sorted(v))).collect();
            Value::Object(members.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

// ---- fuzz ------------------------------------------------------------------------------------------

/// The `update_config` fuzz harness: parse, and for an accepted document check that the writer
/// reproduces a document the reader reads back to the same value.
pub(crate) fn fuzz_run(data: &[u8]) -> bool {
    let Ok(config) = UpdateConfig::parse(data) else {
        return false;
    };
    let written = match config.to_bytes() {
        Ok(bytes) => bytes,
        // Pretty-printing can take a compact document near the cap over it.
        Err(UpdateConfigError::TooLarge { .. }) => return true,
        Err(e) => panic!("an accepted config does not write: {e}"),
    };
    let again = UpdateConfig::parse(&written).expect("the written config reads");
    assert_eq!(again, config, "update config round trip");
    assert_eq!(
        again.to_bytes().expect("rewrite"),
        written,
        "the writer is canonical"
    );
    true
}
