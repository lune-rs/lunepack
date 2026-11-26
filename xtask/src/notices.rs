//! Third-party notices (M13-D11): one file naming every package linked into the released
//! binaries, with its licence expression, source and licence texts, the bundled font's licence
//! and LuneUI's own notices.
//!
//! `xtask notices` writes `crates/lunepack-cli/THIRD-PARTY-NOTICES.txt`; `xtask notices --check`
//! compares the committed file with what would be written and fails with the first differing
//! line. The package set and each package's directory come from `cargo metadata --locked` and
//! nothing else: the dependency graph's normal and build edges, on any platform, from the five
//! shipped binary crates. A package with no licence expression, an expression no allowlisted
//! licence satisfies, or no licence text (no file in the package and no stored canonical text for
//! its identifier in `xtask/licenses/`) fails the command, so nothing is shipped without its
//! notice. The output is deterministic: sorted, LF, no date, no path, no host name.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, anyhow, bail};
use cargo_metadata::{DependencyKind, Metadata, MetadataCommand, Package, PackageId};

/// The packages whose dependencies are linked into what a release ships: the runtime, the update
/// service, the Windows stub, the UI and the CLI (M13-D11), and the C library (M14-D13), which is
/// not released but whose dependencies the shipped notices must provably cover.
pub const ROOTS: &[&str] = &[
    "lunepack-runtime",
    "lunepack-service",
    "lunepack-stub",
    "lunepack-ui",
    "lunepack-cli",
    "lunepack-ffi",
];

/// Where the generated file lives, relative to the workspace root. It sits in the CLI's crate so
/// the CLI can embed it and a published CLI package carries it.
pub const OUTPUT: &str = "crates/lunepack-cli/THIRD-PARTY-NOTICES.txt";

/// The canonical licence texts kept for a package that ships none of its own, relative to the
/// workspace root; one file per SPDX identifier, `<id>.txt`.
pub const CANONICAL_DIR: &str = "xtask/licenses";

/// The bundled font's licence text, relative to the workspace root.
pub const FONT_LICENSE: &str = "crates/lunepack-ui-luneui/assets/fonts/OFL.txt";

/// The licences the dependency graph may carry, by SPDX identifier. It is the allowlist of
/// `deny.toml` (the weekly `cargo deny check licenses`): adding one is a decision with its reason.
pub const ALLOWED: &[&str] = &[
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CDLA-Permissive-2.0",
    "ISC",
    "MIT",
    "MPL-2.0",
    "Unicode-3.0",
    "Zlib",
];

/// Name of the notices file in LuneUI's repository (its checkout is found from the `lune-ui`
/// package).
const LUNEUI_NOTICES: &str = "THIRD_PARTY_NOTICES.md";

/// Licence files of LuneUI's repository that cover test fixtures of its gallery application, which
/// no lunepack binary contains.
const LUNEUI_UNSHIPPED_LICENSES: &[&str] = &["lunegit-fixtures.txt"];

/// Everything the generator needs besides the workspace.
pub struct Config<'a> {
    /// Names of the binary crates whose dependencies are listed.
    pub roots: &'a [&'a str],
    /// SPDX identifiers a package may be licensed under.
    pub allowed: &'a [&'a str],
    /// Directory of `<id>.txt` canonical texts.
    pub canonical: PathBuf,
    /// The bundled font's licence, when there is one.
    pub font_license: Option<PathBuf>,
    /// Pass `--locked` to `cargo metadata`.
    pub locked: bool,
}

impl Config<'static> {
    /// The configuration of the real workspace rooted at `root`.
    pub fn for_workspace(root: &Path) -> Self {
        Config {
            roots: ROOTS,
            allowed: ALLOWED,
            canonical: root.join(CANONICAL_DIR),
            font_license: Some(root.join(FONT_LICENSE)),
            locked: true,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// SPDX expressions

/// A parsed SPDX licence expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// One identifier; an `X WITH exception` is the identifier `X` (the exception only widens
    /// what the licence permits).
    Id(String),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

/// Parses `text`. The deprecated `A/B` form Cargo still accepts means `A OR B`. Operators are the
/// upper-case words of SPDX; anything else the grammar does not know is an error.
pub fn parse_expr(text: &str) -> Result<Expr> {
    let spaced = text
        .replace('/', " OR ")
        .replace('(', " ( ")
        .replace(')', " ) ");
    let tokens: Vec<&str> = spaced.split_whitespace().collect();
    let mut at = 0;
    let expr = parse_or(&tokens, &mut at)?;
    if at != tokens.len() {
        bail!("unexpected `{}` in licence expression", tokens[at]);
    }
    Ok(expr)
}

fn parse_or(tokens: &[&str], at: &mut usize) -> Result<Expr> {
    let mut left = parse_and(tokens, at)?;
    while tokens.get(*at) == Some(&"OR") {
        *at += 1;
        let right = parse_and(tokens, at)?;
        left = Expr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and(tokens: &[&str], at: &mut usize) -> Result<Expr> {
    let mut left = parse_atom(tokens, at)?;
    while tokens.get(*at) == Some(&"AND") {
        *at += 1;
        let right = parse_atom(tokens, at)?;
        left = Expr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_atom(tokens: &[&str], at: &mut usize) -> Result<Expr> {
    let token = *tokens
        .get(*at)
        .ok_or_else(|| anyhow!("licence expression ends early"))?;
    *at += 1;
    if token == "(" {
        let inner = parse_or(tokens, at)?;
        if tokens.get(*at) != Some(&")") {
            bail!("licence expression has an unclosed `(`");
        }
        *at += 1;
        return Ok(inner);
    }
    if matches!(token, ")" | "OR" | "AND" | "WITH") {
        bail!("unexpected `{token}` in licence expression");
    }
    if !token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
    {
        bail!("`{token}` is not an SPDX identifier");
    }
    if tokens.get(*at) == Some(&"WITH") {
        *at += 1;
        let exception = tokens
            .get(*at)
            .ok_or_else(|| anyhow!("`WITH` has no exception"))?;
        if matches!(*exception, "(" | ")" | "OR" | "AND" | "WITH") {
            bail!("`WITH` is followed by `{exception}`");
        }
        *at += 1;
    }
    Ok(Expr::Id(token.to_owned()))
}

/// The identifiers a package of this expression is taken to be licensed under: for `OR` the first
/// alternative every identifier of which is allowed, for `AND` all of both sides. `None` when no
/// alternative is wholly allowed.
pub fn satisfy(expr: &Expr, allowed: &[&str]) -> Option<Vec<String>> {
    match expr {
        Expr::Id(id) => allowed.contains(&id.as_str()).then(|| vec![id.clone()]),
        Expr::And(a, b) => {
            let mut out = satisfy(a, allowed)?;
            out.extend(satisfy(b, allowed)?);
            Some(out)
        }
        Expr::Or(a, b) => satisfy(a, allowed).or_else(|| satisfy(b, allowed)),
    }
}

// ---------------------------------------------------------------------------------------------
// Texts

/// A text read from disk, as UTF-8 with LF line ends and no trailing blanks; the bytes that are
/// not UTF-8 are read as Latin-1, which is what the few old files in that case use.
fn normalize(bytes: &[u8]) -> String {
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => bytes.iter().map(|&b| char::from(b)).collect(),
    };
    let text = text.trim_start_matches('\u{feff}').replace("\r\n", "\n");
    let mut out = String::with_capacity(text.len() + 1);
    for line in text.replace('\r', "\n").trim_matches('\n').split('\n') {
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// The texts of the file, each stored once and numbered in the order it is first used.
#[derive(Default)]
struct Texts {
    numbers: BTreeMap<String, usize>,
    list: Vec<String>,
}

impl Texts {
    fn add(&mut self, text: String) -> usize {
        if let Some(&n) = self.numbers.get(&text) {
            return n;
        }
        let n = self.list.len() + 1;
        self.numbers.insert(text.clone(), n);
        self.list.push(text);
        n
    }
}

/// Extensions that mark a file whose name starts like a licence file as something else.
const NOT_TEXT: &[&str] = &[
    "rs", "toml", "lock", "json", "yml", "yaml", "sh", "py", "c", "h", "cc", "cpp", "js", "ts",
];

/// Name prefixes (upper case) of the files that carry a package's licence or notice.
const LICENSE_PREFIXES: &[&str] = &["LICENSE", "LICENCE", "COPYING", "UNLICENSE", "NOTICE"];

/// The regular files of `dir` that carry a licence or a notice, by name, sorted. `extra` is the
/// manifest's own `license-file`, when it names a file of `dir`.
fn license_files(dir: &Path, extra: Option<&str>) -> Result<Vec<(String, String)>> {
    let mut names = BTreeSet::new();
    let entries = fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let upper = name.to_ascii_uppercase();
        let ext = upper.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
        let text_like = ext.is_none_or(|e| !NOT_TEXT.contains(&e.as_str()));
        if text_like
            && LICENSE_PREFIXES.iter().any(|p| upper.starts_with(p))
            && fs::metadata(entry.path()).is_ok_and(|m| m.is_file())
        {
            names.insert(name);
        }
    }
    if let Some(extra) = extra
        && !extra.contains('/')
        && !extra.contains('\\')
        && fs::metadata(dir.join(extra)).is_ok_and(|m| m.is_file())
    {
        names.insert(extra.to_owned());
    }
    let mut out = Vec::new();
    for name in names {
        let bytes = fs::read(dir.join(&name))
            .with_context(|| format!("cannot read a licence file of {}", dir.display()))?;
        out.push((name, normalize(&bytes)));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// The package set

/// The packages that are a normal or build dependency, on any platform and transitively, of one
/// of `roots`, the roots' own workspace and the other workspace members left out: the result is
/// the third-party code.
fn third_party<'m>(md: &'m Metadata, roots: &[&str]) -> Result<Vec<&'m Package>> {
    let resolve = md
        .resolve
        .as_ref()
        .ok_or_else(|| anyhow!("cargo metadata returned no dependency graph"))?;
    let nodes: BTreeMap<&PackageId, _> = resolve.nodes.iter().map(|n| (&n.id, n)).collect();
    let mut stack = Vec::new();
    for name in roots {
        let root = md
            .packages
            .iter()
            .find(|p| p.name.as_str() == *name && md.workspace_members.contains(&p.id))
            .ok_or_else(|| anyhow!("the workspace has no package `{name}`"))?;
        stack.push(&root.id);
    }
    let mut seen: BTreeSet<&PackageId> = stack.iter().copied().collect();
    while let Some(id) = stack.pop() {
        let node = nodes
            .get(id)
            .ok_or_else(|| anyhow!("the dependency graph has no node for {id}"))?;
        for dep in &node.deps {
            let linked = dep
                .dep_kinds
                .iter()
                .any(|k| matches!(k.kind, DependencyKind::Normal | DependencyKind::Build));
            if linked && seen.insert(&dep.pkg) {
                stack.push(&dep.pkg);
            }
        }
    }
    let mut out: Vec<&Package> = md
        .packages
        .iter()
        .filter(|p| seen.contains(&p.id) && !md.workspace_members.contains(&p.id))
        .collect();
    out.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    Ok(out)
}

/// A package's source as the file prints it: no path of this machine in it.
fn source_text(p: &Package) -> Result<String> {
    let Some(source) = &p.source else {
        bail!(
            "{} {} is a path dependency outside the workspace: it has no public source to name",
            p.name,
            p.version
        );
    };
    let repr = source.repr.as_str();
    if repr == "registry+https://github.com/rust-lang/crates.io-index"
        || repr == "sparse+https://index.crates.io/"
    {
        return Ok("crates.io".to_owned());
    }
    Ok(repr.to_owned())
}

/// The directory of the package's own files.
fn package_dir(p: &Package) -> Result<&Path> {
    p.manifest_path
        .as_std_path()
        .parent()
        .ok_or_else(|| anyhow!("{} has no manifest directory", p.name))
}

/// The directory above `start` that holds `file`, within a few levels (a package of a git
/// repository sits in a subdirectory of the checkout).
fn find_above(start: &Path, file: &str) -> Option<PathBuf> {
    start
        .ancestors()
        .take(5)
        .find(|d| d.join(file).is_file())
        .map(Path::to_path_buf)
}

// ---------------------------------------------------------------------------------------------
// The file

/// The JSON `cargo metadata` prints for the workspace at `dir`.
pub fn metadata_json(dir: &Path, locked: bool) -> Result<String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut args = vec!["metadata", "--format-version", "1"];
    if locked {
        args.push("--locked");
    }
    let out = Command::new(&cargo)
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("cannot run {}", PathBuf::from(&cargo).display()))?;
    if !out.status.success() {
        bail!(
            "cargo metadata failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    String::from_utf8(out.stdout).context("cargo metadata output is not UTF-8")
}

/// Runs `cargo metadata` over the workspace at `dir`.
pub fn run_metadata(dir: &Path, locked: bool) -> Result<Metadata> {
    MetadataCommand::parse(metadata_json(dir, locked)?)
        .context("cannot parse cargo metadata output")
}

/// The text of the notices file for the workspace at `dir`.
pub fn generate(dir: &Path, config: &Config<'_>) -> Result<String> {
    let md = run_metadata(dir, config.locked)?;
    render(&md, config)
}

/// The text of the notices file for the packages in `md`.
pub fn render(md: &Metadata, config: &Config<'_>) -> Result<String> {
    let packages = third_party(md, config.roots)?;
    let mut texts = Texts::default();
    let mut body = String::new();
    let mut problems = Vec::new();
    for p in &packages {
        match package_section(p, config, &mut texts) {
            Ok(section) => body.push_str(&section),
            Err(e) => problems.push(format!("{} {}: {e:#}", p.name, p.version)),
        }
    }
    if !problems.is_empty() {
        let shown = problems.iter().take(100).cloned().collect::<Vec<_>>();
        bail!(
            "{} package(s) cannot be given a notice:\n  {}{}",
            problems.len(),
            shown.join("\n  "),
            if problems.len() > shown.len() {
                format!("\n  and {} more", problems.len() - shown.len())
            } else {
                String::new()
            }
        );
    }

    let mut out = String::new();
    out.push_str(HEADER);
    let _ = writeln!(out, "\nPackages: {}\n", packages.len());
    out.push_str("== Packages ==\n\n");
    out.push_str(&body);
    out.push_str(&luneui_section(&packages, &mut texts)?);
    out.push_str(&font_section(config, &mut texts)?);
    out.push_str("== Licence texts ==\n");
    for (i, text) in texts.list.iter().enumerate() {
        let _ = write!(out, "\n--- text {} ---\n{text}", i + 1);
    }
    Ok(out)
}

const HEADER: &str = "\
Third-party notices for the lunepack binaries
=============================================

lunepack's own code is licensed under MIT OR Apache-2.0 (LICENSE-MIT and LICENSE-APACHE in the
repository). The release binaries (lunepack-runtime, lunepack-service, lunepack-stub, lunepack-ui and
lunepack) are linked with the Rust packages below, the font and the notices after them. This file
is generated from `cargo metadata` by `cargo run -p xtask -- notices`; do not edit it by hand.

Each package lists its licence expression, its source and the licence texts it ships, as numbers into
the \"Licence texts\" section at the end. A text shared by several packages is stored once. A package
that ships no text of its own is given the canonical text of its licence, marked `canonical`.
";

/// One package's entry, with its texts added to `texts`.
fn package_section(p: &Package, config: &Config<'_>, texts: &mut Texts) -> Result<String> {
    let license = p
        .license
        .as_deref()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .ok_or_else(|| anyhow!("has no licence expression"))?;
    let expr = parse_expr(license).with_context(|| format!("licence `{license}`"))?;
    let used = satisfy(&expr, config.allowed).ok_or_else(|| {
        anyhow!("licence `{license}` is not allowed: no alternative is wholly in the allowlist")
    })?;
    let source = source_text(p)?;
    let mut files = license_files(package_dir(p)?, p.license_file.as_ref().map(|f| f.as_str()))?;
    if files.is_empty()
        && p.source
            .as_ref()
            .is_some_and(|s| s.repr.starts_with("git+"))
        && let Some(above) = package_dir(p)?.ancestors().skip(1).take(4).find(|d| {
            fs::read_dir(d).is_ok() && !license_files(d, None).unwrap_or_default().is_empty()
        })
    {
        // A git repository keeps one licence at its top, for every package in it.
        files = license_files(above, None)?;
    }
    let mut out = String::new();
    let _ = writeln!(out, "### {} {}", p.name, p.version);
    let _ = writeln!(out, "licence: {license}");
    let _ = writeln!(out, "source: {source}");
    if files.is_empty() {
        // The canonical text has no copyright line of its own: the manifest names the holders.
        if !p.authors.is_empty() {
            let _ = writeln!(out, "authors: {}", p.authors.join(", "));
        }
        if let Some(repository) = &p.repository {
            let _ = writeln!(out, "repository: {repository}");
        }
        let mut ids: Vec<String> = Vec::new();
        for id in used {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        for id in ids {
            let path = config.canonical.join(format!("{id}.txt"));
            let bytes = fs::read(&path).map_err(|_| {
                anyhow!("ships no licence text and xtask/licenses/{id}.txt does not exist")
            })?;
            let n = texts.add(normalize(&bytes));
            let _ = writeln!(out, "text: canonical {id}, text {n}");
        }
    } else {
        for (name, text) in files {
            let n = texts.add(text);
            let _ = writeln!(out, "text: {name}, text {n}");
        }
    }
    out.push('\n');
    Ok(out)
}

/// LuneUI's own notices (its repository's `THIRD_PARTY_NOTICES.md` and the licence texts beside
/// it), when LuneUI is among the packages.
fn luneui_section(packages: &[&Package], texts: &mut Texts) -> Result<String> {
    let Some(ui) = packages
        .iter()
        .find(|p| p.name.as_str() == "lune-ui" && p.source.is_some())
    else {
        return Ok(String::new());
    };
    let root = find_above(package_dir(ui)?, LUNEUI_NOTICES).ok_or_else(|| {
        anyhow!("the lune-ui checkout holds no {LUNEUI_NOTICES}; its notices cannot be included")
    })?;
    let notices = normalize(&fs::read(root.join(LUNEUI_NOTICES))?);
    let mut out = String::new();
    out.push_str("== LuneUI ==\n\n");
    out.push_str(
        "The UI binary links LuneUI (the lune-ui packages above). LuneUI's own third-party notices follow,\n\
         verbatim, with the licence texts its repository keeps in `licenses/`; its Nerd Font and sample\n\
         files belong to its gallery application, which lunepack does not ship (the licence text of the\n\
         sample files is left out).\n\n",
    );
    out.push_str("--- LuneUI THIRD_PARTY_NOTICES.md ---\n");
    out.push_str(&notices);
    out.push('\n');
    let licenses = root.join("licenses");
    let mut names = Vec::new();
    if licenses.is_dir() {
        for entry in fs::read_dir(&licenses)? {
            let entry = entry?;
            if entry.path().is_file()
                && let Ok(name) = entry.file_name().into_string()
                && !LUNEUI_UNSHIPPED_LICENSES.contains(&name.as_str())
            {
                names.push(name);
            }
        }
    }
    names.sort();
    for name in names {
        let n = texts.add(normalize(&fs::read(licenses.join(&name))?));
        let _ = writeln!(out, "licenses/{name}: text {n}");
    }
    out.push('\n');
    Ok(out)
}

/// The bundled font's licence, when the configuration names one.
fn font_section(config: &Config<'_>, texts: &mut Texts) -> Result<String> {
    let Some(path) = &config.font_license else {
        return Ok(String::new());
    };
    let bytes = fs::read(path).context("cannot read the font licence")?;
    let n = texts.add(normalize(&bytes));
    Ok(format!(
        "== RznSans (font) ==\n\n\
         RznSans-Regular.ttf and RznSans-Medium.ttf (version 1.007) are compiled, unmodified, into the\n\
         lunepack-ui binary and are the only font its screens use. They are licensed under the SIL Open\n\
         Font License, Version 1.1; the copyright line, the Reserved Font Name `RznSans` and the full\n\
         licence are in text {n}. The fonts are not sold by themselves.\n\n"
    ))
}

// ---------------------------------------------------------------------------------------------
// The command

/// How the committed `committed` text differs from `fresh`: the first line that differs, or the
/// length. `None` when they are equal.
pub fn first_difference(committed: &str, fresh: &str) -> Option<String> {
    if committed == fresh {
        return None;
    }
    let short = |s: &str| {
        let mut t: String = s.chars().take(100).collect();
        if s.chars().count() > 100 {
            t.push_str("...");
        }
        t
    };
    let mut a = committed.split('\n');
    let mut b = fresh.split('\n');
    let mut line = 0usize;
    loop {
        line += 1;
        match (a.next(), b.next()) {
            (Some(x), Some(y)) if x == y => {}
            (Some(x), Some(y)) => {
                return Some(format!(
                    "line {line}: committed {:?}, generated {:?}",
                    short(x),
                    short(y)
                ));
            }
            (Some(_), None) => {
                return Some(format!("line {line}: the committed file has more lines"));
            }
            (None, Some(_)) => {
                return Some(format!("line {line}: the committed file ends early"));
            }
            (None, None) => return Some("the files differ".to_owned()),
        }
    }
}

/// Entry point for `xtask notices [--check]`: exit 0 written or equal, 1 the committed file is
/// stale, 2 an error (including a package that cannot be given a notice).
pub fn main(args: impl IntoIterator<Item = String>) -> ExitCode {
    let mut check = false;
    for arg in args {
        match arg.as_str() {
            "--check" => check = true,
            other => {
                eprintln!("notices: unknown argument `{other}`; usage: notices [--check]");
                return ExitCode::from(2);
            }
        }
    }
    match run(check) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("notices: error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run(check: bool) -> Result<ExitCode> {
    let root = std::env::current_dir()?;
    let config = Config::for_workspace(&root);
    let fresh = generate(&root, &config)?;
    let target = root.join(OUTPUT);
    if check {
        let committed = fs::read_to_string(&target).with_context(|| {
            format!("cannot read {OUTPUT}; run `cargo run -p xtask -- notices`")
        })?;
        return Ok(match first_difference(&committed, &fresh) {
            None => {
                println!("notices: ok ({OUTPUT} is current)");
                ExitCode::SUCCESS
            }
            Some(diff) => {
                println!(
                    "notices: {OUTPUT} is stale, {diff}; run `cargo run -p xtask -- notices` and commit the result"
                );
                ExitCode::from(1)
            }
        });
    }
    fs::write(&target, &fresh).with_context(|| format!("cannot write {OUTPUT}"))?;
    println!("notices: wrote {OUTPUT} ({} bytes)", fresh.len());
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(text: &str, allowed: &[&str]) -> Option<Vec<String>> {
        satisfy(&parse_expr(text).unwrap(), allowed)
    }

    #[test]
    fn or_takes_the_first_allowed_alternative_and_needs_both() {
        let allowed = ["MIT", "Apache-2.0", "ISC"];
        assert_eq!(ids("MIT OR Apache-2.0", &allowed), Some(vec!["MIT".into()]));
        assert_eq!(
            ids("GPL-3.0-only OR Apache-2.0", &allowed),
            Some(vec!["Apache-2.0".into()])
        );
        assert_eq!(
            ids("Apache-2.0 AND ISC", &allowed),
            Some(vec!["Apache-2.0".into(), "ISC".into()])
        );
        assert_eq!(ids("Apache-2.0 AND GPL-3.0-only", &allowed), None);
        assert_eq!(ids("GPL-3.0-only", &allowed), None);
    }

    #[test]
    fn precedence_parentheses_slash_and_with() {
        let allowed = ["MIT", "Apache-2.0", "Unicode-3.0"];
        // AND binds tighter than OR.
        assert_eq!(
            ids("GPL-2.0-only OR MIT AND Apache-2.0", &allowed),
            Some(vec!["MIT".into(), "Apache-2.0".into()])
        );
        assert_eq!(
            ids("(MIT OR Apache-2.0) AND Unicode-3.0", &allowed),
            Some(vec!["MIT".into(), "Unicode-3.0".into()])
        );
        assert_eq!(ids("MIT/Apache-2.0", &allowed), Some(vec!["MIT".into()]));
        assert_eq!(ids("Unlicense/MIT", &allowed), Some(vec!["MIT".into()]));
        assert_eq!(
            ids("Apache-2.0 WITH LLVM-exception OR MIT", &allowed),
            Some(vec!["Apache-2.0".into()])
        );
    }

    #[test]
    fn a_malformed_expression_is_an_error() {
        for bad in [
            "",
            "MIT OR",
            "OR MIT",
            "(MIT",
            "MIT)",
            "MIT AND AND ISC",
            "MIT WITH",
            "MI T!",
            "MIT ISC",
        ] {
            assert!(parse_expr(bad).is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn normalize_gives_lf_and_trims_blank_ends() {
        assert_eq!(
            normalize(b"\xef\xbb\xbf\r\n\r\nA  \r\nB\t\r\n\r\n"),
            "A\nB\n"
        );
        // Not UTF-8: read as Latin-1.
        assert_eq!(normalize(b"(c) \xa9 x"), "(c) \u{a9} x\n");
    }

    #[test]
    fn texts_are_stored_once_in_first_use_order() {
        let mut t = Texts::default();
        assert_eq!(t.add("a\n".into()), 1);
        assert_eq!(t.add("b\n".into()), 2);
        assert_eq!(t.add("a\n".into()), 1);
        assert_eq!(t.list, vec!["a\n", "b\n"]);
    }

    #[test]
    fn first_difference_names_the_line() {
        assert_eq!(first_difference("a\nb\n", "a\nb\n"), None);
        let d = first_difference("a\nb\nc\n", "a\nX\nc\n").unwrap();
        assert!(d.starts_with("line 2:"), "{d}");
        assert!(
            first_difference("a\n", "a\nb\n")
                .unwrap()
                .starts_with("line 2:")
        );
        assert!(
            first_difference("a\nb\n", "a\n")
                .unwrap()
                .starts_with("line 2:")
        );
    }
}
