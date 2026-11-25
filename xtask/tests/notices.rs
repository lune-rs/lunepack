//! Tests for `xtask notices`: the package set, the licence rules and the output's form, over a
//! small fixture workspace whose packages are given a registry source after `cargo metadata` (a
//! path dependency has none, and the real file names every package's source).

use std::fs;
use std::path::PathBuf;

use cargo_metadata::MetadataCommand;
use tempfile::TempDir;
use xtask::notices::{Config, first_difference, metadata_json, render};

const ALLOWED: &[&str] = &["MIT", "Apache-2.0", "Zlib"];

struct Fx {
    _tmp: TempDir,
    ws: PathBuf,
    deps: PathBuf,
    canonical: PathBuf,
}

impl Fx {
    /// A workspace `ws` with the binary `fixture-bin`, and the directory of its dependencies.
    fn new() -> Fx {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("ws");
        let deps = tmp.path().join("deps");
        let canonical = tmp.path().join("canonical");
        for d in [&ws, &deps, &canonical] {
            fs::create_dir_all(d).unwrap();
        }
        Fx {
            _tmp: tmp,
            ws,
            deps,
            canonical,
        }
    }

    /// A package `name` under `deps` with `license` (when given) and these files.
    fn dep(&self, name: &str, version: &str, license: Option<&str>, files: &[(&str, &[u8])]) {
        let dir = self.deps.join(name);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src/lib.rs"), "").unwrap();
        let license = license.map_or(String::new(), |l| format!("license = \"{l}\"\n"));
        fs::write(
            dir.join("Cargo.toml"),
            format!(
                "[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\nauthors = [\"A. Author\"]\n{license}"
            ),
        )
        .unwrap();
        for (file, bytes) in files {
            fs::write(dir.join(file), bytes).unwrap();
        }
    }

    /// The workspace: `fixture-bin` with the given `[dependencies]`-style lines, per table.
    fn workspace(&self, normal: &[&str], build: &[&str], dev: &[&str]) {
        let table = |names: &[&str]| {
            names
                .iter()
                .map(|n| format!("{n} = {{ path = \"../../deps/{n}\" }}\n"))
                .collect::<String>()
        };
        fs::write(
            self.ws.join("Cargo.toml"),
            "[workspace]\nmembers = [\"bin\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        fs::create_dir_all(self.ws.join("bin/src")).unwrap();
        fs::write(self.ws.join("bin/src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(
            self.ws.join("bin/Cargo.toml"),
            format!(
                "[package]\nname = \"fixture-bin\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n[dependencies]\n{}\n[build-dependencies]\n{}\n[dev-dependencies]\n{}",
                table(normal),
                table(build),
                table(dev)
            ),
        )
        .unwrap();
    }

    fn config(&self) -> Config<'static> {
        Config {
            roots: &["fixture-bin"],
            allowed: ALLOWED,
            canonical: self.canonical.clone(),
            font_license: None,
            locked: false,
        }
    }

    fn render(&self) -> anyhow::Result<String> {
        self.render_with(&self.config())
    }

    fn render_with(&self, config: &Config<'_>) -> anyhow::Result<String> {
        let mut json: serde_json::Value =
            serde_json::from_str(&metadata_json(&self.ws, false).unwrap()).unwrap();
        let members: Vec<String> = json["workspace_members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m.as_str().unwrap().to_owned())
            .collect();
        for p in json["packages"].as_array_mut().unwrap() {
            if !members.contains(&p["id"].as_str().unwrap().to_owned()) {
                p["source"] =
                    serde_json::json!("registry+https://github.com/rust-lang/crates.io-index");
            }
        }
        let md = MetadataCommand::parse(json.to_string()).unwrap();
        render(&md, config)
    }
}

const MIT_A: &[u8] = b"MIT License\n\nCopyright (c) A\n\nPermission is hereby granted.\n";

fn entries(out: &str) -> Vec<&str> {
    out.lines().filter_map(|l| l.strip_prefix("### ")).collect()
}

#[test]
fn lists_normal_and_build_dependencies_transitively_and_never_dev_or_members() {
    let fx = Fx::new();
    fx.dep("zeta", "1.0.0", Some("MIT"), &[("LICENSE", MIT_A)]);
    fx.dep(
        "alpha",
        "2.0.0",
        Some("MIT OR Apache-2.0"),
        &[("LICENSE-MIT", MIT_A)],
    );
    fx.dep("builder", "0.3.0", Some("MIT"), &[("LICENSE", MIT_A)]);
    fx.dep("devonly", "0.1.0", Some("GPL-3.0-only"), &[]);
    fx.workspace(&["zeta", "alpha"], &["builder"], &["devonly"]);
    // A dependency of a dependency: the transitive edge.
    let mid = fx.deps.join("zeta/Cargo.toml");
    fx.dep(
        "leaf",
        "0.0.9",
        Some("Zlib"),
        &[("COPYING", b"zlib text\n")],
    );
    let mut manifest = fs::read_to_string(&mid).unwrap();
    manifest.push_str("\n[dependencies]\nleaf = { path = \"../leaf\" }\n");
    fs::write(&mid, manifest).unwrap();

    let out = fx.render().unwrap();
    assert_eq!(
        entries(&out),
        ["alpha 2.0.0", "builder 0.3.0", "leaf 0.0.9", "zeta 1.0.0"]
    );
    assert!(out.contains("Packages: 4\n"));
    assert!(
        !out.contains("fixture-bin"),
        "a workspace member is not listed"
    );
}

#[test]
fn the_output_is_deterministic_and_has_no_path_and_no_carriage_return() {
    let fx = Fx::new();
    fx.dep(
        "one",
        "1.0.0",
        Some("MIT"),
        &[("LICENSE", b"MIT\r\n\r\nCopyright (c) A  \r\n")],
    );
    fx.workspace(&["one"], &[], &[]);
    let a = fx.render().unwrap();
    let b = fx.render().unwrap();
    assert_eq!(a, b);
    assert!(!a.contains('\r'));
    let root = fx.ws.parent().unwrap().to_string_lossy().into_owned();
    assert!(
        !a.contains(&root),
        "the output names a path of this machine"
    );
    assert!(a.ends_with('\n'));
}

#[test]
fn identical_texts_are_stored_once_and_referenced_by_number() {
    let fx = Fx::new();
    // The same text with another line end and trailing blanks is the same text.
    fx.dep("a", "1.0.0", Some("MIT"), &[("LICENSE", MIT_A)]);
    fx.dep(
        "b",
        "1.0.0",
        Some("MIT"),
        &[(
            "LICENSE-MIT",
            b"MIT License\r\n\r\nCopyright (c) A\r\n\r\nPermission is hereby granted.  \r\n\r\n",
        )],
    );
    fx.dep("c", "1.0.0", Some("MIT"), &[("LICENSE", b"Another text\n")]);
    fx.workspace(&["a", "b", "c"], &[], &[]);
    let out = fx.render().unwrap();
    assert_eq!(out.matches("\n--- text ").count(), 2, "{out}");
    assert!(out.contains("### a 1.0.0\nlicence: MIT\nsource: crates.io\ntext: LICENSE, text 1\n"));
    assert!(
        out.contains("### b 1.0.0\nlicence: MIT\nsource: crates.io\ntext: LICENSE-MIT, text 1\n")
    );
    assert!(out.contains("### c 1.0.0\nlicence: MIT\nsource: crates.io\ntext: LICENSE, text 2\n"));
}

#[test]
fn a_package_without_a_licence_expression_fails_and_is_named() {
    let fx = Fx::new();
    fx.dep("nolicence", "1.0.0", None, &[("LICENSE", MIT_A)]);
    fx.workspace(&["nolicence"], &[], &[]);
    let err = format!("{:#}", fx.render().unwrap_err());
    assert!(
        err.contains("nolicence 1.0.0") && err.contains("no licence expression"),
        "{err}"
    );
}

#[test]
fn an_expression_outside_the_allowlist_fails_but_an_allowed_alternative_passes() {
    let fx = Fx::new();
    fx.dep("gpl", "1.0.0", Some("GPL-3.0-only"), &[("LICENSE", MIT_A)]);
    fx.dep(
        "both",
        "1.0.0",
        Some("MIT AND GPL-3.0-only"),
        &[("LICENSE", MIT_A)],
    );
    fx.dep(
        "either",
        "1.0.0",
        Some("GPL-3.0-only OR MIT"),
        &[("LICENSE", MIT_A)],
    );
    fx.workspace(&["gpl", "both", "either"], &[], &[]);
    let err = format!("{:#}", fx.render().unwrap_err());
    assert!(err.contains("2 package(s)"), "{err}");
    assert!(
        err.contains("gpl 1.0.0") && err.contains("both 1.0.0"),
        "{err}"
    );
    assert!(!err.contains("either 1.0.0"), "{err}");
}

#[test]
fn a_malformed_expression_fails() {
    let fx = Fx::new();
    fx.dep("bad", "1.0.0", Some("MIT OR"), &[("LICENSE", MIT_A)]);
    fx.workspace(&["bad"], &[], &[]);
    let err = format!("{:#}", fx.render().unwrap_err());
    assert!(err.contains("bad 1.0.0"), "{err}");
}

#[test]
fn a_package_without_a_text_gets_the_canonical_one_or_fails() {
    let fx = Fx::new();
    fx.dep(
        "bare",
        "1.0.0",
        Some("MIT OR Apache-2.0"),
        &[("README.md", b"x")],
    );
    fx.workspace(&["bare"], &[], &[]);
    let err = format!("{:#}", fx.render().unwrap_err());
    assert!(
        err.contains("bare 1.0.0") && err.contains("MIT.txt"),
        "{err}"
    );

    fs::write(fx.canonical.join("MIT.txt"), "Canonical MIT <holders>\n").unwrap();
    let out = fx.render().unwrap();
    assert!(
        out.contains("### bare 1.0.0\nlicence: MIT OR Apache-2.0\nsource: crates.io\nauthors: A. Author\ntext: canonical MIT, text 1\n"),
        "{out}"
    );
    assert!(out.contains("--- text 1 ---\nCanonical MIT <holders>\n"));
}

#[test]
fn a_file_that_only_looks_like_a_licence_is_not_one() {
    let fx = Fx::new();
    fx.dep(
        "code",
        "1.0.0",
        Some("MIT"),
        &[("license.rs", b"fn x() {}")],
    );
    fx.workspace(&["code"], &[], &[]);
    // No text but the canonical one, which does not exist: the .rs file is not taken for it.
    assert!(fx.render().is_err());
}

#[test]
fn a_root_the_workspace_does_not_have_fails() {
    let fx = Fx::new();
    fx.workspace(&[], &[], &[]);
    let config = Config {
        roots: &["no-such-binary"],
        ..fx.config()
    };
    let err = format!("{:#}", fx.render_with(&config).unwrap_err());
    assert!(err.contains("no-such-binary"), "{err}");
}

#[test]
fn check_names_the_first_differing_line() {
    let a = "one\ntwo\nthree\n";
    assert_eq!(first_difference(a, a), None);
    let d = first_difference(a, "one\ntwO\nthree\n").unwrap();
    assert!(d.starts_with("line 2:"), "{d}");
}
