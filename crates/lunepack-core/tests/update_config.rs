//! The update-config document (FORMAT.md 13, M5 step 1): the writer's golden in `docs/FORMAT.md`,
//! round trips, every validator's boundaries, evolution, the core feed rule's corpus, the desktop
//! path rule and the fuzz seed replay.
//!
//! Every fixture is the real writer's output (the testkit's sample config), edited through its JSON
//! value where a correct writer could not produce it.

use std::path::Path;

use lunepack_core::error::JsonError;
use lunepack_core::update_config::{
    DENIED_URL_SCHEMES, MACOS_CODE_SIGNATURE_DIR, MACOS_ENTRY_DIR, MACOS_HELPER_APP,
    MACOS_HELPER_ICON, MACOS_HELPER_INFO_PLIST, MACOS_HELPER_UI, MACOS_INFO_PLIST,
    MACOS_INSTALLER_PAYLOAD, MAX_UPDATE_CONFIG_BYTES, RUNTIME_FILE, RUNTIME_FILE_WINDOWS, UI_FILE,
    UPDATE_CONFIG_PATH_MACOS, config_path, runtime_file,
};
use lunepack_core::{
    AppId, DesktopPathError, FeedKind, FeedRule, FileType, Target, TrustedRoot, UPDATE_CONFIG_FILE,
    UpdateConfig, UpdateConfigError, check_feed, desktop_safe_path,
};
use lunepack_testkit::{FakeHasher, FakeKeyPair, FakeVerifier, fuzz_seeds, sample_update_config};
use serde_json::{Map, Value, json};

fn sample() -> UpdateConfig {
    sample_update_config()
}

fn value_of(config: &UpdateConfig) -> Map<String, Value> {
    serde_json::from_slice(&config.to_bytes().unwrap()).unwrap()
}

/// The sample's written bytes with `edit` applied to their JSON value.
fn edited(edit: impl FnOnce(&mut Map<String, Value>)) -> Vec<u8> {
    let mut map = value_of(&sample());
    edit(&mut map);
    serde_json::to_vec(&map).unwrap()
}

fn with_install(key: &str, value: Value) -> Vec<u8> {
    edited(|m| {
        m["install"]
            .as_object_mut()
            .unwrap()
            .insert(key.to_owned(), value);
    })
}

fn with_root(key: &str, value: Value) -> Vec<u8> {
    edited(|m| {
        m["root"]
            .as_object_mut()
            .unwrap()
            .insert(key.to_owned(), value);
    })
}

fn with_top(key: &str, value: Value) -> Vec<u8> {
    edited(|m| {
        m.insert(key.to_owned(), value);
    })
}

fn parse(bytes: &[u8]) -> Result<UpdateConfig, UpdateConfigError> {
    UpdateConfig::parse(bytes)
}

#[track_caller]
fn invalid_field(bytes: &[u8]) -> &'static str {
    match parse(bytes) {
        Err(UpdateConfigError::Invalid { field, .. }) => field,
        other => panic!("expected an invalid field, got {other:?}"),
    }
}

// ---- location ------------------------------------------------------------------------------------

#[test]
fn the_location_is_fixed() {
    assert_eq!(UPDATE_CONFIG_FILE, "lunepack-update.json");
    assert_eq!(config_path(Target::LinuxX86_64), "lunepack-update.json");
    assert_eq!(config_path(Target::WindowsAarch64), "lunepack-update.json");
    assert_eq!(
        config_path(Target::MacosUniversal),
        UPDATE_CONFIG_PATH_MACOS
    );
    assert_eq!(runtime_file(Target::LinuxAarch64), RUNTIME_FILE);
    assert_eq!(runtime_file(Target::WindowsX86_64), RUNTIME_FILE_WINDOWS);
    assert_eq!(runtime_file(Target::MacosX86_64), "lunepack-runtime");
}

#[test]
fn the_macos_bundle_paths_agree_with_each_other() {
    assert_eq!(
        MACOS_HELPER_UI,
        format!("{MACOS_HELPER_APP}/Contents/MacOS/{UI_FILE}")
    );
    assert_eq!(
        MACOS_HELPER_INFO_PLIST,
        format!("{MACOS_HELPER_APP}/Contents/Info.plist")
    );
    assert!(MACOS_HELPER_ICON.starts_with(&format!("{MACOS_HELPER_APP}/Contents/Resources/")));
    assert!(MACOS_INFO_PLIST.starts_with("Contents/") && MACOS_ENTRY_DIR.starts_with("Contents/"));
    assert!(UPDATE_CONFIG_PATH_MACOS.starts_with("Contents/Resources/"));
    assert!(MACOS_INSTALLER_PAYLOAD.starts_with("Contents/Resources/"));
    assert_eq!(MACOS_CODE_SIGNATURE_DIR, "Contents/_CodeSignature");
    assert!(Target::MacosAarch64.is_macos() && Target::MacosUniversal.is_macos());
    assert!(!Target::LinuxX86_64.is_macos() && !Target::WindowsX86_64.is_macos());
}

// ---- writer and reader -----------------------------------------------------------------------------

#[test]
fn a_written_config_reads_back_equal() {
    let config = sample();
    let bytes = config.to_bytes().unwrap();
    let read = parse(&bytes).unwrap();
    assert_eq!(read, config);
    assert_eq!(read.to_bytes().unwrap(), bytes, "the writer is canonical");
    assert!(bytes.ends_with(b"}\n"));
}

#[test]
fn members_are_written_in_byte_order() {
    let text = String::from_utf8(sample().to_bytes().unwrap()).unwrap();
    let top: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("  \"") && !l.starts_with("   "))
        .map(|l| l.trim_start().split('"').nth(1).unwrap())
        .collect();
    let mut want = top.clone();
    want.sort_unstable();
    assert_eq!(top, want);
    assert_eq!(top.len(), 11);
}

#[test]
fn new_takes_the_roots_parts_and_adds_the_trailing_slash() {
    let keys = [FakeKeyPair::from_seed(1).public_key()];
    let root = TrustedRoot::from_parts(
        AppId::parse("org.example.hello").unwrap(),
        1,
        1,
        &keys,
        &FakeHasher,
        &FakeVerifier,
    )
    .unwrap();
    let s = sample();
    let config = UpdateConfig::new(
        &root,
        s.version.clone(),
        s.target,
        "https://updates.example.org/hello",
        s.channel.clone(),
        60,
        s.install.clone(),
    )
    .unwrap();
    assert_eq!(config.feed, "https://updates.example.org/hello/");
    assert_eq!(config.root.version, 1);
    config.check_root(&root).unwrap();
    assert!(matches!(
        sample().check_root(&root),
        Err(UpdateConfigError::RootMismatch("root"))
    ));
    let mut other = config.clone();
    other.app_id = AppId::parse("org.example.other").unwrap();
    assert!(matches!(
        other.check_root(&root),
        Err(UpdateConfigError::RootMismatch("app_id"))
    ));
    // A bad member fails at construction, with the reader's error.
    let bad = UpdateConfig::new(
        &root,
        s.version,
        s.target,
        "http://10.0.0.1/",
        s.channel,
        60,
        s.install,
    );
    assert!(matches!(
        bad,
        Err(UpdateConfigError::Feed(FeedRule::HttpNotLoopback))
    ));
}

#[test]
fn the_writer_refuses_what_the_reader_refuses() {
    let mut c = sample();
    c.install.name = "Hello\nExec=evil".to_owned();
    assert!(matches!(
        c.to_bytes(),
        Err(UpdateConfigError::Invalid {
            field: "install.name",
            ..
        })
    ));
    let mut c = sample();
    c.health_timeout_secs = 4;
    assert!(c.to_bytes().is_err());
    let mut c = sample();
    c.extra.insert("feed".to_owned(), json!("x"));
    assert!(matches!(
        c.to_bytes(),
        Err(UpdateConfigError::Invalid { field: "extra", .. })
    ));
}

// ---- evolution -------------------------------------------------------------------------------------

#[test]
fn an_unknown_top_level_member_is_kept_and_ignored() {
    let bytes = with_top("x_future", json!({"b": 1, "a": [true]}));
    let read = parse(&bytes).unwrap();
    assert_eq!(
        read.extra.get("x_future"),
        Some(&json!({"a": [true], "b": 1}))
    );
    let mut plain = read.clone();
    plain.extra.clear();
    assert_eq!(
        plain,
        sample(),
        "ignored: everything else reads as without it"
    );
    let rewritten = parse(&read.to_bytes().unwrap()).unwrap();
    assert_eq!(rewritten, read, "kept: the writer writes it back");
}

#[test]
fn an_unknown_member_inside_root_or_install_is_refused() {
    assert!(matches!(
        parse(&with_install("x_future", json!(1))),
        Err(UpdateConfigError::Unknown("install"))
    ));
    assert!(matches!(
        parse(&with_root("x_future", json!(1))),
        Err(UpdateConfigError::Unknown("root"))
    ));
}

#[test]
fn a_critical_name_or_a_newer_format_is_newer_format() {
    assert!(matches!(
        parse(&with_top("critical", json!(["x-future"]))),
        Err(UpdateConfigError::NewerFormat)
    ));
    assert!(matches!(
        parse(&with_top("format", json!(2))),
        Err(UpdateConfigError::NewerFormat)
    ));
    assert_eq!(invalid_field(&with_top("format", json!(0))), "format");
    assert!(matches!(
        parse(&with_top("critical", json!([1]))),
        Err(UpdateConfigError::WrongType("critical"))
    ));
    assert_eq!(
        invalid_field(&with_top("kind", json!("install-state"))),
        "kind"
    );
}

#[test]
fn every_member_is_required() {
    for key in [
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
    ] {
        let bytes = edited(|m| {
            m.remove(key);
        });
        assert!(
            matches!(parse(&bytes), Err(UpdateConfigError::Missing(f)) if f == key),
            "{key}"
        );
    }
    for key in [
        "bin",
        "categories",
        "comment",
        "entry",
        "icon",
        "name",
        "terminal",
    ] {
        let bytes = edited(|m| {
            m["install"].as_object_mut().unwrap().remove(key);
        });
        assert!(
            matches!(parse(&bytes), Err(UpdateConfigError::Missing(f)) if f.ends_with(key)),
            "install.{key}"
        );
    }
}

#[test]
fn strict_json_is_enforced() {
    let mut dup = sample().to_bytes().unwrap();
    let end = dup.iter().rposition(|&b| b == b'}').unwrap();
    dup.splice(end..end, b",\"kind\":\"update-config\"".iter().copied());
    assert!(matches!(
        parse(&dup),
        Err(UpdateConfigError::Json(JsonError::DuplicateKey(_)))
    ));
    let text = String::from_utf8(sample().to_bytes().unwrap()).unwrap();
    let inner = text.replacen(
        "\"terminal\": false",
        "\"terminal\": false, \"name\": \"B\"",
        1,
    );
    assert!(matches!(
        parse(inner.as_bytes()),
        Err(UpdateConfigError::Json(JsonError::DuplicateKey(_)))
    ));
    let mut bom = vec![0xEF, 0xBB, 0xBF];
    bom.extend(sample().to_bytes().unwrap());
    assert!(matches!(parse(&bom), Err(UpdateConfigError::Json(_))));
    assert!(matches!(parse(b"[]"), Err(UpdateConfigError::Json(_))));
}

#[test]
fn the_size_cap_is_64_kib() {
    let pad = |n: usize| with_top("x_pad", json!("a".repeat(n)));
    let base = pad(0).len();
    let at_cap = pad(MAX_UPDATE_CONFIG_BYTES as usize - base);
    assert_eq!(at_cap.len() as u64, MAX_UPDATE_CONFIG_BYTES);
    parse(&at_cap).unwrap();
    let over = pad(MAX_UPDATE_CONFIG_BYTES as usize - base + 1);
    assert!(matches!(
        parse(&over),
        Err(UpdateConfigError::TooLarge { .. })
    ));
}

// ---- validators ------------------------------------------------------------------------------------

#[test]
fn name_and_comment_boundaries() {
    parse(&with_install("name", json!("é".repeat(128)))).unwrap();
    assert_eq!(
        invalid_field(&with_install("name", json!("é".repeat(129)))),
        "install.name"
    );
    assert_eq!(
        invalid_field(&with_install("name", json!(""))),
        "install.name"
    );
    for bad in [
        "Hel\\lo",
        "Hel\nlo",
        "Hel\u{85}lo",
        "Hel\u{7f}lo",
        "Hel\u{1}lo",
        "Hel\u{2028}lo",
        "Hel\u{2029}lo",
        " Hello",
        "Hello ",
        "Hello\u{3000}",
        "\tHello",
    ] {
        assert_eq!(
            invalid_field(&with_install("name", json!(bad))),
            "install.name",
            "{bad:?}"
        );
        assert_eq!(
            invalid_field(&with_install("comment", json!(bad))),
            "install.comment",
            "{bad:?}"
        );
    }
    parse(&with_install("name", json!("Hello, World; = [x]"))).unwrap();
    parse(&with_install("comment", json!(""))).unwrap();
    parse(&with_install("comment", json!(null))).unwrap();
    parse(&with_install("comment", json!("x".repeat(512)))).unwrap();
    assert_eq!(
        invalid_field(&with_install("comment", json!("x".repeat(513)))),
        "install.comment"
    );
    assert!(matches!(
        parse(&with_install("name", json!(null))),
        Err(UpdateConfigError::WrongType("install.name"))
    ));
}

#[test]
fn publisher_is_optional_and_absent_stays_absent() {
    // An M5-shaped document (no `publisher` member) still parses, to `None`.
    let m5 = sample().to_bytes().unwrap();
    assert!(!String::from_utf8_lossy(&m5).contains("publisher"));
    let read = parse(&m5).unwrap();
    assert_eq!(read.install.publisher, None);
    // None is left out of the written bytes, never written as null: the bytes are unchanged.
    assert_eq!(read.to_bytes().unwrap(), m5);

    let mut with = sample();
    with.install.publisher = Some("Acme, Inc.".to_owned());
    let bytes = with.to_bytes().unwrap();
    assert_ne!(bytes, m5);
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(text.contains("\"publisher\": \"Acme, Inc.\""), "{text}");
    let back = parse(&bytes).unwrap();
    assert_eq!(back, with);
    assert_eq!(
        back.to_bytes().unwrap(),
        bytes,
        "canonical bytes round-trip"
    );
    // Members stay in byte order: `name` < `publisher` < `terminal`.
    let (n, p, t) = (
        text.find("\"name\"").unwrap(),
        text.find("\"publisher\"").unwrap(),
        text.find("\"terminal\"").unwrap(),
    );
    assert!(n < p && p < t);
}

#[test]
fn publisher_boundaries() {
    parse(&with_install("publisher", json!("é".repeat(128)))).unwrap();
    parse(&with_install("publisher", json!("P"))).unwrap();
    for bad in [
        "".to_owned(),
        "é".repeat(129),
        "Ac\\me".to_owned(),
        "Ac\nme".to_owned(),
        "Ac\u{85}me".to_owned(),
        "Ac\u{7f}me".to_owned(),
        "Ac\u{2028}me".to_owned(),
        " Acme".to_owned(),
        "Acme ".to_owned(),
    ] {
        assert_eq!(
            invalid_field(&with_install("publisher", json!(bad))),
            "install.publisher",
            "{bad:?}"
        );
    }
    // A written `null` is not the absent form: the writer never writes it.
    assert!(matches!(
        parse(&with_install("publisher", json!(null))),
        Err(UpdateConfigError::WrongType("install.publisher"))
    ));
    assert!(matches!(
        parse(&with_install("publisher", json!(7))),
        Err(UpdateConfigError::WrongType("install.publisher"))
    ));
}

#[test]
fn the_writer_refuses_a_bad_publisher() {
    let mut c = sample();
    c.install.publisher = Some("Ac\nme".to_owned());
    assert!(c.to_bytes().is_err());
}

fn ft(ext: &str, mime: &str, name: &str) -> Value {
    json!({"ext": ext, "mime": mime, "name": name})
}

#[test]
fn the_declaration_members_are_optional_and_absent_stays_absent() {
    // The sample (M5/M6 shape) holds none of them, and still parses, to the empty values.
    let plain = sample().to_bytes().unwrap();
    let text = String::from_utf8_lossy(&plain).into_owned();
    for key in ["file_types", "url_schemes", "autostart"] {
        assert!(!text.contains(key), "{key}");
    }
    let read = parse(&plain).unwrap();
    assert!(read.install.file_types.is_empty());
    assert!(read.install.url_schemes.is_empty());
    assert!(!read.install.autostart);
    // Empty and false are left out of the written bytes, never written: the bytes are unchanged.
    assert_eq!(read.to_bytes().unwrap(), plain);
    // A reader accepts the explicit empty forms and the writer drops them again.
    let explicit = edited(|m| {
        let install = m["install"].as_object_mut().unwrap();
        install.insert("file_types".to_owned(), json!([]));
        install.insert("url_schemes".to_owned(), json!([]));
        install.insert("autostart".to_owned(), json!(false));
    });
    assert_eq!(parse(&explicit).unwrap().to_bytes().unwrap(), plain);
}

#[test]
fn the_declaration_members_round_trip_in_byte_order() {
    let mut with = sample();
    with.install.file_types = vec![
        FileType {
            ext: "ex".to_owned(),
            mime: "application/x-example".to_owned(),
            name: "Example file".to_owned(),
        },
        FileType {
            ext: "png".to_owned(),
            mime: "image/png".to_owned(),
            name: "PNG image".to_owned(),
        },
    ];
    with.install.url_schemes = vec!["example".to_owned(), "ex+tra.v-2".to_owned()];
    with.install.autostart = true;
    let bytes = with.to_bytes().unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    let back = parse(&bytes).unwrap();
    assert_eq!(back, with);
    assert_eq!(
        back.to_bytes().unwrap(),
        bytes,
        "canonical bytes round-trip"
    );
    // `autostart` < `bin` ... `entry` < `file_types` < `icon` ... `terminal` < `url_schemes`.
    let at = |key: &str| text.find(&format!("\"{key}\"")).unwrap();
    assert!(at("autostart") < at("bin"));
    assert!(at("entry") < at("file_types") && at("file_types") < at("icon"));
    assert!(at("terminal") < at("url_schemes"));
    // Each file type's members are in byte order, and the declaration order is kept.
    assert!(text.find("\"ext\"").unwrap() < text.find("\"mime\"").unwrap());
    assert!(text.find("application/x-example").unwrap() < text.find("image/png").unwrap());
}

#[test]
fn file_type_rules() {
    let ok = |types: Vec<Value>| parse(&with_install("file_types", Value::Array(types))).unwrap();
    ok(vec![ft("a", "a/b", "N")]);
    ok(vec![ft(&"z9".repeat(8), "text/plain", &"é".repeat(128))]);
    ok(vec![ft(
        "ex",
        &format!("{0}/{0}", "A0!#$&^_.+-".repeat(11) + "a"),
        "n",
    )]);
    let types32: Vec<Value> = (0..32).map(|i| ft(&format!("e{i}"), "a/b", "n")).collect();
    assert_eq!(ok(types32.clone()).install.file_types.len(), 32);
    let mut types33 = types32;
    types33.push(ft("e32", "a/b", "n"));
    assert_eq!(
        invalid_field(&with_install("file_types", Value::Array(types33))),
        "install.file_types"
    );
    for bad in [
        ft("", "a/b", "n"),
        ft("EX", "a/b", "n"),
        ft(".ex", "a/b", "n"),
        ft("e x", "a/b", "n"),
        ft("é", "a/b", "n"),
        ft(&"e".repeat(17), "a/b", "n"),
        ft("ex", "ab", "n"),
        ft("ex", "a/", "n"),
        ft("ex", "/b", "n"),
        ft("ex", "a/b/c", "n"),
        ft("ex", "a/b;c/d", "n"),
        ft("ex", "a/b; charset=x", "n"),
        ft("ex", "a /b", "n"),
        ft("ex", "a/b\n", "n"),
        ft("ex", "a/é", "n"),
        ft("ex", "a/b,c", "n"),
        ft("ex", &format!("{}/b", "a".repeat(128)), "n"),
        ft("ex", &format!("a/{}", "b".repeat(128)), "n"),
        ft("ex", "a/b", ""),
        ft("ex", "a/b", &"é".repeat(129)),
        ft("ex", "a/b", " n"),
        ft("ex", "a/b", "n\nExec=x"),
        ft("ex", "a/b", "n\\"),
    ] {
        assert_eq!(
            invalid_field(&with_install("file_types", json!([bad.clone()]))),
            "install.file_types",
            "{bad}"
        );
    }
    // The same extension twice, with different mime types.
    assert_eq!(
        invalid_field(&with_install(
            "file_types",
            json!([ft("ex", "a/b", "n"), ft("ex", "c/d", "n")])
        )),
        "install.file_types"
    );
    // The same mime type under two extensions is fine (`jpg` and `jpeg`).
    ok(vec![
        ft("jpg", "image/jpeg", "n"),
        ft("jpeg", "image/jpeg", "n"),
    ]);
    // Shapes: not an array, an item that is not an object, a missing, unknown or mistyped member.
    assert!(matches!(
        parse(&with_install("file_types", json!("x"))),
        Err(UpdateConfigError::WrongType("install.file_types"))
    ));
    assert!(matches!(
        parse(&with_install("file_types", json!(null))),
        Err(UpdateConfigError::WrongType("install.file_types"))
    ));
    assert!(matches!(
        parse(&with_install("file_types", json!(["ex"]))),
        Err(UpdateConfigError::WrongType("install.file_types"))
    ));
    assert!(matches!(
        parse(&with_install(
            "file_types",
            json!([{"ext": "ex", "mime": "a/b"}])
        )),
        Err(UpdateConfigError::Missing("install.file_types.name"))
    ));
    assert!(matches!(
        parse(&with_install(
            "file_types",
            json!([{"ext": "ex", "mime": "a/b", "name": "n", "icon": "x"}])
        )),
        Err(UpdateConfigError::Unknown("install.file_types"))
    ));
    assert!(matches!(
        parse(&with_install(
            "file_types",
            json!([{"ext": 1, "mime": "a/b", "name": "n"}])
        )),
        Err(UpdateConfigError::WrongType("install.file_types"))
    ));
}

#[test]
fn url_scheme_rules() {
    let read = |schemes: Vec<String>| parse(&with_install("url_schemes", json!(schemes)));
    for ok in ["a", "example", "x-1.2+3", &format!("a{}", "b".repeat(31))] {
        read(vec![ok.to_owned()]).unwrap();
    }
    let eight: Vec<String> = (0..8).map(|i| format!("app{i}")).collect();
    assert_eq!(read(eight.clone()).unwrap().install.url_schemes.len(), 8);
    let mut nine = eight;
    nine.push("app8".to_owned());
    assert!(matches!(
        read(nine),
        Err(UpdateConfigError::Invalid {
            field: "install.url_schemes",
            ..
        })
    ));
    for bad in [
        "",
        "1app",
        "-app",
        "+app",
        "App",
        "a_b",
        "a b",
        "a:b",
        "a/b",
        "a;b",
        "é",
        &format!("a{}", "b".repeat(32)),
    ] {
        assert!(
            matches!(
                read(vec![bad.to_owned()]),
                Err(UpdateConfigError::Invalid {
                    field: "install.url_schemes",
                    ..
                })
            ),
            "{bad:?}"
        );
    }
    assert!(matches!(
        read(vec!["app".to_owned(), "app".to_owned()]),
        Err(UpdateConfigError::Invalid {
            field: "install.url_schemes",
            ..
        })
    ));
    // The deny-list, every entry, in either case, and the `ms-` prefix.
    let mut denied: Vec<String> = DENIED_URL_SCHEMES.iter().map(|s| (*s).to_owned()).collect();
    denied.extend(["ms-settings", "ms-", "ms-x"].map(str::to_owned));
    for scheme in denied {
        for text in [scheme.clone(), scheme.to_ascii_uppercase()] {
            assert!(
                matches!(
                    read(vec![text.clone()]),
                    Err(UpdateConfigError::Invalid {
                        field: "install.url_schemes",
                        ..
                    })
                ),
                "{text}"
            );
        }
    }
    assert!(lunepack_core::update_config::is_denied_url_scheme(
        "MS-Settings"
    ));
    assert!(!lunepack_core::update_config::is_denied_url_scheme("mss-x"));
    // The well-known ones the plan names.
    for name in [
        "http",
        "https",
        "file",
        "ftp",
        "mailto",
        "data",
        "javascript",
        "about",
    ] {
        assert!(DENIED_URL_SCHEMES.contains(&name), "{name}");
    }
    assert!(matches!(
        parse(&with_install("url_schemes", json!("x"))),
        Err(UpdateConfigError::WrongType("install.url_schemes"))
    ));
    assert!(matches!(
        parse(&with_install("url_schemes", json!([1]))),
        Err(UpdateConfigError::WrongType("install.url_schemes"))
    ));
}

#[test]
fn autostart_must_be_a_boolean() {
    assert!(
        parse(&with_install("autostart", json!(true)))
            .unwrap()
            .install
            .autostart
    );
    for bad in [json!(null), json!(1), json!("true")] {
        assert!(matches!(
            parse(&with_install("autostart", bad)),
            Err(UpdateConfigError::WrongType("install.autostart"))
        ));
    }
}

#[test]
fn the_writer_refuses_bad_declarations() {
    let bad_type = FileType {
        ext: "EX".to_owned(),
        mime: "a/b".to_owned(),
        name: "n".to_owned(),
    };
    let mut c = sample();
    c.install.file_types = vec![bad_type];
    assert!(c.to_bytes().is_err());
    let mut c = sample();
    c.install.url_schemes = vec!["https".to_owned()];
    assert!(c.to_bytes().is_err());
}

#[test]
fn category_boundaries() {
    let cats = |v: Vec<String>| with_install("categories", json!(v));
    parse(&cats(vec![])).unwrap();
    parse(&cats((0..16).map(|i| format!("C{i}")).collect())).unwrap();
    assert_eq!(
        invalid_field(&cats((0..17).map(|i| format!("C{i}")).collect())),
        "install.categories"
    );
    parse(&cats(vec!["X-My-App".to_owned(), "a".repeat(64)])).unwrap();
    for bad in [
        "",
        "Has Space",
        "Semi;colon",
        "Dot.ted",
        "Ünï",
        &"a".repeat(65),
    ] {
        assert_eq!(
            invalid_field(&cats(vec![bad.to_owned()])),
            "install.categories",
            "{bad:?}"
        );
    }
    assert_eq!(
        invalid_field(&cats(vec!["Utility".to_owned(), "Utility".to_owned()])),
        "install.categories"
    );
}

#[test]
fn bin_boundaries() {
    for ok in ["hello", "Hello_2.0", "_x", "a-b", &"b".repeat(64)] {
        parse(&with_install("bin", json!(ok))).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    parse(&with_install("bin", json!(null))).unwrap();
    for bad in ["", "-x", ".x", "a/b", "a b", "ä", &"b".repeat(65)] {
        assert_eq!(
            invalid_field(&with_install("bin", json!(bad))),
            "install.bin",
            "{bad:?}"
        );
    }
}

#[test]
fn entry_and_icon_rules() {
    for ok in [
        "app",
        "bin/app",
        "a/b/c/app",
        "Hello.app/Contents/MacOS/hello",
    ] {
        parse(&with_install("entry", json!(ok))).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    let deep = vec!["d"; 32].join("/");
    parse(&with_install("entry", json!(deep))).unwrap();
    let too_deep = vec!["d"; 33].join("/");
    for bad in [
        too_deep.as_str(),
        "../app",
        "/abs",
        "bin\\app",
        "bin/lunepack-runtime",
        "lunepack-runtime",
        "bin/LUNEPACK-RUNTIME",
        "lunepack-runtime.exe",
        "lunepack-ui",
        "bin/LUNEPACK-UI",
        "lunepack-ui.exe",
        "bin/Lunepack-UI.EXE",
        "lunepack-update.json/app",
        "bin/Lunepack-Update.JSON",
    ] {
        assert_eq!(
            invalid_field(&with_install("entry", json!(bad))),
            "install.entry",
            "{bad:?}"
        );
    }
    parse(&with_install("icon", json!("share/icons/app.svg"))).unwrap();
    parse(&with_install("icon", json!("app.PNG"))).unwrap();
    parse(&with_install("icon", json!(null))).unwrap();
    for bad in ["app.ico", "app", "../app.png", "lunepack-update.json/x.png"] {
        assert_eq!(
            invalid_field(&with_install("icon", json!(bad))),
            "install.icon",
            "{bad:?}"
        );
    }
    assert!(matches!(
        parse(&with_install("terminal", json!("no"))),
        Err(UpdateConfigError::WrongType("install.terminal"))
    ));
}

#[test]
fn root_rules() {
    let key = |b: u8| format!("{b:02x}").repeat(32);
    parse(&with_root("keys", json!([key(1)]))).unwrap();
    parse(&with_root(
        "keys",
        json!((0..16).map(key).collect::<Vec<_>>()),
    ))
    .unwrap();
    assert_eq!(
        invalid_field(&with_root(
            "keys",
            json!((0..17).map(key).collect::<Vec<_>>())
        )),
        "root.keys"
    );
    assert_eq!(invalid_field(&with_root("keys", json!([]))), "root.keys");
    assert_eq!(
        invalid_field(&with_root("keys", json!([key(1), key(1)]))),
        "root.keys"
    );
    assert_eq!(
        invalid_field(&with_root("keys", json!([key(0xab).to_uppercase()]))),
        "root.keys"
    );
    assert_eq!(
        invalid_field(&with_root("keys", json!([key(1)[..62].to_owned()]))),
        "root.keys"
    );
    assert_eq!(
        invalid_field(&with_root("threshold", json!(0))),
        "root.threshold"
    );
    assert_eq!(
        invalid_field(&with_root("threshold", json!(3))),
        "root.threshold"
    );
    parse(&with_root("threshold", json!(2))).unwrap();
    assert_eq!(
        invalid_field(&with_root("version", json!(0))),
        "root.version"
    );
    assert_eq!(
        invalid_field(&with_root("version", json!(1u64 << 53))),
        "root.version"
    );
    assert!(matches!(
        parse(&with_root("version", json!(1.5))),
        Err(UpdateConfigError::WrongType("root.version"))
    ));
}

#[test]
fn top_level_rules() {
    for (key, bad) in [
        ("app_id", json!("Not An Id")),
        ("version", json!("v1.0")),
        ("target", json!("linux-arm64")),
        ("channel", json!("Stable Channel")),
    ] {
        assert_eq!(invalid_field(&with_top(key, bad)), key);
    }
    for (secs, ok) in [(4, false), (5, true), (3600, true), (3601, false)] {
        let result = parse(&with_top("health_timeout_secs", json!(secs)));
        assert_eq!(result.is_ok(), ok, "{secs}");
    }
}

#[test]
fn errors_never_echo_the_value() {
    let marker = "SECRETMARKER";
    let cases = [
        with_install("name", json!(format!("{marker}\n"))),
        with_install("publisher", json!(format!("{marker}\n"))),
        with_install("entry", json!(format!("../{marker}"))),
        with_install("bin", json!(format!("-{marker}"))),
        with_install("categories", json!([format!("{marker};")])),
        with_install("file_types", json!([ft(&format!("{marker};"), "a/b", "n")])),
        with_install(
            "file_types",
            json!([ft("ex", &format!("{marker};x/y"), "n")]),
        ),
        with_install(
            "file_types",
            json!([ft("ex", "a/b", &format!("{marker}\n"))]),
        ),
        with_install(
            "file_types",
            json!([{"ext": "ex", "mime": "a/b", "name": "n", marker: 1}]),
        ),
        with_install("url_schemes", json!([format!("{marker};")])),
        with_install("url_schemes", json!([format!("ms-{marker}")])),
        with_install(marker, json!(1)),
        with_top("feed", json!(format!("http://{marker}.example/"))),
        with_top("app_id", json!(format!("{marker} x"))),
        with_top("version", json!(marker)),
        with_top("target", json!(marker)),
        with_top("critical", json!([marker])),
        with_root("keys", json!([marker])),
    ];
    for bytes in cases {
        let err = parse(&bytes).unwrap_err();
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains(marker), "{shown}");
    }
}

// ---- the feed rule (core) --------------------------------------------------------------------------

/// Accepted by both the core and the facade, with these kinds (step 1 contract).
pub const ACCEPTED: [(&str, FeedKind); 7] = [
    ("https://updates.example.com/app/", FeedKind::Https),
    ("https://203.0.113.5:8443/r/", FeedKind::Https),
    ("http://127.0.0.1:8080/r/", FeedKind::HttpLoopback),
    ("http://127.255.0.1:9/", FeedKind::HttpLoopback),
    ("http://[::1]:8080/r/", FeedKind::HttpLoopback),
    ("file:///srv/r/", FeedKind::File),
    ("file:///C:/x/", FeedKind::File),
];

#[test]
fn the_core_accepts_the_corpus() {
    for (feed, kind) in ACCEPTED {
        assert_eq!(check_feed(feed).unwrap(), kind, "{feed}");
    }
}

#[test]
fn the_core_refuses_the_corpus() {
    use FeedRule::*;
    let cases: Vec<(String, FeedRule)> = [
        ("http://localhost:8080/", HttpNotLoopback),
        ("http://LOCALHOST/", HttpNotLoopback),
        ("http://127.1/", HttpNotLoopback),
        ("http://0x7f.0.0.1/", HttpNotLoopback),
        ("http://2130706433/", HttpNotLoopback),
        ("http://0177.0.0.1/", HttpNotLoopback),
        ("http://127.0.0.01/", HttpNotLoopback),
        ("http://127.0.0.1./", HttpNotLoopback),
        ("http://%31%32%37.0.0.1/", Forbidden),
        ("http://[::ffff:127.0.0.1]/", HttpNotLoopback),
        ("http://[0:0:0:0:0:0:0:1]/", HttpNotLoopback),
        ("http://127.0.0.1@evil.example/", Forbidden),
        ("http://evil.example#@127.0.0.1/", Forbidden),
        ("http://127.0.0.1\\@evil.example/", Forbidden),
        ("http://127.0.0.1:80/", Port),
        ("http://127.0.0.1:080/", Port),
        ("http://127.0.0.1:65536/", Port),
        ("http://10.0.0.1/", HttpNotLoopback),
        ("http://example.com/", HttpNotLoopback),
        ("HTTP://127.0.0.1/", Scheme),
        ("https://Example.com/", Host),
        ("https://example.com:443/", Port),
        ("https://example.com/a/../b/", Path),
        ("https://exa\tmple.com/", Byte),
        (" https://example.com/", Byte),
        ("https://exämple.com/", Byte),
    ]
    .into_iter()
    .map(|(f, r)| (f.to_owned(), r))
    .collect();
    for (feed, rule) in &cases {
        match check_feed(feed) {
            Err(UpdateConfigError::Feed(got)) => assert_eq!(got, *rule, "{feed:?}"),
            other => panic!("{feed:?}: {other:?}"),
        }
    }
}

#[test]
fn the_core_feed_rule_details() {
    use FeedRule::*;
    let refused = [
        ("https://example.com", Path),
        ("https://example.com/a", Path),
        ("https://example.com//", Path),
        ("https://example.com/./", Path),
        ("https://example.com/a:b/", Path),
        ("https://[::1]/", Ipv6Host),
        ("https://-a.example/", Host),
        ("https://a-.example/", Host),
        ("https://a..example/", Host),
        ("https://example.com./", Host),
        ("https://a_b.example/", Host),
        ("https://1.2.3/", Host),
        ("https://a.0x10/", Host),
        ("https://256.0.0.1/", Host),
        ("https://example.com:/", Port),
        ("https://example.com:0/", Port),
        ("https://example.com:a/", Port),
        ("https://example.com:1:2/", Host),
        ("https:///a/", Host),
        ("http:///a/", HttpNotLoopback),
        ("http://[::1/", HttpNotLoopback),
        ("http://[::1]x/", HttpNotLoopback),
        ("http://128.0.0.1/", HttpNotLoopback),
        ("ftp://example.com/", Scheme),
        ("file://host/x/", Scheme),
        ("file:///c:/x/", Path),
        ("file:///x/C:/", Path),
        ("file:///srv/r", Path),
        ("https://example.com/a?b/", Forbidden),
    ];
    for (feed, rule) in refused {
        match check_feed(feed) {
            Err(UpdateConfigError::Feed(got)) => assert_eq!(got, rule, "{feed:?}"),
            other => panic!("{feed:?}: {other:?}"),
        }
    }
    let long_label = format!("https://{}.example/", "a".repeat(63));
    assert!(check_feed(&long_label).is_ok());
    let too_long_label = format!("https://{}.example/", "a".repeat(64));
    assert!(check_feed(&too_long_label).is_err());
    let host = vec!["a".repeat(63); 4].join(".");
    assert_eq!(host.len(), 255);
    assert!(check_feed(&format!("https://{host}/")).is_err());
    let path = format!("https://e.example/{}/", "p".repeat(2048 - 19));
    assert_eq!(path.len(), 2048);
    assert!(check_feed(&path).is_ok());
    let path = format!("https://e.example/{}/", "p".repeat(2048 - 18));
    assert!(matches!(
        check_feed(&path),
        Err(UpdateConfigError::Feed(TooLong))
    ));
    for ok in [
        "https://localhost/",
        "https://0.0.0.0/",
        "https://a1.example/x.y_z~w-v/",
        "https://example.com:65535/",
        "http://127.0.0.1/",
        "http://127.0.0.1:443/",
        "file:///",
        "file:///C:/",
    ] {
        assert!(check_feed(ok).is_ok(), "{ok}");
    }
}

#[test]
fn the_reader_applies_the_feed_rule() {
    assert!(matches!(
        parse(&with_top("feed", json!("http://10.0.0.1/"))),
        Err(UpdateConfigError::Feed(FeedRule::HttpNotLoopback))
    ));
    assert!(matches!(
        parse(&with_top("feed", json!("https://example.com/no-slash"))),
        Err(UpdateConfigError::Feed(FeedRule::Path))
    ));
    let read = parse(&with_top("feed", json!("file:///C:/x/"))).unwrap();
    assert_eq!(read.feed_kind().unwrap(), FeedKind::File);
}

// ---- desktop paths ---------------------------------------------------------------------------------

#[test]
fn desktop_safe_path_rule() {
    for ok in [
        "/home/me/.local/share/org.example.app/current/bin/app",
        "/home/me/My Apps/app",
        "/home/jürgen/app",
        "C:/x/(1)/[a]/app+x=y,z;#@!&*",
    ] {
        desktop_safe_path(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    assert_eq!(desktop_safe_path(""), Err(DesktopPathError::Empty));
    for bad in [
        "/a\"b",
        "/a`b",
        "/a$b",
        "/a\\b",
        "/a%b",
        "/a'b",
        "/a\nb",
        "/a\tb",
        "/a\u{85}b",
        "/a\u{7f}b",
        "/a\u{2028}b",
        "/a\u{202e}b",
        "/a\u{200b}b",
        "/a\u{feff}b",
    ] {
        assert_eq!(
            desktop_safe_path(bad),
            Err(DesktopPathError::Char),
            "{bad:?}"
        );
    }
}

// ---- fuzz seeds ------------------------------------------------------------------------------------

#[test]
fn the_update_config_seeds_replay() {
    let seeds: Vec<_> = fuzz_seeds()
        .into_iter()
        .filter(|s| s.harness == "update_config")
        .collect();
    assert!(seeds.iter().any(|s| s.accepted) && seeds.iter().any(|s| !s.accepted));
    for seed in seeds {
        assert_eq!(
            lunepack_core::fuzz::accepts("update_config", &seed.bytes),
            Some(seed.accepted),
            "{}",
            seed.name
        );
        let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/seeds/update_config")
            .join(&seed.name);
        assert_eq!(
            std::fs::read(&committed).unwrap(),
            seed.bytes,
            "{}",
            seed.name
        );
    }
}

// ---- FORMAT.md 13 golden example ---------------------------------------------------------------

const GOLDEN_MARK: &str =
    "<!-- golden: update-config, generated by crates/lunepack-core/tests/update_config.rs -->";

fn golden_block(text: &str) -> Option<&str> {
    let after = text.split_once(GOLDEN_MARK)?.1;
    let body = after.trim_start().strip_prefix("```json\n")?;
    Some(body.split_once("\n```")?.0)
}

#[test]
fn the_format_md_example_is_what_the_writer_writes() {
    let generated = String::from_utf8(sample().to_bytes().unwrap()).unwrap();
    let generated = generated.strip_suffix('\n').unwrap();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/FORMAT.md");
    let text = std::fs::read_to_string(&path).unwrap();
    let block = golden_block(&text)
        .unwrap_or_else(|| panic!("docs/FORMAT.md has no golden block after {GOLDEN_MARK}"));
    assert_eq!(
        block, generated,
        "docs/FORMAT.md 13's example differs from what the writer writes; replace it with:\n{generated}"
    );
    // The block is the writer's bytes, so the reader reads it.
    parse(format!("{block}\n").as_bytes()).unwrap();
}

#[test]
fn the_golden_check_rejects_a_changed_example() {
    // The instrument: a changed config must not match the generated text of the original.
    let a = String::from_utf8(sample().to_bytes().unwrap()).unwrap();
    let mut changed = sample();
    changed.install.terminal = true;
    let b = String::from_utf8(changed.to_bytes().unwrap()).unwrap();
    assert_ne!(a, b);
    let doc = format!("{GOLDEN_MARK}\n\n```json\n{}\n```\n", b.trim_end());
    assert_ne!(golden_block(&doc), Some(a.trim_end()));
}
