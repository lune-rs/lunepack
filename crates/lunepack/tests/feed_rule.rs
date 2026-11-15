//! The update-config feed rule (FORMAT.md 13.3, M5-D16, M5 step 1): the corpus asserted against the
//! core rule and the facade's parser check separately, and a deterministic differential between
//! them over generated strings.

use lunepack::unstable_internals::check_parsed_feed;
use lunepack::{FeedKind, FeedRule, UpdateConfigError, check_config_feed};
use lunepack_core::check_feed;
use url::Url;

const ACCEPTED: [(&str, FeedKind); 7] = [
    ("https://updates.example.com/app/", FeedKind::Https),
    ("https://203.0.113.5:8443/r/", FeedKind::Https),
    ("http://127.0.0.1:8080/r/", FeedKind::HttpLoopback),
    ("http://127.255.0.1:9/", FeedKind::HttpLoopback),
    ("http://[::1]:8080/r/", FeedKind::HttpLoopback),
    ("file:///srv/r/", FeedKind::File),
    ("file:///C:/x/", FeedKind::File),
];

const REFUSED: [&str; 26] = [
    // Name and numeric host forms.
    "http://localhost:8080/",
    "http://LOCALHOST/",
    "http://127.1/",
    "http://0x7f.0.0.1/",
    "http://2130706433/",
    "http://0177.0.0.1/",
    "http://127.0.0.01/",
    "http://127.0.0.1./",
    "http://%31%32%37.0.0.1/",
    // IPv6 forms.
    "http://[::ffff:127.0.0.1]/",
    "http://[0:0:0:0:0:0:0:1]/",
    // Userinfo, fragment and backslash.
    "http://127.0.0.1@evil.example/",
    "http://evil.example#@127.0.0.1/",
    "http://127.0.0.1\\@evil.example/",
    // Ports.
    "http://127.0.0.1:80/",
    "http://127.0.0.1:080/",
    "http://127.0.0.1:65536/",
    // Non-loopback http hosts.
    "http://10.0.0.1/",
    "http://example.com/",
    // Case and normalisation.
    "HTTP://127.0.0.1/",
    "https://Example.com/",
    "https://example.com:443/",
    "https://example.com/a/../b/",
    // Whitespace and non-ASCII.
    "https://exa\tmple.com/",
    " https://example.com/",
    "https://exämple.com/",
];

#[test]
fn the_accepted_corpus_has_the_same_kind_in_core_and_facade() {
    for (feed, kind) in ACCEPTED {
        assert_eq!(check_feed(feed).unwrap(), kind, "core: {feed}");
        assert_eq!(check_parsed_feed(feed).unwrap(), kind, "parser: {feed}");
        assert_eq!(check_config_feed(feed).unwrap(), kind, "facade: {feed}");
    }
}

#[test]
fn the_refused_corpus_is_refused_by_the_core() {
    for feed in REFUSED {
        assert!(
            matches!(check_feed(feed), Err(UpdateConfigError::Feed(_))),
            "core accepted {feed:?}"
        );
        assert!(
            matches!(check_config_feed(feed), Err(UpdateConfigError::Feed(_))),
            "facade accepted {feed:?}"
        );
    }
}

#[test]
fn the_refused_corpus_is_refused_by_the_parser_check_on_its_own() {
    // Defence in depth: wherever the URL parser takes the string, the facade's own checks refuse
    // it even without the core rule in front.
    let mut parsed = 0;
    for feed in REFUSED {
        if Url::parse(feed).is_err() {
            continue;
        }
        parsed += 1;
        assert!(
            check_parsed_feed(feed).is_err(),
            "the parser check accepted {feed:?}"
        );
    }
    // The instrument: most of the corpus does parse, so this test is not vacuous.
    assert!(parsed >= 20, "only {parsed} of the corpus parsed");
}

#[test]
fn parser_check_rules() {
    let rule = |f: &str| check_parsed_feed(f).unwrap_err();
    assert_eq!(rule("not a url"), FeedRule::Unparsable);
    assert_eq!(rule("https://Example.com/"), FeedRule::Normalised);
    assert_eq!(rule("https://u:p@example.com/"), FeedRule::Userinfo);
    assert_eq!(rule("ftp://example.com/"), FeedRule::Scheme);
    assert_eq!(rule("http://10.0.0.1/"), FeedRule::HttpNotLoopback);
    assert_eq!(rule("http://example.com/"), FeedRule::HttpNotLoopback);
    let shown = check_config_feed("http://SECRETMARKER.example/")
        .unwrap_err()
        .to_string();
    assert!(!shown.contains("SECRETMARKER"), "{shown}");
}

/// xorshift64*: a fixed, seeded generator (the testkit's `FakeRng` arrives with the `Rng` trait in
/// M5 step 3).
struct Gen(u64);

impl Gen {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

const ALPHABET: &[u8] = b"0123456789.x%[]:@/abcdefzABZ\t";

fn generated(g: &mut Gen) -> String {
    let scheme = g.pick(&[
        "https://", "http://", "file:///", "HTTP://", "https:/", "file://",
    ]);
    let host = g.pick(&[
        "",
        "127.0.0.1",
        "127.",
        "[::1]",
        "[",
        "a.b",
        "0x7f.",
        "10.0.0.1",
        "example.com",
        "1.2.3.4",
    ]);
    let mut s = format!("{scheme}{host}");
    let noise = |g: &mut Gen, s: &mut String| {
        if g.below(2) == 0 {
            for _ in 0..=g.below(3) {
                s.push(ALPHABET[g.below(ALPHABET.len())] as char);
            }
        }
    };
    noise(g, &mut s);
    if g.below(3) == 0 {
        s.push(':');
        let port = g.pick(&["8080", "80", "443", "080", "0", "65535", "65536", ""]);
        s.push_str(port);
    }
    if g.below(6) != 0 {
        s.push('/');
        s.push_str(g.pick(&["", "r", "a.b", "..", "C:", "x~y"]));
        noise(g, &mut s);
        if g.below(4) != 0 {
            s.push('/');
        }
    }
    s
}

#[test]
fn differential_core_accept_implies_facade_accept() {
    let mut g = Gen(0x5eed_1e55_f00d_cafe);
    let mut core_accepted = 0;
    for _ in 0..2000 {
        let feed = generated(&mut g);
        let core = check_feed(&feed);
        let facade = check_config_feed(&feed);
        match &core {
            Ok(kind) => {
                core_accepted += 1;
                assert_eq!(facade.as_ref().ok(), Some(kind), "facade refused {feed:?}");
                let url = Url::parse(&feed).expect("a core-accepted feed parses");
                assert_eq!(url.as_str(), feed, "serialisation of {feed:?}");
            }
            Err(_) => assert!(facade.is_err(), "facade accepted {feed:?}"),
        }
    }
    // The instrument: the generator reaches both sides of the rule.
    assert!(
        (50..1950).contains(&core_accepted),
        "{core_accepted} of 2000 accepted by the core"
    );
}
