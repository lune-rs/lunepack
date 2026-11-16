//! The authoritative feed check of an update configuration (FORMAT.md 13.3, M5-D16): the core's
//! rule, then the URL parser the transport uses ([`url::Url`], as in `FeedUrls::new`). Run by the
//! packager before it writes a configuration and by the facade before any request with a feed
//! read from one.

use std::net::Ipv6Addr;

use lunepack_core::{FeedKind, FeedRule, UpdateConfigError, check_feed};
use url::{Host, Url};

/// Checks a feed string from an update configuration: [`lunepack_core::check_feed`], then
/// [`check_parsed_feed`]. Every refusal names the rule; the string is never shown.
pub fn check_config_feed(feed: &str) -> Result<FeedKind, UpdateConfigError> {
    let kind = check_feed(feed)?;
    let parsed = check_parsed_feed(feed).map_err(UpdateConfigError::Feed)?;
    if parsed != kind {
        return Err(UpdateConfigError::Feed(FeedRule::SchemeMismatch));
    }
    Ok(kind)
}

/// The parser half of [`check_config_feed`] on its own: the string parses, serialises back to
/// itself byte for byte, has an `https`, `http` or `file` scheme and no user name or password, and
/// an `http` host is an IPv4 address with first octet 127 or `::1`. The kind comes from the parsed
/// scheme.
pub fn check_parsed_feed(feed: &str) -> Result<FeedKind, FeedRule> {
    let url = Url::parse(feed).map_err(|_| FeedRule::Unparsable)?;
    if url.as_str() != feed {
        return Err(FeedRule::Normalised);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(FeedRule::Userinfo);
    }
    let kind = match url.scheme() {
        "https" => FeedKind::Https,
        "http" => FeedKind::HttpLoopback,
        "file" => FeedKind::File,
        _ => return Err(FeedRule::Scheme),
    };
    if kind == FeedKind::HttpLoopback {
        let loopback = match url.host() {
            Some(Host::Ipv4(a)) => a.octets()[0] == 127,
            Some(Host::Ipv6(a)) => a == Ipv6Addr::LOCALHOST,
            _ => false,
        };
        if !loopback {
            return Err(FeedRule::HttpNotLoopback);
        }
    }
    Ok(kind)
}
