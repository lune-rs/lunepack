//! AWS Signature Version 4 for S3-compatible stores (P-D2): HMAC-SHA256 written here over `sha2`,
//! the canonical request, the string to sign and the `Authorization` header.
//!
//! The functions are pure: the caller hands in the request's parts and the time, and gets back the
//! header value. `S3Store` builds the parts once and sends exactly what it signed.
//!
//! Checked against RFC 4231 (HMAC) and the worked examples of AWS's S3 documentation (the
//! signatures there are reproduced byte for byte in this module's tests).

use std::fmt;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const BLOCK: usize = 64;
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The SHA-256 of nothing, in lowercase hex: the payload hash of a request with no body.
pub(crate) const EMPTY_SHA256_HEX: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// An access key and its secret. `Debug` shows neither, there is no `Display`, and both are
/// wiped from memory when the value is dropped.
pub struct Credentials {
    access_key: String,
    secret_key: String,
}

impl Credentials {
    /// Credentials from an access key id and its secret key.
    pub fn new(access_key: impl Into<String>, secret_key: impl Into<String>) -> Credentials {
        Credentials {
            access_key: access_key.into(),
            secret_key: secret_key.into(),
        }
    }

    /// Whether both parts are usable in a header: non-empty printable ASCII without a space, `/`
    /// or `,` (which would change how the `Authorization` header parses).
    pub(crate) fn is_well_formed(&self) -> bool {
        let ok = |text: &str, extra_forbidden: &[u8]| {
            !text.is_empty()
                && text
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && !extra_forbidden.contains(&b))
        };
        ok(&self.access_key, b"/,") && ok(&self.secret_key, b"")
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key", &"<redacted>")
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.access_key.zeroize();
        self.secret_key.zeroize();
    }
}

/// HMAC-SHA256 (RFC 2104).
pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = Zeroizing::new([0u8; BLOCK]);
    let mut outer_pad = Zeroizing::new([0u8; BLOCK]);
    for i in 0..BLOCK {
        inner_pad[i] = block[i] ^ 0x36;
        outer_pad[i] = block[i] ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad.as_slice());
    inner.update(message);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad.as_slice());
    outer.update(inner_hash.as_slice());
    outer.finalize().into()
}

/// Lowercase hex of `bytes`.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// SigV4's URI encoding of one path text: RFC 3986 unreserved characters stay, every other byte
/// is `%XX` with uppercase hex, and `/` stays when `keep_slash` is set (an object key's segments
/// are separated by it).
pub(crate) fn uri_encode(text: &str, keep_slash: bool) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else if byte == b'/' && keep_slash {
            out.push('/');
        } else {
            out.push('%');
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
    }
    out
}

/// `YYYYMMDD'T'HHMMSS'Z'` for a Unix time in seconds (UTC).
pub(crate) fn amz_date(unix_secs: u64) -> String {
    let days = i64::try_from(unix_secs / 86_400).unwrap_or(i64::MAX / 2);
    let within_day = unix_secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        within_day / 3600,
        within_day % 3600 / 60,
        within_day % 60
    )
}

/// Proleptic Gregorian date of a day count since 1970-01-01 (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// The parts of one request that SigV4 covers.
pub(crate) struct SigningInput<'a> {
    /// `GET`, `PUT` or `DELETE`.
    pub method: &'a str,
    /// The path exactly as sent (already URI-encoded, once, as S3 wants).
    pub canonical_uri: &'a str,
    /// The query string in canonical form (sorted, encoded); empty for none.
    pub canonical_query: &'a str,
    /// The signed headers: lowercase name and value, in any order.
    pub headers: &'a [(&'a str, &'a str)],
    /// The lowercase hex SHA-256 of the body (the value of `x-amz-content-sha256`).
    pub payload_sha256_hex: &'a str,
    /// The request time, `YYYYMMDD'T'HHMMSS'Z'`.
    pub amz_date: &'a str,
    /// The region of the credential scope (`auto` for R2).
    pub region: &'a str,
}

/// A header value as the canonical request writes it: trimmed, runs of spaces folded to one.
fn canonical_value(value: &str) -> String {
    value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

/// The canonical request text and the `SignedHeaders` list.
fn canonical_request(input: &SigningInput<'_>) -> (String, String) {
    let mut headers: Vec<(&str, String)> = input
        .headers
        .iter()
        .map(|(name, value)| (*name, canonical_value(value)))
        .collect();
    headers.sort_by(|a, b| a.0.cmp(b.0));
    let mut block = String::new();
    for (name, value) in &headers {
        block.push_str(name);
        block.push(':');
        block.push_str(value);
        block.push('\n');
    }
    let signed = headers
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    let request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        input.method,
        input.canonical_uri,
        input.canonical_query,
        block,
        signed,
        input.payload_sha256_hex
    );
    (request, signed)
}

/// The signature (lowercase hex) of the request.
pub(crate) fn signature(credentials: &Credentials, input: &SigningInput<'_>) -> (String, String) {
    let (request, signed_headers) = canonical_request(input);
    let date = input.amz_date.get(..8).unwrap_or(input.amz_date);
    let scope = format!("{date}/{}/s3/aws4_request", input.region);
    let to_sign = format!(
        "{ALGORITHM}\n{}\n{scope}\n{}",
        input.amz_date,
        hex_lower(&Sha256::digest(request.as_bytes()))
    );
    let seed = Zeroizing::new(format!("AWS4{}", credentials.secret_key));
    let k_date = Zeroizing::new(hmac_sha256(seed.as_bytes(), date.as_bytes()));
    let k_region = Zeroizing::new(hmac_sha256(k_date.as_slice(), input.region.as_bytes()));
    let k_service = Zeroizing::new(hmac_sha256(k_region.as_slice(), b"s3"));
    let k_signing = Zeroizing::new(hmac_sha256(k_service.as_slice(), b"aws4_request"));
    let signature = hex_lower(&hmac_sha256(k_signing.as_slice(), to_sign.as_bytes()));
    (signature, signed_headers)
}

/// The value of the `Authorization` header for the request.
pub(crate) fn authorization(credentials: &Credentials, input: &SigningInput<'_>) -> String {
    let (signature, signed_headers) = signature(credentials, input);
    let date = input.amz_date.get(..8).unwrap_or(input.amz_date);
    format!(
        "{ALGORITHM} Credential={}/{date}/{}/s3/aws4_request, SignedHeaders={signed_headers}, \
         Signature={signature}",
        credentials.access_key, input.region
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn hmac_hex(key: &[u8], data: &[u8]) -> String {
        hex_lower(&hmac_sha256(key, data))
    }

    // RFC 4231, section 4: test cases 1-4, 6 and 7 (case 5 is a truncated output, which this code
    // never produces).
    #[test]
    fn hmac_rfc4231_case_1() {
        assert_eq!(
            hmac_hex(&[0x0b; 20], b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_rfc4231_case_2() {
        assert_eq!(
            hmac_hex(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_rfc4231_case_3() {
        assert_eq!(
            hmac_hex(&[0xaa; 20], &[0xdd; 50]),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn hmac_rfc4231_case_4() {
        let key = unhex("0102030405060708090a0b0c0d0e0f10111213141516171819");
        assert_eq!(key.len(), 25);
        assert_eq!(
            hmac_hex(&key, &[0xcd; 50]),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        );
    }

    #[test]
    fn hmac_rfc4231_case_6_key_longer_than_the_block() {
        assert_eq!(
            hmac_hex(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn hmac_rfc4231_case_7_key_and_data_longer_than_the_block() {
        assert_eq!(
            hmac_hex(
                &[0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than \
                  block-size data. The key needs to be hashed before being used by the HMAC \
                  algorithm."
            ),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
    }

    // The edges of the "key longer than the block" rule (expected values from Python's hmac).
    #[test]
    fn hmac_keys_of_the_block_size_and_one_over() {
        assert_eq!(
            hmac_hex(&[0x42; 64], b"x"),
            "c661f285f4bf22069fb45df0f88aa26b92a14329cd6e967b3311203a3e482e6d"
        );
        assert_eq!(
            hmac_hex(&[0x42; 65], b"x"),
            "15342efe2ef1b34b5f0fdef4db2f00b940ff9620adcbc56b1a47defc054af37e"
        );
    }

    const AWS_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const AWS_DATE: &str = "20130524T000000Z";
    const HOST: &str = "examplebucket.s3.amazonaws.com";

    fn aws_credentials() -> Credentials {
        Credentials::new("AKIAIOSFODNN7EXAMPLE", AWS_SECRET)
    }

    // The S3 documentation's "GET Object" example (Range: bytes=0-9).
    #[test]
    fn aws_example_get_object() {
        let input = SigningInput {
            method: "GET",
            canonical_uri: "/test.txt",
            canonical_query: "",
            headers: &[
                ("host", HOST),
                ("range", "bytes=0-9"),
                ("x-amz-content-sha256", EMPTY_SHA256_HEX),
                ("x-amz-date", AWS_DATE),
            ],
            payload_sha256_hex: EMPTY_SHA256_HEX,
            amz_date: AWS_DATE,
            region: "us-east-1",
        };
        let (signature, signed) = signature(&aws_credentials(), &input);
        assert_eq!(
            signature,
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        assert_eq!(signed, "host;range;x-amz-content-sha256;x-amz-date");
        assert_eq!(
            authorization(&aws_credentials(), &input),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    // "PUT Object": the key `test$file.text` (so `$` is encoded) and a body.
    #[test]
    fn aws_example_put_object() {
        let body_hash = hex_lower(&Sha256::digest(b"Welcome to Amazon S3."));
        assert_eq!(
            body_hash,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        assert_eq!(uri_encode("test$file.text", true), "test%24file.text");
        let input = SigningInput {
            method: "PUT",
            canonical_uri: "/test%24file.text",
            canonical_query: "",
            headers: &[
                ("date", "Fri, 24 May 2013 00:00:00 GMT"),
                ("host", HOST),
                ("x-amz-content-sha256", &body_hash),
                ("x-amz-date", AWS_DATE),
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ],
            payload_sha256_hex: &body_hash,
            amz_date: AWS_DATE,
            region: "us-east-1",
        };
        assert_eq!(
            signature(&aws_credentials(), &input).0,
            "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    // "GET Bucket Lifecycle" and "GET Bucket (List Objects)": a query string.
    #[test]
    fn aws_examples_with_a_query() {
        for (query, expected) in [
            (
                "lifecycle=",
                "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
            ),
            (
                "max-keys=2&prefix=J",
                "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
            ),
        ] {
            let input = SigningInput {
                method: "GET",
                canonical_uri: "/",
                canonical_query: query,
                headers: &[
                    ("host", HOST),
                    ("x-amz-content-sha256", EMPTY_SHA256_HEX),
                    ("x-amz-date", AWS_DATE),
                ],
                payload_sha256_hex: EMPTY_SHA256_HEX,
                amz_date: AWS_DATE,
                region: "us-east-1",
            };
            assert_eq!(signature(&aws_credentials(), &input).0, expected, "{query}");
        }
    }

    #[test]
    fn empty_payload_hash_constant_is_the_sha256_of_nothing() {
        assert_eq!(hex_lower(&Sha256::digest(b"")), EMPTY_SHA256_HEX);
    }

    #[test]
    fn header_values_are_trimmed_and_folded() {
        let sign = |headers: &[(&str, &str)]| {
            signature(
                &aws_credentials(),
                &SigningInput {
                    method: "GET",
                    canonical_uri: "/k",
                    canonical_query: "",
                    headers,
                    payload_sha256_hex: EMPTY_SHA256_HEX,
                    amz_date: AWS_DATE,
                    region: "auto",
                },
            )
        };
        assert_eq!(
            sign(&[("host", "h"), ("x-amz-meta-a", "  one   two  ")]),
            sign(&[("x-amz-meta-a", "one two"), ("host", "h")])
        );
        assert_ne!(
            sign(&[("host", "h"), ("x-amz-meta-a", "one two")]),
            sign(&[("host", "h"), ("x-amz-meta-a", "onetwo")])
        );
    }

    #[test]
    fn uri_encoding_keeps_unreserved_and_the_slash_only_when_asked() {
        assert_eq!(uri_encode("a-b_c.d~E9", false), "a-b_c.d~E9");
        assert_eq!(
            uri_encode("1.0.0+b1/pack bin", true),
            "1.0.0%2Bb1/pack%20bin"
        );
        assert_eq!(uri_encode("a/b", false), "a%2Fb");
        assert_eq!(uri_encode("100%", true), "100%25");
        assert_eq!(uri_encode("a?b#c&d=e", true), "a%3Fb%23c%26d%3De");
    }

    #[test]
    fn dates_follow_the_calendar() {
        assert_eq!(amz_date(0), "19700101T000000Z");
        assert_eq!(amz_date(1_369_353_600), AWS_DATE);
        assert_eq!(amz_date(951_782_400), "20000229T000000Z");
        assert_eq!(amz_date(951_868_799), "20000229T235959Z");
        assert_eq!(amz_date(951_868_800), "20000301T000000Z");
        assert_eq!(amz_date(4_102_444_800), "21000101T000000Z");
        // 2100 is not a leap year.
        assert_eq!(amz_date(4_107_542_400), "21000301T000000Z");
        assert_eq!(amz_date(1_700_000_000), "20231114T221320Z");
    }

    #[test]
    fn credentials_do_not_show_themselves() {
        let credentials = Credentials::new("AKIDEXAMPLE0001", "s3cr3t-value-0002");
        let shown = format!("{credentials:?}");
        assert!(!shown.contains("AKIDEXAMPLE0001"), "{shown}");
        assert!(!shown.contains("s3cr3t-value-0002"), "{shown}");
        assert!(shown.contains("redacted"));
    }

    #[test]
    fn credentials_well_formedness() {
        assert!(Credentials::new("AKID", "secret/with+chars=").is_well_formed());
        for (id, secret) in [
            ("", "s"),
            ("a", ""),
            ("a b", "s"),
            ("a/b", "s"),
            ("a,b", "s"),
            ("a\n", "s"),
            ("a", "s\r"),
            ("é", "s"),
        ] {
            assert!(
                !Credentials::new(id, secret).is_well_formed(),
                "{id:?} {secret:?}"
            );
        }
    }
}
