//! The macOS bundle files `pack` writes (M8-D6): the update window's helper-app `Info.plist`, a
//! deterministic XML property-list writer, and the check an `.icns` icon file passes.
//!
//! The writer is a function of its inputs only (no time, no host): the keys come out sorted, the
//! layout is fixed, and every string is escaped for XML (`& < > " '`). A string with a character
//! XML 1.0 cannot carry is refused, never rewritten.

use std::fmt::Write as _;

use anyhow::{Result, bail};
use lunepack_core::AppId;
use lunepack_core::update_config::UI_FILE;

/// `LSMinimumSystemVersion` of the helper app: the lowest macOS the runtime supports (M8-D14).
pub const MIN_SYSTEM_VERSION: &str = "10.15";
/// The helper's `CFBundleIconFile`: the icon's name without its extension.
pub const HELPER_ICON_NAME: &str = "lunepack-update";
/// Largest `.icns` file read, in bytes.
pub const MAX_ICNS_BYTES: u64 = 4 * 1024 * 1024;

/// One value of a property list this module writes.
enum Value<'a> {
    String(&'a str),
    Bool(bool),
}

/// Escapes `text` for an XML text node and refuses a character XML 1.0 cannot carry.
fn escape(text: &str) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if c.is_control() || matches!(c, '\u{FFFE}' | '\u{FFFF}') => {
                bail!("a property list string holds a character XML cannot carry")
            }
            c => out.push(c),
        }
    }
    Ok(out)
}

/// Renders a flat dictionary as an XML property list, keys in byte order, one tab of indent.
fn render(entries: &mut [(&str, Value<'_>)]) -> Result<Vec<u8>> {
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
    );
    out.push_str("<plist version=\"1.0\">\n<dict>\n");
    for (key, value) in entries.iter() {
        // Keys are this module's own constants, so only the values can need escaping.
        let _ = writeln!(out, "\t<key>{key}</key>");
        match value {
            Value::String(text) => {
                let _ = writeln!(out, "\t<string>{}</string>", escape(text)?);
            }
            Value::Bool(true) => out.push_str("\t<true/>\n"),
            Value::Bool(false) => out.push_str("\t<false/>\n"),
        }
    }
    out.push_str("</dict>\n</plist>\n");
    Ok(out.into_bytes())
}

/// The bundle identifier of the update window's helper app: the app id with `_` written as `-`
/// (a bundle identifier allows letters, digits, `-` and `.`), then `.lunepack-update`.
pub fn helper_bundle_id(app_id: &AppId) -> String {
    format!("{}.lunepack-update", app_id.as_str().replace('_', "-"))
}

/// The `Info.plist` of the helper app `Contents/Helpers/lunepack-update.app` (M8-D6): the UI as
/// its executable, `name` (`install.name`) as its name and, when the pack carries an icon, the
/// icon's file name.
pub fn helper_info_plist(app_id: &AppId, name: &str, icon: bool) -> Result<Vec<u8>> {
    let id = helper_bundle_id(app_id);
    let mut entries = vec![
        ("CFBundleExecutable", Value::String(UI_FILE)),
        ("CFBundleIdentifier", Value::String(&id)),
        ("CFBundleName", Value::String(name)),
        ("CFBundlePackageType", Value::String("APPL")),
        ("LSMinimumSystemVersion", Value::String(MIN_SYSTEM_VERSION)),
        ("NSHighResolutionCapable", Value::Bool(true)),
    ];
    if icon {
        entries.push(("CFBundleIconFile", Value::String(HELPER_ICON_NAME)));
    }
    render(&mut entries)
}

/// Checks `bytes` as an `.icns` file: the `icns` magic and a big-endian length that equals the
/// file's, at least the 8-byte header. Carries no byte of the file.
pub fn check_icns(bytes: &[u8]) -> std::result::Result<(), &'static str> {
    if bytes.get(..4) != Some(b"icns") {
        return Err("not an icns file");
    }
    let Some(length) = bytes.get(4..8).and_then(|b| <[u8; 4]>::try_from(b).ok()) else {
        return Err("truncated");
    };
    let length = u32::from_be_bytes(length);
    if length < 8 || u64::from(length) != bytes.len() as u64 {
        return Err("the length in its header is not the file's length");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> AppId {
        AppId::parse("org.example.my_app").unwrap()
    }

    #[test]
    fn the_helper_plist_is_a_golden() {
        let got = helper_info_plist(&id(), "My App", true).unwrap();
        let want = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
\t<key>CFBundleExecutable</key>\n\
\t<string>lunepack-ui</string>\n\
\t<key>CFBundleIconFile</key>\n\
\t<string>lunepack-update</string>\n\
\t<key>CFBundleIdentifier</key>\n\
\t<string>org.example.my-app.lunepack-update</string>\n\
\t<key>CFBundleName</key>\n\
\t<string>My App</string>\n\
\t<key>CFBundlePackageType</key>\n\
\t<string>APPL</string>\n\
\t<key>LSMinimumSystemVersion</key>\n\
\t<string>10.15</string>\n\
\t<key>NSHighResolutionCapable</key>\n\
\t<true/>\n\
</dict>\n\
</plist>\n";
        assert_eq!(String::from_utf8(got).unwrap(), want);
    }

    #[test]
    fn the_plist_is_the_same_bytes_for_the_same_inputs() {
        let a = helper_info_plist(&id(), "Name", false).unwrap();
        let b = helper_info_plist(&id(), "Name", false).unwrap();
        assert_eq!(a, b);
        let text = String::from_utf8(a).unwrap();
        assert!(!text.contains("CFBundleIconFile"));
    }

    #[test]
    fn the_five_xml_characters_are_escaped() {
        let got = helper_info_plist(&id(), "a<b>&\"c\"'d'", false).unwrap();
        let text = String::from_utf8(got).unwrap();
        assert!(
            text.contains("<string>a&lt;b&gt;&amp;&quot;c&quot;&apos;d&apos;</string>"),
            "{text}"
        );
        assert!(!text.contains("a<b"));
    }

    #[test]
    fn a_non_ascii_name_is_kept_and_a_bad_character_is_refused() {
        let got = helper_info_plist(&id(), "Café ☕", false).unwrap();
        assert!(String::from_utf8(got).unwrap().contains("Café ☕"));
        assert!(helper_info_plist(&id(), "a\u{1}b", false).is_err());
        assert!(helper_info_plist(&id(), "a\u{FFFF}b", false).is_err());
    }

    #[test]
    fn icns_needs_its_magic_and_its_own_length() {
        let mut ok = b"icns".to_vec();
        ok.extend_from_slice(&12u32.to_be_bytes());
        ok.extend_from_slice(b"data");
        assert_eq!(check_icns(&ok), Ok(()));
        assert!(check_icns(b"").is_err());
        assert!(check_icns(b"icns").is_err());
        let mut short = ok.clone();
        short.pop();
        assert!(check_icns(&short).is_err());
        let mut long = ok.clone();
        long.push(0);
        assert!(check_icns(&long).is_err());
        let mut wrong = ok.clone();
        wrong[0] = b'x';
        assert!(check_icns(&wrong).is_err());
        let mut tiny = b"icns".to_vec();
        tiny.extend_from_slice(&4u32.to_be_bytes());
        assert!(check_icns(&tiny).is_err());
    }
}
