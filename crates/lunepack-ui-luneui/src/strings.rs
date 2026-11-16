//! The words on the screens. The UI owns them and maps them from closed codes (the engine sends
//! none), with wording per OS where the OS names things differently (M6 step 8).

/// The OS the screens run on, which picks the wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Windows.
    Windows,
    /// macOS.
    Macos,
    /// Linux.
    Linux,
}

impl Os {
    /// The OS this build runs on.
    pub fn current() -> Os {
        if cfg!(target_os = "windows") {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::Macos
        } else {
            Os::Linux
        }
    }

    /// What the machine is called in "nothing was changed on this ...".
    pub fn machine(self) -> &'static str {
        match self {
            Os::Windows => "PC",
            Os::Macos => "Mac",
            Os::Linux => "computer",
        }
    }

    /// Where the installed app can be found afterwards.
    pub fn launcher(self) -> &'static str {
        match self {
            Os::Windows => "the Start menu",
            Os::Macos => "the Applications folder",
            Os::Linux => "your application menu",
        }
    }
}

/// The rail's three install steps.
pub const INSTALL_STEPS: [&str; 3] = ["Welcome", "Install", "Finish"];

/// The install flow's checklist while installing, in the order the engine reports them.
pub const INSTALL_ROWS: [&str; 4] = [
    "Check the package signature",
    "Unpack files",
    "Add shortcuts",
    "Register the install",
];

/// The welcome screen's title.
pub fn install_title(name: &str) -> String {
    format!("Install {name}")
}

/// The welcome screen's line under the title.
pub fn install_scope() -> &'static str {
    "Installs for your account only. No administrator rights needed."
}

/// The done screen's body.
pub fn install_done(os: Os, name: &str, version: &str) -> String {
    format!(
        "{name} {version} is installed. You'll find it in {}.",
        os.launcher()
    )
}

/// The failed screen's title.
pub fn install_failed_title() -> &'static str {
    "Installation didn't finish"
}

/// The failed screen's line under the title.
pub fn install_failed_note(os: Os) -> String {
    format!("Nothing was changed on this {}.", os.machine())
}

/// What an exit code of the runtime (docs/RUNTIME.md, "Exit codes") means to a person.
pub fn failure_reason(code: u32, name: &str) -> String {
    match code {
        4 => "Another installer is running. Wait for it to finish, then try again.".to_string(),
        7 => "The package couldn't be verified, so nothing was installed.".to_string(),
        8 | 11 => "The download didn't complete. Check the connection and try again.".to_string(),
        9 => format!(
            "Another program is using the {name} folder, so its files couldn't be written. Close it and try again."
        ),
        23 => format!("{name} is already installed."),
        24 => "The shortcuts couldn't be created. Nothing was installed.".to_string(),
        26 => {
            "This install isn't the one this computer expects, so nothing was changed.".to_string()
        }
        27 => "No release is available yet. Try again later.".to_string(),
        _ => format!("Something went wrong (error {code})."),
    }
}

/// The runtime's `kind` for an exit code, for the details a person can copy.
pub fn kind_name(code: u32) -> &'static str {
    match code {
        2 => "usage",
        3 => "not_installed",
        4 => "busy",
        5 => "cancelled",
        6 => "stale",
        7 => "verify",
        8 => "transport",
        9 => "fs",
        10 => "state",
        11 => "incomplete",
        12 => "nothing_staged",
        13 => "schema_mismatch",
        14 => "update_config",
        15 => "unexpected_version",
        16 => "token_mismatch",
        17 => "machine_scope",
        18 => "unsupported",
        19 => "process",
        20 => "rolled_back",
        21 => "wait_timeout",
        22 => "rollback_unavailable",
        23 => "already_installed",
        24 => "integration",
        25 => "in_use",
        26 => "install_mismatch",
        27 => "no_release",
        _ => "internal",
    }
}

/// `bytes` as "61 MB" (decimal units, one decimal below 10).
pub fn size_text(bytes: u64) -> String {
    let (value, unit) = if bytes >= 1_000_000_000 {
        (bytes as f64 / 1e9, "GB")
    } else if bytes >= 1_000_000 {
        (bytes as f64 / 1e6, "MB")
    } else if bytes >= 1_000 {
        (bytes as f64 / 1e3, "KB")
    } else {
        return format!("{bytes} B");
    };
    if value < 10.0 {
        format!("{value:.1} {unit}")
    } else {
        format!("{value:.0} {unit}")
    }
}

/// "38 of 61 MB": `done` of `total` in the unit of `total`.
pub fn progress_text(done: u64, total: u64) -> String {
    let (div, unit) = if total >= 1_000_000_000 {
        (1e9, "GB")
    } else if total >= 1_000_000 {
        (1e6, "MB")
    } else if total >= 1_000 {
        (1e3, "KB")
    } else {
        (1.0, "B")
    };
    let done = done.min(total);
    if total as f64 / div < 10.0 && div > 1.0 {
        format!(
            "{:.1} of {:.1} {unit}",
            done as f64 / div,
            total as f64 / div
        )
    } else {
        format!(
            "{:.0} of {:.0} {unit}",
            done as f64 / div,
            total as f64 / div
        )
    }
}
