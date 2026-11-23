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

/// The rail's three uninstall steps.
pub const UNINSTALL_STEPS: [&str; 3] = ["Confirm", "Remove", "Done"];

/// The install flow's checklist while installing, in the order the engine reports them.
pub fn install_rows(os: Os) -> [&'static str; 4] {
    [
        "Check the package signature",
        "Unpack files",
        "Add shortcuts",
        match os {
            Os::Windows => "Register in Apps & features",
            Os::Macos => "Add to Applications",
            Os::Linux => "Register the install",
        },
    ]
}

/// The welcome screen's title.
pub fn install_title(name: &str) -> String {
    format!("Install {name}")
}

/// The welcome screen's line under the title.
pub fn install_scope() -> &'static str {
    "Installs for your account only. No administrator rights needed."
}

/// The welcome screen's line under the title once "Install for all users" is ticked.
pub fn install_scope_all_users() -> &'static str {
    "Installs for everyone on this PC. Windows will ask for administrator approval."
}

/// The label of the welcome screen's all-users checkbox.
pub fn install_all_users_label() -> &'static str {
    "Install for all users"
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

/// The title of the screen that shows the command to run as an administrator (M11-D9, D14).
pub fn admin_command_title() -> &'static str {
    "Finish in a terminal"
}

/// The line under that title: what the command does, by flow (`install` is true for an install).
pub fn admin_command_note(install: bool, name: &str) -> String {
    if install {
        format!(
            "Run this command in a terminal as an administrator to install {name} for all users."
        )
    } else {
        format!("Run this command in a terminal as an administrator to uninstall {name}.")
    }
}

/// The label of the button that copies the administrator command.
pub fn admin_command_copy() -> &'static str {
    "Copy command"
}

/// The title of the screen that says the install went on in the system's installer (M11-D8).
pub fn handed_off_title() -> &'static str {
    "Continue in Installer"
}

/// The line under that title.
pub fn handed_off_note(name: &str) -> String {
    format!("Installer has opened to install {name} for all users. You can close this window.")
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
        25 => format!("{name} is still running. Close it and try again."),
        24 => "The shortcuts couldn't be created. Nothing was installed.".to_string(),
        26 => {
            "This install isn't the one this computer expects, so nothing was changed.".to_string()
        }
        27 => "No release is available yet. Try again later.".to_string(),
        // M8-D4: a copy in a place lunepack does not update (translocated, a disk image, another
        // volume, not the user's).
        28 => unsupported_location_text(name),
        _ => format!("Something went wrong (error {code})."),
    }
}

/// What the user is told when the app runs from, or is installed in, a place that is not updated
/// (exit 28, M8-D4).
pub fn unsupported_location_text(name: &str) -> String {
    format!("Move {name} to your Applications folder and open it from there.")
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
        28 => "unsupported_location",
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

/// The update window's title while waiting for the app to close.
pub fn update_waiting_title(name: &str) -> String {
    format!("Waiting for {name} to close")
}

/// The line under it.
pub fn update_waiting_note(version: &str) -> String {
    format!("Version {version} installs as soon as it does.")
}

/// The update window's title while applying.
pub fn update_applying_title(version: &str) -> String {
    format!("Updating to {version}")
}

/// The line under it, with the percentage when the engine reports one.
pub fn update_applying_note(percent: Option<u32>) -> String {
    match percent {
        Some(p) => format!("Switching versions \u{b7} {p}%"),
        None => "Switching versions".to_owned(),
    }
}

/// The title while the new version starts.
pub fn update_starting_title(name: &str, version: &str) -> String {
    format!("Starting {name} {version}")
}

/// The line under it.
pub fn update_starting_note() -> &'static str {
    "Checking that it opens correctly."
}

/// The title of a rolled-back update.
pub fn update_rolled_back_title() -> &'static str {
    "Update undone"
}

/// The line under it: the version that failed and the one that is back.
pub fn update_rolled_back_note(from: &str, to: &str) -> String {
    format!("{from} didn't start correctly, so {to} is back.")
}

/// The title of a failed update.
pub fn update_failed_title() -> &'static str {
    "Update didn't finish"
}

/// The confirm screen's title.
pub fn uninstall_title(name: &str) -> String {
    format!("Uninstall {name}?")
}

/// The line over the list of what goes.
pub fn uninstall_intro(os: Os) -> String {
    format!("These will be removed from this {}:", os.machine())
}

/// What an uninstall removes, for the confirm screen.
pub fn uninstall_items(os: Os, location: Option<&str>) -> Vec<String> {
    let app = match location {
        Some(l) => format!("The app ({l})"),
        None => "The app".to_owned(),
    };
    match os {
        Os::Windows => vec![
            app,
            "Start menu and desktop shortcuts".to_owned(),
            "Its entry in Apps & features".to_owned(),
        ],
        Os::Macos => vec![app, "Its shortcuts in Applications".to_owned()],
        Os::Linux => vec![
            app,
            "Its application menu entry and command link".to_owned(),
        ],
    }
}

/// The removing screen's line, by how far the engine got.
pub fn uninstall_removing_note(shortcuts_done: bool) -> &'static str {
    if shortcuts_done {
        "Removing files"
    } else {
        "Removing shortcuts"
    }
}

/// The done screen's title.
pub fn uninstall_done_title(name: &str) -> String {
    format!("{name} was removed")
}

/// The done screen's line: what was left behind, or that nothing was.
pub fn uninstall_done_note(leftovers: usize) -> String {
    match leftovers {
        0 => "Nothing was left behind.".to_owned(),
        1 => "One item was in use and was left behind:".to_owned(),
        n => format!("{n} items were in use and were left behind:"),
    }
}

/// The failed uninstall's title.
pub fn uninstall_failed_title() -> &'static str {
    "Uninstall didn't finish"
}

/// The line under it.
pub fn uninstall_failed_note(name: &str) -> String {
    format!("{name} is still installed.")
}

/// The "and N more" row of a long list of leftovers.
pub fn and_more(n: usize) -> String {
    format!("and {n} more")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_28_tells_the_user_to_move_the_app() {
        assert_eq!(
            failure_reason(28, "My App"),
            "Move My App to your Applications folder and open it from there."
        );
        assert_eq!(kind_name(28), "unsupported_location");
    }
}
