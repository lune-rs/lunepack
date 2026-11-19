//! The GUI launcher stub (M7-D7): starts the installed app's current version and exits 0, or shows
//! a message box and exits 90–95.

#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    lunepack_os_windows::harden_dll_search();
    std::process::exit(lunepack_stub::run(lunepack_stub::Variant::Gui));
}
