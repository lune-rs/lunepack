//! The console launcher stub (M7-D7): starts the installed app's current version on the same
//! console, waits, and exits with its exit code; or prints one line and exits 90–95.

fn main() {
    lunepack_os_windows::harden_dll_search();
    std::process::exit(lunepack_stub::run(lunepack_stub::Variant::Console));
}
