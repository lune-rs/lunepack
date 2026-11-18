//! M7-D9: `startup` gives the process the app id as its app user model id, before anything can
//! show a window. Windows only; this file is its own test binary (own process), so no other test
//! has set the id first.
#![cfg(windows)]

use std::io::Write as _;
use std::sync::Arc;

use lunepack::{Installation, Platform, startup_for};
use lunepack_core::{Fs, LayoutScheme, UPDATE_CONFIG_FILE};
use lunepack_testkit::{
    FakeHasher, FakeProcess, FakeVerifier, MemFs, abs_path, sample_update_config,
};

#[test]
fn startup_sets_the_process_app_user_model_id_to_the_app_id() {
    assert_eq!(
        lunepack_os_windows::process_aumid().expect("read back"),
        None,
        "this process has no id yet"
    );

    let fs = Arc::new(MemFs::new());
    let config = sample_update_config();
    let tree = abs_path("/Downloads/boot");
    fs.create_dir_all(&tree).expect("tree");
    let mut f = fs
        .create_new(&tree.join(UPDATE_CONFIG_FILE))
        .expect("config file");
    f.write_all(&config.to_bytes().expect("bytes"))
        .expect("write");
    f.sync().expect("sync");
    let exe = tree.join(config.install.entry.to_string());

    let platform = Platform::native()
        .with_fs(Arc::clone(&fs) as Arc<dyn Fs>)
        .with_hasher(Arc::new(FakeHasher))
        .with_verifier(Arc::new(FakeVerifier))
        .with_process(Arc::new(FakeProcess::new("/unused")))
        .with_data_home(abs_path("/Programs"))
        .with_layout_scheme(LayoutScheme::WINDOWS);
    let inst = Installation::from_exe_with(&exe, platform).expect("installation");
    startup_for(&inst, Vec::new()).expect("startup");

    assert_eq!(
        lunepack_os_windows::process_aumid()
            .expect("read back")
            .as_deref(),
        Some(config.app_id.as_str())
    );
}
