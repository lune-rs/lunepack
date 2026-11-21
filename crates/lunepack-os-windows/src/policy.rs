//! The administrator's policy for one app (M10-D12): [`RegistryPolicy`], the core's
//! `PolicySource` over `HKLM\SOFTWARE\Policies\lunepack\<app id>` in the native registry view.
//!
//! Two `REG_DWORD` values, `DisableSelfUpdate` and `NoUpdateUi`. A missing key or value is off; a
//! `REG_DWORD` 0 is off and any other number is on; a value of another type is on; any error other
//! than "not found" is on (fail closed), logged without the value.

use lunepack_core::{AppId, MachinePolicy, PolicySource};

use crate::integration::prefix_ok;
use crate::registry::{Hive, Key, Value};

/// The policy key's parent, below the hive.
const POLICY_ROOT: &str = r"SOFTWARE\Policies\lunepack";
/// The value that switches self-update off.
const DISABLE_SELF_UPDATE: &str = "DisableSelfUpdate";
/// The value that suppresses the update window.
const NO_UPDATE_UI: &str = "NoUpdateUi";

/// Reads the policy from the registry.
#[derive(Debug, Clone)]
pub struct RegistryPolicy {
    hive: Hive,
    root: String,
}

impl Default for RegistryPolicy {
    fn default() -> Self {
        RegistryPolicy::new()
    }
}

impl RegistryPolicy {
    /// The real policy: `HKLM\SOFTWARE\Policies\lunepack\<app id>`.
    pub fn new() -> RegistryPolicy {
        RegistryPolicy {
            hive: Hive::LocalMachine,
            root: POLICY_ROOT.to_owned(),
        }
    }

    /// The policy read from `HKCU\<prefix>\SOFTWARE\Policies\lunepack\<app id>` (for tests and
    /// tools). `None` for a prefix [`crate::WinScope::with_registry_prefix`] refuses.
    pub fn with_registry_prefix(prefix: &str) -> Option<RegistryPolicy> {
        prefix_ok(prefix).then(|| RegistryPolicy {
            hive: Hive::CurrentUser,
            root: format!(r"{prefix}\{POLICY_ROOT}"),
        })
    }
}

/// One value as a flag: absent is off, a number is on unless 0, anything else is on.
fn flag(policy_key: &Key, name: &'static str) -> bool {
    match policy_key.get(name) {
        Ok(None) => false,
        Ok(Some(Value::Dword(v))) => v != 0,
        Ok(Some(_)) => true,
        Err(e) => {
            tracing::warn!(
                value = name,
                code = e.raw_os_error(),
                "a policy value could not be read; treated as on"
            );
            true
        }
    }
}

impl PolicySource for RegistryPolicy {
    fn read(&self, app_id: &AppId) -> MachinePolicy {
        let path = format!(r"{}\{}", self.root, app_id.as_str());
        match Key::open(self.hive, &path, false) {
            Ok(None) => MachinePolicy::default(),
            Ok(Some(policy_key)) => MachinePolicy {
                self_update_disabled: flag(&policy_key, DISABLE_SELF_UPDATE),
                no_update_ui: flag(&policy_key, NO_UPDATE_UI),
            },
            Err(e) => {
                tracing::warn!(
                    code = e.raw_os_error(),
                    "the policy key could not be opened; treated as on"
                );
                MachinePolicy {
                    self_update_disabled: true,
                    no_update_ui: true,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry;

    struct Root(String);

    impl Root {
        fn new() -> Root {
            use std::hash::{BuildHasher as _, Hasher as _};
            let mut h = std::collections::hash_map::RandomState::new().build_hasher();
            h.write_u32(std::process::id());
            let root = format!(r"Software\lunepack-test-policy-{:016x}", h.finish());
            assert!(
                Key::open(Hive::CurrentUser, &root, false)
                    .expect("probe")
                    .is_none(),
                "the test root is new"
            );
            Root(root)
        }

        fn app_key(&self, app: &str) -> Key {
            Key::create(
                Hive::CurrentUser,
                &format!(r"{}\{POLICY_ROOT}\{app}", self.0),
            )
            .expect("create the policy key")
        }

        fn policy(&self) -> RegistryPolicy {
            RegistryPolicy::with_registry_prefix(&self.0).expect("prefix")
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = registry::delete_tree(Hive::CurrentUser, &self.0);
        }
    }

    fn app(id: &str) -> AppId {
        AppId::parse(id).expect("app id")
    }

    #[test]
    fn a_missing_key_or_value_is_off() {
        let root = Root::new();
        let p = root.policy();
        assert_eq!(p.read(&app("a.b")), MachinePolicy::default());
        root.app_key("a.b");
        assert_eq!(p.read(&app("a.b")), MachinePolicy::default());
        root.app_key("a.b").set_dword(NO_UPDATE_UI, 1).expect("set");
        let read = p.read(&app("a.b"));
        assert!(!read.self_update_disabled && read.no_update_ui);
    }

    #[test]
    fn a_dword_is_on_unless_zero_and_each_value_is_its_own() {
        let root = Root::new();
        let p = root.policy();
        let policy_key = root.app_key("a.b");
        policy_key.set_dword(DISABLE_SELF_UPDATE, 0).expect("set");
        policy_key.set_dword(NO_UPDATE_UI, 0).expect("set");
        assert_eq!(p.read(&app("a.b")), MachinePolicy::default());
        policy_key.set_dword(DISABLE_SELF_UPDATE, 1).expect("set");
        let read = p.read(&app("a.b"));
        assert!(read.self_update_disabled && !read.no_update_ui);
        policy_key
            .set_dword(DISABLE_SELF_UPDATE, 0xffff_ffff)
            .expect("set");
        policy_key.set_dword(NO_UPDATE_UI, 2).expect("set");
        let read = p.read(&app("a.b"));
        assert!(read.self_update_disabled && read.no_update_ui);
    }

    #[test]
    fn a_value_of_another_type_is_on() {
        let root = Root::new();
        let p = root.policy();
        let policy_key = root.app_key("a.b");
        policy_key.set_str(DISABLE_SELF_UPDATE, "0").expect("set");
        policy_key.set_str(NO_UPDATE_UI, "").expect("set");
        let read = p.read(&app("a.b"));
        assert!(read.self_update_disabled && read.no_update_ui, "{read:?}");
    }

    #[test]
    fn another_app_is_not_affected() {
        let root = Root::new();
        let p = root.policy();
        root.app_key("a.b")
            .set_dword(DISABLE_SELF_UPDATE, 1)
            .expect("set");
        assert_eq!(p.read(&app("a.c")), MachinePolicy::default());
    }

    #[test]
    fn the_real_policy_reads_a_missing_key_as_off() {
        // `HKLM\SOFTWARE\Policies\lunepack\<this id>` is not there: off, through the real hive.
        let real = RegistryPolicy::new();
        assert_eq!(
            real.read(&app("lunepack-test-no-such-policy-app")),
            MachinePolicy::default()
        );
    }

    #[test]
    fn a_bad_prefix_is_refused() {
        for bad in ["", r"a\\b", "a/b", "a\nb"] {
            assert!(
                RegistryPolicy::with_registry_prefix(bad).is_none(),
                "{bad:?}"
            );
        }
    }
}
