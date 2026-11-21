//! The Service Control Manager side of the per-machine install (M10 step 9): the registration of
//! the update service ([`WindowsRegistrar`], the core's `ServiceRegistrar`), the client's way to
//! it ([`WindowsConnector`], the core's `ServiceConnector`) and the service's own dispatcher
//! ([`run_service`]).
//!
//! # Registration (M10-D10)
//!
//! The service is named `lunepack-<app id>` (the pipe has the same name), runs in its own process
//! as LocalSystem, starts on demand, and its image path is the absolute path in double quotes with
//! no arguments. Its descriptor is the default one Windows gave the new service plus one allow
//! entry for Users with exactly start, query status and read control, and an explicit owner
//! (Administrators). After it is set, the descriptor is read back and judged
//! ([`judge_service_descriptor`]): nobody outside LocalSystem, Administrators and TrustedInstaller
//! may hold a right beyond reading the configuration and the status, interrogating and starting;
//! a registration that fails the read-back is deleted again.
//!
//! The core's `register` replaces a registration that exists (the engine's first install and its
//! `repair` both call it): the old service is stopped and deleted, then created anew.
//! [`WindowsRegistrar::register_new`] is the strict form: an existing service of that name is an
//! error.
//!
//! # Connecting
//!
//! [`WindowsConnector`] opens the SCM with connect rights only and the service with start and
//! query-status rights only (what a standard user holds, M10-D10), starts the service when it is
//! not running, then opens the pipe and checks that LocalSystem owns it. It never elevates and
//! never prompts.
//!
//! # The service side
//!
//! [`run_service`] hands the process to the SCM's dispatcher, reports start pending, running, stop
//! pending and stopped, and runs the body on the service's main thread. The body gets a
//! [`ServiceControl`]: a flag to poll and a hook that ends a blocked accept when a stop or a
//! shutdown arrives.
//!
//! This module uses no impersonation API and reads no environment variable.

use std::path::{Path, PathBuf};

use lunepack_core::{AppId, ServiceRegError};

use crate::security::{
    ACE_ALLOWED, ACE_ALLOWED_CALLBACK, ACE_DENIED, ACE_DENIED_CALLBACK, Descriptor,
    SID_ADMINISTRATORS, SID_SYSTEM, SID_TRUSTED_INSTALLER, SID_USERS,
};

/// `SERVICE_QUERY_CONFIG`.
const SERVICE_QUERY_CONFIG: u32 = 0x0001;
/// `SERVICE_QUERY_STATUS`.
const SERVICE_QUERY_STATUS: u32 = 0x0004;
/// `SERVICE_ENUMERATE_DEPENDENTS`.
const SERVICE_ENUMERATE_DEPENDENTS: u32 = 0x0008;
/// `SERVICE_START`.
const SERVICE_START: u32 = 0x0010;
/// `SERVICE_INTERROGATE`.
const SERVICE_INTERROGATE: u32 = 0x0080;
/// `SERVICE_USER_DEFINED_CONTROL`: Windows's own default entries for Interactive and Service
/// accounts hold it (read back on Windows 11). The service answers a control it does not know with
/// `ERROR_CALL_NOT_IMPLEMENTED` and does nothing, so the right changes nothing.
const SERVICE_USER_DEFINED_CONTROL: u32 = 0x0100;
/// `READ_CONTROL`.
const READ_CONTROL: u32 = 0x0002_0000;
/// `SYNCHRONIZE`.
const SYNCHRONIZE: u32 = 0x0010_0000;

/// What Users hold on the service: start, query status and read control, exactly (P-W5).
pub const USERS_MASK: u32 = SERVICE_START | SERVICE_QUERY_STATUS | READ_CONTROL;

/// The rights an account outside LocalSystem, Administrators and TrustedInstaller may hold on the
/// service: reading the configuration and the status, listing dependents, interrogating, starting,
/// a user-defined control (Windows's own default entries hold it) and reading the descriptor.
/// Everything else (change config, stop, pause, delete, write DAC, write owner, the generic and
/// system-security bits) is outside.
pub const NON_ADMIN_ALLOWED: u32 = SERVICE_QUERY_CONFIG
    | SERVICE_QUERY_STATUS
    | SERVICE_ENUMERATE_DEPENDENTS
    | SERVICE_START
    | SERVICE_INTERROGATE
    | SERVICE_USER_DEFINED_CONTROL
    | READ_CONTROL
    | SYNCHRONIZE;

/// The allow entry for Users appended to the default descriptor, in descriptor text: start (`RP`),
/// query status (`LC`) and read control (`RC`), exactly [`USERS_MASK`].
pub const USERS_ENTRY: &str = "(A;;RPLCRC;;;BU)";

/// The longest display name, in UTF-16 units.
const MAX_DISPLAY_UNITS: usize = 256;

/// The service name of `app_id`: `lunepack-<app id>`.
pub fn service_name(app_id: &AppId) -> String {
    format!("lunepack-{}", app_id.as_str())
}

/// The pipe name of `app_id` (the part after `\\.\pipe\`): `lunepack-<app id>`.
pub fn pipe_name(app_id: &AppId) -> String {
    format!("lunepack-{}", app_id.as_str())
}

/// The display name of the service: `<name> Update Service`, control characters dropped, cut to
/// 256 UTF-16 units without splitting a character.
pub fn display_name(name: &str) -> String {
    let mut out = String::new();
    let mut units = 0usize;
    for c in format!("{name} Update Service").chars() {
        if c.is_control() {
            continue;
        }
        units += c.len_utf16();
        if units > MAX_DISPLAY_UNITS {
            break;
        }
        out.push(c);
    }
    out
}

/// The image path as the SCM stores it: the absolute path in double quotes, no arguments. A path
/// that is not absolute, is not valid text, or holds a quote or a control character is refused
/// (the service's command line would not be the path alone).
pub fn quote_image(image: &Path) -> Result<String, ServiceRegError> {
    let text = image
        .to_str()
        .ok_or(ServiceRegError::Os("the image path is not text"))?;
    if !image.is_absolute() || text.chars().any(|c| c == '"' || c.is_control()) {
        return Err(ServiceRegError::Os("the image path is not usable"));
    }
    Ok(format!("\"{text}\""))
}

/// The path inside a stored image string: exactly one quoted path and nothing after it, or an
/// unquoted path without a space-separated argument. Anything else is `None`.
pub fn unquote_image(stored: &str) -> Option<PathBuf> {
    let path = if let Some(rest) = stored.strip_prefix('"') {
        rest.strip_suffix('"').filter(|p| !p.contains('"'))?
    } else if stored.contains(['"', ' ']) {
        return None;
    } else {
        stored
    };
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// The descriptor text to apply: the explicit owner Administrators, then `default_dacl` (the DACL
/// of the new service in descriptor text, as `ConvertSecurityDescriptorToStringSecurityDescriptor`
/// writes it for the DACL alone) with [`USERS_ENTRY`] appended. `None` when `default_dacl` is not
/// a DACL alone with at least one entry.
pub fn with_users_entry(default_dacl: &str) -> Option<String> {
    let body = default_dacl.strip_prefix("D:")?;
    let clean = !body.contains("O:") && !body.contains("G:") && !body.contains("S:");
    (clean && body.ends_with(')')).then(|| format!("O:BA{default_dacl}{USERS_ENTRY}"))
}

/// Judges a service descriptor as read back: the owner is LocalSystem, Administrators or
/// TrustedInstaller; the DACL is present; every entry is an allow or deny of a plain type; an allow
/// entry for any SID outside those three holds only rights from [`NON_ADMIN_ALLOWED`]; and Users
/// hold exactly [`USERS_MASK`]. The error is a fixed description.
pub fn judge_service_descriptor(descriptor: &Descriptor) -> Result<(), &'static str> {
    let trusted =
        |sid: &str| sid == SID_SYSTEM || sid == SID_ADMINISTRATORS || sid == SID_TRUSTED_INSTALLER;
    if !trusted(&descriptor.owner) {
        return Err("the service's owner is not an administrator account");
    }
    let entries = descriptor
        .entries
        .as_ref()
        .ok_or("the service has no access list")?;
    let mut users = 0u32;
    for ace in entries {
        match ace.kind {
            ACE_DENIED | ACE_DENIED_CALLBACK => continue,
            ACE_ALLOWED | ACE_ALLOWED_CALLBACK => {}
            _ => return Err("the service has an entry of an unknown kind"),
        }
        if trusted(&ace.sid) {
            continue;
        }
        if ace.mask & !NON_ADMIN_ALLOWED != 0 {
            return Err("an account outside the administrators may change the service");
        }
        if ace.sid == SID_USERS {
            users |= ace.mask;
        }
    }
    if users != USERS_MASK {
        return Err("Users do not hold exactly start, query status and read control");
    }
    Ok(())
}

#[cfg(windows)]
pub use ffi::{HostError, ServiceControl, WindowsConnector, WindowsRegistrar, run_service};

#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi {
    use std::ffi::c_void;
    use std::fmt;
    use std::os::windows::ffi::OsStrExt as _;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Duration, Instant};

    use lunepack_core::service::Duplex;
    use lunepack_core::{AppId, ConnectError, ServiceConnector, ServiceRegError, ServiceRegistrar};
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT,
        ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DISABLED,
        ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_EXISTS, ERROR_SERVICE_MARKED_FOR_DELETE,
        ERROR_SERVICE_NOT_ACTIVE, GetLastError, NO_ERROR, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
        OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW, QueryServiceObjectSecurity,
        QueryServiceStatusEx, RegisterServiceCtrlHandlerExW, SC_HANDLE, SC_MANAGER_CONNECT,
        SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_ACCEPT_SHUTDOWN,
        SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS, SERVICE_CHANGE_CONFIG,
        SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_NO_CHANGE,
        SERVICE_QUERY_CONFIG as SC_SERVICE_QUERY_CONFIG,
        SERVICE_QUERY_STATUS as SC_SERVICE_QUERY_STATUS, SERVICE_RUNNING,
        SERVICE_START as SC_SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS,
        SERVICE_STATUS_HANDLE, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOP_PENDING,
        SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceObjectSecurity,
        SetServiceStatus, StartServiceCtrlDispatcherW, StartServiceW,
    };
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, GetExitCodeProcess,
        PROCESS_INFORMATION, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
    };

    use super::{
        READ_CONTROL, display_name, judge_service_descriptor, pipe_name, quote_image, service_name,
        unquote_image, with_users_entry,
    };
    use crate::pipe::{ExpectedOwner, PipeClient, PipeError};
    use crate::security::{HandleGuard, LocalGuard, sd_descriptor, wide};

    /// `DELETE`.
    const DELETE: u32 = 0x0001_0000;
    /// How long `remove` waits for a running service to stop.
    const STOP_WAIT: Duration = Duration::from_secs(30);
    /// How long a self-test may run.
    const SELF_TEST_LIMIT: Duration = Duration::from_secs(10);
    /// The default time [`WindowsConnector`] waits for the service's pipe.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
    /// How long one attempt to open the pipe lasts before the service's state is looked at again.
    const PIPE_SLICE: Duration = Duration::from_secs(2);
    /// The most times the connector starts a service that keeps stopping before it gives up.
    const MAX_STARTS: u32 = 3;
    /// The pause between two looks at a service's state.
    const POLL: Duration = Duration::from_millis(100);

    /// The last Windows error code.
    fn last_error() -> u32 {
        // SAFETY: `GetLastError` takes no argument.
        unsafe { GetLastError() }
    }

    /// An open SCM or service handle; closed on drop.
    struct Sc(SC_HANDLE);

    impl Drop for Sc {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the handle came from a successful open or create call, is owned by this
                // guard alone, and is closed exactly once here.
                unsafe { CloseServiceHandle(self.0) };
            }
        }
    }

    /// Opens the service control manager with `access`; the error is the Windows code.
    fn open_manager(access: u32) -> Result<Sc, u32> {
        // SAFETY: null machine and database names mean the local active database.
        let handle = unsafe { OpenSCManagerW(null(), null(), access) };
        if handle.is_null() {
            return Err(last_error());
        }
        Ok(Sc(handle))
    }

    /// Opens the service `name` with `access`; the error is the Windows code.
    fn open_service(manager: &Sc, name: &str, access: u32) -> Result<Sc, u32> {
        let name = wide(name);
        // SAFETY: `manager` is an open SCM handle; `name` is a NUL-terminated `u16` buffer that
        // outlives the call.
        let handle = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
        if handle.is_null() {
            return Err(last_error());
        }
        Ok(Sc(handle))
    }

    /// The current state of `service` (needs query-status).
    fn state_of(service: &Sc) -> Result<u32, u32> {
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0u32;
        // SAFETY: `status` is a writable `SERVICE_STATUS_PROCESS`, its exact size is passed, and
        // the call writes at most that many bytes through the pointer.
        let ok = unsafe {
            QueryServiceStatusEx(
                service.0,
                SC_STATUS_PROCESS_INFO,
                (&raw mut status).cast::<u8>(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(status.dwCurrentState)
    }

    // ---- the registrar ----------------------------------------------------------------------

    /// The core's `ServiceRegistrar` over the SCM. Needs an administrator's token (it creates and
    /// deletes services and sets their descriptors).
    #[derive(Debug, Clone)]
    pub struct WindowsRegistrar {
        display_name: String,
    }

    /// Why one creation attempt did not produce a service.
    enum CreateError {
        Exists,
        MarkedForDelete,
        Other(ServiceRegError),
    }

    impl WindowsRegistrar {
        /// A registrar whose services show `app_name` as `<app_name> Update Service` (cut to 256
        /// characters).
        pub fn new(app_name: &str) -> WindowsRegistrar {
            WindowsRegistrar {
                display_name: display_name(app_name),
            }
        }

        /// Registers the service of `app_id` with the binary `image`: own process, demand start,
        /// LocalSystem, the quoted image path, the default descriptor plus Users' start and
        /// query-status entry, read back and judged. An existing service of that name is an error
        /// and is left as it is; a registration that fails the read-back is deleted again.
        pub fn register_new(&self, app_id: &AppId, image: &Path) -> Result<(), ServiceRegError> {
            match self.create(app_id, image) {
                Ok(()) => Ok(()),
                Err(CreateError::Exists | CreateError::MarkedForDelete) => {
                    Err(ServiceRegError::Os("the service exists already"))
                }
                Err(CreateError::Other(e)) => Err(e),
            }
        }

        /// The owner and the access list of the service as the SCM holds them (for the tests and
        /// the acceptance script).
        pub fn descriptor(
            &self,
            app_id: &AppId,
        ) -> Result<crate::security::Descriptor, ServiceRegError> {
            let manager = open_manager(SC_MANAGER_CONNECT)
                .map_err(|_| ServiceRegError::Os("open the service manager"))?;
            let service = open_service(&manager, &service_name(app_id), READ_CONTROL)
                .map_err(not_registered)?;
            read_descriptor(&service)
        }

        fn create(&self, app_id: &AppId, image: &Path) -> Result<(), CreateError> {
            let quoted = wide(&quote_image(image).map_err(CreateError::Other)?);
            let name = wide(&service_name(app_id));
            let display = wide(&self.display_name);
            let manager = open_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)
                .map_err(|_| CreateError::Other(ServiceRegError::Os("open the service manager")))?;
            // SAFETY: `manager` is an open SCM handle; every string is a NUL-terminated `u16`
            // buffer that outlives the call; the load-order group, tag, dependencies, account
            // (LocalSystem) and password are null.
            let handle = unsafe {
                CreateServiceW(
                    manager.0,
                    name.as_ptr(),
                    display.as_ptr(),
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_NORMAL,
                    quoted.as_ptr(),
                    null(),
                    null_mut(),
                    null(),
                    null(),
                    null(),
                )
            };
            if handle.is_null() {
                return Err(match last_error() {
                    ERROR_SERVICE_EXISTS => CreateError::Exists,
                    ERROR_SERVICE_MARKED_FOR_DELETE => CreateError::MarkedForDelete,
                    _ => CreateError::Other(ServiceRegError::Os("create the service")),
                });
            }
            let service = Sc(handle);
            if let Err(e) = apply_descriptor(&service) {
                // SAFETY: `service` is an open service handle with delete access.
                unsafe { DeleteService(service.0) };
                return Err(CreateError::Other(e));
            }
            Ok(())
        }
    }

    /// Reads the owner and the access list of `service` (needs read-control).
    fn read_descriptor(service: &Sc) -> Result<crate::security::Descriptor, ServiceRegError> {
        let buffer = query_security(
            service,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        )?;
        sd_descriptor(buffer.as_ptr().cast_mut().cast())
            .map_err(|_| ServiceRegError::Os("read the service's descriptor"))
    }

    /// The self-relative descriptor of `service` for `information`, in an 8-byte aligned buffer.
    fn query_security(service: &Sc, information: u32) -> Result<Vec<u64>, ServiceRegError> {
        const FAIL: ServiceRegError = ServiceRegError::Os("read the service's descriptor");
        let mut needed = 0u32;
        // SAFETY: a null buffer of size zero only asks for the size needed; `needed` is writable.
        let ok = unsafe {
            QueryServiceObjectSecurity(service.0, information, null_mut(), 0, &mut needed)
        };
        if ok != 0 || last_error() != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
            return Err(FAIL);
        }
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        let size = u32::try_from(buffer.len() * 8).map_err(|_| FAIL)?;
        // SAFETY: `buffer` is writable for `size` bytes and 8-byte aligned; `needed` is writable.
        let ok = unsafe {
            QueryServiceObjectSecurity(
                service.0,
                information,
                buffer.as_mut_ptr().cast(),
                size,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(FAIL);
        }
        Ok(buffer)
    }

    /// Gives `service` the default descriptor plus Users' entry and an explicit owner, then reads
    /// it back and judges it.
    fn apply_descriptor(service: &Sc) -> Result<(), ServiceRegError> {
        const FAIL: ServiceRegError = ServiceRegError::Os("set the service's descriptor");
        let default = query_security(service, DACL_SECURITY_INFORMATION)?;
        let mut text: *mut u16 = null_mut();
        // SAFETY: `default` holds a self-relative descriptor the SCM wrote; `text` is a valid out
        // pointer; on success the system hands over a NUL-terminated string it allocated with
        // `LocalAlloc`, which the guard below releases.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                default.as_ptr().cast_mut().cast(),
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(FAIL);
        }
        let _free = LocalGuard(text.cast());
        // SAFETY: `text` is non-null and NUL-terminated (the call succeeded), so scanning for the
        // terminator stays inside the allocation, which the guard keeps alive.
        let units = unsafe {
            let mut len = 0usize;
            while *text.add(len) != 0 {
                len += 1;
            }
            std::slice::from_raw_parts(text, len)
        };
        let dacl = String::from_utf16(units).map_err(|_| FAIL)?;
        let composed = wide(&with_users_entry(&dacl).ok_or(FAIL)?);
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `composed` is a NUL-terminated `u16` buffer; `descriptor` is a valid out
        // pointer; on success the system allocates the descriptor with `LocalAlloc`.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                composed.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(FAIL);
        }
        let _descriptor = LocalGuard(descriptor);
        // SAFETY: `service` has write-DAC and write-owner access (created with all access);
        // `descriptor` is a valid self-relative descriptor kept alive by the guard.
        let ok = unsafe {
            SetServiceObjectSecurity(
                service.0,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                descriptor,
            )
        };
        if ok == 0 {
            return Err(FAIL);
        }
        judge_service_descriptor(&read_descriptor(service)?).map_err(ServiceRegError::Os)
    }

    fn not_registered(code: u32) -> ServiceRegError {
        if code == ERROR_SERVICE_DOES_NOT_EXIST {
            ServiceRegError::NotRegistered
        } else {
            ServiceRegError::Os("open the service")
        }
    }

    /// The text of the wide string `at` points to, which must lie inside the `len` bytes from
    /// `base`; `None` when it does not end there.
    fn wide_in(base: *const u8, len: usize, at: *const u16) -> Option<String> {
        let start = (at as usize).checked_sub(base as usize)?;
        if at.is_null() || start >= len || start % 2 != 0 {
            return None;
        }
        let max = (len - start) / 2;
        let mut n = 0usize;
        // SAFETY: `at` lies inside the buffer (checked above) and every read stays below `max`
        // units, the buffer's end.
        while n < max && unsafe { *at.add(n) } != 0 {
            n += 1;
        }
        if n == max {
            return None;
        }
        // SAFETY: the `n` units from `at` were just read inside the buffer.
        String::from_utf16(unsafe { std::slice::from_raw_parts(at, n) }).ok()
    }

    /// Stops `service` when it runs and waits up to `limit` for it to be stopped.
    fn stop_and_wait(service: &Sc, limit: Duration) -> Result<(), ServiceRegError> {
        let end = Instant::now() + limit;
        loop {
            let state = state_of(service).map_err(|_| ServiceRegError::Os("query the service"))?;
            if state == SERVICE_STOPPED {
                return Ok(());
            }
            if state != SERVICE_STOP_PENDING {
                let mut status = SERVICE_STATUS::default();
                // SAFETY: `service` has stop access; `status` is a writable `SERVICE_STATUS`.
                let ok = unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) };
                if ok == 0 && last_error() == ERROR_SERVICE_NOT_ACTIVE {
                    return Ok(());
                }
            }
            if Instant::now() >= end {
                return Err(ServiceRegError::Os("the service did not stop"));
            }
            std::thread::sleep(POLL);
        }
    }

    impl ServiceRegistrar for WindowsRegistrar {
        fn register(&self, app_id: &AppId, image: &Path) -> Result<(), ServiceRegError> {
            self.remove(app_id)?;
            // A service the SCM still holds open elsewhere stays "marked for delete" until the
            // last handle closes; give it a moment.
            let end = Instant::now() + Duration::from_secs(10);
            loop {
                match self.create(app_id, image) {
                    Ok(()) => return Ok(()),
                    Err(CreateError::MarkedForDelete) if Instant::now() < end => {
                        std::thread::sleep(Duration::from_millis(250));
                    }
                    Err(CreateError::MarkedForDelete | CreateError::Exists) => {
                        return Err(ServiceRegError::Os(
                            "the old service is still being deleted",
                        ));
                    }
                    Err(CreateError::Other(e)) => return Err(e),
                }
            }
        }

        fn image(&self, app_id: &AppId) -> Result<Option<PathBuf>, ServiceRegError> {
            let manager = open_manager(SC_MANAGER_CONNECT)
                .map_err(|_| ServiceRegError::Os("open the service manager"))?;
            let service =
                match open_service(&manager, &service_name(app_id), SC_SERVICE_QUERY_CONFIG) {
                    Ok(service) => service,
                    Err(ERROR_SERVICE_DOES_NOT_EXIST) => return Ok(None),
                    Err(_) => return Err(ServiceRegError::Os("open the service")),
                };
            const FAIL: ServiceRegError = ServiceRegError::Os("read the service's configuration");
            let mut needed = 0u32;
            // SAFETY: a null buffer of size zero only asks for the size needed.
            let ok = unsafe { QueryServiceConfigW(service.0, null_mut(), 0, &mut needed) };
            if ok != 0 || last_error() != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
                return Err(FAIL);
            }
            let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
            let size = u32::try_from(buffer.len() * 8).map_err(|_| FAIL)?;
            // SAFETY: `buffer` is writable for `size` bytes and 8-byte aligned, which is what a
            // `QUERY_SERVICE_CONFIGW` followed by its strings needs.
            let ok = unsafe {
                QueryServiceConfigW(
                    service.0,
                    buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>(),
                    size,
                    &mut needed,
                )
            };
            if ok == 0 {
                return Err(FAIL);
            }
            // SAFETY: the call succeeded, so the start of the buffer holds a `QUERY_SERVICE_CONFIGW`
            // (aligned, see above); only its binary-path pointer is read.
            let path =
                unsafe { (*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>()).lpBinaryPathName };
            let text = wide_in(buffer.as_ptr().cast(), buffer.len() * 8, path).ok_or(FAIL)?;
            unquote_image(&text).map(Some).ok_or(ServiceRegError::Os(
                "the registered image path is unexpected",
            ))
        }

        fn set_image(&self, app_id: &AppId, image: &Path) -> Result<(), ServiceRegError> {
            let quoted = wide(&quote_image(image)?);
            let manager = open_manager(SC_MANAGER_CONNECT)
                .map_err(|_| ServiceRegError::Os("open the service manager"))?;
            let service = open_service(&manager, &service_name(app_id), SERVICE_CHANGE_CONFIG)
                .map_err(not_registered)?;
            // SAFETY: `service` has change-config access; every unchanged setting is
            // `SERVICE_NO_CHANGE` or null; `quoted` is a NUL-terminated `u16` buffer that outlives
            // the call.
            let ok = unsafe {
                windows_sys::Win32::System::Services::ChangeServiceConfigW(
                    service.0,
                    SERVICE_NO_CHANGE,
                    SERVICE_NO_CHANGE,
                    SERVICE_NO_CHANGE,
                    quoted.as_ptr(),
                    null(),
                    null_mut(),
                    null(),
                    null(),
                    null(),
                    null(),
                )
            };
            if ok == 0 {
                return Err(ServiceRegError::Os("change the service's image"));
            }
            Ok(())
        }

        fn self_test(&self, image: &Path) -> Result<(), ServiceRegError> {
            self_test(image)
        }

        fn remove(&self, app_id: &AppId) -> Result<(), ServiceRegError> {
            let manager = open_manager(SC_MANAGER_CONNECT)
                .map_err(|_| ServiceRegError::Os("open the service manager"))?;
            let service = match open_service(
                &manager,
                &service_name(app_id),
                SERVICE_STOP | SC_SERVICE_QUERY_STATUS | DELETE,
            ) {
                Ok(service) => service,
                Err(ERROR_SERVICE_DOES_NOT_EXIST) => return Ok(()),
                Err(_) => return Err(ServiceRegError::Os("open the service")),
            };
            stop_and_wait(&service, STOP_WAIT)?;
            // SAFETY: `service` is an open service handle with delete access.
            if unsafe { DeleteService(service.0) } == 0
                && last_error() != ERROR_SERVICE_MARKED_FOR_DELETE
            {
                return Err(ServiceRegError::Os("delete the service"));
            }
            Ok(())
        }
    }

    // ---- the self-test ----------------------------------------------------------------------

    /// The system's Windows directory, asked of the system (never of the environment).
    fn system_root() -> Option<Vec<u16>> {
        let mut buffer = [0u16; 520];
        // SAFETY: `buffer` is writable for its stated length in `u16` units.
        let n = unsafe { GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        let n = n as usize;
        (n > 0 && n < buffer.len()).then(|| buffer[..n].to_vec())
    }

    /// Runs `image --self-test` once: no window, no inherited handle and no standard handles, the
    /// environment holding only `SystemRoot`, the working directory the image's folder. Exit code
    /// 0 within [`SELF_TEST_LIMIT`] is success; a timeout kills the process.
    fn self_test(image: &Path) -> Result<(), ServiceRegError> {
        const FAIL: ServiceRegError = ServiceRegError::SelfTestFailed;
        let quoted = quote_image(image).map_err(|_| FAIL)?;
        let folder = image.parent().ok_or(FAIL)?;
        let app: Vec<u16> = image
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut command = wide(&format!("{quoted} --self-test"));
        let dir: Vec<u16> = folder
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut environment: Vec<u16> = "SystemRoot=".encode_utf16().collect();
        environment.extend(system_root().ok_or(FAIL)?);
        environment.extend([0, 0]);
        if app[..app.len() - 1].contains(&0) {
            return Err(FAIL);
        }
        // SAFETY: an all-zero `STARTUPINFOW` is valid; only `cb` is set (no standard handles are
        // requested, since `dwFlags` stays 0).
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        // SAFETY: an all-zero `PROCESS_INFORMATION` is valid; the call fills it.
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `app`, `dir` and `environment` are NUL-terminated (the environment doubly) `u16`
        // buffers and `command` a writable NUL-terminated one, all outliving the call; the
        // security attributes are null; handle inheritance is off, so the child holds none of this
        // process's handles; `startup` and `info` are valid for the call.
        let ok = unsafe {
            CreateProcessW(
                app.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                0,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast::<c_void>(),
                dir.as_ptr(),
                &startup,
                &mut info,
            )
        };
        if ok == 0 {
            return Err(FAIL);
        }
        let _thread = HandleGuard(info.hThread);
        let process = HandleGuard(info.hProcess);
        // SAFETY: `process` is an open process handle with synchronize access.
        let waited = unsafe { WaitForSingleObject(process.0, SELF_TEST_LIMIT.as_millis() as u32) };
        if waited != WAIT_OBJECT_0 {
            // SAFETY: `process` is an open process handle with terminate access (the handle
            // `CreateProcessW` returns has all access).
            unsafe { TerminateProcess(process.0, 1) };
            // SAFETY: as above; reaps the process so no handle outlives it by long.
            unsafe { WaitForSingleObject(process.0, 5_000) };
            return Err(FAIL);
        }
        let mut code = 1u32;
        // SAFETY: `process` is an open process handle; `code` is writable.
        let ok = unsafe { GetExitCodeProcess(process.0, &mut code) };
        if ok != 0 && code == 0 {
            Ok(())
        } else {
            Err(FAIL)
        }
    }

    // ---- the connector ----------------------------------------------------------------------

    /// The core's `ServiceConnector` over the SCM and the named pipe: starts the update service
    /// when it is not running (a standard user may, M10-D10), then opens the pipe and checks that
    /// LocalSystem owns it. Never elevates and never prompts.
    #[derive(Debug, Clone)]
    pub struct WindowsConnector {
        timeout: Duration,
    }

    impl Default for WindowsConnector {
        fn default() -> Self {
            WindowsConnector::new()
        }
    }

    impl WindowsConnector {
        /// A connector that waits up to 30 seconds for the service's pipe.
        pub fn new() -> WindowsConnector {
            WindowsConnector {
                timeout: CONNECT_TIMEOUT,
            }
        }

        /// A connector that waits up to `timeout` for the service's pipe.
        pub fn with_timeout(timeout: Duration) -> WindowsConnector {
            WindowsConnector { timeout }
        }
    }

    /// Makes sure `service` is running or starting, waiting for a stop in progress first.
    fn ensure_started(service: &Sc, end: Instant, starts: &mut u32) -> Result<(), ConnectError> {
        loop {
            let state = state_of(service).map_err(|_| ConnectError::Failed("query the service"))?;
            match state {
                SERVICE_RUNNING | SERVICE_START_PENDING => return Ok(()),
                SERVICE_STOP_PENDING => {
                    if Instant::now() >= end {
                        return Err(ConnectError::Failed("the service did not stop"));
                    }
                    std::thread::sleep(POLL);
                }
                _ => {
                    if *starts >= MAX_STARTS {
                        return Err(ConnectError::Failed("the service keeps stopping"));
                    }
                    *starts += 1;
                    // SAFETY: `service` has start access; no arguments are passed.
                    if unsafe { StartServiceW(service.0, 0, null()) } != 0 {
                        return Ok(());
                    }
                    return match last_error() {
                        ERROR_SERVICE_ALREADY_RUNNING => Ok(()),
                        ERROR_SERVICE_DISABLED => Err(ConnectError::Disabled),
                        ERROR_SERVICE_DOES_NOT_EXIST | ERROR_SERVICE_MARKED_FOR_DELETE => {
                            Err(ConnectError::NotInstalled)
                        }
                        ERROR_ACCESS_DENIED => Err(ConnectError::Failed("not allowed to start")),
                        _ => Err(ConnectError::Failed("start the service")),
                    };
                }
            }
        }
    }

    impl ServiceConnector for WindowsConnector {
        fn connect(&self, app_id: &AppId) -> Result<Box<dyn Duplex>, ConnectError> {
            let end = Instant::now() + self.timeout;
            let manager = open_manager(SC_MANAGER_CONNECT)
                .map_err(|_| ConnectError::Failed("open the service manager"))?;
            let service = match open_service(
                &manager,
                &service_name(app_id),
                SC_SERVICE_START | SC_SERVICE_QUERY_STATUS,
            ) {
                Ok(service) => service,
                Err(ERROR_SERVICE_DOES_NOT_EXIST) => return Err(ConnectError::NotInstalled),
                Err(ERROR_ACCESS_DENIED) => {
                    return Err(ConnectError::Failed("not allowed to start"));
                }
                Err(_) => return Err(ConnectError::Failed("open the service")),
            };
            let pipe = pipe_name(app_id);
            let mut starts = 0u32;
            loop {
                ensure_started(&service, end, &mut starts)?;
                let left = end.saturating_duration_since(Instant::now());
                match PipeClient::connect(&pipe, ExpectedOwner::LocalSystem, left.min(PIPE_SLICE)) {
                    Ok(client) => return Ok(Box::new(client)),
                    Err(PipeError::Untrusted) => return Err(ConnectError::WrongOwner),
                    Err(PipeError::Busy | PipeError::NotFound | PipeError::Timeout)
                        if Instant::now() < end => {}
                    Err(PipeError::Busy) => return Err(ConnectError::Busy),
                    Err(PipeError::NotFound | PipeError::Timeout) => {
                        return Err(ConnectError::Failed("the service's pipe did not appear"));
                    }
                    Err(_) => return Err(ConnectError::Failed("open the service's pipe")),
                }
            }
        }
    }

    // ---- the service side -------------------------------------------------------------------

    /// Why [`run_service`] ended without running the body to its end.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum HostError {
        /// The process was not started by the service control manager (the dispatcher could not
        /// connect to it): run from a console, for instance.
        NotAService,
        /// The service name is empty or holds a NUL.
        InvalidName,
        /// Another call of [`run_service`] holds the process's one service slot.
        InUse,
        /// The SCM refused (what was attempted and the Windows error code).
        Os {
            /// The attempted operation (a fixed description).
            what: &'static str,
            /// The Windows error code.
            code: u32,
        },
    }

    impl fmt::Display for HostError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                HostError::NotAService => f.write_str("not started by the service control manager"),
                HostError::InvalidName => f.write_str("not a valid service name"),
                HostError::InUse => f.write_str("a service is running in this process already"),
                HostError::Os { what, code } => write!(f, "{what} failed (Windows error {code})"),
            }
        }
    }

    impl std::error::Error for HostError {}

    /// A stop hook: runs once when a stop or a shutdown arrives.
    type Hook = Box<dyn FnOnce() + Send>;

    /// The state the control handler and the service's main thread share.
    struct Shared {
        stop: Arc<AtomicBool>,
        hooks: Mutex<Vec<Hook>>,
        status: Mutex<Status>,
    }

    /// What the SCM was last told.
    struct Status {
        handle: StatusHandle,
        state: u32,
        checkpoint: u32,
    }

    /// A service status handle (a kernel-side token, usable from any thread).
    struct StatusHandle(SERVICE_STATUS_HANDLE);

    // SAFETY: a status handle is an opaque token the SCM accepts from any thread; it is only used
    // under the `Status` mutex.
    unsafe impl Send for StatusHandle {}

    fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    impl Shared {
        /// Tells the SCM the state, unless it was told `SERVICE_STOPPED` already or a stop is
        /// pending and this is not the final report.
        fn report(&self, state: u32, exit_code: u32) {
            let mut status = locked(&self.status);
            if status.state == SERVICE_STOPPED
                || (status.state == SERVICE_STOP_PENDING && state != SERVICE_STOPPED)
            {
                return;
            }
            let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
            if pending {
                status.checkpoint += 1;
            } else {
                status.checkpoint = 0;
            }
            let report = SERVICE_STATUS {
                dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                dwCurrentState: state,
                dwControlsAccepted: if state == SERVICE_RUNNING {
                    SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
                } else {
                    0
                },
                dwWin32ExitCode: exit_code,
                dwServiceSpecificExitCode: 0,
                dwCheckPoint: status.checkpoint,
                dwWaitHint: if pending { 10_000 } else { 0 },
            };
            // SAFETY: the handle came from `RegisterServiceCtrlHandlerExW`; `report` is a valid
            // `SERVICE_STATUS` that lives for the call.
            unsafe { SetServiceStatus(status.handle.0, &report) };
            status.state = state;
        }

        /// Sets the stop flag and runs the hooks, once.
        fn request_stop(&self) {
            let hooks = {
                let mut hooks = locked(&self.hooks);
                self.stop.store(true, Ordering::SeqCst);
                std::mem::take(&mut *hooks)
            };
            for hook in hooks {
                hook();
            }
        }
    }

    /// What the service's body gets: a flag to poll and hooks that run when the SCM asks the
    /// service to stop (a stop or a shutdown). Cheap to clone.
    #[derive(Clone)]
    pub struct ServiceControl {
        shared: Arc<Shared>,
    }

    impl ServiceControl {
        /// Whether the SCM asked the service to stop.
        pub fn stop_requested(&self) -> bool {
            self.shared.stop.load(Ordering::SeqCst)
        }

        /// The flag [`ServiceControl::stop_requested`] reads.
        pub fn stop_flag(&self) -> Arc<AtomicBool> {
            Arc::clone(&self.shared.stop)
        }

        /// Runs `hook` once when the SCM asks the service to stop: on the control thread, at that
        /// moment, or at once (on this thread) when the request came already. Meant for ending a
        /// blocked accept (`PipeCanceller::cancel`).
        pub fn on_stop(&self, hook: impl FnOnce() + Send + 'static) {
            let run_now = {
                let mut hooks = locked(&self.shared.hooks);
                if self.shared.stop.load(Ordering::SeqCst) {
                    Some(hook)
                } else {
                    hooks.push(Box::new(hook));
                    None
                }
            };
            if let Some(hook) = run_now {
                hook();
            }
        }
    }

    /// The body [`run_service`] was given, waiting for the dispatcher to call `service_main`.
    type Body = Box<dyn FnOnce(ServiceControl) -> u32 + Send>;

    /// The process's one service: its name (wide) and body, until `service_main` takes them.
    static PENDING: Mutex<Option<(Vec<u16>, Body)>> = Mutex::new(None);
    /// Why `service_main` could not run the body, when it could not.
    static FAILED: Mutex<Option<HostError>> = Mutex::new(None);

    /// The control handler: stop and shutdown stop the service, interrogate is answered, anything
    /// else is not implemented.
    unsafe extern "system" fn control_handler(
        control: u32,
        _event: u32,
        _data: *mut c_void,
        context: *mut c_void,
    ) -> u32 {
        // SAFETY: `context` is the pointer `service_main` made with `Arc::into_raw` and never
        // gave back, so the `Shared` it names lives for the rest of the process.
        let shared = unsafe { &*context.cast::<Shared>() };
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                shared.report(SERVICE_STOP_PENDING, 0);
                shared.request_stop();
                NO_ERROR
            }
            SERVICE_CONTROL_INTERROGATE => NO_ERROR,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }

    /// The dispatcher's entry: registers the control handler, reports the state changes and runs
    /// the body.
    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
        let Some((name, body)) = locked(&PENDING).take() else {
            return;
        };
        let shared = Arc::new(Shared {
            stop: Arc::new(AtomicBool::new(false)),
            hooks: Mutex::new(Vec::new()),
            status: Mutex::new(Status {
                handle: StatusHandle(null_mut()),
                state: 0,
                checkpoint: 0,
            }),
        });
        // One reference is handed to the control handler and deliberately never taken back: the
        // SCM may call the handler until the process ends, and the process ends right after.
        let context = Arc::into_raw(Arc::clone(&shared)).cast::<c_void>();
        // SAFETY: `name` is a NUL-terminated `u16` buffer; the handler is a valid
        // `extern "system"` function; `context` stays valid for the process's life (see above).
        let handle =
            unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), context) };
        if handle.is_null() {
            *locked(&FAILED) = Some(HostError::Os {
                what: "register the control handler",
                code: last_error(),
            });
            return;
        }
        locked(&shared.status).handle = StatusHandle(handle);
        shared.report(SERVICE_START_PENDING, 0);
        shared.report(SERVICE_RUNNING, 0);
        let control = ServiceControl {
            shared: Arc::clone(&shared),
        };
        let code = catch_unwind(AssertUnwindSafe(|| body(control))).unwrap_or(1);
        shared.report(SERVICE_STOP_PENDING, 0);
        shared.report(SERVICE_STOPPED, code);
    }

    /// Hands the process to the service control manager and runs `body` as the service `name`
    /// (the name an own-process service is registered under is not checked by the SCM, but must be
    /// given). `body` runs on the service's main thread after the service reported running, gets
    /// the [`ServiceControl`], and returns the Windows exit code reported with the stop (0 for
    /// success); a panic in it reports 1. Returns when the service has stopped.
    ///
    /// When the process was not started by the SCM (the dispatcher cannot connect to it) nothing
    /// runs and the error is [`HostError::NotAService`], so the binary can exit.
    pub fn run_service<F>(name: &str, body: F) -> Result<(), HostError>
    where
        F: FnOnce(ServiceControl) -> u32 + Send + 'static,
    {
        if name.is_empty() || name.contains('\0') {
            return Err(HostError::InvalidName);
        }
        let name = wide(name);
        {
            let mut pending = locked(&PENDING);
            if pending.is_some() {
                return Err(HostError::InUse);
            }
            *pending = Some((name.clone(), Box::new(body)));
        }
        *locked(&FAILED) = None;
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: name.as_ptr().cast_mut(),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: null_mut(),
                lpServiceProc: None,
            },
        ];
        // SAFETY: `table` is a valid, null-terminated table that outlives the call; `name` lives
        // until the call returns; the dispatcher only reads the table.
        let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
        if ok == 0 {
            let code = last_error();
            *locked(&PENDING) = None;
            return Err(if code == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
                HostError::NotAService
            } else if code == ERROR_SERVICE_ALREADY_RUNNING {
                // A process may call the dispatcher once.
                HostError::InUse
            } else {
                HostError::Os {
                    what: "start the service dispatcher",
                    code,
                }
            });
        }
        match locked(&FAILED).take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::Ace;

    fn app(id: &str) -> AppId {
        AppId::parse(id).expect("a valid app id")
    }

    #[test]
    fn the_service_and_the_pipe_are_named_after_the_app_id() {
        assert_eq!(
            service_name(&app("com.acme.tool")),
            "lunepack-com.acme.tool"
        );
        assert_eq!(pipe_name(&app("com.acme.tool")), "lunepack-com.acme.tool");
    }

    #[test]
    fn the_display_name_is_cut_to_256_units_without_splitting_a_character() {
        assert_eq!(display_name("Acme"), "Acme Update Service");
        let long = display_name(&"x".repeat(1000));
        assert_eq!(long.encode_utf16().count(), 256);
        // A character outside the basic plane takes two units and is dropped whole at the edge.
        let edge = display_name(&format!("{}\u{1F600}", "x".repeat(255)));
        assert_eq!(edge.encode_utf16().count(), 255);
        assert!(!edge.contains('\u{1F600}'));
        assert!(!display_name("A\nB\0C").contains(['\n', '\0']));
    }

    #[cfg(windows)]
    #[test]
    fn the_image_is_stored_as_the_absolute_path_in_quotes_with_no_arguments() {
        let image = Path::new(
            r"C:\Program Files\Acme App\.lunepack\machine\service\1.0.0\lunepack-service.exe",
        );
        let stored = quote_image(image).expect("quoted");
        assert_eq!(
            stored,
            r#""C:\Program Files\Acme App\.lunepack\machine\service\1.0.0\lunepack-service.exe""#
        );
        assert_eq!(unquote_image(&stored).as_deref(), Some(image));
    }

    #[test]
    fn a_path_that_cannot_stand_alone_in_a_command_line_is_refused() {
        for bad in [r#"C:\a"b\x.exe"#, "C:\\a\nb\\x.exe", r"relative\x.exe", ""] {
            assert!(quote_image(Path::new(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_stored_image_with_arguments_or_stray_quotes_has_no_path() {
        for stored in [
            r#""C:\a\x.exe" --flag"#,
            r#""C:\a\x.exe"#,
            r#"C:\a\x.exe""#,
            r#""C:\a"\x.exe""#,
            r"C:\a b\x.exe --flag",
            r#""""#,
            "",
        ] {
            assert_eq!(unquote_image(stored), None, "{stored:?}");
        }
        assert_eq!(
            unquote_image(r"C:\a\x.exe").as_deref(),
            Some(Path::new(r"C:\a\x.exe"))
        );
    }

    #[test]
    fn users_get_exactly_start_query_status_and_read_control() {
        assert_eq!(USERS_MASK, 0x0002_0014);
        assert_eq!(USERS_ENTRY, "(A;;RPLCRC;;;BU)");
        let default = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";
        let composed = with_users_entry(default).expect("composed");
        assert!(composed.starts_with("O:BAD:("));
        assert!(composed.ends_with("(A;;CCLCSWLOCRRC;;;SU)(A;;RPLCRC;;;BU)"));
        // Only a bare DACL is accepted.
        assert_eq!(with_users_entry("O:SYD:(A;;GA;;;SY)"), None);
        assert_eq!(with_users_entry("D:(A;;GA;;;SY)S:(AU;;GA;;;SY)"), None);
        assert_eq!(with_users_entry("D:"), None);
        assert_eq!(with_users_entry("D:P"), None);
        assert_eq!(with_users_entry(""), None);
    }

    fn allow(sid: &str, mask: u32) -> Ace {
        Ace {
            kind: ACE_ALLOWED,
            sid: sid.to_owned(),
            mask,
            flags: 0,
        }
    }

    fn good() -> Descriptor {
        Descriptor {
            owner: SID_ADMINISTRATORS.to_owned(),
            entries: Some(vec![
                allow(SID_SYSTEM, 0x000f_01ff),
                allow(SID_ADMINISTRATORS, 0x000f_01ff),
                allow("S-1-5-4", 0x0002_018d),
                allow(SID_USERS, USERS_MASK),
            ]),
        }
    }

    #[test]
    fn the_default_descriptor_plus_users_passes_the_read_back() {
        assert_eq!(judge_service_descriptor(&good()), Ok(()));
    }

    #[test]
    fn every_right_that_changes_the_service_fails_for_a_non_administrator() {
        // change config, stop, pause/continue, delete, write DAC, write owner, generic write,
        // generic all, maximum allowed, access system security.
        for bit in [
            0x2u32,
            0x20,
            0x40,
            0x0001_0000,
            0x0004_0000,
            0x0008_0000,
            0x4000_0000,
            0x1000_0000,
            0x0200_0000,
            0x0100_0000,
        ] {
            let mut d = good();
            d.entries
                .as_mut()
                .expect("entries")
                .push(allow("S-1-5-4", bit));
            assert!(
                judge_service_descriptor(&d).is_err(),
                "{bit:#x} for another account"
            );
            let mut d = good();
            d.entries.as_mut().expect("entries")[3] = allow(SID_USERS, USERS_MASK | bit);
            assert!(judge_service_descriptor(&d).is_err(), "{bit:#x} for Users");
        }
    }

    #[test]
    fn the_owner_the_entry_kinds_and_the_users_mask_are_judged() {
        let mut d = good();
        d.owner = "S-1-5-21-1-2-3-1001".to_owned();
        assert!(judge_service_descriptor(&d).is_err(), "a user as owner");
        let mut d = good();
        d.entries = None;
        assert!(judge_service_descriptor(&d).is_err(), "no DACL");
        let mut d = good();
        d.entries.as_mut().expect("entries").push(Ace {
            kind: 5,
            sid: String::new(),
            mask: 0,
            flags: 0,
        });
        assert!(judge_service_descriptor(&d).is_err(), "an object entry");
        // A deny entry removes rights and is skipped.
        let mut d = good();
        d.entries.as_mut().expect("entries").push(Ace {
            kind: ACE_DENIED,
            sid: "S-1-5-4".to_owned(),
            mask: 0x0001_0000,
            flags: 0,
        });
        assert_eq!(judge_service_descriptor(&d), Ok(()));
        // Users must hold exactly the mask: none, or less, fails.
        let mut d = good();
        d.entries.as_mut().expect("entries").pop();
        assert!(judge_service_descriptor(&d).is_err(), "no Users entry");
        let mut d = good();
        d.entries.as_mut().expect("entries")[3] = allow(SID_USERS, SERVICE_START);
        assert!(
            judge_service_descriptor(&d).is_err(),
            "Users cannot read status"
        );
        // The three trusted SIDs may hold anything.
        let mut d = good();
        d.entries
            .as_mut()
            .expect("entries")
            .push(allow(SID_TRUSTED_INSTALLER, 0x000f_01ff));
        assert_eq!(judge_service_descriptor(&d), Ok(()));
    }
}
