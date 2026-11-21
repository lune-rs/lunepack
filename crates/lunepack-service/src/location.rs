//! Where the service may run from (M10-D7): its image must be
//! `<R>\.lunepack\machine\service\<version>\lunepack-service.exe` with `<version>` in its canonical
//! text and `<R>`'s parent the Program Files known folder. Anything else is refused before any
//! other action: a copy of the binary somewhere else (a user's folder, a download) never serves a
//! pipe as LocalSystem, and never finds an install root it was not placed in.

use std::path::{Component, Path, PathBuf, Prefix};

use lunepack_core::{MachineLayout, Version};

/// Why an image path is not the service's place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationError {
    /// Not `<R>\.lunepack\machine\service\<version>\lunepack-service.exe` (or not absolute).
    NotAServiceImage,
    /// `<R>` is not directly under the Program Files folder.
    NotUnderProgramFiles,
}

/// Where the service runs from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    /// The install root's layout.
    pub layout: MachineLayout,
    /// The version of this binary (its directory's name).
    pub version: Version,
}

/// Checks `image` (the running binary's own path) against the rule; `program_files` is the known
/// folder, asked of the shell by the caller.
pub fn locate(image: &Path, program_files: &Path) -> Result<Located, LocationError> {
    if !image.is_absolute() || has_dots(image) {
        return Err(LocationError::NotAServiceImage);
    }
    let (layout, version) =
        MachineLayout::of_service_image(image).ok_or(LocationError::NotAServiceImage)?;
    let parent = layout
        .root()
        .parent()
        .ok_or(LocationError::NotUnderProgramFiles)?;
    if !same_folder(parent, program_files) {
        return Err(LocationError::NotUnderProgramFiles);
    }
    Ok(Located { layout, version })
}

fn has_dots(path: &Path) -> bool {
    path.components()
        .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
}

/// The components of `path` in a comparable form: a verbatim drive prefix (`\\?\C:`) reads as the
/// plain one, and names compare without case (Windows paths do not).
fn comparable(path: &Path) -> Vec<String> {
    path.components()
        .map(|c| match c {
            Component::Prefix(p) => match p.kind() {
                Prefix::VerbatimDisk(d) | Prefix::Disk(d) => {
                    format!("{}:", char::from(d).to_ascii_lowercase())
                }
                _ => p.as_os_str().to_string_lossy().to_lowercase(),
            },
            other => other.as_os_str().to_string_lossy().to_lowercase(),
        })
        .collect()
}

fn same_folder(a: &Path, b: &Path) -> bool {
    a.is_absolute()
        && b.is_absolute()
        && !has_dots(a)
        && !has_dots(b)
        && comparable(a) == comparable(b)
}

/// The folder `<R>`'s display name: the last component of the install root.
pub fn display_name(layout: &MachineLayout) -> Option<String> {
    layout
        .root()
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
}

/// The path of the file the service logs to, under `R\.lunepack\logs`.
pub fn log_path(layout: &MachineLayout) -> PathBuf {
    layout.logs_dir().join("service.log")
}
