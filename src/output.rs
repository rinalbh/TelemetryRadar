//! Preflight user-selected result paths before starting capture or changing trust.
use crate::{Error, Result};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

/// Reject existing files and destinations that resolve to the same output path.
/// Parent symlinks/`..` components are resolved before comparing names. This is
/// only preflight: writers must still use create-new/atomic no-clobber publication.
pub fn validate_new_outputs(paths: &[PathBuf]) -> Result<()> {
    let mut destinations = HashSet::new();
    for path in paths {
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(Error::Invalid(format!(
                    "Output already exists: {}",
                    path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let name = path.file_name().ok_or_else(|| {
            Error::Invalid(format!("Output needs a filename: {}", path.display()))
        })?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let resolved = parent.canonicalize()?.join(name);
        // Windows commonly aliases differently cased filenames. Conservatively
        // reject such collisions, including in case-sensitive Windows directories.
        #[cfg(windows)]
        let resolved = PathBuf::from(resolved.to_string_lossy().to_lowercase());
        if !destinations.insert(resolved) {
            return Err(Error::Invalid(format!(
                "Multiple outputs refer to the same destination: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_aliases_before_any_result_is_created() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("nested")).unwrap();
        let direct = directory.path().join("capture.pcapng");
        let alias = directory.path().join("nested/../capture.pcapng");
        assert!(validate_new_outputs(&[direct.clone(), alias]).is_err());
        assert!(!direct.exists());
    }
    #[test]
    fn preserves_existing_results() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("flows.mitm");
        std::fs::write(&path, b"previous capture").unwrap();
        assert!(validate_new_outputs(std::slice::from_ref(&path)).is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"previous capture");
    }
}
