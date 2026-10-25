use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};
use telemetryradar::opencode::{DiscoveryOptions, DiscoverySource, Error, discover};

fn options() -> DiscoveryOptions {
    DiscoveryOptions {
        executable: None,
        search_path: Some(OsString::new()),
        common_locations: vec![],
    }
}

fn executable(dir: &Path) -> PathBuf {
    let path = dir.join(if cfg!(windows) {
        "opencode.exe"
    } else {
        "opencode"
    });
    std::fs::write(&path, b"discovery fixture; never executed").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    path
}

#[test]
fn precedence_override_then_path_then_common() {
    let root = tempfile::tempdir().unwrap();
    for sub in ["explicit", "path with spaces", "common"] {
        std::fs::create_dir(root.path().join(sub)).unwrap();
    }
    let explicit = executable(&root.path().join("explicit"));
    let path = executable(&root.path().join("path with spaces"));
    let common = executable(&root.path().join("common"));
    let mut inputs = options();
    inputs.executable = Some(explicit.clone());
    inputs.search_path = Some(std::env::join_paths([path.parent().unwrap()]).unwrap());
    inputs.common_locations.push(common.clone());
    let found = discover(&inputs).unwrap();
    assert_eq!(found.source, DiscoverySource::Override);
    assert_eq!(found.executable, explicit.canonicalize().unwrap());
    inputs.executable = None;
    let found = discover(&inputs).unwrap();
    assert_eq!(found.source, DiscoverySource::Path);
    assert_eq!(found.executable, path.canonicalize().unwrap());
    inputs.search_path = None;
    let found = discover(&inputs).unwrap();
    assert_eq!(found.source, DiscoverySource::CommonLocation);
    assert_eq!(found.executable, common.canonicalize().unwrap());
}

#[test]
fn invalid_override_does_not_silently_fall_back() {
    let root = tempfile::tempdir().unwrap();
    let mut inputs = options();
    inputs.common_locations.push(executable(root.path()));
    inputs.executable = Some(root.path().join("missing"));
    assert!(matches!(
        discover(&inputs),
        Err(Error::InvalidExecutable { .. })
    ));
    inputs.executable = Some(root.path().to_path_buf());
    assert!(matches!(
        discover(&inputs),
        Err(Error::InvalidExecutable { .. })
    ));
}

#[test]
fn absent_installation_is_actionable() {
    assert!(matches!(discover(&options()), Err(Error::NotFound)));
}

#[cfg(windows)]
#[test]
fn npm_shim_prefers_native_executable() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("node_modules/@opencode/cli/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let native = executable(&bin);
    let shim = root.path().join("opencode.cmd");
    std::fs::write(&shim, b"fixture shim; never executed").unwrap();
    let mut inputs = options();
    inputs.executable = Some(shim);
    assert_eq!(
        discover(&inputs).unwrap().executable,
        native.canonicalize().unwrap()
    );
}

#[cfg(unix)]
#[test]
fn rejects_non_executable_files() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let path = executable(root.path());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut inputs = options();
    inputs.executable = Some(path);
    assert!(matches!(
        discover(&inputs),
        Err(Error::InvalidExecutable { .. })
    ));
}
