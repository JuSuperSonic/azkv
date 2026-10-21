use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::Profile;

/// Written by `az login` in every config dir; used here as the profile marker.
pub const PROFILE_MARKER: &str = "azureProfile.json";

pub fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| Error::Config("HOME is not set".into()))
}

pub fn azure_dir() -> Result<PathBuf> {
    Ok(home_dir()?.join(".azure"))
}

pub fn is_config_dir(dir: &Path) -> bool {
    dir.join(PROFILE_MARKER).is_file()
}

/// `~/.azure` (named `default`) followed by every `~/.azure/<name>` config dir.
pub fn discover() -> Result<Vec<Profile>> {
    discover_in(&azure_dir()?)
}

pub fn discover_in(base: &Path) -> Result<Vec<Profile>> {
    let mut profiles = Vec::new();
    if is_config_dir(base) {
        profiles.push(Profile { name: "default".into(), dir: base.to_path_buf() });
    }
    let mut names: Vec<String> = fs::read_dir(base)
        .map_err(|source| Error::Read { path: base.to_path_buf(), source })?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir() && is_config_dir(&entry.path()))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    profiles.extend(names.into_iter().map(|name| Profile { dir: base.join(&name), name }));
    Ok(profiles)
}

/// Profile selected by `AZURE_CONFIG_DIR`, else `~/.azure`.
pub fn active() -> Result<Profile> {
    resolve_with(None, &azure_dir()?)
}

/// `None` -> active profile, `<name>` -> `~/.azure/<name>`, path -> that directory.
pub fn resolve(spec: Option<&str>) -> Result<Profile> {
    resolve_with(spec, &azure_dir()?)
}

fn resolve_with(spec: Option<&str>, default_dir: &Path) -> Result<Profile> {
    match spec {
        None => match std::env::var_os("AZURE_CONFIG_DIR") {
            Some(value) => {
                let dir = PathBuf::from(value);
                check(&dir)?;
                Ok(Profile { name: profile_name(&dir), dir })
            },
            None => Ok(Profile { name: "default".into(), dir: default_dir.to_path_buf() }),
        },
        Some(spec) => {
            if spec == "default" {
                return Ok(Profile { name: "default".into(), dir: default_dir.to_path_buf() });
            }
            let dir = if spec.contains('/') || spec.contains('\\') { expand(spec) } else { default_dir.join(spec) };
            check(&dir)?;
            Ok(Profile { name: profile_name(&dir), dir })
        },
    }
}

fn check(dir: &Path) -> Result<()> {
    if !is_config_dir(dir) {
        return Err(Error::Config(format!(
            "{} is not an Azure CLI config dir ({} missing) - run `az login` with AZURE_CONFIG_DIR set to it",
            dir.display(),
            PROFILE_MARKER
        )));
    }
    Ok(())
}

fn profile_name(dir: &Path) -> String {
    dir.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_else(|| dir.display().to_string())
}

fn expand(spec: &str) -> PathBuf {
    match spec.strip_prefix("~/") {
        Some(rest) => home_dir().map(|home| home.join(rest)).unwrap_or_else(|_| PathBuf::from(spec)),
        None => PathBuf::from(spec),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_dirs(base: &Path, names: &[&str]) {
        for name in names {
            let dir = base.join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(PROFILE_MARKER), "{}").unwrap();
        }
    }

    #[test]
    fn discover_lists_default_and_sorted_named_profiles() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(PROFILE_MARKER), "{}").unwrap();
        profile_dirs(tmp.path(), &["prod", "dev"]);
        fs::create_dir_all(tmp.path().join("logs")).unwrap();
        fs::write(tmp.path().join("logs").join("x.txt"), "").unwrap();

        let profiles = discover_in(tmp.path()).unwrap();
        let names: Vec<_> = profiles.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["default", "dev", "prod"]);
        assert_eq!(profiles[2].dir, tmp.path().join("prod"));
    }

    #[test]
    fn discover_ignores_dirs_without_login_state() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("telemetry")).unwrap();
        assert!(discover_in(tmp.path()).unwrap().is_empty());
    }

    #[test]
    fn discover_fails_on_missing_base() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(discover_in(&tmp.path().join("nope")).is_err());
    }

    #[test]
    fn resolve_accepts_names_paths_and_default() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(PROFILE_MARKER), "{}").unwrap();
        profile_dirs(tmp.path(), &["test"]);

        let named = resolve_with(Some("test"), tmp.path()).unwrap();
        assert_eq!(named.dir, tmp.path().join("test"));
        assert_eq!(named.name, "test");

        let path = tmp.path().join("test");
        let by_path = resolve_with(Some(path.to_str().unwrap()), tmp.path()).unwrap();
        assert_eq!(by_path.dir, path);

        let default = resolve_with(Some("default"), tmp.path()).unwrap();
        assert_eq!(default.dir, tmp.path());
    }

    #[test]
    fn resolve_rejects_dirs_without_profile() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("empty")).unwrap();
        let err = resolve_with(Some("empty"), tmp.path()).unwrap_err();
        assert!(err.to_string().contains("not an Azure CLI config dir"));
    }

    #[test]
    fn tilde_is_expanded() {
        let home = home_dir().unwrap();
        assert_eq!(expand("~/x"), home.join("x"));
        assert_eq!(expand("/abs/x"), PathBuf::from("/abs/x"));
    }
}
