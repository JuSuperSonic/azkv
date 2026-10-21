use std::path::{Path, PathBuf};

use tracing_subscriber::EnvFilter;

pub fn init_logging() {
    let Some(path) = log_path() else {
        return;
    };
    let secure_dir = std::env::var_os("AZKV_LOG").is_none();
    let Some(file) = open_log(&path, secure_dir) else {
        return;
    };
    // The TUI owns the terminal, so events go to a file instead of stdout/stderr.
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| format!("{}=info", env!("CARGO_CRATE_NAME")));
    let _ = tracing_subscriber::fmt()
        .with_file(true)
        .with_line_number(true)
        .with_target(false)
        .with_ansi(false)
        .with_writer(file)
        .with_env_filter(EnvFilter::builder().parse_lossy(filter))
        .try_init();
}

fn open_log(path: &Path, secure_dir: bool) -> Option<std::fs::File> {
    if let Some(parent) = path.parent() {
        let existed = parent.exists();
        let _ = std::fs::create_dir_all(parent);
        #[cfg(unix)]
        if secure_dir || !existed {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Some(file)
}

fn log_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("AZKV_LOG").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(path));
    }
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local").join("state")))?;
    Some(base.join("azkv").join("azkv.log"))
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn log_and_directory_are_private() {
        let dir = std::env::temp_dir().join(format!(
            "azkv-log-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let path = dir.join("azkv.log");
        let file = open_log(&path, true).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        drop(file);
        let _file = open_log(&path, true).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn custom_existing_parent_directory_is_not_chmodded() {
        let dir = std::env::temp_dir().join(format!(
            "azkv-log-parent-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _file = open_log(&dir.join("azkv.log"), false).unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o755);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
