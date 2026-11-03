use std::{
    fs,
    path::{Path, PathBuf},
};

use tracing_subscriber::EnvFilter;

const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;
const KEEP_LOG_FILES: u32 = 3;

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

fn open_log(path: &Path, secure_dir: bool) -> Option<fs::File> {
    if let Some(parent) = path.parent() {
        let existed = parent.exists();
        let _ = fs::create_dir_all(parent);
        #[cfg(unix)]
        if secure_dir || !existed {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    rotate_log(path, MAX_LOG_BYTES, KEEP_LOG_FILES);
    let mut options = fs::OpenOptions::new();
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
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Some(file)
}

// shortcut: the log is rotated when it is opened, so one very long session can
// exceed MAX_LOG_BYTES; switch to a size-checking MakeWriter if that matters.
fn rotate_log(path: &Path, max_bytes: u64, keep: u32) {
    if fs::metadata(path).map_or(true, |meta| meta.len() < max_bytes) {
        return;
    }
    for index in (1..keep).rev() {
        let from = indexed(path, index);
        if from.exists() {
            let to = indexed(path, index + 1);
            let _ = fs::remove_file(&to);
            let _ = fs::rename(from, to);
        }
    }
    let _ = fs::remove_file(indexed(path, 1));
    let _ = fs::rename(path, indexed(path, 1));
}

fn indexed(path: &Path, index: u32) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

pub(crate) fn log_path() -> Option<PathBuf> {
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
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        drop(file);
        let _file = open_log(&path, true).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn custom_existing_parent_directory_is_not_chmodded() {
        let dir = std::env::temp_dir().join(format!(
            "azkv-log-parent-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let _file = open_log(&dir.join("azkv.log"), false).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o755);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_log_is_rotated_and_oldest_dropped() {
        let dir = std::env::temp_dir().join(format!(
            "azkv-log-rotate-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("azkv.log");
        fs::write(&path, vec![b'x'; 64]).unwrap();
        for index in 1..=KEEP_LOG_FILES {
            fs::write(indexed(&path, index), format!("old{index}")).unwrap();
        }

        rotate_log(&path, 64, KEEP_LOG_FILES);

        assert!(!path.exists());
        assert_eq!(fs::read(indexed(&path, 1)).unwrap().len(), 64);
        assert_eq!(fs::read_to_string(indexed(&path, 2)).unwrap(), "old1");
        assert_eq!(fs::read_to_string(indexed(&path, 3)).unwrap(), "old2");
        assert!(!indexed(&path, 4).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn small_log_is_not_rotated() {
        let dir = std::env::temp_dir().join(format!(
            "azkv-log-keep-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("azkv.log");
        fs::write(&path, b"tiny").unwrap();

        rotate_log(&path, 64, KEEP_LOG_FILES);

        assert_eq!(fs::read_to_string(&path).unwrap(), "tiny");
        assert!(!indexed(&path, 1).exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
