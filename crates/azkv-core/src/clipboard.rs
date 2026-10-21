use std::io::Write;
use std::process::{Command, Stdio};

use crate::error::{Error, Result};

/// Copies text with the platform clipboard tool.
pub fn copy(text: &str) -> Result<()> {
    copy_with(text, std::env::consts::OS)
}

pub fn copy_with(text: &str, os: &str) -> Result<()> {
    let mut last_error = String::from("no clipboard tool found");
    for (command, args) in candidates_for(os) {
        let Ok(mut child) = Command::new(command).args(*args).stdin(Stdio::piped()).stdout(Stdio::null()).spawn()
        else {
            continue;
        };
        let written = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("clipboard tool has no stdin"))
            .and_then(|mut stdin| stdin.write_all(text.as_bytes()))
            .and_then(|()| child.wait());
        match written {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => last_error = format!("{command} exited with {status}"),
            Err(err) => last_error = format!("{command}: {err}"),
        }
    }
    Err(Error::Clipboard(last_error))
}

/// Reads text with the platform clipboard tool.
pub fn read() -> Result<String> {
    read_with(std::env::consts::OS)
}

pub fn read_with(os: &str) -> Result<String> {
    let mut last_error = String::from("no clipboard tool found");
    for (command, args) in read_candidates_for(os) {
        match Command::new(command).args(*args).output() {
            Ok(output) if output.status.success() => {
                return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
            },
            Ok(output) => last_error = format!("{command} exited with {}", output.status),
            Err(err) => last_error = format!("{command}: {err}"),
        }
    }
    Err(Error::Clipboard(last_error))
}

/// Clipboard tools to try, in order, for reading text.
pub fn read_candidates_for(os: &str) -> &'static [(&'static str, &'static [&'static str])] {
    match os {
        "macos" => &[("pbpaste", &[])],
        "linux" | "freebsd" | "openbsd" => {
            &[("wl-paste", &[]), ("xclip", &["-selection", "clipboard", "-o"]), ("xsel", &["--clipboard", "--output"])]
        },
        _ => &[],
    }
}

/// Clipboard tools to try, in order, for the given OS.
pub fn candidates_for(os: &str) -> &'static [(&'static str, &'static [&'static str])] {
    match os {
        "macos" => &[("pbcopy", &[])],
        "linux" | "freebsd" | "openbsd" => {
            &[("wl-copy", &[]), ("xclip", &["-selection", "clipboard"]), ("xsel", &["--clipboard", "--input"])]
        },
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_uses_pbcopy() {
        assert_eq!(candidates_for("macos"), &[("pbcopy", &[] as &[&str])]);
    }

    #[test]
    fn linux_tries_wayland_then_x11() {
        let candidates = candidates_for("linux");
        assert_eq!(candidates[0].0, "wl-copy");
        assert_eq!(candidates[1].0, "xclip");
        assert_eq!(candidates[1].1, ["-selection", "clipboard"]);
    }

    #[test]
    fn unknown_os_has_no_clipboard_tool() {
        assert!(candidates_for("windows").is_empty());
    }

    #[test]
    fn macos_reads_with_pbpaste() {
        assert_eq!(read_candidates_for("macos"), &[("pbpaste", &[] as &[&str])]);
    }

    #[test]
    fn linux_read_tries_wayland_then_x11() {
        let candidates = read_candidates_for("linux");
        assert_eq!(candidates[0].0, "wl-paste");
        assert_eq!(candidates[1].1, ["-selection", "clipboard", "-o"]);
    }

    #[test]
    fn unknown_os_read_fails_cleanly() {
        let err = read_with("windows").unwrap_err();
        assert!(err.to_string().contains("no clipboard tool"));
    }

    #[test]
    fn unknown_os_copy_fails_cleanly() {
        let err = copy_with("x", "windows").unwrap_err();
        assert!(err.to_string().contains("no clipboard tool"));
    }
}
