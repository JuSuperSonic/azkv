use azkv_core::{Error, Remote};

/// Status-bar error: one readable sentence, with the full cause kept in the log.
pub fn short(err: impl Into<anyhow::Error>) -> String {
    let err = err.into();
    log_error(&err);
    match err.downcast_ref::<Error>() {
        Some(Error::Connect { timeout: true, .. }) => "request timed out — check the proxy/VPN".into(),
        Some(Error::Connect { proxy: Some(proxy), dns: true, .. }) => {
            format!("proxy {proxy} could not resolve the target — check DNS/VPN")
        },
        Some(Error::Connect { dns: true, .. }) => "could not resolve the target — check DNS/VPN".into(),
        Some(Error::Connect { proxy: Some(proxy), .. }) => {
            format!("proxy {proxy} unreachable — is the tunnel running?")
        },
        Some(Error::Connect { .. }) => "cannot reach Azure — check your network/VPN".into(),
        Some(Error::Remote { kind: Remote::Firewall, .. }) => {
            "access denied — this address is not allowed by the vault firewall".into()
        },
        Some(Error::Remote { kind: Remote::Unauthorized, .. }) => {
            "authentication failed (401) — run `az login` for this profile".into()
        },
        Some(Error::Remote { kind: Remote::Forbidden, .. }) => "access denied (403) — check your role".into(),
        Some(Error::Remote { kind: Remote::Throttled, .. }) => "throttled by Azure — try again shortly".into(),
        Some(Error::Remote { kind: Remote::SoftDeleted, .. }) => {
            "secret is soft-deleted — recover or purge it before reusing this name".into()
        },
        Some(Error::Remote { kind: Remote::NotFound, .. }) => "not found (404) — it may have been deleted".into(),
        Some(Error::Remote { kind: Remote::BadRequest, .. }) => {
            "bad request (400) — check the vault and subscription".into()
        },
        Some(Error::Remote { kind: Remote::Unavailable, .. }) => "Azure is unavailable right now — try again".into(),
        Some(Error::Auth(_)) => "cannot get an Azure token — sign in again with `az login`".into(),
        _ => clip(&err.to_string(), 180),
    }
}

fn clip(text: &str, max: usize) -> String {
    let mut chars = text.chars();
    let clipped: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() { format!("{}…", clipped.trim_end()) } else { clipped }
}

/// Keep the full cause chain out of the TUI but available for diagnosis.
pub fn log_error(err: &anyhow::Error) {
    tracing::error!("{err:#}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect(proxy: Option<&str>, dns: bool, timeout: bool) -> Error {
        Error::Connect { proxy: proxy.map(str::to_string), dns, timeout, message: String::new() }
    }

    #[test]
    fn proxy_failure_reads_as_a_tunnel_problem() {
        assert_eq!(
            short(connect(Some("socks5h://localhost:1080"), false, false)),
            "proxy socks5h://localhost:1080 unreachable — is the tunnel running?"
        );
        assert_eq!(short(connect(None, false, false)), "cannot reach Azure — check your network/VPN");
    }

    #[test]
    fn dns_and_timeout_failures_are_explained() {
        assert_eq!(short(connect(None, true, false)), "could not resolve the target — check DNS/VPN");
        assert_eq!(
            short(connect(Some("http://proxy:3128"), true, false)),
            "proxy http://proxy:3128 could not resolve the target — check DNS/VPN"
        );
        assert_eq!(short(connect(Some("http://proxy:3128"), false, true)), "request timed out — check the proxy/VPN");
    }

    #[test]
    fn firewall_and_auth_errors_are_explained() {
        let denied = Error::Remote { kind: Remote::Firewall, message: String::new() };
        assert_eq!(short(denied), "access denied — this address is not allowed by the vault firewall");

        let expired = Error::Remote { kind: Remote::Unauthorized, message: String::new() };
        assert_eq!(short(expired), "authentication failed (401) — run `az login` for this profile");
    }

    #[test]
    fn soft_deleted_secret_conflicts_are_explained() {
        let err = Error::Remote { kind: Remote::SoftDeleted, message: "cannot write secret 'db'".into() };
        assert_eq!(short(err), "secret is soft-deleted — recover or purge it before reusing this name");
    }

    #[test]
    fn unknown_errors_keep_the_readable_context() {
        let err = anyhow::anyhow!("permission denied").context("cannot write secret 'db'");
        assert_eq!(short(err), "cannot write secret 'db'");
    }

    #[test]
    fn token_failures_point_at_the_profile() {
        let err = Error::Auth("no valid Azure token for tenant t and no refresh token".into());
        assert_eq!(short(err), "cannot get an Azure token — sign in again with `az login`");
    }

    #[test]
    fn errors_are_logged_to_the_file() {
        let path = std::env::temp_dir().join(format!(
            "azkv-test-{}-{}.log",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let file = std::fs::OpenOptions::new().create(true).append(true).open(&path).unwrap();
        let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(file).finish();
        let err = anyhow::anyhow!("permission denied").context("cannot write secret 'db'");
        tracing::subscriber::with_default(subscriber, || log_error(&err));
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(text.contains("cannot write secret 'db'"));
        assert!(text.contains("permission denied"));
    }
}
