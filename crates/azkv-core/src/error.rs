use std::path::PathBuf;

use azure_core::error::ErrorKind;

/// Why Azure refused a call, derived from the HTTP status and the response text.
/// Callers use this instead of matching on error strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remote {
    NotFound,
    Unauthorized,
    Forbidden,
    /// 403 caused by the vault firewall, not by missing roles.
    Firewall,
    Throttled,
    /// 409 because the secret is soft-deleted and its name is still reserved.
    SoftDeleted,
    Unavailable,
    BadRequest,
    Other,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Azure answered with a failure status.
    #[error("{message}")]
    Remote { kind: Remote, message: String },

    /// No answer at all: DNS, TCP, proxy or timeout.
    #[error("{message}")]
    Connect { proxy: Option<String>, dns: bool, timeout: bool, message: String },

    /// The Azure CLI profile cannot produce a token.
    #[error("{0}")]
    Auth(String),

    /// Local profile, path or configuration problem.
    #[error("{0}")]
    Config(String),

    /// Invalid user input, such as an unparseable expiry or unknown vault.
    #[error("{0}")]
    Input(String),

    /// No clipboard tool worked.
    #[error("{0}")]
    Clipboard(String),

    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{context}")]
    Parse {
        context: String,
        #[source]
        source: serde_json::Error,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    /// Classifies a non-success HTTP response.
    pub(crate) fn from_status(status: u16, message: String) -> Self {
        let kind = classify(status, &message);
        Self::Remote { kind, message }
    }

    /// Classifies an `azure_core` error and prefixes it with the failed operation.
    pub(crate) fn from_azure(err: azure_core::Error, context: &str) -> Self {
        if matches!(err.kind(), ErrorKind::Credential) {
            // The credential layer wraps our typed error; keep transport
            // failures readable instead of reporting every refresh as auth.
            return match err.into_downcast::<Error>() {
                Ok(inner @ Error::Connect { .. }) => inner,
                Ok(inner) => Self::Auth(format!("{context}: {}", first_line(&inner.to_string()))),
                Err(err) => Self::Auth(format!("{context}: {}", first_line(&err.to_string()))),
            };
        }
        let detail = first_line(&err.to_string());
        match err.kind() {
            ErrorKind::HttpResponse { status, .. } => {
                Self::from_status(u16::from(*status), format!("{context}: {detail}"))
            },
            _ => Self::Remote { kind: Remote::Other, message: format!("{context}: {detail}") },
        }
    }

    /// Wraps a transport failure with the target and the proxy in use, if any.
    pub(crate) fn connect(err: &reqwest::Error, proxy: Option<&str>, target: &str) -> Self {
        let message = match proxy {
            Some(proxy) => format!("cannot reach {target} via proxy {proxy} (is the proxy or tunnel up?)"),
            None => format!("cannot reach {target}"),
        };
        Self::Connect { proxy: proxy.map(str::to_string), dns: is_dns(err), timeout: err.is_timeout(), message }
    }
}

/// True when a Key Vault call failed because the object does not exist.
pub fn is_not_found(err: &Error) -> bool {
    matches!(err, Error::Remote { kind: Remote::NotFound, .. })
}

fn classify(status: u16, message: &str) -> Remote {
    if status == 404 {
        return Remote::NotFound;
    }
    if status == 401 {
        return Remote::Unauthorized;
    }
    if status == 403 {
        let firewall = message.to_ascii_lowercase().contains("client address is not authorized");
        return if firewall { Remote::Firewall } else { Remote::Forbidden };
    }
    if status == 409 && is_soft_deleted(message) {
        return Remote::SoftDeleted;
    }
    if status == 429 {
        return Remote::Throttled;
    }
    if status == 400 {
        return Remote::BadRequest;
    }
    if (500..600).contains(&status) {
        return Remote::Unavailable;
    }
    Remote::Other
}

/// Key Vault reports a soft-deleted name as a 409 with one of these phrases.
fn is_soft_deleted(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    [
        "deleted but recoverable",
        "recoverable state",
        "recover or purge",
        "purged or recovered",
        "deleted state",
        "secretdeleted",
    ]
    .iter()
    .any(|phrase| message.contains(phrase))
}

fn is_dns(err: &reqwest::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(err) = source {
        let text = err.to_string().to_ascii_lowercase();
        if text.contains("dns") || text.contains("lookup") {
            return true;
        }
        source = err.source();
    }
    false
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().trim().chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use azure_core::http::StatusCode;

    use super::*;

    #[test]
    fn statuses_map_to_callers_vocabulary() {
        let kind = |status| classify(status, "request failed");
        assert_eq!(kind(404), Remote::NotFound);
        assert_eq!(kind(401), Remote::Unauthorized);
        assert_eq!(kind(403), Remote::Forbidden);
        assert_eq!(kind(409), Remote::Other);
        assert_eq!(kind(429), Remote::Throttled);
        assert_eq!(kind(400), Remote::BadRequest);
        assert_eq!(kind(500), Remote::Unavailable);
        assert_eq!(kind(502), Remote::Unavailable);
        assert_eq!(kind(418), Remote::Other);
    }

    #[test]
    fn firewall_denials_are_distinguished_from_role_denials() {
        let firewall = classify(403, "Forbidden: Client address is not authorized");
        assert_eq!(firewall, Remote::Firewall);
    }

    #[test]
    fn soft_deleted_conflicts_are_recognised() {
        let body = "Conflict: A secret with the name 'db' is currently in a deleted but recoverable \
                    state, and its name cannot be reused; in this state, the secret can only be \
                    recovered or purged.";
        assert_eq!(classify(409, body), Remote::SoftDeleted);
        assert_eq!(classify(409, "role assignment exists"), Remote::Other);
    }

    #[test]
    fn azure_http_errors_keep_their_kind_and_context() {
        let err = azure_core::Error::with_message(
            ErrorKind::HttpResponse {
                status: StatusCode::NotFound,
                error_code: Some("SecretNotFound".into()),
                raw_response: None,
            },
            "not found",
        );
        let err = Error::from_azure(err, "cannot read secret 'x'");
        assert!(is_not_found(&err));
        assert!(err.to_string().starts_with("cannot read secret 'x'"));
    }

    #[test]
    fn azure_credential_errors_become_auth_errors() {
        let err = Error::from_azure(azure_core::Error::with_message(ErrorKind::Credential, "no token"), "read");
        assert!(matches!(err, Error::Auth(message) if message.contains("no token")));
    }

    #[test]
    fn wrapped_transport_errors_keep_their_connect_kind() {
        let source = Error::Connect {
            proxy: Some("http://proxy:3128".into()),
            dns: false,
            timeout: false,
            message: "cannot reach the token endpoint".into(),
        };
        let err = azure_core::Error::with_error(ErrorKind::Credential, source, "token refresh failed");
        let err = Error::from_azure(err, "cannot read secret 'x'");
        assert!(matches!(err, Error::Connect { proxy: Some(proxy), .. } if proxy == "http://proxy:3128"));
    }

    #[test]
    fn unknown_errors_stay_readable() {
        let err = Error::Input("vault 'kv-a' not found in any accessible subscription".into());
        assert_eq!(err.to_string(), "vault 'kv-a' not found in any accessible subscription");
        assert!(!is_not_found(&err));
    }
}
