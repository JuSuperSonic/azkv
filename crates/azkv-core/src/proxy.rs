use std::sync::{Arc, OnceLock};
use std::time::Duration;

use azure_core::http::HttpClient;
use reqwest::redirect::Policy;

use crate::error::{Error, Result};

/// Explicit proxy for Key Vault and Azure management (ARM) calls.
///
/// `az` is not run for token acquisition: the Azure CLI MSAL cache is read and
/// refreshed directly with the default transport (honouring proxy env vars).
/// When absent, reqwest's system proxy support is used unchanged.
#[derive(Clone, Debug)]
pub struct ProxySettings {
    proxy: String,
    no_proxy: Option<String>,
    client: reqwest::Client,
}

/// One process-wide client for calls without an explicit proxy. Creating a
/// client per TUI action throws away the connection pool and TLS sessions.
static SHARED_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
static SHARED_TRANSPORT: OnceLock<Arc<dyn HttpClient>> = OnceLock::new();

impl ProxySettings {
    /// `None` leaves the default system-proxy behavior untouched.
    pub fn new(proxy: Option<&str>, no_proxy: Option<&str>) -> Result<Option<Self>> {
        let Some(proxy) = proxy.map(str::trim).filter(|proxy| !proxy.is_empty()) else {
            return Ok(None);
        };
        // Bare `host:port` is the ssh -D case; HTTP proxies need an explicit scheme.
        let proxy = if proxy.contains("://") { proxy.to_string() } else { format!("socks5h://{proxy}") };
        // An explicit --no-proxy wins; otherwise honour the usual env vars.
        let no_proxy =
            no_proxy.map(str::trim).filter(|no_proxy| !no_proxy.is_empty()).map(str::to_string).or_else(env_no_proxy);
        let matcher = no_proxy.as_deref().and_then(reqwest::NoProxy::from_string);
        let proxy_url = proxy;
        let display_url = redact_url(&proxy_url);
        let proxy_matcher = reqwest::Proxy::all(&proxy_url)
            .map_err(|_| Error::Config(format!("invalid proxy URL '{display_url}'")))?
            .no_proxy(matcher);
        // Same timeouts/redirect policy as the SDK's default transport.
        let client = reqwest::ClientBuilder::new()
            .proxy(proxy_matcher)
            .connect_timeout(Duration::from_secs(20))
            .read_timeout(Duration::from_secs(60))
            .redirect(Policy::none())
            .build()
            .map_err(|err| Error::Config(format!("cannot build the proxy HTTP client: {err}")))?;
        Ok(Some(Self { proxy: proxy_url, no_proxy, client }))
    }

    pub async fn check(&self) -> Result<()> {
        const PROBE: &str = "https://management.azure.com/metadata/endpoints?api-version=2020-09-01";
        self.client
            .get(PROBE)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map(|_| ())
            .map_err(|err| Error::connect(&err, Some(&self.display_url()), "management.azure.com"))
    }

    pub fn url(&self) -> &str {
        &self.proxy
    }

    /// The proxy URL without credentials, for status text and error messages.
    pub fn display_url(&self) -> String {
        redact_url(&self.proxy)
    }

    pub fn no_proxy(&self) -> Option<&str> {
        self.no_proxy.as_deref()
    }

    pub fn transport(&self) -> Arc<dyn HttpClient> {
        Arc::new(self.client.clone())
    }

    /// Same transport, for management-plane REST calls.
    pub fn http(&self) -> reqwest::Client {
        self.client.clone()
    }

    pub(crate) fn shared_client() -> Result<reqwest::Client> {
        if let Some(client) = SHARED_CLIENT.get() {
            return Ok(client.clone());
        }
        let client = reqwest::ClientBuilder::new()
            .connect_timeout(Duration::from_secs(20))
            .read_timeout(Duration::from_secs(60))
            .redirect(Policy::none())
            .build()
            .map_err(|err| Error::Config(format!("cannot build the HTTP client: {err}")))?;
        Ok(SHARED_CLIENT.get_or_init(|| client).clone())
    }

    pub(crate) fn shared_transport() -> Result<Arc<dyn HttpClient>> {
        if let Some(transport) = SHARED_TRANSPORT.get() {
            return Ok(Arc::clone(transport));
        }
        let client = Self::shared_client()?;
        Ok(Arc::clone(SHARED_TRANSPORT.get_or_init(|| Arc::new(client))))
    }
}

/// Settings are equal when they describe the same proxy and bypass list.
impl PartialEq for ProxySettings {
    fn eq(&self, other: &Self) -> bool {
        self.proxy == other.proxy && self.no_proxy == other.no_proxy
    }
}

fn env_no_proxy() -> Option<String> {
    ["NO_PROXY", "no_proxy"].iter().find_map(|key| std::env::var(key).ok().filter(|value| !value.trim().is_empty()))
}

fn redact_url(url: &str) -> String {
    let Ok(mut parsed) = reqwest::Url::parse(url) else {
        return if url.contains('@') { "<redacted>".into() } else { url.to_string() };
    };
    if parsed.username().is_empty() && parsed.password().is_none() {
        return url.to_string();
    }
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_proxy_flag_keeps_the_default_transport() {
        assert!(ProxySettings::new(None, None).unwrap().is_none());
        assert!(ProxySettings::new(Some("   "), None).unwrap().is_none());
    }

    #[test]
    fn invalid_proxy_url_is_rejected() {
        assert!(ProxySettings::new(Some("not a url"), None).is_err());
    }

    #[test]
    fn bare_proxy_address_defaults_to_socks5h() {
        let settings = ProxySettings::new(Some("localhost:1911"), None).unwrap().unwrap();
        assert_eq!(settings.url(), "socks5h://localhost:1911");
    }

    #[test]
    fn proxy_builds_a_transport_and_keeps_the_bypass_list() {
        let settings =
            ProxySettings::new(Some("http://127.0.0.1:8080"), Some("localhost, 127.0.0.1")).unwrap().unwrap();
        assert_eq!(settings.url(), "http://127.0.0.1:8080");
        assert_eq!(settings.no_proxy(), Some("localhost, 127.0.0.1"));
        let _ = settings.transport();
    }

    #[test]
    fn shared_transport_is_reused() {
        let first = ProxySettings::shared_transport().unwrap();
        let second = ProxySettings::shared_transport().unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn check_fails_when_the_proxy_is_not_listening() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let settings = ProxySettings::new(Some(&format!("socks5h://127.0.0.1:{port}")), None).unwrap().unwrap();
        assert!(settings.check().await.is_err());
    }

    #[test]
    fn proxy_credentials_are_hidden_from_display_url() {
        let settings = ProxySettings::new(Some("http://alice:hunter2@127.0.0.1:8080"), None).unwrap().unwrap();
        assert_eq!(settings.url(), "http://alice:hunter2@127.0.0.1:8080");
        let display = settings.display_url();
        assert!(!display.contains("alice"));
        assert!(!display.contains("hunter2"));
        assert!(display.contains("127.0.0.1:8080"));

        let settings = ProxySettings::new(Some("socks5h://alice:hunter2@127.0.0.1:1080"), None).unwrap().unwrap();
        let display = settings.display_url();
        assert!(!display.contains("alice"));
        assert!(!display.contains("hunter2"));
        assert!(display.contains("127.0.0.1:1080"));
    }
}
