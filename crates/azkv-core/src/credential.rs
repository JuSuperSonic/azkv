use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_core::error::ErrorKind;
use serde::Deserialize;
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use crate::error::{Error, Result};
use crate::proxy::ProxySettings;
use crate::token_cache::{CLIENT_ID, Cache, CachedRefresh, TokenCache};

/// Acquires tokens from the Azure CLI's MSAL cache, one cache per
/// (subscription or tenant, resource). Expired access tokens are refreshed
/// with the cached refresh token; no `az` process is started.
#[derive(Debug)]
pub struct AzAuth {
    cache: TokenCache,
    /// Parsed cache, reused until a token miss forces a reload.
    parsed: tokio::sync::Mutex<Option<Arc<Cache>>>,
    tokens: tokio::sync::Mutex<HashMap<String, AccessToken>>,
    refreshed: tokio::sync::Mutex<Option<CachedRefresh>>,
    /// Serialises refreshes so concurrent callers share one request.
    refresh: tokio::sync::Mutex<()>,
}

impl AzAuth {
    pub fn new(config_dir: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            cache: TokenCache::new(config_dir),
            parsed: tokio::sync::Mutex::new(None),
            tokens: tokio::sync::Mutex::new(HashMap::new()),
            refreshed: tokio::sync::Mutex::new(None),
            refresh: tokio::sync::Mutex::new(()),
        })
    }

    pub fn default_subscription(&self) -> Option<String> {
        self.cache.default_subscription()
    }

    pub fn credential(self: &Arc<Self>, subscription_id: &str) -> Arc<dyn TokenCredential> {
        Arc::new(SubscriptionCredential { auth: Arc::clone(self), subscription_id: subscription_id.to_string() })
    }

    /// Raw ARM token, cached per subscription/tenant.
    pub async fn arm_token(&self, subscription: Option<&str>, tenant: Option<&str>) -> Result<String> {
        let token = self.token(subscription, tenant, "https://management.azure.com").await?;
        Ok(token.token.secret().to_string())
    }

    /// Parsed cache, reloaded only when an in-memory token is missing.
    async fn parsed_cache(&self, reload: bool) -> Result<Arc<Cache>> {
        if !reload {
            let parsed = self.parsed.lock().await;
            if let Some(cache) = parsed.as_ref() {
                return Ok(Arc::clone(cache));
            }
        }
        let cache = Arc::new(self.cache.load()?);
        *self.parsed.lock().await = Some(Arc::clone(&cache));
        Ok(cache)
    }

    async fn cached_token(&self, key: &str) -> Option<AccessToken> {
        let tokens = self.tokens.lock().await;
        tokens.get(key).filter(|token| token.expires_on > OffsetDateTime::now_utc() + Duration::minutes(2)).cloned()
    }

    async fn token(&self, subscription: Option<&str>, tenant: Option<&str>, resource: &str) -> Result<AccessToken> {
        let cache = self.parsed_cache(false).await?;
        let tenant_id = cache.tenant_for(subscription, tenant)?;
        let key = format!("{}|{}|{resource}", subscription.unwrap_or("-"), tenant_id);
        if let Some(token) = self.cached_token(&key).await {
            return Ok(token);
        }

        // One refresh at a time: the next waiter sees the fresh token above.
        let _refresh = self.refresh.lock().await;
        if let Some(token) = self.cached_token(&key).await {
            return Ok(token);
        }

        // The Azure CLI may have logged in since the cache was parsed.
        let cache = self.parsed_cache(true).await?;
        let tenant_id = cache.tenant_for(subscription, tenant)?;
        let key = format!("{}|{}|{resource}", subscription.unwrap_or("-"), tenant_id);
        if let Some(token) = self.cached_token(&key).await {
            return Ok(token);
        }

        if let Some(cached) = cache.access_token(resource, &tenant_id) {
            let token = AccessToken::new(
                cached.secret,
                OffsetDateTime::from_unix_timestamp(cached.expires_on)
                    .map_err(|_| Error::Auth("invalid token expiry in the Azure CLI cache".into()))?,
            );
            self.tokens.lock().await.insert(key, token.clone());
            return Ok(token);
        }

        let account = cache.account_for_tenant(&tenant_id);
        let stored = self.refreshed.lock().await.clone();
        let refresh = stored
            .filter(|token| {
                account.as_deref().is_none_or(|account| token.home_account_id.eq_ignore_ascii_case(account))
            })
            .or_else(|| cache.refresh_token(account.as_deref()));
        let Some(refresh) = refresh else {
            return Err(Error::Auth(format!(
                "no valid Azure token for tenant {tenant_id} and no refresh token in {} - \
                 sign in again with `az login`",
                self.cache.config_dir().join("msal_token_cache.json").display()
            )));
        };

        let refreshed = refresh_token(&refresh, &tenant_id, resource).await?;
        if let Some(secret) = refreshed.refresh_token {
            *self.refreshed.lock().await = Some(CachedRefresh { secret, ..refresh });
        }
        self.tokens.lock().await.insert(key, refreshed.token.clone());
        Ok(refreshed.token)
    }
}

#[derive(Debug)]
struct SubscriptionCredential {
    auth: Arc<AzAuth>,
    subscription_id: String,
}

#[async_trait::async_trait]
impl TokenCredential for SubscriptionCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        let resource = resource_from_scopes(scopes);
        self.auth.token(Some(&self.subscription_id), None, &resource).await.map_err(|err| {
            let message = err.to_string();
            azure_core::Error::with_error(ErrorKind::Credential, err, message)
        })
    }
}

/// `https://vault.azure.net/.default` -> `https://vault.azure.net`.
pub fn resource_from_scopes(scopes: &[&str]) -> String {
    scopes
        .first()
        .map(|scope| scope.trim_end_matches("/.default").to_string())
        .filter(|scope| !scope.is_empty())
        .unwrap_or_else(|| "https://vault.azure.net".to_string())
}

struct Refreshed {
    token: AccessToken,
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct RefreshResponse {
    access_token: String,
    expires_in: i64,
    #[serde(default)]
    refresh_token: Option<String>,
}

async fn refresh_token(cached: &CachedRefresh, tenant: &str, resource: &str) -> Result<Refreshed> {
    let base = if cached.environment.contains("://") {
        cached.environment.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", cached.environment.trim_end_matches('/'))
    };
    if base == "https://" {
        return Err(Error::Auth("the Azure CLI token cache has no authority".into()));
    }
    let url = format!("{base}/{tenant}/oauth2/v2.0/token");
    let scope = format!("{}/.default offline_access", resource.trim_end_matches('/'));
    let http = ProxySettings::shared_client()?;
    let response = http
        .post(&url)
        .timeout(StdDuration::from_secs(30))
        .form(&[
            ("client_id", CLIENT_ID),
            ("grant_type", "refresh_token"),
            ("refresh_token", cached.secret.as_str()),
            ("scope", scope.as_str()),
        ])
        .send()
        .await
        .map_err(|err| Error::connect(&err, None, &url))?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let detail = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|value| {
                value
                    .get("error_description")
                    .or_else(|| value.get("error"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_else(|| body.trim().to_string());
        return Err(Error::from_status(
            status.as_u16(),
            format!("Azure token refresh failed ({status}): {}", first_line(&detail)),
        ));
    }
    let parsed: RefreshResponse = serde_json::from_str(&body)
        .map_err(|source| Error::Parse { context: "unexpected Azure token response".into(), source })?;
    Ok(Refreshed {
        token: AccessToken::new(parsed.access_token, OffsetDateTime::now_utc() + Duration::seconds(parsed.expires_in)),
        refresh_token: parsed.refresh_token.filter(|token| !token.is_empty()),
    })
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().trim().chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use serde_json::json;

    use super::*;

    #[test]
    fn scopes_map_to_the_resource_endpoint() {
        assert_eq!(resource_from_scopes(&["https://vault.azure.net/.default"]), "https://vault.azure.net");
        assert_eq!(resource_from_scopes(&["https://vault.azure.net"]), "https://vault.azure.net");
        assert_eq!(resource_from_scopes(&[]), "https://vault.azure.net");
    }

    fn write_profile(dir: &std::path::Path) {
        fs::write(
            dir.join("azureProfile.json"),
            r#"{"subscriptions":[{"id":"sub-1","tenantId":"tenant-1","isDefault":true}]}"#,
        )
        .unwrap();
    }

    fn write_cache(dir: &std::path::Path, access: Value, refresh: Value) {
        fs::write(
            dir.join("msal_token_cache.json"),
            json!({ "AccessToken": access, "RefreshToken": refresh }).to_string(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn unexpired_tokens_are_reused_from_the_cli_cache() {
        let tmp = tempfile::tempdir().unwrap();
        write_profile(tmp.path());
        let expires = OffsetDateTime::now_utc().unix_timestamp() + 3600;
        write_cache(
            tmp.path(),
            json!({
                "token": {
                    "secret": "cached-token",
                    "expires_on": expires.to_string(),
                    "realm": "tenant-1",
                    "target": "https://vault.azure.net/.default",
                    "environment": "login.microsoftonline.com",
                    "home_account_id": "account",
                    "client_id": CLIENT_ID
                }
            }),
            json!({}),
        );

        let auth = AzAuth::new(tmp.path().to_path_buf());
        let credential = auth.credential("sub-1");
        let token = credential.get_token(&["https://vault.azure.net/.default"], None).await.unwrap();
        assert_eq!(token.token.secret(), "cached-token");

        // The parsed cache is reused: a second call must not need the file.
        fs::remove_file(tmp.path().join("msal_token_cache.json")).unwrap();
        let token = credential.get_token(&["https://vault.azure.net/.default"], None).await.unwrap();
        assert_eq!(token.token.secret(), "cached-token");
    }

    #[tokio::test]
    async fn expired_tokens_are_refreshed_with_the_cached_refresh_token() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 2048];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.contains("grant_type=refresh_token"), "{request}");
            assert!(request.contains("refresh_token=refresh-token"), "{request}");
            assert!(request.contains("tenant-1/oauth2/v2.0/token"), "{request}");
            let body = r#"{"access_token":"fresh-token","expires_in":3600,"refresh_token":"new-refresh"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        });

        let tmp = tempfile::tempdir().unwrap();
        write_profile(tmp.path());
        let expired = OffsetDateTime::now_utc().unix_timestamp() - 10;
        write_cache(
            tmp.path(),
            json!({
                "token": {
                    "secret": "expired-token",
                    "expires_on": expired.to_string(),
                    "realm": "tenant-1",
                    "target": "https://vault.azure.net/.default",
                    "environment": format!("http://{address}"),
                    "home_account_id": "account",
                    "client_id": CLIENT_ID
                }
            }),
            json!({
                "refresh": {
                    "secret": "refresh-token",
                    "environment": format!("http://{address}"),
                    "home_account_id": "account",
                    "client_id": CLIENT_ID
                }
            }),
        );

        let auth = AzAuth::new(tmp.path().to_path_buf());
        let token = auth.credential("sub-1").get_token(&["https://vault.azure.net/.default"], None).await.unwrap();
        assert_eq!(token.token.secret(), "fresh-token");
        server.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_refreshes_share_one_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let server = {
            let requests = Arc::clone(&requests);
            std::thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                loop {
                    if stop_rx.try_recv().is_ok() {
                        break;
                    }
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            stream.set_nonblocking(false).unwrap();
                            stream.set_read_timeout(Some(StdDuration::from_secs(1))).unwrap();
                            let mut request = Vec::new();
                            let mut buffer = [0_u8; 2048];
                            loop {
                                let read = stream.read(&mut buffer).unwrap();
                                if read == 0 {
                                    break;
                                }
                                request.extend_from_slice(&buffer[..read]);
                                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            let body = r#"{"access_token":"fresh-token","expires_in":3600}"#;
                            let response = format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            stream.write_all(response.as_bytes()).unwrap();
                            stream.flush().unwrap();
                        },
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(StdDuration::from_millis(10));
                        },
                        Err(_) => break,
                    }
                }
            })
        };

        let tmp = tempfile::tempdir().unwrap();
        write_profile(tmp.path());
        let expired = OffsetDateTime::now_utc().unix_timestamp() - 10;
        write_cache(
            tmp.path(),
            json!({
                "token": {
                    "secret": "expired-token",
                    "expires_on": expired.to_string(),
                    "realm": "tenant-1",
                    "target": "https://vault.azure.net/.default",
                    "environment": format!("http://{address}"),
                    "home_account_id": "account",
                    "client_id": CLIENT_ID
                }
            }),
            json!({
                "refresh": {
                    "secret": "refresh-token",
                    "environment": format!("http://{address}"),
                    "home_account_id": "account",
                    "client_id": CLIENT_ID
                }
            }),
        );

        let auth = AzAuth::new(tmp.path().to_path_buf());
        let first = auth.credential("sub-1");
        let second = auth.credential("sub-1");
        let (first, second) = tokio::join!(
            first.get_token(&["https://vault.azure.net/.default"], None),
            second.get_token(&["https://vault.azure.net/.default"], None),
        );
        assert_eq!(first.unwrap().token.secret(), "fresh-token");
        assert_eq!(second.unwrap().token.secret(), "fresh-token");
        stop_tx.send(()).unwrap();
        server.join().unwrap();
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_expired_token_without_a_refresh_token_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        write_profile(tmp.path());
        let expired = OffsetDateTime::now_utc().unix_timestamp() - 10;
        write_cache(
            tmp.path(),
            json!({
                "token": {
                    "secret": "expired-token",
                    "expires_on": expired.to_string(),
                    "realm": "tenant-1",
                    "target": "https://vault.azure.net/.default",
                    "client_id": CLIENT_ID
                }
            }),
            json!({}),
        );

        let auth = AzAuth::new(tmp.path().to_path_buf());
        let err = auth.credential("sub-1").get_token(&["https://vault.azure.net/.default"], None).await.unwrap_err();
        assert!(err.to_string().contains("no refresh token"), "{err}");
    }
}
