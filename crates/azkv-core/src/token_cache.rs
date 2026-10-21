use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;

use crate::error::{Error, Result};

/// Public client used by the Azure CLI; tokens in its cache are refreshable.
pub const CLIENT_ID: &str = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";

/// Read-only view of the Azure CLI's MSAL token cache and profile.
///
/// No `az` process is started: unexpired access tokens are reused, and an
/// expired one is refreshed with the cached refresh token.
#[derive(Clone, Debug)]
pub struct TokenCache {
    dir: PathBuf,
}

#[derive(Clone, Debug)]
pub struct CachedToken {
    pub secret: String,
    pub expires_on: i64,
    pub realm: String,
    pub target: String,
    pub home_account_id: String,
}

#[derive(Clone, Debug)]
pub struct CachedRefresh {
    pub secret: String,
    pub environment: String,
    pub home_account_id: String,
}

#[derive(Debug, Default)]
pub struct Cache {
    access_tokens: Vec<CachedToken>,
    refresh_tokens: Vec<CachedRefresh>,
    subscriptions: Vec<ProfileSubscription>,
}

#[derive(Clone, Debug, Deserialize)]
struct ProfileSubscription {
    id: String,
    #[serde(default, rename = "tenantId")]
    tenant_id: String,
    #[serde(default, rename = "isDefault")]
    is_default: bool,
}

#[derive(Deserialize)]
struct ProfileFile {
    #[serde(default)]
    subscriptions: Vec<ProfileSubscription>,
}

#[derive(Deserialize)]
struct CacheFile {
    #[serde(default, rename = "AccessToken")]
    access_tokens: HashMap<String, Value>,
    #[serde(default, rename = "RefreshToken")]
    refresh_tokens: HashMap<String, Value>,
}

#[derive(Deserialize)]
struct AccessEntry {
    secret: String,
    expires_on: Expiry,
    #[serde(default)]
    realm: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    home_account_id: String,
    #[serde(default)]
    client_id: String,
}

#[derive(Deserialize)]
struct RefreshEntry {
    secret: String,
    #[serde(default)]
    environment: String,
    #[serde(default)]
    home_account_id: String,
    #[serde(default)]
    client_id: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Expiry {
    Number(f64),
    Text(String),
}

impl Expiry {
    fn epoch(&self) -> Option<i64> {
        let value = match self {
            Self::Number(value) => *value,
            Self::Text(text) => text.trim().parse().ok()?,
        };
        value.is_finite().then_some(value as i64)
    }
}

impl TokenCache {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn config_dir(&self) -> &Path {
        &self.dir
    }

    pub fn load(&self) -> Result<Cache> {
        let path = self.dir.join("msal_token_cache.json");
        let text = fs::read_to_string(&path).map_err(|source| Error::Read { path: path.clone(), source })?;
        let text = text.trim_start_matches('\u{feff}');
        let raw: CacheFile = serde_json::from_str(text).map_err(|source| Error::Parse {
            context: format!("unexpected token cache in {}", path.display()),
            source,
        })?;

        let access_tokens = raw
            .access_tokens
            .into_values()
            .filter_map(|value| serde_json::from_value::<AccessEntry>(value).ok())
            .filter(|entry| !entry.secret.is_empty() && entry.client_id.eq_ignore_ascii_case(CLIENT_ID))
            .filter_map(|entry| {
                Some(CachedToken {
                    secret: entry.secret,
                    expires_on: entry.expires_on.epoch()?,
                    realm: entry.realm,
                    target: entry.target,
                    home_account_id: entry.home_account_id,
                })
            })
            .collect();

        let refresh_tokens = raw
            .refresh_tokens
            .into_values()
            .filter_map(|value| serde_json::from_value::<RefreshEntry>(value).ok())
            .filter(|entry| !entry.secret.is_empty() && entry.client_id.eq_ignore_ascii_case(CLIENT_ID))
            .map(|entry| CachedRefresh {
                secret: entry.secret,
                environment: entry.environment,
                home_account_id: entry.home_account_id,
            })
            .collect();

        Ok(Cache { access_tokens, refresh_tokens, subscriptions: self.subscriptions() })
    }

    /// Subscription selected with `az account set` in this profile.
    pub fn default_subscription(&self) -> Option<String> {
        self.subscriptions()
            .into_iter()
            .find(|subscription| subscription.is_default)
            .map(|subscription| subscription.id)
    }

    fn subscriptions(&self) -> Vec<ProfileSubscription> {
        let Ok(text) = fs::read_to_string(self.dir.join("azureProfile.json")) else {
            return Vec::new();
        };
        let text = text.trim_start_matches('\u{feff}');
        serde_json::from_str::<ProfileFile>(text).map(|profile| profile.subscriptions).unwrap_or_default()
    }
}

impl Cache {
    pub fn tenant_for(&self, subscription: Option<&str>, explicit: Option<&str>) -> Result<String> {
        if let Some(tenant) = explicit {
            return Ok(tenant.to_string());
        }
        if let Some(id) = subscription {
            if let Some(tenant) = self
                .subscriptions
                .iter()
                .find(|subscription| subscription.id.eq_ignore_ascii_case(id))
                .map(|subscription| subscription.tenant_id.clone())
                .filter(|tenant| !tenant.is_empty())
            {
                return Ok(tenant);
            }
            return Err(Error::Config(format!(
                "subscription {id} is not in azureProfile.json - refresh the Azure CLI profile"
            )));
        }
        if let Some(tenant) = self
            .subscriptions
            .iter()
            .find(|subscription| subscription.is_default)
            .or_else(|| self.subscriptions.first())
            .map(|subscription| subscription.tenant_id.clone())
            .filter(|tenant| !tenant.is_empty())
        {
            return Ok(tenant);
        }
        if let Some(tenant) = self.access_tokens.iter().map(|token| &token.realm).find(|realm| is_tenant_id(realm)) {
            return Ok(tenant.clone());
        }
        Err(Error::Config("no tenant in the Azure CLI profile - sign in again with `az login`".into()))
    }

    pub fn access_token(&self, resource: &str, tenant: &str) -> Option<CachedToken> {
        let resource = resource.trim_end_matches('/');
        let default_scope = format!("{resource}/.default");
        let minimum = OffsetDateTime::now_utc().unix_timestamp() + 120;
        self.access_tokens
            .iter()
            .filter(|token| token.expires_on > minimum)
            .find(|token| {
                token.realm.eq_ignore_ascii_case(tenant)
                    && token
                        .target
                        .split_whitespace()
                        .any(|scope| scope.eq_ignore_ascii_case(&default_scope) || scope.eq_ignore_ascii_case(resource))
            })
            .cloned()
    }

    pub fn account_for_tenant(&self, tenant: &str) -> Option<String> {
        self.access_tokens
            .iter()
            .find(|token| token.realm.eq_ignore_ascii_case(tenant))
            .map(|token| token.home_account_id.clone())
            .filter(|account| !account.is_empty())
    }

    pub fn refresh_token(&self, account: Option<&str>) -> Option<CachedRefresh> {
        let by_account = account.and_then(|account| {
            self.refresh_tokens.iter().find(|token| token.home_account_id.eq_ignore_ascii_case(account)).cloned()
        });
        by_account.or_else(|| (self.refresh_tokens.len() == 1).then(|| self.refresh_tokens[0].clone()))
    }
}

fn is_tenant_id(realm: &str) -> bool {
    realm.len() == 36 && realm.chars().filter(|character| *character == '-').count() == 4
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;

    use super::*;

    fn profile(dir: &Path) {
        fs::write(
            dir.join("azureProfile.json"),
            "\u{feff}{\"subscriptions\":[{\"id\":\"sub-1\",\"tenantId\":\"tenant-1\"},\
             {\"id\":\"sub-2\",\"tenantId\":\"tenant-2\",\"isDefault\":true}]}",
        )
        .unwrap();
    }

    fn cache(dir: &Path, access: Value, refresh: Value) {
        fs::write(
            dir.join("msal_token_cache.json"),
            json!({ "AccessToken": access, "RefreshToken": refresh }).to_string(),
        )
        .unwrap();
    }

    #[test]
    fn the_default_subscription_comes_from_the_profile_file() {
        let tmp = tempfile::tempdir().unwrap();
        profile(tmp.path());
        let cache = TokenCache::new(tmp.path());
        assert_eq!(cache.default_subscription(), Some("sub-2".into()));
    }

    #[test]
    fn subscriptions_resolve_to_their_tenant() {
        let tmp = tempfile::tempdir().unwrap();
        profile(tmp.path());
        cache(tmp.path(), json!({}), json!({}));
        let cache = TokenCache::new(tmp.path()).load().unwrap();
        assert_eq!(cache.tenant_for(Some("sub-1"), None).unwrap(), "tenant-1");
        assert_eq!(cache.tenant_for(None, Some("tenant-x")).unwrap(), "tenant-x");
        assert!(cache.tenant_for(Some("missing"), None).is_err());
        assert_eq!(cache.tenant_for(None, None).unwrap(), "tenant-2");
    }

    #[test]
    fn access_tokens_are_matched_by_resource_tenant_and_expiry() {
        let tmp = tempfile::tempdir().unwrap();
        profile(tmp.path());
        let now = OffsetDateTime::now_utc().unix_timestamp();
        cache(
            tmp.path(),
            json!({
                "vault-current": {
                    "secret": "vault-token",
                    "expires_on": (now + 3600).to_string(),
                    "realm": "tenant-1",
                    "target": "https://vault.azure.net/.default https://vault.azure.net/user_impersonation",
                    "environment": "login.microsoftonline.com",
                    "home_account_id": "account",
                    "client_id": CLIENT_ID
                },
                "vault-expired": {
                    "secret": "expired",
                    "expires_on": (now - 10).to_string(),
                    "realm": "tenant-2",
                    "target": "https://vault.azure.net/.default",
                    "client_id": CLIENT_ID
                },
                "other-client": {
                    "secret": "other",
                    "expires_on": (now + 3600).to_string(),
                    "realm": "tenant-1",
                    "target": "https://vault.azure.net/.default",
                    "client_id": "another-client"
                }
            }),
            json!({
                "refresh": {
                    "secret": "refresh-token",
                    "environment": "login.microsoftonline.com",
                    "home_account_id": "account",
                    "client_id": CLIENT_ID
                }
            }),
        );
        let cache = TokenCache::new(tmp.path()).load().unwrap();
        let token = cache.access_token("https://vault.azure.net", "tenant-1").unwrap();
        assert_eq!(token.secret, "vault-token");
        assert!(cache.access_token("https://vault.azure.net", "tenant-2").is_none());
        assert_eq!(cache.account_for_tenant("tenant-1").as_deref(), Some("account"));
        assert_eq!(cache.refresh_token(Some("account")).unwrap().secret, "refresh-token");
    }

    #[test]
    fn legacy_resource_scopes_are_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        profile(tmp.path());
        let now = OffsetDateTime::now_utc().unix_timestamp();
        cache(
            tmp.path(),
            json!({
                "legacy": {
                    "secret": "legacy-token",
                    "expires_on": (now + 3600).to_string(),
                    "realm": "tenant-1",
                    "target": "https://vault.azure.net",
                    "client_id": CLIENT_ID
                }
            }),
            json!({}),
        );
        let cache = TokenCache::new(tmp.path()).load().unwrap();
        assert_eq!(cache.access_token("https://vault.azure.net/", "tenant-1").unwrap().secret, "legacy-token");
    }

    #[test]
    fn a_missing_cache_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let err = TokenCache::new(tmp.path()).load().unwrap_err();
        assert!(err.to_string().contains("msal_token_cache.json"));
    }
}
