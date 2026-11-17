use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use futures::stream;
use reqwest::Client;
use serde::Deserialize;

use crate::credential::AzAuth;
use crate::error::{Error, Result};
use crate::model::{Subscription, Tenant, Vault, VaultInfo};
use crate::proxy::ProxySettings;

use self::model::{
    merge_subscription_results, parse_vault_info, subscriptions_from_arm, tenants_from_arm, vaults_from_arm,
};
use self::network::client_allowed;
use self::token::{Claims, claims_from_token};

const ARM: &str = "https://management.azure.com";

mod model;
mod network;
mod roles;
mod token;

pub use model::tenants_from;

#[derive(Clone, Debug, Default)]
pub struct Overview {
    pub subscriptions: Vec<Subscription>,
    pub tenants: Vec<Tenant>,
    pub warnings: Vec<String>,
}

/// Azure Resource Manager client: subscriptions, tenants, vaults and role
/// assignments over ARM REST. Tokens come from the Azure CLI's MSAL cache,
/// refreshed natively without starting the `az` binary.
#[derive(Clone)]
pub struct Arm {
    http: Client,
    auth: Arc<AzAuth>,
    proxy: Option<String>,
}

impl Arm {
    pub fn new(auth: Arc<AzAuth>, proxy: Option<&ProxySettings>) -> Result<Self> {
        let http = match proxy {
            Some(proxy) => proxy.http(),
            None => ProxySettings::shared_client()?,
        };
        Ok(Self { http, auth, proxy: proxy.map(ProxySettings::display_url) })
    }

    pub async fn subscriptions(&self) -> Result<Vec<Subscription>> {
        Ok(self.overview().await?.subscriptions)
    }

    /// Subscriptions across every tenant the profile can see, plus tenant names.
    pub async fn overview(&self) -> Result<Overview> {
        let default = self.auth.default_subscription();
        let default_hint = default.as_deref();
        let tenants = self.tenants().await.unwrap_or_default();
        let (subscriptions, warnings) = if tenants.is_empty() {
            (self.subscriptions_in(None, default_hint).await?, Vec::new())
        } else {
            let tenant_ids: Vec<String> = tenants.iter().map(|tenant| tenant.id.clone()).collect();
            let results = stream::iter(tenant_ids)
                .map(|tenant_id| async move {
                    let result = self.subscriptions_in(Some(&tenant_id), default_hint).await;
                    (tenant_id, result)
                })
                .buffer_unordered(8)
                .collect::<Vec<_>>()
                .await;
            let (by_id, warnings, last_error) = merge_subscription_results(results);
            if by_id.is_empty()
                && let Some(err) = last_error
            {
                return Err(err);
            }
            (by_id.into_values().collect(), warnings)
        };
        let tenants = if tenants.is_empty() { tenants_from(&subscriptions) } else { tenants };
        Ok(Overview { subscriptions, tenants, warnings })
    }

    async fn tenants(&self) -> Result<Vec<Tenant>> {
        let token = self.auth.arm_token(None, None).await?;
        let url = format!("{ARM}/tenants?api-version=2022-12-01");
        Ok(tenants_from_arm(self.get_all(&token, &url).await?))
    }

    async fn subscriptions_in(&self, tenant: Option<&str>, default: Option<&str>) -> Result<Vec<Subscription>> {
        let token = self.auth.arm_token(None, tenant).await?;
        let url = format!("{ARM}/subscriptions?api-version=2022-12-01");
        Ok(subscriptions_from_arm(self.get_all(&token, &url).await?, default))
    }

    pub async fn vaults(&self, subscription: &Subscription) -> Result<Vec<Vault>> {
        let token = self.auth.arm_token(Some(&subscription.id), None).await?;
        let url = format!(
            "{ARM}/subscriptions/{}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01",
            subscription.id
        );
        Ok(vaults_from_arm(self.get_all(&token, &url).await?, subscription))
    }

    /// Vault details plus the signed-in user's roles on it. Role lookup
    /// degrades to an error message instead of failing the window.
    pub async fn vault_info(&self, vault: &Vault) -> Result<VaultInfo> {
        let resource_group =
            vault.resource_group.as_deref().ok_or_else(|| Error::Config("resource group unknown".into()))?;
        let resource_id = vault.resource_id(resource_group);
        let token = self.auth.arm_token(Some(&vault.subscription_id), None).await?;
        let url = format!("{ARM}{resource_id}?api-version=2023-07-01");
        let (body, client_ip) = tokio::join!(self.get_text(&token, &url), self.client_ip(),);
        let body = body?;
        let mut info = parse_vault_info(&body)?;
        info.client_ip = client_ip;
        info.client_allowed = client_ip.map(|ip| client_allowed(&info, ip));
        info.resource_group = info.resource_group.or_else(|| Some(resource_group.to_string()));

        let claims = claims_from_token(&token);
        let Claims { name, oid } = claims;
        info.user = name;
        if info.rbac == Some(true) {
            match oid {
                Some(oid) => {
                    match self.roles(&token, &resource_id, resource_group, &vault.subscription_id, &oid).await {
                        Ok(roles) => info.roles = roles,
                        Err(err) => info.roles_error = Some(first_line(&err.to_string())),
                    }
                },
                None => info.roles_error = Some("no object id in the access token".into()),
            }
        }
        Ok(info)
    }

    /// Resolves a vault name or URL to the subscription that owns it.
    pub async fn find_vault(
        &self,
        spec: &str,
        subscriptions: &[Subscription],
        preferred: Option<&str>,
    ) -> Result<Vault> {
        let name = Vault::name_from_spec(spec);
        let preferred = preferred.and_then(|preferred| {
            subscriptions.iter().find(|sub| sub.id == preferred || sub.name.eq_ignore_ascii_case(preferred))
        });
        let first = preferred.or_else(|| subscriptions.iter().find(|sub| sub.is_default));

        if let Some(sub) = first
            && let Some(vault) = self.vault_in(sub, &name).await?
        {
            return Ok(vault);
        }

        let rest: Vec<(usize, &Subscription)> =
            subscriptions.iter().filter(|sub| first.is_none_or(|first| first.id != sub.id)).enumerate().collect();
        let found = stream::iter(rest)
            .map(|(index, sub)| {
                let name = name.clone();
                async move { (index, self.vault_in(sub, &name).await.ok().flatten()) }
            })
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        let mut found: Vec<(usize, Vault)> =
            found.into_iter().filter_map(|(index, vault)| vault.map(|vault| (index, vault))).collect();
        found.sort_by_key(|(index, _)| *index);
        found
            .into_iter()
            .next()
            .map(|(_, vault)| vault)
            .ok_or_else(|| Error::Input(format!("vault '{name}' not found in any accessible subscription")))
    }

    async fn vault_in(&self, subscription: &Subscription, name: &str) -> Result<Option<Vault>> {
        Ok(self.vaults(subscription).await?.into_iter().find(|vault| vault.name.eq_ignore_ascii_case(name)))
    }

    /// Public egress IP, requested through the same proxy as Azure calls.
    async fn client_ip(&self) -> Option<IpAddr> {
        let response = self.http.get("https://api.ipify.org").timeout(Duration::from_secs(2)).send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        response.text().await.ok()?.trim().parse().ok()
    }

    async fn get_text(&self, token: &str, url: &str) -> Result<String> {
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|err| Error::connect(&err, self.proxy.as_deref(), url))?;
        let status = response.status();
        let body = response.text().await.map_err(|err| Error::connect(&err, self.proxy.as_deref(), url))?;
        if !status.is_success() {
            let message = format!("Azure management API returned {status} for {url}: {}", first_line(&body));
            return Err(Error::from_status(status.as_u16(), message));
        }
        Ok(body)
    }

    /// Follows ARM `nextLink` pages. The token is only sent back to ARM.
    async fn get_all<T>(&self, token: &str, url: &str) -> Result<Vec<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut items = Vec::new();
        let mut next = Some(url.to_string());
        let mut pages = 0;
        while let Some(page_url) = next {
            pages += 1;
            if pages > 1000 {
                return Err(Error::Remote {
                    kind: crate::Remote::Other,
                    message: format!("too many pages listing {url}"),
                });
            }
            let body = self.get_text(token, &page_url).await?;
            let page: Page<T> = serde_json::from_str(&body).map_err(|source| Error::Parse {
                context: format!("unexpected list response from {page_url}"),
                source,
            })?;
            items.extend(page.value);
            next = match page.next_link {
                Some(link) => {
                    if !link.starts_with(ARM) {
                        return Err(Error::Remote {
                            kind: crate::Remote::Other,
                            message: format!("unexpected nextLink from {page_url}"),
                        });
                    }
                    Some(link)
                },
                None => None,
            };
        }
        Ok(items)
    }
}

#[derive(Deserialize)]
struct Page<T> {
    value: Vec<T>,
    #[serde(default, rename = "nextLink")]
    next_link: Option<String>,
}

pub(super) fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use self::model::{ArmSubscription, ArmVault};

    #[test]
    fn list_pages_expose_the_next_link() {
        let page: Page<ArmVault> =
            serde_json::from_str(r#"{"value":[],"nextLink":"https://management.azure.com/next"}"#).unwrap();
        assert_eq!(page.next_link.as_deref(), Some("https://management.azure.com/next"));
        let last: Page<ArmVault> = serde_json::from_str(r#"{"value":[]}"#).unwrap();
        assert!(last.next_link.is_none());
    }

    #[test]
    fn malformed_subscription_json_is_an_error() {
        assert!(serde_json::from_str::<Page<ArmSubscription>>("{").is_err());
    }
}
