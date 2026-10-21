use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use futures::StreamExt;
use futures::stream;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;

use crate::credential::AzAuth;
use crate::error::{Error, Result};
use crate::model::{Subscription, Tenant, Vault, VaultInfo};
use crate::proxy::ProxySettings;

const ARM: &str = "https://management.azure.com";
/// Role definitions rarely change; one list response is ~1 MB.
const ROLE_CACHE_TTL: Duration = Duration::from_secs(300);
type RoleNames = HashMap<String, String>;
type RoleNameCache = HashMap<String, (Instant, RoleNames)>;
static ROLE_NAMES: OnceLock<Mutex<RoleNameCache>> = OnceLock::new();

#[derive(Clone, Debug, Default)]
pub struct Overview {
    pub subscriptions: Vec<Subscription>,
    pub tenants: Vec<Tenant>,
    /// Tenants whose subscription lookup failed while others succeeded.
    pub warnings: Vec<String>,
}

/// Azure Resource Manager client: subscriptions, tenants, vaults and role
/// assignments over ARM REST. Tokens come from the Azure CLI's MSAL cache,
/// refreshed natively without starting the `az` binary.
///
/// ARM is spoken directly because the official Rust SDK has no management
/// clients for `azure_core` 1.x: the published `azure_mgmt_*` crates are from
/// the legacy 0.21 line. The reqwest client is the same one injected into the
/// Key Vault SDK as its `HttpClient`, so SOCKS5h works identically here.
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
        // Access-policy vaults have no relevant RBAC roles; only query IAM ones.
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

    /// Key Vault roles the signed-in user has on the vault, directly or through
    /// groups. `assignedTo()` expands transitive group membership server-side,
    /// which avoids the Graph permission problems of expanding groups ourselves.
    async fn roles(
        &self,
        token: &str,
        resource_id: &str,
        resource_group: &str,
        subscription_id: &str,
        oid: &str,
    ) -> Result<Vec<String>> {
        let scopes = [
            resource_id.to_string(),
            format!("/subscriptions/{subscription_id}/resourceGroups/{resource_group}"),
            format!("/subscriptions/{subscription_id}"),
        ];
        // Listing at subscription scope includes subscopes (resource groups and
        // vaults); higher management-group assignments are not inherited here.
        let url = format!(
            "{ARM}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=assignedTo('{oid}')"
        );
        let assignments: Vec<RoleAssignment> = self.get_all(token, &url).await?;
        let mut definition_ids = BTreeSet::new();
        for assignment in assignments {
            let properties = assignment.properties;
            let applies = properties
                .scope
                .as_deref()
                .is_some_and(|scope| scopes.iter().any(|candidate| candidate.eq_ignore_ascii_case(scope)));
            if applies && let Some(id) = properties.role_definition_id {
                definition_ids.insert(id);
            }
        }

        let mut roles = BTreeSet::new();
        let mut names = self.role_definition_names(token, subscription_id, &definition_ids).await?;
        for id in definition_ids {
            if let Some(name) = names.remove(&id.to_ascii_lowercase()) {
                roles.insert(name);
            }
        }
        let mut roles: Vec<String> = roles.into_iter().collect();
        roles.retain(|role| is_key_vault_role(role));
        Ok(roles)
    }

    /// Resolve role definition names with one subscription-wide list request.
    /// Assignments can point at roles defined above the subscription, so any
    /// IDs missing from the list are fetched individually in parallel.
    async fn role_definition_names(
        &self,
        token: &str,
        subscription_id: &str,
        ids: &BTreeSet<String>,
    ) -> Result<HashMap<String, String>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let url = format!(
            "{ARM}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
        );
        let mut names = match cached_role_names(subscription_id) {
            Some(names) => names,
            None => self
                .get_all::<RoleDefinition>(token, &url)
                .await
                .unwrap_or_default()
                .into_iter()
                .filter_map(|definition| Some((definition.id?.to_ascii_lowercase(), definition.properties.role_name?)))
                .collect(),
        };

        let missing: Vec<String> =
            ids.iter().filter(|id| !names.contains_key(&id.to_ascii_lowercase())).cloned().collect();
        let fetched: Vec<Result<(String, Option<String>)>> = stream::iter(missing)
            .map(|id| async move {
                let body = self.get_text(token, &format!("{ARM}{id}?api-version=2022-04-01")).await?;
                let definition: RoleDefinition = serde_json::from_str(&body)
                    .map_err(|source| Error::Parse { context: "unexpected role definition".into(), source })?;
                Ok((id, definition.properties.role_name))
            })
            .buffer_unordered(8)
            .collect()
            .await;
        let complete = merge_role_names(&mut names, fetched);
        if complete {
            cache_role_names(subscription_id, &names);
        }
        Ok(names)
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
        tokio::time::timeout(Duration::from_secs(2), async {
            let response = self.http.get("https://api.ipify.org").send().await.ok()?;
            if !response.status().is_success() {
                return None;
            }
            response.text().await.ok()?.trim().parse().ok()
        })
        .await
        .ok()?
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

fn merge_subscription_results(
    results: Vec<(String, Result<Vec<Subscription>>)>,
) -> (BTreeMap<String, Subscription>, Vec<String>, Option<Error>) {
    let mut by_id = BTreeMap::new();
    let mut warnings = Vec::new();
    let mut last_error = None;
    for (tenant, result) in results {
        match result {
            Ok(subscriptions) => {
                for subscription in subscriptions {
                    by_id.insert(subscription.id.clone(), subscription);
                }
            },
            Err(err) => {
                warnings.push(format!("tenant {tenant}: {}", first_line(&err.to_string())));
                last_error = Some(err);
            },
        }
    }
    warnings.sort();
    (by_id, warnings, last_error)
}

#[derive(Deserialize)]
struct Page<T> {
    value: Vec<T>,
    #[serde(default, rename = "nextLink")]
    next_link: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArmSubscription {
    subscription_id: String,
    #[serde(default)]
    display_name: Option<String>,
    tenant_id: String,
    #[serde(default)]
    state: Option<String>,
}

fn subscriptions_from_arm(items: Vec<ArmSubscription>, default: Option<&str>) -> Vec<Subscription> {
    let mut subscriptions: Vec<Subscription> = items
        .into_iter()
        .map(|sub| Subscription {
            is_default: default == Some(sub.subscription_id.as_str()),
            name: sub.display_name.filter(|name| !name.is_empty()).unwrap_or_else(|| sub.subscription_id.clone()),
            id: sub.subscription_id,
            tenant_id: sub.tenant_id,
            state: sub.state.filter(|state| !state.is_empty()).unwrap_or_else(|| "Unknown".into()),
        })
        .collect();
    subscriptions.sort_by(|a, b| {
        b.is_default.cmp(&a.is_default).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    subscriptions
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArmTenant {
    tenant_id: String,
    #[serde(default)]
    display_name: Option<String>,
}

fn tenants_from_arm(items: Vec<ArmTenant>) -> Vec<Tenant> {
    let mut tenants: Vec<Tenant> = items
        .into_iter()
        .map(|tenant| Tenant {
            name: tenant.display_name.filter(|name| !name.is_empty()).unwrap_or_else(|| tenant.tenant_id.clone()),
            id: tenant.tenant_id,
        })
        .collect();
    tenants.sort_by_key(|tenant| tenant.name.to_lowercase());
    tenants
}

pub fn tenants_from(subscriptions: &[Subscription]) -> Vec<Tenant> {
    let mut tenants = BTreeMap::new();
    for subscription in subscriptions {
        tenants
            .entry(subscription.tenant_id.clone())
            .or_insert_with(|| Tenant { id: subscription.tenant_id.clone(), name: subscription.tenant_id.clone() });
    }
    tenants.into_values().collect()
}

#[derive(Deserialize)]
struct ArmVault {
    #[serde(default)]
    id: String,
    name: String,
    #[serde(default)]
    properties: Option<ArmVaultProperties>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArmVaultProperties {
    #[serde(default)]
    vault_uri: Option<String>,
}

fn vaults_from_arm(items: Vec<ArmVault>, subscription: &Subscription) -> Vec<Vault> {
    let mut vaults: Vec<Vault> = items
        .into_iter()
        .map(|item| {
            let mut vault = Vault::from_name(&item.name, subscription, resource_group_of(&item.id));
            if let Some(uri) = item.properties.and_then(|props| props.vault_uri)
                && !uri.is_empty()
            {
                vault.url = format!("{}/", uri.trim_end_matches('/'));
            }
            vault
        })
        .collect();
    vaults.sort_by(|a, b| a.name.cmp(&b.name));
    vaults
}

fn resource_group_of(resource_id: &str) -> Option<String> {
    let rest = resource_id.split_once("/resourceGroups/")?.1;
    let group = rest.split('/').next()?;
    (!group.is_empty()).then(|| group.to_string())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultJson {
    #[serde(default)]
    resource_group: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    properties: VaultPropertiesJson,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct VaultPropertiesJson {
    #[serde(default)]
    public_network_access: Option<String>,
    #[serde(default)]
    network_acls: Option<NetworkAclsJson>,
    #[serde(default)]
    private_endpoint_connections: Option<Vec<Value>>,
    #[serde(default)]
    enable_rbac_authorization: Option<bool>,
    #[serde(default)]
    soft_delete_retention_in_days: Option<i64>,
    #[serde(default)]
    enable_purge_protection: Option<bool>,
    #[serde(default)]
    sku: Option<SkuJson>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct NetworkAclsJson {
    #[serde(default)]
    default_action: Option<String>,
    #[serde(default)]
    bypass: Option<String>,
    #[serde(default)]
    ip_rules: Option<Vec<IpRuleJson>>,
    #[serde(default)]
    virtual_network_rules: Option<Vec<Value>>,
}

#[derive(Deserialize)]
struct IpRuleJson {
    #[serde(default)]
    value: Option<String>,
}

#[derive(Deserialize)]
struct SkuJson {
    #[serde(default)]
    name: Option<String>,
}

fn parse_vault_info(json: &str) -> Result<VaultInfo> {
    let parsed: VaultJson = serde_json::from_str(json)
        .map_err(|source| Error::Parse { context: "unexpected vault response".into(), source })?;
    let properties = parsed.properties;
    let acls = properties.network_acls.unwrap_or_default();
    Ok(VaultInfo {
        resource_group: parsed.resource_group,
        location: parsed.location,
        sku: properties.sku.and_then(|sku| sku.name),
        public_network_access: properties.public_network_access,
        firewall: acls.default_action,
        bypass: acls.bypass,
        ip_rules: acls.ip_rules.unwrap_or_default().into_iter().filter_map(|rule| rule.value).collect(),
        vnet_rules: acls.virtual_network_rules.map_or(0, |rules| rules.len()),
        private_endpoints: properties.private_endpoint_connections.map_or(0, |items| items.len()),
        rbac: properties.enable_rbac_authorization,
        soft_delete_days: properties.soft_delete_retention_in_days,
        purge_protection: properties.enable_purge_protection,
        ..VaultInfo::default()
    })
}

#[derive(Deserialize)]
struct RoleAssignment {
    #[serde(default)]
    properties: RoleAssignmentProperties,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RoleAssignmentProperties {
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    role_definition_id: Option<String>,
}

#[derive(Deserialize)]
struct RoleDefinition {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    properties: RoleDefinitionProperties,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RoleDefinitionProperties {
    #[serde(default)]
    role_name: Option<String>,
}

struct Claims {
    name: Option<String>,
    oid: Option<String>,
}

fn claims_from_token(token: &str) -> Claims {
    let payload = token
        .split('.')
        .nth(1)
        .and_then(base64_url_decode)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let claim = |keys: &[&str]| {
        let payload = payload.as_ref()?;
        keys.iter().find_map(|key| payload.get(*key).and_then(Value::as_str)).map(str::to_string)
    };
    Claims { name: claim(&["upn", "unique_name", "preferred_username", "name"]), oid: claim(&["oid"]) }
}

fn base64_url_decode(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => break,
            _ => return None,
        } as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(bytes)
}

fn client_allowed(info: &VaultInfo, ip: IpAddr) -> bool {
    if info.public_network_access.as_deref().is_some_and(|access| access.eq_ignore_ascii_case("Disabled")) {
        return false;
    }
    match info.firewall.as_deref() {
        Some(action) if action.eq_ignore_ascii_case("Deny") => info.ip_rules.iter().any(|rule| ip_in_rule(ip, rule)),
        Some(action) if action.eq_ignore_ascii_case("Allow") => true,
        // Azure defaults the firewall action to Allow when it is not set.
        None => true,
        _ => false,
    }
}

fn ip_in_rule(ip: IpAddr, rule: &str) -> bool {
    let rule = rule.trim();
    let (base, prefix) = match rule.split_once('/') {
        Some((base, prefix)) => match prefix.parse::<u8>() {
            Ok(prefix) => (base, Some(prefix)),
            Err(_) => return false,
        },
        None => (rule, None),
    };
    match (ip, base.trim().parse::<IpAddr>()) {
        (IpAddr::V4(ip), Ok(IpAddr::V4(base))) => {
            let prefix = prefix.unwrap_or(32);
            prefix <= 32 && (prefix == 0 || u32::from(ip) >> (32 - prefix) == u32::from(base) >> (32 - prefix))
        },
        (IpAddr::V6(ip), Ok(IpAddr::V6(base))) => {
            let prefix = prefix.unwrap_or(128);
            prefix <= 128 && (prefix == 0 || u128::from(ip) >> (128 - prefix) == u128::from(base) >> (128 - prefix))
        },
        _ => false,
    }
}

/// Built-in and custom Key Vault roles are named `Key Vault ...`.
fn is_key_vault_role(name: &str) -> bool {
    name.starts_with("Key Vault")
}

/// Merge the fallback lookups that succeeded. Returns false when any failed,
/// so a partial result is not cached.
fn merge_role_names(names: &mut HashMap<String, String>, fetched: Vec<Result<(String, Option<String>)>>) -> bool {
    let mut complete = true;
    for result in fetched {
        match result {
            Ok((id, Some(name))) => {
                names.insert(id.to_ascii_lowercase(), name);
            },
            Ok((_, None)) => {},
            Err(_) => complete = false,
        }
    }
    complete
}

fn cached_role_names(subscription_id: &str) -> Option<HashMap<String, String>> {
    let cache = ROLE_NAMES.get_or_init(|| Mutex::new(HashMap::new()));
    let cache = cache.lock().ok()?;
    let (at, names) = cache.get(&subscription_id.to_ascii_lowercase())?;
    (at.elapsed() < ROLE_CACHE_TTL).then(|| names.clone())
}

fn cache_role_names(subscription_id: &str, names: &HashMap<String, String>) {
    if names.is_empty() {
        return;
    }
    let cache = ROLE_NAMES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut cache) = cache.lock() {
        cache.insert(subscription_id.to_ascii_lowercase(), (Instant::now(), names.clone()));
    }
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subscription(id: &str, tenant: &str, is_default: bool) -> Subscription {
        Subscription {
            id: id.into(),
            name: format!("sub-{id}"),
            tenant_id: tenant.into(),
            state: "Enabled".into(),
            is_default,
        }
    }

    #[test]
    fn subscriptions_are_parsed_from_arm_with_default_first() {
        let items: Page<ArmSubscription> = serde_json::from_str(
            r#"{"value":[
              {"subscriptionId":"s1","displayName":"Alpha","tenantId":"t1","state":"Enabled"},
              {"subscriptionId":"s2","displayName":"zeta","tenantId":"t1","state":"Enabled"}
            ]}"#,
        )
        .unwrap();
        let subs = subscriptions_from_arm(items.value, Some("s2"));
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].id, "s2");
        assert!(subs[0].is_default);
        assert_eq!(subs[1].name, "Alpha");
    }

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

    #[test]
    fn tenants_use_display_name_and_are_sorted() {
        let items: Page<ArmTenant> = serde_json::from_str(
            r#"{"value":[
              {"tenantId":"t2","displayName":"Zeta"},
              {"tenantId":"t1","displayName":"alpha"},
              {"tenantId":"t3","displayName":null}
            ]}"#,
        )
        .unwrap();
        let tenants = tenants_from_arm(items.value);
        assert_eq!(tenants[0].name, "alpha");
        assert_eq!(tenants[1].name, "t3");
        assert_eq!(tenants[1].id, "t3");
    }

    #[test]
    fn partial_tenant_failures_keep_subscriptions_and_report_the_tenant() {
        let results = vec![
            ("t1".into(), Ok(vec![subscription("s1", "t1", true)])),
            ("t2".into(), Err(Error::Config("denied".into()))),
        ];
        let (by_id, warnings, last_error) = merge_subscription_results(results);
        assert_eq!(by_id.len(), 1);
        assert!(by_id.contains_key("s1"));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("t2"));
        assert!(last_error.is_some());
    }

    #[test]
    fn every_tenant_failing_is_an_error() {
        let results = vec![
            ("t1".into(), Err(Error::Config("denied".into()))),
            ("t2".into(), Err(Error::Config("denied".into()))),
        ];
        let (by_id, _, last_error) = merge_subscription_results(results);
        assert!(by_id.is_empty());
        assert!(last_error.is_some());
    }

    #[test]
    fn a_failed_role_lookup_does_not_hide_resolved_roles() {
        let mut names = HashMap::from([("builtin".to_string(), "Key Vault Reader".to_string())]);
        let complete = merge_role_names(
            &mut names,
            vec![
                Ok(("custom".to_string(), Some("Key Vault Secrets Officer".to_string()))),
                Err(Error::Config("denied".into())),
            ],
        );
        assert!(!complete);
        assert_eq!(names["custom"], "Key Vault Secrets Officer");
        assert_eq!(names["builtin"], "Key Vault Reader");
    }

    #[test]
    fn tenants_can_be_derived_from_subscriptions() {
        let subs = [subscription("a", "t1", true), subscription("b", "t1", false), subscription("c", "t2", false)];
        let tenants = tenants_from(&subs);
        assert_eq!(tenants.len(), 2);
        assert_eq!(tenants[0].id, "t1");
        assert_eq!(tenants[0].name, "t1");
    }

    #[test]
    fn vaults_carry_their_resource_group_from_the_arm_id() {
        let sub = subscription("s1", "t1", true);
        let items: Page<ArmVault> = serde_json::from_str(
            r#"{"value":[
              {"id":"/subscriptions/s1/resourceGroups/rg-b/providers/Microsoft.KeyVault/vaults/kv-b","name":"kv-b","properties":{"vaultUri":"https://kv-b.vault.azure.net/"}},
              {"id":"/subscriptions/s1/resourceGroups/rg-a/providers/Microsoft.KeyVault/vaults/kv-a","name":"kv-a"}
            ]}"#,
        )
        .unwrap();
        let vaults = vaults_from_arm(items.value, &sub);
        assert_eq!(vaults.len(), 2);
        assert_eq!(vaults[0].name, "kv-a");
        assert_eq!(vaults[0].resource_group.as_deref(), Some("rg-a"));
        assert_eq!(vaults[0].url, "https://kv-a.vault.azure.net/");
        assert_eq!(vaults[1].url, "https://kv-b.vault.azure.net/");
        assert_eq!(vaults[1].subscription_id, "s1");
        assert_eq!(vaults[1].tenant_id, "t1");
    }

    #[test]
    fn vault_info_parses_firewall_and_properties() {
        let json = r#"{
          "resourceGroup": "rg-kv",
          "location": "westeurope",
          "properties": {
            "publicNetworkAccess": "Enabled",
            "enableRbacAuthorization": true,
            "softDeleteRetentionInDays": 90,
            "enablePurgeProtection": true,
            "privateEndpointConnections": [{ "id": "pe-1" }],
            "sku": { "name": "standard" },
            "networkAcls": {
              "defaultAction": "Deny",
              "bypass": "AzureServices",
              "ipRules": [{ "value": "1.2.3.4" }, { "value": "5.6.7.8" }],
              "virtualNetworkRules": [{ "id": "subnet-1" }]
            }
          }
        }"#;
        let info = parse_vault_info(json).unwrap();
        assert_eq!(info.resource_group.as_deref(), Some("rg-kv"));
        assert_eq!(info.location.as_deref(), Some("westeurope"));
        assert_eq!(info.sku.as_deref(), Some("standard"));
        assert_eq!(info.public_network_access.as_deref(), Some("Enabled"));
        assert_eq!(info.firewall.as_deref(), Some("Deny"));
        assert_eq!(info.bypass.as_deref(), Some("AzureServices"));
        assert_eq!(info.ip_rules, ["1.2.3.4", "5.6.7.8"]);
        assert_eq!(info.vnet_rules, 1);
        assert_eq!(info.private_endpoints, 1);
        assert_eq!(info.rbac, Some(true));
        assert_eq!(info.soft_delete_days, Some(90));
        assert_eq!(info.purge_protection, Some(true));
        assert!(info.roles.is_empty());
        assert!(info.user.is_none());
    }

    #[test]
    fn only_key_vault_roles_are_kept() {
        assert!(is_key_vault_role("Key Vault Reader"));
        assert!(is_key_vault_role("Key Vault Secrets Officer"));
        assert!(!is_key_vault_role("Contributor"));
        assert!(!is_key_vault_role("User Access Administrator"));
    }

    #[test]
    fn role_definition_names_are_cached_per_subscription() {
        let subscription = "cache-test-subscription";
        let mut names = HashMap::new();
        names.insert("id-1".into(), "Key Vault Reader".into());
        cache_role_names(subscription, &names);
        assert_eq!(cached_role_names(subscription), Some(names));
        cache_role_names("cache-empty-subscription", &HashMap::new());
        assert!(cached_role_names("cache-empty-subscription").is_none());
    }

    #[test]
    fn vault_info_tolerates_missing_network_acls() {
        let info = parse_vault_info(r#"{"properties":{}}"#).unwrap();
        assert_eq!(info, VaultInfo::default());
    }

    #[test]
    fn firewall_rules_match_single_addresses_and_cidrs() {
        assert!(ip_in_rule("51.103.78.171".parse().unwrap(), "51.103.78.171"));
        assert!(ip_in_rule("51.103.78.171".parse().unwrap(), "51.103.78.0/24"));
        assert!(!ip_in_rule("51.103.79.1".parse().unwrap(), "51.103.78.0/24"));
        assert!(ip_in_rule("51.103.79.1".parse().unwrap(), "0.0.0.0/0"));
        assert!(ip_in_rule("2001:db8::1".parse().unwrap(), "2001:db8::/32"));
        assert!(!ip_in_rule("2001:db9::1".parse().unwrap(), "2001:db8::/32"));
        assert!(!ip_in_rule("51.103.78.171".parse().unwrap(), "2001:db8::/32"));
        assert!(!ip_in_rule("51.103.78.171".parse().unwrap(), "not-an-ip"));
    }

    #[test]
    fn client_verdict_follows_public_access_and_ip_rules() {
        let mut info =
            VaultInfo { firewall: Some("Deny".into()), ip_rules: vec!["10.0.0.0/8".into()], ..VaultInfo::default() };
        let ip = "10.1.2.3".parse().unwrap();
        assert!(client_allowed(&info, ip));
        assert!(!client_allowed(&info, "192.0.2.1".parse().unwrap()));

        info.firewall = Some("Allow".into());
        assert!(client_allowed(&info, "192.0.2.1".parse().unwrap()));

        info.firewall = Some("Deny".into());
        info.public_network_access = Some("Disabled".into());
        assert!(!client_allowed(&info, ip));

        info.public_network_access = None;
        info.firewall = None;
        assert!(client_allowed(&info, ip));
    }

    #[test]
    fn claims_are_read_from_the_access_token() {
        let claims = claims_from_token("x.eyJ1cG4iOiAiYUBiLmMiLCAib2lkIjogIm9pZC0xIn0.y");
        assert_eq!(claims.name.as_deref(), Some("a@b.c"));
        assert_eq!(claims.oid.as_deref(), Some("oid-1"));
        assert!(claims_from_token("not-a-jwt").name.is_none());
    }
}
