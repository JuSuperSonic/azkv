use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::model::{Subscription, Tenant, Vault, VaultInfo};

use super::first_line;

pub(super) fn merge_subscription_results(
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
#[serde(rename_all = "camelCase")]
pub(super) struct ArmSubscription {
    subscription_id: String,
    #[serde(default)]
    display_name: Option<String>,
    tenant_id: String,
    #[serde(default)]
    state: Option<String>,
}

pub(super) fn subscriptions_from_arm(items: Vec<ArmSubscription>, default: Option<&str>) -> Vec<Subscription> {
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
pub(super) struct ArmTenant {
    tenant_id: String,
    #[serde(default)]
    display_name: Option<String>,
}

pub(super) fn tenants_from_arm(items: Vec<ArmTenant>) -> Vec<Tenant> {
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
pub(super) struct ArmVault {
    #[serde(default)]
    id: String,
    name: String,
    #[serde(default)]
    properties: Option<ArmVaultProperties>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ArmVaultProperties {
    #[serde(default)]
    vault_uri: Option<String>,
}

pub(super) fn vaults_from_arm(items: Vec<ArmVault>, subscription: &Subscription) -> Vec<Vault> {
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

pub(super) fn resource_group_of(resource_id: &str) -> Option<String> {
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

pub(super) fn parse_vault_info(json: &str) -> Result<VaultInfo> {
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

#[cfg(test)]
mod tests {
    use super::super::Page;
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
    fn vault_info_tolerates_missing_network_acls() {
        let info = parse_vault_info(r#"{"properties":{}}"#).unwrap();
        assert_eq!(info, VaultInfo::default());
    }
}
