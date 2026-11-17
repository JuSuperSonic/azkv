use std::sync::Arc;

use anyhow::Result;
use azkv_core::arm::Arm;
use azkv_core::credential::AzAuth;
use azkv_core::vault::KvVault;
use azkv_core::{Overview, Profile, ProxySettings, Subscription, Tenant, Vault};
use tracing::warn;

pub struct Connected {
    auth: Arc<AzAuth>,
    pub vault: Vault,
}

pub fn arm_for(profile: &Profile, proxy: &Option<ProxySettings>) -> Result<Arm> {
    Ok(Arm::new(AzAuth::new(profile.dir.clone()), proxy.as_ref())?)
}

/// Subscriptions and tenants, with per-tenant warnings logged once.
pub async fn overview(profile: &Profile, proxy: &Option<ProxySettings>) -> Result<Overview> {
    overview_of(&arm_for(profile, proxy)?).await
}

/// Same as [`overview`] for a client the caller already built.
pub async fn overview_of(arm: &Arm) -> Result<Overview> {
    let overview = arm.overview().await?;
    for warning in &overview.warnings {
        warn!("{warning}");
    }
    Ok(overview)
}

pub async fn connect(
    profile: &Profile,
    spec: &str,
    preferred: Option<&str>,
    proxy: &Option<ProxySettings>,
) -> Result<Connected> {
    let auth = AzAuth::new(profile.dir.clone());
    let arm = Arm::new(Arc::clone(&auth), proxy.as_ref())?;
    let overview = overview_of(&arm).await?;
    let vault = arm.find_vault(spec, &overview.subscriptions, preferred).await?;
    Ok(Connected { auth, vault })
}

pub fn vault_client(connected: &Connected, proxy: &Option<ProxySettings>) -> Result<KvVault> {
    Ok(KvVault::for_vault(&connected.vault, &connected.auth, proxy.as_ref())?)
}

/// Connect to a vault when only the client is needed.
pub async fn client(
    profile: &Profile,
    spec: &str,
    preferred: Option<&str>,
    proxy: &Option<ProxySettings>,
) -> Result<KvVault> {
    vault_client(&connect(profile, spec, preferred, proxy).await?, proxy)
}

pub fn matches_subscription(sub: &Subscription, needle: &str) -> bool {
    sub.id == needle || sub.name.eq_ignore_ascii_case(needle)
}

pub fn filter_by_tenant(subscriptions: &[Subscription], tenants: &[Tenant], needle: &str) -> Vec<Subscription> {
    let ids: Vec<&str> = tenants
        .iter()
        .filter(|tenant| tenant.id == needle || tenant.name.eq_ignore_ascii_case(needle))
        .map(|tenant| tenant.id.as_str())
        .collect();
    subscriptions.iter().filter(|sub| ids.contains(&sub.tenant_id.as_str())).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(id: &str, name: &str, tenant: &str, default: bool) -> Subscription {
        Subscription {
            id: id.into(),
            name: name.into(),
            tenant_id: tenant.into(),
            state: "Enabled".into(),
            is_default: default,
        }
    }

    #[test]
    fn subscriptions_match_id_or_name() {
        let subs = [sub("id-1", "prod", "t1", true)];
        assert!(matches_subscription(&subs[0], "id-1"));
        assert!(matches_subscription(&subs[0], "PROD"));
        assert!(!matches_subscription(&subs[0], "dev"));
    }

    #[test]
    fn tenant_filter_matches_id_or_display_name() {
        let subs = [sub("s1", "one", "t1", true), sub("s2", "two", "t2", false)];
        let tenants =
            [Tenant { id: "t1".into(), name: "Coucou".into() }, Tenant { id: "t2".into(), name: "test".into() }];
        let filtered = filter_by_tenant(&subs, &tenants, "test");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "s2");
        assert_eq!(filter_by_tenant(&subs, &tenants, "t1")[0].id, "s1");
        assert!(filter_by_tenant(&subs, &tenants, "missing").is_empty());
    }
}
