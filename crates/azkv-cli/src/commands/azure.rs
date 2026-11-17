use anyhow::{Context as _, Result};
use azkv_core::Subscription;
use azkv_core::arm::Arm;
use azkv_core::profiles;
use futures::StreamExt;
use futures::stream;
use tracing::{info, warn};

use super::Context;
use crate::logging::OUTPUT;
use crate::session::{arm_for, filter_by_tenant, matches_subscription, overview, overview_of};

pub async fn profiles() -> Result<()> {
    let active = profiles::active().ok();
    for profile in profiles::discover()? {
        let marker = if active.as_ref().is_some_and(|a| a.dir == profile.dir) { "*" } else { " " };
        info!(target: OUTPUT, "{marker} {:<12} {}", profile.name, profile.dir.display());
    }
    Ok(())
}

pub async fn tenants(ctx: &Context) -> Result<()> {
    let overview = overview(&ctx.profile, &ctx.proxy).await?;
    for tenant in &overview.tenants {
        let count = overview.subscriptions.iter().filter(|sub| sub.tenant_id == tenant.id).count();
        info!(target: OUTPUT, "{}\t{}\t{} subscriptions", tenant.name, tenant.id, count);
    }
    Ok(())
}

pub async fn subscriptions(ctx: &Context, tenant: Option<String>) -> Result<()> {
    let overview = overview(&ctx.profile, &ctx.proxy).await?;
    let subs = match tenant {
        Some(needle) => filter_by_tenant(&overview.subscriptions, &overview.tenants, &needle),
        None => overview.subscriptions,
    };
    for sub in &subs {
        let marker = if sub.is_default { "*" } else { " " };
        info!(target: OUTPUT, "{marker} {}\t{}\t{}\t{}", sub.name, sub.id, sub.tenant_id, sub.state);
    }
    Ok(())
}

pub async fn vaults(ctx: &Context, subscription: Option<String>, tenant: Option<String>, all: bool) -> Result<()> {
    let arm = arm_for(&ctx.profile, &ctx.proxy)?;
    let overview = overview_of(&arm).await?;
    let mut subs = match tenant {
        Some(needle) => filter_by_tenant(&overview.subscriptions, &overview.tenants, &needle),
        None => overview.subscriptions.clone(),
    };
    if all {
        list_all(&arm, &subs).await;
        return Ok(());
    }
    let sub = match subscription {
        Some(needle) => subs
            .iter()
            .find(|sub| matches_subscription(sub, &needle))
            .cloned()
            .with_context(|| format!("subscription '{needle}' not found"))?,
        None => {
            subs.sort_by_key(|sub| !sub.is_default);
            subs.into_iter().next().context("no subscriptions in this profile")?
        },
    };
    for vault in arm.vaults(&sub).await? {
        info!(target: OUTPUT, "{}", vault.url);
    }
    Ok(())
}

async fn list_all(arm: &Arm, subs: &[Subscription]) {
    let mut stream =
        stream::iter(subs.iter()).map(|sub| async move { (sub, arm.vaults(sub).await) }).buffer_unordered(8);
    while let Some((sub, result)) = stream.next().await {
        match result {
            Ok(vaults) => {
                for vault in vaults {
                    info!(target: OUTPUT, "{}\t{}", vault.url, sub.name);
                }
            },
            Err(err) => warn!(subscription = %sub.name, "cannot list vaults: {err:#}"),
        }
    }
}
