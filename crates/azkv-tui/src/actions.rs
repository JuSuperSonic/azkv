use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::app::{Action, Msg, matches};
use crate::error::short;
use anyhow::{Result, bail};
use azkv_core::arm::Arm;
use azkv_core::copy::{DEFAULT_CONCURRENCY, execute_copy, plan};
use azkv_core::credential::AzAuth;
use azkv_core::vault::KvVault;
use azkv_core::{Profile, ProxySettings, Secret, SecretMeta, SecretStore, clipboard, is_not_found};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{info, warn};

pub type AuthCache = HashMap<PathBuf, Arc<AzAuth>>;

fn auth_for(profile: &Profile, cache: &mut AuthCache) -> Arc<AzAuth> {
    cache.entry(profile.dir.clone()).or_insert_with(|| AzAuth::new(profile.dir.clone())).clone()
}

pub fn execute(
    action: Action,
    tx: &UnboundedSender<Msg>,
    auths: &mut AuthCache,
    proxy: Option<&ProxySettings>,
) -> bool {
    let proxy = proxy.cloned();
    match action {
        Action::Quit => return true,
        Action::Copy(text) => {
            let result = clipboard::copy(&text).map_err(|err| err.to_string());
            let _ = tx.send(Msg::Copied(result));
        },
        Action::LoadOverview { profile } => {
            let auth = auth_for(&profile, auths);
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = match Arm::new(auth, proxy.as_ref()) {
                    Ok(arm) => arm
                        .overview()
                        .await
                        .inspect(|overview| {
                            for warning in &overview.warnings {
                                warn!("{warning}");
                            }
                        })
                        .map_err(short),
                    Err(err) => Err(short(err)),
                };
                let _ = tx.send(Msg::Overview { dir: profile.dir, result });
            });
        },
        Action::LoadVaults { profile, subscription } => {
            let auth = auth_for(&profile, auths);
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = match Arm::new(auth, proxy.as_ref()) {
                    Ok(arm) => arm.vaults(&subscription).await.map_err(short),
                    Err(err) => Err(short(err)),
                };
                let _ = tx.send(Msg::Vaults { dir: profile.dir, subscription_id: subscription.id, result });
            });
        },
        Action::LoadSecrets { profile, subscription: _, vault } => {
            let auth = auth_for(&profile, auths);
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = match KvVault::for_vault(&vault, &auth, proxy.as_ref()) {
                    Ok(client) => client.meta().await.map_err(short),
                    Err(err) => Err(short(err)),
                };
                let _ = tx.send(Msg::Secrets { url: vault.url, result });
            });
        },
        Action::FetchValue { profile, subscription: _, vault, name } => {
            let auth = auth_for(&profile, auths);
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = match KvVault::for_vault(&vault, &auth, proxy.as_ref()) {
                    Ok(client) => client.get(&name).await.map(|secret| secret.value).map_err(short),
                    Err(err) => Err(short(err)),
                };
                let _ = tx.send(Msg::Value { url: vault.url, name, result });
            });
        },
        Action::RefreshSecret { profile, subscription: _, vault, name } => {
            let auth = auth_for(&profile, auths);
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = match KvVault::for_vault(&vault, &auth, proxy.as_ref()) {
                    Ok(client) => client.refresh(&name).await.map_err(short),
                    Err(err) => Err(short(err)),
                };
                let _ = tx.send(Msg::Refreshed { url: vault.url, name, result });
            });
        },
        Action::SaveSecret { profile, vault, secret, updated, patch } => {
            let auth = auth_for(&profile, auths);
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = match KvVault::for_vault(&vault, &auth, proxy.as_ref()) {
                    Ok(client) => save_secret(&client, &secret, updated, patch).await.map_err(short),
                    Err(err) => Err(short(err)),
                };
                let value = (!patch).then(|| secret.value.clone());
                let _ = tx.send(Msg::Saved { url: vault.url, name: secret.name, value, result });
            });
        },
        Action::LoadVaultInfo { profile, vault } => {
            let auth = auth_for(&profile, auths);
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = match Arm::new(auth, proxy.as_ref()) {
                    Ok(arm) => arm.vault_info(&vault).await.map_err(short),
                    Err(err) => Err(short(err)),
                };
                let _ = tx.send(Msg::VaultInfo { url: vault.url, result });
            });
        },
        Action::LoadCopyVaults { profile, subscription } => {
            let auth = auth_for(&profile, auths);
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = match Arm::new(auth, proxy.as_ref()) {
                    Ok(arm) => arm.vaults(&subscription).await.map_err(short),
                    Err(err) => Err(short(err)),
                };
                let _ = tx.send(Msg::CopyVaults { subscription_id: subscription.id, result });
            });
        },
        Action::CheckProxy { proxy } => {
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = proxy.check().await.map_err(short);
                let _ = tx.send(Msg::ProxyChecked { proxy, result });
            });
        },
        Action::DuplicateSecret { profile, vault, source, name } => {
            let auth = auth_for(&profile, auths);
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = match KvVault::for_vault(&vault, &auth, proxy.as_ref()) {
                    Ok(client) => duplicate_secret(&client, &source, &name).await.map_err(short),
                    Err(err) => Err(short(err)),
                };
                let _ = tx.send(Msg::Duplicated { url: vault.url, name, result });
            });
        },
        Action::DeleteSecret { profile, vault, name } => {
            let auth = auth_for(&profile, auths);
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = match KvVault::for_vault(&vault, &auth, proxy.as_ref()) {
                    Ok(client) => client.delete(&name).await.map_err(short),
                    Err(err) => Err(short(err)),
                };
                let _ = tx.send(Msg::Deleted { url: vault.url, name, result });
            });
        },
        Action::PlanCopyVault { profile, source, dest, filter } => {
            let auth = auth_for(&profile, auths);
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = async {
                    let source_client = KvVault::for_vault(&source, &auth, proxy.as_ref())?;
                    let dest_client = KvVault::for_vault(&dest, &auth, proxy.as_ref())?;
                    let names = source_client
                        .names()
                        .await?
                        .into_iter()
                        .filter(|name| matches(name, &filter))
                        .collect::<Vec<_>>();
                    let existing = dest_client.names().await?.into_iter().collect();
                    Ok::<_, anyhow::Error>(plan(&names, &existing, false))
                }
                .await
                .map_err(short);
                let _ = tx.send(Msg::CopyPlan { source, dest, result });
            });
        },
        Action::CopyVault { profile, source, dest, plan } => {
            let auth = auth_for(&profile, auths);
            let tx = tx.clone();
            tokio::spawn(async move {
                let source_name = source.name.clone();
                let dest_name = dest.name.clone();
                let result = async {
                    info!(
                        "copy {} -> {}: {} new, {} to overwrite, {} to skip",
                        source.name,
                        dest.name,
                        plan.create.len(),
                        plan.overwrite.len(),
                        plan.skip.len()
                    );
                    let source_client = KvVault::for_vault(&source, &auth, proxy.as_ref())?;
                    let dest_client = KvVault::for_vault(&dest, &auth, proxy.as_ref())?;
                    Ok::<_, anyhow::Error>(execute_copy(&source_client, &dest_client, &plan, DEFAULT_CONCURRENCY).await)
                }
                .await
                .map_err(short);
                if let Ok(report) = &result {
                    for (name, message) in &report.failed {
                        warn!("copy to {}: '{name}' failed: {message}", dest_name);
                    }
                }
                let _ = tx.send(Msg::CopiedVault { source: source_name, dest: dest_name, result });
            });
        },
    }
    false
}

async fn save_secret(
    client: &KvVault,
    secret: &Secret,
    updated: Option<Option<i128>>,
    patch: bool,
) -> Result<SecretMeta> {
    match updated {
        None => match client.get(&secret.name).await {
            Ok(_) => bail!("secret '{}' already exists", secret.name),
            Err(err) if is_not_found(&err) => {},
            Err(err) => return Err(err.into()),
        },
        Some(expected) if patch => {
            let Some(meta) = client.meta_of(&secret.name).await? else {
                bail!("secret '{}' not found", secret.name);
            };
            if meta.updated.map(|updated| updated.unix_timestamp_nanos()) != expected {
                bail!("secret '{}' changed since it was opened; close and reopen the editor", secret.name);
            }
        },
        Some(expected) => {
            let (meta, _) = client.refresh(&secret.name).await?;
            if meta.updated.map(|updated| updated.unix_timestamp_nanos()) != expected {
                bail!("secret '{}' changed since it was opened; close and reopen the editor", secret.name);
            }
        },
    }
    if patch { Ok(client.update(secret).await?) } else { Ok(client.put(secret).await?) }
}

async fn duplicate_secret(client: &KvVault, source: &str, name: &str) -> Result<SecretMeta> {
    let secret = client.get(source).await?;
    match client.get(name).await {
        Ok(_) => bail!("secret '{name}' already exists"),
        Err(err) if is_not_found(&err) => {},
        Err(err) => return Err(err.into()),
    }
    Ok(client.put(&Secret { name: name.to_string(), ..secret }).await?)
}
