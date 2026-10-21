use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, bail};
use azkv_core::arm::Arm;
use azkv_core::copy::{DEFAULT_CONCURRENCY, execute_copy, make_plan};
use azkv_core::credential::AzAuth;
use azkv_core::vault::KvVault;
use azkv_core::{Profile, ProxySettings, Secret, SecretMeta, SecretStore, clipboard, is_not_found};
use tokio::sync::mpsc::UnboundedSender;

use crate::app::{Action, Msg};
use crate::error::short;

pub type AuthCache = HashMap<PathBuf, Arc<AzAuth>>;

fn auth_for(profile: &Profile, cache: &mut AuthCache) -> Arc<AzAuth> {
    cache.entry(profile.dir.clone()).or_insert_with(|| AzAuth::new(profile.dir.clone())).clone()
}

/// Runs one UI action: quits, copies text or spawns the matching Azure call.
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
                                tracing::warn!("{warning}");
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
        Action::SaveSecret { profile, vault, secret, updated } => {
            let auth = auth_for(&profile, auths);
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = match KvVault::for_vault(&vault, &auth, proxy.as_ref()) {
                    Ok(client) => save_secret(&client, &secret, updated).await.map_err(short),
                    Err(err) => Err(short(err)),
                };
                let _ = tx.send(Msg::Saved { url: vault.url, name: secret.name, value: secret.value, result });
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
        Action::CopyToVault { profile, dest, secret, overwrite } => {
            let auth = auth_for(&profile, auths);
            let tx = tx.clone();
            tokio::spawn(async move {
                let dest_name = dest.name.clone();
                let name = secret.name.clone();
                let result = check_and_copy(&dest, &auth, proxy.as_ref(), secret, overwrite).await;
                match result {
                    Ok(Some(secret)) => {
                        let _ = tx.send(Msg::CopyToExists { dest, secret });
                    },
                    Ok(None) => {
                        let _ = tx.send(Msg::CopiedTo { dest: dest_name, name, result: Ok(()) });
                    },
                    Err(err) => {
                        let _ = tx.send(Msg::CopiedTo { dest: dest_name, name, result: Err(short(err)) });
                    },
                }
            });
        },
        Action::CopyVault { profile, source, dest } => {
            let auth = auth_for(&profile, auths);
            let tx = tx.clone();
            tokio::spawn(async move {
                let source_name = source.name.clone();
                let dest_name = dest.name.clone();
                let result = async {
                    let source_client = KvVault::for_vault(&source, &auth, proxy.as_ref())?;
                    let dest_client = KvVault::for_vault(&dest, &auth, proxy.as_ref())?;
                    let plan = make_plan(&source_client, &dest_client, false).await?;
                    Ok::<_, anyhow::Error>(execute_copy(&source_client, &dest_client, &plan, DEFAULT_CONCURRENCY).await)
                }
                .await
                .map_err(short);
                let _ = tx.send(Msg::CopiedVault { source: source_name, dest: dest_name, result });
            });
        },
    }
    false
}

/// Returns the secret when the destination already has it and overwrite is off.
async fn check_and_copy(
    dest: &azkv_core::Vault,
    auth: &Arc<AzAuth>,
    proxy: Option<&ProxySettings>,
    secret: Secret,
    overwrite: bool,
) -> Result<Option<Secret>> {
    let client = KvVault::for_vault(dest, auth, proxy)?;
    if !overwrite {
        match client.get(&secret.name).await {
            Ok(_) => return Ok(Some(secret)),
            Err(err) if is_not_found(&err) => {},
            Err(err) => return Err(err.into()),
        }
    }
    client.put(&secret).await?;
    Ok(None)
}

/// Writes a secret after checking that a create is new or an edit is still current.
async fn save_secret(client: &KvVault, secret: &Secret, updated: Option<Option<i128>>) -> Result<SecretMeta> {
    match updated {
        None => match client.get(&secret.name).await {
            Ok(_) => bail!("secret '{}' already exists", secret.name),
            Err(err) if is_not_found(&err) => {},
            Err(err) => return Err(err.into()),
        },
        Some(expected) => {
            let (meta, _) = client.refresh(&secret.name).await?;
            if meta.updated.map(|updated| updated.unix_timestamp_nanos()) != expected {
                bail!("secret '{}' changed since it was opened; close and reopen the editor", secret.name);
            }
        },
    }
    Ok(client.put(secret).await?)
}

/// Copies a secret's value/metadata under a new name, refusing to overwrite.
async fn duplicate_secret(client: &KvVault, source: &str, name: &str) -> Result<SecretMeta> {
    let secret = client.get(source).await?;
    match client.get(name).await {
        Ok(_) => bail!("secret '{name}' already exists"),
        Err(err) if is_not_found(&err) => {},
        Err(err) => return Err(err.into()),
    }
    Ok(client.put(&Secret { name: name.to_string(), ..secret }).await?)
}
