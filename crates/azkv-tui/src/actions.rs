use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::app::{Action, Msg, matches};
use crate::error::short;
use anyhow::{Result, bail};
use azkv_core::arm::Arm;
use azkv_core::copy::{CopyPlan, DEFAULT_CONCURRENCY, execute_copy, plan};
use azkv_core::credential::AzAuth;
use azkv_core::vault::KvVault;
use azkv_core::{
    Profile, ProxySettings, Secret, SecretMeta, SecretStore, Subscription, Vault, clipboard, is_not_found,
};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{info, warn};

pub type AuthCache = HashMap<PathBuf, Arc<AzAuth>>;

fn auth_for(profile: &Profile, cache: &mut AuthCache) -> Arc<AzAuth> {
    cache.entry(profile.dir.clone()).or_insert_with(|| AzAuth::new(profile.dir.clone())).clone()
}

/// What every background task needs besides the action payload.
struct Run<'a> {
    tx: &'a UnboundedSender<Msg>,
    auths: &'a mut AuthCache,
    proxy: Option<ProxySettings>,
}

impl Run<'_> {
    /// Cached Azure CLI auth for a profile.
    fn auth(&mut self, profile: &Profile) -> Arc<AzAuth> {
        auth_for(profile, self.auths)
    }

    /// Sender and proxy owned by a spawned task; resolve the auth first.
    fn into_task(self) -> (UnboundedSender<Msg>, Option<ProxySettings>) {
        (self.tx.clone(), self.proxy)
    }
}

pub fn execute(
    action: Action,
    tx: &UnboundedSender<Msg>,
    auths: &mut AuthCache,
    proxy: Option<&ProxySettings>,
) -> bool {
    let run = Run { tx, auths, proxy: proxy.cloned() };
    match action {
        Action::Quit => return true,
        Action::Copy(text) => copy_text(&text, tx),
        Action::LoadOverview { profile } => load_overview(profile, run),
        Action::LoadVaults { profile, subscription } => load_vaults(profile, subscription, run),
        Action::LoadSecrets { profile, vault, .. } => load_secrets(profile, vault, run),
        Action::FetchValue { profile, vault, name, .. } => fetch_value(profile, vault, name, run),
        Action::RefreshSecret { profile, vault, name, .. } => refresh_secret(profile, vault, name, run),
        Action::SaveSecret { profile, vault, secret, updated, patch } => {
            save(profile, vault, secret, updated, patch, run);
        },
        Action::LoadVaultInfo { profile, vault } => load_vault_info(profile, vault, run),
        Action::LoadCopyVaults { profile, subscription } => load_copy_vaults(profile, subscription, run),
        Action::CheckProxy { proxy } => check_proxy(proxy, tx),
        Action::DuplicateSecret { profile, vault, source, name } => duplicate(profile, vault, source, name, run),
        Action::DeleteSecret { profile, vault, name } => delete(profile, vault, name, run),
        Action::PlanCopyVault { profile, source, dest, filter } => plan_copy(profile, source, dest, filter, run),
        Action::CopyVault { profile, source, dest, plan } => copy_vault(profile, source, dest, plan, run),
    }
    false
}

fn copy_text(text: &str, tx: &UnboundedSender<Msg>) {
    let result = clipboard::copy(text).map_err(|err| err.to_string());
    let _ = tx.send(Msg::Copied(result));
}

fn load_overview(profile: Profile, mut run: Run) {
    let auth = run.auth(&profile);
    let (tx, proxy) = run.into_task();
    tokio::spawn(async move {
        let result = async {
            let overview = Arm::new(auth, proxy.as_ref())?.overview().await?;
            for warning in &overview.warnings {
                warn!("{warning}");
            }
            Ok::<_, anyhow::Error>(overview)
        }
        .await
        .map_err(short);
        let _ = tx.send(Msg::Overview { dir: profile.dir, result });
    });
}

fn load_vaults(profile: Profile, subscription: Subscription, mut run: Run) {
    let auth = run.auth(&profile);
    let (tx, proxy) = run.into_task();
    tokio::spawn(async move {
        let result = async {
            let arm = Arm::new(auth, proxy.as_ref())?;
            arm.vaults(&subscription).await
        }
        .await
        .map_err(short);
        let _ = tx.send(Msg::Vaults { dir: profile.dir, subscription_id: subscription.id, result });
    });
}

fn load_secrets(profile: Profile, vault: Vault, mut run: Run) {
    let auth = run.auth(&profile);
    let (tx, proxy) = run.into_task();
    tokio::spawn(async move {
        let result = async {
            let client = KvVault::for_vault(&vault, &auth, proxy.as_ref())?;
            client.meta().await
        }
        .await
        .map_err(short);
        let _ = tx.send(Msg::Secrets { url: vault.url, result });
    });
}

fn fetch_value(profile: Profile, vault: Vault, name: String, mut run: Run) {
    let auth = run.auth(&profile);
    let (tx, proxy) = run.into_task();
    tokio::spawn(async move {
        let result = async {
            let client = KvVault::for_vault(&vault, &auth, proxy.as_ref())?;
            Ok::<_, anyhow::Error>(client.get(&name).await?.value)
        }
        .await
        .map_err(short);
        let _ = tx.send(Msg::Value { url: vault.url, name, result });
    });
}

fn refresh_secret(profile: Profile, vault: Vault, name: String, mut run: Run) {
    let auth = run.auth(&profile);
    let (tx, proxy) = run.into_task();
    tokio::spawn(async move {
        let result = async {
            let client = KvVault::for_vault(&vault, &auth, proxy.as_ref())?;
            client.refresh(&name).await
        }
        .await
        .map_err(short);
        let _ = tx.send(Msg::Refreshed { url: vault.url, name, result });
    });
}

fn save(profile: Profile, vault: Vault, secret: Secret, updated: Option<Option<i128>>, patch: bool, mut run: Run) {
    let auth = run.auth(&profile);
    let (tx, proxy) = run.into_task();
    tokio::spawn(async move {
        let result = async {
            let client = KvVault::for_vault(&vault, &auth, proxy.as_ref())?;
            save_secret(&client, &secret, updated, patch).await
        }
        .await
        .map_err(short);
        let value = (!patch).then(|| secret.value.clone());
        let _ = tx.send(Msg::Saved { url: vault.url, name: secret.name, value, result });
    });
}

fn load_vault_info(profile: Profile, vault: Vault, mut run: Run) {
    let auth = run.auth(&profile);
    let (tx, proxy) = run.into_task();
    tokio::spawn(async move {
        let result = async {
            let arm = Arm::new(auth, proxy.as_ref())?;
            arm.vault_info(&vault).await
        }
        .await
        .map_err(short);
        let _ = tx.send(Msg::VaultInfo { url: vault.url, result });
    });
}

fn load_copy_vaults(profile: Profile, subscription: Subscription, mut run: Run) {
    let auth = run.auth(&profile);
    let (tx, proxy) = run.into_task();
    tokio::spawn(async move {
        let result = async {
            let arm = Arm::new(auth, proxy.as_ref())?;
            arm.vaults(&subscription).await
        }
        .await
        .map_err(short);
        let _ = tx.send(Msg::CopyVaults { subscription_id: subscription.id, result });
    });
}

fn check_proxy(proxy: ProxySettings, tx: &UnboundedSender<Msg>) {
    let tx = tx.clone();
    tokio::spawn(async move {
        let result = proxy.check().await.map_err(short);
        let _ = tx.send(Msg::ProxyChecked { proxy, result });
    });
}

fn duplicate(profile: Profile, vault: Vault, source: String, name: String, mut run: Run) {
    let auth = run.auth(&profile);
    let (tx, proxy) = run.into_task();
    tokio::spawn(async move {
        let result = async {
            let client = KvVault::for_vault(&vault, &auth, proxy.as_ref())?;
            duplicate_secret(&client, &source, &name).await
        }
        .await
        .map_err(short);
        let _ = tx.send(Msg::Duplicated { url: vault.url, name, result });
    });
}

fn delete(profile: Profile, vault: Vault, name: String, mut run: Run) {
    let auth = run.auth(&profile);
    let (tx, proxy) = run.into_task();
    tokio::spawn(async move {
        let result = async {
            let client = KvVault::for_vault(&vault, &auth, proxy.as_ref())?;
            client.delete(&name).await
        }
        .await
        .map_err(short);
        let _ = tx.send(Msg::Deleted { url: vault.url, name, result });
    });
}

fn plan_copy(profile: Profile, source: Vault, dest: Vault, filter: String, mut run: Run) {
    let auth = run.auth(&profile);
    let (tx, proxy) = run.into_task();
    tokio::spawn(async move {
        let result = async {
            let source_client = KvVault::for_vault(&source, &auth, proxy.as_ref())?;
            let dest_client = KvVault::for_vault(&dest, &auth, proxy.as_ref())?;
            let names =
                source_client.names().await?.into_iter().filter(|name| matches(name, &filter)).collect::<Vec<_>>();
            let existing = dest_client.names().await?.into_iter().collect();
            Ok::<_, anyhow::Error>(plan(&names, &existing, false))
        }
        .await
        .map_err(short);
        let _ = tx.send(Msg::CopyPlan { source, dest, result });
    });
}

fn copy_vault(profile: Profile, source: Vault, dest: Vault, plan: CopyPlan, mut run: Run) {
    let auth = run.auth(&profile);
    let (tx, proxy) = run.into_task();
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
