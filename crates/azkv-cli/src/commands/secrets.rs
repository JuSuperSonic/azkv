use std::io::{IsTerminal, Read};

use anyhow::{Context as _, Result};
use azkv_core::{Secret, SecretStore};
use tracing::{error, info};

use super::Context;
use crate::logging::OUTPUT;
use crate::session::client;

pub async fn list(ctx: &Context, vault: &str, subscription: Option<&str>) -> Result<()> {
    let client = client(&ctx.profile, vault, subscription, &ctx.proxy).await?;
    for name in client.names().await? {
        info!(target: OUTPUT, "{name}");
    }
    Ok(())
}

pub async fn get(
    ctx: &Context,
    vault: &str,
    name: &str,
    version: Option<&str>,
    subscription: Option<&str>,
) -> Result<()> {
    let client = client(&ctx.profile, vault, subscription, &ctx.proxy).await?;
    let secret = client.get_version(name, version).await?;
    info!(target: OUTPUT, "{}", secret.value);
    Ok(())
}

pub async fn set(ctx: &Context, vault: &str, name: &str, subscription: Option<&str>) -> Result<()> {
    let mut value = String::new();
    if std::io::stdin().is_terminal() {
        error!("reading secret value from stdin (end with Ctrl-D)");
    }
    std::io::stdin().read_to_string(&mut value).context("cannot read the secret value from stdin")?;
    let secret = Secret {
        name: name.to_string(),
        value,
        content_type: None,
        tags: Default::default(),
        enabled: true,
        expires: None,
        not_before: None,
    };
    client(&ctx.profile, vault, subscription, &ctx.proxy).await?.put(&secret).await?;
    info!(target: OUTPUT, "secret '{name}' set");
    Ok(())
}

pub async fn delete(ctx: &Context, vault: &str, name: &str, subscription: Option<&str>) -> Result<()> {
    client(&ctx.profile, vault, subscription, &ctx.proxy).await?.delete(name).await?;
    info!(target: OUTPUT, "secret '{name}' deletion initiated");
    Ok(())
}
