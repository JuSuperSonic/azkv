mod azure;
mod copy;
mod secrets;

use anyhow::Result;
use azkv_core::{Profile, ProxySettings};

use crate::cli::Command;

pub struct Context {
    pub profile: Profile,
    pub proxy: Option<ProxySettings>,
}

pub async fn run(command: Command, ctx: &Context) -> Result<()> {
    match command {
        Command::Profiles => azure::profiles().await,
        Command::Tenants => azure::tenants(ctx).await,
        Command::Subscriptions { tenant } => azure::subscriptions(ctx, tenant).await,
        Command::Vaults { subscription, tenant, all } => azure::vaults(ctx, subscription, tenant, all).await,
        Command::Secrets { vault, subscription } => secrets::list(ctx, &vault, subscription.as_deref()).await,
        Command::Get { vault, name, version, subscription } => {
            secrets::get(ctx, &vault, &name, version.as_deref(), subscription.as_deref()).await
        },
        Command::Set { vault, name, subscription } => secrets::set(ctx, &vault, &name, subscription.as_deref()).await,
        Command::Delete { vault, name, subscription } => {
            secrets::delete(ctx, &vault, &name, subscription.as_deref()).await
        },
        Command::Copy {
            from,
            to,
            from_profile,
            to_profile,
            from_subscription,
            to_subscription,
            overwrite,
            dry_run,
            concurrency,
        } => {
            let options = copy::Options {
                from,
                to,
                from_profile,
                to_profile,
                from_subscription,
                to_subscription,
                overwrite,
                dry_run,
                concurrency,
            };
            copy::run(ctx, options).await
        },
    }
}
