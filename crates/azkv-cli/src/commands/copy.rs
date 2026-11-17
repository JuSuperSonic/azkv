use anyhow::{Result, bail};
use azkv_core::copy::{execute_copy, make_plan};
use azkv_core::profiles;
use tracing::info;

use super::Context;
use crate::logging::OUTPUT;
use crate::output::{render_plan, render_report};
use crate::session::{connect, vault_client};

pub struct Options {
    pub from: String,
    pub to: String,
    pub from_profile: Option<String>,
    pub to_profile: Option<String>,
    pub from_subscription: Option<String>,
    pub to_subscription: Option<String>,
    pub overwrite: bool,
    pub dry_run: bool,
    pub concurrency: usize,
}

pub async fn run(ctx: &Context, options: Options) -> Result<()> {
    let from_profile = match options.from_profile {
        Some(spec) => profiles::resolve(Some(&spec))?,
        None => ctx.profile.clone(),
    };
    let to_profile = match options.to_profile {
        Some(spec) => profiles::resolve(Some(&spec))?,
        None => from_profile.clone(),
    };

    let source = connect(&from_profile, &options.from, options.from_subscription.as_deref(), &ctx.proxy).await?;
    let dest = connect(&to_profile, &options.to, options.to_subscription.as_deref(), &ctx.proxy).await?;
    let source_client = vault_client(&source, &ctx.proxy)?;
    let dest_client = vault_client(&dest, &ctx.proxy)?;
    let plan = make_plan(&source_client, &dest_client, options.overwrite).await?;
    for line in render_plan(&source.vault, &dest.vault, &plan) {
        info!(target: OUTPUT, "{line}");
    }
    if options.dry_run {
        info!(target: OUTPUT, "dry run: nothing written");
        return Ok(());
    }
    let report = execute_copy(&source_client, &dest_client, &plan, options.concurrency).await;
    for line in render_report(&report) {
        info!(target: OUTPUT, "{line}");
    }
    if !report.succeeded() {
        bail!("{} secret(s) failed to copy", report.failed.len());
    }
    Ok(())
}
