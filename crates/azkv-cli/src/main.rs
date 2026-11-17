mod cli;
mod commands;
mod logging;
mod output;
mod session;
use anyhow::Result;
use azkv_core::ProxySettings;
use azkv_core::profiles;
use clap::Parser;

use commands::Context;

#[tokio::main]
async fn main() -> Result<()> {
    logging::init();
    let cli = cli::Cli::parse();
    let profile = profiles::resolve(cli.profile.as_deref())?;
    let proxy = ProxySettings::new(cli.proxy.as_deref(), cli.no_proxy.as_deref())?;
    commands::run(cli.command, &Context { profile, proxy }).await
}
