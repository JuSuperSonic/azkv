use std::io::{IsTerminal, Read};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use azkv_core::arm::Arm;
use azkv_core::copy::{CopyPlan, CopyReport, execute_copy, make_plan};
use azkv_core::credential::AzAuth;
use azkv_core::profiles;
use azkv_core::vault::KvVault;
use azkv_core::{Overview, Profile, ProxySettings, Secret, SecretStore, Subscription, Tenant, Vault};
use clap::{Parser, Subcommand};
use futures::StreamExt;
use futures::stream;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::{EnvFilter, filter_fn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(name = "azkvctl", about = "Azure Key Vault CLI: browse and copy secrets")]
struct Cli {
    /// Azure CLI profile: name under ~/.azure, or a config dir path
    #[arg(long, global = true, env = "AZKV_PROFILE")]
    profile: Option<String>,

    /// HTTP(S)/SOCKS proxy for Key Vault and Azure management calls (default: proxy env)
    #[arg(long, global = true, env = "AZKV_PROXY")]
    proxy: Option<String>,

    /// Hosts that bypass --proxy (default: NO_PROXY env)
    #[arg(long, global = true, env = "AZKV_NO_PROXY")]
    no_proxy: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List Azure CLI config profiles
    Profiles,
    /// List tenants visible to the profile
    Tenants,
    /// List subscriptions (all tenants)
    Subscriptions {
        /// Filter by tenant id or display name
        #[arg(long)]
        tenant: Option<String>,
    },
    /// List key vaults
    Vaults {
        /// Subscription id or name (default: the profile's default subscription)
        #[arg(long)]
        subscription: Option<String>,
        /// Filter by tenant id or display name
        #[arg(long)]
        tenant: Option<String>,
        /// Scan every subscription and print vault URLs
        #[arg(long)]
        all: bool,
    },
    /// List secret names in a vault
    Secrets {
        /// Vault name or URL
        vault: String,
        #[arg(long)]
        subscription: Option<String>,
    },
    /// Print one secret value
    Get {
        /// Vault name or URL
        vault: String,
        /// Secret name
        name: String,
        /// Specific version (default: latest)
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        subscription: Option<String>,
    },
    /// Create or update a secret (value read from stdin)
    Set {
        /// Vault name or URL
        vault: String,
        /// Secret name
        name: String,
        #[arg(long)]
        subscription: Option<String>,
    },
    /// Delete a secret (soft delete)
    Delete {
        /// Vault name or URL
        vault: String,
        /// Secret name
        name: String,
        #[arg(long)]
        subscription: Option<String>,
    },
    /// Copy every secret from one vault to another
    Copy {
        /// Source vault name or URL
        #[arg(long = "from")]
        from: String,
        /// Destination vault name or URL
        #[arg(long = "to")]
        to: String,
        /// Azure CLI profile for the source (default: --profile)
        #[arg(long)]
        from_profile: Option<String>,
        /// Azure CLI profile for the destination (default: source profile)
        #[arg(long)]
        to_profile: Option<String>,
        /// Subscription hint for the source vault
        #[arg(long)]
        from_subscription: Option<String>,
        /// Subscription hint for the destination vault
        #[arg(long)]
        to_subscription: Option<String>,
        /// Update secrets that already exist in the destination
        #[arg(long)]
        overwrite: bool,
        /// Show the plan without writing anything
        #[arg(long)]
        dry_run: bool,
        /// Parallel reads/writes
        #[arg(long, default_value_t = azkv_core::copy::DEFAULT_CONCURRENCY)]
        concurrency: usize,
    },
}

struct Connected {
    auth: Arc<AzAuth>,
    vault: Vault,
}

fn arm_for(profile: &Profile, proxy: &Option<ProxySettings>) -> Result<Arm> {
    Ok(Arm::new(AzAuth::new(profile.dir.clone()), proxy.as_ref())?)
}

fn warn_overview(overview: &Overview) {
    for warning in &overview.warnings {
        tracing::warn!("{warning}");
    }
}

async fn connect(
    profile: &Profile,
    spec: &str,
    preferred: Option<&str>,
    proxy: &Option<ProxySettings>,
) -> Result<Connected> {
    let auth = AzAuth::new(profile.dir.clone());
    let arm = Arm::new(Arc::clone(&auth), proxy.as_ref())?;
    let overview = arm.overview().await?;
    warn_overview(&overview);
    let vault = arm.find_vault(spec, &overview.subscriptions, preferred).await?;
    Ok(Connected { auth, vault })
}

fn vault_client(connected: &Connected, proxy: &Option<ProxySettings>) -> Result<KvVault> {
    Ok(KvVault::for_vault(&connected.vault, &connected.auth, proxy.as_ref())?)
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let cli = Cli::parse();
    let profile = profiles::resolve(cli.profile.as_deref())?;
    let proxy = ProxySettings::new(cli.proxy.as_deref(), cli.no_proxy.as_deref())?;

    match cli.command {
        Command::Profiles => {
            let active = profiles::active().ok();
            for profile in profiles::discover()? {
                let marker = if active.as_ref().is_some_and(|a| a.dir == profile.dir) { "*" } else { " " };
                tracing::info!(target: OUTPUT, "{marker} {:<12} {}", profile.name, profile.dir.display());
            }
        },
        Command::Tenants => {
            let overview = arm_for(&profile, &proxy)?.overview().await?;
            warn_overview(&overview);
            for tenant in &overview.tenants {
                let count = overview.subscriptions.iter().filter(|sub| sub.tenant_id == tenant.id).count();
                tracing::info!(target: OUTPUT, "{}\t{}\t{} subscriptions", tenant.name, tenant.id, count);
            }
        },
        Command::Subscriptions { tenant } => {
            let overview = arm_for(&profile, &proxy)?.overview().await?;
            warn_overview(&overview);
            let subs = match tenant {
                Some(needle) => filter_by_tenant(&overview.subscriptions, &overview.tenants, &needle),
                None => overview.subscriptions,
            };
            for sub in &subs {
                let marker = if sub.is_default { "*" } else { " " };
                tracing::info!(target: OUTPUT, "{marker} {}\t{}\t{}\t{}", sub.name, sub.id, sub.tenant_id, sub.state);
            }
        },
        Command::Vaults { subscription, tenant, all } => {
            let arm = arm_for(&profile, &proxy)?;
            let overview = arm.overview().await?;
            warn_overview(&overview);
            let mut subs = match tenant {
                Some(needle) => filter_by_tenant(&overview.subscriptions, &overview.tenants, &needle),
                None => overview.subscriptions.clone(),
            };
            if all {
                list_all_vaults(&arm, &subs).await;
            } else {
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
                    tracing::info!(target: OUTPUT, "{}", vault.url);
                }
            }
        },
        Command::Secrets { vault, subscription } => {
            let connected = connect(&profile, &vault, subscription.as_deref(), &proxy).await?;
            let client = vault_client(&connected, &proxy)?;
            for name in client.names().await? {
                tracing::info!(target: OUTPUT, "{name}");
            }
        },
        Command::Get { vault, name, version, subscription } => {
            let connected = connect(&profile, &vault, subscription.as_deref(), &proxy).await?;
            let client = vault_client(&connected, &proxy)?;
            let secret = client.get_version(&name, version.as_deref()).await?;
            tracing::info!(target: OUTPUT, "{}", secret.value);
        },
        Command::Set { vault, name, subscription } => {
            let mut value = String::new();
            if std::io::stdin().is_terminal() {
                eprintln!("reading secret value from stdin (end with Ctrl-D)");
            }
            std::io::stdin().read_to_string(&mut value).context("cannot read the secret value from stdin")?;
            let connected = connect(&profile, &vault, subscription.as_deref(), &proxy).await?;
            let secret = Secret {
                name: name.clone(),
                value,
                content_type: None,
                tags: Default::default(),
                enabled: true,
                expires: None,
                not_before: None,
            };
            vault_client(&connected, &proxy)?.put(&secret).await?;
            tracing::info!(target: OUTPUT, "secret '{name}' set");
        },
        Command::Delete { vault, name, subscription } => {
            let connected = connect(&profile, &vault, subscription.as_deref(), &proxy).await?;
            vault_client(&connected, &proxy)?.delete(&name).await?;
            tracing::info!(target: OUTPUT, "secret '{name}' deletion initiated");
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
            let from_profile = match from_profile {
                Some(spec) => profiles::resolve(Some(&spec))?,
                None => profile.clone(),
            };
            let to_profile = match to_profile {
                Some(spec) => profiles::resolve(Some(&spec))?,
                None => from_profile.clone(),
            };

            let source = connect(&from_profile, &from, from_subscription.as_deref(), &proxy).await?;
            let dest = connect(&to_profile, &to, to_subscription.as_deref(), &proxy).await?;
            let source_client = vault_client(&source, &proxy)?;
            let dest_client = vault_client(&dest, &proxy)?;
            let plan = make_plan(&source_client, &dest_client, overwrite).await?;
            for line in render_plan(&source.vault, &dest.vault, &plan) {
                tracing::info!(target: OUTPUT, "{line}");
            }
            if dry_run {
                tracing::info!(target: OUTPUT, "dry run: nothing written");
                return Ok(());
            }
            let report = execute_copy(&source_client, &dest_client, &plan, concurrency).await;
            for line in render_report(&report) {
                tracing::info!(target: OUTPUT, "{line}");
            }
            if !report.succeeded() {
                bail!("{} secret(s) failed to copy", report.failed.len());
            }
        },
    }
    Ok(())
}

/// Events with this target are command output: bare lines on stdout.
const OUTPUT: &str = "azkv::output";

fn init_logging() {
    // Output keeps stdout pipe-friendly (no timestamp/level); diagnostics go to stderr.
    let output = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_ansi(false)
        .without_time()
        .with_level(false)
        .with_target(false)
        .with_filter(filter_fn(|meta| meta.target() == OUTPUT));
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into());
    let diagnostics = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(EnvFilter::builder().parse_lossy(filter));
    let _ = tracing_subscriber::registry().with(output).with(diagnostics).try_init();
}

async fn list_all_vaults(arm: &Arm, subs: &[Subscription]) {
    let mut stream =
        stream::iter(subs.iter()).map(|sub| async move { (sub, arm.vaults(sub).await) }).buffer_unordered(8);
    while let Some((sub, result)) = stream.next().await {
        match result {
            Ok(vaults) => {
                for vault in vaults {
                    tracing::info!(target: OUTPUT, "{}\t{}", vault.url, sub.name);
                }
            },
            Err(err) => tracing::warn!(subscription = %sub.name, "cannot list vaults: {err:#}"),
        }
    }
}

fn matches_subscription(sub: &Subscription, needle: &str) -> bool {
    sub.id == needle || sub.name.eq_ignore_ascii_case(needle)
}

fn filter_by_tenant(subscriptions: &[Subscription], tenants: &[Tenant], needle: &str) -> Vec<Subscription> {
    let ids: Vec<&str> = tenants
        .iter()
        .filter(|tenant| tenant.id == needle || tenant.name.eq_ignore_ascii_case(needle))
        .map(|tenant| tenant.id.as_str())
        .collect();
    subscriptions.iter().filter(|sub| ids.contains(&sub.tenant_id.as_str())).cloned().collect()
}

fn render_plan(source: &Vault, dest: &Vault, plan: &CopyPlan) -> Vec<String> {
    let mut lines = vec![
        format!("source:      {} ({})", source.url, source.subscription_name),
        format!("destination: {} ({})", dest.url, dest.subscription_name),
        format!(
            "plan: {} to create, {} to overwrite, {} already exist",
            plan.create.len(),
            plan.overwrite.len(),
            plan.conflicts()
        ),
    ];
    for name in &plan.skip {
        lines.push(format!("  WARN  {name} already exists in destination (skipped, use --overwrite)"));
    }
    lines
}

fn render_report(report: &CopyReport) -> Vec<String> {
    let mut lines = Vec::new();
    for name in &report.created {
        lines.push(format!("  OK      {name}"));
    }
    for name in &report.overwritten {
        lines.push(format!("  UPDATE  {name}"));
    }
    for name in &report.skipped {
        lines.push(format!("  SKIP    {name} (already exists)"));
    }
    for (name, error) in &report.failed {
        lines.push(format!("  FAIL    {name}: {error}"));
    }
    lines.push(format!(
        "summary: {} created, {} overwritten, {} skipped (already exist), {} failed",
        report.created.len(),
        report.overwritten.len(),
        report.skipped.len(),
        report.failed.len()
    ));
    lines
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use azkv_core::copy::{CopyReport, plan};

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

    fn vault(name: &str) -> Vault {
        Vault {
            name: name.into(),
            url: azkv_core::model::url_for(name),
            subscription_id: "s1".into(),
            subscription_name: "sub-one".into(),
            tenant_id: "t1".into(),
            resource_group: None,
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn proxy_flags_parse_and_apply_globally() {
        let cli = Cli::try_parse_from([
            "azkvctl",
            "--proxy",
            "http://127.0.0.1:8080",
            "--no-proxy",
            "localhost,127.0.0.1",
            "profiles",
        ])
        .unwrap();
        assert_eq!(cli.proxy.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(cli.no_proxy.as_deref(), Some("localhost,127.0.0.1"));

        // Flags also work after the subcommand because they are global.
        let cli = Cli::try_parse_from(["azkvctl", "vaults", "--proxy", "http://proxy:3128"]).unwrap();
        assert_eq!(cli.proxy.as_deref(), Some("http://proxy:3128"));
    }

    #[test]
    fn copy_arguments_are_parsed_with_profiles_and_flags() {
        let cli = Cli::try_parse_from([
            "azkvctl",
            "--profile",
            "test",
            "copy",
            "--from",
            "kv-a",
            "--to",
            "https://kv-b.vault.azure.net/",
            "--from-profile",
            "test",
            "--to-profile",
            "coucou",
            "--overwrite",
            "--dry-run",
            "--concurrency",
            "3",
        ])
        .unwrap();
        assert_eq!(cli.profile.as_deref(), Some("test"));
        match cli.command {
            Command::Copy { from, to, from_profile, to_profile, overwrite, dry_run, concurrency, .. } => {
                assert_eq!(from, "kv-a");
                assert_eq!(to, "https://kv-b.vault.azure.net/");
                assert_eq!(from_profile.as_deref(), Some("test"));
                assert_eq!(to_profile.as_deref(), Some("coucou"));
                assert!(overwrite);
                assert!(dry_run);
                assert_eq!(concurrency, 3);
            },
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn copy_defaults_are_safe() {
        let cli = Cli::try_parse_from(["azkvctl", "copy", "--from", "a", "--to", "b"]).unwrap();
        match cli.command {
            Command::Copy { overwrite, dry_run, concurrency, .. } => {
                assert!(!overwrite);
                assert!(!dry_run);
                assert_eq!(concurrency, azkv_core::copy::DEFAULT_CONCURRENCY);
            },
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn vaults_all_flag_and_tenant_filter_parse() {
        let cli = Cli::try_parse_from(["azkvctl", "vaults", "--all", "--tenant", "test"]).unwrap();
        match cli.command {
            Command::Vaults { all, tenant, .. } => {
                assert!(all);
                assert_eq!(tenant.as_deref(), Some("test"));
            },
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn get_version_set_and_delete_parse() {
        let cli =
            Cli::try_parse_from(["azkvctl", "get", "kv-a", "db", "--version", "v1", "--subscription", "s1"]).unwrap();
        match cli.command {
            Command::Get { name, version, subscription, .. } => {
                assert_eq!(name, "db");
                assert_eq!(version.as_deref(), Some("v1"));
                assert_eq!(subscription.as_deref(), Some("s1"));
            },
            _ => panic!("wrong command"),
        }

        let cli = Cli::try_parse_from(["azkvctl", "set", "kv-a", "db"]).unwrap();
        assert!(matches!(cli.command, Command::Set { ref name, .. } if name == "db"));
        assert!(Cli::try_parse_from(["azkvctl", "set", "kv-a", "db", "hunter2"]).is_err());

        let cli = Cli::try_parse_from(["azkvctl", "delete", "kv-a", "db"]).unwrap();
        assert!(matches!(cli.command, Command::Delete { ref name, .. } if name == "db"));
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

    #[test]
    fn plan_alerts_on_existing_secrets() {
        let existing = BTreeSet::from(["old".to_string()]);
        let plan = plan(&strings(&["new", "old"]), &existing, false);
        let lines = render_plan(&vault("kv-a"), &vault("kv-b"), &plan);
        assert!(lines[0].contains("kv-a.vault.azure.net"));
        assert!(lines[1].contains("kv-b.vault.azure.net"));
        assert!(lines[2].contains("1 to create, 0 to overwrite, 1 already exist"));
        assert!(lines[3].contains("WARN  old already exists"));
    }

    #[test]
    fn report_lines_cover_every_outcome() {
        let report = CopyReport {
            created: strings(&["a"]),
            overwritten: strings(&["b"]),
            skipped: strings(&["c"]),
            failed: vec![("d".into(), "denied".into())],
        };
        let lines = render_report(&report);
        assert!(lines[0].contains("OK      a"));
        assert!(lines[1].contains("UPDATE  b"));
        assert!(lines[2].contains("SKIP    c (already exists)"));
        assert!(lines[3].contains("FAIL    d: denied"));
        assert_eq!(lines[4], "summary: 1 created, 1 overwritten, 1 skipped (already exist), 1 failed");
    }

    #[test]
    fn successful_report_has_no_failures() {
        let report = CopyReport { created: strings(&["a"]), ..Default::default() };
        assert!(report.succeeded());
        assert!(render_report(&report)[1].starts_with("summary: 1 created"));
    }
}
