use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "azkvctl", version, about = "Azure Key Vault CLI: browse and copy secrets")]
pub(crate) struct Cli {
    /// Azure CLI profile: name under ~/.azure, or a config dir path
    #[arg(long, global = true, env = "AZKV_PROFILE")]
    pub(crate) profile: Option<String>,

    /// HTTP(S)/SOCKS proxy for Key Vault and Azure management calls (default: proxy env)
    #[arg(long, global = true, env = "AZKV_PROXY")]
    pub(crate) proxy: Option<String>,

    /// Hosts that bypass --proxy (default: NO_PROXY env)
    #[arg(long, global = true, env = "AZKV_NO_PROXY")]
    pub(crate) no_proxy: Option<String>,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
