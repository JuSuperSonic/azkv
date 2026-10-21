//! Azure Key Vault plumbing shared by the `azkv` TUI and the `azkvctl` CLI.

pub mod arm;
pub mod clipboard;
pub mod copy;
pub mod credential;
mod error;
pub mod model;
pub mod profiles;
pub mod proxy;
mod token_cache;
pub mod vault;

pub use arm::{Arm, Overview};
pub use copy::{CopyPlan, CopyReport, execute_copy, make_plan, plan};
pub use credential::AzAuth;
pub use error::{Error, Remote, Result, is_not_found};
pub use model::{
    Profile, Secret, SecretMeta, SecretState, Subscription, Tenant, Vault, VaultInfo, fmt_date, fmt_timestamp,
    parse_expiry,
};
pub use proxy::ProxySettings;
pub use vault::{KvVault, SecretStore};
