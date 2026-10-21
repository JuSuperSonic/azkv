use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;

use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime};

use crate::error::{Error, Result};

/// One Azure CLI config directory (`AZURE_CONFIG_DIR`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// `default` for `~/.azure`, otherwise the directory name.
    pub name: String,
    pub dir: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tenant {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub tenant_id: String,
    pub state: String,
    pub is_default: bool,
}

impl Subscription {
    pub fn enabled(&self) -> bool {
        self.state.eq_ignore_ascii_case("enabled")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vault {
    pub name: String,
    pub url: String,
    pub subscription_id: String,
    pub subscription_name: String,
    pub tenant_id: String,
    pub resource_group: Option<String>,
}

impl Vault {
    pub fn from_name(name: &str, subscription: &Subscription, resource_group: Option<String>) -> Self {
        Self {
            name: name.to_string(),
            url: url_for(name),
            subscription_id: subscription.id.clone(),
            subscription_name: subscription.name.clone(),
            tenant_id: subscription.tenant_id.clone(),
            resource_group,
        }
    }

    /// ARM resource id, used as the scope for role assignments.
    pub fn resource_id(&self, resource_group: &str) -> String {
        format!(
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.KeyVault/vaults/{}",
            self.subscription_id, resource_group, self.name
        )
    }

    /// Accepts a vault name or a full URL and returns the vault name.
    pub fn name_from_spec(spec: &str) -> String {
        spec.trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .split('.')
            .next()
            .unwrap_or(spec)
            .to_string()
    }
}

pub fn url_for(name: &str) -> String {
    format!("https://{name}.vault.azure.net/")
}

/// Management-plane facts shown in the TUI info window.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultInfo {
    pub resource_group: Option<String>,
    pub location: Option<String>,
    pub sku: Option<String>,
    /// `Enabled`, `Disabled` or unset.
    pub public_network_access: Option<String>,
    /// Firewall default action: `Allow` or `Deny`.
    pub firewall: Option<String>,
    pub bypass: Option<String>,
    pub ip_rules: Vec<String>,
    pub vnet_rules: usize,
    pub private_endpoints: usize,
    /// `None` when the vault does not use RBAC (access policies instead).
    pub rbac: Option<bool>,
    pub soft_delete_days: Option<i64>,
    pub purge_protection: Option<bool>,
    /// Signed-in user or service principal for the current profile.
    pub user: Option<String>,
    pub roles: Vec<String>,
    pub roles_error: Option<String>,
    /// Public egress address as seen by Azure (through the proxy when one is set).
    pub client_ip: Option<IpAddr>,
    /// Whether that address passes the vault firewall.
    pub client_allowed: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretState {
    On,
    Off,
    Expired,
    Pending,
}

impl SecretState {
    pub fn of(
        enabled: bool,
        not_before: Option<OffsetDateTime>,
        expires: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Self {
        if !enabled {
            Self::Off
        } else if expires.is_some_and(|expires| expires < now) {
            Self::Expired
        } else if not_before.is_some_and(|not_before| not_before > now) {
            Self::Pending
        } else {
            Self::On
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
            Self::Expired => "expired",
            Self::Pending => "pending",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretMeta {
    pub name: String,
    pub enabled: bool,
    pub expires: Option<OffsetDateTime>,
    pub not_before: Option<OffsetDateTime>,
    pub updated: Option<OffsetDateTime>,
    pub content_type: Option<String>,
    pub tags: BTreeMap<String, String>,
}

impl SecretMeta {
    pub fn state(&self, now: OffsetDateTime) -> SecretState {
        SecretState::of(self.enabled, self.not_before, self.expires, now)
    }

    pub fn current_state(&self) -> SecretState {
        self.state(OffsetDateTime::now_utc())
    }
}

/// A secret with its value, as copied between vaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secret {
    pub name: String,
    pub value: String,
    pub content_type: Option<String>,
    pub tags: BTreeMap<String, String>,
    pub enabled: bool,
    pub expires: Option<OffsetDateTime>,
    pub not_before: Option<OffsetDateTime>,
}

/// `YYYY-MM-DD HH:MM` in UTC, short enough for a table column.
pub fn fmt_timestamp(time: Option<OffsetDateTime>) -> Option<String> {
    let text = time?.format(&Rfc3339).ok()?;
    Some(text.chars().take(16).collect::<String>().replace('T', " "))
}

/// `YYYY-MM-DD` in UTC, for editable fields.
pub fn fmt_date(time: Option<OffsetDateTime>) -> String {
    time.map(|time| format!("{:04}-{:02}-{:02}", time.year(), u8::from(time.month()), time.day())).unwrap_or_default()
}

/// Empty means "no expiry"; otherwise `YYYY-MM-DD` (UTC midnight) or RFC 3339.
pub fn parse_expiry(text: &str) -> Result<Option<OffsetDateTime>> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    if let Ok(datetime) = OffsetDateTime::parse(text, &Rfc3339) {
        return Ok(Some(datetime));
    }
    let invalid = || Error::Input("expected YYYY-MM-DD or an RFC 3339 timestamp".into());
    let mut parts = text.split('-');
    let (Some(year), Some(month), Some(day), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(invalid());
    };
    let year: i32 = year.parse().map_err(|_| invalid())?;
    let month: u8 = month.parse().map_err(|_| invalid())?;
    let day: u8 = day.parse().map_err(|_| invalid())?;
    let month = Month::try_from(month).map_err(|_| invalid())?;
    let date = Date::from_calendar_date(year, month, day).map_err(|_| invalid())?;
    Ok(Some(date.midnight().assume_utc()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_name_from_url_or_name() {
        assert_eq!(Vault::name_from_spec("https://kv-test-users.vault.azure.net/"), "kv-test-users");
        assert_eq!(Vault::name_from_spec("kv-test-users"), "kv-test-users");
        assert_eq!(Vault::name_from_spec("http://kv-x.vault.azure.net"), "kv-x");
    }

    #[test]
    fn resource_ids_are_built_for_role_scope() {
        let sub = Subscription {
            id: "s1".into(),
            name: "prod".into(),
            tenant_id: "t1".into(),
            state: "Enabled".into(),
            is_default: true,
        };
        let vault = Vault::from_name("kv-a", &sub, Some("rg".into()));
        assert_eq!(
            vault.resource_id("rg"),
            "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-a"
        );
    }

    #[test]
    fn url_for_builds_the_vault_host() {
        assert_eq!(url_for("kv-a"), "https://kv-a.vault.azure.net/");
    }

    #[test]
    fn secret_state_prefers_off_then_expired_then_pending() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let past = OffsetDateTime::from_unix_timestamp(1_600_000_000).unwrap();
        let future = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        assert_eq!(SecretState::of(true, None, None, now), SecretState::On);
        assert_eq!(SecretState::of(true, None, Some(future), now), SecretState::On);
        assert_eq!(SecretState::of(true, None, Some(past), now), SecretState::Expired);
        assert_eq!(SecretState::of(true, Some(future), None, now), SecretState::Pending);
        assert_eq!(SecretState::of(true, Some(future), Some(past), now), SecretState::Expired);
        assert_eq!(SecretState::of(false, Some(future), None, now), SecretState::Off);
        assert_eq!(SecretState::Expired.label(), "expired");
        assert_eq!(SecretState::Pending.label(), "pending");
    }

    #[test]
    fn timestamps_are_trimmed_for_display() {
        let time = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        assert_eq!(fmt_timestamp(Some(time)).as_deref(), Some("2023-11-14 22:13"));
        assert_eq!(fmt_timestamp(None), None);
    }

    #[test]
    fn expiry_parses_dates_and_timestamps() {
        assert_eq!(parse_expiry("").unwrap(), None);
        assert_eq!(parse_expiry("   ").unwrap(), None);
        let date = parse_expiry("2027-01-31").unwrap().unwrap();
        assert_eq!(date.year(), 2027);
        assert_eq!(u8::from(date.month()), 1);
        assert_eq!(date.day(), 31);
        assert_eq!(date.hour(), 0);
        let timestamp = parse_expiry("2027-01-31T10:20:30Z").unwrap().unwrap();
        assert_eq!(timestamp.hour(), 10);
        assert!(parse_expiry("31/01/2027").is_err());
        assert!(parse_expiry("2027-13-01").is_err());
        assert!(parse_expiry("2027-01").is_err());
    }

    #[test]
    fn dates_format_for_editing() {
        let time = parse_expiry("2027-05-09").unwrap().unwrap();
        assert_eq!(fmt_date(Some(time)), "2027-05-09");
        assert_eq!(fmt_date(None), "");
    }

    #[test]
    fn enabled_is_case_insensitive() {
        let sub = Subscription {
            id: "1".into(),
            name: "s".into(),
            tenant_id: "t".into(),
            state: "Enabled".into(),
            is_default: true,
        };
        assert!(sub.enabled());
    }
}
