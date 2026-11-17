use std::path::PathBuf;
use std::time::Instant;

use azkv_core::Overview;
use azkv_core::copy::{CopyPlan, CopyReport};

use super::*;

impl App {
    pub fn handle(&mut self, msg: Msg) -> Option<Action> {
        match msg {
            Msg::Key(key) => self.on_key(key),
            Msg::Paste(text) => {
                self.paste(&text);
                None
            },
            Msg::Resize => None,
            Msg::Overview { dir, result } => self.on_overview(&dir, result),
            Msg::Vaults { dir, subscription_id, result } => self.on_vaults(&dir, &subscription_id, result),
            Msg::Secrets { url, result } => self.on_secrets(&url, result),
            Msg::Value { url, name, result } => self.on_value(&url, name, result),
            Msg::Refreshed { url, name, result } => self.on_refreshed(&url, name, result),
            Msg::Saved { url, name, value, result } => self.on_saved(&url, name, value, result),
            Msg::Deleted { url, name, result } => self.on_deleted(&url, name, result),
            Msg::Duplicated { url, name, result } => self.on_duplicated(&url, name, result),
            Msg::CopyVaults { subscription_id, result } => self.on_copy_vaults(&subscription_id, result),
            Msg::ProxyChecked { proxy, result } => self.on_proxy_checked(proxy, result),
            Msg::CopyPlan { source, dest, result } => self.on_copy_plan(source, dest, result),
            Msg::CopiedVault { source, dest, result } => self.on_copied_vault(source, dest, result),
            Msg::VaultInfo { url, result } => self.on_vault_info(url, result),
            Msg::Copied(result) => self.on_copied(result),
        }
    }

    fn on_overview(&mut self, dir: &PathBuf, result: Result<Overview, String>) -> Option<Action> {
        if self.stale_profile(dir) {
            return None;
        }
        self.loading = false;
        match result {
            Ok(overview) => {
                let Overview { subscriptions, tenants, warnings } = overview;
                self.subscriptions = subscriptions;
                self.tenants = tenants;
                self.tenant_idx = None;
                self.sub_idx = 0;
                self.reset_views();
                if self.subscriptions.is_empty() {
                    self.status = "no subscriptions in this profile".into();
                    return None;
                }
                self.status = if warnings.is_empty() {
                    format!("{} subscriptions, {} tenants", self.subscriptions.len(), self.tenants.len())
                } else {
                    format!(
                        "{} subscriptions, {} tenants; {} tenant(s) failed (see log)",
                        self.subscriptions.len(),
                        self.tenants.len(),
                        warnings.len()
                    )
                };
                self.load_vaults()
            },
            Err(err) => {
                self.status = format!("error: {err}");
                None
            },
        }
    }

    fn on_vaults(
        &mut self,
        dir: &PathBuf,
        subscription_id: &str,
        result: Result<Vec<Vault>, String>,
    ) -> Option<Action> {
        if self.stale_profile(dir) {
            return None;
        }
        if self.stale_subscription(subscription_id) {
            return None;
        }
        self.loading = false;
        match result {
            Ok(vaults) => {
                let previous = self.vault().map(|vault| vault.url);
                let refreshing = self.status.starts_with("refreshing");
                self.vaults = vaults;
                let visible = self.visible_vaults();
                let kept =
                    previous.as_ref().and_then(|url| visible.iter().position(|index| self.vaults[*index].url == *url));
                let selected = kept.or_else(|| (!visible.is_empty()).then_some(0));
                self.vault_state.select(selected);
                self.status = if refreshing {
                    format!("refreshed {} vaults", self.vaults.len())
                } else {
                    format!(
                        "{} vaults in {}",
                        self.vaults.len(),
                        self.subscription().map(|sub| sub.name).unwrap_or_default()
                    )
                };
                if std::mem::take(&mut self.copy_refreshing) {
                    return self.refresh_copy();
                }
                if kept.is_some() { None } else { self.open_vault() }
            },
            Err(err) => {
                self.vaults.clear();
                self.vault_state.select(None);
                self.copy_refreshing = false;
                self.status = format!("error: {err}");
                None
            },
        }
    }

    fn on_secrets(&mut self, url: &str, result: Result<Vec<SecretMeta>, String>) -> Option<Action> {
        if self.stale_vault(url) {
            return None;
        }
        self.loading = false;
        match result {
            Ok(secrets) => {
                self.secrets = secrets;
                self.values.clear();
                self.revealed = false;
                self.pending_copy = None;
                self.pending_edit = None;
                let visible = self.visible_secrets();
                let index = self
                    .pending_select
                    .take()
                    .and_then(|name| visible.iter().position(|index| self.secrets[*index].name == name))
                    .unwrap_or(0);
                self.secret_state.select(if visible.is_empty() { None } else { Some(index) });
                self.status = if self.status.starts_with("refreshing secrets") {
                    format!("refreshed {} secrets", self.secrets.len())
                } else {
                    format!("{} secrets", self.secrets.len())
                };
                self.preview()
            },
            Err(err) => {
                self.secrets.clear();
                self.secret_state.select(None);
                self.status = format!("error: {err}");
                None
            },
        }
    }

    fn on_value(&mut self, url: &str, name: String, result: Result<String, String>) -> Option<Action> {
        if self.stale_vault(url) {
            return None;
        }
        let editing = self.pending_edit.as_deref() == Some(name.as_str());
        if editing {
            self.pending_edit = None;
        }
        let copying = self.pending_copy.as_deref() == Some(name.as_str());
        if copying {
            self.pending_copy = None;
        }
        let copy_value = match &result {
            Ok(value) => copying.then(|| value.clone()),
            Err(err) => {
                self.status = format!("error: {err}");
                None
            },
        };
        self.values.insert(name.clone(), result);
        if editing && self.values.get(&name).is_some_and(Result::is_ok) {
            return self.open_editor();
        }
        copy_value.map(Action::Copy)
    }

    fn on_refreshed(
        &mut self,
        url: &str,
        name: String,
        result: Result<(SecretMeta, String), String>,
    ) -> Option<Action> {
        if self.stale_vault(url) {
            return None;
        }
        self.loading = false;
        match result {
            Ok((meta, value)) => {
                if let Some(row) = self.secrets.iter_mut().find(|secret| secret.name == name) {
                    *row = meta;
                }
                self.values.insert(name.clone(), Ok(value));
                self.status = format!("refreshed {name}");
            },
            Err(err) => self.status = format!("error: {err}"),
        }
        None
    }

    fn on_saved(
        &mut self,
        url: &str,
        name: String,
        value: Option<String>,
        result: Result<SecretMeta, String>,
    ) -> Option<Action> {
        if self.stale_vault(url) {
            return None;
        }
        match result {
            Ok(meta) => {
                self.editor = None;
                let enabled = meta.enabled;
                let existing = self.secrets.iter().position(|secret| secret.name == name);
                match existing {
                    Some(index) => self.secrets[index] = meta,
                    None => {
                        self.secrets.push(meta);
                        self.secrets.sort_by(|a, b| a.name.cmp(&b.name));
                        self.revealed = false;
                        if let Some(position) =
                            self.visible_secrets().iter().position(|index| self.secrets[*index].name == name)
                        {
                            self.secret_state.select(Some(position));
                        }
                    },
                }
                let reload = match value {
                    Some(value) => {
                        self.values.insert(name.clone(), Ok(value));
                        None
                    },
                    // Attributes-only save: the value was never read.
                    None if enabled => {
                        self.values.remove(&name);
                        self.preview()
                    },
                    None => {
                        self.values.insert(
                            name.clone(),
                            Err("secret is disabled — enable it to read or copy the value".into()),
                        );
                        None
                    },
                };
                self.status = if existing.is_some() { format!("saved '{name}'") } else { format!("created '{name}'") };
                reload
            },
            Err(err) => {
                self.status = format!("save failed: {err}");
                None
            },
        }
    }

    fn on_deleted(&mut self, url: &str, name: String, result: Result<(), String>) -> Option<Action> {
        if self.stale_vault(url) {
            return None;
        }
        match result {
            Ok(()) => {
                let position = self.secret_state.selected().unwrap_or(0);
                self.secrets.retain(|secret| secret.name != name);
                self.values.remove(&name);
                self.revealed = false;
                let len = self.visible_secrets().len();
                self.secret_state.select(if len == 0 { None } else { Some(position.min(len - 1)) });
                self.status = format!("deleted '{name}' (soft delete)");
            },
            Err(err) => self.status = format!("delete failed: {err}"),
        }
        None
    }

    fn on_duplicated(&mut self, url: &str, name: String, result: Result<SecretMeta, String>) -> Option<Action> {
        if self.stale_vault(url) {
            return None;
        }
        match result {
            Ok(meta) => {
                self.secrets.retain(|secret| secret.name != name);
                self.secrets.push(meta);
                self.secrets.sort_by(|a, b| a.name.cmp(&b.name));
                self.values.remove(&name);
                self.revealed = false;
                if let Some(position) =
                    self.visible_secrets().iter().position(|index| self.secrets[*index].name == name)
                {
                    self.secret_state.select(Some(position));
                }
                self.status = format!("duplicated to '{name}'");
            },
            Err(err) => self.status = format!("duplicate failed: {err}"),
        }
        None
    }

    fn on_copy_vaults(&mut self, subscription_id: &str, result: Result<Vec<Vault>, String>) -> Option<Action> {
        if self.copy_sub.as_ref().is_none_or(|sub| sub.id != subscription_id) {
            return None;
        }
        self.loading = false;
        match result {
            Ok(vaults) => {
                self.show_copy_vaults(vaults);
            },
            Err(err) => {
                self.status = format!("error: {err}");
            },
        }
        None
    }

    fn on_proxy_checked(&mut self, proxy: ProxySettings, result: Result<(), String>) -> Option<Action> {
        self.proxy_checking = false;
        match result {
            Ok(()) => {
                let label = proxy.display_url();
                self.set_proxy(Some(proxy));
                self.proxy_editor = None;
                self.status = format!("proxy reachable: {label}");
                self.reload_after_proxy()
            },
            Err(err) => {
                // Keep the editor open so the address can be fixed.
                self.status = format!("proxy check failed: {err}");
                None
            },
        }
    }

    fn on_copy_plan(&mut self, source: Vault, dest: Vault, result: Result<CopyPlan, String>) -> Option<Action> {
        self.loading = false;
        match result {
            Ok(mut plan) => {
                self.copy_review = Some(CopyReview {
                    source,
                    dest,
                    total: plan.skip.len(),
                    queue: plan.skip.drain(..).collect(),
                    plan,
                    yes: false,
                });
                self.next_conflict()
            },
            Err(err) => {
                self.status = format!("copy failed: {err}");
                None
            },
        }
    }

    fn on_copied_vault(&mut self, source: String, dest: String, result: Result<CopyReport, String>) -> Option<Action> {
        self.loading = false;
        self.status = match result {
            Ok(report) => {
                let copied = report.created.len() + report.overwritten.len();
                let failed = report.failed.len();
                let skipped = report.skipped.len();
                if copied == 0 && failed == 0 && skipped == 0 {
                    format!("no secrets in {source}")
                } else if failed > 0 {
                    let (_, message) = &report.failed[0];
                    let more = failed.saturating_sub(1);
                    let more = if more > 0 { format!(" (+{more} more, see log)") } else { String::new() };
                    format!(
                        "copy failed: {} ({failed} of {} secrets, {copied} copied, {skipped} skipped){more}",
                        crate::error::clip(message, 120),
                        copied + failed + skipped
                    )
                } else if skipped > 0 {
                    format!("copied {copied} secrets to {dest}, {skipped} already existed")
                } else if !report.overwritten.is_empty() {
                    format!("copied {copied} secrets to {dest}, {} overwritten", report.overwritten.len())
                } else {
                    format!("copied {copied} secrets to {dest}")
                }
            },
            Err(err) => format!("copy failed: {err}"),
        };
        None
    }

    fn on_vault_info(&mut self, url: String, result: Result<VaultInfo, String>) -> Option<Action> {
        if self.info_url.as_deref() != Some(url.as_str()) {
            return None;
        }
        self.info_cache.insert(url, (Instant::now(), result.clone()));
        self.info = Some(result);
        None
    }

    fn on_copied(&mut self, result: Result<(), String>) -> Option<Action> {
        self.status = match result {
            Ok(()) => "copied to clipboard".into(),
            Err(err) => format!("clipboard error: {err}"),
        };
        None
    }

    /// Ignore background responses for a profile the user left meanwhile.
    fn stale_profile(&self, dir: &PathBuf) -> bool {
        self.profile().is_none_or(|profile| &profile.dir != dir)
    }

    fn stale_subscription(&self, id: &str) -> bool {
        self.subscription().is_none_or(|sub| sub.id != id)
    }

    /// Ignore background responses for a vault the user left meanwhile.
    fn stale_vault(&self, url: &str) -> bool {
        self.vault().is_none_or(|vault| vault.url != url)
    }
}
