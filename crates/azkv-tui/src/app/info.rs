use std::time::Duration;

use super::*;
use ratatui::crossterm::event::{KeyCode, KeyEvent};

pub(super) const INFO_TTL: Duration = Duration::from_secs(180);

impl App {
    /// Vault whose info window is open, if any.
    pub fn info_vault(&self) -> Option<&Vault> {
        let url = self.info_url.as_ref()?;
        self.vaults.iter().find(|vault| &vault.url == url)
    }

    pub(super) fn on_help_key(&mut self, key: KeyEvent) -> Option<Action> {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('h')) {
            self.help = false;
        }
        None
    }

    pub(super) fn open_info(&mut self) -> Option<Action> {
        self.info_moved = false;
        self.show_info(false)
    }

    /// Show cached info when it is younger than [INFO_TTL]; otherwise load it.
    /// `force` bypasses the cache (`r` refresh key).
    pub(super) fn show_info(&mut self, force: bool) -> Option<Action> {
        let vault = self.vault()?;
        let profile = self.profile()?.clone();
        self.info_url = Some(vault.url.clone());
        if !force
            && let Some((at, result)) = self.info_cache.get(&vault.url)
            && at.elapsed() < INFO_TTL
        {
            self.info = Some(result.clone());
            self.status = format!("vault info: {}", vault.name);
            return None;
        }

        self.info = None;
        self.status = "loading vault info...".into();
        Some(Action::LoadVaultInfo { profile, vault })
    }

    pub(super) fn on_info_key(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('i') => {
                self.info_url = None;
                self.info = None;
                if std::mem::take(&mut self.info_moved) {
                    return self.open_vault();
                }
            },
            KeyCode::Down => {
                let len = self.visible_vaults().len();
                let before = self.vault_state.selected();
                step_selection(&mut self.vault_state, len, 1);
                if self.vault_state.selected() != before {
                    self.info_moved = true;
                    return self.show_info(false);
                }
            },
            KeyCode::Up => {
                let len = self.visible_vaults().len();
                let before = self.vault_state.selected();
                step_selection(&mut self.vault_state, len, -1);
                if self.vault_state.selected() != before {
                    self.info_moved = true;
                    return self.show_info(false);
                }
            },
            KeyCode::Char('r') => return self.show_info(true),
            _ => {},
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::app::{Action, App, Msg, Pane};
    use azkv_core::{Overview, Profile, SecretMeta, Subscription, Tenant, Vault, VaultInfo};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn vault(name: &str, subscription: &Subscription) -> Vault {
        Vault::from_name(name, subscription, Some("rg".into()))
    }

    fn loaded_app() -> App {
        let mut app = App::new(vec![profile("test"), profile("coucou")], 0);
        let subscriptions = vec![sub("s1", "prod", "t1", true), sub("s2", "dev", "t2", false)];
        let tenants = vec![
            Tenant { id: "t1".into(), name: "Tenant One".into() },
            Tenant { id: "t2".into(), name: "Tenant Two".into() },
        ];
        app.handle(Msg::Overview {
            dir: app.profile().unwrap().dir.clone(),
            result: Ok(Overview { subscriptions, tenants, warnings: Vec::new() }),
        });
        app
    }

    fn with_vaults(app: &mut App) {
        let subscription = app.subscription().unwrap();
        let vaults = vec![vault("kv-a", &subscription), vault("kv-b", &subscription)];
        app.handle(Msg::Vaults {
            dir: app.profile().unwrap().dir.clone(),
            subscription_id: subscription.id,
            result: Ok(vaults),
        });
    }

    fn with_secrets(app: &mut App, names: &[&str]) {
        let url = app.vault().unwrap().url;
        app.handle(Msg::Secrets { url, result: Ok(names.iter().map(|name| meta(name)).collect()) });
    }

    fn meta(name: &str) -> SecretMeta {
        SecretMeta {
            name: name.into(),
            enabled: true,
            expires: None,
            not_before: None,
            updated: None,
            content_type: Some("text/plain".into()),
            tags: Default::default(),
        }
    }

    fn profile(name: &str) -> Profile {
        Profile { name: name.into(), dir: PathBuf::from(format!("/azure/{name}")) }
    }

    fn sub(id: &str, name: &str, tenant: &str, default: bool) -> Subscription {
        Subscription {
            id: id.into(),
            name: name.into(),
            tenant_id: tenant.into(),
            state: "Enabled".into(),
            is_default: default,
        }
    }

    #[test]
    fn info_window_loads_details_and_closes() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        app.pane = Pane::Vaults;
        let action = app.on_key(key(KeyCode::Char('i'))).unwrap();
        let Action::LoadVaultInfo { vault, .. } = action else {
            panic!("expected LoadVaultInfo, got {action:?}");
        };
        assert_eq!(vault.name, "kv-a");
        assert_eq!(app.info_url.as_deref(), Some(vault.url.as_str()));
        assert!(app.info.is_none());

        let info = VaultInfo {
            resource_group: Some("rg".into()),
            firewall: Some("Deny".into()),
            ip_rules: vec!["1.2.3.4".into(), "5.6.7.8".into()],
            rbac: Some(true),
            user: Some("me@example.com".into()),
            roles: vec!["Key Vault Secrets User".into()],
            ..VaultInfo::default()
        };
        assert!(app.handle(Msg::VaultInfo { url: vault.url, result: Ok(info) }).is_none());
        assert!(matches!(
            &app.info,
            Some(Ok(info)) if info.firewall.as_deref() == Some("Deny")
                && info.roles == vec!["Key Vault Secrets User".to_string()]
        ));
        assert!(app.on_key(key(KeyCode::Char('q'))).is_none());
        assert!(app.info_url.is_none());
        assert!(app.info.is_none());
    }

    #[test]
    fn help_opens_for_every_pane_and_swallows_pane_keys() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);

        assert!(app.on_key(key(KeyCode::Char('h'))).is_none());
        assert!(app.help);
        assert!(app.info_url.is_none(), "h shows shortcuts, not vault details");
        assert_eq!(app.pane, Pane::Vaults);
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.pane, Pane::Vaults, "keys behind the overlay are inert");
        app.on_key(key(KeyCode::Esc));
        assert!(!app.help);

        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('h')));
        assert!(app.help);
        app.on_key(key(KeyCode::Char('q')));
        assert!(!app.help, "q closes the overlay instead of quitting");
        app.on_key(key(KeyCode::Char('h')));
        assert!(app.help, "h opens the overlay again");
        app.on_key(key(KeyCode::Char('h')));
        assert!(!app.help, "h toggles the overlay off");
        assert_eq!(app.pane, Pane::Secrets);
    }

    #[test]
    fn info_is_not_opened_from_the_secrets_pane() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;

        assert!(app.on_key(key(KeyCode::Char('i'))).is_none());
        assert!(app.info_url.is_none());
    }

    #[test]
    fn info_arrows_reload_the_selected_vault_and_secrets_on_close() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Vaults;
        app.on_key(key(KeyCode::Char('i')));

        let action = app.on_key(key(KeyCode::Down)).unwrap();
        let Action::LoadVaultInfo { vault, .. } = action else {
            panic!("expected LoadVaultInfo, got {action:?}");
        };
        assert_eq!(vault.name, "kv-b");
        assert_eq!(app.vault().unwrap().name, "kv-b");
        assert!(app.info_moved);

        let action = app.on_key(key(KeyCode::Esc)).unwrap();
        assert!(matches!(action, Action::LoadSecrets { .. }));
        assert!(app.info_url.is_none());
        assert!(!app.info_moved);
    }

    #[test]
    fn info_is_cached_for_a_minute_and_r_forces_a_refresh() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        app.pane = Pane::Vaults;
        let action = app.on_key(key(KeyCode::Char('i'))).unwrap();
        let Action::LoadVaultInfo { vault, .. } = action else {
            panic!("expected LoadVaultInfo, got {action:?}");
        };
        app.handle(Msg::VaultInfo {
            url: vault.url,
            result: Ok(VaultInfo { resource_group: Some("rg-a".into()), ..VaultInfo::default() }),
        });
        app.on_key(key(KeyCode::Esc));

        assert!(app.on_key(key(KeyCode::Char('i'))).is_none());
        assert!(matches!(
            &app.info,
            Some(Ok(info)) if info.resource_group.as_deref() == Some("rg-a")
        ));

        let action = app.on_key(key(KeyCode::Char('r'))).unwrap();
        let Action::LoadVaultInfo { vault, .. } = action else {
            panic!("expected LoadVaultInfo, got {action:?}");
        };
        assert_eq!(vault.name, "kv-a");
        assert!(app.info.is_none());
    }

    #[test]
    fn moving_in_info_uses_a_fresh_cache_without_reloading() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        app.pane = Pane::Vaults;
        app.on_key(key(KeyCode::Char('i')));
        let vault_b = app.vaults[1].url.clone();
        app.info_cache.insert(
            vault_b,
            (Instant::now(), Ok(VaultInfo { resource_group: Some("rg-b".into()), ..VaultInfo::default() })),
        );

        assert!(app.on_key(key(KeyCode::Down)).is_none());
        assert_eq!(app.vault().unwrap().name, "kv-b");
        assert!(matches!(
            &app.info,
            Some(Ok(info)) if info.resource_group.as_deref() == Some("rg-b")
        ));
    }

    #[test]
    fn moving_in_info_refetches_a_stale_cache_entry() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        app.pane = Pane::Vaults;
        app.on_key(key(KeyCode::Char('i')));
        let vault_b = app.vaults[1].url.clone();
        app.info_cache.insert(vault_b, (Instant::now() - INFO_TTL - Duration::from_secs(1), Ok(VaultInfo::default())));

        let action = app.on_key(key(KeyCode::Down)).unwrap();
        let Action::LoadVaultInfo { vault, .. } = action else {
            panic!("expected LoadVaultInfo, got {action:?}");
        };
        assert_eq!(vault.name, "kv-b");
    }

    #[test]
    fn stale_vault_info_is_ignored() {
        let mut app = loaded_app();
        app.info_url = Some("https://kv-a.vault.azure.net/".into());
        app.handle(Msg::VaultInfo { url: "https://other.vault.azure.net/".into(), result: Ok(VaultInfo::default()) });
        assert!(app.info.is_none());
    }
}
