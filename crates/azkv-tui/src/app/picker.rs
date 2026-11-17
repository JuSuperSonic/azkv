use super::*;
use ratatui::crossterm::event::{KeyCode, KeyEvent};

impl App {
    pub(super) fn on_picker_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.code == KeyCode::Char('r')
            && self.picker.as_ref().is_some_and(|picker| picker.kind == PickerKind::CopyVault)
        {
            self.copy_refreshing = true;
            self.status = "refreshing vaults...".into();
            return self.load_vaults();
        }
        let picker = self.picker.as_mut()?;
        if picker.filtering {
            match key.code {
                KeyCode::Esc => {
                    picker.filtering = false;
                    picker.filter.clear();
                    picker.selected = 0;
                },
                KeyCode::Enter => picker.filtering = false,
                KeyCode::Backspace => {
                    picker.filter.pop();
                    picker.selected = 0;
                },
                KeyCode::Char(character) => {
                    picker.filter.push(character);
                    picker.selected = 0;
                },
                _ => {},
            }
            return None;
        }
        match key.code {
            KeyCode::Char('/') => {
                picker.filtering = true;
                picker.filter.clear();
                picker.selected = 0;
                None
            },
            KeyCode::Esc | KeyCode::Char('q') => {
                self.picker = None;
                self.copy_refreshing = false;
                None
            },
            KeyCode::Down => {
                let last = picker.visible().len().saturating_sub(1);
                if !picker.items.is_empty() {
                    picker.selected = (picker.selected + 1).min(last);
                }
                None
            },
            KeyCode::Up => {
                picker.selected = picker.selected.saturating_sub(1);
                None
            },
            KeyCode::Enter => {
                if self.picker.as_ref()?.visible().is_empty() {
                    return None;
                }
                let picker = self.picker.take()?;
                self.copy_refreshing = false;
                self.apply_picker(picker)
            },
            _ => None,
        }
    }

    pub(super) fn apply_picker(&mut self, picker: Picker) -> Option<Action> {
        let index = *picker.visible().get(picker.selected)?;
        let value = *picker.values.get(index)?;
        match picker.kind {
            PickerKind::Profiles => {
                self.profile_idx = value?;
                self.pane = Pane::Vaults;
                self.reset_views();
                self.subscriptions.clear();
                self.tenants.clear();
                self.tenant_idx = None;
                self.loading = true;
                Some(Action::LoadOverview { profile: self.profile()?.clone() })
            },
            PickerKind::Tenants => {
                self.tenant_idx = value;
                self.sub_idx = 0;
                self.pane = Pane::Vaults;
                self.reset_views();
                if self.filtered_subscriptions().is_empty() {
                    self.status = "no subscriptions in this tenant".into();
                    return None;
                }
                self.load_vaults()
            },
            PickerKind::Subscriptions => {
                self.sub_idx = value?;
                self.pane = Pane::Vaults;
                self.reset_views();
                self.load_vaults()
            },
            PickerKind::CopySubscription => {
                let subscription = self.subscriptions.get(value?)?.clone();
                self.select_copy_subscription(subscription)
            },
            PickerKind::CopyVault => {
                let dest = self.copy_vaults.get(value?)?.clone();
                self.ask_copy_vault(dest)
            },
        }
    }

    pub(super) fn on_filter_key(&mut self, key: KeyEvent) -> Option<Action> {
        let pane = self.pane;
        match key.code {
            KeyCode::Esc => {
                self.filtering = false;
                self.clear_filter(pane);
                self.reset_selection(pane);
            },
            KeyCode::Enter => self.filtering = false,
            KeyCode::Backspace => {
                self.filter_mut(pane).pop();
                self.reset_selection(pane);
            },
            KeyCode::Char(character) => {
                self.filter_mut(pane).push(character);
                self.reset_selection(pane);
            },
            _ => return None,
        }
        if pane == Pane::Secrets { self.preview() } else { None }
    }

    pub(super) fn open_profile_picker(&mut self) {
        let items =
            self.profiles.iter().map(|profile| format!("{}  {}", profile.name, profile.dir.display())).collect();
        let values = (0..self.profiles.len()).map(Some).collect();
        self.picker = Some(Picker {
            kind: PickerKind::Profiles,
            title: "Azure CLI profiles",
            items,
            values,
            selected: self.profile_idx,
            filter: String::new(),
            filtering: false,
        });
    }

    pub(super) fn open_tenant_picker(&mut self) {
        let mut items = vec!["All tenants".to_string()];
        let mut values = vec![None];
        for (index, tenant) in self.tenants.iter().enumerate() {
            let count = self.subscriptions.iter().filter(|sub| sub.tenant_id == tenant.id).count();
            items.push(format!("{}  ({count} subscriptions)", tenant.name));
            values.push(Some(index));
        }
        let selected = self.tenant_idx.map(|index| index + 1).unwrap_or(0);
        self.picker = Some(Picker {
            kind: PickerKind::Tenants,
            title: "tenants",
            items,
            values,
            selected,
            filter: String::new(),
            filtering: false,
        });
    }

    pub(super) fn open_subscription_picker(&mut self) {
        let subs = self.filtered_subscriptions();
        let items = subs
            .iter()
            .filter_map(|index| self.subscriptions.get(*index))
            .map(|sub| format!("{}  {}  [{}]", sub.name, self.tenant_name(&sub.tenant_id), sub.state))
            .collect();
        let values = (0..subs.len()).map(Some).collect();
        self.picker = Some(Picker {
            kind: PickerKind::Subscriptions,
            title: "subscriptions",
            items,
            values,
            selected: self.sub_idx,
            filter: String::new(),
            filtering: false,
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::app::{Action, App, Msg, Pane};
    use azkv_core::{Overview, Profile, SecretMeta, Subscription, Tenant, Vault};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::path::PathBuf;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn profile(name: &str) -> Profile {
        Profile { name: name.into(), dir: PathBuf::from(format!("/azure/{name}")) }
    }

    fn vault(name: &str, subscription: &Subscription) -> Vault {
        Vault::from_name(name, subscription, Some("rg".into()))
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
    fn starts_by_loading_the_selected_profile() {
        let mut app = App::new(vec![profile("test")], 0);
        assert_eq!(app.start(), Some(Action::LoadOverview { profile: profile("test") }));
        assert!(app.loading);
    }

    #[test]
    fn overview_selects_default_subscription_and_loads_vaults() {
        let app = loaded_app();
        assert_eq!(app.subscriptions.len(), 2);
        assert_eq!(app.subscription().unwrap().id, "s1");
        assert!(app.loading);
    }

    #[test]
    fn overview_from_another_profile_is_ignored() {
        let mut app = App::new(vec![profile("test")], 0);
        let action = app.handle(Msg::Overview { dir: PathBuf::from("/azure/coucou"), result: Ok(Overview::default()) });
        assert!(action.is_none());
        assert!(app.subscriptions.is_empty());
    }

    #[test]
    fn vaults_load_and_auto_open_the_first_vault() {
        let mut app = loaded_app();
        let subscription = app.subscription().unwrap();
        let action = app.handle(Msg::Vaults {
            dir: app.profile().unwrap().dir.clone(),
            subscription_id: subscription.id.clone(),
            result: Ok(vec![vault("kv-a", &subscription), vault("kv-b", &subscription)]),
        });
        assert!(matches!(action, Some(Action::LoadSecrets { .. })));
        assert_eq!(app.vault_state.selected(), Some(0));
        assert_eq!(app.vault().unwrap().name, "kv-a");
    }

    #[test]
    fn stale_vault_response_is_ignored() {
        let mut app = loaded_app();
        let action = app.handle(Msg::Vaults {
            dir: app.profile().unwrap().dir.clone(),
            subscription_id: "other".into(),
            result: Ok(vec![]),
        });
        assert!(action.is_none());
        assert!(app.vaults.is_empty());
    }

    #[test]
    fn secrets_load_and_fetch_the_first_value() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        let url = app.vault().unwrap().url;
        let action = app.handle(Msg::Secrets { url, result: Ok(vec![meta("alpha"), meta("beta")]) });
        assert!(matches!(action, Some(Action::FetchValue { ref name, .. }) if name == "alpha"));
        assert_eq!(app.secrets.len(), 2);
        assert!(!app.loading);
    }

    #[test]
    fn values_from_another_vault_are_ignored() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        let action = app.handle(Msg::Value {
            url: "https://other.vault.azure.net/".into(),
            name: "alpha".into(),
            result: Ok("x".into()),
        });
        assert!(action.is_none());
        assert!(app.values.is_empty());
    }

    #[test]
    fn filtering_narrows_secrets_and_resets_selection() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["db-password", "db-user", "api-key"]);
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('/')));
        for character in "DB".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        app.on_key(key(KeyCode::Enter));
        assert!(!app.filtering);
        assert_eq!(app.secret_filter, "DB");
        assert_eq!(app.visible_secrets().len(), 2);
        assert_eq!(app.secret_state.selected(), Some(0));
    }

    #[test]
    fn y_copies_every_visible_name() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["db-password", "db-user", "api-key"]);
        app.pane = Pane::Secrets;
        app.secret_filter = "db".into();
        assert_eq!(app.on_key(key(KeyCode::Char('Y'))), Some(Action::Copy("db-password\ndb-user".into())));

        app.secret_filter = "zz".into();
        assert!(app.on_key(key(KeyCode::Char('Y'))).is_none());
        assert_eq!(app.status, "no secrets to copy");
    }

    #[test]
    fn escape_clears_the_filter() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["a", "b"]);
        app.pane = Pane::Secrets;
        app.secret_filter = "zz".into();
        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.visible_secrets().len(), 2);
    }

    #[test]
    fn navigation_clamps_at_the_edges() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        app.pane = Pane::Vaults;
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.vault_state.selected(), Some(0));
        app.on_key(key(KeyCode::Char('G')));
        assert_eq!(app.vault_state.selected(), Some(1));
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.vault_state.selected(), Some(1));
    }

    #[test]
    fn page_keys_jump_one_screenful() {
        let mut app = loaded_app();
        let subscription = app.subscription().unwrap();
        let vaults = (0..5).map(|index| vault(&format!("kv-{index}"), &subscription)).collect();
        app.handle(Msg::Vaults {
            dir: app.profile().unwrap().dir.clone(),
            subscription_id: subscription.id,
            result: Ok(vaults),
        });
        app.pane = Pane::Vaults;
        app.vault_rows = 2;

        app.on_key(key(KeyCode::PageDown));
        assert_eq!(app.vault_state.selected(), Some(2));
        app.on_key(key(KeyCode::PageDown));
        assert_eq!(app.vault_state.selected(), Some(4));
        app.on_key(key(KeyCode::PageUp));
        assert_eq!(app.vault_state.selected(), Some(2));
    }

    #[test]
    fn tenant_picker_filters_subscriptions_and_reloads_vaults() {
        let mut app = loaded_app();
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('t')));
        assert!(app.picker.is_some());
        app.on_key(key(KeyCode::Down)); // All tenants -> Tenant One
        let action = app.on_key(key(KeyCode::Enter));
        assert_eq!(app.tenant_idx, Some(0));
        assert_eq!(app.pane, Pane::Vaults);
        assert_eq!(app.filtered_subscriptions(), vec![0]);
        assert!(matches!(
            action,
            Some(Action::LoadVaults { ref subscription, .. }) if subscription.id == "s1"
        ));
    }

    #[test]
    fn tenant_picker_all_tenants_keeps_every_subscription() {
        let mut app = loaded_app();
        app.tenant_idx = Some(1);
        app.on_key(key(KeyCode::Char('t')));
        app.on_key(key(KeyCode::Up));
        app.on_key(key(KeyCode::Up));
        let action = app.on_key(key(KeyCode::Enter));
        assert_eq!(app.tenant_idx, None);
        assert_eq!(app.filtered_subscriptions(), vec![0, 1]);
        assert!(matches!(action, Some(Action::LoadVaults { .. })));
    }

    #[test]
    fn tenant_without_subscriptions_reports_it() {
        let mut app = loaded_app();
        app.tenants.push(Tenant { id: "t3".into(), name: "Empty".into() });
        app.on_key(key(KeyCode::Char('t')));
        for _ in 0..3 {
            app.on_key(key(KeyCode::Down));
        }
        let action = app.on_key(key(KeyCode::Enter));
        assert_eq!(app.tenant_idx, Some(2));
        assert!(action.is_none());
        assert!(app.status.contains("no subscriptions"));
    }

    #[test]
    fn subscription_picker_switches_subscription() {
        let mut app = loaded_app();
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('s')));
        app.on_key(key(KeyCode::Down));
        let action = app.on_key(key(KeyCode::Enter));
        assert_eq!(app.pane, Pane::Vaults);
        assert!(matches!(
            action,
            Some(Action::LoadVaults { ref subscription, .. }) if subscription.id == "s2"
        ));
    }

    #[test]
    fn profile_picker_reloads_the_overview() {
        let mut app = loaded_app();
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('p')));
        app.on_key(key(KeyCode::Down));
        let action = app.on_key(key(KeyCode::Enter));
        assert_eq!(app.profile_idx, 1);
        assert_eq!(app.pane, Pane::Vaults);
        assert!(matches!(
            action,
            Some(Action::LoadOverview { ref profile }) if profile.name == "coucou"
        ));
        assert!(app.subscriptions.is_empty());
    }

    #[test]
    fn profile_picker_filters_with_slash() {
        let mut app = loaded_app();
        app.on_key(key(KeyCode::Char('p')));
        app.on_key(key(KeyCode::Char('/')));
        assert!(app.picker.as_ref().unwrap().filtering);
        for character in "cou".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        let picker = app.picker.as_ref().unwrap();
        assert_eq!(picker.filter, "cou");
        assert_eq!(picker.visible(), vec![1], "only the coucou profile is listed");
        assert_eq!(picker.selected, 0);

        app.on_key(key(KeyCode::Enter));
        assert!(app.picker.as_ref().is_some_and(|picker| !picker.filtering));
        let action = app.on_key(key(KeyCode::Enter));
        assert_eq!(app.profile_idx, 1);
        assert!(matches!(
            action,
            Some(Action::LoadOverview { ref profile }) if profile.name == "coucou"
        ));
    }

    #[test]
    fn picker_filter_escape_clears_but_keeps_the_picker() {
        let mut app = loaded_app();
        app.on_key(key(KeyCode::Char('p')));
        app.on_key(key(KeyCode::Char('/')));
        app.on_key(key(KeyCode::Char('x')));
        app.on_key(key(KeyCode::Esc));
        let picker = app.picker.as_ref().unwrap();
        assert!(!picker.filtering);
        assert!(picker.filter.is_empty());
    }

    #[test]
    fn picker_escape_closes_without_switching() {
        let mut app = loaded_app();
        app.on_key(key(KeyCode::Char('s')));
        assert!(app.picker.is_some());
        app.on_key(key(KeyCode::Esc));
        assert!(app.picker.is_none());
        assert_eq!(app.sub_idx, 0);
    }
}
