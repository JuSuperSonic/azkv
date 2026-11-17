use super::*;
use ratatui::crossterm::event::{KeyCode, KeyEvent};

impl App {
    /// Returns true when the selection actually changed.
    pub(super) fn move_selection(&mut self, delta: isize) -> bool {
        match self.pane {
            Pane::Vaults => {
                let len = self.visible_vaults().len();
                let before = self.vault_state.selected();
                step_selection(&mut self.vault_state, len, delta);
                self.vault_state.selected() != before
            },
            Pane::Secrets => {
                let len = self.visible_secrets().len();
                step_selection(&mut self.secret_state, len, delta);
                self.revealed = false;
                false
            },
        }
    }

    pub(super) fn page_step(&self) -> isize {
        match self.pane {
            Pane::Vaults => self.vault_rows.max(1) as isize,
            Pane::Secrets => self.secret_rows.max(1) as isize,
        }
    }

    /// Returns true when the selection actually changed.
    pub(super) fn jump_to_edge(&mut self, to_end: bool) -> bool {
        match self.pane {
            Pane::Vaults => {
                let len = self.visible_vaults().len();
                let before = self.vault_state.selected();
                jump_selection(&mut self.vault_state, len, to_end);
                self.vault_state.selected() != before
            },
            Pane::Secrets => {
                let len = self.visible_secrets().len();
                jump_selection(&mut self.secret_state, len, to_end);
                self.revealed = false;
                false
            },
        }
    }

    pub(super) fn after_secret_move(&mut self, moved: bool) -> Option<Action> {
        if self.pane == Pane::Secrets {
            self.preview()
        } else if moved {
            // Selecting a vault previews its secrets without pressing enter.
            self.open_vault()
        } else {
            None
        }
    }

    pub(super) fn open_vault(&mut self) -> Option<Action> {
        self.secrets.clear();
        self.secret_state.select(None);
        self.values.clear();
        self.secret_filter.clear();
        self.revealed = false;
        self.pending_edit = None;
        self.pending_copy = None;
        self.copy_review = None;
        self.load_secrets()
    }

    pub(super) fn load_vaults(&mut self) -> Option<Action> {
        let profile = self.profile()?.clone();
        let subscription = self.subscription()?;
        self.loading = true;
        Some(Action::LoadVaults { profile, subscription })
    }

    pub(super) fn load_secrets(&mut self) -> Option<Action> {
        let (profile, subscription, vault) = self.context()?;
        self.loading = true;
        Some(Action::LoadSecrets { profile, subscription, vault })
    }

    /// With a secret selected, re-read only that row; otherwise reload the list.
    pub(super) fn refresh_secret(&mut self) -> Option<Action> {
        let Some(name) = self.selected_secret().map(|secret| secret.name.clone()) else {
            self.status = "refreshing secrets...".into();
            return self.load_secrets();
        };
        let (profile, subscription, vault) = self.context()?;
        self.loading = true;
        self.status = format!("refreshing {name}...");
        Some(Action::RefreshSecret { profile, subscription, vault, name })
    }

    pub(super) fn preview(&mut self) -> Option<Action> {
        let name = self.selected_secret()?.name.clone();
        if self.values.contains_key(&name) {
            return None;
        }
        let (profile, subscription, vault) = self.context()?;
        Some(Action::FetchValue { profile, subscription, vault, name })
    }

    pub(super) fn copy_names(&mut self) -> Option<Action> {
        let names: Vec<&str> = self
            .visible_secrets()
            .into_iter()
            .filter_map(|index| self.secrets.get(index))
            .map(|s| s.name.as_str())
            .collect();
        if names.is_empty() {
            self.status = "no secrets to copy".into();
            return None;
        }
        Some(Action::Copy(names.join("\n")))
    }

    pub(super) fn copy_value(&mut self) -> Option<Action> {
        let name = self.selected_secret()?.name.clone();
        match self.values.get(&name) {
            Some(Ok(value)) => Some(Action::Copy(value.clone())),
            Some(Err(err)) => {
                self.status = format!("error: {err}");
                None
            },
            None => {
                self.pending_copy = Some(name);
                self.status = "fetching value...".into();
                self.preview()
            },
        }
    }

    /// The secret under the cursor, or `None` plus a status hint when the
    /// secrets pane has nothing selected.
    fn secret_in_focus(&mut self) -> Option<SecretMeta> {
        if self.pane == Pane::Secrets
            && let Some(secret) = self.selected_secret()
        {
            return Some(secret.clone());
        }
        self.status = "select a secret first".into();
        None
    }

    pub(super) fn ask_delete(&mut self) -> Option<Action> {
        let name = self.secret_in_focus()?.name;
        self.confirm_delete = Some(DeleteConfirm { name, yes: false });
        None
    }

    pub(super) fn on_delete_key(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Left | KeyCode::Right | KeyCode::Up | KeyCode::Down => {
                if let Some(confirm) = self.confirm_delete.as_mut() {
                    confirm.yes = !confirm.yes;
                }
                None
            },
            KeyCode::Enter => {
                let confirm = self.confirm_delete.take()?;
                if !confirm.yes {
                    self.status = "delete cancelled".into();
                    return None;
                }
                let profile = self.profile()?.clone();
                let vault = self.vault()?;
                Some(Action::DeleteSecret { profile, vault, name: confirm.name })
            },
            KeyCode::Esc => {
                self.confirm_delete = None;
                self.status = "delete cancelled".into();
                None
            },
            _ => None,
        }
    }

    pub(super) fn open_duplicate(&mut self) -> Option<Action> {
        let source = self.secret_in_focus()?.name;
        let mut name = EditField::new("name", &format!("{source}-copy"));
        name.focus();
        self.duplicate = Some(Duplicate { source, name });
        None
    }

    pub(super) fn on_duplicate_key(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc => {
                self.duplicate = None;
                self.status = "duplicate cancelled".into();
                None
            },
            KeyCode::Enter => {
                let (source, name) = {
                    let duplicate = self.duplicate.as_ref()?;
                    (duplicate.source.clone(), duplicate.name.text().trim().to_string())
                };
                if name.is_empty() {
                    self.status = "duplicate: name required".into();
                    return None;
                }
                if name == source {
                    self.status = "duplicate: choose a different name".into();
                    return None;
                }
                let profile = self.profile()?.clone();
                let vault = self.vault()?;
                self.duplicate = None;
                Some(Action::DuplicateSecret { profile, vault, source, name })
            },
            _ => {
                let duplicate = self.duplicate.as_mut()?;
                edit_field(&mut duplicate.name, key.code);
                None
            },
        }
    }

    pub(super) fn reset_views(&mut self) {
        self.vaults.clear();
        self.vault_state.select(None);
        self.secrets.clear();
        self.secret_state.select(None);
        self.values.clear();
        self.vault_filter.clear();
        self.secret_filter.clear();
        self.revealed = false;
        self.pending_copy = None;
        self.pending_edit = None;
        self.copy_review = None;
        self.copy_refreshing = false;
        self.info_cache.clear();
        self.duplicate = None;
        self.confirm_delete = None;
    }

    pub(super) fn reset_selection(&mut self, pane: Pane) {
        match pane {
            Pane::Vaults => {
                let len = self.visible_vaults().len();
                self.vault_state.select(if len == 0 { None } else { Some(0) });
            },
            Pane::Secrets => {
                let len = self.visible_secrets().len();
                self.secret_state.select(if len == 0 { None } else { Some(0) });
                self.revealed = false;
            },
        }
    }

    pub(super) fn filter_mut(&mut self, pane: Pane) -> &mut String {
        match pane {
            Pane::Vaults => &mut self.vault_filter,
            Pane::Secrets => &mut self.secret_filter,
        }
    }

    pub(super) fn clear_filter(&mut self, pane: Pane) {
        self.filter_mut(pane).clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::app::{Action, App, Msg, Pane};
    use azkv_core::{Overview, Profile, SecretMeta, SecretState, Subscription, Tenant, Vault};
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
    fn enter_on_a_vault_focuses_secrets_without_reloading() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Vaults;
        let action = app.on_key(key(KeyCode::Enter));
        assert!(action.is_none(), "enter must not reload the vault");
        assert_eq!(app.pane, Pane::Secrets);
        assert_eq!(app.secrets.len(), 1);
    }

    #[test]
    fn copy_cached_value_needs_no_fetch() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok("secret".into()));
        let action = app.on_key(key(KeyCode::Char('c')));
        assert_eq!(action, Some(Action::Copy("secret".into())));
    }

    #[test]
    fn copy_missing_value_fetches_then_copies_on_arrival() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        let action = app.on_key(key(KeyCode::Char('c')));
        assert!(matches!(action, Some(Action::FetchValue { ref name, .. }) if name == "alpha"));
        assert_eq!(app.pending_copy.as_deref(), Some("alpha"));

        let url = app.vault().unwrap().url;
        let action = app.handle(Msg::Value { url, name: "alpha".into(), result: Ok("secret".into()) });
        assert_eq!(action, Some(Action::Copy("secret".into())));
        assert!(app.pending_copy.is_none());
    }

    #[test]
    fn copy_name_uses_the_selected_secret() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha", "beta"]);
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.on_key(key(KeyCode::Char('y'))), Some(Action::Copy("beta".into())));
    }

    #[test]
    fn space_reveals_and_fetches_an_uncached_value() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;
        let action = app.on_key(key(KeyCode::Char(' ')));
        assert!(app.revealed);
        assert!(matches!(action, Some(Action::FetchValue { .. })));
        // Enter no longer reveals in the secrets pane.
        assert!(app.on_key(key(KeyCode::Enter)).is_none());
        assert!(app.revealed);
    }

    #[test]
    fn refreshing_secrets_refreshes_only_the_selected_secret() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha", "beta"]);
        app.values.insert("alpha".into(), Ok("old".into()));
        app.values.insert("beta".into(), Ok("old".into()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.selected_secret().unwrap().name, "beta");

        let action = app.on_key(key(KeyCode::Char('r'))).unwrap();
        let Action::RefreshSecret { name, .. } = action else {
            panic!("expected RefreshSecret, got {action:?}");
        };
        assert_eq!(name, "beta");
        assert_eq!(app.status, "refreshing beta...");
        assert_eq!(app.values.len(), 2);

        let url = app.vault().unwrap().url;
        app.handle(Msg::Refreshed { url, name: "beta".into(), result: Ok((meta("beta"), "new".into())) });
        assert_eq!(app.status, "refreshed beta");
        assert_eq!(app.values.get("beta"), Some(&Ok("new".into())));
        assert_eq!(app.secrets.len(), 2);
    }

    #[test]
    fn refreshing_secrets_without_a_selection_reloads_the_list() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;
        app.secret_state.select(None);

        let action = app.on_key(key(KeyCode::Char('r'))).unwrap();
        assert!(matches!(action, Action::LoadSecrets { .. }));
        assert!(app.loading);
        assert_eq!(app.status, "refreshing secrets...");
    }

    #[test]
    fn refreshing_vaults_keeps_the_selection_and_loaded_secrets() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Vaults;
        app.status = "refreshing vaults...".into();

        let subscription = app.subscription().unwrap();
        let vaults = vec![vault("kv-a", &subscription), vault("kv-b", &subscription)];
        let action = app.handle(Msg::Vaults {
            dir: app.profile().unwrap().dir.clone(),
            subscription_id: subscription.id,
            result: Ok(vaults),
        });

        assert!(action.is_none());
        assert_eq!(app.vault().unwrap().name, "kv-a");
        assert_eq!(app.secrets.len(), 1);
        assert_eq!(app.status, "refreshed 2 vaults");
    }

    #[test]
    fn refreshing_vaults_with_a_filter_keeps_the_visible_selection() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        app.vault_filter = "kv-b".into();
        app.reset_selection(Pane::Vaults);
        with_secrets(&mut app, &["alpha"]);
        app.status = "refreshing vaults...".into();

        let subscription = app.subscription().unwrap();
        let vaults = vec![vault("kv-a", &subscription), vault("kv-b", &subscription), vault("kv-c", &subscription)];
        let action = app.handle(Msg::Vaults {
            dir: app.profile().unwrap().dir.clone(),
            subscription_id: subscription.id,
            result: Ok(vaults),
        });

        assert!(action.is_none());
        assert_eq!(app.vault_state.selected(), Some(0));
        assert_eq!(app.vault().unwrap().name, "kv-b");
        assert_eq!(app.secrets.len(), 1);
    }

    #[test]
    fn secret_states_are_rendered_from_core() {
        assert_eq!(SecretState::On.label(), "on");
        assert!(matches("db", ""));
        assert!(!matches("db", "x"));
    }

    #[test]
    fn filters_support_pipe_alternatives() {
        assert!(matches("db-password", "db|api"));
        assert!(matches("api-key", "db|api"));
        assert!(!matches("cache", "db|api"));
        // Spaces around pipes and a trailing pipe (still typing) are tolerated.
        assert!(matches("api-key", " db | api "));
        assert!(matches("db-password", "db|"));
        // A filter with no terms at all behaves like an empty filter.
        assert!(matches("db-password", "|"));
    }

    #[test]
    fn delete_defaults_to_no_and_yes_deletes() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha", "beta"]);
        app.pane = Pane::Secrets;

        assert!(app.on_key(key(KeyCode::Char('D'))).is_none());
        let confirm = app.confirm_delete.as_ref().unwrap();
        assert_eq!(confirm.name, "alpha");
        assert!(!confirm.yes, "No must be focused by default");

        assert!(app.on_key(key(KeyCode::Enter)).is_none());
        assert!(app.confirm_delete.is_none());
        assert_eq!(app.status, "delete cancelled");

        assert!(app.on_key(key(KeyCode::Char('D'))).is_none());
        assert!(app.on_key(key(KeyCode::Right)).is_none());
        assert!(app.confirm_delete.as_ref().unwrap().yes);
        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        match action {
            Action::DeleteSecret { name, vault, .. } => {
                assert_eq!(name, "alpha");
                assert_eq!(vault.name, "kv-a");
            },
            other => panic!("expected DeleteSecret, got {other:?}"),
        }
        assert!(app.confirm_delete.is_none());
    }

    #[test]
    fn delete_can_be_cancelled() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('D')));
        assert!(app.on_key(key(KeyCode::Esc)).is_none());
        assert!(app.confirm_delete.is_none());
        assert_eq!(app.status, "delete cancelled");
    }

    #[test]
    fn delete_and_duplicate_are_gated_to_the_secrets_pane() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Vaults;

        assert!(app.on_key(key(KeyCode::Char('D'))).is_none());
        assert!(app.confirm_delete.is_none());
        assert_eq!(app.status, "select a secret first");

        assert!(app.on_key(key(KeyCode::Char('d'))).is_none());
        assert!(app.duplicate.is_none());
    }

    #[test]
    fn deleted_message_removes_the_row_and_clamps_the_selection() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha", "beta"]);
        app.pane = Pane::Secrets;
        app.secret_state.select(Some(1));
        let url = app.vault().unwrap().url;

        app.handle(Msg::Deleted { url, name: "beta".into(), result: Ok(()) });
        assert_eq!(app.secrets.len(), 1);
        assert_eq!(app.secrets[0].name, "alpha");
        assert_eq!(app.secret_state.selected(), Some(0));
        assert!(app.status.contains("deleted"));
    }

    #[test]
    fn duplicate_prefills_a_new_name() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;

        assert!(app.on_key(key(KeyCode::Char('d'))).is_none());
        let duplicate = app.duplicate.as_ref().unwrap();
        assert_eq!(duplicate.source, "alpha");
        assert_eq!(duplicate.name.text(), "alpha-copy");
        assert!(duplicate.name.is_selected());

        // Typing replaces the selected prefill.
        app.on_key(key(KeyCode::Char('z')));
        assert_eq!(app.duplicate.as_ref().unwrap().name.text(), "z");

        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        match action {
            Action::DuplicateSecret { source, name, .. } => {
                assert_eq!(source, "alpha");
                assert_eq!(name, "z");
            },
            other => panic!("expected DuplicateSecret, got {other:?}"),
        }
        assert!(app.duplicate.is_none());
    }

    #[test]
    fn duplicate_rejects_empty_and_unchanged_names() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;

        app.on_key(key(KeyCode::Char('d')));
        app.on_key(key(KeyCode::Backspace));
        assert!(app.on_key(key(KeyCode::Enter)).is_none());
        assert!(app.duplicate.is_some());
        assert!(app.status.contains("name required"));

        app.on_key(key(KeyCode::Esc));
        app.on_key(key(KeyCode::Char('d')));
        app.on_key(key(KeyCode::Backspace));
        for character in "alpha".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        assert!(app.on_key(key(KeyCode::Enter)).is_none());
        assert!(app.duplicate.is_some());
        assert!(app.status.contains("different name"));
    }

    #[test]
    fn duplicated_message_adds_and_selects_the_new_secret() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;
        let url = app.vault().unwrap().url;

        app.handle(Msg::Duplicated { url, name: "alpha-copy".into(), result: Ok(meta("alpha-copy")) });
        assert_eq!(app.secrets.len(), 2);
        assert_eq!(app.secrets[1].name, "alpha-copy");
        assert_eq!(app.selected_secret().unwrap().name, "alpha-copy");
        assert!(app.status.contains("duplicated"));
    }
}
