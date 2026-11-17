use super::*;
use ratatui::crossterm::event::{KeyCode, KeyEvent};

impl App {
    pub(super) fn open_copy_vault(&mut self) -> Option<Action> {
        if self.vault().is_none() {
            self.status = "select a vault first".into();
            return None;
        }
        self.copy_targets()
    }

    pub(super) fn copy_targets(&mut self) -> Option<Action> {
        if self.subscriptions.is_empty() {
            self.status = "no subscriptions in this profile".into();
            return None;
        }
        if self.subscriptions.len() == 1 {
            return self.select_copy_subscription(self.subscriptions[0].clone());
        }
        let items = self
            .subscriptions
            .iter()
            .map(|sub| format!("{}  [{}]", sub.name, self.tenant_name(&sub.tenant_id)))
            .collect();
        let values = (0..self.subscriptions.len()).map(Some).collect();
        self.picker = Some(Picker {
            kind: PickerKind::CopySubscription,
            title: "copy to subscription",
            items,
            values,
            selected: 0,
            filter: String::new(),
            filtering: false,
        });
        None
    }

    pub(super) fn select_copy_subscription(&mut self, subscription: Subscription) -> Option<Action> {
        self.copy_sub = Some(subscription.clone());
        if self.subscription().is_some_and(|current| current.id == subscription.id) {
            self.show_copy_vaults(self.vaults.clone());
            return None;
        }
        self.load_copy_vaults(subscription)
    }

    pub(super) fn refresh_copy(&mut self) -> Option<Action> {
        let subscription = self.copy_sub.clone()?;
        if self.subscription().is_some_and(|current| current.id == subscription.id) {
            self.show_copy_vaults(self.vaults.clone());
            None
        } else {
            self.load_copy_vaults(subscription)
        }
    }

    pub(super) fn show_copy_vaults(&mut self, vaults: Vec<Vault>) {
        let current = self.vault().map(|vault| vault.url.clone());
        self.copy_vaults = vaults.into_iter().filter(|vault| Some(&vault.url) != current.as_ref()).collect();
        if self.copy_vaults.is_empty() {
            self.picker = None;
            self.status = "no other vaults in this subscription".into();
            return;
        }
        let items =
            self.copy_vaults.iter().map(|vault| format!("{}  ({})", vault.name, vault.subscription_name)).collect();
        let values = (0..self.copy_vaults.len()).map(Some).collect();
        self.picker = Some(Picker {
            kind: PickerKind::CopyVault,
            title: "copy to vault",
            items,
            values,
            selected: 0,
            filter: String::new(),
            filtering: false,
        });
    }

    pub(super) fn load_copy_vaults(&mut self, subscription: Subscription) -> Option<Action> {
        let profile = self.profile()?.clone();
        self.copy_sub = Some(subscription.clone());
        self.loading = true;
        self.status = format!("loading vaults in {}...", subscription.name);
        Some(Action::LoadCopyVaults { profile, subscription })
    }

    /// Check the destination first so existing secrets can be reviewed one by one.
    pub(super) fn ask_copy_vault(&mut self, dest: Vault) -> Option<Action> {
        let source = self.vault()?.clone();
        if source.url == dest.url {
            self.status = "destination is the source vault".into();
            return None;
        }
        let profile = self.profile()?.clone();
        self.loading = true;
        self.status = format!("checking {}...", dest.name);
        Some(Action::PlanCopyVault { profile, source, dest, filter: self.secret_filter.clone() })
    }

    pub(super) fn on_copy_review_key(&mut self, key: KeyEvent) -> Option<Action> {
        let review = self.copy_review.as_mut()?;
        match key.code {
            KeyCode::Left | KeyCode::Right | KeyCode::Up | KeyCode::Down => {
                review.yes = !review.yes;
                None
            },
            KeyCode::Enter => {
                let name = review.queue.pop_front()?;
                if review.yes {
                    review.plan.overwrite.push(name);
                } else {
                    review.plan.skip.push(name);
                }
                review.yes = false;
                self.next_conflict()
            },
            KeyCode::Esc => {
                self.copy_review = None;
                self.status = "copy cancelled".into();
                None
            },
            _ => None,
        }
    }

    /// Asks about the next undecided conflict, or starts the copy when done.
    pub(super) fn next_conflict(&mut self) -> Option<Action> {
        let review = self.copy_review.as_ref()?;
        let Some(name) = review.current().map(str::to_string) else {
            let review = self.copy_review.take()?;
            return self.run_copy_vault(review);
        };
        self.status = format!("'{name}' already exists in {}", review.dest.name);
        None
    }

    pub(super) fn run_copy_vault(&mut self, review: CopyReview) -> Option<Action> {
        let profile = self.profile()?.clone();
        self.loading = true;
        self.status = format!(
            "copying {} secrets to {}...",
            review.plan.create.len() + review.plan.overwrite.len(),
            review.dest.name
        );
        Some(Action::CopyVault { profile, source: review.source, dest: review.dest, plan: review.plan })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::app::{Action, App, Msg, Pane, PickerKind};
    use azkv_core::copy::CopyPlan;
    use azkv_core::{Overview, Profile, SecretMeta, Subscription, Tenant, Vault};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::collections::VecDeque;
    use std::path::PathBuf;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
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

    #[test]
    fn copy_to_another_subscription_loads_its_vaults() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;
        assert!(app.on_key(key(KeyCode::Char('C'))).is_none());
        let picker = app.picker.as_ref().unwrap();
        assert_eq!(picker.kind, PickerKind::CopySubscription);
        assert_eq!(picker.items.len(), 2);
        assert!(picker.items[0].contains("Tenant One"));
        app.on_key(key(KeyCode::Down));
        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        let Action::LoadCopyVaults { subscription, .. } = action else {
            panic!("expected LoadCopyVaults, got {action:?}");
        };
        assert_eq!(subscription.id, "s2");
        assert_eq!(app.copy_sub.as_ref().unwrap().id, "s2");
        assert!(app.loading);
    }

    #[test]
    fn single_subscription_reuses_the_loaded_vault_list() {
        let mut app = App::new(vec![profile("test")], 0);
        app.handle(Msg::Overview {
            dir: app.profile().unwrap().dir.clone(),
            result: Ok(Overview { subscriptions: vec![sub("s1", "prod", "t1", true)], ..Overview::default() }),
        });
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;
        assert!(app.on_key(key(KeyCode::Char('C'))).is_none());
        let picker = app.picker.as_ref().unwrap();
        assert_eq!(picker.kind, PickerKind::CopyVault);
        assert_eq!(picker.items, vec!["kv-b  (prod)".to_string()]);
        assert!(!app.loading);
    }

    #[test]
    fn current_copy_subscription_reuses_the_loaded_vault_list() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;
        assert!(app.on_key(key(KeyCode::Char('C'))).is_none());
        assert_eq!(app.picker.as_ref().unwrap().kind, PickerKind::CopySubscription);
        assert!(app.on_key(key(KeyCode::Enter)).is_none());
        let picker = app.picker.as_ref().unwrap();
        assert_eq!(picker.kind, PickerKind::CopyVault);
        assert_eq!(picker.items, vec!["kv-b  (prod)".to_string()]);
        assert!(!app.loading);
    }

    #[test]
    fn refreshing_the_copy_vault_picker_reloads_the_panel_and_its_list() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('C')));
        app.on_key(key(KeyCode::Enter));
        let action = app.on_key(key(KeyCode::Char('r'))).unwrap();
        assert!(matches!(action, Action::LoadVaults { .. }));
        assert!(app.copy_refreshing);

        let subscription = app.subscription().unwrap();
        let vaults = vec![vault("kv-a", &subscription), vault("kv-c", &subscription)];
        app.handle(Msg::Vaults {
            dir: app.profile().unwrap().dir.clone(),
            subscription_id: subscription.id,
            result: Ok(vaults),
        });
        assert!(!app.copy_refreshing);
        let picker = app.picker.as_ref().unwrap();
        assert_eq!(picker.kind, PickerKind::CopyVault);
        assert_eq!(picker.items, vec!["kv-c  (prod)".to_string()]);
    }

    #[test]
    fn copy_vault_picker_excludes_the_current_vault() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        let subscription = app.subscription().unwrap();
        app.copy_sub = Some(subscription.clone());
        app.handle(Msg::CopyVaults {
            subscription_id: subscription.id.clone(),
            result: Ok(vec![vault("kv-a", &subscription), vault("kv-b", &subscription)]),
        });
        let picker = app.picker.as_ref().unwrap();
        assert_eq!(picker.kind, PickerKind::CopyVault);
        assert_eq!(picker.items, vec!["kv-b  (prod)".to_string()]);
        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        assert!(matches!(action, Action::PlanCopyVault { .. }), "got {action:?}");

        assert!(app.loading);
        assert_eq!(app.status, "checking kv-b...");
    }

    #[test]
    fn copy_vault_picker_is_filterable() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        let subscription = app.subscription().unwrap();
        app.copy_sub = Some(subscription.clone());
        app.handle(Msg::CopyVaults {
            subscription_id: subscription.id.clone(),
            result: Ok(vec![vault("kv-a", &subscription), vault("kv-b", &subscription), vault("kv-c", &subscription)]),
        });
        assert!(app.on_key(key(KeyCode::Char('/'))).is_none());
        for character in "kv-c".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        assert_eq!(app.picker.as_ref().unwrap().visible(), vec![1]);
        assert!(app.on_key(key(KeyCode::Enter)).is_none(), "enter keeps the filter");
        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        assert!(matches!(action, Action::PlanCopyVault { .. }), "got {action:?}");
        assert_eq!(app.status, "checking kv-c...");
    }

    #[test]
    fn existing_secrets_are_reviewed_one_by_one() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        let subscription = app.subscription().unwrap();
        app.copy_sub = Some(subscription.clone());
        app.handle(Msg::CopyVaults {
            subscription_id: subscription.id.clone(),
            result: Ok(vec![vault("kv-b", &subscription)]),
        });
        app.on_key(key(KeyCode::Enter));

        let source = app.vault().unwrap();
        app.handle(Msg::CopyPlan {
            source,
            dest: vault("kv-b", &subscription),
            result: Ok(CopyPlan {
                create: vec!["gamma".into()],
                overwrite: vec![],
                skip: vec!["alpha".into(), "beta".into()],
            }),
        });
        assert!(!app.loading);
        assert_eq!(app.status, "'alpha' already exists in kv-b");
        let review = app.copy_review.as_ref().unwrap();
        assert_eq!((review.position(), review.total), (1, 2));
        assert!(!review.yes, "No is focused by default");

        // Enter on the default focus skips alpha.
        assert!(app.on_key(key(KeyCode::Enter)).is_none());
        assert_eq!(app.status, "'beta' already exists in kv-b");
        assert_eq!(app.copy_review.as_ref().unwrap().position(), 2);
        assert!(!app.copy_review.as_ref().unwrap().yes, "focus resets to No");

        // Focus Yes, then confirm: beta is overwritten.
        assert!(app.on_key(key(KeyCode::Right)).is_none());
        assert!(app.copy_review.as_ref().unwrap().yes);
        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        let Action::CopyVault { source, dest, plan, .. } = action else {
            panic!("expected CopyVault, got {action:?}");
        };
        assert_eq!(source.name, "kv-a");
        assert_eq!(dest.name, "kv-b");
        assert_eq!(plan.create, vec!["gamma"]);
        assert_eq!(plan.overwrite, vec!["beta"]);
        assert_eq!(plan.skip, vec!["alpha"]);
        assert!(app.copy_review.is_none());
        assert_eq!(app.status, "copying 2 secrets to kv-b...");
    }

    #[test]
    fn copy_without_conflicts_starts_immediately() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        let subscription = app.subscription().unwrap();
        let source = app.vault().unwrap();
        let action = app.handle(Msg::CopyPlan {
            source,
            dest: vault("kv-b", &subscription),
            result: Ok(CopyPlan { create: vec!["alpha".into()], ..Default::default() }),
        });
        let Some(Action::CopyVault { plan, .. }) = action else {
            panic!("expected CopyVault");
        };
        assert_eq!(plan.create, vec!["alpha"]);
        assert!(app.copy_review.is_none());
    }

    #[test]
    fn copy_review_esc_cancels_the_whole_copy() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        let subscription = app.subscription().unwrap();
        let source = app.vault().unwrap();
        app.handle(Msg::CopyPlan {
            source,
            dest: vault("kv-b", &subscription),
            result: Ok(CopyPlan { skip: vec!["alpha".into()], ..Default::default() }),
        });
        assert!(app.copy_review.is_some());
        assert!(app.on_key(key(KeyCode::Esc)).is_none());
        assert!(app.copy_review.is_none());
        assert!(app.status.contains("cancelled"));
    }

    #[test]
    fn copy_of_existing_secrets_reports_overwrites() {
        let mut app = loaded_app();
        let dest = vault("kv-b", &app.subscription().unwrap());
        app.handle(Msg::CopiedVault {
            source: "kv-a".into(),
            dest: dest.name.clone(),
            result: Ok(azkv_core::copy::CopyReport {
                created: vec!["alpha".into()],
                overwritten: vec!["beta".into()],
                ..Default::default()
            }),
        });
        assert_eq!(app.status, "copied 2 secrets to kv-b, 1 overwritten");
    }

    #[test]
    fn copy_matching_uses_the_vault_picker_and_reports_progress() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Vaults;
        assert!(app.on_key(key(KeyCode::Char('C'))).is_none());
        assert!(app.picker.is_none());

        app.pane = Pane::Secrets;
        assert!(app.on_key(key(KeyCode::Char('C'))).is_none());
        assert_eq!(app.picker.as_ref().unwrap().kind, PickerKind::CopySubscription);
        assert_eq!(app.vault().unwrap().name, "kv-a");

        let subscription = app.subscription().unwrap();
        app.copy_sub = Some(subscription.clone());
        app.handle(Msg::CopyVaults {
            subscription_id: subscription.id.clone(),
            result: Ok(vec![vault("kv-a", &subscription), vault("kv-b", &subscription)]),
        });
        assert_eq!(app.picker.as_ref().unwrap().kind, PickerKind::CopyVault);

        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        assert!(matches!(action, Action::PlanCopyVault { .. }), "got {action:?}");
        let source = app.vault().unwrap();
        let dest = vault("kv-b", &subscription);
        let action = app.handle(Msg::CopyPlan {
            source,
            dest,
            result: Ok(CopyPlan {
                create: vec!["alpha".into(), "beta".into()],
                skip: vec!["gamma".into()],
                ..Default::default()
            }),
        });
        assert!(action.is_none(), "conflicts are reviewed before copying");
        assert_eq!(app.status, "'gamma' already exists in kv-b");

        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        let Action::CopyVault { source, dest, plan, .. } = action else {
            panic!("expected CopyVault, got {action:?}");
        };
        assert_eq!(source.name, "kv-a");
        assert_eq!(dest.name, "kv-b");
        assert_eq!(plan.create, vec!["alpha", "beta"]);
        assert_eq!(plan.skip, vec!["gamma"]);
        assert_eq!(app.status, "copying 2 secrets to kv-b...");

        app.handle(Msg::CopiedVault {
            source: "kv-a".into(),
            dest: "kv-b".into(),
            result: Ok(azkv_core::copy::CopyReport {
                created: vec!["alpha".into(), "beta".into()],
                skipped: vec!["gamma".into()],
                ..Default::default()
            }),
        });
        assert_eq!(app.status, "copied 2 secrets to kv-b, 1 already existed");
        assert!(!app.loading);
    }

    #[test]
    fn copy_vault_carries_the_secret_filter() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;
        app.secret_filter = "db|api".into();
        assert!(app.on_key(key(KeyCode::Char('C'))).is_none());
        let subscription = app.subscription().unwrap();
        app.copy_sub = Some(subscription.clone());
        app.handle(Msg::CopyVaults {
            subscription_id: subscription.id.clone(),
            result: Ok(vec![vault("kv-a", &subscription), vault("kv-b", &subscription)]),
        });
        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        let Action::PlanCopyVault { filter, dest, .. } = action else {
            panic!("expected PlanCopyVault, got {action:?}");
        };
        assert_eq!(filter, "db|api");
        assert_eq!(dest.name, "kv-b");
        assert!(app.loading);
        assert_eq!(app.status, "checking kv-b...");
    }

    #[test]
    fn copy_all_reports_failures() {
        let mut app = loaded_app();
        app.handle(Msg::CopiedVault {
            source: "kv-a".into(),
            dest: "kv-b".into(),
            result: Ok(azkv_core::copy::CopyReport {
                created: vec!["alpha".into()],
                failed: vec![("beta".into(), "denied".into())],
                ..Default::default()
            }),
        });
        assert_eq!(app.status, "copy failed: denied (1 of 2 secrets, 1 copied, 0 skipped)");
    }

    #[test]
    fn copy_failure_explains_soft_deleted_and_points_to_the_log() {
        let mut app = loaded_app();
        app.handle(Msg::CopiedVault {
            source: "kv-a".into(),
            dest: "kv-b".into(),
            result: Ok(azkv_core::copy::CopyReport {
                skipped: vec!["alpha".into(), "beta".into(), "gamma".into()],
                failed: vec![
                    ("db".into(), "destination secret 'db' is soft-deleted: recover or purge it".into()),
                    ("api".into(), "denied".into()),
                ],
                ..Default::default()
            }),
        });
        assert!(app.status.starts_with("copy failed: destination secret 'db' is soft-deleted"));
        assert!(app.status.ends_with("(2 of 5 secrets, 0 copied, 3 skipped) (+1 more, see log)"));
    }

    #[test]
    fn changing_vault_or_profile_clears_pending_work() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pending_edit = Some("alpha".into());
        app.pending_copy = Some("alpha".into());
        app.copy_review = Some(CopyReview {
            source: app.vaults[0].clone(),
            dest: app.vaults[1].clone(),
            plan: CopyPlan::default(),
            queue: VecDeque::from(["alpha".to_string()]),
            total: 1,
            yes: false,
        });

        app.open_vault();
        assert!(app.pending_edit.is_none());
        assert!(app.pending_copy.is_none());
        assert!(app.copy_review.is_none());

        app.pending_edit = Some("alpha".into());
        app.pending_copy = Some("alpha".into());
        app.copy_review = Some(CopyReview {
            source: app.vaults[0].clone(),
            dest: app.vaults[1].clone(),
            plan: CopyPlan::default(),
            queue: VecDeque::from(["alpha".to_string()]),
            total: 1,
            yes: false,
        });
        app.reset_views();
        assert!(app.pending_edit.is_none());
        assert!(app.pending_copy.is_none());
        assert!(app.copy_review.is_none());
    }

    #[test]
    fn stale_copy_vault_responses_are_ignored() {
        let mut app = loaded_app();
        app.copy_sub = Some(app.subscriptions[0].clone());
        assert!(app.handle(Msg::CopyVaults { subscription_id: "s2".into(), result: Ok(vec![]) }).is_none());
        assert!(app.picker.is_none());
    }

    #[test]
    fn moving_in_the_vault_list_loads_that_vaults_secrets() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        app.pane = Pane::Vaults;
        assert_eq!(app.vault().unwrap().name, "kv-a");

        let action = app.on_key(key(KeyCode::Down)).unwrap();
        let Action::LoadSecrets { vault, .. } = action else {
            panic!("expected LoadSecrets, got {action:?}");
        };
        assert_eq!(vault.name, "kv-b");
        assert!(app.secrets.is_empty());

        // No movement at the end of the list, so no extra reload.
        assert!(app.on_key(key(KeyCode::Down)).is_none());

        let action = app.on_key(key(KeyCode::Char('g'))).unwrap();
        let Action::LoadSecrets { vault, .. } = action else {
            panic!("expected LoadSecrets");
        };
        assert_eq!(vault.name, "kv-a");
    }
}
