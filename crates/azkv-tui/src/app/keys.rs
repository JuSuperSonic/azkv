use super::*;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

impl App {
    pub fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Some(Action::Quit);
        }
        if key.code == KeyCode::Char('e') && key.modifiers.contains(KeyModifiers::CONTROL) && self.editor.is_none() {
            self.show_hints = !self.show_hints;
            return None;
        }
        if self.help {
            return self.on_help_key(key);
        }
        if self.info_url.is_some() {
            return self.on_info_key(key);
        }
        if self.proxy_editor.is_some() {
            return self.on_proxy_key(key);
        }
        if self.editor.is_some() {
            return self.on_editor_key(key);
        }
        if self.picker.is_some() {
            return self.on_picker_key(key);
        }
        if self.copy_review.is_some() {
            return self.on_copy_review_key(key);
        }
        if self.duplicate.is_some() {
            return self.on_duplicate_key(key);
        }
        if self.confirm_delete.is_some() {
            return self.on_delete_key(key);
        }
        if self.filtering {
            return self.on_filter_key(key);
        }
        match key.code {
            KeyCode::Char('q') => Some(Action::Quit),
            KeyCode::Char('p') => {
                self.open_profile_picker();
                None
            },
            KeyCode::Char('t') => {
                self.open_tenant_picker();
                None
            },
            KeyCode::Char('s') => {
                self.open_subscription_picker();
                None
            },
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                self.pane = other(self.pane);
                None
            },
            KeyCode::Down => {
                let moved = self.move_selection(1);
                self.after_secret_move(moved)
            },
            KeyCode::Up => {
                let moved = self.move_selection(-1);
                self.after_secret_move(moved)
            },
            KeyCode::PageDown | KeyCode::PageUp => {
                let step = self.page_step() * if key.code == KeyCode::PageDown { 1 } else { -1 };
                let moved = self.move_selection(step);
                self.after_secret_move(moved)
            },
            KeyCode::Char('g') | KeyCode::Home => {
                let moved = self.jump_to_edge(false);
                self.after_secret_move(moved)
            },
            KeyCode::Char('G') | KeyCode::End => {
                let moved = self.jump_to_edge(true);
                self.after_secret_move(moved)
            },
            KeyCode::Char('/') => {
                self.filtering = true;
                self.clear_filter(self.pane);
                self.reset_selection(self.pane);
                None
            },
            KeyCode::Esc => {
                self.clear_filter(self.pane);
                self.reset_selection(self.pane);
                None
            },
            KeyCode::Enter => match self.pane {
                // Secrets are already loaded when the selection moves; jump to them.
                Pane::Vaults => {
                    self.pane = Pane::Secrets;
                    None
                },
                Pane::Secrets => None,
            },
            KeyCode::Char(' ') if self.pane == Pane::Secrets => {
                self.revealed = !self.revealed;
                if self.revealed { self.preview() } else { None }
            },
            KeyCode::Char('r') => match self.pane {
                Pane::Vaults => {
                    self.status = "refreshing vaults...".into();
                    self.load_vaults()
                },
                Pane::Secrets => self.refresh_secret(),
            },
            KeyCode::Char('a') if self.pane == Pane::Secrets => self.open_new_secret(),
            KeyCode::Char('e') => self.open_editor(),
            KeyCode::Char('d') => self.open_duplicate(),
            KeyCode::Char('D') => self.ask_delete(),
            KeyCode::Char('i') if self.pane == Pane::Vaults => self.open_info(),
            KeyCode::Char('h') => {
                self.help = true;
                None
            },
            KeyCode::Char('P') => {
                self.open_proxy_editor();
                None
            },
            KeyCode::Char('C') if self.pane == Pane::Secrets => self.open_copy_vault(),
            KeyCode::Char('c') => self.copy_value(),
            KeyCode::Char('y') => self.selected_secret().map(|secret| Action::Copy(secret.name.clone())),
            KeyCode::Char('Y') if self.pane == Pane::Secrets => self.copy_names(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::app::{Action, App, Msg, Pane};
    use azkv_core::{Overview, Profile, Subscription, Tenant, Vault};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::path::PathBuf;

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
    fn q_quits_and_ctrl_c_quits() {
        let mut app = loaded_app();
        assert_eq!(app.on_key(key(KeyCode::Char('q'))), Some(Action::Quit));
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(app.on_key(ctrl_c), Some(Action::Quit));
    }

    #[test]
    fn tab_and_arrows_switch_panes() {
        let mut app = loaded_app();
        assert_eq!(app.pane, Pane::Vaults);
        app.on_key(key(KeyCode::Tab));
        assert_eq!(app.pane, Pane::Secrets);
        app.on_key(key(KeyCode::Left));
        assert_eq!(app.pane, Pane::Vaults);
        app.on_key(key(KeyCode::Right));
        assert_eq!(app.pane, Pane::Secrets);
        app.on_key(key(KeyCode::BackTab));
        assert_eq!(app.pane, Pane::Vaults);
    }

    #[test]
    fn resize_is_not_an_error_and_keeps_state() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        let vault = app.vault().unwrap().name;
        assert!(app.handle(Msg::Resize).is_none());
        assert_eq!(app.vault().unwrap().name, vault);
    }
    #[test]
    fn ctrl_e_toggles_the_command_hints() {
        let mut app = loaded_app();
        assert!(app.show_hints);
        let ctrl_e = KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL);
        assert!(app.on_key(ctrl_e).is_none());
        assert!(!app.show_hints);
        app.on_key(ctrl_e);
        assert!(app.show_hints);
    }

    #[test]
    fn letters_no_longer_move_the_selection() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        app.pane = Pane::Vaults;
        app.on_key(key(KeyCode::Char('j')));
        assert_eq!(app.vault_state.selected(), Some(0));
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.vault_state.selected(), Some(1));
        app.on_key(key(KeyCode::Char('k')));
        assert_eq!(app.vault_state.selected(), Some(1));

        app.on_key(key(KeyCode::Char('s')));
        let before = app.picker.as_ref().unwrap().selected;
        app.on_key(key(KeyCode::Char('j')));
        assert_eq!(app.picker.as_ref().unwrap().selected, before);
    }
}
