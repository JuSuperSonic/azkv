use std::collections::BTreeMap;

use super::*;
use azkv_core::{Secret, clipboard, fmt_date, parse_expiry};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

impl App {
    pub(super) fn open_editor(&mut self) -> Option<Action> {
        let secret = self.selected_secret()?.clone();
        let name = secret.name.clone();
        // A disabled secret cannot be read, so open it with a locked value.
        let (value, locked) = if !secret.enabled {
            (String::new(), true)
        } else {
            match self.values.get(&name) {
                Some(Ok(value)) => (value.clone(), false),
                Some(Err(err)) => {
                    self.status = format!("error: {err}");
                    return None;
                },
                None => {
                    self.pending_edit = Some(name);
                    self.status = "fetching value...".into();
                    return self.preview();
                },
            }
        };
        self.editor = Some(Editor {
            secret: name,
            name: None,
            fields: vec![
                EditField::new("value", &value),
                EditField::new("type", secret.content_type.as_deref().unwrap_or("")),
                EditField::date("expires", &fmt_date(secret.expires)),
                EditField::date("activates", &fmt_date(secret.not_before)),
                EditField::new("tags", &format_tags(&secret.tags)),
            ],
            enabled: secret.enabled,
            active: 0,
            value_locked: locked,
            original_value: value,
            original_expires: secret.expires,
            original_not_before: secret.not_before,
            original_updated: secret.updated.map(|updated| updated.unix_timestamp_nanos()),
        });
        self.status = if locked {
            "edit: secret disabled, enable it to edit the value".into()
        } else {
            "edit: tab/↑↓ next, enter save, esc cancel".into()
        };
        None
    }

    pub(super) fn open_new_secret(&mut self) -> Option<Action> {
        if self.vault().is_none() {
            self.status = "select a vault first".into();
            return None;
        }
        self.editor = Some(Editor {
            secret: String::new(),
            name: Some(EditField::new("name", "")),
            fields: vec![
                EditField::new("value", ""),
                EditField::new("type", ""),
                EditField::date("expires", ""),
                EditField::date("activates", ""),
                EditField::new("tags", ""),
            ],
            enabled: true,
            active: 0,
            value_locked: false,
            original_value: String::new(),
            original_expires: None,
            original_not_before: None,
            original_updated: None,
        });
        self.status = "new secret: tab/↑↓ next, enter save, esc cancel".into();
        None
    }

    /// Pasted text goes to the active editor field; only the value keeps
    /// newlines, other fields fold them to spaces.
    pub(super) fn paste(&mut self, text: &str) {
        let Some(editor) = self.editor.as_mut() else {
            return;
        };
        let value_index = usize::from(editor.name.is_some());
        let multiline = text.contains(['\r', '\n']);
        // A multiline blob pasted into the name field is clearly a value.
        if editor.name.is_some() && editor.active == 0 && multiline {
            editor.active = value_index;
        }
        let is_value = editor.active == value_index;
        if is_value && editor.value_locked {
            self.status = "value locked: enable the secret to edit it".into();
            return;
        }
        let text =
            if is_value { text.replace("\r\n", "\n").replace('\r', "\n") } else { text.replace(['\r', '\n'], " ") };
        if let Some(field) = editor.active_field_mut() {
            field.insert_text(&text);
        }
        self.status = format!("pasted {} characters", text.chars().count());
    }

    pub(super) fn newline_in_value(&mut self) {
        let Some(editor) = self.editor.as_mut() else {
            return;
        };
        let value_index = usize::from(editor.name.is_some());
        if editor.value_locked {
            return;
        }
        if editor.active == value_index
            && let Some(field) = editor.active_field_mut()
        {
            field.insert_text("\n");
        }
    }

    pub(super) fn on_editor_key(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc => {
                self.editor = None;
                self.status = "edit cancelled".into();
                return None;
            },
            KeyCode::Char('v') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                match clipboard::read() {
                    Ok(text) => self.paste(&text),
                    Err(err) => self.status = format!("error: {err}"),
                }
                return None;
            },
            KeyCode::Char(' ')
                if self.editor.as_ref().is_some_and(|editor| editor.active + 1 == editor.field_count()) =>
            {
                if let Some(editor) = self.editor.as_mut() {
                    editor.enabled = !editor.enabled;
                }
                return None;
            },
            KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let field = self.editor.as_mut()?.active_field_mut()?;
                field.deselect();
                field.cursor = 0;
                return None;
            },
            KeyCode::Char('e') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let field = self.editor.as_mut()?.active_field_mut()?;
                field.deselect();
                field.cursor = field.value.len();
                return None;
            },
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.newline_in_value();
                return None;
            },
            KeyCode::Enter => return self.save_editor(),
            KeyCode::Down | KeyCode::Tab => {
                if let Some(editor) = self.editor.as_mut() {
                    editor.active = (editor.active + 1) % editor.field_count();
                }
                return None;
            },
            KeyCode::Up | KeyCode::BackTab => {
                if let Some(editor) = self.editor.as_mut() {
                    let len = editor.field_count();
                    editor.active = (editor.active + len - 1) % len;
                }
                return None;
            },
            _ => {},
        }
        let editor = self.editor.as_mut()?;
        if editor.value_locked && editor.active == usize::from(editor.name.is_some()) {
            return None;
        }
        edit_field(editor.active_field_mut()?, key.code);
        None
    }

    pub(super) fn save_editor(&mut self) -> Option<Action> {
        let editor = self.editor.as_ref()?.clone();
        let expires = if editor.field(2).dirty {
            match parse_expiry(&editor.field(2).text()) {
                Ok(expires) => expires,
                Err(err) => {
                    self.status = format!("expires: {err}");
                    return None;
                },
            }
        } else {
            editor.original_expires
        };
        let not_before = if editor.field(3).dirty {
            match parse_expiry(&editor.field(3).text()) {
                Ok(not_before) => not_before,
                Err(err) => {
                    self.status = format!("activates: {err}");
                    return None;
                },
            }
        } else {
            editor.original_not_before
        };
        if let (Some(expires), Some(not_before)) = (expires, not_before)
            && expires <= not_before
        {
            self.status = "expires: must be after activates".into();
            return None;
        }
        let content_type = {
            let text = editor.field(1).text();
            if text.trim().is_empty() { None } else { Some(text) }
        };
        let (name, value, tags, enabled, not_before, expected_updated) = if let Some(name_field) = &editor.name {
            let name = name_field.text().trim().to_string();
            if name.is_empty() {
                self.status = "new secret: name required".into();
                return None;
            }
            if self.secrets.iter().any(|secret| secret.name.eq_ignore_ascii_case(&name)) {
                self.status = format!("secret '{name}' already exists");
                return None;
            }
            let tags = match parse_tags(&editor.field(4).text()) {
                Ok(tags) => tags,
                Err(err) => {
                    self.status = format!("tags: {err}");
                    return None;
                },
            };
            (name, editor.field(0).text(), tags, editor.enabled, not_before, None)
        } else {
            let meta = self.secrets.iter().find(|secret| secret.name == editor.secret)?.clone();
            let tags = if editor.field(4).dirty {
                match parse_tags(&editor.field(4).text()) {
                    Ok(tags) => tags,
                    Err(err) => {
                        self.status = format!("tags: {err}");
                        return None;
                    },
                }
            } else {
                meta.tags
            };
            let expected_updated = Some(editor.original_updated);
            (editor.secret.clone(), editor.value_for_save(), tags, editor.enabled, not_before, expected_updated)
        };
        let patch = editor.value_locked;
        let secret = Secret { name, value, content_type, tags, enabled, expires, not_before };
        let profile = self.profile()?.clone();
        let vault = self.vault()?;
        Some(Action::SaveSecret { profile, vault, secret, updated: expected_updated, patch })
    }
}

pub(super) fn format_tags(tags: &BTreeMap<String, String>) -> String {
    tags.iter().map(|(key, value)| format!("{key}={value}")).collect::<Vec<_>>().join(", ")
}

/// Comma-separated `key=value` pairs for the single-line tag field.
/// shortcut: tag values containing commas cannot be edited here; replace with
/// per-tag rows if that becomes a real need.
pub(super) fn parse_tags(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut tags = BTreeMap::new();
    for pair in text.split(',').map(str::trim).filter(|pair| !pair.is_empty()) {
        let Some((key, value)) = pair.split_once('=') else {
            return Err(format!("'{pair}' is not key=value"));
        };
        let key = key.trim();
        if key.is_empty() {
            return Err("empty key".into());
        }
        tags.insert(key.to_string(), value.trim().to_string());
    }
    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::app::{Action, App, Msg, Pane};
    use azkv_core::{Overview, Profile, SecretMeta, Subscription, Tenant, Vault, parse_expiry};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::path::PathBuf;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
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
    fn editor_opens_prefilled_from_the_cached_value() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok("secret\nvalue".into()));
        app.pane = Pane::Secrets;
        assert!(app.on_key(key(KeyCode::Char('e'))).is_none());
        let editor = app.editor.as_ref().unwrap();
        assert_eq!(editor.secret, "alpha");
        assert_eq!(editor.fields[0].text(), "secret\nvalue");
        assert_eq!(editor.fields[0].display(), "secret⏎value");
        assert_eq!(editor.fields[1].text(), "text/plain");
        assert_eq!(editor.fields[2].text(), "");
        assert_eq!(editor.active, 0);
    }

    #[test]
    fn editing_an_uncached_value_fetches_it_first() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;
        let action = app.on_key(key(KeyCode::Char('e')));
        assert!(matches!(action, Some(Action::FetchValue { ref name, .. }) if name == "alpha"));
        assert_eq!(app.pending_edit.as_deref(), Some("alpha"));
        let url = app.vault().unwrap().url;
        assert!(app.handle(Msg::Value { url, name: "alpha".into(), result: Ok("fresh".into()) }).is_none());
        assert_eq!(app.editor.as_ref().unwrap().fields[0].text(), "fresh");
    }

    #[test]
    fn editor_types_tabs_and_saves() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok("secret".into()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));
        app.on_key(key(KeyCode::Char('!')));
        app.on_key(key(KeyCode::Tab));
        assert_eq!(app.editor.as_ref().unwrap().active, 1);
        app.on_key(key(KeyCode::Tab));
        for character in "2027-01-31".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        let Action::SaveSecret { vault, secret, .. } = action else {
            panic!("expected SaveSecret, got {action:?}");
        };
        assert_eq!(vault.name, "kv-a");
        assert_eq!(secret.value, "secret!");
        assert_eq!(secret.content_type.as_deref(), Some("text/plain"));
        assert_eq!(secret.expires.unwrap().day(), 31);
    }

    #[test]
    fn disabled_secret_opens_a_locked_editor_and_saves_attributes() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.secrets[0].enabled = false;
        app.pane = Pane::Secrets;

        assert!(app.on_key(key(KeyCode::Char('e'))).is_none());
        let editor = app.editor.as_ref().expect("editor opens without fetching the value");
        assert!(editor.value_locked);
        assert!(!editor.enabled);
        assert_eq!(editor.fields[0].text(), "");
        assert!(app.status.contains("enable it to edit the value"));

        // The locked value ignores typing and pasting.
        app.on_key(key(KeyCode::Char('x')));
        app.paste("secret");
        assert_eq!(app.editor.as_ref().unwrap().fields[0].text(), "");

        for _ in 0..5 {
            app.on_key(key(KeyCode::Tab));
        }
        app.on_key(key(KeyCode::Char(' ')));
        assert!(app.editor.as_ref().unwrap().enabled);

        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        let Action::SaveSecret { secret, patch, .. } = action else {
            panic!("expected SaveSecret, got {action:?}");
        };
        assert!(patch, "enabling uses an attributes-only save");
        assert!(secret.enabled);
    }

    #[test]
    fn attribute_only_save_drops_the_stale_value() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok("old".into()));
        let url = app.vault().unwrap().url;

        app.handle(Msg::Saved { url: url.clone(), name: "alpha".into(), value: None, result: Ok(meta("alpha")) });
        assert!(!app.values.contains_key("alpha"), "the value must be fetched again");
        assert!(app.secrets[0].enabled);

        let mut disabled = meta("alpha");
        disabled.enabled = false;
        app.handle(Msg::Saved { url: url.clone(), name: "alpha".into(), value: None, result: Ok(disabled) });
        assert!(matches!(app.values.get("alpha"), Some(Err(message)) if message.contains("disabled")));
    }

    #[test]
    fn editor_parses_an_activation_date() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok("secret".into()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));
        app.on_key(key(KeyCode::Tab));
        app.on_key(key(KeyCode::Tab));
        app.on_key(key(KeyCode::Tab));
        assert_eq!(app.editor.as_ref().unwrap().active, 3);
        for character in "20280201".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        assert_eq!(app.editor.as_ref().unwrap().fields[3].text(), "2028-02-01");

        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        let Action::SaveSecret { secret, .. } = action else {
            panic!("expected SaveSecret, got {action:?}");
        };
        assert_eq!(secret.not_before.unwrap().day(), 1);
    }

    #[test]
    fn editor_arrows_move_between_fields() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok("secret".into()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));

        app.on_key(key(KeyCode::Down));
        assert_eq!(app.editor.as_ref().unwrap().active, 1);
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.editor.as_ref().unwrap().active, 2);
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.editor.as_ref().unwrap().active, 3);
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.editor.as_ref().unwrap().active, 4);
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.editor.as_ref().unwrap().active, 5);
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.editor.as_ref().unwrap().active, 0);
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.editor.as_ref().unwrap().active, 5);
    }

    #[test]
    fn editor_preserves_untouched_lifecycle_timestamps() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        let expires = parse_expiry("2027-01-31T18:45:00Z").unwrap();
        let not_before = parse_expiry("2026-12-01T09:30:00Z").unwrap();
        let updated = parse_expiry("2026-10-01T12:00:00Z").unwrap();
        app.secrets[0].expires = expires;
        app.secrets[0].not_before = not_before;
        app.secrets[0].updated = updated;
        app.values.insert("alpha".into(), Ok("secret".into()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));
        app.secrets[0].updated = parse_expiry("2026-11-01T00:00:00Z").unwrap();

        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        let Action::SaveSecret { secret, updated: expected, .. } = action else {
            panic!("expected SaveSecret, got {action:?}");
        };
        assert_eq!(secret.expires, expires);
        assert_eq!(secret.not_before, not_before);
        assert_eq!(expected, Some(updated.map(|time| time.unix_timestamp_nanos())));
    }

    #[test]
    fn add_secret_collects_a_name_and_value() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;

        assert!(app.on_key(key(KeyCode::Char('a'))).is_none());
        let editor = app.editor.as_ref().unwrap();
        assert_eq!(editor.active, 0);
        assert_eq!(editor.name.as_ref().unwrap().text(), "");

        for character in "beta".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.editor.as_ref().unwrap().active, 1);
        for character in "hunter2".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.editor.as_ref().unwrap().active, 5);
        for character in "env=dev, team=kv".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }

        let action = app.on_key(key(KeyCode::Enter));
        let Some(action) = action else {
            panic!("expected SaveSecret, status: {}", app.status);
        };
        let Action::SaveSecret { secret, updated, .. } = action else {
            panic!("expected SaveSecret, got {action:?}");
        };
        assert_eq!(secret.name, "beta");
        assert_eq!(secret.value, "hunter2");
        assert!(secret.enabled);
        assert_eq!(secret.tags["env"], "dev");
        assert_eq!(secret.tags["team"], "kv");
        assert!(secret.expires.is_none());
        assert!(updated.is_none());
    }

    #[test]
    fn editor_toggles_enabled_and_saves_it() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok("secret".into()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));
        assert!(app.editor.as_ref().unwrap().enabled);

        app.on_key(key(KeyCode::Up));
        assert_eq!(app.editor.as_ref().unwrap().active, 5);
        app.on_key(key(KeyCode::Char(' ')));
        assert!(!app.editor.as_ref().unwrap().enabled);

        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        let Action::SaveSecret { secret, .. } = action else {
            panic!("expected SaveSecret, got {action:?}");
        };
        assert!(!secret.enabled);
    }

    #[test]
    fn editor_shows_and_saves_existing_tags() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.secrets[0].tags.insert("env".into(), "prod".into());
        app.secrets[0].tags.insert("team".into(), "kv".into());
        app.values.insert("alpha".into(), Ok("secret".into()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));

        assert_eq!(app.editor.as_ref().unwrap().field(4).text(), "env=prod, team=kv");
        app.on_key(key(KeyCode::Up));
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.editor.as_ref().unwrap().active, 4);
        for character in ", tier=gold".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }

        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        let Action::SaveSecret { secret, .. } = action else {
            panic!("expected SaveSecret, got {action:?}");
        };
        assert_eq!(secret.tags["env"], "prod");
        assert_eq!(secret.tags["team"], "kv");
        assert_eq!(secret.tags["tier"], "gold");
        assert_eq!(secret.value, "secret");
    }

    #[test]
    fn editor_rejects_malformed_tags() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok("secret".into()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));
        app.on_key(key(KeyCode::Up));
        app.on_key(key(KeyCode::Up));
        for character in "broken".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }

        assert!(app.on_key(key(KeyCode::Enter)).is_none());
        assert!(app.editor.is_some());
        assert!(app.status.starts_with("tags:"));
    }

    #[test]
    fn tags_parse_and_format_round_trip() {
        let tags = parse_tags("env=prod, team=kv").unwrap();
        assert_eq!(format_tags(&tags), "env=prod, team=kv");
        assert!(parse_tags("broken").is_err());
        assert!(parse_tags("=value").is_err());
        assert!(parse_tags("").unwrap().is_empty());
    }

    #[test]
    fn editor_pastes_a_multiline_value() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok(String::new()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));

        app.handle(Msg::Paste("line1\r\nline2\nline3".into()));
        assert_eq!(app.editor.as_ref().unwrap().field(0).text(), "line1\nline2\nline3");

        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        let Action::SaveSecret { secret, .. } = action else {
            panic!("expected SaveSecret, got {action:?}");
        };
        assert_eq!(secret.value, "line1\nline2\nline3");
    }

    #[test]
    fn pasting_inserts_at_the_cursor_in_one_pass() {
        let mut field = EditField::new("value", "ab");
        field.cursor = 1;
        let text = "x".repeat(10_000);
        field.insert_text(&text);
        assert_eq!(field.text(), format!("a{text}b"));
        assert_eq!(field.cursor(), 10_001);
        assert!(field.dirty);
    }

    #[test]
    fn editor_inserts_a_newline_with_shift_enter() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok(String::new()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));

        app.on_key(key(KeyCode::Char('a')));
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT));
        app.on_key(key(KeyCode::Char('b')));
        assert_eq!(app.editor.as_ref().unwrap().field(0).text(), "a\nb");
    }

    #[test]
    fn new_secret_pastes_a_multiline_certificate_into_value() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('a')));
        for character in "cert".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        app.on_key(key(KeyCode::Tab));
        assert_eq!(app.editor.as_ref().unwrap().active, 1);

        let certificate = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        app.handle(Msg::Paste(certificate.into()));
        assert_eq!(app.editor.as_ref().unwrap().field(0).text(), certificate);
    }

    #[test]
    fn new_secret_moves_a_multiline_paste_from_name_to_value() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('a')));
        assert_eq!(app.editor.as_ref().unwrap().active, 0);

        let certificate = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        app.handle(Msg::Paste(certificate.into()));
        let editor = app.editor.as_ref().unwrap();
        assert_eq!(editor.active, 1);
        assert_eq!(editor.name.as_ref().unwrap().text(), "");
        assert_eq!(editor.field(0).text(), certificate);
    }

    #[test]
    fn ctrl_a_and_ctrl_e_move_to_the_start_and_end() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok("line one\nline two".into()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));
        assert_eq!(app.editor.as_ref().unwrap().field(0).cursor(), 17);
        let hints = app.show_hints;

        app.on_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL));
        assert_eq!(app.editor.as_ref().unwrap().field(0).cursor(), 0);
        app.on_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL));
        assert_eq!(app.editor.as_ref().unwrap().field(0).cursor(), 17);
        assert_eq!(app.show_hints, hints);
    }

    #[test]
    fn multiline_values_show_newline_markers() {
        assert_eq!(EditField::new("value", "a\nb").display(), "a⏎b");
    }

    #[test]
    fn add_secret_refuses_an_empty_or_existing_name() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;

        app.on_key(key(KeyCode::Char('a')));
        assert!(app.on_key(key(KeyCode::Enter)).is_none());
        assert!(app.editor.is_some());
        assert!(app.status.contains("name required"));

        for character in "alpha".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        assert!(app.on_key(key(KeyCode::Enter)).is_none());
        assert!(app.editor.is_some());
        assert!(app.status.contains("already exists"));
    }

    #[test]
    fn created_secret_is_added_and_selected() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('a')));
        let url = app.vault().unwrap().url;

        app.handle(Msg::Saved { url, name: "beta".into(), value: Some("v".into()), result: Ok(meta("beta")) });
        assert!(app.editor.is_none());
        assert_eq!(app.secrets.len(), 2);
        assert_eq!(app.secrets[1].name, "beta");
        assert_eq!(app.selected_secret().unwrap().name, "beta");
        assert_eq!(app.values["beta"], Ok("v".into()));
        assert!(app.status.contains("created"));
    }

    #[test]
    fn editor_keeps_an_untouched_multiline_value() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok("line1\nline2".into()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));
        app.on_key(key(KeyCode::Tab));
        app.on_key(key(KeyCode::Char('!')));
        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        let Action::SaveSecret { secret, .. } = action else {
            panic!("expected SaveSecret");
        };
        assert_eq!(secret.value, "line1\nline2");
        assert_eq!(secret.content_type.as_deref(), Some("text/plain!"));
    }

    #[test]
    fn editor_rejects_an_invalid_expiry_and_stays_open() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok("secret".into()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));
        app.on_key(key(KeyCode::Tab));
        app.on_key(key(KeyCode::Tab));
        for character in "2026".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        assert!(app.on_key(key(KeyCode::Enter)).is_none());
        assert!(app.editor.is_some());
        assert!(app.status.starts_with("expires:"));
    }

    #[test]
    fn editor_rejects_expiry_before_activation() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok("secret".into()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));
        app.on_key(key(KeyCode::Tab));
        app.on_key(key(KeyCode::Tab));
        for character in "20270101".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        app.on_key(key(KeyCode::Tab));
        for character in "20270501".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }

        assert!(app.on_key(key(KeyCode::Enter)).is_none());
        assert!(app.editor.is_some(), "the editor stays open");
        assert_eq!(app.status, "expires: must be after activates");
    }

    #[test]
    fn date_fields_insert_dashes_while_typing() {
        let mut field = EditField::date("expires", "");
        assert_eq!(field.placeholder(), Some("____-__-__"));
        for character in "20261031".chars() {
            field.insert(character);
        }
        assert_eq!(field.text(), "2026-10-31");
        field.backspace();
        assert_eq!(field.text(), "2026-10-3");
        field.insert('1');
        assert_eq!(field.text(), "2026-10-31");
        field.insert('-');
        assert_eq!(field.text(), "2026-10-31", "dashes are inserted, not typed");
        assert_eq!(field.placeholder(), None);
    }

    #[test]
    fn date_fields_format_pasted_dates() {
        let mut field = EditField::date("activates", "");
        field.insert_text("2026-12-01");
        assert_eq!(field.text(), "2026-12-01");
    }

    #[test]
    fn text_fields_have_no_date_mask() {
        assert_eq!(EditField::new("type", "").placeholder(), None);
    }

    #[test]
    fn escape_cancels_editing_and_restores_normal_keys() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok("secret".into()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));
        assert!(app.on_key(key(KeyCode::Char('q'))).is_none());
        assert_eq!(app.editor.as_ref().unwrap().fields[0].text(), "secretq");
        app.on_key(key(KeyCode::Esc));
        assert!(app.editor.is_none());
        assert_eq!(app.on_key(key(KeyCode::Char('q'))), Some(Action::Quit));
    }

    #[test]
    fn successful_save_updates_only_the_edited_row() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha", "beta"]);
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));
        let mut saved = meta("alpha");
        saved.content_type = Some("application/json".into());
        let url = app.vault().unwrap().url;
        let action = app.handle(Msg::Saved { url, name: "alpha".into(), value: Some("new".into()), result: Ok(saved) });
        assert!(action.is_none(), "saving must not reload the vault");
        assert!(app.editor.is_none());
        assert_eq!(app.secrets.len(), 2);
        assert_eq!(app.secrets[0].content_type.as_deref(), Some("application/json"));
        assert_eq!(app.secrets[1].name, "beta");
        assert_eq!(app.values["alpha"], Ok("new".into()));
    }

    #[test]
    fn failed_save_keeps_the_editor_and_reports_it() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok("secret".into()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));
        assert!(app.editor.is_some());
        let url = app.vault().unwrap().url;
        app.handle(Msg::Saved { url, name: "alpha".into(), value: Some("x".into()), result: Err("boom".into()) });
        assert!(app.editor.is_some());
        assert!(app.status.contains("boom"));
    }

    #[test]
    fn reloading_after_save_keeps_the_saved_secret_selected() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha", "beta"]);
        app.pending_select = Some("beta".into());
        let url = app.vault().unwrap().url;
        let action = app.handle(Msg::Secrets { url, result: Ok(vec![meta("alpha"), meta("beta")]) });
        assert!(matches!(action, Some(Action::FetchValue { ref name, .. }) if name == "beta"));
        assert_eq!(app.secret_state.selected(), Some(1));
    }
}
