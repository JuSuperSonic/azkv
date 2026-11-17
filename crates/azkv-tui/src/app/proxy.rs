use super::*;
use ratatui::crossterm::event::{KeyCode, KeyEvent};

pub struct ProxyEditor {
    pub enabled: bool,
    /// 0 = http, 1 = socks5h (ssh -D).
    pub scheme: usize,
    pub host: EditField,
    pub port: EditField,
    /// 0 enabled, 1 scheme, 2 host, 3 port.
    pub active: usize,
    /// Full URL the window was opened with; reused while the split fields are
    /// untouched so credentials/paths survive.
    hidden: String,
    original_scheme: usize,
}

impl ProxyEditor {
    /// Move focus; text fields always resume at the end of their value.
    pub(super) fn focus(&mut self, active: usize) {
        self.active = active;
        match active {
            2 => self.host.focus(),
            3 => self.port.focus(),
            _ => {},
        }
    }
}

impl App {
    pub(super) fn open_proxy_editor(&mut self) {
        let current =
            self.proxy.as_ref().or(self.last_proxy.as_ref()).map(|proxy| proxy.url().to_string()).unwrap_or_default();
        let (scheme, host, port) = split_proxy(&current);
        self.proxy_editor = Some(ProxyEditor {
            enabled: self.proxy.is_some(),
            scheme,
            host: EditField::new("address", &host),
            port: EditField::new("port", &port),
            active: 0,
            hidden: current,
            original_scheme: scheme,
        });
        self.status = "proxy: space toggle, left/right scheme, tab/up/down fields".into();
    }

    pub(super) fn on_proxy_key(&mut self, key: KeyEvent) -> Option<Action> {
        // The proxy check runs in the background; ignore edits until it answers.
        if self.proxy_checking {
            return None;
        }
        match key.code {
            KeyCode::Esc => {
                self.proxy_editor = None;
                self.status = "proxy unchanged".into();
                return None;
            },
            KeyCode::Enter => return self.apply_proxy(),
            KeyCode::Tab | KeyCode::Down => {
                if let Some(editor) = self.proxy_editor.as_mut() {
                    editor.focus((editor.active + 1) % 4);
                }
                return None;
            },
            KeyCode::BackTab | KeyCode::Up => {
                if let Some(editor) = self.proxy_editor.as_mut() {
                    editor.focus((editor.active + 3) % 4);
                }
                return None;
            },
            _ => {},
        }
        let editor = self.proxy_editor.as_mut()?;
        match editor.active {
            0 => {
                if key.code == KeyCode::Char(' ') {
                    editor.enabled = !editor.enabled;
                }
            },
            1 => {
                if matches!(key.code, KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')) {
                    editor.scheme = 1 - editor.scheme;
                }
            },
            2 => edit_field(&mut editor.host, key.code),
            3 => edit_field(&mut editor.port, key.code),
            _ => {},
        }
        None
    }

    pub(super) fn apply_proxy(&mut self) -> Option<Action> {
        let editor = self.proxy_editor.as_ref()?;
        if !editor.enabled {
            self.set_proxy(None);
            self.proxy_editor = None;
            self.status = "proxy disabled".into();
            return self.reload_after_proxy();
        }
        let untouched = !editor.hidden.is_empty()
            && !editor.host.dirty
            && !editor.port.dirty
            && editor.scheme == editor.original_scheme;
        let url = if untouched {
            editor.hidden.clone()
        } else {
            let Some(url) = proxy_url(editor.scheme, &editor.host.text(), &editor.port.text()) else {
                self.status = "proxy: address required".into();
                return None;
            };
            url
        };
        let no_proxy = self.last_proxy.as_ref().and_then(|proxy| proxy.no_proxy()).map(str::to_string);
        match ProxySettings::new(Some(&url), no_proxy.as_deref()) {
            Ok(Some(proxy)) => {
                self.proxy_checking = true;
                self.status = format!("checking proxy {}...", proxy.display_url());
                Some(Action::CheckProxy { proxy })
            },
            Ok(None) => {
                self.status = "proxy: address required".into();
                None
            },
            Err(err) => {
                self.status = format!("proxy: {err}");
                None
            },
        }
    }

    pub(super) fn reload_after_proxy(&mut self) -> Option<Action> {
        self.values.clear();
        self.info_cache.clear();
        if self.vault().is_some() { self.open_vault() } else { self.load_vaults() }
    }
}

/// Splits `scheme://host:port` into the editor fields. Empty input defaults to
/// the usual local SOCKS tunnel (`ssh -D 1080`).
pub(super) fn split_proxy(url: &str) -> (usize, String, String) {
    let url = url.trim();
    if url.is_empty() {
        return (1, "localhost".into(), "1080".into());
    }
    let scheme = usize::from(!url.starts_with("http"));
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    match rest.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            (scheme, host.to_string(), port.to_string())
        },
        _ => (scheme, rest.to_string(), String::new()),
    }
}

/// `host` may be a bare host or a full URL; `port` is appended only when the
/// URL does not already carry one.
pub(super) fn proxy_url(scheme: usize, host: &str, port: &str) -> Option<String> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    let base = if host.contains("://") {
        host.to_string()
    } else {
        format!("{}://{host}", if scheme == 1 { "socks5h" } else { "http" })
    };
    let port = port.trim();
    let has_port =
        base.rsplit_once(':').is_some_and(|(_, tail)| !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()));
    Some(if port.is_empty() || has_port { base } else { format!("{base}:{port}") })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::app::{Action, App, Msg, Pane};
    use azkv_core::{Overview, Profile, Subscription, Tenant, Vault};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::path::PathBuf;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
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

    /// Finishes the connectivity check that Enter starts, as the main loop would.
    fn confirm_proxy(app: &mut App) -> Option<Action> {
        let action = app.on_key(key(KeyCode::Enter));
        let Some(Action::CheckProxy { proxy }) = action else {
            panic!("expected CheckProxy, got {action:?}");
        };
        app.handle(Msg::ProxyChecked { proxy, result: Ok(()) })
    }

    fn vault(name: &str, subscription: &Subscription) -> Vault {
        Vault::from_name(name, subscription, Some("rg".into()))
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
    fn proxy_modal_enables_an_address_and_port() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        app.pane = Pane::Vaults;
        app.on_key(key(KeyCode::Char('P')));
        let editor = app.proxy_editor.as_ref().unwrap();
        assert!(!editor.enabled);
        assert_eq!(editor.active, 0);
        assert_eq!(editor.scheme, 1);
        assert_eq!(editor.host.text(), "localhost");
        assert_eq!(editor.port.text(), "1080");

        app.on_key(key(KeyCode::Char(' ')));
        assert!(app.proxy_editor.as_ref().unwrap().enabled);
        app.on_key(key(KeyCode::Tab));
        assert_eq!(app.proxy_editor.as_ref().unwrap().scheme, 1);
        app.on_key(key(KeyCode::Left));
        assert_eq!(app.proxy_editor.as_ref().unwrap().scheme, 0);
        app.on_key(key(KeyCode::Right));
        assert_eq!(app.proxy_editor.as_ref().unwrap().scheme, 1);
        app.on_key(key(KeyCode::Tab));
        for character in "proxy.corp".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        app.on_key(key(KeyCode::Tab));
        for character in "3128".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        let Action::CheckProxy { proxy } = action else {
            panic!("expected CheckProxy, got {action:?}");
        };
        assert!(app.proxy_checking);
        assert_eq!(proxy.url(), "socks5h://proxy.corp:3128");
        let action = app.handle(Msg::ProxyChecked { proxy, result: Ok(()) }).unwrap();
        assert!(matches!(action, Action::LoadSecrets { .. }));
        assert!(app.proxy_editor.is_none());
        assert_eq!(app.proxy.as_ref().unwrap().url(), "socks5h://proxy.corp:3128");
        assert!(app.status.contains("reachable"));
    }

    #[test]
    fn proxy_modal_typing_replaces_the_selected_value() {
        let mut app = loaded_app();
        app.proxy = ProxySettings::new(Some("socks5h://localhost:1911"), None).unwrap();
        app.on_key(key(KeyCode::Char('P')));
        app.on_key(key(KeyCode::Tab)); // scheme
        app.on_key(key(KeyCode::Tab)); // address
        app.on_key(key(KeyCode::Tab)); // port
        app.on_key(key(KeyCode::Char('9')));
        let editor = app.proxy_editor.as_ref().unwrap();
        assert_eq!(editor.active, 3);
        assert_eq!(editor.host.text(), "localhost");
        assert_eq!(editor.port.text(), "9");
    }

    #[test]
    fn proxy_modal_splits_an_existing_url_and_reuses_it_untouched() {
        let mut app = loaded_app();
        app.proxy = ProxySettings::new(Some("socks5h://localhost:1911"), None).unwrap();
        app.on_key(key(KeyCode::Char('P')));
        let editor = app.proxy_editor.as_ref().unwrap();
        assert_eq!(editor.scheme, 1);
        assert_eq!(editor.host.text(), "localhost");
        assert_eq!(editor.port.text(), "1911");
        // Apply without touching the fields: exact original URL, hidden field wins.
        confirm_proxy(&mut app);
        assert_eq!(app.proxy.as_ref().unwrap().url(), "socks5h://localhost:1911");
    }

    #[test]
    fn split_proxy_handles_schemes_ports_and_defaults() {
        assert_eq!(split_proxy(""), (1, "localhost".into(), "1080".into()));
        assert_eq!(split_proxy("socks5h://localhost:1911"), (1, "localhost".into(), "1911".into()));
        assert_eq!(split_proxy("http://proxy.corp:3128"), (0, "proxy.corp".into(), "3128".into()));
        assert_eq!(split_proxy("https://proxy.corp"), (0, "proxy.corp".into(), String::new()));
        assert_eq!(split_proxy("[::1]:1911"), (1, "[::1]".into(), "1911".into()));
    }

    #[test]
    fn proxy_modal_can_disable_the_current_proxy() {
        let mut app = loaded_app();
        app.proxy = ProxySettings::new(Some("http://proxy.corp:3128"), None).unwrap();
        app.on_key(key(KeyCode::Char('P')));
        let editor = app.proxy_editor.as_ref().unwrap();
        assert!(editor.enabled);
        assert_eq!(editor.host.text(), "proxy.corp");
        assert_eq!(editor.port.text(), "3128");
        app.on_key(key(KeyCode::Char(' ')));
        app.on_key(key(KeyCode::Enter));
        assert!(app.proxy.is_none());
        assert!(app.proxy_editor.is_none());
        assert!(app.status.contains("disabled"));
    }

    #[test]
    fn proxy_config_is_kept_while_disabled() {
        let mut app = loaded_app();
        app.on_key(key(KeyCode::Char('P')));
        app.on_key(key(KeyCode::Char(' ')));
        app.on_key(key(KeyCode::Tab));
        app.on_key(key(KeyCode::Tab));
        for character in "proxy.corp".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        app.on_key(key(KeyCode::Tab));
        for character in "3128".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
        confirm_proxy(&mut app);
        assert_eq!(app.proxy.as_ref().unwrap().url(), "socks5h://proxy.corp:3128");

        app.on_key(key(KeyCode::Char('P')));
        app.on_key(key(KeyCode::Char(' ')));
        app.on_key(key(KeyCode::Enter));
        assert!(app.proxy.is_none());

        app.on_key(key(KeyCode::Char('P')));
        let editor = app.proxy_editor.as_ref().unwrap();
        assert!(!editor.enabled);
        assert_eq!(editor.host.text(), "proxy.corp");
        assert_eq!(editor.port.text(), "3128");
        app.on_key(key(KeyCode::Char(' ')));
        confirm_proxy(&mut app);
        assert_eq!(app.proxy.as_ref().unwrap().url(), "socks5h://proxy.corp:3128");
    }

    #[test]
    fn remembered_proxy_keeps_its_no_proxy_list() {
        let mut app = loaded_app();
        app.set_proxy(ProxySettings::new(Some("http://proxy.corp:3128"), Some("localhost,127.0.0.1")).unwrap());
        app.on_key(key(KeyCode::Char('P')));
        app.on_key(key(KeyCode::Char(' ')));
        app.on_key(key(KeyCode::Enter));
        assert!(app.proxy.is_none());

        app.on_key(key(KeyCode::Char('P')));
        app.on_key(key(KeyCode::Char(' ')));
        confirm_proxy(&mut app);
        assert_eq!(app.proxy.as_ref().unwrap().url(), "http://proxy.corp:3128");
        assert_eq!(app.proxy.as_ref().unwrap().no_proxy(), Some("localhost,127.0.0.1"));
    }

    #[test]
    fn proxy_check_failure_keeps_the_editor_open() {
        let mut app = loaded_app();
        app.on_key(key(KeyCode::Char('P')));
        app.on_key(key(KeyCode::Char(' ')));
        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        let Action::CheckProxy { proxy } = action else {
            panic!("expected CheckProxy, got {action:?}");
        };
        // While the check runs, keys cannot close or edit the modal.
        assert!(app.on_key(key(KeyCode::Esc)).is_none());
        assert!(app.proxy_editor.is_some());

        app.handle(Msg::ProxyChecked { proxy, result: Err("cannot reach the endpoint".into()) });
        assert!(app.proxy_editor.is_some());
        assert!(app.proxy.is_none());
        assert!(!app.proxy_checking);
        assert!(app.status.starts_with("proxy check failed"));
    }

    #[test]
    fn proxy_fields_select_their_value_on_focus() {
        let mut app = loaded_app();
        app.on_key(key(KeyCode::Char('P')));
        app.on_key(key(KeyCode::Tab)); // scheme
        app.on_key(key(KeyCode::Tab)); // address
        let editor = app.proxy_editor.as_ref().unwrap();
        assert!(editor.host.is_selected());
        assert_eq!(editor.host.cursor(), "localhost".len());

        app.on_key(key(KeyCode::Char('x')));
        let editor = app.proxy_editor.as_ref().unwrap();
        assert_eq!(editor.host.text(), "x");
        assert_eq!(editor.host.cursor(), 1);
        assert!(!editor.host.is_selected());

        app.on_key(key(KeyCode::Tab)); // port, selected
        assert!(app.proxy_editor.as_ref().unwrap().port.is_selected());
        app.on_key(key(KeyCode::Char('9')));
        assert_eq!(app.proxy_editor.as_ref().unwrap().port.text(), "9");

        app.on_key(key(KeyCode::BackTab)); // address, selected again
        assert!(app.proxy_editor.as_ref().unwrap().host.is_selected());
        app.on_key(key(KeyCode::Left)); // arrows drop the selection
        let editor = app.proxy_editor.as_ref().unwrap();
        assert!(!editor.host.is_selected());
        assert_eq!(editor.host.cursor(), 0);
    }

    #[test]
    fn proxy_up_down_moves_focus() {
        let mut app = loaded_app();
        app.on_key(key(KeyCode::Char('P')));
        assert_eq!(app.proxy_editor.as_ref().unwrap().active, 0);

        app.on_key(key(KeyCode::Down));
        assert_eq!(app.proxy_editor.as_ref().unwrap().active, 1);
        app.on_key(key(KeyCode::Down));
        let editor = app.proxy_editor.as_ref().unwrap();
        assert_eq!(editor.active, 2);
        assert!(editor.host.is_selected());

        app.on_key(key(KeyCode::Up));
        assert_eq!(app.proxy_editor.as_ref().unwrap().active, 1);
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.proxy_editor.as_ref().unwrap().active, 0);
        app.on_key(key(KeyCode::Up)); // wraps to the port
        assert_eq!(app.proxy_editor.as_ref().unwrap().active, 3);
    }

    #[test]
    fn proxy_modal_requires_an_address_when_enabled() {
        let mut app = loaded_app();
        app.on_key(key(KeyCode::Char('P')));
        app.on_key(key(KeyCode::Char(' ')));
        app.on_key(key(KeyCode::Tab)); // scheme
        app.on_key(key(KeyCode::Tab)); // address
        app.on_key(key(KeyCode::Backspace)); // clears the selected value
        assert!(app.on_key(key(KeyCode::Enter)).is_none());
        assert!(app.proxy_editor.is_some());
        assert!(app.status.contains("address required"));
    }

    #[test]
    fn proxy_modal_escape_keeps_the_previous_proxy() {
        let mut app = loaded_app();
        app.proxy = ProxySettings::new(Some("http://proxy.corp:3128"), None).unwrap();
        app.on_key(key(KeyCode::Char('P')));
        app.on_key(key(KeyCode::Char('x')));
        app.on_key(key(KeyCode::Esc));
        assert!(app.proxy_editor.is_none());
        assert_eq!(app.proxy.as_ref().unwrap().url(), "http://proxy.corp:3128");
    }

    #[test]
    fn proxy_urls_keep_or_add_the_port() {
        assert_eq!(proxy_url(0, "proxy.corp", "3128").unwrap(), "http://proxy.corp:3128");
        assert_eq!(proxy_url(1, "localhost", "1911").unwrap(), "socks5h://localhost:1911");
        assert_eq!(proxy_url(0, "proxy.corp", "").unwrap(), "http://proxy.corp");
        assert_eq!(proxy_url(0, "https://proxy.corp:8443", "9999").unwrap(), "https://proxy.corp:8443");
        assert_eq!(proxy_url(0, "   ", "3128"), None);
    }
}
