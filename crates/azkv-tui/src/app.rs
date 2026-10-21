use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use azkv_core::{
    Overview, Profile, ProxySettings, Secret, SecretMeta, Subscription, Tenant, Vault, VaultInfo, clipboard, fmt_date,
    parse_expiry,
};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::{ListState, TableState};
use time::OffsetDateTime;

const INFO_TTL: Duration = Duration::from_secs(180);

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Quit,
    LoadOverview { profile: Profile },
    LoadVaults { profile: Profile, subscription: Subscription },
    LoadSecrets { profile: Profile, subscription: Subscription, vault: Vault },
    FetchValue { profile: Profile, subscription: Subscription, vault: Vault, name: String },
    RefreshSecret { profile: Profile, subscription: Subscription, vault: Vault, name: String },
    Copy(String),
    // `None` creates (checking the remote name); `Some(updated)` edits and
    // refuses if the remote secret changed since it was opened.
    SaveSecret { profile: Profile, vault: Vault, secret: Secret, updated: Option<Option<i128>> },
    LoadCopyVaults { profile: Profile, subscription: Subscription },
    CopyToVault { profile: Profile, dest: Vault, secret: Secret, overwrite: bool },
    CopyVault { profile: Profile, source: Vault, dest: Vault },
    LoadVaultInfo { profile: Profile, vault: Vault },
    DuplicateSecret { profile: Profile, vault: Vault, source: String, name: String },
    DeleteSecret { profile: Profile, vault: Vault, name: String },
}

#[derive(Debug)]
pub enum Msg {
    Key(KeyEvent),
    Paste(String),
    Overview { dir: PathBuf, result: Result<Overview, String> },
    Vaults { dir: PathBuf, subscription_id: String, result: Result<Vec<Vault>, String> },
    Secrets { url: String, result: Result<Vec<SecretMeta>, String> },
    Value { url: String, name: String, result: Result<String, String> },
    Refreshed { url: String, name: String, result: Result<(SecretMeta, String), String> },
    Copied(Result<(), String>),
    Resize,
    Saved { url: String, name: String, value: String, result: Result<SecretMeta, String> },
    CopyVaults { subscription_id: String, result: Result<Vec<Vault>, String> },
    CopyToExists { dest: Vault, secret: Secret },
    CopiedTo { dest: String, name: String, result: Result<(), String> },
    CopiedVault { source: String, dest: String, result: Result<azkv_core::copy::CopyReport, String> },
    VaultInfo { url: String, result: Result<VaultInfo, String> },
    Duplicated { url: String, name: String, result: Result<SecretMeta, String> },
    Deleted { url: String, name: String, result: Result<(), String> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pane {
    Vaults,
    Secrets,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PickerKind {
    Profiles,
    Tenants,
    Subscriptions,
    CopySubscription,
    CopyVault,
}

#[derive(Debug)]
pub struct Picker {
    pub kind: PickerKind,
    pub title: &'static str,
    pub items: Vec<String>,
    /// `None` only for the "All tenants" entry.
    pub values: Vec<Option<usize>>,
    pub selected: usize,
}

#[derive(Clone)]
pub struct EditField {
    pub label: &'static str,
    value: Vec<char>,
    cursor: usize,
    dirty: bool,
    /// Set when focus lands on the field; the first edit replaces the value.
    selected: bool,
}

impl EditField {
    fn new(label: &'static str, text: &str) -> Self {
        let value: Vec<char> = text.chars().collect();
        Self { label, cursor: value.len(), value, dirty: false, selected: false }
    }

    pub fn display(&self) -> String {
        self.value
            .iter()
            .map(|character| match character {
                '\n' => '⏎',
                '\r' => ' ',
                other => *other,
            })
            .collect()
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn is_selected(&self) -> bool {
        self.selected
    }

    fn focus(&mut self) {
        self.cursor = self.value.len();
        self.selected = true;
    }

    fn deselect(&mut self) {
        self.selected = false;
    }

    fn text(&self) -> String {
        self.value.iter().collect()
    }

    fn insert(&mut self, character: char) {
        if self.selected {
            self.replace(character);
            return;
        }
        self.value.insert(self.cursor, character);
        self.cursor += 1;
        self.dirty = true;
    }

    /// Inserts pasted text as-is, replacing a selected value first.
    fn insert_text(&mut self, text: &str) {
        if self.selected {
            self.value.clear();
            self.cursor = 0;
            self.selected = false;
        }
        let count = text.chars().count();
        self.value.splice(self.cursor..self.cursor, text.chars());
        self.cursor += count;
        self.dirty = true;
    }

    fn replace(&mut self, character: char) {
        self.value.clear();
        self.value.push(character);
        self.cursor = 1;
        self.selected = false;
        self.dirty = true;
    }

    fn backspace(&mut self) {
        if self.selected {
            self.value.clear();
            self.cursor = 0;
            self.selected = false;
            self.dirty = true;
        } else if self.cursor > 0 {
            self.cursor -= 1;
            self.value.remove(self.cursor);
            self.dirty = true;
        }
    }

    fn delete(&mut self) {
        if self.selected {
            self.value.clear();
            self.cursor = 0;
            self.selected = false;
            self.dirty = true;
        } else if self.cursor < self.value.len() {
            self.value.remove(self.cursor);
            self.dirty = true;
        }
    }
}

#[derive(Clone)]
pub struct Editor {
    pub secret: String,
    /// Set only when creating a secret; the name is then the first field.
    pub name: Option<EditField>,
    pub fields: Vec<EditField>,
    /// Checkbox after the text fields; `space` toggles it.
    pub enabled: bool,
    pub active: usize,
    original_value: String,
    original_expires: Option<OffsetDateTime>,
    original_not_before: Option<OffsetDateTime>,
    original_updated: Option<i128>,
}

impl Editor {
    fn field(&self, index: usize) -> &EditField {
        &self.fields[index]
    }

    fn field_count(&self) -> usize {
        self.fields.len() + usize::from(self.name.is_some()) + 1
    }

    fn active_field_mut(&mut self) -> Option<&mut EditField> {
        let offset = usize::from(self.name.is_some());
        if self.name.is_some() && self.active == 0 {
            self.name.as_mut()
        } else {
            self.fields.get_mut(self.active.checked_sub(offset)?)
        }
    }

    /// Untouched values keep their original text, including newlines.
    fn value_for_save(&self) -> String {
        if self.fields[0].dirty { self.fields[0].text() } else { self.original_value.clone() }
    }
}

pub struct Duplicate {
    pub source: String,
    pub name: EditField,
}

pub struct DeleteConfirm {
    pub name: String,
    /// `false` is the focused default, so Enter alone does not delete.
    pub yes: bool,
}

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
    fn focus(&mut self, active: usize) {
        self.active = active;
        match active {
            2 => self.host.focus(),
            3 => self.port.focus(),
            _ => {},
        }
    }
}

pub struct App {
    pub profiles: Vec<Profile>,
    pub profile_idx: usize,
    pub tenants: Vec<Tenant>,
    pub tenant_idx: Option<usize>,
    pub subscriptions: Vec<Subscription>,
    pub sub_idx: usize,
    pub vaults: Vec<Vault>,
    pub vault_state: ListState,
    pub secrets: Vec<SecretMeta>,
    pub secret_state: TableState,
    pub pane: Pane,
    pub vault_filter: String,
    pub secret_filter: String,
    pub filtering: bool,
    pub revealed: bool,
    pub values: HashMap<String, Result<String, String>>,
    pub pending_copy: Option<String>,
    pub picker: Option<Picker>,
    pub editor: Option<Editor>,
    pub pending_edit: Option<String>,
    pub copy_sub: Option<Subscription>,
    pub copy_vaults: Vec<Vault>,
    pub copy_source: Option<Vault>,
    copy_refreshing: bool,
    pub pending_copy_to: Option<(String, Vault)>,
    pub confirm_overwrite: Option<(Vault, Secret)>,
    pub pending_select: Option<String>,
    pub duplicate: Option<Duplicate>,
    pub confirm_delete: Option<DeleteConfirm>,
    pub proxy: Option<ProxySettings>,
    last_proxy: Option<ProxySettings>,
    pub proxy_editor: Option<ProxyEditor>,
    pub info_url: Option<String>,
    pub info_moved: bool,
    pub info: Option<Result<VaultInfo, String>>,
    info_cache: HashMap<String, (Instant, Result<VaultInfo, String>)>,
    pub show_hints: bool,
    pub loading: bool,
    pub status: String,
}

impl App {
    pub fn new(profiles: Vec<Profile>, profile_idx: usize) -> Self {
        Self {
            profiles,
            profile_idx,
            tenants: Vec::new(),
            tenant_idx: None,
            subscriptions: Vec::new(),
            sub_idx: 0,
            vaults: Vec::new(),
            vault_state: ListState::default(),
            secrets: Vec::new(),
            secret_state: TableState::default(),
            pane: Pane::Vaults,
            vault_filter: String::new(),
            secret_filter: String::new(),
            filtering: false,
            revealed: false,
            values: HashMap::new(),
            pending_copy: None,
            picker: None,
            editor: None,
            pending_edit: None,
            copy_sub: None,
            copy_vaults: Vec::new(),
            copy_source: None,
            copy_refreshing: false,
            pending_copy_to: None,
            confirm_overwrite: None,
            pending_select: None,
            duplicate: None,
            confirm_delete: None,
            proxy: None,
            last_proxy: None,
            proxy_editor: None,
            info_url: None,
            info_moved: false,
            info: None,
            info_cache: HashMap::new(),
            show_hints: true,
            loading: false,
            status: "press p to switch Azure CLI profile".into(),
        }
    }

    pub fn proxy(&self) -> Option<&ProxySettings> {
        self.proxy.as_ref()
    }

    /// Set the active proxy while remembering it for the in-session editor.
    pub fn set_proxy(&mut self, proxy: Option<ProxySettings>) {
        if let Some(proxy) = &proxy {
            self.last_proxy = Some(proxy.clone());
        }
        self.proxy = proxy;
    }

    pub fn start(&mut self) -> Action {
        self.loading = true;
        Action::LoadOverview { profile: self.profile().cloned().expect("at least one profile") }
    }

    pub fn profile(&self) -> Option<&Profile> {
        self.profiles.get(self.profile_idx)
    }

    pub fn subscription(&self) -> Option<Subscription> {
        let index = *self.filtered_subscriptions().get(self.sub_idx)?;
        self.subscriptions.get(index).cloned()
    }

    pub fn vault(&self) -> Option<Vault> {
        let index = *self.visible_vaults().get(self.vault_state.selected()?)?;
        self.vaults.get(index).cloned()
    }

    pub fn selected_secret(&self) -> Option<&SecretMeta> {
        let index = *self.visible_secrets().get(self.secret_state.selected()?)?;
        self.secrets.get(index)
    }

    pub fn filtered_subscriptions(&self) -> Vec<usize> {
        let tenant = self.tenant_idx.and_then(|index| self.tenants.get(index)).map(|tenant| tenant.id.clone());
        self.subscriptions
            .iter()
            .enumerate()
            .filter(|(_, sub)| tenant.as_ref().is_none_or(|tenant| &sub.tenant_id == tenant))
            .map(|(index, _)| index)
            .collect()
    }

    pub fn visible_vaults(&self) -> Vec<usize> {
        self.vaults
            .iter()
            .enumerate()
            .filter(|(_, vault)| matches(&vault.name, &self.vault_filter))
            .map(|(index, _)| index)
            .collect()
    }

    pub fn visible_secrets(&self) -> Vec<usize> {
        self.secrets
            .iter()
            .enumerate()
            .filter(|(_, secret)| matches(&secret.name, &self.secret_filter))
            .map(|(index, _)| index)
            .collect()
    }

    pub fn tenant_name(&self, id: &str) -> String {
        self.tenants
            .iter()
            .find(|tenant| tenant.id == id)
            .map(|tenant| tenant.name.clone())
            .unwrap_or_else(|| id.to_string())
    }

    pub fn handle(&mut self, msg: Msg) -> Option<Action> {
        match msg {
            Msg::Key(key) => self.on_key(key),
            Msg::Paste(text) => {
                self.paste(&text);
                None
            },
            Msg::Overview { dir, result } => {
                if self.profile().is_none_or(|profile| profile.dir != dir) {
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
            },
            Msg::Vaults { dir, subscription_id, result } => {
                if self.profile().is_none_or(|profile| profile.dir != dir) {
                    return None;
                }
                if self.subscription().is_none_or(|sub| sub.id != subscription_id) {
                    return None;
                }
                self.loading = false;
                match result {
                    Ok(vaults) => {
                        let previous = self.vault().map(|vault| vault.url);
                        let refreshing = self.status.starts_with("refreshing");
                        self.vaults = vaults;
                        let visible = self.visible_vaults();
                        let kept = previous
                            .as_ref()
                            .and_then(|url| visible.iter().position(|index| self.vaults[*index].url == *url));
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
            },
            Msg::Secrets { url, result } => {
                if self.vault().is_none_or(|vault| vault.url != url) {
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
                        self.pending_copy_to = None;
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
            },
            Msg::Value { url, name, result } => {
                if self.vault().is_none_or(|vault| vault.url != url) {
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
                let copying_to = self.pending_copy_to.take();
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
                if let Some((expected, dest)) = copying_to {
                    if expected == name {
                        return self.start_copy(dest, &name);
                    }
                    self.status = "copy cancelled: selection changed".into();
                }
                copy_value.map(Action::Copy)
            },
            Msg::Refreshed { url, name, result } => {
                if self.vault().is_none_or(|vault| vault.url != url) {
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
            },
            Msg::Resize => None,
            Msg::Saved { url, name, value, result } => {
                if self.vault().is_none_or(|vault| vault.url != url) {
                    return None;
                }
                match result {
                    Ok(meta) => {
                        self.editor = None;
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
                        self.values.insert(name.clone(), Ok(value));
                        self.status =
                            if existing.is_some() { format!("saved '{name}'") } else { format!("created '{name}'") };
                        None
                    },
                    Err(err) => {
                        self.status = format!("save failed: {err}");
                        None
                    },
                }
            },
            Msg::Deleted { url, name, result } => {
                if self.vault().is_none_or(|vault| vault.url != url) {
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
            },
            Msg::Duplicated { url, name, result } => {
                if self.vault().is_none_or(|vault| vault.url != url) {
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
            },
            Msg::CopyVaults { subscription_id, result } => {
                if self.copy_sub.as_ref().is_none_or(|sub| sub.id != subscription_id) {
                    return None;
                }
                self.loading = false;
                match result {
                    Ok(vaults) => self.show_copy_vaults(vaults),
                    Err(err) => {
                        self.copy_source = None;
                        self.status = format!("error: {err}");
                    },
                }
                None
            },
            Msg::CopyToExists { dest, secret } => {
                self.status = format!("'{}' exists in {} - y overwrite, n cancel", secret.name, dest.name);
                self.confirm_overwrite = Some((dest, secret));
                None
            },
            Msg::CopiedTo { dest, name, result } => {
                self.status = match result {
                    Ok(()) => format!("copied '{name}' to {dest}"),
                    Err(err) => format!("copy failed: {err}"),
                };
                None
            },
            Msg::CopiedVault { source, dest, result } => {
                self.loading = false;
                self.status = match result {
                    Ok(report) => {
                        let copied = report.created.len() + report.overwritten.len();
                        let failed = report.failed.len();
                        let skipped = report.skipped.len();
                        if copied == 0 && failed == 0 && skipped == 0 {
                            format!("no secrets in {source}")
                        } else if failed > 0 {
                            format!(
                                "copy failed: {failed} of {} secrets ({copied} copied, {skipped} skipped)",
                                copied + failed + skipped
                            )
                        } else if skipped > 0 {
                            format!("copied {copied} secrets to {dest}, {skipped} already existed")
                        } else {
                            format!("copied {copied} secrets to {dest}")
                        }
                    },
                    Err(err) => format!("copy failed: {err}"),
                };
                None
            },
            Msg::VaultInfo { url, result } => {
                if self.info_url.as_deref() != Some(url.as_str()) {
                    return None;
                }
                self.info_cache.insert(url, (Instant::now(), result.clone()));
                self.info = Some(result);
                None
            },
            Msg::Copied(result) => {
                self.status = match result {
                    Ok(()) => "copied to clipboard".into(),
                    Err(err) => format!("clipboard error: {err}"),
                };
                None
            },
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Some(Action::Quit);
        }
        if key.code == KeyCode::Char('e') && key.modifiers.contains(KeyModifiers::CONTROL) && self.editor.is_none() {
            self.show_hints = !self.show_hints;
            return None;
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
        if self.confirm_overwrite.is_some() {
            return self.on_confirm_key(key);
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
            KeyCode::Char('g') | KeyCode::Home => {
                let moved = self.jump(false);
                self.after_secret_move(moved)
            },
            KeyCode::Char('G') | KeyCode::End => {
                let moved = self.jump(true);
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
            KeyCode::Char('P') => {
                self.open_proxy_editor();
                None
            },
            KeyCode::Char('C') => match self.pane {
                Pane::Vaults => self.open_copy_vault(),
                Pane::Secrets => self.open_copy(),
            },
            KeyCode::Char('c') => self.copy_value(),
            KeyCode::Char('y') => self.selected_secret().map(|secret| Action::Copy(secret.name.clone())),
            _ => None,
        }
    }

    fn on_picker_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.code == KeyCode::Char('r')
            && self.picker.as_ref().is_some_and(|picker| picker.kind == PickerKind::CopyVault)
        {
            self.copy_refreshing = true;
            self.status = "refreshing vaults...".into();
            return self.load_vaults();
        }
        let picker = self.picker.as_mut()?;
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.picker = None;
                self.copy_source = None;
                self.copy_refreshing = false;
                None
            },
            KeyCode::Down => {
                if !picker.items.is_empty() {
                    picker.selected = (picker.selected + 1).min(picker.items.len() - 1);
                }
                None
            },
            KeyCode::Up => {
                picker.selected = picker.selected.saturating_sub(1);
                None
            },
            KeyCode::Enter => {
                let picker = self.picker.take()?;
                self.copy_refreshing = false;
                self.apply_picker(picker)
            },
            _ => None,
        }
    }

    fn apply_picker(&mut self, picker: Picker) -> Option<Action> {
        let value = *picker.values.get(picker.selected)?;
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
                if let Some(source) = self.copy_source.take() {
                    return self.start_copy_vault(source, dest);
                }
                let name = self.selected_secret()?.name.clone();
                self.start_copy(dest, &name)
            },
        }
    }

    fn on_filter_key(&mut self, key: KeyEvent) -> Option<Action> {
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

    fn open_profile_picker(&mut self) {
        let items =
            self.profiles.iter().map(|profile| format!("{}  {}", profile.name, profile.dir.display())).collect();
        let values = (0..self.profiles.len()).map(Some).collect();
        self.picker = Some(Picker {
            kind: PickerKind::Profiles,
            title: "Azure CLI profiles",
            items,
            values,
            selected: self.profile_idx,
        });
    }

    fn open_tenant_picker(&mut self) {
        let mut items = vec!["All tenants".to_string()];
        let mut values = vec![None];
        for (index, tenant) in self.tenants.iter().enumerate() {
            let count = self.subscriptions.iter().filter(|sub| sub.tenant_id == tenant.id).count();
            items.push(format!("{}  ({count} subscriptions)", tenant.name));
            values.push(Some(index));
        }
        let selected = self.tenant_idx.map(|index| index + 1).unwrap_or(0);
        self.picker = Some(Picker { kind: PickerKind::Tenants, title: "tenants", items, values, selected });
    }

    fn open_subscription_picker(&mut self) {
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
        });
    }

    /// Returns true when the selection actually changed.
    fn move_selection(&mut self, delta: isize) -> bool {
        match self.pane {
            Pane::Vaults => {
                let len = self.visible_vaults().len();
                let before = self.vault_state.selected();
                step_list(&mut self.vault_state, len, delta);
                self.vault_state.selected() != before
            },
            Pane::Secrets => {
                let len = self.visible_secrets().len();
                step_table(&mut self.secret_state, len, delta);
                self.revealed = false;
                false
            },
        }
    }

    /// Returns true when the selection actually changed.
    fn jump(&mut self, to_end: bool) -> bool {
        match self.pane {
            Pane::Vaults => {
                let len = self.visible_vaults().len();
                let before = self.vault_state.selected();
                jump_list(&mut self.vault_state, len, to_end);
                self.vault_state.selected() != before
            },
            Pane::Secrets => {
                let len = self.visible_secrets().len();
                jump_table(&mut self.secret_state, len, to_end);
                self.revealed = false;
                false
            },
        }
    }

    fn after_secret_move(&mut self, moved: bool) -> Option<Action> {
        if self.pane == Pane::Secrets {
            self.preview()
        } else if moved {
            // Selecting a vault previews its secrets without pressing enter.
            self.open_vault()
        } else {
            None
        }
    }

    fn open_vault(&mut self) -> Option<Action> {
        self.secrets.clear();
        self.secret_state.select(None);
        self.values.clear();
        self.secret_filter.clear();
        self.revealed = false;
        self.pending_edit = None;
        self.pending_copy = None;
        self.pending_copy_to = None;
        self.load_secrets()
    }

    fn load_vaults(&mut self) -> Option<Action> {
        let profile = self.profile()?.clone();
        let subscription = self.subscription()?;
        self.loading = true;
        Some(Action::LoadVaults { profile, subscription })
    }

    fn load_secrets(&mut self) -> Option<Action> {
        let profile = self.profile()?.clone();
        let subscription = self.subscription()?;
        let vault = self.vault()?;
        self.loading = true;
        Some(Action::LoadSecrets { profile, subscription, vault })
    }

    /// With a secret selected, re-read only that row; otherwise reload the list.
    fn refresh_secret(&mut self) -> Option<Action> {
        let Some(name) = self.selected_secret().map(|secret| secret.name.clone()) else {
            self.status = "refreshing secrets...".into();
            return self.load_secrets();
        };
        let profile = self.profile()?.clone();
        let subscription = self.subscription()?;
        let vault = self.vault()?;
        self.loading = true;
        self.status = format!("refreshing {name}...");
        Some(Action::RefreshSecret { profile, subscription, vault, name })
    }

    fn preview(&mut self) -> Option<Action> {
        let name = self.selected_secret()?.name.clone();
        if self.values.contains_key(&name) {
            return None;
        }
        let profile = self.profile()?.clone();
        let subscription = self.subscription()?;
        let vault = self.vault()?;
        Some(Action::FetchValue { profile, subscription, vault, name })
    }

    fn copy_value(&mut self) -> Option<Action> {
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

    fn ask_delete(&mut self) -> Option<Action> {
        if self.pane != Pane::Secrets {
            self.status = "select a secret first".into();
            return None;
        }
        let Some(secret) = self.selected_secret() else {
            self.status = "select a secret first".into();
            return None;
        };
        let name = secret.name.clone();
        self.confirm_delete = Some(DeleteConfirm { name, yes: false });
        None
    }

    fn on_delete_key(&mut self, key: KeyEvent) -> Option<Action> {
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

    fn open_duplicate(&mut self) -> Option<Action> {
        if self.pane != Pane::Secrets {
            self.status = "select a secret first".into();
            return None;
        }
        let Some(secret) = self.selected_secret() else {
            self.status = "select a secret first".into();
            return None;
        };
        let source = secret.name.clone();
        let mut name = EditField::new("name", &format!("{source}-copy"));
        name.focus();
        self.duplicate = Some(Duplicate { source, name });
        None
    }

    fn on_duplicate_key(&mut self, key: KeyEvent) -> Option<Action> {
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

    fn open_editor(&mut self) -> Option<Action> {
        let secret = self.selected_secret()?.clone();
        let name = secret.name.clone();
        let value = match self.values.get(&name) {
            Some(Ok(value)) => value.clone(),
            Some(Err(err)) => {
                self.status = format!("error: {err}");
                return None;
            },
            None => {
                self.pending_edit = Some(name);
                self.status = "fetching value...".into();
                return self.preview();
            },
        };
        self.editor = Some(Editor {
            secret: name,
            name: None,
            fields: vec![
                EditField::new("value", &value),
                EditField::new("type", secret.content_type.as_deref().unwrap_or("")),
                EditField::new("expires", &fmt_date(secret.expires)),
                EditField::new("activates", &fmt_date(secret.not_before)),
                EditField::new("tags", &format_tags(&secret.tags)),
            ],
            enabled: secret.enabled,
            active: 0,
            original_value: value,
            original_expires: secret.expires,
            original_not_before: secret.not_before,
            original_updated: secret.updated.map(|updated| updated.unix_timestamp_nanos()),
        });
        self.status = "edit: tab/↑↓ next, enter save, esc cancel".into();
        None
    }

    fn open_new_secret(&mut self) -> Option<Action> {
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
                EditField::new("expires", ""),
                EditField::new("activates", ""),
                EditField::new("tags", ""),
            ],
            enabled: true,
            active: 0,
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
    fn paste(&mut self, text: &str) {
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
        let text =
            if is_value { text.replace("\r\n", "\n").replace('\r', "\n") } else { text.replace(['\r', '\n'], " ") };
        if let Some(field) = editor.active_field_mut() {
            field.insert_text(&text);
        }
        self.status = format!("pasted {} characters", text.chars().count());
    }

    fn newline_in_value(&mut self) {
        let Some(editor) = self.editor.as_mut() else {
            return;
        };
        let value_index = usize::from(editor.name.is_some());
        if editor.active == value_index
            && let Some(field) = editor.active_field_mut()
        {
            field.insert_text("\n");
        }
    }

    fn on_editor_key(&mut self, key: KeyEvent) -> Option<Action> {
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
            KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => {
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
        edit_field(editor.active_field_mut()?, key.code);
        None
    }

    /// Vault whose info window is open, if any.
    pub fn info_vault(&self) -> Option<&Vault> {
        let url = self.info_url.as_ref()?;
        self.vaults.iter().find(|vault| &vault.url == url)
    }

    fn open_info(&mut self) -> Option<Action> {
        self.info_moved = false;
        self.show_info(false)
    }

    /// Show cached info when it is younger than [INFO_TTL]; otherwise load it.
    /// `force` bypasses the cache (`r` refresh key).
    fn show_info(&mut self, force: bool) -> Option<Action> {
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

    fn on_info_key(&mut self, key: KeyEvent) -> Option<Action> {
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
                step_list(&mut self.vault_state, len, 1);
                if self.vault_state.selected() != before {
                    self.info_moved = true;
                    return self.show_info(false);
                }
            },
            KeyCode::Up => {
                let len = self.visible_vaults().len();
                let before = self.vault_state.selected();
                step_list(&mut self.vault_state, len, -1);
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

    fn open_proxy_editor(&mut self) {
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

    fn on_proxy_key(&mut self, key: KeyEvent) -> Option<Action> {
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

    fn apply_proxy(&mut self) -> Option<Action> {
        let editor = self.proxy_editor.as_ref()?;
        if !editor.enabled {
            self.proxy = None;
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
            Ok(proxy) => {
                let label = proxy.as_ref().map(ProxySettings::display_url).unwrap_or_else(|| url.clone());
                self.set_proxy(proxy);
                self.proxy_editor = None;
                self.status = format!("proxy {label}");
                self.reload_after_proxy()
            },
            Err(err) => {
                self.status = format!("proxy: {err}");
                None
            },
        }
    }

    fn reload_after_proxy(&mut self) -> Option<Action> {
        self.values.clear();
        self.info_cache.clear();
        if self.vault().is_some() { self.open_vault() } else { self.load_vaults() }
    }

    fn save_editor(&mut self) -> Option<Action> {
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
        let secret = Secret { name, value, content_type, tags, enabled, expires, not_before };
        let profile = self.profile()?.clone();
        let vault = self.vault()?;
        Some(Action::SaveSecret { profile, vault, secret, updated: expected_updated })
    }

    fn open_copy(&mut self) -> Option<Action> {
        self.copy_source = None;
        if self.selected_secret().is_none() {
            self.status = "select a secret first".into();
            return None;
        }
        self.copy_targets()
    }

    fn open_copy_vault(&mut self) -> Option<Action> {
        let Some(source) = self.vault() else {
            self.status = "select a vault first".into();
            return None;
        };
        self.copy_source = Some(source);
        self.copy_targets()
    }

    fn copy_targets(&mut self) -> Option<Action> {
        if self.subscriptions.is_empty() {
            self.copy_source = None;
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
        });
        None
    }

    /// The current subscription's vaults are already loaded in the panel, so
    /// reuse them instead of fetching the same list again.
    fn select_copy_subscription(&mut self, subscription: Subscription) -> Option<Action> {
        self.copy_sub = Some(subscription.clone());
        if self.subscription().is_some_and(|current| current.id == subscription.id) {
            self.show_copy_vaults(self.vaults.clone());
            return None;
        }
        self.load_copy_vaults(subscription)
    }

    /// Rebuild the destination picker after refreshing the panel behind it.
    fn refresh_copy(&mut self) -> Option<Action> {
        let subscription = self.copy_sub.clone()?;
        if self.subscription().is_some_and(|current| current.id == subscription.id) {
            self.show_copy_vaults(self.vaults.clone());
            None
        } else {
            self.load_copy_vaults(subscription)
        }
    }

    fn show_copy_vaults(&mut self, vaults: Vec<Vault>) {
        let current =
            self.copy_source.as_ref().map(|vault| vault.url.clone()).or_else(|| self.vault().map(|vault| vault.url));
        self.copy_vaults = vaults.into_iter().filter(|vault| Some(&vault.url) != current.as_ref()).collect();
        if self.copy_vaults.is_empty() {
            self.picker = None;
            self.copy_source = None;
            self.status = "no other vaults in this subscription".into();
            return;
        }
        let items =
            self.copy_vaults.iter().map(|vault| format!("{}  ({})", vault.name, vault.subscription_name)).collect();
        let values = (0..self.copy_vaults.len()).map(Some).collect();
        self.picker = Some(Picker { kind: PickerKind::CopyVault, title: "copy to vault", items, values, selected: 0 });
    }

    fn load_copy_vaults(&mut self, subscription: Subscription) -> Option<Action> {
        let profile = self.profile()?.clone();
        self.copy_sub = Some(subscription.clone());
        self.loading = true;
        self.status = format!("loading vaults in {}...", subscription.name);
        Some(Action::LoadCopyVaults { profile, subscription })
    }

    fn start_copy(&mut self, dest: Vault, name: &str) -> Option<Action> {
        let profile = self.profile()?.clone();
        let meta = self.secrets.iter().find(|secret| secret.name == name)?.clone();
        let value = match self.values.get(name) {
            Some(Ok(value)) => value.clone(),
            Some(Err(err)) => {
                self.status = format!("error: {err}");
                return None;
            },
            None => {
                self.pending_copy_to = Some((name.to_string(), dest));
                self.status = "fetching value...".into();
                return self.preview();
            },
        };
        if self.vault().is_some_and(|vault| vault.url == dest.url) {
            self.status = "destination is the current vault".into();
            return None;
        }
        let secret = Secret {
            name: meta.name,
            value,
            content_type: meta.content_type,
            tags: meta.tags,
            enabled: meta.enabled,
            expires: meta.expires,
            not_before: meta.not_before,
        };
        Some(Action::CopyToVault { profile, dest, secret, overwrite: false })
    }

    fn start_copy_vault(&mut self, source: Vault, dest: Vault) -> Option<Action> {
        if source.url == dest.url {
            self.status = "destination is the source vault".into();
            return None;
        }
        let profile = self.profile()?.clone();
        self.loading = true;
        self.status = format!("copying all secrets to {}...", dest.name);
        Some(Action::CopyVault { profile, source, dest })
    }

    fn on_confirm_key(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                let (dest, secret) = self.confirm_overwrite.take()?;
                let profile = self.profile()?.clone();
                Some(Action::CopyToVault { profile, dest, secret, overwrite: true })
            },
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                self.confirm_overwrite = None;
                self.status = "copy cancelled".into();
                None
            },
            _ => None,
        }
    }

    fn reset_views(&mut self) {
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
        self.pending_copy_to = None;
        self.copy_source = None;
        self.copy_refreshing = false;
        self.info_cache.clear();
        self.duplicate = None;
        self.confirm_delete = None;
    }

    fn reset_selection(&mut self, pane: Pane) {
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

    fn filter_mut(&mut self, pane: Pane) -> &mut String {
        match pane {
            Pane::Vaults => &mut self.vault_filter,
            Pane::Secrets => &mut self.secret_filter,
        }
    }

    fn clear_filter(&mut self, pane: Pane) {
        self.filter_mut(pane).clear();
    }
}

fn other(pane: Pane) -> Pane {
    match pane {
        Pane::Vaults => Pane::Secrets,
        Pane::Secrets => Pane::Vaults,
    }
}

pub fn matches(name: &str, filter: &str) -> bool {
    filter.is_empty() || name.to_lowercase().contains(&filter.to_lowercase())
}

fn format_tags(tags: &BTreeMap<String, String>) -> String {
    tags.iter().map(|(key, value)| format!("{key}={value}")).collect::<Vec<_>>().join(", ")
}

/// Comma-separated `key=value` pairs for the single-line tag field.
/// shortcut: tag values containing commas cannot be edited here; replace with
/// per-tag rows if that becomes a real need.
fn parse_tags(text: &str) -> Result<BTreeMap<String, String>, String> {
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

fn edit_field(field: &mut EditField, code: KeyCode) {
    match code {
        KeyCode::Left => {
            field.deselect();
            field.cursor = field.cursor.saturating_sub(1);
        },
        KeyCode::Right => {
            field.deselect();
            field.cursor = (field.cursor + 1).min(field.value.len());
        },
        KeyCode::Home => {
            field.deselect();
            field.cursor = 0;
        },
        KeyCode::End => {
            field.deselect();
            field.cursor = field.value.len();
        },
        KeyCode::Backspace => field.backspace(),
        KeyCode::Delete => field.delete(),
        KeyCode::Char(character) if !character.is_control() => field.insert(character),
        _ => {},
    }
}

/// Splits `scheme://host:port` into the editor fields. Empty input defaults to
/// the usual local SOCKS tunnel (`ssh -D 1080`).
fn split_proxy(url: &str) -> (usize, String, String) {
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
fn proxy_url(scheme: usize, host: &str, port: &str) -> Option<String> {
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

fn step_list(state: &mut ListState, len: usize, delta: isize) {
    if len == 0 {
        return;
    }
    let next = match state.selected() {
        Some(current) => (current as isize + delta).clamp(0, len as isize - 1) as usize,
        None => 0,
    };
    state.select(Some(next));
}

fn step_table(state: &mut TableState, len: usize, delta: isize) {
    if len == 0 {
        return;
    }
    let next = match state.selected() {
        Some(current) => (current as isize + delta).clamp(0, len as isize - 1) as usize,
        None => 0,
    };
    state.select(Some(next));
}

fn jump_list(state: &mut ListState, len: usize, to_end: bool) {
    if len > 0 {
        state.select(Some(if to_end { len - 1 } else { 0 }));
    }
}

fn jump_table(state: &mut TableState, len: usize, to_end: bool) {
    if len > 0 {
        state.select(Some(if to_end { len - 1 } else { 0 }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azkv_core::SecretState;
    use ratatui::crossterm::event::KeyEvent;

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

    #[test]
    fn starts_by_loading_the_selected_profile() {
        let mut app = App::new(vec![profile("test")], 0);
        assert_eq!(app.start(), Action::LoadOverview { profile: profile("test") });
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
    fn picker_escape_closes_without_switching() {
        let mut app = loaded_app();
        app.on_key(key(KeyCode::Char('s')));
        assert!(app.picker.is_some());
        app.on_key(key(KeyCode::Esc));
        assert!(app.picker.is_none());
        assert_eq!(app.sub_idx, 0);
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
    fn secret_states_are_rendered_from_core() {
        assert_eq!(SecretState::On.label(), "on");
        assert!(matches("db", ""));
        assert!(!matches("db", "x"));
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
        for character in "2028-02-01".chars() {
            app.on_key(key(KeyCode::Char(character)));
        }

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
    fn editor_inserts_a_newline_with_ctrl_j() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.values.insert("alpha".into(), Ok(String::new()));
        app.pane = Pane::Secrets;
        app.on_key(key(KeyCode::Char('e')));

        app.on_key(key(KeyCode::Char('a')));
        app.on_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::CONTROL));
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

        app.handle(Msg::Saved { url, name: "beta".into(), value: "v".into(), result: Ok(meta("beta")) });
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
        app.on_key(key(KeyCode::Char('x')));
        assert!(app.on_key(key(KeyCode::Enter)).is_none());
        assert!(app.editor.is_some());
        assert!(app.status.starts_with("expires:"));
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
        let action = app.handle(Msg::Saved { url, name: "alpha".into(), value: "new".into(), result: Ok(saved) });
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
        app.handle(Msg::Saved { url, name: "alpha".into(), value: "x".into(), result: Err("boom".into()) });
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

    #[test]
    fn copy_to_vault_asks_for_a_subscription_then_loads_vaults() {
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
        app.values.insert("alpha".into(), Ok("secret".into()));
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
        let Action::CopyToVault { dest, secret, overwrite, .. } = action else {
            panic!("expected CopyToVault");
        };
        assert_eq!(dest.name, "kv-b");
        assert_eq!(secret.name, "alpha");
        assert_eq!(secret.value, "secret");
        assert!(!overwrite);
    }

    #[test]
    fn copy_all_uses_the_vault_picker_and_reports_progress() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        app.pane = Pane::Vaults;
        assert!(app.on_key(key(KeyCode::Char('C'))).is_none());
        assert_eq!(app.picker.as_ref().unwrap().kind, PickerKind::CopySubscription);
        assert_eq!(app.copy_source.as_ref().unwrap().name, "kv-a");

        let subscription = app.subscription().unwrap();
        app.copy_sub = Some(subscription.clone());
        app.handle(Msg::CopyVaults {
            subscription_id: subscription.id.clone(),
            result: Ok(vec![vault("kv-a", &subscription), vault("kv-b", &subscription)]),
        });
        assert_eq!(app.picker.as_ref().unwrap().kind, PickerKind::CopyVault);

        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        let Action::CopyVault { source, dest, .. } = action else {
            panic!("expected CopyVault, got {action:?}");
        };
        assert_eq!(source.name, "kv-a");
        assert_eq!(dest.name, "kv-b");
        assert!(app.copy_source.is_none());
        assert_eq!(app.status, "copying all secrets to kv-b...");

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
        assert!(app.status.starts_with("copy failed: 1 of 2"));
    }

    #[test]
    fn copying_without_a_cached_value_fetches_then_continues() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        let subscription = app.subscription().unwrap();
        app.copy_sub = Some(subscription.clone());
        app.handle(Msg::CopyVaults {
            subscription_id: subscription.id.clone(),
            result: Ok(vec![vault("kv-b", &subscription)]),
        });
        let action = app.on_key(key(KeyCode::Enter)).unwrap();
        assert!(matches!(action, Action::FetchValue { ref name, .. } if name == "alpha"));
        assert!(app.pending_copy_to.is_some());
        let url = app.vault().unwrap().url;
        let action = app.handle(Msg::Value { url, name: "alpha".into(), result: Ok("later".into()) }).unwrap();
        let Action::CopyToVault { secret, .. } = action else {
            panic!("expected CopyToVault");
        };
        assert_eq!(secret.value, "later");
        assert!(app.pending_copy_to.is_none());
    }

    #[test]
    fn stale_copy_vault_responses_are_ignored() {
        let mut app = loaded_app();
        app.copy_sub = Some(app.subscriptions[0].clone());
        assert!(app.handle(Msg::CopyVaults { subscription_id: "s2".into(), result: Ok(vec![]) }).is_none());
        assert!(app.picker.is_none());
    }

    #[test]
    fn changing_vault_or_profile_clears_pending_work() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        app.pending_edit = Some("alpha".into());
        app.pending_copy = Some("alpha".into());
        app.pending_copy_to = Some(("alpha".into(), app.vaults[1].clone()));

        app.open_vault();
        assert!(app.pending_edit.is_none());
        assert!(app.pending_copy.is_none());
        assert!(app.pending_copy_to.is_none());

        app.pending_edit = Some("alpha".into());
        app.pending_copy = Some("alpha".into());
        app.pending_copy_to = Some(("alpha".into(), app.vaults[1].clone()));
        app.reset_views();
        assert!(app.pending_edit.is_none());
        assert!(app.pending_copy.is_none());
        assert!(app.pending_copy_to.is_none());
    }

    #[test]
    fn existing_destination_asks_before_overwriting() {
        let mut app = loaded_app();
        with_vaults(&mut app);
        with_secrets(&mut app, &["alpha"]);
        let dest = vault("kv-b", &app.subscription().unwrap());
        let secret = Secret {
            name: "alpha".into(),
            value: "new".into(),
            content_type: None,
            tags: Default::default(),
            enabled: true,
            expires: None,
            not_before: None,
        };
        app.handle(Msg::CopyToExists { dest, secret });
        assert!(app.confirm_overwrite.is_some());
        assert!(app.status.contains("exists"));
        assert!(app.on_key(key(KeyCode::Char('q'))).is_none());
        let action = app.on_key(key(KeyCode::Char('y'))).unwrap();
        let Action::CopyToVault { dest, secret, overwrite, .. } = action else {
            panic!("expected CopyToVault");
        };
        assert_eq!(dest.name, "kv-b");
        assert_eq!(secret.value, "new");
        assert!(overwrite);
        assert!(app.confirm_overwrite.is_none());

        app.handle(Msg::CopyToExists { dest, secret });
        assert!(app.on_key(key(KeyCode::Char('n'))).is_none());
        assert!(app.confirm_overwrite.is_none());
        assert!(app.status.contains("cancelled"));
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
        assert!(matches!(action, Action::LoadSecrets { .. }));
        assert!(app.proxy_editor.is_none());
        assert_eq!(app.proxy.as_ref().unwrap().url(), "socks5h://proxy.corp:3128");
        assert!(app.status.contains("proxy"));
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
        app.on_key(key(KeyCode::Enter));
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
        app.on_key(key(KeyCode::Enter));
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
        app.on_key(key(KeyCode::Enter));
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
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.proxy.as_ref().unwrap().url(), "http://proxy.corp:3128");
        assert_eq!(app.proxy.as_ref().unwrap().no_proxy(), Some("localhost,127.0.0.1"));
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
    fn copied_to_success_and_failure_are_reported() {
        let mut app = loaded_app();
        app.handle(Msg::CopiedTo { dest: "kv-b".into(), name: "alpha".into(), result: Ok(()) });
        assert_eq!(app.status, "copied 'alpha' to kv-b");
        app.handle(Msg::CopiedTo { dest: "kv-b".into(), name: "alpha".into(), result: Err("denied".into()) });
        assert!(app.status.contains("denied"));
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
