use std::collections::VecDeque;
use std::path::PathBuf;

use azkv_core::copy::{CopyPlan, CopyReport};
use azkv_core::{Overview, Profile, ProxySettings, Secret, SecretMeta, Subscription, Vault, VaultInfo};
use ratatui::crossterm::event::KeyEvent;

use super::EditField;
use ratatui::widgets::{ListState, TableState};

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Quit,
    LoadOverview { profile: Profile },
    LoadVaults { profile: Profile, subscription: Subscription },
    LoadSecrets { profile: Profile, subscription: Subscription, vault: Vault },
    FetchValue { profile: Profile, subscription: Subscription, vault: Vault, name: String },
    RefreshSecret { profile: Profile, subscription: Subscription, vault: Vault, name: String },
    Copy(String),
    SaveSecret { profile: Profile, vault: Vault, secret: Secret, updated: Option<Option<i128>>, patch: bool },
    LoadCopyVaults { profile: Profile, subscription: Subscription },
    CheckProxy { proxy: ProxySettings },
    PlanCopyVault { profile: Profile, source: Vault, dest: Vault, filter: String },
    CopyVault { profile: Profile, source: Vault, dest: Vault, plan: CopyPlan },
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
    Saved { url: String, name: String, value: Option<String>, result: Result<SecretMeta, String> },
    CopyVaults { subscription_id: String, result: Result<Vec<Vault>, String> },
    ProxyChecked { proxy: ProxySettings, result: Result<(), String> },
    CopyPlan { source: Vault, dest: Vault, result: Result<CopyPlan, String> },
    CopiedVault { source: String, dest: String, result: Result<CopyReport, String> },
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
    /// Index into [`Picker::visible`], not into `items`.
    pub selected: usize,
    /// `/` filter; empty shows every item. `matches` supports `|` for OR.
    pub filter: String,
    pub filtering: bool,
}

impl Picker {
    pub(crate) fn visible(&self) -> Vec<usize> {
        (0..self.items.len()).filter(|index| matches(&self.items[*index], &self.filter)).collect()
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

/// Copy plan under review: `queue` holds the destination conflicts still undecided.
pub struct CopyReview {
    pub source: Vault,
    pub dest: Vault,
    pub plan: CopyPlan,
    pub queue: VecDeque<String>,
    pub total: usize,
    /// `false` is the focused default, so Enter alone skips.
    pub yes: bool,
}

impl CopyReview {
    pub fn current(&self) -> Option<&str> {
        self.queue.front().map(String::as_str)
    }

    /// 1-based position of the conflict being asked about.
    pub fn position(&self) -> usize {
        self.total.saturating_sub(self.queue.len()) + 1
    }
}

pub(super) fn other(pane: Pane) -> Pane {
    match pane {
        Pane::Vaults => Pane::Secrets,
        Pane::Secrets => Pane::Vaults,
    }
}
pub fn matches(name: &str, filter: &str) -> bool {
    let name = name.to_lowercase();
    let terms =
        filter.split('|').map(|term| term.trim().to_lowercase()).filter(|term| !term.is_empty()).collect::<Vec<_>>();
    terms.is_empty() || terms.iter().any(|term| name.contains(term))
}
/// Selection state shared by the vault list and the secrets table.
pub(super) trait Selected {
    fn selected(&self) -> Option<usize>;
    fn select(&mut self, index: Option<usize>);
}

impl Selected for ListState {
    fn selected(&self) -> Option<usize> {
        ListState::selected(self)
    }

    fn select(&mut self, index: Option<usize>) {
        ListState::select(self, index);
    }
}

impl Selected for TableState {
    fn selected(&self) -> Option<usize> {
        TableState::selected(self)
    }

    fn select(&mut self, index: Option<usize>) {
        TableState::select(self, index);
    }
}

pub(super) fn step_selection(state: &mut impl Selected, len: usize, delta: isize) {
    if len == 0 {
        return;
    }
    let next = match state.selected() {
        Some(current) => (current as isize + delta).clamp(0, len as isize - 1) as usize,
        None => 0,
    };
    state.select(Some(next));
}

pub(super) fn jump_selection(state: &mut impl Selected, len: usize, to_end: bool) {
    if len > 0 {
        state.select(Some(if to_end { len - 1 } else { 0 }));
    }
}
