use std::collections::HashMap;
use std::time::Instant;

use azkv_core::{Profile, ProxySettings, SecretMeta, Subscription, Tenant, Vault, VaultInfo};
use ratatui::widgets::{ListState, TableState};

mod copy;
mod editor;
mod info;
mod keys;
mod picker;
mod proxy;
mod secret_editor;
mod secrets;
mod state;
mod update;

pub(in crate::app) use editor::edit_field;
pub use editor::{EditField, Editor};
pub use proxy::ProxyEditor;
pub use state::matches;
pub use state::{Action, CopyReview, DeleteConfirm, Duplicate, Msg, Pane, Picker, PickerKind};
pub(in crate::app) use state::{jump_selection, other, step_selection};

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
    pub vault_rows: usize,
    pub secret_rows: usize,
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
    pub copy_review: Option<CopyReview>,
    copy_refreshing: bool,
    pub pending_select: Option<String>,
    pub duplicate: Option<Duplicate>,
    pub confirm_delete: Option<DeleteConfirm>,
    pub proxy: Option<ProxySettings>,
    last_proxy: Option<ProxySettings>,
    pub proxy_editor: Option<ProxyEditor>,
    proxy_checking: bool,
    pub info_url: Option<String>,
    pub info_moved: bool,
    pub info: Option<Result<VaultInfo, String>>,
    info_cache: HashMap<String, (Instant, Result<VaultInfo, String>)>,
    pub help: bool,
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
            vault_rows: 10,
            secret_rows: 9,
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
            copy_review: None,
            copy_refreshing: false,
            pending_select: None,
            duplicate: None,
            confirm_delete: None,
            proxy: None,
            last_proxy: None,
            proxy_editor: None,
            proxy_checking: false,
            info_url: None,
            info_moved: false,
            info: None,
            info_cache: HashMap::new(),
            help: false,
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

    pub fn start(&mut self) -> Option<Action> {
        let profile = self.profile().cloned()?;
        self.loading = true;
        Some(Action::LoadOverview { profile })
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

    /// Profile, subscription and vault that vault-scoped actions need.
    pub(super) fn context(&self) -> Option<(Profile, Subscription, Vault)> {
        Some((self.profile()?.clone(), self.subscription()?, self.vault()?))
    }
}
