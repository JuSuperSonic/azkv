use std::collections::{BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use futures::StreamExt;
use futures::stream;
use serde::Deserialize;

use crate::error::{Error, Result};

use super::{ARM, Arm};

const ROLE_CACHE_TTL: Duration = Duration::from_secs(300);
type RoleNames = HashMap<String, String>;
type RoleNameCache = HashMap<String, (Instant, RoleNames)>;
static ROLE_NAMES: OnceLock<Mutex<RoleNameCache>> = OnceLock::new();

impl Arm {
    /// Key Vault roles the signed-in user has on the vault, directly or through
    /// groups. `assignedTo()` expands transitive group membership server-side,
    /// which avoids the Graph permission problems of expanding groups ourselves.
    pub(super) async fn roles(
        &self,
        token: &str,
        resource_id: &str,
        resource_group: &str,
        subscription_id: &str,
        oid: &str,
    ) -> Result<Vec<String>> {
        let scopes = [
            resource_id.to_string(),
            format!("/subscriptions/{subscription_id}/resourceGroups/{resource_group}"),
            format!("/subscriptions/{subscription_id}"),
        ];
        // Listing at subscription scope includes subscopes (resource groups and
        // vaults); higher management-group assignments are not inherited here.
        let url = format!(
            "{ARM}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=assignedTo('{oid}')"
        );
        let assignments: Vec<RoleAssignment> = self.get_all(token, &url).await?;
        let mut definition_ids = BTreeSet::new();
        for assignment in assignments {
            let properties = assignment.properties;
            let applies = properties
                .scope
                .as_deref()
                .is_some_and(|scope| scopes.iter().any(|candidate| candidate.eq_ignore_ascii_case(scope)));
            if applies && let Some(id) = properties.role_definition_id {
                definition_ids.insert(id);
            }
        }

        let mut roles = BTreeSet::new();
        let mut names = self.role_definition_names(token, subscription_id, &definition_ids).await?;
        for id in definition_ids {
            if let Some(name) = names.remove(&id.to_ascii_lowercase()) {
                roles.insert(name);
            }
        }
        let mut roles: Vec<String> = roles.into_iter().collect();
        roles.retain(|role| is_key_vault_role(role));
        Ok(roles)
    }

    /// Resolve role definition names with one subscription-wide list request.
    /// Assignments can point at roles defined above the subscription, so any
    /// IDs missing from the list are fetched individually in parallel.
    pub(super) async fn role_definition_names(
        &self,
        token: &str,
        subscription_id: &str,
        ids: &BTreeSet<String>,
    ) -> Result<HashMap<String, String>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let url = format!(
            "{ARM}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
        );
        let mut names = match cached_role_names(subscription_id) {
            Some(names) => names,
            None => self
                .get_all::<RoleDefinition>(token, &url)
                .await
                .unwrap_or_default()
                .into_iter()
                .filter_map(|definition| Some((definition.id?.to_ascii_lowercase(), definition.properties.role_name?)))
                .collect(),
        };

        let missing: Vec<String> =
            ids.iter().filter(|id| !names.contains_key(&id.to_ascii_lowercase())).cloned().collect();
        let fetched: Vec<Result<(String, Option<String>)>> = stream::iter(missing)
            .map(|id| async move {
                let body = self.get_text(token, &format!("{ARM}{id}?api-version=2022-04-01")).await?;
                let definition: RoleDefinition = serde_json::from_str(&body)
                    .map_err(|source| Error::Parse { context: "unexpected role definition".into(), source })?;
                Ok((id, definition.properties.role_name))
            })
            .buffer_unordered(8)
            .collect()
            .await;
        let complete = merge_role_names(&mut names, fetched);
        if complete {
            cache_role_names(subscription_id, &names);
        }
        Ok(names)
    }
}

#[derive(Deserialize)]
struct RoleAssignment {
    #[serde(default)]
    properties: RoleAssignmentProperties,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RoleAssignmentProperties {
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    role_definition_id: Option<String>,
}

#[derive(Deserialize)]
struct RoleDefinition {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    properties: RoleDefinitionProperties,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RoleDefinitionProperties {
    #[serde(default)]
    role_name: Option<String>,
}

/// Built-in and custom Key Vault roles are named `Key Vault ...`.
pub(super) fn is_key_vault_role(name: &str) -> bool {
    name.starts_with("Key Vault")
}

/// Merge the fallback lookups that succeeded. Returns false when any failed,
/// so a partial result is not cached.
pub(super) fn merge_role_names(
    names: &mut HashMap<String, String>,
    fetched: Vec<Result<(String, Option<String>)>>,
) -> bool {
    let mut complete = true;
    for result in fetched {
        match result {
            Ok((id, Some(name))) => {
                names.insert(id.to_ascii_lowercase(), name);
            },
            Ok((_, None)) => {},
            Err(_) => complete = false,
        }
    }
    complete
}

pub(super) fn cached_role_names(subscription_id: &str) -> Option<HashMap<String, String>> {
    let cache = ROLE_NAMES.get_or_init(|| Mutex::new(HashMap::new()));
    let cache = cache.lock().ok()?;
    let (at, names) = cache.get(&subscription_id.to_ascii_lowercase())?;
    (at.elapsed() < ROLE_CACHE_TTL).then(|| names.clone())
}

pub(super) fn cache_role_names(subscription_id: &str, names: &HashMap<String, String>) {
    if names.is_empty() {
        return;
    }
    let cache = ROLE_NAMES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut cache) = cache.lock() {
        cache.insert(subscription_id.to_ascii_lowercase(), (Instant::now(), names.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_role_lookup_does_not_hide_resolved_roles() {
        let mut names = HashMap::from([("builtin".to_string(), "Key Vault Reader".to_string())]);
        let complete = merge_role_names(
            &mut names,
            vec![
                Ok(("custom".to_string(), Some("Key Vault Secrets Officer".to_string()))),
                Err(Error::Config("denied".into())),
            ],
        );
        assert!(!complete);
        assert_eq!(names["custom"], "Key Vault Secrets Officer");
        assert_eq!(names["builtin"], "Key Vault Reader");
    }

    #[test]
    fn only_key_vault_roles_are_kept() {
        assert!(is_key_vault_role("Key Vault Reader"));
        assert!(is_key_vault_role("Key Vault Secrets Officer"));
        assert!(!is_key_vault_role("Contributor"));
        assert!(!is_key_vault_role("User Access Administrator"));
    }

    #[test]
    fn role_definition_names_are_cached_per_subscription() {
        let subscription = "cache-test-subscription";
        let mut names = HashMap::new();
        names.insert("id-1".into(), "Key Vault Reader".into());
        cache_role_names(subscription, &names);
        assert_eq!(cached_role_names(subscription), Some(names));
        cache_role_names("cache-empty-subscription", &HashMap::new());
        assert!(cached_role_names("cache-empty-subscription").is_none());
    }
}
