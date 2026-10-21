use std::collections::BTreeSet;

use futures::stream::{self, StreamExt};

use crate::error::Result;
use crate::vault::SecretStore;

pub const DEFAULT_CONCURRENCY: usize = 8;

/// What a copy would do. Everything in `skip` already exists in the destination.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CopyPlan {
    pub create: Vec<String>,
    pub overwrite: Vec<String>,
    pub skip: Vec<String>,
}

impl CopyPlan {
    pub fn conflicts(&self) -> usize {
        self.skip.len()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CopyReport {
    pub created: Vec<String>,
    pub overwritten: Vec<String>,
    pub skipped: Vec<String>,
    pub failed: Vec<(String, String)>,
}

impl CopyReport {
    pub fn succeeded(&self) -> bool {
        self.failed.is_empty()
    }
}

pub fn plan(source: &[String], existing: &BTreeSet<String>, overwrite: bool) -> CopyPlan {
    let mut plan = CopyPlan::default();
    for name in source.iter().collect::<BTreeSet<_>>() {
        if existing.contains(name) {
            if overwrite {
                plan.overwrite.push(name.clone());
            } else {
                plan.skip.push(name.clone());
            }
        } else {
            plan.create.push(name.clone());
        }
    }
    plan.create.sort();
    plan.overwrite.sort();
    plan.skip.sort();
    plan
}

pub async fn make_plan<S: SecretStore, D: SecretStore>(source: &S, dest: &D, overwrite: bool) -> Result<CopyPlan> {
    let names = source.names().await?;
    let existing: BTreeSet<String> = dest.names().await?.into_iter().collect();
    Ok(plan(&names, &existing, overwrite))
}

/// Reads and writes secrets concurrently. Failures are collected per secret so
/// one bad secret does not stop the copy.
pub async fn execute_copy<S: SecretStore, D: SecretStore>(
    source: &S,
    dest: &D,
    plan: &CopyPlan,
    concurrency: usize,
) -> CopyReport {
    let names: Vec<String> = plan.create.iter().chain(plan.overwrite.iter()).cloned().collect();
    let results = stream::iter(names)
        .map(|name| async move {
            let result = copy_one(source, dest, &name).await;
            (name, result)
        })
        .buffer_unordered(concurrency.max(1))
        .collect::<Vec<_>>()
        .await;

    let overwrites: BTreeSet<&str> = plan.overwrite.iter().map(String::as_str).collect();
    let mut report = CopyReport { skipped: plan.skip.clone(), ..Default::default() };
    for (name, result) in results {
        match result {
            Ok(()) if overwrites.contains(name.as_str()) => report.overwritten.push(name),
            Ok(()) => report.created.push(name),
            Err(err) => report.failed.push((name, err.to_string())),
        }
    }
    report.created.sort();
    report.overwritten.sort();
    report.failed.sort_by(|a, b| a.0.cmp(&b.0));
    report
}

async fn copy_one<S: SecretStore, D: SecretStore>(source: &S, dest: &D, name: &str) -> Result<()> {
    let secret = source.get(name).await?;
    dest.put(&secret).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Mutex;

    use super::*;
    use crate::error::{Error, Remote};
    use crate::model::Secret;

    fn names(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    fn secret(name: &str, value: &str) -> Secret {
        Secret {
            name: name.into(),
            value: value.into(),
            content_type: Some("text/plain".into()),
            tags: BTreeMap::from([("team".to_string(), "core".to_string())]),
            enabled: true,
            expires: None,
            not_before: None,
        }
    }

    #[derive(Default)]
    struct FakeVault {
        secrets: Mutex<BTreeMap<String, Secret>>,
        fail_put: BTreeSet<String>,
        gets: Mutex<usize>,
        puts: Mutex<usize>,
    }

    impl FakeVault {
        fn with(names: &[&str]) -> Self {
            let vault = Self::default();
            {
                let mut secrets = vault.secrets.lock().unwrap();
                for name in names {
                    secrets.insert((*name).into(), secret(name, &format!("{name}-value")));
                }
            }
            vault
        }

        fn insert(&self, secret: Secret) {
            self.secrets.lock().unwrap().insert(secret.name.clone(), secret);
        }

        fn snapshot(&self) -> BTreeMap<String, Secret> {
            self.secrets.lock().unwrap().clone()
        }
    }

    impl SecretStore for FakeVault {
        async fn names(&self) -> Result<Vec<String>> {
            Ok(self.secrets.lock().unwrap().keys().cloned().collect())
        }

        async fn get(&self, name: &str) -> Result<Secret> {
            *self.gets.lock().unwrap() += 1;
            self.secrets
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .ok_or_else(|| Error::Remote { kind: Remote::NotFound, message: format!("{name} not found") })
        }

        async fn put(&self, secret: &Secret) -> Result<crate::SecretMeta> {
            *self.puts.lock().unwrap() += 1;
            if self.fail_put.contains(&secret.name) {
                return Err(Error::Remote {
                    kind: Remote::Forbidden,
                    message: format!("access denied for {}", secret.name),
                });
            }
            self.insert(secret.clone());
            Ok(crate::SecretMeta {
                name: secret.name.clone(),
                enabled: secret.enabled,
                expires: secret.expires,
                not_before: secret.not_before,
                updated: None,
                content_type: secret.content_type.clone(),
                tags: secret.tags.clone(),
            })
        }
    }

    #[test]
    fn plan_creates_missing_and_skips_existing() {
        let plan = plan(&names(&["a", "b", "c"]), &set(&["b"]), false);
        assert_eq!(plan.create, names(&["a", "c"]));
        assert_eq!(plan.skip, names(&["b"]));
        assert!(plan.overwrite.is_empty());
        assert_eq!(plan.conflicts(), 1);
    }

    #[test]
    fn plan_with_overwrite_targets_existing_secrets() {
        let plan = plan(&names(&["a", "b"]), &set(&["a", "b"]), true);
        assert!(plan.create.is_empty());
        assert_eq!(plan.overwrite, names(&["a", "b"]));
        assert!(plan.skip.is_empty());
        assert_eq!(plan.conflicts(), 0);
    }

    #[test]
    fn plan_deduplicates_and_sorts_source_names() {
        let plan = plan(&names(&["b", "a", "b"]), &set(&[]), false);
        assert_eq!(plan.create, names(&["a", "b"]));
    }

    #[test]
    fn plan_handles_empty_vaults() {
        let plan = plan(&[], &set(&["a"]), false);
        assert!(plan.create.is_empty() && plan.overwrite.is_empty() && plan.skip.is_empty());
    }

    #[tokio::test]
    async fn make_plan_lists_both_vaults() {
        let source = FakeVault::with(&["a", "b", "c"]);
        let dest = FakeVault::with(&["b"]);
        let plan = make_plan(&source, &dest, false).await.unwrap();
        assert_eq!(plan.create, names(&["a", "c"]));
        assert_eq!(plan.skip, names(&["b"]));
    }

    #[tokio::test]
    async fn execute_copies_values_and_metadata() {
        let source = FakeVault::with(&["a", "b"]);
        let mut tagged = secret("a", "value-a");
        tagged.tags = BTreeMap::from([("owner".to_string(), "sre".to_string())]);
        tagged.content_type = Some("application/json".into());
        source.insert(tagged);
        let dest = FakeVault::default();

        let plan = make_plan(&source, &dest, false).await.unwrap();
        let report = execute_copy(&source, &dest, &plan, 4).await;

        assert_eq!(report.created, names(&["a", "b"]));
        assert!(report.succeeded());
        let copied = dest.snapshot();
        assert_eq!(copied["a"].value, "value-a");
        assert_eq!(copied["a"].tags["owner"], "sre");
        assert_eq!(copied["a"].content_type.as_deref(), Some("application/json"));
        assert_eq!(copied["b"].value, "b-value");
    }

    #[tokio::test]
    async fn execute_skips_existing_secrets_by_default() {
        let source = FakeVault::with(&["a"]);
        let dest = FakeVault::with(&["a"]);
        dest.insert(secret("a", "destination-value"));

        let plan = make_plan(&source, &dest, false).await.unwrap();
        let report = execute_copy(&source, &dest, &plan, 2).await;

        assert_eq!(report.skipped, names(&["a"]));
        assert!(report.created.is_empty());
        assert_eq!(*source.gets.lock().unwrap(), 0);
        assert_eq!(*dest.puts.lock().unwrap(), 0);
        assert_eq!(dest.snapshot()["a"].value, "destination-value");
    }

    #[tokio::test]
    async fn execute_overwrites_when_asked() {
        let source = FakeVault::with(&["a"]);
        source.insert(secret("a", "source-value"));
        let dest = FakeVault::with(&["a"]);
        dest.insert(secret("a", "destination-value"));

        let plan = make_plan(&source, &dest, true).await.unwrap();
        assert_eq!(plan.overwrite, names(&["a"]));
        let report = execute_copy(&source, &dest, &plan, 2).await;

        assert_eq!(report.overwritten, names(&["a"]));
        assert_eq!(dest.snapshot()["a"].value, "source-value");
    }

    #[tokio::test]
    async fn execute_collects_failures_and_continues() {
        let source = FakeVault::with(&["a", "b", "c", "d"]);
        let dest = FakeVault { fail_put: set(&["c", "b"]), ..Default::default() };

        let plan = make_plan(&source, &dest, false).await.unwrap();
        let report = execute_copy(&source, &dest, &plan, 2).await;

        assert_eq!(report.created, names(&["a", "d"]));
        assert_eq!(report.failed.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(), ["b", "c"]);
        assert!(report.failed[0].1.contains("access denied"));
        assert!(!report.succeeded());
    }

    #[tokio::test]
    async fn execute_with_nothing_to_do_is_a_noop() {
        let source = FakeVault::with(&[]);
        let dest = FakeVault::default();
        let plan = make_plan(&source, &dest, false).await.unwrap();
        let report = execute_copy(&source, &dest, &plan, 8).await;
        assert_eq!(report, CopyReport::default());
        assert!(report.succeeded());
    }

    #[tokio::test]
    async fn execute_tolerates_zero_concurrency() {
        let source = FakeVault::with(&["a"]);
        let dest = FakeVault::default();
        let plan = make_plan(&source, &dest, false).await.unwrap();
        let report = execute_copy(&source, &dest, &plan, 0).await;
        assert_eq!(report.created, names(&["a"]));
    }
}
