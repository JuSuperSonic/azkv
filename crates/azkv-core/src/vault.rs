use std::collections::BTreeMap;
use std::sync::Arc;

use azure_core::credentials::TokenCredential;
use azure_core::http::Transport;
use azure_security_keyvault_secrets::models::{
    Secret as SecretModel, SecretClientGetSecretOptions, SecretProperties, SetSecretParameters,
    UpdateSecretPropertiesParameters,
};
use azure_security_keyvault_secrets::{ResourceExt, SecretClient, SecretClientOptions};
use futures::TryStreamExt;

use crate::credential::AzAuth;
use crate::error::{Error, Result};
use crate::model::{Secret, SecretMeta, Vault};
use crate::proxy::ProxySettings;

/// Minimal vault surface used by the copy engine, so it can be tested with fakes.
/// Only used generically (never as a trait object), so the missing auto-trait bound
/// on the futures is not a problem.
#[allow(async_fn_in_trait)]
pub trait SecretStore {
    async fn names(&self) -> Result<Vec<String>>;
    async fn get(&self, name: &str) -> Result<Secret>;
    async fn put(&self, secret: &Secret) -> Result<SecretMeta>;
}

pub struct KvVault {
    client: SecretClient,
}

impl KvVault {
    pub fn new(url: &str, credential: Arc<dyn TokenCredential>, proxy: Option<&ProxySettings>) -> Result<Self> {
        let mut options = SecretClientOptions::default();
        options.client_options.transport = Some(Transport::new(match proxy {
            Some(proxy) => proxy.transport(),
            None => ProxySettings::shared_transport()?,
        }));
        Ok(Self {
            client: SecretClient::new(url, credential, Some(options))
                .map_err(|err| Error::Config(format!("cannot create a Key Vault client for {url}: {err}")))?,
        })
    }

    /// `proxy` applies to the Key Vault data plane; management calls use it
    /// too. Tokens come from the CLI cache and are refreshed natively.
    pub fn for_vault(vault: &Vault, auth: &Arc<AzAuth>, proxy: Option<&ProxySettings>) -> Result<Self> {
        Self::new(&vault.url, auth.credential(&vault.subscription_id), proxy)
    }

    /// Reads one secret, optionally at a specific version.
    pub async fn get_version(&self, name: &str, version: Option<&str>) -> Result<Secret> {
        let options =
            SecretClientGetSecretOptions { secret_version: version.map(str::to_string), ..Default::default() };
        let context = format!("cannot read secret '{name}'");
        let model = self
            .client
            .get_secret(name, Some(options))
            .await
            .map_err(|err| Error::from_azure(err, &context))?
            .into_model()
            .map_err(|err| Error::from_azure(err, &context))?;
        Ok(secret_from(name, model))
    }

    /// Reads one secret and its metadata, used to refresh a single table row.
    pub async fn refresh(&self, name: &str) -> Result<(SecretMeta, String)> {
        let context = format!("cannot read secret '{name}'");
        let mut model = self
            .client
            .get_secret(name, None)
            .await
            .map_err(|err| Error::from_azure(err, &context))?
            .into_model()
            .map_err(|err| Error::from_azure(err, &context))?;
        let value = model.value.take().unwrap_or_default();
        Ok((meta_from_written(name, model), value))
    }

    /// Updates tags and attributes without touching the value. This is the only
    /// way to change a secret while it is disabled.
    pub async fn update(&self, secret: &Secret) -> Result<SecretMeta> {
        let context = format!("cannot update secret '{}'", secret.name);
        let parameters = update_parameters(secret).try_into().map_err(|err| Error::from_azure(err, &context))?;
        let model = self
            .client
            .update_secret_properties(&secret.name, parameters, None)
            .await
            .map_err(|err| Error::from_azure(err, &context))?
            .into_model()
            .map_err(|err| Error::from_azure(err, &context))?;
        Ok(meta_from_written(&secret.name, model))
    }

    /// Metadata of one secret; unlike `refresh`, this works when it is disabled.
    pub async fn meta_of(&self, name: &str) -> Result<Option<SecretMeta>> {
        Ok(self.meta().await?.into_iter().find(|secret| secret.name == name))
    }

    /// Deletes a secret (soft delete: recoverable from the vault).
    pub async fn delete(&self, name: &str) -> Result<()> {
        self.client
            .delete_secret(name, None)
            .await
            .map_err(|err| Error::from_azure(err, &format!("cannot delete secret '{name}'")))?;
        Ok(())
    }

    /// Secret metadata (no values) for the browse view.
    pub async fn meta(&self) -> Result<Vec<SecretMeta>> {
        let mut pager =
            self.client.list_secret_properties(None).map_err(|err| Error::from_azure(err, "cannot list secrets"))?;
        let mut secrets = Vec::new();
        while let Some(properties) =
            pager.try_next().await.map_err(|err| Error::from_azure(err, "cannot list secrets"))?
        {
            secrets.push(meta_from(properties)?);
        }
        secrets.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(secrets)
    }
}

impl SecretStore for KvVault {
    async fn names(&self) -> Result<Vec<String>> {
        Ok(self.meta().await?.into_iter().map(|meta| meta.name).collect())
    }

    async fn get(&self, name: &str) -> Result<Secret> {
        self.get_version(name, None).await
    }

    async fn put(&self, secret: &Secret) -> Result<SecretMeta> {
        let context = format!("cannot write secret '{}'", secret.name);
        let model = self
            .client
            .set_secret(
                &secret.name,
                set_parameters(secret).try_into().map_err(|err| Error::from_azure(err, &context))?,
                None,
            )
            .await
            .map_err(|err| Error::from_azure(err, &context))?
            .into_model()
            .map_err(|err| Error::from_azure(err, &context))?;
        Ok(meta_from_written(&secret.name, model))
    }
}

fn meta_from(properties: SecretProperties) -> Result<SecretMeta> {
    let name = properties.resource_id().map_err(|err| Error::from_azure(err, "unexpected secret metadata"))?.name;
    let attributes = properties.attributes.unwrap_or_default();
    Ok(SecretMeta {
        name,
        enabled: attributes.enabled.unwrap_or(true),
        expires: attributes.expires,
        not_before: attributes.not_before,
        updated: attributes.updated,
        content_type: properties.content_type,
        tags: to_btree(properties.tags),
    })
}

fn meta_from_written(name: &str, model: SecretModel) -> SecretMeta {
    let attributes = model.attributes.unwrap_or_default();
    SecretMeta {
        name: name.to_string(),
        enabled: attributes.enabled.unwrap_or(true),
        expires: attributes.expires,
        not_before: attributes.not_before,
        updated: attributes.updated,
        content_type: model.content_type,
        tags: to_btree(model.tags),
    }
}

fn secret_from(name: &str, model: SecretModel) -> Secret {
    let attributes = model.attributes.unwrap_or_default();
    Secret {
        name: name.to_string(),
        value: model.value.unwrap_or_default(),
        content_type: model.content_type,
        tags: to_btree(model.tags),
        enabled: attributes.enabled.unwrap_or(true),
        expires: attributes.expires,
        not_before: attributes.not_before,
    }
}

/// Everything `put` needs: value, content type, tags and lifecycle attributes.
pub fn set_parameters(secret: &Secret) -> SetSecretParameters {
    let attributes = azure_security_keyvault_secrets::models::SecretAttributes {
        enabled: Some(secret.enabled),
        expires: secret.expires,
        not_before: secret.not_before,
        ..Default::default()
    };
    SetSecretParameters {
        content_type: secret.content_type.clone(),
        secret_attributes: Some(attributes),
        tags: if secret.tags.is_empty() {
            None
        } else {
            Some(secret.tags.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        },
        value: Some(secret.value.clone()),
    }
}

/// Attributes-only payload: no value, so a disabled secret can be re-enabled.
pub fn update_parameters(secret: &Secret) -> UpdateSecretPropertiesParameters {
    let attributes = azure_security_keyvault_secrets::models::SecretAttributes {
        enabled: Some(secret.enabled),
        expires: secret.expires,
        not_before: secret.not_before,
        ..Default::default()
    };
    UpdateSecretPropertiesParameters {
        content_type: secret.content_type.clone(),
        secret_attributes: Some(attributes),
        // An empty map clears tags; `None` would leave them untouched.
        tags: Some(secret.tags.iter().map(|(key, value)| (key.clone(), value.clone())).collect()),
    }
}

fn to_btree(tags: Option<std::collections::HashMap<String, String>>) -> BTreeMap<String, String> {
    tags.unwrap_or_default().into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_core::credentials::{AccessToken, TokenRequestOptions};

    #[derive(Debug)]
    struct NoCredential;

    #[async_trait::async_trait]
    impl TokenCredential for NoCredential {
        async fn get_token(
            &self,
            _scopes: &[&str],
            _options: Option<TokenRequestOptions<'_>>,
        ) -> azure_core::Result<AccessToken> {
            unreachable!("building a client must not request a token")
        }
    }

    fn secret(name: &str, value: &str) -> Secret {
        Secret {
            name: name.into(),
            value: value.into(),
            content_type: Some("text/plain".into()),
            tags: BTreeMap::from([("env".to_string(), "prod".to_string())]),
            enabled: true,
            expires: None,
            not_before: None,
        }
    }

    #[test]
    fn not_found_errors_are_detected_after_classification() {
        let not_found = azure_core::Error::with_message(
            azure_core::error::ErrorKind::HttpResponse {
                status: azure_core::http::StatusCode::NotFound,
                error_code: Some("SecretNotFound".into()),
                raw_response: None,
            },
            "not found",
        );
        let err = Error::from_azure(not_found, "cannot read secret 'x'");
        assert!(crate::is_not_found(&err));
        assert!(err.to_string().contains("cannot read secret 'x'"));

        let forbidden = azure_core::Error::with_message(
            azure_core::error::ErrorKind::HttpResponse {
                status: azure_core::http::StatusCode::Forbidden,
                error_code: None,
                raw_response: None,
            },
            "forbidden",
        );
        assert!(!crate::is_not_found(&Error::from_azure(forbidden, "cannot read secret 'x'")));
        assert!(!crate::is_not_found(&Error::Config("network down".into())));
    }

    #[test]
    fn client_accepts_a_proxy_transport() {
        let proxy = ProxySettings::new(Some("http://127.0.0.1:8080"), Some("localhost")).unwrap();
        assert!(KvVault::new("https://kv-test.vault.azure.net/", Arc::new(NoCredential), proxy.as_ref()).is_ok());
        assert!(KvVault::new("https://kv-test.vault.azure.net/", Arc::new(NoCredential), None).is_ok());
    }

    #[test]
    fn put_parameters_preserve_metadata() {
        let mut source = secret("api-key", "s3cr3t");
        source.enabled = false;
        source.content_type = Some("application/json".into());
        let params = set_parameters(&source);
        assert_eq!(params.value.as_deref(), Some("s3cr3t"));
        assert_eq!(params.content_type.as_deref(), Some("application/json"));
        assert_eq!(params.tags.as_ref().and_then(|tags| tags.get("env")).map(String::as_str), Some("prod"));
        let attributes = params.secret_attributes.unwrap();
        assert_eq!(attributes.enabled, Some(false));
        assert!(attributes.expires.is_none());
    }

    #[test]
    fn update_parameters_omit_the_value() {
        let source = secret("api-key", "s3cr3t");
        let params = update_parameters(&source);
        assert_eq!(params.secret_attributes.as_ref().and_then(|attributes| attributes.enabled), Some(true));
        assert_eq!(params.tags.as_ref().and_then(|tags| tags.get("env")).map(String::as_str), Some("prod"));
        assert_eq!(params.content_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn empty_tags_are_not_sent() {
        let mut source = secret("k", "v");
        source.tags.clear();
        let params = set_parameters(&source);
        assert!(params.tags.is_none());
    }

    #[test]
    fn service_model_is_mapped_to_domain_secret() {
        let model: SecretModel = serde_json::from_str(
            r#"{
                "value": "abc",
                "contentType": "text/plain",
                "tags": {"env": "prod"},
                "attributes": {"enabled": false, "exp": 1700000000, "nbf": 1600000000}
            }"#,
        )
        .unwrap();
        let mapped = secret_from("api", model);
        assert_eq!(mapped.name, "api");
        assert_eq!(mapped.value, "abc");
        assert_eq!(mapped.content_type.as_deref(), Some("text/plain"));
        assert_eq!(mapped.tags["env"], "prod");
        assert!(!mapped.enabled);
        assert!(mapped.expires.is_some());
        assert!(mapped.not_before.is_some());
    }

    #[test]
    fn missing_attributes_default_to_enabled() {
        let model: SecretModel = serde_json::from_str(r#"{"value":"x"}"#).unwrap();
        let mapped = secret_from("n", model);
        assert!(mapped.enabled);
        assert!(mapped.expires.is_none());
    }
}
