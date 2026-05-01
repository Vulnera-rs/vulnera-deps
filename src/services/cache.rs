use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use serde::de::DeserializeOwned;
use vulnera_contract::infrastructure::cache::CacheBackend;

use crate::application::errors::ApplicationError;
use crate::domain::vulnerability::entities::Package;
use crate::domain::vulnerability::value_objects::Ecosystem;

#[async_trait]
pub trait CacheService: Send + Sync {
    async fn get<T: DeserializeOwned + Send + 'static>(
        &self,
        key: &str,
    ) -> Result<Option<T>, ApplicationError>;

    async fn set<T: Serialize + Send + Sync + 'static>(
        &self,
        key: &str,
        value: &T,
        ttl: Duration,
    ) -> Result<(), ApplicationError>;

    async fn invalidate(&self, key: &str) -> Result<(), ApplicationError>;
}

/// A cache service that performs no caching (no-op).
pub struct NoopCacheService;

#[async_trait]
impl CacheService for NoopCacheService {
    async fn get<T: DeserializeOwned + Send + 'static>(
        &self,
        _key: &str,
    ) -> Result<Option<T>, ApplicationError> {
        Ok(None)
    }

    async fn set<T: Serialize + Send + Sync + 'static>(
        &self,
        _key: &str,
        _value: &T,
        _ttl: Duration,
    ) -> Result<(), ApplicationError> {
        Ok(())
    }

    async fn invalidate(&self, _key: &str) -> Result<(), ApplicationError> {
        Ok(())
    }
}

pub fn package_vulnerabilities_key(package: &Package) -> String {
    format!(
        "pkg_vuln:{}:{}@{}",
        package.ecosystem.canonical_name(),
        package.name,
        package.version
    )
}

pub fn registry_versions_key(ecosystem: &Ecosystem, name: &str) -> String {
    format!("reg_versions:{}:{}", ecosystem.canonical_name(), name)
}

/// Adapter that bridges `Arc<dyn CacheBackend>` (from vulnera-contract) to the
/// `CacheService` trait used within vulnera-deps.
pub struct CacheBackendAdapter {
    backend: Arc<dyn CacheBackend>,
}

impl CacheBackendAdapter {
    pub fn new(backend: Arc<dyn CacheBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl CacheService for CacheBackendAdapter {
    async fn get<T: DeserializeOwned + Send + 'static>(
        &self,
        key: &str,
    ) -> Result<Option<T>, ApplicationError> {
        let data = self
            .backend
            .get_raw(key)
            .await
            .map_err(|e| ApplicationError::Internal(format!("Cache error: {}", e)))?;
        match data {
            Some(bytes) => {
                let value = serde_json::from_slice(&bytes).map_err(|e| {
                    ApplicationError::Internal(format!("Cache deserialization error: {}", e))
                })?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    async fn set<T: Serialize + Send + Sync + 'static>(
        &self,
        key: &str,
        value: &T,
        ttl: Duration,
    ) -> Result<(), ApplicationError> {
        let bytes = serde_json::to_vec(value)
            .map_err(|e| ApplicationError::Internal(format!("Cache serialization error: {}", e)))?;
        self.backend
            .set_raw(key, &bytes, ttl)
            .await
            .map_err(|e| ApplicationError::Internal(format!("Cache error: {}", e)))?;
        Ok(())
    }

    async fn invalidate(&self, key: &str) -> Result<(), ApplicationError> {
        self.backend
            .delete(key)
            .await
            .map_err(|e| ApplicationError::Internal(format!("Cache error: {}", e)))?;
        Ok(())
    }
}
