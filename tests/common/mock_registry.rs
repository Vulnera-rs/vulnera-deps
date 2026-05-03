use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

use vulnera_deps::domain::vulnerability::value_objects::{Ecosystem, Version};
use vulnera_deps::infrastructure::registries::{
    PackageRegistryClient, RegistryError, RegistryPackageMetadata, VersionInfo,
};

#[derive(Debug, Clone)]
pub struct MockRegistryClient {
    versions: Arc<RwLock<HashMap<String, Vec<VersionInfo>>>>,
    metadata: Arc<RwLock<HashMap<String, RegistryPackageMetadata>>>,
    errors: Arc<RwLock<HashMap<String, RegistryError>>>,
    calls: Arc<RwLock<Vec<String>>>,
}

impl MockRegistryClient {
    pub fn new() -> Self {
        Self {
            versions: Arc::new(RwLock::new(HashMap::new())),
            metadata: Arc::new(RwLock::new(HashMap::new())),
            errors: Arc::new(RwLock::new(HashMap::new())),
            calls: Arc::new(RwLock::new(Vec::new())),
        }
    }

    fn versions_key(ecosystem: &Ecosystem, name: &str) -> String {
        format!("{}:{}", ecosystem.canonical_name(), name)
    }

    fn metadata_key(ecosystem: &Ecosystem, name: &str, version: &Version) -> String {
        format!("{}:{}@{}", ecosystem.canonical_name(), name, version)
    }

    pub fn with_version(
        self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        yanked: bool,
        prerelease: bool,
    ) -> Self {
        let key = Self::versions_key(&ecosystem, name);
        let info = VersionInfo {
            version: Version::parse(version).expect("valid version string"),
            yanked,
            is_prerelease: prerelease,
            published_at: None,
        };
        self.versions
            .write()
            .expect("lock not poisoned")
            .entry(key)
            .or_default()
            .push(info);
        self
    }

    pub fn with_versions(
        self,
        ecosystem: Ecosystem,
        name: &str,
        versions: Vec<VersionInfo>,
    ) -> Self {
        let key = Self::versions_key(&ecosystem, name);
        self.versions
            .write()
            .expect("lock not poisoned")
            .insert(key, versions);
        self
    }

    pub fn with_metadata(
        self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        metadata: RegistryPackageMetadata,
    ) -> Self {
        let ver = Version::parse(version).expect("valid version string");
        let key = Self::metadata_key(&ecosystem, name, &ver);
        self.metadata
            .write()
            .expect("lock not poisoned")
            .insert(key, metadata);
        self
    }

    pub fn with_error(self, ecosystem: Ecosystem, name: &str, error: RegistryError) -> Self {
        let key = Self::versions_key(&ecosystem, name);
        self.errors
            .write()
            .expect("lock not poisoned")
            .insert(key, error);
        self
    }

    pub fn called_ecosystem(&self, ecosystem: &Ecosystem) -> bool {
        let eco_str = ecosystem.canonical_name();
        let lv_prefix = format!("list_versions:{}:", eco_str);
        let fm_prefix = format!("fetch_metadata:{}:", eco_str);
        self.calls
            .read()
            .expect("lock not poisoned")
            .iter()
            .any(|call| call.starts_with(&lv_prefix) || call.starts_with(&fm_prefix))
    }

    pub fn called_package(&self, ecosystem: &Ecosystem, name: &str) -> bool {
        let eco_str = ecosystem.canonical_name();
        let list_call = format!("list_versions:{}:{}", eco_str, name);
        let metadata_prefix = format!("fetch_metadata:{}:{}@", eco_str, name);
        self.calls
            .read()
            .expect("lock not poisoned")
            .iter()
            .any(|call| call == &list_call || call.starts_with(&metadata_prefix))
    }

    pub fn call_count(&self) -> usize {
        self.calls.read().expect("lock not poisoned").len()
    }

    pub fn reset() -> Self {
        Self::new()
    }
}

impl Default for MockRegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PackageRegistryClient for MockRegistryClient {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError> {
        let eco_str = ecosystem.canonical_name();
        self.calls
            .write()
            .expect("lock not poisoned")
            .push(format!("list_versions:{}:{}", eco_str, name));

        let key = format!("{}:{}", eco_str, name);

        if let Some(error) = self.errors.read().expect("lock not poisoned").get(&key) {
            return Err(error.clone());
        }

        self.versions
            .read()
            .expect("lock not poisoned")
            .get(&key)
            .cloned()
            .ok_or(RegistryError::NotFound)
    }

    async fn fetch_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &Version,
    ) -> Result<RegistryPackageMetadata, RegistryError> {
        let eco_str = ecosystem.canonical_name();
        self.calls
            .write()
            .expect("lock not poisoned")
            .push(format!("fetch_metadata:{}:{}@{}", eco_str, name, version));

        let err_key = format!("{}:{}", eco_str, name);
        if let Some(error) = self.errors.read().expect("lock not poisoned").get(&err_key) {
            return Err(error.clone());
        }

        let key = format!("{}:{}@{}", eco_str, name, version);
        self.metadata
            .read()
            .expect("lock not poisoned")
            .get(&key)
            .cloned()
            .ok_or(RegistryError::NotFound)
    }
}
