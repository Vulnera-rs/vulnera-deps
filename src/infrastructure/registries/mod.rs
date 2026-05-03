use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vulnera_advisor::{PackageRegistry, VersionRegistry};

use crate::domain::vulnerability::value_objects::{Ecosystem, Version};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version: Version,
    pub yanked: bool,
    pub is_prerelease: bool,
    pub published_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl VersionInfo {
    pub fn new(
        version: Version,
        yanked: bool,
        published_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Self {
        Self {
            version,
            yanked,
            is_prerelease: false,
            published_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryDependency {
    pub name: String,
    pub requirement: String,
    pub is_dev: bool,
    pub is_optional: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryPackageMetadata {
    pub name: String,
    pub version: Version,
    pub dependencies: Vec<RegistryDependency>,
    pub project_url: Option<String>,
    pub license: Option<String>,
}

#[derive(Error, Debug, Clone)]
pub enum RegistryError {
    #[error("Rate limited")]
    RateLimited,
    #[error("Not found")]
    NotFound,
    #[error("Unsupported ecosystem: {0}")]
    UnsupportedEcosystem(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("HTTP error: {message}")]
    Http {
        message: String,
        status: Option<u16>,
    },
    #[error("{0}")]
    Other(String),
}

#[async_trait]
pub trait PackageRegistryClient: Send + Sync {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError>;

    async fn fetch_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &Version,
    ) -> Result<RegistryPackageMetadata, RegistryError>;
}

pub struct VulneraRegistryAdapter {
    registry: PackageRegistry,
}

impl VulneraRegistryAdapter {
    pub fn new() -> Self {
        Self {
            registry: PackageRegistry::new(),
        }
    }

    pub fn with_registry(registry: PackageRegistry) -> Self {
        Self { registry }
    }
}

impl Default for VulneraRegistryAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PackageRegistryClient for VulneraRegistryAdapter {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError> {
        let eco_str = ecosystem.advisor_name();
        match self.registry.get_versions(eco_str, name).await {
            Ok(version_strings) => {
                let mut versions: Vec<VersionInfo> = version_strings
                    .iter()
                    .filter_map(|v| {
                        let parsed = Version::parse(v).ok()?;
                        Some(VersionInfo {
                            version: parsed,
                            yanked: false,
                            is_prerelease: v.contains('-')
                                || v.contains("alpha")
                                || v.contains("beta")
                                || v.contains("rc")
                                || v.contains("dev"),
                            published_at: None,
                        })
                    })
                    .collect();
                versions.sort_by(|a, b| a.version.cmp(&b.version));
                Ok(versions)
            }
            Err(e) => {
                let msg = e.to_string().to_lowercase();
                // Classify known error patterns. This is a best-effort approach;
                // ideally vulnera-advisor would expose structured error types.
                if msg.contains("not found") || msg.contains("404") {
                    Err(RegistryError::NotFound)
                } else if (msg.contains("rate") && msg.contains("limit")) || msg.contains("429") {
                    Err(RegistryError::RateLimited)
                } else {
                    Err(RegistryError::Http {
                        message: e.to_string(),
                        status: None,
                    })
                }
            }
        }
    }

    async fn fetch_metadata(
        &self,
        _ecosystem: Ecosystem,
        _name: &str,
        _version: &Version,
    ) -> Result<RegistryPackageMetadata, RegistryError> {
        // FIXME: vulnera-advisor's PackageRegistry does not expose per-version dependency
        // metadata. Until the advisor crate adds this capability, fetch_metadata returns
        // an error for callers that depend on dependency metadata (e.g., RecursiveResolver).
        // For full transitive resolution, use a lockfile-based parser instead.
        Err(RegistryError::Other(
            "dependency metadata per version not available from advisor; use a lockfile parser for transitive resolution".into(),
        ))
    }
}
