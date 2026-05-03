use serde::Deserialize;

#[derive(Debug, Default, Clone, Deserialize)]
pub struct ApisConfig {
    #[serde(default)]
    pub github: GithubApiConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubApiConfig {
    #[serde(default = "default_max_files_scanned")]
    pub max_files_scanned: u32,
    #[serde(default = "default_max_total_bytes")]
    pub max_total_bytes: u64,
    #[serde(default = "default_max_single_file_bytes")]
    pub max_single_file_bytes: u64,
    #[serde(default = "default_max_concurrent_file_fetches")]
    pub max_concurrent_file_fetches: usize,
}

fn default_max_files_scanned() -> u32 {
    500
}
fn default_max_total_bytes() -> u64 {
    50 * 1024 * 1024
}
fn default_max_single_file_bytes() -> u64 {
    2 * 1024 * 1024
}
fn default_max_concurrent_file_fetches() -> usize {
    4
}

impl Default for GithubApiConfig {
    fn default() -> Self {
        Self {
            max_files_scanned: default_max_files_scanned(),
            max_total_bytes: default_max_total_bytes(),
            max_single_file_bytes: default_max_single_file_bytes(),
            max_concurrent_file_fetches: default_max_concurrent_file_fetches(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct DepsConfig {
    pub apis: ApisConfig,
    pub analysis: DepsAnalysisConfig,
}

#[derive(Debug, Clone)]
pub struct DepsAnalysisConfig {
    pub max_concurrent_packages: usize,
    pub max_concurrent_registry_queries: usize,
}

impl Default for DepsAnalysisConfig {
    fn default() -> Self {
        Self {
            max_concurrent_packages: 8,
            max_concurrent_registry_queries: 10,
        }
    }
}
