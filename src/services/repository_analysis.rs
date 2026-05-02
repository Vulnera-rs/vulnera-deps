//! Repository analysis service for GitHub repository scanning

use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tracing::debug;

use crate::application::errors::ApplicationError;
use crate::config::DepsConfig;
use crate::domain::vulnerability::entities::{Package, Vulnerability};
use crate::domain::vulnerability::repositories::VulnerabilityRepository;
use crate::domain::vulnerability::value_objects::Ecosystem;
use crate::infrastructure::parsers::ParserFactory;

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct RepositoryFile {
    pub path: String,
    pub size: u64,
    pub sha: Option<String>,
}

pub struct FetchedFileContent {
    pub path: String,
    pub content: String,
}

#[derive(Error, Debug, Clone)]
pub enum RepositorySourceError {
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Access denied: {0}")]
    AccessDenied(String),
    #[error("Rate limited: {message}")]
    RateLimited {
        message: String,
        retry_after: Option<u64>,
    },
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("{0}")]
    Other(String),
}

#[async_trait::async_trait]
pub trait RepositorySourceClient: Send + Sync {
    async fn list_repository_files(
        &self,
        owner: &str,
        repo: &str,
        reference: Option<&str>,
        max_files: u32,
        max_total_bytes: u64,
    ) -> Result<Vec<RepositoryFile>, RepositorySourceError>;

    async fn fetch_file_contents(
        &self,
        owner: &str,
        repo: &str,
        files: &[RepositoryFile],
        reference: Option<&str>,
        max_single_file_bytes: u64,
        max_concurrent_fetches: usize,
    ) -> Result<Vec<FetchedFileContent>, RepositorySourceError>;
}

/// Input for analyzing a repository (already validated & parsed from request/URL)
#[derive(Debug, Clone)]
pub struct RepositoryAnalysisInput {
    pub owner: String,
    pub repo: String,
    pub requested_ref: Option<String>,
    pub include_paths: Option<Vec<String>>,
    pub exclude_paths: Option<Vec<String>>,
    pub max_files: u32,
    pub include_lockfiles: bool,
    pub return_packages: bool,
}

/// Repository analysis file result (internal)
#[derive(Debug, Clone)]
pub struct RepositoryFileResultInternal {
    pub path: String,
    pub ecosystem: Option<Ecosystem>,
    pub packages: Vec<Package>,
    pub error: Option<String>,
}

/// Repository analysis aggregate result (internal) - transformed to DTO in controller
#[derive(Debug, Clone)]
pub struct RepositoryAnalysisInternalResult {
    pub id: uuid::Uuid,
    pub owner: String,
    pub repo: String,
    pub requested_ref: Option<String>,
    pub commit_sha: String,
    pub files: Vec<RepositoryFileResultInternal>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub severity_breakdown: crate::domain::vulnerability::entities::SeverityBreakdown,
    pub total_files_scanned: u32,
    pub analyzed_files: u32,
    pub skipped_files: u32,
    pub unique_packages: u32,
    pub duration: std::time::Duration,
    pub file_errors: u32,
    pub rate_limit_remaining: Option<u32>,
    pub truncated: bool,
}

/// Repository analysis service trait
#[async_trait]
pub trait RepositoryAnalysisService: Send + Sync {
    async fn analyze_repository(
        &self,
        input: RepositoryAnalysisInput,
    ) -> Result<RepositoryAnalysisInternalResult, ApplicationError>;
}

/// Repository analysis service implementation
pub struct RepositoryAnalysisServiceImpl<C: RepositorySourceClient> {
    source_client: Arc<C>,
    vuln_repo: Option<Arc<dyn VulnerabilityRepository>>,
    parser_factory: Arc<ParserFactory>,
    config: Arc<DepsConfig>,
}

impl<C: RepositorySourceClient> RepositoryAnalysisServiceImpl<C> {
    pub fn new(
        source_client: Arc<C>,
        vuln_repo: Option<Arc<dyn VulnerabilityRepository>>,
        parser_factory: Arc<ParserFactory>,
        config: Arc<DepsConfig>,
    ) -> Self {
        Self {
            source_client,
            vuln_repo,
            parser_factory,
            config,
        }
    }
}

#[async_trait]
impl<C: RepositorySourceClient + 'static> RepositoryAnalysisService
    for RepositoryAnalysisServiceImpl<C>
{
    #[tracing::instrument(skip(self, input))]
    async fn analyze_repository(
        &self,
        input: RepositoryAnalysisInput,
    ) -> Result<RepositoryAnalysisInternalResult, ApplicationError> {
        let start = std::time::Instant::now();
        let max_files = input
            .max_files
            .min(self.config.apis.github.max_files_scanned);
        let files = self
            .source_client
            .list_repository_files(
                &input.owner,
                &input.repo,
                input.requested_ref.as_deref(),
                max_files,
                self.config.apis.github.max_total_bytes,
            )
            .await
            .map_err(|e| match e {
                RepositorySourceError::NotFound(_) | RepositorySourceError::AccessDenied(_) => {
                    ApplicationError::NotFound {
                        resource: "repository".to_string(),
                        id: format!("{}/{}", &input.owner, &input.repo),
                    }
                }
                RepositorySourceError::RateLimited { message, .. } => {
                    ApplicationError::RateLimited { message }
                }
                RepositorySourceError::Validation(msg) => ApplicationError::Domain(
                    crate::domain::vulnerability::errors::VulnerabilityDomainError::InvalidInput {
                        field: "ref".into(),
                        message: msg,
                    },
                ),
                other => ApplicationError::Configuration {
                    message: format!("repository source error: {}", other),
                },
            })?;
        // Apply include/exclude filters
        let filtered: Vec<_> = files
            .into_iter()
            .filter(|f| {
                if let Some(ref includes) = input.include_paths
                    && !includes.iter().any(|p| f.path.starts_with(p))
                {
                    return false;
                }
                if let Some(ref excludes) = input.exclude_paths
                    && excludes.iter().any(|p| f.path.starts_with(p))
                {
                    return false;
                }
                true
            })
            .collect();

        // Identify candidate dependency files (those with a parser)
        let mut candidate_files = Vec::new();
        let mut total_bytes: u64 = 0;
        for f in &filtered {
            if f.size > self.config.apis.github.max_single_file_bytes {
                continue; // skip oversized file
            }
            if !input.include_lockfiles && is_lockfile_path(&f.path) {
                continue;
            }
            if self.parser_factory.create_parser(&f.path).is_some() {
                if total_bytes + f.size > self.config.apis.github.max_total_bytes {
                    break; // enforce total bytes cap
                }
                total_bytes += f.size;
                candidate_files.push(f.clone());
            }
        }

        // Fetch contents for candidate files
        let fetched = if candidate_files.is_empty() {
            Vec::new()
        } else {
            self.source_client
                .fetch_file_contents(
                    &input.owner,
                    &input.repo,
                    &candidate_files,
                    input.requested_ref.as_deref(),
                    self.config.apis.github.max_single_file_bytes,
                    self.config.apis.github.max_concurrent_file_fetches,
                )
                .await
                .map_err(|e| match e {
                    RepositorySourceError::RateLimited {
                        ..
                    } => ApplicationError::RateLimited {
                        message: e.to_string(),
                    },
                    RepositorySourceError::NotFound(_)
                    | RepositorySourceError::AccessDenied(
                        _,
                    ) => ApplicationError::NotFound {
                        resource: "file contents".into(),
                        id: format!("{}/{}", &input.owner, &input.repo),
                    },
                    RepositorySourceError::Validation(
                        msg,
                    ) => ApplicationError::Domain(
                        crate::domain::vulnerability::errors::VulnerabilityDomainError::InvalidInput {
                            field: "ref".into(),
                            message: msg,
                        },
                    ),
                    other => ApplicationError::Configuration {
                        message: format!("repository source error: {}", other),
                    },
                })?
        };

        // Map path -> content for quick lookup
        let mut content_map: HashMap<String, String> = HashMap::new();
        for fc in fetched {
            content_map.insert(fc.path, fc.content);
        }

        // Parse files
        let mut parsed_files: Vec<RepositoryFileResultInternal> = Vec::new();
        let mut unique_packages: HashMap<String, Package> = HashMap::new();
        let mut file_errors = 0u32;

        for file in &candidate_files {
            let ecosystem = self.parser_factory.detect_ecosystem(&file.path);
            if let Some(content) = content_map.get(&file.path) {
                if let Some(parser) = self.parser_factory.create_parser(&file.path) {
                    match parser.parse(content) {
                        Ok(parse_result) => {
                            for p in &parse_result.packages {
                                unique_packages
                                    .entry(p.identifier())
                                    .or_insert_with(|| p.clone());
                            }
                            parsed_files.push(RepositoryFileResultInternal {
                                path: file.path.clone(),
                                ecosystem,
                                packages: if input.return_packages {
                                    parse_result.packages
                                } else {
                                    vec![]
                                },
                                error: None,
                            });
                        }
                        Err(e) => {
                            file_errors += 1;
                            parsed_files.push(RepositoryFileResultInternal {
                                path: file.path.clone(),
                                ecosystem,
                                packages: vec![],
                                error: Some(e.to_string()),
                            });
                        }
                    }
                }
            } else {
                // content missing (fetch failed)
                file_errors += 1;
                parsed_files.push(RepositoryFileResultInternal {
                    path: file.path.clone(),
                    ecosystem,
                    packages: vec![],
                    error: Some("content not fetched".into()),
                });
            }
        }

        // Vulnerability lookup
        let mut all_vulns: Vec<Vulnerability> = Vec::new();
        if let Some(vuln_repo) = &self.vuln_repo {
            for pkg in unique_packages.values() {
                match vuln_repo.find_vulnerabilities(pkg).await {
                    Ok(mut v) => {
                        let before = v.len();
                        v.retain(|vv| vv.affects_package(pkg));
                        let after = v.len();
                        debug!(
                            "filtered repository vulnerabilities by version: package={} total={} affecting={}",
                            pkg.identifier(),
                            before,
                            after
                        );
                        all_vulns.append(&mut v)
                    }
                    Err(e) => debug!("vuln lookup failed for package {}: {}", pkg.identifier(), e),
                }
            }
        }
        // Deduplicate vulnerabilities by id
        let mut seen = HashSet::new();
        all_vulns.retain(|v| seen.insert(v.id.as_str().to_string()));
        let severity_breakdown =
            crate::domain::vulnerability::entities::SeverityBreakdown::from_vulnerabilities(
                &all_vulns,
            );

        let internal = RepositoryAnalysisInternalResult {
            id: uuid::Uuid::new_v4(),
            owner: input.owner.clone(),
            repo: input.repo.clone(),
            requested_ref: input.requested_ref.clone(),
            // FIXME: commit_sha should be the resolved Git SHA, not the requested ref.
            // The source client should return the resolved SHA; until that capability is
            // added, store the requested ref with a best-effort note.
            commit_sha: input
                .requested_ref
                .clone()
                .unwrap_or_else(|| "HEAD".to_string()),
            files: parsed_files,
            vulnerabilities: all_vulns.clone(),
            severity_breakdown,
            total_files_scanned: filtered.len() as u32,
            analyzed_files: candidate_files.len() as u32,
            skipped_files: (filtered.len() - candidate_files.len()) as u32,
            unique_packages: unique_packages.len() as u32,
            duration: start.elapsed(),
            file_errors,
            rate_limit_remaining: None,
            truncated: (filtered.len() as u32) >= max_files
                || total_bytes >= self.config.apis.github.max_total_bytes,
        };
        Ok(internal)
    }
}

fn is_lockfile_path(path: &str) -> bool {
    let file_name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();

    matches!(
        file_name.as_str(),
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "npm-shrinkwrap.json"
            | "pipfile.lock"
            | "poetry.lock"
            | "cargo.lock"
            | "go.sum"
            | "composer.lock"
            | "gemfile.lock"
            | "packages.lock.json"
            | "paket.lock"
    )
}
