//! Vulnera Dependency Analyzer - Multi-ecosystem vulnerability scanning
//!
//! This crate provides dependency vulnerability analysis across multiple package ecosystems,
//! aggregating vulnerability data from OSV, NVD, and GitHub Security Advisories.
//!
//! # Supported Ecosystems
//!
//! | Ecosystem | Files |
//! |-----------|-------|
//! | npm | `package.json`, `package-lock.json`, `yarn.lock` |
//! | PyPI | `requirements.txt`, `Pipfile`, `pyproject.toml` |
//! | Maven | `pom.xml`, `build.gradle` |
//! | Cargo | `Cargo.toml`, `Cargo.lock` |
//! | Go | `go.mod`, `go.sum` |
//! | Composer | `composer.json`, `composer.lock` |
//! | RubyGems | `Gemfile`, `Gemfile.lock` |
//! | NuGet | `*.csproj`, `packages.config` |
//!
//! # Features
//!
//! - **Concurrent Processing** - Parallel package analysis with configurable limits
//! - **Version Resolution** - Registry integration for accurate version lookup
//! - **Safe Recommendations** - Upgrade suggestions with impact classification
//! - **CVE Aggregation** - Combined data from multiple vulnerability sources
//!
//! # Usage
//!
//! ```rust,ignore
//! use vulnera_deps::DependencyAnalyzerModule;
//! use vulnera_contract::config::DependencyConfig;
//!
//! let module = DependencyAnalyzerModule::new(config, osv_client, nvd_client, ghsa_client);
//! let results = module.analyze(input).await?;
//! ```
//!
//! # Architecture
//!
//! ```text
//! vulnera-deps/
//! ├── domain/         # Package, Vulnerability entities
//! ├── application/    # Analysis use cases
//! ├── services/       # Repository analysis service
//! ├── types/          # Version resolution traits
//! └── module.rs       # AnalysisModule implementation
//! ```

pub mod application;
pub mod config;
pub mod domain;
pub mod infrastructure;
pub mod module;
pub mod services;
pub mod types;
pub mod use_cases;

// Core configuration types
pub use config::*;

// Domain types needed by consumers
pub use domain::dependency_graph::*;
pub use domain::source_location::*;
pub use domain::version_constraint::*;
pub use domain::vulnerability::entities::*;
pub use domain::vulnerability::repositories::*;
pub use domain::vulnerability::value_objects::*;

// Application types
pub use application::analysis_context::{AnalysisConfig, AnalysisContext, WorkspaceInfo};
pub use application::errors::{ApiError, ApplicationError, VulnerabilityError};
pub use application::events::{DependencyEvent, EventEmitter};

// Infrastructure types consumed externally
pub use infrastructure::parsers::{ParseResult, ParserFactory};

// Service traits and types
pub use services::cache::CacheService;
pub use services::contamination::{ContaminationPathAnalyzer, ContaminationResult};
pub use services::dependency_resolver::{DependencyResolverService, DependencyResolverServiceImpl};
pub use services::graph::{GraphEdge, GraphNode, UnifiedDependencyGraph};
pub use services::remediation::{
    BumpType, ConstraintRelaxationPoint, RemediationPlan, RemediationResolver,
};
pub use services::repository_analysis::{
    RepositoryAnalysisInput, RepositoryAnalysisInternalResult, RepositoryAnalysisService,
    RepositoryAnalysisServiceImpl, RepositoryFileResultInternal,
};

// Module entry point
pub use module::*;

// Shared types
pub use types::*;
pub use use_cases::AnalyzeDependenciesUseCase;
