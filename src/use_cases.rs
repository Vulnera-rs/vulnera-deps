//! Vulnerability analysis use cases

use std::sync::Arc;
use std::time::Instant;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use crate::application::errors::ApplicationError;
use crate::application::events::{DependencyEvent, EventEmitter};
use crate::domain::vulnerability::{
    entities::{AnalysisReport, Package, Vulnerability},
    value_objects::Ecosystem,
};
use crate::services::cache::CacheService;

use crate::infrastructure::parsers::{ParseResult, ParserFactory};
use crate::infrastructure::registries::{PackageRegistryClient, VulneraRegistryAdapter};

use crate::application::analysis_context::{AnalysisContext, detect_workspace};
use crate::domain::{DependencyGraph, PackageId};
use crate::services::contamination::ContaminationPathAnalyzer;
use crate::services::graph::UnifiedDependencyGraph;
use crate::services::remediation::RemediationResolver;
use crate::services::resolution_algorithms::{BacktrackingResolver, LexicographicOptimizer};
use crate::services::{
    dependency_resolver::{DependencyResolverService, DependencyResolverServiceImpl},
    resolution::RecursiveResolver,
};
use std::collections::HashMap;
use std::path::PathBuf;
use vulnera_advisor::{PackageRegistry, VulnerabilityManager};

/// Use case for analyzing dependencies from a file
pub struct AnalyzeDependenciesUseCase<C: CacheService + 'static> {
    parser_factory: Arc<ParserFactory>,
    advisor: Arc<VulnerabilityManager>,
    cache_service: Arc<C>,
    max_concurrent_requests: usize,
    max_concurrent_registry_queries: usize,
    dependency_resolver: Arc<dyn DependencyResolverService>,
    recursive_resolver: Arc<RecursiveResolver<C>>,
    analysis_context: Option<Arc<AnalysisContext>>,
    remediation_resolver: Arc<RemediationResolver>,
    event_emitter: Arc<dyn EventEmitter>,
}

impl<C: CacheService + 'static> AnalyzeDependenciesUseCase<C> {
    /// Create a new use case instance
    pub fn new(
        parser_factory: Arc<ParserFactory>,
        advisor: Arc<VulnerabilityManager>,
        registry: Arc<PackageRegistry>,
        cache_service: Arc<C>,
        max_concurrent_requests: usize,
        event_emitter: Arc<dyn EventEmitter>,
    ) -> Self {
        let dependency_resolver = Arc::new(DependencyResolverServiceImpl::new());
        let remediation_resolver =
            Arc::new(RemediationResolver::new(advisor.clone(), registry.clone()));
        let registry_client = Arc::new(VulneraRegistryAdapter::new());
        let recursive_resolver = Arc::new(RecursiveResolver::new(
            registry_client,
            cache_service.clone(),
            5,
        ));
        Self {
            parser_factory,
            advisor,
            cache_service,
            max_concurrent_requests,
            max_concurrent_registry_queries: 5,
            dependency_resolver,
            recursive_resolver,
            analysis_context: None,
            remediation_resolver,
            event_emitter,
        }
    }

    /// Create a new use case instance with full configuration
    pub fn new_with_config(
        parser_factory: Arc<ParserFactory>,
        advisor: Arc<VulnerabilityManager>,
        registry: Arc<PackageRegistry>,
        cache_service: Arc<C>,
        max_concurrent_requests: usize,
        max_concurrent_registry_queries: usize,
        event_emitter: Arc<dyn EventEmitter>,
    ) -> Self {
        let dependency_resolver = Arc::new(DependencyResolverServiceImpl::new());
        let remediation_resolver =
            Arc::new(RemediationResolver::new(advisor.clone(), registry.clone()));
        let registry_client = Arc::new(VulneraRegistryAdapter::new());
        let recursive_resolver = Arc::new(RecursiveResolver::new(
            registry_client,
            cache_service.clone(),
            5,
        ));
        Self {
            parser_factory,
            advisor,
            cache_service,
            max_concurrent_requests,
            max_concurrent_registry_queries,
            dependency_resolver,
            recursive_resolver,
            analysis_context: None,
            remediation_resolver,
            event_emitter,
        }
    }

    /// Create a new use case instance with analysis context
    pub fn new_with_context(
        parser_factory: Arc<ParserFactory>,
        advisor: Arc<VulnerabilityManager>,
        registry: Arc<PackageRegistry>,
        cache_service: Arc<C>,
        max_concurrent_requests: usize,
        max_concurrent_registry_queries: usize,
        project_root: Option<PathBuf>,
        event_emitter: Arc<dyn EventEmitter>,
    ) -> Self {
        let dependency_resolver = Arc::new(DependencyResolverServiceImpl::new());
        let remediation_resolver =
            Arc::new(RemediationResolver::new(advisor.clone(), registry.clone()));
        let registry_client = Arc::new(VulneraRegistryAdapter::new());
        let recursive_resolver = Arc::new(RecursiveResolver::new(
            registry_client,
            cache_service.clone(),
            5,
        ));
        let analysis_context = project_root.map(|root| Arc::new(AnalysisContext::new(root)));
        Self {
            parser_factory,
            advisor,
            cache_service,
            max_concurrent_requests,
            max_concurrent_registry_queries,
            dependency_resolver,
            recursive_resolver,
            analysis_context,
            remediation_resolver,
            event_emitter,
        }
    }

    /// Execute the use case to analyze dependencies
    /// Returns both the analysis report and the dependency graph
    pub async fn execute(
        &self,
        file_content: &str,
        ecosystem: Ecosystem,
        filename: Option<&str>,
    ) -> Result<(AnalysisReport, DependencyGraph), ApplicationError> {
        let start_time = Instant::now();
        info!(
            "Starting dependency analysis for ecosystem: {:?}",
            ecosystem
        );

        self.event_emitter
            .emit(DependencyEvent::AnalysisStarted {
                file_path: filename.unwrap_or("unknown").to_string(),
                ecosystem: ecosystem.to_string(),
            })
            .await;

        // Use analysis context for workspace detection and caching if available
        let file_path = filename.map(PathBuf::from);
        if let (Some(ctx), Some(path)) = (&self.analysis_context, &file_path) {
            // Check if file should be ignored
            if ctx.should_ignore(path) {
                info!("File {} is ignored by analysis context", path.display());
                let empty_graph = DependencyGraph::new();
                return Ok((
                    AnalysisReport::new(
                        vec![],
                        vec![],
                        start_time.elapsed(),
                        vec!["File ignored".to_string()],
                        false,
                        0,
                        0,
                    ),
                    empty_graph,
                ));
            }

            // Check if file needs re-analysis (cache check)
            if !ctx.needs_analysis(path) {
                debug!(
                    "File {} is up-to-date in cache, attempting to retrieve cached results",
                    path.display()
                );

                // Try to retrieve cached results
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                file_content.hash(&mut hasher);
                let content_hash = hasher.finish();
                let cache_key = format!("analysis_result:{}:{}", path.display(), content_hash);

                // Try to get cached report and graph
                if let Ok(Some(cached_result)) = self
                    .cache_service
                    .get::<(AnalysisReport, DependencyGraph)>(&cache_key)
                    .await
                {
                    info!("Retrieved cached analysis results for {}", path.display());
                    return Ok(cached_result);
                } else {
                    debug!(
                        "No cached results found for {}, proceeding with analysis",
                        path.display()
                    );
                }
            }

            // Detect workspace if not already detected
            if ctx.workspace.is_none()
                && let Some(workspace) = detect_workspace(&ctx.project_root)
            {
                // Note: We can't mutate ctx here, but we could update it in a future version
                debug!("Detected workspace: {:?}", workspace);
            }
        }

        // Precompute Cargo resolution flag before moving ecosystem
        let do_cargo_resolution = matches!(ecosystem, Ecosystem::Cargo)
            && filename.map(|f| f.ends_with("Cargo.toml")).unwrap_or(false);

        // Parse the dependency file
        let parse_result = match self.parse_dependencies(file_content, ecosystem.clone(), filename)
        {
            Ok(result) => result,
            Err(e) => {
                self.event_emitter
                    .emit(DependencyEvent::AnalysisError {
                        file_path: filename.unwrap_or("unknown").to_string(),
                        error: e.to_string(),
                    })
                    .await;
                return Err(e);
            }
        };
        let mut packages = parse_result.packages;
        let dependencies = parse_result.dependencies;

        for pkg in &packages {
            self.event_emitter
                .emit(DependencyEvent::PackageParsed {
                    package: pkg.clone(),
                    location: None,
                })
                .await;
        }

        if packages.is_empty() {
            warn!("No packages found in dependency file");
            let analysis_duration = start_time.elapsed();
            let empty_graph = DependencyGraph::new();
            return Ok((
                AnalysisReport::new(
                    packages,
                    vec![],
                    analysis_duration,
                    vec!["No packages found".to_string()],
                    false,
                    0,
                    0,
                ),
                empty_graph,
            ));
        }

        // Build dependency graph using DependencyResolverService
        let mut dependency_graph = match self
            .dependency_resolver
            .build_graph(packages.clone(), dependencies, ecosystem.clone())
            .await
        {
            Ok(graph) => graph,
            Err(e) => {
                self.event_emitter
                    .emit(DependencyEvent::AnalysisError {
                        file_path: filename.unwrap_or("unknown").to_string(),
                        error: e.to_string(),
                    })
                    .await;
                return Err(e);
            }
        };

        // If the graph is empty (manifest-only project without lockfile),
        // use the RecursiveResolver to perform a deep subtree resolution.
        if dependency_graph.dependency_count() == 0 && !packages.is_empty() {
            debug!(
                "No dependency edges found for {:?}. Triggering recursive resolution for deep analysis.",
                ecosystem
            );
            match self
                .recursive_resolver
                .resolve(packages.clone(), ecosystem.clone())
                .await
            {
                Ok(res) => {
                    dependency_graph = res.graph;
                    debug!(
                        "Recursive resolution completed: {} packages, {} dependencies",
                        dependency_graph.package_count(),
                        dependency_graph.dependency_count()
                    );
                }
                Err(e) => {
                    warn!(
                        "Recursive resolution failed, falling back to flat analysis: {}",
                        e
                    );
                }
            }
        } else {
            debug!(
                "Built dependency graph: {} packages, {} dependencies",
                dependency_graph.package_count(),
                dependency_graph.dependency_count()
            );
        }

        // Final synchronization: ensure the packages list matches the nodes in the graph.
        // This ensures that any packages discovered during resolution are included in the analysis.
        // We filter out the project root node if it's present in the graph but not in the original
        // packages list, as it's typically the starting point rather than a dependency to be scanned.
        let mut final_packages = Vec::new();
        let initial_package_ids: std::collections::HashSet<_> =
            packages.iter().map(PackageId::from_package).collect();

        for node in dependency_graph.nodes.values() {
            let pkg = &node.package;
            let id = &node.id;

            // Include if it's an original package OR discovered transitive dependency (has incoming edges).
            let has_incoming = dependency_graph.edges.iter().any(|e| &e.to == id);

            if (initial_package_ids.contains(id) || has_incoming)
                && !final_packages
                    .iter()
                    .any(|p: &Package| p.name == pkg.name && p.version == pkg.version)
            {
                final_packages.push(pkg.clone());
            }
        }
        packages = final_packages;

        // Keep the graph in sync with the filtered packages list
        let final_package_ids: std::collections::HashSet<_> =
            packages.iter().map(PackageId::from_package).collect();
        dependency_graph
            .nodes
            .retain(|id, _| final_package_ids.contains(id));
        dependency_graph
            .edges
            .retain(|e| final_package_ids.contains(&e.from) && final_package_ids.contains(&e.to));
        dependency_graph
            .root_packages
            .retain(|id| final_package_ids.contains(id));

        // Resolve Cargo.toml minor/major specs to latest available version from crates.io (caret semantics)
        // Use parallel processing for better performance
        if do_cargo_resolution {
            let cargo_packages: Vec<_> = packages
                .iter()
                .enumerate()
                .filter_map(|(idx, pkg)| {
                    if matches!(pkg.ecosystem, Ecosystem::Cargo) {
                        Some((idx, pkg))
                    } else {
                        None
                    }
                })
                .collect();

            if !cargo_packages.is_empty() {
                // Process registry queries in parallel with bounded concurrency
                let semaphore = Arc::new(tokio::sync::Semaphore::new(
                    self.max_concurrent_registry_queries,
                ));
                let mut join_set: JoinSet<
                    Result<
                        (
                            usize,
                            Option<crate::domain::vulnerability::value_objects::Version>,
                        ),
                        ApplicationError,
                    >,
                > = JoinSet::new();

                for (idx, pkg) in cargo_packages {
                    let pkg_name = pkg.name.clone();
                    let lower = pkg.version.clone();
                    let upper = if lower.0.major > 0 {
                        crate::domain::vulnerability::value_objects::Version::new(
                            lower.0.major + 1,
                            0,
                            0,
                        )
                    } else if lower.0.minor > 0 {
                        crate::domain::vulnerability::value_objects::Version::new(
                            0,
                            lower.0.minor + 1,
                            0,
                        )
                    } else {
                        crate::domain::vulnerability::value_objects::Version::new(
                            0,
                            0,
                            lower.0.patch + 1,
                        )
                    };
                    let permit = Arc::clone(&semaphore);

                    join_set.spawn(async move {
                        let _permit = permit.acquire().await.map_err(|e| {
                            ApplicationError::Vulnerability(
                                crate::application::errors::VulnerabilityError::Api(
                                    crate::application::errors::ApiError::Http {
                                        status: 500,
                                        message: format!("Failed to acquire semaphore: {}", e),
                                    },
                                ),
                            )
                        })?;
                        // Create a new registry client instance for each task
                        let registry = VulneraRegistryAdapter::new();
                        match registry.list_versions(Ecosystem::Cargo, &pkg_name).await {
                            Ok(mut vers) => {
                                // Prefer stable, non-yanked versions within [lower, upper)
                                vers.retain(|vi| {
                                    !vi.yanked
                                        && !vi.is_prerelease
                                        && vi.version >= lower
                                        && vi.version < upper
                                });
                                // Use LexicographicOptimizer to select best version
                                // (prefers patch > minor > major upgrades)
                                let candidate_versions: Vec<_> =
                                    vers.iter().map(|vi| vi.version.clone()).collect();
                                let selected = LexicographicOptimizer::select_version(
                                    Some(&lower),
                                    &candidate_versions,
                                );
                                Ok((
                                    idx,
                                    selected.and_then(|v| if v > lower { Some(v) } else { None }),
                                ))
                            }
                            Err(e) => {
                                debug!(
                                    "crates.io version resolution failed for {}: {}",
                                    pkg_name, e
                                );
                                Ok((idx, None))
                            }
                        }
                    });
                }

                // Collect results and update packages
                while let Some(result) = join_set.join_next().await {
                    match result {
                        Ok(Ok((idx, Some(resolved_version)))) => {
                            if let Some(pkg) = packages.get_mut(idx)
                                && resolved_version > pkg.version
                            {
                                debug!(
                                    "Resolved Cargo.toml spec for {}: {} -> {}",
                                    pkg.name, pkg.version, resolved_version
                                );
                                pkg.version = resolved_version;
                            }
                        }
                        Ok(Ok((_idx, None))) => {
                            // Resolution failed, keep original version
                        }
                        Ok(Err(e)) => {
                            warn!("Error during parallel Cargo version resolution: {}", e);
                        }
                        Err(e) => {
                            warn!("Join error during parallel Cargo version resolution: {}", e);
                        }
                    }
                }
            }
        }

        info!(
            "Parsed {} packages from dependency file (graph has {} packages)",
            packages.len(),
            dependency_graph.package_count()
        );

        // Convert packages to Arc for shared ownership to avoid cloning
        let packages_arc: Vec<Arc<Package>> =
            packages.iter().map(|p| Arc::new(p.clone())).collect();

        // Look up vulnerabilities for all packages concurrently
        let vulnerabilities = match self
            .process_packages_concurrently_arc(&packages_arc, self.event_emitter.clone())
            .await
        {
            Ok(v) => v,
            Err(e) => {
                self.event_emitter
                    .emit(DependencyEvent::AnalysisError {
                        file_path: filename.unwrap_or("unknown").to_string(),
                        error: e.to_string(),
                    })
                    .await;
                return Err(e);
            }
        };

        // Build UnifiedDependencyGraph for path analysis
        let unified_graph = UnifiedDependencyGraph::from_dependency_graph(&dependency_graph)
            .unwrap_or_else(|_| UnifiedDependencyGraph::new());

        // Run contamination analysis for each vulnerability
        let root_ids: Vec<PackageId> = dependency_graph.root_packages.clone();
        let mut total_contamination_paths = 0usize;
        let mut contaminated_vulnerabilities = 0usize;
        for vuln in &vulnerabilities {
            let mut vuln_contaminated = false;
            for affected in &vuln.affected_packages {
                self.event_emitter
                    .emit(DependencyEvent::VulnerabilityFound {
                        package: affected.package.clone(),
                        vulnerability: vuln.clone(),
                    })
                    .await;

                let pkg_id = PackageId::from_package(&affected.package);
                for root in &root_ids {
                    let result = ContaminationPathAnalyzer::analyze(&unified_graph, root, &pkg_id);
                    if result.contaminated {
                        vuln_contaminated = true;
                        total_contamination_paths += result.path_count;
                        debug!(
                            "Contamination path from {:?} to {:?}: {} paths (truncated: {})",
                            root, pkg_id, result.path_count, result.truncated
                        );
                    }
                }

                // Resolve remediation
                match self
                    .remediation_resolver
                    .resolve(&unified_graph, &pkg_id, &affected.package.version)
                    .await
                {
                    Ok(plan) => {
                        debug!(
                            "Remediation for {}: nearest={:?}, latest={:?}, bump={:?}",
                            pkg_id, plan.nearest_safe, plan.latest_safe, plan.bump_type
                        );
                    }
                    Err(e) => {
                        warn!("Failed to resolve remediation for {}: {}", pkg_id, e);
                    }
                }
            }
            if vuln_contaminated {
                contaminated_vulnerabilities += 1;
            }
        }

        let analysis_duration = start_time.elapsed();
        let sources_queried = {
            let mut set = std::collections::BTreeSet::new();
            set.insert("vulnera-advisor".to_string());
            for v in &vulnerabilities {
                for src in &v.sources {
                    set.insert(format!("{:?}", src));
                }
            }
            if set.is_empty() {
                vec!["OSV".to_string(), "NVD".to_string()]
            } else {
                set.into_iter().collect()
            }
        };

        // Use BacktrackingResolver for complex constraint resolution if needed
        // This could be used for resolving version conflicts in the dependency graph
        if dependency_graph.dependency_count() > 0 {
            debug!(
                "Dependency graph available with {} edges for constraint resolution",
                dependency_graph.dependency_count()
            );

            // Fetch available versions for all packages in the graph
            match self
                .get_available_versions(&dependency_graph, ecosystem.clone())
                .await
            {
                Ok(available_versions) => {
                    if !available_versions.is_empty() {
                        let resolution_result =
                            BacktrackingResolver::resolve(&dependency_graph, &available_versions);
                        if !resolution_result.conflicts.is_empty() {
                            warn!(
                                "Found {} dependency conflicts in the dependency graph",
                                resolution_result.conflicts.len()
                            );
                            for conflict in &resolution_result.conflicts {
                                warn!("Conflict for {}: {}", conflict.package, conflict.message);
                            }
                        } else {
                            debug!(
                                "Successfully resolved {} packages with no conflicts",
                                resolution_result.resolved.len()
                            );
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to fetch available versions for conflict resolution: {}",
                        e
                    );
                    // Continue without conflict resolution - this is best-effort
                }
            }
        }

        let packages_found = packages.len();
        let vulnerabilities_found = vulnerabilities.len();

        let contamination_completed = !root_ids.is_empty();
        let report = AnalysisReport::new(
            packages,
            vulnerabilities,
            analysis_duration,
            sources_queried,
            contamination_completed,
            total_contamination_paths,
            contaminated_vulnerabilities,
        );

        info!(
            "Analysis completed in {:?}: {} packages, {} vulnerabilities (graph: {} nodes, {} edges)",
            analysis_duration,
            report.metadata.total_packages,
            report.metadata.total_vulnerabilities,
            dependency_graph.package_count(),
            dependency_graph.dependency_count()
        );

        // Store results in cache if analysis context is available
        if let (Some(_ctx), Some(path)) = (&self.analysis_context, &file_path) {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            file_content.hash(&mut hasher);
            let content_hash = hasher.finish();
            let cache_key = format!("analysis_result:{}:{}", path.display(), content_hash);

            // Cache the results with a TTL of 24 hours
            let cache_ttl = std::time::Duration::from_secs(24 * 3600);
            let result_to_cache = (report.clone(), dependency_graph.clone());
            if let Err(e) = self
                .cache_service
                .set(&cache_key, &result_to_cache, cache_ttl)
                .await
            {
                warn!(
                    "Failed to cache analysis results for {}: {}",
                    path.display(),
                    e
                );
            } else {
                debug!("Cached analysis results for {}", path.display());
            }
        }

        self.event_emitter
            .emit(DependencyEvent::AnalysisCompleted {
                file_path: filename.unwrap_or("unknown").to_string(),
                packages_found,
                vulnerabilities_found,
                duration_ms: analysis_duration.as_millis() as u64,
            })
            .await;

        Ok((report, dependency_graph))
    }

    /// Parse dependency file content into packages
    fn parse_dependencies(
        &self,
        file_content: &str,
        ecosystem: Ecosystem,
        filename: Option<&str>,
    ) -> Result<ParseResult, ApplicationError> {
        // Try to find a parser based on filename first
        if let Some(filename) = filename
            && let Some(parser) = self.parser_factory.create_parser(filename)
        {
            debug!("Using parser for filename: {}", filename);
            return parser.parse(file_content).map_err(ApplicationError::Parse);
        }

        // Fall back to ecosystem-based parsing by trying common filenames for the ecosystem
        let common_filenames = match ecosystem {
            Ecosystem::Npm => vec!["package.json", "package-lock.json", "yarn.lock"],
            Ecosystem::PyPI => vec![
                "uv.lock",
                "poetry.lock",
                "Pipfile.lock",
                "requirements.txt",
                "Pipfile",
                "pyproject.toml",
            ],
            Ecosystem::Maven => vec!["pom.xml"],
            Ecosystem::Cargo => vec!["Cargo.toml", "Cargo.lock"],
            Ecosystem::Go => vec!["go.mod", "go.sum"],
            Ecosystem::Packagist => vec!["composer.json", "composer.lock"],
            _ => vec![],
        };

        // Try each common filename for the ecosystem
        for filename in common_filenames {
            if let Some(parser) = self.parser_factory.create_parser(filename) {
                debug!(
                    "Using parser for ecosystem {:?} with filename: {}",
                    ecosystem, filename
                );
                return parser.parse(file_content).map_err(ApplicationError::Parse);
            }
        }

        error!("No parser found for ecosystem: {:?}", ecosystem);
        Err(ApplicationError::InvalidEcosystem {
            ecosystem: format!("{:?}", ecosystem),
        })
    }

    /// Process packages concurrently with proper error handling and bounded concurrency
    /// Uses Arc<Package> to avoid unnecessary cloning
    async fn process_packages_concurrently_arc(
        &self,
        packages: &[Arc<Package>],
        event_emitter: Arc<dyn EventEmitter>,
    ) -> Result<Vec<Vulnerability>, ApplicationError> {
        let mut all_vulnerabilities = Vec::new();
        let mut join_set: JoinSet<Result<Vec<Vulnerability>, ApplicationError>> = JoinSet::new();

        for chunk in packages.chunks(self.max_concurrent_requests) {
            for package_arc in chunk {
                let advisor = self.advisor.clone();
                let cache_service = self.cache_service.clone();
                let package_clone = Arc::clone(package_arc);
                let cache_key = crate::services::cache::package_vulnerabilities_key(&package_clone);
                let emitter = event_emitter.clone();

                join_set.spawn(async move {
                    // Check cache
                    if let Ok(Some(cached)) =
                        cache_service.get::<Vec<Vulnerability>>(&cache_key).await
                    {
                        emitter
                            .emit(DependencyEvent::CacheHit {
                                package_id: PackageId::from_package(&package_clone),
                            })
                            .await;
                        let filtered: Vec<Vulnerability> = cached
                            .into_iter()
                            .filter(|v| v.affects_package(&package_clone))
                            .collect();
                        return Ok(filtered);
                    }

                    emitter
                        .emit(DependencyEvent::CacheMiss {
                            package_id: PackageId::from_package(&package_clone),
                        })
                        .await;

                    // Query real advisor
                    let eco_str = package_clone.ecosystem.advisor_name();
                    let ver_str = package_clone.version.to_string();
                    match advisor
                        .matches(eco_str, &package_clone.name, &ver_str)
                        .await
                    {
                        Ok(advisories) => {
                            let vulnerabilities: Vec<Vulnerability> = advisories
                                .into_iter()
                                .filter_map(|a| advisory_to_vulnerability(a, &package_clone))
                                .collect();

                            // Cache filtered results
                            let cache_ttl = std::time::Duration::from_secs(24 * 3600);
                            let _ = cache_service
                                .set(&cache_key, &vulnerabilities, cache_ttl)
                                .await;

                            Ok(vulnerabilities)
                        }
                        Err(e) => {
                            warn!(
                                "Failed to query advisor for {}: {}",
                                package_clone.identifier(),
                                e
                            );
                            Ok(vec![])
                        }
                    }
                });
            }

            while let Some(result) = join_set.join_next().await {
                match result {
                    Ok(Ok(vulns)) => all_vulnerabilities.extend(vulns),
                    Ok(Err(e)) => warn!("Package processing error: {}", e),
                    Err(e) => warn!("Join error: {}", e),
                }
            }
        }

        Ok(all_vulnerabilities)
    }

    /// Helper method to fetch available versions for all packages in a dependency graph
    async fn get_available_versions(
        &self,
        graph: &DependencyGraph,
        ecosystem: Ecosystem,
    ) -> Result<
        HashMap<PackageId, Vec<crate::domain::vulnerability::value_objects::Version>>,
        ApplicationError,
    > {
        use crate::infrastructure::registries::VulneraRegistryAdapter;

        let registry: Arc<dyn PackageRegistryClient> = Arc::new(VulneraRegistryAdapter::new());

        let mut available_versions = HashMap::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            self.max_concurrent_registry_queries,
        ));
        let mut join_set: JoinSet<
            Result<
                (
                    PackageId,
                    Vec<crate::domain::vulnerability::value_objects::Version>,
                ),
                ApplicationError,
            >,
        > = JoinSet::new();

        // Fetch versions for each package in the graph
        for package_id in graph.nodes.keys() {
            let package_id_clone = package_id.clone();
            let package_name = package_id.name.clone();
            let ecosystem_clone = ecosystem.clone();
            let registry_clone = registry.clone();
            let permit = Arc::clone(&semaphore);

            join_set.spawn(async move {
                let _permit = permit.acquire().await.map_err(|e| {
                    ApplicationError::Vulnerability(
                        crate::application::errors::VulnerabilityError::Api(
                            crate::application::errors::ApiError::Http {
                                status: 500,
                                message: format!("Failed to acquire semaphore: {}", e),
                            },
                        ),
                    )
                })?;

                match registry_clone
                    .list_versions(ecosystem_clone, &package_name)
                    .await
                {
                    Ok(version_infos) => {
                        let versions: Vec<crate::domain::vulnerability::value_objects::Version> =
                            version_infos.into_iter().map(|vi| vi.version).collect();
                        Ok((package_id_clone, versions))
                    }
                    Err(e) => {
                        debug!("Failed to fetch versions for {}: {}", package_name, e);
                        // Return empty vector rather than error - best effort
                        Ok((package_id_clone, Vec::new()))
                    }
                }
            });
        }

        // Collect results
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok((package_id, versions))) => {
                    if !versions.is_empty() {
                        available_versions.insert(package_id, versions);
                    }
                }
                Ok(Err(e)) => {
                    warn!("Error fetching available versions: {}", e);
                    // Continue with other packages
                }
                Err(e) => {
                    warn!("Join error while fetching available versions: {}", e);
                    // Continue with other packages
                }
            }
        }

        Ok(available_versions)
    }
}

/// Map a vulnera_advisor Advisory to our domain Vulnerability.
fn advisory_to_vulnerability(
    advisory: vulnera_advisor::Advisory,
    package: &Package,
) -> Option<Vulnerability> {
    let id = crate::domain::vulnerability::value_objects::VulnerabilityId::new(advisory.id.clone())
        .ok()?;

    let severity = advisory
        .enrichment
        .as_ref()
        .and_then(|e| e.cvss_v3_severity)
        .map(|s| match s {
            vulnera_advisor::Severity::Critical => {
                crate::domain::vulnerability::value_objects::Severity::Critical
            }
            vulnera_advisor::Severity::High => {
                crate::domain::vulnerability::value_objects::Severity::High
            }
            vulnera_advisor::Severity::Medium => {
                crate::domain::vulnerability::value_objects::Severity::Medium
            }
            vulnera_advisor::Severity::Low => {
                crate::domain::vulnerability::value_objects::Severity::Low
            }
            vulnera_advisor::Severity::None => {
                crate::domain::vulnerability::value_objects::Severity::Low
            }
        })
        .unwrap_or(crate::domain::vulnerability::value_objects::Severity::Medium);

    let affected_packages: Vec<crate::domain::vulnerability::entities::AffectedPackage> = advisory
        .affected
        .iter()
        .map(|aff| {
            let pkg = Package::new(
                aff.package.name.clone(),
                package.version.clone(),
                crate::domain::vulnerability::value_objects::Ecosystem::from_alias(
                    &aff.package.ecosystem,
                )
                .unwrap_or(package.ecosystem.clone()),
            )
            .unwrap_or_else(|_| package.clone());

            let vulnerable_ranges: Vec<crate::domain::vulnerability::value_objects::VersionRange> =
                aff.ranges
                    .iter()
                    .map(|r| {
                        let introduced = r.events.iter().find_map(|e| {
                            if let vulnera_advisor::Event::Introduced(v) = e {
                                Some(v.clone())
                            } else {
                                None
                            }
                        });
                        let fixed = r.events.iter().find_map(|e| {
                            if let vulnera_advisor::Event::Fixed(v) = e {
                                Some(v.clone())
                            } else {
                                None
                            }
                        });
                        let start = introduced.as_ref().and_then(|v| {
                            crate::domain::vulnerability::value_objects::Version::parse(v).ok()
                        });
                        let end = fixed.as_ref().and_then(|v| {
                            crate::domain::vulnerability::value_objects::Version::parse(v).ok()
                        });
                        crate::domain::vulnerability::value_objects::VersionRange::new(
                            start, end, true, false,
                        )
                    })
                    .collect();

            let fixed_versions: Vec<crate::domain::vulnerability::value_objects::Version> = aff
                .ranges
                .iter()
                .flat_map(|r| {
                    r.events.iter().filter_map(|e| {
                        if let vulnera_advisor::Event::Fixed(v) = e {
                            crate::domain::vulnerability::value_objects::Version::parse(v).ok()
                        } else {
                            None
                        }
                    })
                })
                .collect();

            crate::domain::vulnerability::entities::AffectedPackage::new(
                pkg,
                vulnerable_ranges,
                fixed_versions,
            )
        })
        .collect();

    let sources = advisory
        .aliases
        .as_ref()
        .map(|a| {
            a.iter()
                .map(|alias| {
                    if alias.starts_with("GHSA-") {
                        crate::domain::vulnerability::value_objects::VulnerabilitySource::GHSA
                    } else if alias.starts_with("CVE-") {
                        crate::domain::vulnerability::value_objects::VulnerabilitySource::NVD
                    } else {
                        crate::domain::vulnerability::value_objects::VulnerabilitySource::OSV
                    }
                })
                .collect()
        })
        .unwrap_or_else(|| {
            vec![crate::domain::vulnerability::value_objects::VulnerabilitySource::OSV]
        });

    let new_vuln = crate::domain::vulnerability::entities::NewVulnerability {
        id,
        summary: advisory.summary.unwrap_or_default(),
        description: advisory.details.unwrap_or_default(),
        severity,
        affected_packages,
        references: advisory.references.iter().map(|r| r.url.clone()).collect(),
        published_at: advisory.published.unwrap_or_else(chrono::Utc::now),
        sources,
    };

    new_vuln.build().ok()
}
