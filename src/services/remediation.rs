//! Remediation planning services
//!
//! Queries vulnera-advisors for safe version suggestions and identifies
//! whether a fix requires a direct or transitive dependency bump,
//! including constraint relaxation points where a direct dependency
//! pins a vulnerable transitive.

use std::sync::Arc;
use tracing::{debug, warn};

use vulnera_advisor::{PackageRegistry, VersionRegistry, VulnerabilityManager};

use crate::application::errors::ApplicationError;
use crate::domain::dependency_graph::PackageId;
use crate::domain::vulnerability::value_objects::Version;
use crate::services::contamination::ContaminationPathAnalyzer;
use crate::services::graph::UnifiedDependencyGraph;

/// Whether the vulnerable package is a direct or transitive dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BumpType {
    Direct,
    Transitive,
}

/// A point in the dependency tree where a direct dependency's version
/// constraint is preventing the vulnerable transitive from being upgraded.
#[derive(Debug, Clone)]
pub struct ConstraintRelaxationPoint {
    pub direct_dependency: PackageId,
    pub transitive_dependency: PackageId,
    pub description: String,
}

/// Complete remediation plan for a single vulnerable package.
#[derive(Debug, Clone)]
pub struct RemediationPlan {
    pub package: PackageId,
    pub current_version: Version,
    pub nearest_safe: Option<Version>,
    pub latest_safe: Option<Version>,
    pub upgrade_impact: Option<String>,
    pub bump_type: Option<BumpType>,
    pub vulnerability_ids: Vec<String>,
    pub constraint_relaxation_points: Vec<ConstraintRelaxationPoint>,
}

/// Resolves safe version upgrades and constraint analysis for vulnerable packages.
pub struct RemediationResolver {
    advisor: Arc<VulnerabilityManager>,
    registry: Arc<PackageRegistry>,
}

impl RemediationResolver {
    pub fn new(advisor: Arc<VulnerabilityManager>, registry: Arc<PackageRegistry>) -> Self {
        Self { advisor, registry }
    }

    /// Resolve remediation for a single vulnerable package.
    ///
    /// 1. Queries the advisor for matching advisories.
    /// 2. Fetches available versions from the registry.
    /// 3. Computes nearest and latest safe versions.
    /// 4. Determines direct vs transitive bump type.
    /// 5. For transitive packages, identifies constraint relaxation points.
    pub async fn resolve(
        &self,
        graph: &UnifiedDependencyGraph,
        package: &PackageId,
        current_version: &Version,
    ) -> Result<RemediationPlan, ApplicationError> {
    let ver_str = current_version.to_string();
        let eco_str = &package.ecosystem;
        let name = &package.name;

        // Note: Both advisor.matches() and registry.get_versions() normalize ecosystem
        // names internally via canonicalize_ecosystem() (to lowercase), so the
        // canonical_name() stored in PackageId is the correct format to pass directly.
        // 1. Query advisor for matching advisories
        let advisories = self
            .advisor
            .matches(eco_str, name, &ver_str)
            .await
            .map_err(|e| {
                ApplicationError::Vulnerability(
                    crate::application::errors::VulnerabilityError::Repository {
                        message: format!("advisor query failed: {}", e),
                    },
                )
            })?;

        // Collect vulnerability IDs
        let vulnerability_ids: Vec<String> = advisories.iter().map(|a| a.id.clone()).collect();

        // 2. Fetch available versions from registry (best-effort)
        let available_versions = match self.registry.get_versions(eco_str, name).await {
            Ok(versions) => {
                let mut v: Vec<String> = versions;
                v.sort_by(|a, b| {
                    let pa = crate::domain::vulnerability::value_objects::Version::parse(a)
                        .unwrap_or_else(|_| Version::new(0, 0, 0));
                    let pb = crate::domain::vulnerability::value_objects::Version::parse(b)
                        .unwrap_or_else(|_| Version::new(0, 0, 0));
                    pa.cmp(&pb)
                });
                Some(v)
            }
            Err(e) => {
                debug!("Registry unavailable for {} {}: {}", eco_str, name, e);
                None
            }
        };

        // 3. Build remediation via advisor's logic
        let remediation = vulnera_advisor::build_remediation(
            eco_str,
            name,
            &ver_str,
            &advisories,
            available_versions.as_deref(),
            |v, events| self.matches_semver_range(v, events),
        );

        // 4. Determine bump type
        let bump_type = if graph.is_direct(package) {
            Some(BumpType::Direct)
        } else {
            Some(BumpType::Transitive)
        };

        // 5. Find constraint relaxation points for transitive packages
        let constraint_relaxation_points = if bump_type == Some(BumpType::Transitive) {
            self.find_relaxation_points(graph, package)
        } else {
            Vec::new()
        };

        // Parse nearest/latest safe back to Version
        let nearest_safe = remediation
            .nearest_safe
            .as_ref()
            .and_then(|v| Version::parse(v).ok());
        let latest_safe = remediation
            .latest_safe
            .as_ref()
            .and_then(|v| Version::parse(v).ok());
        let upgrade_impact = remediation.upgrade_impact.map(|i| i.to_string());

        Ok(RemediationPlan {
            package: package.clone(),
            current_version: current_version.clone(),
            nearest_safe,
            latest_safe,
            upgrade_impact,
            bump_type,
            vulnerability_ids,
            constraint_relaxation_points,
        })
    }

    /// Batch resolve for multiple vulnerable packages using sequential (non-Arc graph) resolution.
    pub async fn resolve_batch(
        &self,
        graph: &UnifiedDependencyGraph,
        packages: &[(PackageId, Version)],
        _max_concurrent: usize,
    ) -> Vec<RemediationPlan> {
        let mut plans = Vec::with_capacity(packages.len());
        for (pkg_id, ver) in packages {
            match self.resolve(graph, pkg_id, ver).await {
                Ok(plan) => plans.push(plan),
                Err(e) => warn!("Failed to resolve remediation for {}: {}", pkg_id, e),
            }
        }
        plans
    }

    /// semver range matcher matching OSV event semantics.
    /// Checks if a version string falls within any interval described by the events.
    /// Each interval is bounded by Event::Introduced (start, inclusive) and Event::Fixed (end, exclusive).
    fn matches_semver_range(&self, version: &str, events: &[vulnera_advisor::Event]) -> bool {
        let Ok(v) = semver::Version::parse(version) else {
            return false;
        };

        let mut intervals: Vec<(Option<semver::Version>, Option<semver::Version>, bool)> =
            Vec::new();
        let mut current_start: Option<semver::Version> = None;

        for event in events {
            match event {
                vulnera_advisor::Event::Introduced(ver) => {
                    if let Ok(parsed) = semver::Version::parse(ver) {
                        current_start = Some(parsed);
                    } else if ver == "0" {
                        current_start = Some(semver::Version::new(0, 0, 0));
                    }
                }
                vulnera_advisor::Event::Fixed(ver) => {
                    let end = semver::Version::parse(ver).ok();
                    intervals.push((current_start.clone(), end, false));
                    current_start = None;
                }
                vulnera_advisor::Event::LastAffected(ver) => {
                    let end = semver::Version::parse(ver).ok();
                    intervals.push((current_start.clone(), end, true));
                    current_start = None;
                }
                vulnera_advisor::Event::Limit(ver) => {
                    let end = semver::Version::parse(ver).ok();
                    intervals.push((current_start.clone(), end, false));
                    current_start = None;
                }
            }
        }

        if current_start.is_some() {
            intervals.push((current_start, None, false));
        }

        intervals.into_iter().any(|(start, end, end_inclusive)| {
            if let Some(start) = &start
                && v < *start
            {
                return false;
            }
            match (end, end_inclusive) {
                (Some(end), true) => v <= end,
                (Some(end), false) => v < end,
                (None, _) => true,
            }
        })
    }

    /// Walk the graph to find where a direct dependency pins the vulnerable transitive.
    fn find_relaxation_points(
        &self,
        graph: &UnifiedDependencyGraph,
        vulnerable: &PackageId,
    ) -> Vec<ConstraintRelaxationPoint> {
        let mut points = Vec::new();

        // For each root, find the shortest path to the vulnerable package
        for root in graph.roots() {
            let Some(path) = ContaminationPathAnalyzer::shortest_path(graph, root, vulnerable)
            else {
                continue;
            };

            if path.len() < 3 {
                // Direct dependency of root
                points.push(ConstraintRelaxationPoint {
                    direct_dependency: root.clone(),
                    transitive_dependency: vulnerable.clone(),
                    description: format!(
                        "Root dependency {} directly depends on vulnerable package {}",
                        root, vulnerable
                    ),
                });
                continue;
            }

            // The first edge from root to next node is the direct dependency
            // that transitively pulls in the vulnerable package
            if let Some(transitive_dep) = path.get(1) {
                points.push(ConstraintRelaxationPoint {
                    direct_dependency: root.clone(),
                    transitive_dependency: transitive_dep.clone(),
                    description: format!(
                        "Root dependency {} pulls in {} which transitively depends on vulnerable {}",
                        root, transitive_dep, vulnerable
                    ),
                });
            }
        }

        points
    }
}
