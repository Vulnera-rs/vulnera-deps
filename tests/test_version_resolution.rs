//! Integration tests for version resolution algorithms

use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use vulnera_contract::infrastructure::cache::CacheBackend;
use vulnera_deps::domain::vulnerability::entities::{AffectedPackage, Package, Vulnerability};
use vulnera_deps::domain::vulnerability::value_objects::{
    Ecosystem, Severity, Version, VersionRange, VulnerabilityId, VulnerabilitySource,
};
use vulnera_deps::domain::{
    DependencyEdge, DependencyGraph, PackageId, PackageNode, VersionConstraint,
};
use vulnera_deps::services::cache::CacheBackendAdapter;
use vulnera_deps::services::resolution_algorithms::{BacktrackingResolver, LexicographicOptimizer};
use vulnera_deps::services::version_resolution::VersionResolutionServiceImpl;
use vulnera_deps::types::VersionResolutionService;
use vulnera_infrastructure::cache::NoOpCache;

mod common;
use common::MockRegistryClient;

fn create_version(v: &str) -> Version {
    Version::parse(v).unwrap()
}

fn _create_package_id(name: &str, _version: &str) -> PackageId {
    PackageId::new("npm".to_string(), name.to_string())
}

#[test]
fn test_lexicographic_optimizer_patch_preference() {
    let current = create_version("1.2.3");
    let candidates = vec![
        create_version("1.2.4"), // patch
        create_version("1.3.0"), // minor
        create_version("2.0.0"), // major
    ];

    let selected = LexicographicOptimizer::select_version(Some(&current), &candidates);
    assert_eq!(selected, Some(create_version("1.2.4")));
}

#[test]
fn test_lexicographic_optimizer_minor_preference() {
    let current = create_version("1.2.3");
    let candidates = vec![
        create_version("1.3.0"), // minor
        create_version("2.0.0"), // major
    ];

    let selected = LexicographicOptimizer::select_version(Some(&current), &candidates);
    assert_eq!(selected, Some(create_version("1.3.0")));
}

#[test]
fn test_lexicographic_optimizer_major_preference() {
    let current = create_version("1.2.3");
    let candidates = vec![
        create_version("2.0.0"), // major
    ];

    let selected = LexicographicOptimizer::select_version(Some(&current), &candidates);
    assert_eq!(selected, Some(create_version("2.0.0")));
}

#[test]
fn test_lexicographic_optimizer_downgrade_avoidance() {
    let current = create_version("1.2.3");
    let candidates = vec![
        create_version("1.2.2"), // downgrade
        create_version("1.2.1"), // downgrade
    ];

    let selected = LexicographicOptimizer::select_version(Some(&current), &candidates);
    assert_eq!(selected, None);
}

#[test]
fn test_lexicographic_optimizer_minimal_upgrade() {
    let current = create_version("1.2.3");
    let candidates = vec![
        create_version("1.2.4"), // patch
        create_version("1.2.5"), // patch (larger)
    ];

    let selected = LexicographicOptimizer::select_version(Some(&current), &candidates);
    assert_eq!(selected, Some(create_version("1.2.4")));
}

#[test]
fn test_backtracking_resolver_basic() {
    let mut graph = DependencyGraph::new();
    let pkg_a = Package::new("a".to_string(), create_version("1.0.0"), Ecosystem::Npm).unwrap();

    let node_a = PackageNode::new(pkg_a);
    let id_a = node_a.id.clone();
    graph.add_node(node_a);

    let mut available_versions = HashMap::new();
    available_versions.insert(
        id_a.clone(),
        vec![create_version("1.0.0"), create_version("1.1.0")],
    );

    let result = BacktrackingResolver::resolve(&graph, &available_versions);

    assert!(result.conflicts.is_empty());
    assert_eq!(result.resolved.get(&id_a), Some(&create_version("1.1.0"))); // Should pick latest
}

#[test]
fn test_backtracking_resolver_conflict() {
    let mut graph = DependencyGraph::new();
    let pkg_a = Package::new("a".to_string(), create_version("1.0.0"), Ecosystem::Npm).unwrap();

    let node_a = PackageNode::new(pkg_a);
    let id_a = node_a.id.clone();
    graph.add_node(node_a);

    // No versions available for 'a'
    let available_versions = HashMap::new();

    let result = BacktrackingResolver::resolve(&graph, &available_versions);

    assert!(!result.conflicts.is_empty());
    assert_eq!(result.conflicts[0].package, id_a);
}

#[test]
fn test_backtracking_resolver_with_dependencies() {
    // A -> B
    let mut graph = DependencyGraph::new();
    let pkg_a = Package::new("a".to_string(), create_version("1.0.0"), Ecosystem::Npm).unwrap();
    let pkg_b = Package::new("b".to_string(), create_version("1.0.0"), Ecosystem::Npm).unwrap();

    let node_a = PackageNode::new(pkg_a);
    let node_b = PackageNode::new(pkg_b);
    let id_a = node_a.id.clone();
    let id_b = node_b.id.clone();

    graph.add_node(node_a);
    graph.add_node(node_b);

    graph.add_edge(DependencyEdge::new(
        id_a.clone(),
        id_b.clone(),
        VersionConstraint::Any,
        false,
    ));

    let mut available_versions = HashMap::new();
    available_versions.insert(id_a.clone(), vec![create_version("1.0.0")]);
    available_versions.insert(id_b.clone(), vec![create_version("2.0.0")]);

    let result = BacktrackingResolver::resolve(&graph, &available_versions);

    assert!(result.conflicts.is_empty());
    assert_eq!(result.resolved.get(&id_a), Some(&create_version("1.0.0")));
    assert_eq!(result.resolved.get(&id_b), Some(&create_version("2.0.0")));
}

// ---------------------------------------------------------------------------
// VersionResolutionService integration tests via MockRegistryClient
// ---------------------------------------------------------------------------

#[tokio::test]
async fn version_resolution_with_mock_versions() {
    let mock = MockRegistryClient::new()
        .with_version(Ecosystem::Npm, "test-pkg", "1.0.0", false, false)
        .with_version(Ecosystem::Npm, "test-pkg", "1.1.0", false, false)
        .with_version(Ecosystem::Npm, "test-pkg", "2.0.0", false, false);
    let registry = Arc::new(mock);

    let no_op_cache = Arc::new(NoOpCache::new());
    let cache: Arc<dyn CacheBackend> = no_op_cache;
    let cache_adapter = Arc::new(CacheBackendAdapter::new(cache));
    let service = VersionResolutionServiceImpl::new_with_cache(registry.clone(), cache_adapter);

    let current = Some(Version::parse("1.0.0").unwrap());
    let vulnerabilities = vec![];

    let result = service
        .recommend(Ecosystem::Npm, "test-pkg", current, &vulnerabilities)
        .await
        .expect("recommend should succeed");

    assert_eq!(
        result.nearest_safe_above_current,
        Some(Version::parse("1.0.0").unwrap()),
    );
    assert_eq!(
        result.most_up_to_date_safe,
        Some(Version::parse("2.0.0").unwrap()),
    );
    assert!(registry.called_package(&Ecosystem::Npm, "test-pkg"));
    assert_eq!(registry.call_count(), 1);
}

#[tokio::test]
async fn version_resolution_with_registry_unavailable() {
    let mock = MockRegistryClient::new().with_error(
        Ecosystem::Npm,
        "test-pkg",
        vulnera_deps::infrastructure::registries::RegistryError::RateLimited,
    );

    let vuln = Vulnerability {
        id: VulnerabilityId::new("CVE-2024-0001".to_string()).unwrap(),
        summary: "Test vuln".to_string(),
        description: "All versions below 3.0.0 are vulnerable".to_string(),
        severity: Severity::High,
        affected_packages: vec![AffectedPackage {
            package: Package::new(
                "test-pkg".to_string(),
                Version::parse("0.0.0").unwrap(),
                Ecosystem::Npm,
            )
            .unwrap(),
            vulnerable_ranges: vec![VersionRange::less_than(Version::parse("3.0.0").unwrap())],
            fixed_versions: vec![
                Version::parse("2.0.0").unwrap(),
                Version::parse("2.1.0").unwrap(),
            ],
        }],
        references: vec![],
        published_at: Utc::now(),
        sources: vec![VulnerabilitySource::OSV],
    };

    let registry = Arc::new(mock);

    let no_op_cache = Arc::new(NoOpCache::new());
    let cache: Arc<dyn CacheBackend> = no_op_cache;
    let cache_adapter = Arc::new(CacheBackendAdapter::new(cache));
    let service = VersionResolutionServiceImpl::new_with_cache(registry.clone(), cache_adapter);

    let current = Some(Version::parse("1.0.0").unwrap());
    let result = service
        .recommend(Ecosystem::Npm, "test-pkg", current, &[vuln])
        .await
        .expect("recommend should fall back to fixed versions");

    assert_eq!(
        result.nearest_safe_above_current,
        Some(Version::parse("2.0.0").unwrap()),
    );
    assert!(
        result
            .notes
            .iter()
            .any(|n| n.contains("registry unavailable"))
    );
}

#[tokio::test]
async fn version_resolution_yanked_versions_excluded() {
    let mock = MockRegistryClient::new()
        .with_version(Ecosystem::Npm, "test-pkg", "1.0.0", true, false)
        .with_version(Ecosystem::Npm, "test-pkg", "1.1.0", false, false)
        .with_version(Ecosystem::Npm, "test-pkg", "2.0.0", false, false);
    let registry = Arc::new(mock);

    let no_op_cache = Arc::new(NoOpCache::new());
    let cache: Arc<dyn CacheBackend> = no_op_cache;
    let cache_adapter = Arc::new(CacheBackendAdapter::new(cache));
    let service = VersionResolutionServiceImpl::new_with_cache(registry.clone(), cache_adapter);

    let current = Some(Version::parse("1.0.0").unwrap());
    let vulnerabilities = vec![];

    let result = service
        .recommend(Ecosystem::Npm, "test-pkg", current, &vulnerabilities)
        .await
        .expect("recommend should succeed");

    assert_eq!(
        result.nearest_safe_above_current,
        Some(Version::parse("1.1.0").unwrap()),
    );
    assert_eq!(
        result.most_up_to_date_safe,
        Some(Version::parse("2.0.0").unwrap()),
    );
}

#[tokio::test]
async fn version_resolution_no_safe_version() {
    let mock = MockRegistryClient::new()
        .with_version(Ecosystem::Npm, "test-pkg", "1.0.0", false, false)
        .with_version(Ecosystem::Npm, "test-pkg", "1.1.0", false, false)
        .with_version(Ecosystem::Npm, "test-pkg", "2.0.0", false, false);
    let registry = Arc::new(mock);

    let no_op_cache = Arc::new(NoOpCache::new());
    let cache: Arc<dyn CacheBackend> = no_op_cache;
    let cache_adapter = Arc::new(CacheBackendAdapter::new(cache));
    let service = VersionResolutionServiceImpl::new_with_cache(registry.clone(), cache_adapter);

    let vuln = Vulnerability {
        id: VulnerabilityId::new("CVE-2024-0002".to_string()).unwrap(),
        summary: "All versions vulnerable".to_string(),
        description: "All versions are affected with no fix".to_string(),
        severity: Severity::Critical,
        affected_packages: vec![AffectedPackage {
            package: Package::new(
                "test-pkg".to_string(),
                Version::parse("0.0.0").unwrap(),
                Ecosystem::Npm,
            )
            .unwrap(),
            vulnerable_ranges: vec![VersionRange::less_than(Version::parse("999.0.0").unwrap())],
            fixed_versions: vec![],
        }],
        references: vec![],
        published_at: Utc::now(),
        sources: vec![VulnerabilitySource::OSV],
    };

    let current = Some(Version::parse("1.0.0").unwrap());
    let result = service
        .recommend(Ecosystem::Npm, "test-pkg", current, &[vuln])
        .await
        .expect("recommend should succeed with empty safe list");

    assert_eq!(result.nearest_safe_above_current, None);
    assert_eq!(result.most_up_to_date_safe, None);
    assert!(
        result
            .notes
            .iter()
            .any(|n| n.contains("all available versions are vulnerable"))
    );
}
