//! Integration tests for dependency resolution

use std::sync::Arc;
use vulnera_deps::ParserFactory;
use vulnera_deps::domain::vulnerability::entities::Package;
use vulnera_deps::domain::vulnerability::value_objects::{Ecosystem, Version};
use vulnera_deps::infrastructure::registries::{
    RegistryDependency, RegistryPackageMetadata, VersionInfo,
};
use vulnera_deps::services::dependency_resolver::{
    DependencyResolverService, DependencyResolverServiceImpl, build_graph_from_lockfile,
    build_graph_from_manifest,
};

mod common;
use common::MockRegistryClient;

#[tokio::test]
async fn test_build_graph_from_manifest_npm() {
    let parser_factory = Arc::new(ParserFactory::new());

    let manifest_content = r#"{
        "name": "test-package",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.17.1",
            "lodash": "4.17.21"
        },
        "devDependencies": {
            "jest": "^27.0.0"
        }
    }"#;

    let graph = build_graph_from_manifest(
        manifest_content,
        "package.json",
        parser_factory,
        None, // No registry for now
    )
    .await
    .expect("Failed to build graph from manifest");

    assert_eq!(graph.package_count(), 3); // express, lodash, jest

    // Verify nodes exist
    let express_node = graph.nodes.values().find(|n| n.package.name == "express");
    assert!(express_node.is_some());
    assert_eq!(express_node.unwrap().package.ecosystem, Ecosystem::Npm);

    let lodash_node = graph.nodes.values().find(|n| n.package.name == "lodash");
    assert!(lodash_node.is_some());

    let jest_node = graph.nodes.values().find(|n| n.package.name == "jest");
    assert!(jest_node.is_some());
}

#[tokio::test]
async fn test_build_graph_from_manifest_cargo() {
    let parser_factory = Arc::new(ParserFactory::new());

    let manifest_content = r#"[package]
name = "test-crate"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }

[dev-dependencies]
tempfile = "3.2"
"#;

    let graph = build_graph_from_manifest(manifest_content, "Cargo.toml", parser_factory, None)
        .await
        .expect("Failed to build graph from manifest");

    assert_eq!(graph.package_count(), 3); // serde, tokio, tempfile

    let serde_node = graph.nodes.values().find(|n| n.package.name == "serde");
    assert!(serde_node.is_some());
    assert_eq!(serde_node.unwrap().package.ecosystem, Ecosystem::Cargo);
}

#[tokio::test]
async fn test_build_graph_from_lockfile_npm() {
    let parser_factory = Arc::new(ParserFactory::new());

    // Minimal package-lock.json
    let lockfile_content = r#"{
        "name": "test-package",
        "version": "1.0.0",
        "lockfileVersion": 2,
        "requires": true,
        "packages": {
            "": {
                "name": "test-package",
                "version": "1.0.0",
                "dependencies": {
                    "express": "^4.17.1"
                }
            },
            "node_modules/express": {
                "version": "4.17.1",
                "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
                "integrity": "sha512-...",
                "dependencies": {
                    "accepts": "~1.3.7"
                }
            },
            "node_modules/accepts": {
                "version": "1.3.7",
                "resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.7.tgz",
                "integrity": "sha512-..."
            }
        },
        "dependencies": {
            "express": {
                "version": "4.17.1",
                "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
                "integrity": "sha512-...",
                "requires": {
                    "accepts": "~1.3.7"
                }
            },
            "accepts": {
                "version": "1.3.7",
                "resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.7.tgz",
                "integrity": "sha512-..."
            }
        }
    }"#;

    let graph = build_graph_from_lockfile(lockfile_content, "package-lock.json", &parser_factory)
        .await
        .expect("Failed to build graph from lockfile");

    // Should contain express and accepts
    // Note: The parser might return more or fewer depending on implementation details
    // But at least express and accepts should be there

    let express_node = graph.nodes.values().find(|n| n.package.name == "express");
    assert!(express_node.is_some());
    assert_eq!(
        express_node
            .unwrap()
            .metadata
            .resolved_version
            .as_ref()
            .unwrap()
            .to_string(),
        "4.17.1"
    );

    let accepts_node = graph.nodes.values().find(|n| n.package.name == "accepts");
    assert!(accepts_node.is_some());
    assert_eq!(
        accepts_node
            .unwrap()
            .metadata
            .resolved_version
            .as_ref()
            .unwrap()
            .to_string(),
        "1.3.7"
    );
}

// Transitive dependency resolution is tested in:
// - dependency_resolution_with_mock_registry (resolves dep-a -> dep-b)
// - recursive_resolution_with_mock_data (resolves root -> mid -> deep)

// ---------------------------------------------------------------------------
// Dependency resolution integration tests via MockRegistryClient
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dependency_resolution_with_mock_registry() {
    let mock = MockRegistryClient::new()
        .with_versions(
            Ecosystem::Npm,
            "dep-a",
            vec![
                VersionInfo::new(Version::parse("1.0.0").unwrap(), false, None),
                VersionInfo::new(Version::parse("1.2.0").unwrap(), false, None),
            ],
        )
        .with_versions(
            Ecosystem::Npm,
            "dep-b",
            vec![VersionInfo::new(
                Version::parse("2.0.0").unwrap(),
                false,
                None,
            )],
        )
        .with_metadata(
            Ecosystem::Npm,
            "root",
            "1.0.0",
            RegistryPackageMetadata {
                name: "root".to_string(),
                version: Version::parse("1.0.0").unwrap(),
                dependencies: vec![RegistryDependency {
                    name: "dep-a".to_string(),
                    requirement: ">=1.1.0".to_string(),
                    is_dev: false,
                    is_optional: false,
                }],
                project_url: None,
                license: None,
            },
        )
        .with_metadata(
            Ecosystem::Npm,
            "dep-a",
            "1.2.0",
            RegistryPackageMetadata {
                name: "dep-a".to_string(),
                version: Version::parse("1.2.0").unwrap(),
                dependencies: vec![RegistryDependency {
                    name: "dep-b".to_string(),
                    requirement: "^2.0.0".to_string(),
                    is_dev: false,
                    is_optional: false,
                }],
                project_url: None,
                license: None,
            },
        )
        .with_metadata(
            Ecosystem::Npm,
            "dep-b",
            "2.0.0",
            RegistryPackageMetadata {
                name: "dep-b".to_string(),
                version: Version::parse("2.0.0").unwrap(),
                dependencies: vec![],
                project_url: None,
                license: None,
            },
        );

    let registry: Arc<dyn vulnera_deps::infrastructure::registries::PackageRegistryClient> =
        Arc::new(mock);
    let resolver = DependencyResolverServiceImpl::new();

    let root = Package::new(
        "root".to_string(),
        Version::parse("1.0.0").unwrap(),
        Ecosystem::Npm,
    )
    .unwrap();

    let result = resolver
        .resolve_transitive(&root, registry)
        .await
        .expect("transitive resolution should succeed");

    assert_eq!(result.len(), 2);
    assert!(
        result
            .iter()
            .any(|pkg| pkg.name == "dep-a" && pkg.version == Version::parse("1.2.0").unwrap())
    );
    assert!(
        result
            .iter()
            .any(|pkg| pkg.name == "dep-b" && pkg.version == Version::parse("2.0.0").unwrap())
    );
}

#[tokio::test]
async fn dependency_resolution_registry_unavailable() {
    let mock = MockRegistryClient::new().with_error(
        Ecosystem::Npm,
        "root",
        vulnera_deps::infrastructure::registries::RegistryError::RateLimited,
    );

    let registry: Arc<dyn vulnera_deps::infrastructure::registries::PackageRegistryClient> =
        Arc::new(mock);
    let resolver = DependencyResolverServiceImpl::new();

    let root = Package::new(
        "root".to_string(),
        Version::parse("1.0.0").unwrap(),
        Ecosystem::Npm,
    )
    .unwrap();

    let err = resolver
        .resolve_transitive(&root, registry)
        .await
        .expect_err("should fail when root metadata fetch returns error");

    assert!(
        format!("{:?}", err).contains("RateLimited")
            || format!("{}", err).contains("rate")
            || format!("{}", err).contains("RateLimited"),
        "error should mention rate limiting, got: {}",
        err
    );
}

#[tokio::test]
async fn recursive_resolution_with_mock_data() {
    // root -> mid -> deep  (three levels of depth)
    let mock = MockRegistryClient::new()
        .with_versions(
            Ecosystem::Npm,
            "mid",
            vec![VersionInfo::new(
                Version::parse("2.0.0").unwrap(),
                false,
                None,
            )],
        )
        .with_versions(
            Ecosystem::Npm,
            "deep",
            vec![
                VersionInfo::new(Version::parse("1.0.0").unwrap(), false, None),
                VersionInfo::new(Version::parse("1.5.0").unwrap(), false, None),
            ],
        )
        .with_metadata(
            Ecosystem::Npm,
            "root",
            "1.0.0",
            RegistryPackageMetadata {
                name: "root".to_string(),
                version: Version::parse("1.0.0").unwrap(),
                dependencies: vec![RegistryDependency {
                    name: "mid".to_string(),
                    requirement: ">=1.0.0".to_string(),
                    is_dev: false,
                    is_optional: false,
                }],
                project_url: None,
                license: None,
            },
        )
        .with_metadata(
            Ecosystem::Npm,
            "mid",
            "2.0.0",
            RegistryPackageMetadata {
                name: "mid".to_string(),
                version: Version::parse("2.0.0").unwrap(),
                dependencies: vec![RegistryDependency {
                    name: "deep".to_string(),
                    requirement: "^1.0.0".to_string(),
                    is_dev: false,
                    is_optional: false,
                }],
                project_url: None,
                license: None,
            },
        )
        .with_metadata(
            Ecosystem::Npm,
            "deep",
            "1.5.0",
            RegistryPackageMetadata {
                name: "deep".to_string(),
                version: Version::parse("1.5.0").unwrap(),
                dependencies: vec![],
                project_url: None,
                license: None,
            },
        );

    let registry: Arc<dyn vulnera_deps::infrastructure::registries::PackageRegistryClient> =
        Arc::new(mock);
    let resolver = DependencyResolverServiceImpl::new();

    let root = Package::new(
        "root".to_string(),
        Version::parse("1.0.0").unwrap(),
        Ecosystem::Npm,
    )
    .unwrap();

    let result = resolver
        .resolve_transitive(&root, registry)
        .await
        .expect("recursive resolution should succeed");

    assert_eq!(result.len(), 2, "should resolve mid and deep");
    assert!(
        result
            .iter()
            .any(|pkg| pkg.name == "mid" && pkg.version == Version::parse("2.0.0").unwrap())
    );
    assert!(
        result
            .iter()
            .any(|pkg| pkg.name == "deep" && pkg.version == Version::parse("1.5.0").unwrap())
    );
}
