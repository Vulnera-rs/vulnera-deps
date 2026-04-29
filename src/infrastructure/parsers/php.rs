//! PHP ecosystem parsers

use super::traits::{FilePattern, PackageFileParser, ParseResult, SourceType};
use super::version_extractor;
use crate::application::errors::ParseError;
use crate::domain::vulnerability::{
    entities::{Dependency, Package},
    value_objects::{Ecosystem, Version},
};
use serde_json::Value;
use std::collections::HashMap;

/// Parser for composer.json files
pub struct ComposerParser;

impl Default for ComposerParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ComposerParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract dependencies from JSON object
    fn extract_dependencies(
        &self,
        json: &Value,
        dep_type: &str,
        root_package: &Package,
    ) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();

        if let Some(deps) = json.get(dep_type).and_then(|d| d.as_object()) {
            for (name, version_value) in deps {
                // Skip PHP version requirement
                if name == "php" {
                    continue;
                }

                let version_str =
                    version_value
                        .as_str()
                        .ok_or_else(|| ParseError::MissingField {
                            field: format!("version for package {}", name),
                        })?;

                let result = version_extractor::composer(version_str)?;
                let Some((_cleaned, version)) = result else {
                    continue;
                };

                let package = Package::new(name.clone(), version, Ecosystem::Packagist)
                    .map_err(|e| ParseError::MissingField { field: e })?;

                packages.push(package.clone());

                // Create dependency edge from root
                dependencies.push(Dependency::new(
                    root_package.clone(),
                    package,
                    version_str.to_string(),
                    false, // Direct dependency from manifest
                ));
            }
        }

        Ok(ParseResult {
            packages,
            dependencies,
            source_type: SourceType::Manifest,
        })
    }
}

impl PackageFileParser for ComposerParser {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError> {
        let json: Value = serde_json::from_str(content)?;
        let mut result = ParseResult::default();

        // Extract root package info
        let root_name = json
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("root")
            .to_string();
        let root_version_str = json
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0");
        let root_version =
            Version::parse(root_version_str).unwrap_or_else(|_| Version::new(0, 0, 0));
        let root_package = Package::new(root_name, root_version, Ecosystem::Packagist)
            .map_err(|e| ParseError::MissingField { field: e })?;

        // Extract different types of dependencies
        let deps = self.extract_dependencies(&json, "require", &root_package)?;
        result.packages.extend(deps.packages);
        result.dependencies.extend(deps.dependencies);

        let dev_deps = self.extract_dependencies(&json, "require-dev", &root_package)?;
        result.packages.extend(dev_deps.packages);
        result.dependencies.extend(dev_deps.dependencies);

        result.source_type = SourceType::Manifest;
        Ok(result)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Packagist
    }

    fn patterns(&self) -> &[FilePattern] {
        &[FilePattern::Name("composer.json")]
    }
}

/// Parser for composer.lock files
pub struct ComposerLockParser;

impl Default for ComposerLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ComposerLockParser {
    pub fn new() -> Self {
        Self
    }

    fn infer_dependency_version(requirement: &str) -> Option<Version> {
        match version_extractor::composer(requirement) {
            Ok(Some((_, version))) => Some(version),
            _ => None,
        }
    }

    /// Extract packages and dependencies from composer.lock
    fn extract_lock_data(&self, json: &Value, section: &str) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();
        let mut pending_dependencies: Vec<(Package, String, String)> = Vec::new();

        if let Some(packages_array) = json.get(section).and_then(|p| p.as_array()) {
            for package_info in packages_array {
                if let Some(package_obj) = package_info.as_object() {
                    let name = package_obj
                        .get("name")
                        .and_then(|n| n.as_str())
                        .ok_or_else(|| ParseError::MissingField {
                            field: "package name".to_string(),
                        })?;

                    let version_str = package_obj
                        .get("version")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| ParseError::MissingField {
                            field: "package version".to_string(),
                        })?;

                    let version =
                        version_extractor::composer_locked(version_str)?.ok_or_else(|| {
                            ParseError::Version {
                                version: version_str.to_string(),
                            }
                        })?;

                    let package = Package::new(name.to_string(), version, Ecosystem::Packagist)
                        .map_err(|e| ParseError::MissingField { field: e })?;

                    packages.push(package.clone());

                    // Extract dependencies from "require" block inside the package
                    if let Some(require) = package_obj.get("require").and_then(|r| r.as_object()) {
                        for (dep_name, dep_req_val) in require {
                            if dep_name == "php" {
                                continue;
                            }

                            if let Some(dep_req) = dep_req_val.as_str() {
                                pending_dependencies.push((
                                    package.clone(),
                                    dep_name.to_string(),
                                    dep_req.to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        let mut package_by_name: HashMap<String, Package> = HashMap::new();
        for package in &packages {
            package_by_name
                .entry(package.name.clone())
                .and_modify(|current| {
                    if package.version > current.version {
                        *current = package.clone();
                    }
                })
                .or_insert_with(|| package.clone());
        }

        for (from, dep_name, dep_req) in pending_dependencies {
            if let Some(existing_target) = package_by_name.get(&dep_name) {
                dependencies.push(Dependency::new(
                    from,
                    existing_target.clone(),
                    dep_req,
                    false,
                ));
                continue;
            }

            if let Some(inferred_version) = Self::infer_dependency_version(&dep_req)
                && let Ok(inferred_target) =
                    Package::new(dep_name, inferred_version, Ecosystem::Packagist)
            {
                dependencies.push(Dependency::new(from, inferred_target, dep_req, false));
            }
        }

        Ok(ParseResult {
            packages,
            dependencies,
            source_type: SourceType::Manifest,
        })
    }
}

impl PackageFileParser for ComposerLockParser {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError> {
        let json: Value = serde_json::from_str(content)?;
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();

        // Extract from packages section
        let result = self.extract_lock_data(&json, "packages")?;
        packages.extend(result.packages);
        dependencies.extend(result.dependencies);

        // Extract from packages-dev section
        let result_dev = self.extract_lock_data(&json, "packages-dev")?;
        packages.extend(result_dev.packages);
        dependencies.extend(result_dev.dependencies);

        Ok(ParseResult {
            packages,
            dependencies,
            source_type: SourceType::LockFile,
        })
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Packagist
    }

    fn patterns(&self) -> &[FilePattern] {
        &[FilePattern::Name("composer.lock")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_composer_json_parser() {
        let parser = ComposerParser::new();
        let content = r#"
        {
            "name": "my/project",
            "require": {
                "php": "^8.0",
                "symfony/console": "^5.4",
                "guzzlehttp/guzzle": "~7.0",
                "monolog/monolog": ">=2.0"
            },
            "require-dev": {
                "phpunit/phpunit": "^9.5",
                "symfony/var-dumper": "*"
            }
        }
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 4); // Excluding php and wildcard

        let symfony_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "symfony/console")
            .unwrap();
        assert_eq!(symfony_pkg.version, Version::parse("5.4").unwrap());
        assert_eq!(symfony_pkg.ecosystem, Ecosystem::Packagist);

        let guzzle_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "guzzlehttp/guzzle")
            .unwrap();
        assert_eq!(guzzle_pkg.version, Version::parse("7.0").unwrap());
    }

    #[test]
    fn test_composer_lock_parser() {
        let parser = ComposerLockParser::new();
        let content = r#"
        {
            "_readme": [
                "This file locks the dependencies of your project to a known state"
            ],
            "packages": [
                {
                    "name": "symfony/console",
                    "version": "v5.4.8",
                    "source": {
                        "type": "git",
                        "url": "https://github.com/symfony/console.git",
                        "reference": "7fccea8728aa2d431a6725b02b3ce759049fc84d"
                    },
                    "require": {
                        "php": ">=7.2.5",
                        "symfony/polyfill-mbstring": "~1.0",
                        "symfony/service-contracts": "^1.1|^2"
                    }
                },
                {
                    "name": "monolog/monolog",
                    "version": "2.5.0",
                    "source": {
                        "type": "git",
                        "url": "https://github.com/Seldaek/monolog.git",
                        "reference": "4192345e260f1d51b365536199744b987e160edc"
                    }
                }
            ],
            "packages-dev": [
                {
                    "name": "phpunit/phpunit",
                    "version": "9.5.20",
                    "source": {
                        "type": "git",
                        "url": "https://github.com/sebastianbergmann/phpunit.git",
                        "reference": "12bc8879fb65aef2138b26fc633cb1e3620cffba"
                    }
                }
            ]
        }
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 3);

        let symfony_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "symfony/console")
            .unwrap();
        assert_eq!(symfony_pkg.version, Version::parse("5.4.8").unwrap());

        // Check dependencies
        let deps: Vec<_> = result
            .dependencies
            .iter()
            .filter(|d| d.from.name == "symfony/console")
            .collect();
        assert_eq!(deps.len(), 2); // php is skipped

        let polyfill_dep = deps
            .iter()
            .find(|d| d.to.name == "symfony/polyfill-mbstring")
            .unwrap();
        assert_eq!(polyfill_dep.requirement, "~1.0");

        let monolog_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "monolog/monolog")
            .unwrap();
        assert_eq!(monolog_pkg.version, Version::parse("2.5.0").unwrap());
    }

    #[test]
    fn test_parser_patterns() {
        let composer_parser = ComposerParser::new();
        let lock_parser = ComposerLockParser::new();

        assert_eq!(
            composer_parser.patterns(),
            &[FilePattern::Name("composer.json")]
        );
        assert_eq!(
            lock_parser.patterns(),
            &[FilePattern::Name("composer.lock")]
        );
    }
}
