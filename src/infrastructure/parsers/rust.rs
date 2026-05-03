//! Rust ecosystem parsers

use super::traits::{FilePattern, PackageFileParser, ParseResult, SourceType};
use super::version_extractor;
use crate::domain::errors::ParseError;
use crate::domain::vulnerability::{
    entities::{Dependency, Package},
    value_objects::{Ecosystem, Version},
};

/// Parser for Cargo.toml files
pub struct CargoParser;

impl Default for CargoParser {
    fn default() -> Self {
        Self::new()
    }
}

impl CargoParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract dependencies from TOML section
    fn extract_dependencies(
        &self,
        toml_value: &toml::Value,
        section: &str,
        root_package: &Package,
    ) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();

        if let Some(deps) = toml_value.get(section).and_then(|s| s.as_table()) {
            for (name, version_info) in deps {
                let version_str = match version_info {
                    toml::Value::String(v) => v.clone(),
                    toml::Value::Table(t) => {
                        // Handle complex dependency specifications
                        if let Some(version) = t.get("version").and_then(|v| v.as_str()) {
                            version.to_string()
                        } else if t.get("git").is_some() || t.get("path").is_some() {
                            // Include git/path dependencies as unresolved-version entries
                            // so dependency edges are preserved in analysis graphs.
                            "0.0.0".to_string()
                        } else {
                            "0.0.0".to_string()
                        }
                    }
                    _ => "0.0.0".to_string(),
                };

                // Use centralized version extractor
                let Some((_, version)) = version_extractor::cargo(&version_str)? else {
                    continue; // Skip wildcards (*) and unresolvable versions
                };

                let package = Package::new(name.clone(), version, Ecosystem::Cargo)
                    .map_err(|e| ParseError::MissingField { field: e })?;

                packages.push(package.clone());

                // Create dependency edge from root
                dependencies.push(Dependency::new(
                    root_package.clone(),
                    package,
                    version_str,
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

impl PackageFileParser for CargoParser {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError> {
        let toml_value: toml::Value = toml::from_str(content)?;
        let mut result = ParseResult {
            packages: Vec::new(),
            dependencies: Vec::new(),
            source_type: SourceType::Manifest,
        };

        // Extract root package info
        let root_name = toml_value
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("root")
            .to_string();
        let root_version_str = toml_value
            .get("package")
            .and_then(|p| p.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0");
        let root_version =
            Version::parse(root_version_str).unwrap_or_else(|_| Version::new(0, 0, 0));
        let root_package = Package::new(root_name, root_version, Ecosystem::Cargo)
            .map_err(|e| ParseError::MissingField { field: e })?;

        // Extract from dependencies section
        let deps = self.extract_dependencies(&toml_value, "dependencies", &root_package)?;
        result.packages.extend(deps.packages);
        result.dependencies.extend(deps.dependencies);

        // Extract from dev-dependencies section
        let dev_deps = self.extract_dependencies(&toml_value, "dev-dependencies", &root_package)?;
        result.packages.extend(dev_deps.packages);
        result.dependencies.extend(dev_deps.dependencies);

        // Extract from build-dependencies section
        let build_deps =
            self.extract_dependencies(&toml_value, "build-dependencies", &root_package)?;
        result.packages.extend(build_deps.packages);
        result.dependencies.extend(build_deps.dependencies);

        // Extract from workspace.dependencies section
        let workspace_deps =
            self.extract_dependencies(&toml_value, "workspace.dependencies", &root_package)?;
        result.packages.extend(workspace_deps.packages);
        result.dependencies.extend(workspace_deps.dependencies);

        Ok(result)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    fn patterns(&self) -> &[FilePattern] {
        &[FilePattern::Name("Cargo.toml")]
    }
}

/// Parser for Cargo.lock files
pub struct CargoLockParser;

impl Default for CargoLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl CargoLockParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract packages and dependencies from Cargo.lock
    fn extract_lock_data(&self, toml_value: &toml::Value) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();
        let mut package_map = std::collections::HashMap::new();

        // First pass: Collect all packages
        if let Some(packages_array) = toml_value.get("package").and_then(|p| p.as_array()) {
            for package_info in packages_array {
                if let Some(package_table) = package_info.as_table() {
                    let name = package_table
                        .get("name")
                        .and_then(|n| n.as_str())
                        .ok_or_else(|| ParseError::MissingField {
                            field: "package name".to_string(),
                        })?;

                    let version_str = package_table
                        .get("version")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| ParseError::MissingField {
                            field: "package version".to_string(),
                        })?;

                    let version =
                        version_extractor::cargo_locked(version_str)?.ok_or_else(|| {
                            ParseError::Version {
                                version: version_str.to_string(),
                            }
                        })?;

                    let package = Package::new(name.to_string(), version, Ecosystem::Cargo)
                        .map_err(|e| ParseError::MissingField { field: e })?;

                    packages.push(package.clone());
                    // Key by name and version for precise lookup
                    package_map.insert((name.to_string(), version_str.to_string()), package);
                }
            }
        }

        // Second pass: Build dependency edges
        if let Some(packages_array) = toml_value.get("package").and_then(|p| p.as_array()) {
            for package_info in packages_array {
                if let Some(package_table) = package_info.as_table() {
                    let name = package_table
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or_default();
                    let version_str = package_table
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();

                    if let Some(source_pkg) =
                        package_map.get(&(name.to_string(), version_str.to_string()))
                        && let Some(deps) =
                            package_table.get("dependencies").and_then(|d| d.as_array())
                    {
                        for dep_val in deps {
                            if let Some(dep_str) = dep_val.as_str() {
                                // Format: "name version" or just "name"
                                let parts: Vec<&str> = dep_str.split_whitespace().collect();
                                let dep_name = parts[0];

                                // If version is specified, use it. If not, we have to guess or find the only one.
                                // Cargo.lock usually specifies version if ambiguous.
                                let target_pkg: Option<Package> = if parts.len() >= 2 {
                                    let dep_version = parts[1];
                                    package_map
                                        .get(&(dep_name.to_string(), dep_version.to_string()))
                                        .cloned()
                                } else {
                                    package_map
                                        .iter()
                                        .find(|((n, _), _)| n == dep_name)
                                        .map(|(_, p)| p.clone())
                                };

                                if let Some(target) = target_pkg {
                                    dependencies.push(Dependency::new(
                                        source_pkg.clone(),
                                        target.clone(),
                                        target.version.to_string(), // Requirement is effectively the locked version
                                        false, // We don't know if it's transitive from here easily, but in a lockfile everything is explicit
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(ParseResult {
            packages,
            dependencies,
            source_type: SourceType::LockFile,
        })
    }
}

impl PackageFileParser for CargoLockParser {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError> {
        let toml_value: toml::Value = toml::from_str(content)?;
        self.extract_lock_data(&toml_value)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    fn patterns(&self) -> &[FilePattern] {
        &[FilePattern::Name("Cargo.lock")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cargo_toml_parser() {
        let parser = CargoParser::new();
        let content = r#"
[package]
name = "my-package"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
reqwest = "^0.11"
clap = "~3.2"

[dev-dependencies]
tokio-test = "0.4"
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 5);

        let serde_pkg = result.packages.iter().find(|p| p.name == "serde").unwrap();
        assert_eq!(serde_pkg.version, Version::parse("1.0").unwrap());
        assert_eq!(serde_pkg.ecosystem, Ecosystem::Cargo);

        let tokio_pkg = result.packages.iter().find(|p| p.name == "tokio").unwrap();
        assert_eq!(tokio_pkg.version, Version::parse("1.0").unwrap());
    }

    #[test]
    fn test_cargo_lock_parser() {
        let parser = CargoLockParser::new();
        let content = r#"
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "serde"
version = "1.0.136"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.17.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "pin-project-lite",
]
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 2);

        let serde_pkg = result.packages.iter().find(|p| p.name == "serde").unwrap();
        assert_eq!(serde_pkg.version, Version::parse("1.0.136").unwrap());

        let tokio_pkg = result.packages.iter().find(|p| p.name == "tokio").unwrap();
        assert_eq!(tokio_pkg.version, Version::parse("1.17.0").unwrap());
    }

    #[test]
    fn test_parser_patterns() {
        let cargo_parser = CargoParser::new();
        let lock_parser = CargoLockParser::new();

        assert_eq!(cargo_parser.patterns(), &[FilePattern::Name("Cargo.toml")]);
        assert_eq!(lock_parser.patterns(), &[FilePattern::Name("Cargo.lock")]);
    }
}
