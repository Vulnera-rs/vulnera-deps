//! Python ecosystem parsers

use super::traits::{FilePattern, PackageFileParser, ParseResult, SourceType};
use super::version_extractor;
use crate::application::errors::ParseError;
use crate::domain::vulnerability::{
    entities::Package,
    value_objects::{Ecosystem, Version},
};
use pep508_rs::{Requirement, VerbatimUrl};
use std::str::FromStr;

/// Parser for requirements.txt files
pub struct RequirementsTxtParser;

impl Default for RequirementsTxtParser {
    fn default() -> Self {
        Self::new()
    }
}

impl RequirementsTxtParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse a single requirement line
    fn parse_requirement_line(&self, line: &str) -> Result<Option<Package>, ParseError> {
        let mut line = line.trim();

        // Skip empty lines, comments, options, and include directives
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("--")
            || line.starts_with("-r")
            || line.starts_with("-e")
        {
            return Ok(None);
        }

        // Strip inline comments
        if let Some(pos) = line.find('#') {
            line = line[..pos].trim();
            if line.is_empty() {
                return Ok(None);
            }
        }

        // Try pep508_rs parsing - if it fails (e.g. old-style VCS URLs), skip
        let requirement: Requirement<VerbatimUrl> = match Requirement::from_str(line) {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };

        match requirement.version_or_url {
            Some(pep508_rs::VersionOrUrl::VersionSpecifier(ref spec)) => {
                let spec_str = spec.to_string();
                if let Some((_, version)) = version_extractor::python(&spec_str)? {
                    let package =
                        Package::new(requirement.name.to_string(), version, Ecosystem::PyPI)
                            .map_err(|e| ParseError::MissingField { field: e })?;
                    return Ok(Some(package));
                }
                Ok(None)
            }
            None => {
                let version = Version::new(0, 0, 0);
                let package =
                    Package::new(requirement.name.to_string(), version, Ecosystem::PyPI)
                        .map_err(|e| ParseError::MissingField { field: e })?;
                Ok(Some(package))
            }
            _ => Ok(None),
        }
    }
}

impl PackageFileParser for RequirementsTxtParser {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();

        for line in content.lines() {
            if let Some(package) = self.parse_requirement_line(line)? {
                packages.push(package);
            }
        }

        Ok(ParseResult {
            packages,
            dependencies: Vec::new(),
            source_type: SourceType::Manifest,
        })
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }

    fn patterns(&self) -> &[FilePattern] {
        &[FilePattern::Name("requirements.txt")]
    }
}

/// Parser for Pipfile files
pub struct PipfileParser;

impl Default for PipfileParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PipfileParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract dependencies from TOML section
    fn extract_dependencies(
        &self,
        toml_value: &toml::Value,
        section: &str,
    ) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        if let Some(deps) = toml_value.get(section).and_then(|s| s.as_table()) {
            for (name, version_info) in deps {
                let version_str = match version_info {
                    toml::Value::String(v) => v.clone(),
                    toml::Value::Table(t) => {
                        if let Some(version) = t.get("version").and_then(|v| v.as_str()) {
                            version.to_string()
                        } else {
                            "0.0.0".to_string()
                        }
                    }
                    _ => "0.0.0".to_string(),
                };

                let version = match version_extractor::python(&version_str)? {
                    Some((_, v)) => v,
                    None => Version::parse("0.0.0").unwrap(),
                };

                let package = Package::new(name.clone(), version, Ecosystem::PyPI)
                    .map_err(|e| ParseError::MissingField { field: e })?;

                packages.push(package);
            }
        }

        Ok(packages)
    }
}

impl PackageFileParser for PipfileParser {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError> {
        let toml_value: toml::Value = toml::from_str(content)?;
        let mut packages = Vec::new();

        packages.extend(self.extract_dependencies(&toml_value, "packages")?);
        packages.extend(self.extract_dependencies(&toml_value, "dev-packages")?);

        Ok(ParseResult {
            packages,
            dependencies: Vec::new(),
            source_type: SourceType::Manifest,
        })
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }

    fn patterns(&self) -> &[FilePattern] {
        &[FilePattern::Name("Pipfile")]
    }
}

/// Parser for pyproject.toml files
pub struct PyProjectTomlParser;

impl Default for PyProjectTomlParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PyProjectTomlParser {
    pub fn new() -> Self {
        Self
    }

    fn extract_from_tool_table(
        &self,
        toml_value: &toml::Value,
        tool_name: &str,
    ) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();
        if let Some(tool) = toml_value.get("tool")
            && let Some(section) = tool.get(tool_name)
            && let Some(deps) = section.get("dependencies").and_then(|d| d.as_table())
        {
            for (name, version_info) in deps {
                if name == "python" {
                    continue;
                }

                let version_str = match version_info {
                    toml::Value::String(v) => v.clone(),
                    toml::Value::Table(t) => {
                        if let Some(version) = t.get("version").and_then(|v| v.as_str()) {
                            version.to_string()
                        } else {
                            "0.0.0".to_string()
                        }
                    }
                    _ => "0.0.0".to_string(),
                };

                let version = match version_extractor::python(&version_str)? {
                    Some((_, v)) => v,
                    None => Version::parse("0.0.0").unwrap(),
                };

                let package = Package::new(name.clone(), version, Ecosystem::PyPI)
                    .map_err(|e| ParseError::MissingField { field: e })?;

                packages.push(package);
            }
        }
        Ok(packages)
    }

    /// Extract dependencies from pyproject.toml
    fn extract_pyproject_dependencies(
        &self,
        toml_value: &toml::Value,
    ) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        // Extract from project.dependencies
        if let Some(project) = toml_value.get("project") {
            if let Some(deps) = project.get("dependencies").and_then(|d| d.as_array()) {
                for dep in deps {
                    if let Some(dep_str) = dep.as_str()
                        && let Some(package) = self.parse_dependency_string(dep_str)?
                    {
                        packages.push(package);
                    }
                }
            }

            // Extract from project.optional-dependencies
            if let Some(optional_deps) = project
                .get("optional-dependencies")
                .and_then(|d| d.as_table())
            {
                for (_, deps_array) in optional_deps {
                    if let Some(deps) = deps_array.as_array() {
                        for dep in deps {
                            if let Some(dep_str) = dep.as_str()
                                && let Some(package) = self.parse_dependency_string(dep_str)?
                            {
                                packages.push(package);
                            }
                        }
                    }
                }
            }
        }

        // Extract from tool.poetry.dependencies (Poetry format)
        packages.extend(self.extract_from_tool_table(toml_value, "poetry")?);

        // Extract from tool.pdm.dependencies (PDM format - similar to Poetry)
        packages.extend(self.extract_from_tool_table(toml_value, "pdm")?);

        // Extract from tool.flit.metadata (Flit format)
        if let Some(tool) = toml_value.get("tool")
            && let Some(flit) = tool.get("flit")
            && let Some(metadata) = flit.get("metadata")
        {
            if let Some(deps) = metadata.get("requires").and_then(|d| d.as_array()) {
                for dep in deps {
                    if let Some(dep_str) = dep.as_str()
                        && let Some(package) = self.parse_dependency_string(dep_str)?
                    {
                        packages.push(package);
                    }
                }
            }

            if let Some(optional_deps) = metadata.get("requires-extra").and_then(|d| d.as_table()) {
                for (_, deps_array) in optional_deps {
                    if let Some(deps) = deps_array.as_array() {
                        for dep in deps {
                            if let Some(dep_str) = dep.as_str()
                                && let Some(package) = self.parse_dependency_string(dep_str)?
                            {
                                packages.push(package);
                            }
                        }
                    }
                }
            }
        }

        Ok(packages)
    }

    /// Parse a PEP 508 dependency string like "requests>=2.25.1"
    fn parse_dependency_string(&self, dep_str: &str) -> Result<Option<Package>, ParseError> {
        let dep_str = dep_str.trim();

        if dep_str.is_empty() {
            return Ok(None);
        }

        let requirement: Requirement<VerbatimUrl> = Requirement::from_str(dep_str)
            .map_err(|e| ParseError::InvalidContent(e.to_string()))?;

        match requirement.version_or_url {
            Some(pep508_rs::VersionOrUrl::VersionSpecifier(ref spec)) => {
                let spec_str = spec.to_string();
                if let Some((_, version)) = version_extractor::python(&spec_str)? {
                    let package =
                        Package::new(requirement.name.to_string(), version, Ecosystem::PyPI)
                            .map_err(|e| ParseError::MissingField { field: e })?;
                    return Ok(Some(package));
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}

impl PackageFileParser for PyProjectTomlParser {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError> {
        let toml_value: toml::Value = toml::from_str(content)?;
        let packages = self.extract_pyproject_dependencies(&toml_value)?;

        Ok(ParseResult {
            packages,
            dependencies: Vec::new(),
            source_type: SourceType::Manifest,
        })
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }

    fn patterns(&self) -> &[FilePattern] {
        &[FilePattern::Name("pyproject.toml")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_requirements_txt_parser() {
        let parser = RequirementsTxtParser::new();
        let content = r#"
# This is a comment
requests==2.25.1
flask>=1.1.0
django~=3.2.0
numpy
# Another comment
pytest>=6.0.0  # inline comment
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 5);

        let requests_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "requests")
            .unwrap();
        assert_eq!(requests_pkg.version, Version::parse("2.25.1").unwrap());
    }

    #[test]
    fn test_requirements_txt_parser_with_pre_release_versions() {
        let parser = RequirementsTxtParser::new();
        let content = r#"
black==21.5b0
package1==1.0a1
package2==2.0rc1
package3==1.2.3a4
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 4);

        let black_pkg = result.packages.iter().find(|p| p.name == "black").unwrap();
        assert_eq!(black_pkg.version, Version::parse("21.5.0-beta.0").unwrap());
    }

    #[test]
    fn test_requirements_txt_with_trailing_backslash_and_comment() {
        // Trailing backslash is not standard pip continuation; verify it's skipped
        let parser = RequirementsTxtParser::new();
        let content = "requests>=2.25.1\n# next line after backslash is just a comment\nflask>=1.1.0";
        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 2);
    }

    #[test]
    fn test_requirements_txt_skip_include() {
        let parser = RequirementsTxtParser::new();
        let content = "-r other-requirements.txt\nrequests==2.25.1";
        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 1);
    }

    #[test]
    fn test_pipfile_parser() {
        let parser = PipfileParser::new();
        let content = r#"
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
requests = "==2.25.1"
flask = ">=1.1.0"
django = "*"

[dev-packages]
pytest = ">=6.0.0"
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 4);

        let requests_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "requests")
            .unwrap();
        assert_eq!(requests_pkg.version, Version::parse("2.25.1").unwrap());
    }

    #[test]
    fn test_pyproject_toml_parser() {
        let parser = PyProjectTomlParser::new();
        let content = r#"
[project]
name = "my-package"
version = "0.1.0"
dependencies = [
    "requests>=2.25.1",
    "flask==1.1.4",
    "click>=7.0"
]

[project.optional-dependencies]
dev = [
    "pytest>=6.0.0",
    "black>=21.0.0"
]
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 5);

        let requests_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "requests")
            .unwrap();
        assert_eq!(requests_pkg.version, Version::parse("2.25.1").unwrap());
    }

    #[test]
    fn test_pyproject_toml_parser_poetry() {
        let parser = PyProjectTomlParser::new();
        let content = r#"
[tool.poetry.dependencies]
python = "^3.8"
requests = ">=2.25.1"
flask = ">=1.1.0"
click = ">=7.0"
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 3);
    }

    #[test]
    fn test_pyproject_toml_parser_pdm() {
        let parser = PyProjectTomlParser::new();
        let content = r#"
[tool.pdm.dependencies]
requests = ">=2.25.1"
flask = ">=1.1.0"
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 2);
    }

    #[test]
    fn test_pyproject_toml_parser_flit() {
        let parser = PyProjectTomlParser::new();
        let content = r#"
[tool.flit.metadata]
requires = [
    "requests>=2.25.1",
    "flask==1.1.4"
]
requires-extra = { dev = ["pytest>=6.0.0"] }
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 3);
    }

    #[test]
    fn test_parser_patterns() {
        let req_parser = RequirementsTxtParser::new();
        assert_eq!(
            req_parser.patterns(),
            &[FilePattern::Name("requirements.txt")]
        );

        let pipfile_parser = PipfileParser::new();
        assert_eq!(pipfile_parser.patterns(), &[FilePattern::Name("Pipfile")]);

        let pyproject_parser = PyProjectTomlParser::new();
        assert_eq!(
            pyproject_parser.patterns(),
            &[FilePattern::Name("pyproject.toml")]
        );
    }
}
