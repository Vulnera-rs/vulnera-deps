//! Go ecosystem parsers

use super::traits::{FilePattern, PackageFileParser, ParseResult, SourceType};
use super::version_extractor;
use crate::application::errors::ParseError;
use crate::domain::vulnerability::{entities::Package, value_objects::Ecosystem};

/// Parser for go.mod files
pub struct GoModParser;

impl Default for GoModParser {
    fn default() -> Self {
        Self::new()
    }
}

impl GoModParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse go.mod file content
    fn parse_go_mod(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();
        let mut in_require_block = false;

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with("//") {
                continue;
            }

            // Handle require block
            if line.starts_with("require (") {
                in_require_block = true;
                continue;
            } else if line == ")" && in_require_block {
                in_require_block = false;
                continue;
            }

            // Parse require statements
            if (line.starts_with("require ") || in_require_block)
                && let Some(package) = self.parse_require_line(line)?
            {
                packages.push(package);
            }
        }

        Ok(packages)
    }

    /// Parse a single require line
    fn parse_require_line(&self, line: &str) -> Result<Option<Package>, ParseError> {
        let line = line.trim();

        // Remove "require " prefix if present
        let line = if let Some(stripped) = line.strip_prefix("require ") {
            stripped
        } else {
            line
        };

        // Skip lines that don't look like dependencies
        if line.is_empty() || line.starts_with("//") || line == "(" || line == ")" {
            return Ok(None);
        }

        // Parse module path and version
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return Ok(None);
        }

        let module_path = parts[0];
        let version_str = parts[1];

        let version = match version_extractor::go_locked(version_str)? {
            Some(v) => v,
            None => return Ok(None),
        };

        let package = Package::new(module_path.to_string(), version, Ecosystem::Go)
            .map_err(|e| ParseError::MissingField { field: e })?;

        Ok(Some(package))
    }
}

impl PackageFileParser for GoModParser {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError> {
        let packages = self.parse_go_mod(content)?;
        Ok(ParseResult {
            packages,
            dependencies: Vec::new(),
            source_type: SourceType::Manifest,
        })
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Go
    }

    fn patterns(&self) -> &[FilePattern] {
        &[FilePattern::Name("go.mod")]
    }
}

/// Parser for go.sum files
pub struct GoSumParser;

impl Default for GoSumParser {
    fn default() -> Self {
        Self::new()
    }
}

impl GoSumParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse go.sum file content
    fn parse_go_sum(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();
        let mut seen_modules = std::collections::HashSet::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines
            if line.is_empty() {
                continue;
            }

            // Parse go.sum line format: module version hash
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let module_path = parts[0];
                let version_str = parts[1];

                // Skip /go.mod entries (they're metadata)
                if version_str.ends_with("/go.mod") {
                    continue;
                }

                // Avoid duplicates (go.sum can have multiple entries per module)
                let module_key = format!("{}@{}", module_path, version_str);
                if seen_modules.contains(&module_key) {
                    continue;
                }
                seen_modules.insert(module_key);

                let version = match version_extractor::go_locked(version_str)? {
                    Some(v) => v,
                    None => continue,
                };

                let package = Package::new(module_path.to_string(), version, Ecosystem::Go)
                    .map_err(|e| ParseError::MissingField { field: e })?;

                packages.push(package);
            }
        }

        Ok(packages)
    }
}

impl PackageFileParser for GoSumParser {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError> {
        let packages = self.parse_go_sum(content)?;
        Ok(ParseResult {
            packages,
            dependencies: Vec::new(),
            source_type: SourceType::LockFile,
        })
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Go
    }

    fn patterns(&self) -> &[FilePattern] {
        &[FilePattern::Name("go.sum")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vulnerability::value_objects::Version;

    #[test]
    fn test_go_mod_parser() {
        let parser = GoModParser::new();
        let content = r#"
module example.com/myproject

go 1.18

require (
    github.com/gin-gonic/gin v1.8.1
    github.com/stretchr/testify v1.7.1
    golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
)

require (
    github.com/davecgh/go-spew v1.1.1 // indirect
    github.com/pmezard/go-difflib v1.0.0 // indirect
)
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 5);

        let gin_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "github.com/gin-gonic/gin")
            .unwrap();
        assert_eq!(gin_pkg.version, Version::parse("1.8.1").unwrap());
        assert_eq!(gin_pkg.ecosystem, Ecosystem::Go);

        let crypto_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "golang.org/x/crypto")
            .unwrap();
        assert_eq!(crypto_pkg.version, Version::parse("0.0.0").unwrap());
    }

    #[test]
    fn test_go_sum_parser() {
        let parser = GoSumParser::new();
        let content = r#"
github.com/gin-gonic/gin v1.8.1 h1:4+fr/el88TOO3ewCmQr8cx/CtZ/umlIRIs5M4NTNjf8=
github.com/gin-gonic/gin v1.8.1/go.mod h1:ji8BvRH1azfM+SYow9zQ6SZMvR8qOMZHmsCuWR9tTTk=
github.com/stretchr/testify v1.7.1 h1:5TQK59W5E3v0r2duFAb7P95B6hEeOyEnHRa8MjYSMTY=
github.com/stretchr/testify v1.7.1/go.mod h1:6Fq8oRcR53rry900zMqJjRRixrwX3KX962/h/Wwjteg=
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 2); // Should skip /go.mod entries

        let gin_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "github.com/gin-gonic/gin")
            .unwrap();
        assert_eq!(gin_pkg.version, Version::parse("1.8.1").unwrap());
    }

    #[test]
    fn test_go_mod_inline_require() {
        let parser = GoModParser::new();
        let content = r#"
module example.com/myapp

go 1.21

require github.com/gin-gonic/gin v1.9.1
require github.com/stretchr/testify v1.8.4
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 2);

        let gin_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "github.com/gin-gonic/gin")
            .unwrap();
        assert_eq!(gin_pkg.version, Version::parse("1.9.1").unwrap());

        let testify_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "github.com/stretchr/testify")
            .unwrap();
        assert_eq!(testify_pkg.version, Version::parse("1.8.4").unwrap());
    }

    #[test]
    fn test_parser_patterns() {
        let mod_parser = GoModParser::new();
        let sum_parser = GoSumParser::new();

        assert_eq!(mod_parser.patterns(), &[FilePattern::Name("go.mod")]);
        assert_eq!(sum_parser.patterns(), &[FilePattern::Name("go.sum")]);
    }
}
