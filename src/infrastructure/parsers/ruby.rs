//! Ruby ecosystem parsers (Gemfile, Gemfile.lock)
//!
//! Notes:
//! - Gemfile.lock parser prefers resolved versions from the `GEM -> specs:` section.
//! - Gemfile parser extracts the first version-like constraint per `gem` line and cleans it
//!   to a base semver version for querying (e.g., "~> 6.1.0" -> "6.1.0").
//!
//! Limitations:
//! - Some platform-specific versions in Gemfile.lock (e.g., "1.14.0-x86_64-linux") are
//!   normalized to the numeric base (e.g., "1.14.0") to satisfy semver parsing.
//! - Gemfile lines with only git/path constraints default to "0.0.0" for version.

use super::traits::{FilePattern, PackageFileParser, ParseResult, SourceType};
use super::version_extractor;
use crate::application::errors::ParseError;
use crate::domain::vulnerability::{
    entities::{Dependency, Package},
    value_objects::{Ecosystem, Version},
};
use regex::Regex;
use std::collections::HashMap;

fn is_comment_or_blank(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || t.starts_with('#')
}

static RE_GEM_LINE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"(?i)^\s*gem\s+["']([^"']+)["']\s*(?:,\s*(.+))?\s*$"#).unwrap()
});

static RE_QUOTED_STRING: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r#""([^"]+)"|'([^']+)'"#).unwrap());

// ── Lock state machine ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum LockState {
    Searching,
    InGemSection,
    InSpecs,
    InDeps(Package),
}

/// Parse "name (version)" from a trimmed spec line like `actionmailer (6.1.7.1)`.
fn parse_lock_package_entry(s: &str) -> Option<(&str, &str)> {
    let paren_open = s.find('(')?;
    let paren_close = s.rfind(')')?;
    if paren_open >= paren_close {
        return None;
    }
    let name = s[..paren_open].trim();
    let version = s[paren_open + 1..paren_close].trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

/// Parse "name (constraint)" or bare "name" from a trimmed dep line like
/// `actionpack (= 6.1.7.1)` or `rake`.
fn parse_lock_dep_entry(s: &str) -> Option<(&str, Option<&str>)> {
    if let Some(paren_open) = s.find('(') {
        let paren_close = s.rfind(')')?;
        if paren_open >= paren_close {
            return None;
        }
        let name = s[..paren_open].trim();
        let constraint = s[paren_open + 1..paren_close].trim();
        if name.is_empty() {
            return None;
        }
        Some((
            name,
            if constraint.is_empty() {
                None
            } else {
                Some(constraint)
            },
        ))
    } else {
        let name = s.trim();
        if name.is_empty() {
            return None;
        }
        Some((name, None))
    }
}

/// Parse a Gemfile `gem` declaration line to (name, version-like-string).
/// Returns None if the line is not a valid `gem` line.
fn parse_gem_line(line: &str) -> Option<(String, Option<String>)> {
    // Basic match for: gem 'name'[, version_or_constraints, ...]
    // We capture the gem name in group 1, and the rest of the args (if any) in group 2.
    let caps = RE_GEM_LINE.captures(line)?;
    let name = caps.get(1)?.as_str().trim().to_string();
    let args = caps.get(2).map(|m| m.as_str().trim().to_string());

    // If args exist, try to find the first quoted string that looks like a version constraint.
    if let Some(args_str) = args.as_ref() {
        for m in RE_QUOTED_STRING.captures_iter(args_str) {
            let candidate = m
                .get(1)
                .or_else(|| m.get(2))
                .map(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if candidate.is_empty() {
                continue;
            }
            // We accept the first candidate that contains a digit, then clean it later
            if candidate.chars().any(|c| c.is_ascii_digit()) {
                return Some((name, Some(candidate.to_string())));
            }
        }
    }

    Some((name, None))
}

/// Parser for Gemfile
pub struct GemfileParser;

impl Default for GemfileParser {
    fn default() -> Self {
        Self::new()
    }
}

impl GemfileParser {
    pub fn new() -> Self {
        Self
    }

    fn parse_gemfile_content(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        for line in content.lines() {
            if is_comment_or_blank(line) {
                continue;
            }

            if let Some((name, maybe_constraint)) = parse_gem_line(line) {
                let version = match maybe_constraint {
                    Some(ref c) => match version_extractor::gem_manifest(c)? {
                        Some((_, ver)) => ver,
                        None => Version::parse("0.0.0").unwrap(),
                    },
                    None => Version::parse("0.0.0").unwrap(),
                };

                let package = Package::new(name, version, Ecosystem::RubyGems)
                    .map_err(|e| ParseError::MissingField { field: e })?;
                packages.push(package);
            }
        }

        Ok(packages)
    }
}

impl PackageFileParser for GemfileParser {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError> {
        let packages = self.parse_gemfile_content(content)?;
        Ok(ParseResult {
            packages,
            dependencies: Vec::new(),
            source_type: SourceType::Manifest,
        })
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::RubyGems
    }

    fn patterns(&self) -> &[FilePattern] {
        &[FilePattern::Name("Gemfile")]
    }
}

/// Parser for Gemfile.lock
pub struct GemfileLockParser;

impl Default for GemfileLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl GemfileLockParser {
    pub fn new() -> Self {
        Self
    }

    fn parse_gemfile_lock_content(&self, content: &str) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();
        let mut state = LockState::Searching;
        let mut pending_dependencies: Vec<(Package, String, String)> = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            let indent = line.len() - trimmed.len();

            // Any top-level section header resets the state machine.
            if indent == 0 {
                if trimmed == "GEM" {
                    state = LockState::InGemSection;
                } else {
                    state = LockState::Searching;
                }
                continue;
            }

            match &state {
                LockState::Searching => {}
                LockState::InGemSection => {
                    if trimmed == "specs:" {
                        state = LockState::InSpecs;
                    }
                }
                LockState::InSpecs => {
                    if indent == 4
                        && let Some((name, raw_version)) = parse_lock_package_entry(trimmed)
                            && let Some(version) = version_extractor::gem_locked(raw_version)? {
                                let package =
                                    Package::new(name.to_string(), version, Ecosystem::RubyGems)
                                        .map_err(|e| ParseError::MissingField { field: e })?;
                                packages.push(package.clone());
                                state = LockState::InDeps(package);
                            }
                }
                LockState::InDeps(current) => {
                    if indent == 6 {
                        if let Some((dep_name, dep_req)) = parse_lock_dep_entry(trimmed) {
                            pending_dependencies.push((
                                current.clone(),
                                dep_name.to_string(),
                                dep_req.unwrap_or("*").to_string(),
                            ));
                        }
                    } else if indent == 4
                        && let Some((name, raw_version)) = parse_lock_package_entry(trimmed)
                            && let Some(version) = version_extractor::gem_locked(raw_version)? {
                                let package =
                                    Package::new(name.to_string(), version, Ecosystem::RubyGems)
                                        .map_err(|e| ParseError::MissingField { field: e })?;
                                packages.push(package.clone());
                                state = LockState::InDeps(package);
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
            if let Some(target) = package_by_name.get(&dep_name) {
                dependencies.push(Dependency::new(from, target.clone(), dep_req, false));
                continue;
            }

            let stripped = dep_req
                .trim()
                .strip_prefix("~> ")
                .or_else(|| dep_req.trim().strip_prefix(">= "))
                .or_else(|| dep_req.trim().strip_prefix("<="))
                .or_else(|| dep_req.trim().strip_prefix("> "))
                .or_else(|| dep_req.trim().strip_prefix("< "))
                .or_else(|| dep_req.trim().strip_prefix("= "))
                .or_else(|| dep_req.trim().strip_prefix("~ "))
                .unwrap_or(dep_req.trim())
                .trim();

            if let Some(version) = version_extractor::gem_locked(stripped)
                .ok()
                .flatten()
                .and_then(|v| Package::new(dep_name.clone(), v, Ecosystem::RubyGems).ok())
            {
                dependencies.push(Dependency::new(from, version, dep_req, false));
            }
        }

        Ok(ParseResult {
            packages,
            dependencies,
            source_type: SourceType::LockFile,
        })
    }
}

impl PackageFileParser for GemfileLockParser {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError> {
        self.parse_gemfile_lock_content(content)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::RubyGems
    }

    fn patterns(&self) -> &[FilePattern] {
        &[FilePattern::Name("Gemfile.lock")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gemfile_parser_basic() {
        let parser = GemfileParser::new();
        let content = r#"
# A sample Gemfile
source "https://rubygems.org"

gem "rails", "~> 6.1.0"
gem 'puma', '>= 5.0'
gem "dotenv-rails"
gem "octokit", "~> 5.0", ">= 5.1" # multiple constraints, we take the first
"#;

        let result = parser.parse(content).unwrap();
        // rails, puma, dotenv-rails, octokit
        assert_eq!(result.packages.len(), 4);
        let rails = result.packages.iter().find(|p| p.name == "rails").unwrap();
        assert_eq!(rails.version, Version::parse("6.1.0").unwrap());

        let puma = result.packages.iter().find(|p| p.name == "puma").unwrap();
        assert_eq!(puma.version, Version::parse("5.0.0").unwrap());

        let dotenv = result
            .packages
            .iter()
            .find(|p| p.name == "dotenv-rails")
            .unwrap();
        assert_eq!(dotenv.version, Version::parse("0.0.0").unwrap());

        let octo = result
            .packages
            .iter()
            .find(|p| p.name == "octokit")
            .unwrap();
        assert_eq!(octo.version, Version::parse("5.0.0").unwrap());
    }

    #[test]
    fn test_gemfile_lock_parser_specs() {
        let parser = GemfileLockParser::new();
        let content = r#"
GEM
  remote: https://rubygems.org/
  specs:
    actionmailer (6.1.7.1)
      actionpack (= 6.1.7.1)
      activesupport (= 6.1.7.1)
    rake (13.0.1)
    nokogiri (1.14.0-x86_64-linux)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  rails (~> 6.1.7)
  rake
"#;

        let result = parser.parse(content).unwrap();
        // We parse specs: actionmailer, rake, nokogiri -> 3
        assert_eq!(result.packages.len(), 3);

        let rake = result.packages.iter().find(|p| p.name == "rake").unwrap();
        assert_eq!(rake.version, Version::parse("13.0.1").unwrap());

        let nok = result
            .packages
            .iter()
            .find(|p| p.name == "nokogiri")
            .unwrap();
        // Cleaned from "1.14.0-x86_64-linux" to "1.14.0"
        assert_eq!(nok.version, Version::parse("1.14.0").unwrap());

        // Check dependencies
        let deps: Vec<_> = result
            .dependencies
            .iter()
            .filter(|d| d.from.name == "actionmailer")
            .collect();
        assert_eq!(deps.len(), 2);

        let actionpack_dep = deps.iter().find(|d| d.to.name == "actionpack").unwrap();
        assert_eq!(actionpack_dep.requirement, "= 6.1.7.1");
    }
}
