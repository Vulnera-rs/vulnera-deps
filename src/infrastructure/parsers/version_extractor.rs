use std::collections::HashMap;

use crate::application::errors::ParseError;
use crate::domain::vulnerability::value_objects::Version;

// Centralized version extraction for all ecosystems.
// Returns `Ok(Some(cleaned))` for versions that can be scanned,
// `Ok(None)` for versions that should be skipped (URLs, workspace refs, wildcards),
// `Err` for malformed input.

// ── Shared utilities ──────────────────────────────────────────────────────────

fn strip_v_prefix(s: &str) -> &str {
    s.strip_prefix('v').unwrap_or(s)
}

fn trim(s: &str) -> &str {
    s.trim()
}

fn is_non_semver_url(s: &str) -> bool {
    let v = s.trim();
    v.starts_with("git+")
        || v.starts_with("git://")
        || v.starts_with("http://")
        || v.starts_with("https://")
        || v.starts_with("file:")
        || v.starts_with("link:")
        || v.starts_with("workspace:")
        || v.starts_with("npm:")
        || v.starts_with("github:")
        || v.starts_with("gitlab:")
        || v.starts_with("bitbucket:")
        || v.contains("://")
        || (v.contains('/') && v.contains('#'))
        || v == "."
        || v == ".."
        || v.starts_with("./")
        || v.starts_with("../")
}

fn strip_prefixes<'a>(s: &'a str, prefixes: &[&str]) -> &'a str {
    let mut s = s;
    for p in prefixes {
        if let Some(rest) = s.strip_prefix(p) {
            s = rest;
            break;
        }
    }
    s
}

fn take_first_split<'a>(s: &'a str, delimiters: &[char]) -> &'a str {
    if let Some(pos) = s.find(delimiters) {
        s[..pos].trim()
    } else {
        s.trim()
    }
}

fn handle_wildcard(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() || t == "*" || t.eq_ignore_ascii_case("latest") || t.eq_ignore_ascii_case("x") {
        return None;
    }
    Some(t.to_string())
}

/// Truncate 4+ segment versions like `1.2.3.4` to `1.2.3`.
/// Preserves prerelease/build metadata (e.g., `1.2.3.4-rc.1` -> `1.2.3-rc.1`).
fn truncate_to_3_segments(s: &str) -> String {
    // Split off prerelease/build metadata first
    let (base, suffix) = if let Some(pos) = s.find('-') {
        (&s[..pos], Some(&s[pos..]))
    } else if let Some(pos) = s.find('+') {
        (&s[..pos], Some(&s[pos..]))
    } else {
        (s, None)
    };
    let parts: Vec<&str> = base.split('.').collect();
    if parts.len() > 3 {
        let truncated = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
        match suffix {
            Some(sfx) => format!("{}{}", truncated, sfx),
            None => truncated,
        }
    } else {
        s.to_string()
    }
}

fn normalize_incomplete(s: &str) -> String {
    let dot_count = s.matches('.').count();
    match dot_count {
        0 => format!("{}.0.0", s),
        1 => format!("{}.0", s),
        _ => s.to_string(),
    }
}

// ── npm ───────────────────────────────────────────────────────────────────────

pub fn npm(raw: &str) -> Result<Option<(String, Version)>, ParseError> {
    let s = trim(raw);
    if s.is_empty() {
        return Ok(None);
    }
    if is_non_semver_url(s) {
        return Ok(None);
    }

    let cleaned = strip_prefixes(s, &["^", "~", ">=", "<=", ">", "<", "="]);
    let cleaned = take_first_split(cleaned, &[' ', '\t', '|']);
    let cleaned = trim(cleaned);

    handle_wildcard(cleaned)
        .map(|v| {
            let ver = Version::parse(&v).map_err(|_| ParseError::Version { version: v.clone() })?;
            Ok((v, ver))
        })
        .transpose()
}

pub fn npm_locked(raw: &str) -> Result<Option<Version>, ParseError> {
    let s = trim(raw);
    if s.is_empty() || is_non_semver_url(s) {
        return Ok(None);
    }
    let cleaned = strip_v_prefix(s);
    let v = Version::parse(cleaned).map_err(|_| ParseError::Version {
        version: s.to_string(),
    })?;
    Ok(Some(v))
}

// ── Cargo ─────────────────────────────────────────────────────────────────────

pub fn cargo(raw: &str) -> Result<Option<(String, Version)>, ParseError> {
    let s = trim(raw);
    if s.is_empty() || s == "*" {
        return Ok(None);
    }
    let cleaned = strip_prefixes(s, &["^", "~", ">=", "<=", ">", "<", "="]);
    let cleaned = take_first_split(cleaned, &[',']);
    let cleaned = trim(cleaned);
    if cleaned.is_empty() {
        return Ok(None);
    }
    let ver = Version::parse(cleaned).map_err(|_| ParseError::Version {
        version: s.to_string(),
    })?;
    Ok(Some((cleaned.to_string(), ver)))
}

pub fn cargo_locked(raw: &str) -> Result<Option<Version>, ParseError> {
    let s = trim(raw);
    if s.is_empty() {
        return Ok(None);
    }
    let v = Version::parse(s).map_err(|_| ParseError::Version {
        version: s.to_string(),
    })?;
    Ok(Some(v))
}

// ── Go ────────────────────────────────────────────────────────────────────────

pub fn go_locked(raw: &str) -> Result<Option<Version>, ParseError> {
    let s = trim(raw);
    if s.is_empty() {
        return Ok(None);
    }
    let cleaned = strip_v_prefix(s);

    let cleaned = if let Some(stripped) = cleaned.strip_suffix("+incompatible") {
        stripped
    } else {
        cleaned
    };

    let cleaned = if let Some(dash_pos) = cleaned.find('-') {
        let base = &cleaned[..dash_pos];
        if base.matches('.').count() >= 2 {
            base
        } else {
            cleaned
        }
    } else {
        cleaned
    };

    let v = Version::parse(cleaned).map_err(|_| ParseError::Version {
        version: s.to_string(),
    })?;
    Ok(Some(v))
}

// ── Python (PEP 440 -> semver) ────────────────────────────────────────────────

pub fn python(raw: &str) -> Result<Option<(String, Version)>, ParseError> {
    let s = trim(raw);
    if s.is_empty() || s == "*" {
        return Ok(None);
    }

    let cleaned = strip_prefixes(s, &["==", ">=", "<=", "~=", ">", "<", "!="]);
    let cleaned = take_first_split(cleaned, &[',', ';']);
    let cleaned = trim(cleaned);
    if cleaned.is_empty() {
        return Ok(None);
    }

    let normalized = normalize_python_prerelease(cleaned);
    let normalized = truncate_to_3_segments(&normalized);

    let v = Version::parse(&normalized).map_err(|_| ParseError::Version {
        version: s.to_string(),
    })?;
    Ok(Some((normalized, v)))
}

fn normalize_python_prerelease(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() || !s.contains('.') {
        return normalize_incomplete(s);
    }
    // Check for X.YaN, X.YbN, X.YrcN patterns (PEP 440 prerelease).
    // Use a simple manual scan from the right to find the prerelease marker.
    // First, try the regex approach:
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^(\d+\.\d+(?:\.\d+)?)(a|b|rc)(\d+)$").unwrap()
    });
    if let Some(caps) = RE.captures(s) {
        let base = caps.get(1).unwrap().as_str();
        let pre_type = caps.get(2).unwrap().as_str();
        let pre_num = caps.get(3).unwrap().as_str();
        let semver_pre = match pre_type {
            "a" => "alpha",
            "b" => "beta",
            "rc" => "rc",
            _ => pre_type,
        };
        return format!("{}-{}.{}", normalize_incomplete(base), semver_pre, pre_num);
    }
    normalize_incomplete(s)
}

pub fn python_locked(raw: &str) -> Result<Option<Version>, ParseError> {
    let s = trim(raw);
    if s.is_empty() {
        return Ok(None);
    }
    let cleaned = strip_v_prefix(s);
    let normalized = normalize_python_prerelease(cleaned);
    let normalized = truncate_to_3_segments(&normalized);
    let v = Version::parse(&normalized).map_err(|_| ParseError::Version {
        version: s.to_string(),
    })?;
    Ok(Some(v))
}

// ── Composer (PHP) ────────────────────────────────────────────────────────────

pub fn composer(raw: &str) -> Result<Option<(String, Version)>, ParseError> {
    let s = trim(raw);
    if s.is_empty() || s == "*" {
        return Ok(None);
    }
    if s == "php" {
        return Ok(None);
    }
    let cleaned = strip_prefixes(s, &["^", "~", ">=", "<=", ">", "<", "="]);
    let cleaned = take_first_split(cleaned, &['|', ',']);
    let cleaned = trim(cleaned);
    let cleaned = if let Some(dash_pos) = cleaned.find('-') {
        let base = &cleaned[..dash_pos];
        if base.matches('.').count() >= 1 {
            base
        } else {
            cleaned
        }
    } else {
        cleaned
    };
    let cleaned = trim(cleaned);
    if cleaned.is_empty() {
        return Ok(None);
    }
    let ver = Version::parse(cleaned).map_err(|_| ParseError::Version {
        version: s.to_string(),
    })?;
    Ok(Some((cleaned.to_string(), ver)))
}

pub fn composer_locked(raw: &str) -> Result<Option<Version>, ParseError> {
    let s = trim(raw);
    if s.is_empty() {
        return Ok(None);
    }
    let cleaned = strip_v_prefix(s);
    let v = Version::parse(cleaned).map_err(|_| ParseError::Version {
        version: s.to_string(),
    })?;
    Ok(Some(v))
}

// ── NuGet ─────────────────────────────────────────────────────────────────────

pub fn nuget_locked(raw: &str) -> Result<Option<Version>, ParseError> {
    let s = trim(raw);
    if s.is_empty() || s.contains("$(") {
        return Ok(None);
    }
    let cleaned = if s.starts_with('[') || s.starts_with('(') {
        let inner = s
            .trim_start_matches('[')
            .trim_start_matches('(')
            .trim_end_matches(']')
            .trim_end_matches(')');
        if let Some(comma_pos) = inner.find(',') {
            inner[..comma_pos].trim()
        } else {
            inner.trim()
        }
    } else {
        s
    };

    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        return Ok(None);
    }

    // Handle floating versions like 1.0.0-*
    if cleaned.contains('*') {
        return Ok(None);
    }

    let truncated = truncate_to_3_segments(cleaned);
    let v = Version::parse(&truncated).map_err(|_| ParseError::Version {
        version: s.to_string(),
    })?;
    Ok(Some(v))
}

// ── Maven ─────────────────────────────────────────────────────────────────────

pub fn maven(
    raw: &str,
    properties: &HashMap<String, String>,
) -> Result<Option<String>, ParseError> {
    let s = trim(raw);
    if s.is_empty() {
        return Ok(None);
    }

    let resolved = resolve_maven_properties(s, properties);

    // If resolution left unresolved property references, fail
    if resolved.contains("${") {
        return Err(ParseError::Version {
            version: s.to_string(),
        });
    }

    let cleaned = if resolved.starts_with('[') || resolved.starts_with('(') {
        let inner = resolved
            .trim_start_matches('[')
            .trim_start_matches('(')
            .trim_end_matches(']')
            .trim_end_matches(')');
        if let Some(comma_pos) = inner.find(',') {
            inner[..comma_pos].trim()
        } else {
            inner.trim()
        }
    } else {
        &resolved
    };

    if cleaned.is_empty()
        || cleaned.eq_ignore_ascii_case("latest")
        || cleaned.eq_ignore_ascii_case("release")
    {
        return Ok(None);
    }

    Ok(Some(cleaned.to_string()))
}

fn resolve_maven_properties(s: &str, properties: &HashMap<String, String>) -> String {
    let mut result = s.to_string();
    // Resolve ${property.name} recursively, up to 5 levels
    for _ in 0..5 {
        let before = result.clone();
        if result.starts_with("${") && result.ends_with('}') {
            let key = &result[2..result.len() - 1];
            if let Some(val) = properties.get(key) {
                result = val.clone();
            } else {
                break;
            }
        } else {
            // Replace any remaining ${...} patterns
            let mut replaced = String::new();
            let mut rest = result.as_str();
            while let Some(start) = rest.find("${") {
                replaced.push_str(&rest[..start]);
                let after_start = &rest[start + 2..];
                if let Some(end) = after_start.find('}') {
                    let key = &after_start[..end];
                    if let Some(val) = properties.get(key) {
                        replaced.push_str(val);
                    }
                    rest = &after_start[end + 1..];
                } else {
                    replaced.push_str(&rest[start..]);
                    break;
                }
            }
            replaced.push_str(rest);
            result = replaced;
        }
        if result == before {
            break;
        }
    }
    result
}

// ── RubyGem ───────────────────────────────────────────────────────────────────

pub fn gem_manifest(raw: &str) -> Result<Option<(String, Version)>, ParseError> {
    let s = trim(raw);
    if s.is_empty() {
        return Ok(None);
    }
    // Handle ~> operator (pessimistic version constraint)
    let cleaned = strip_prefixes(s, &["~>", ">=", "<=", ">", "<", "=", "~"]);
    let cleaned = trim(cleaned);
    if cleaned.is_empty() {
        return Ok(None);
    }
    let ver = Version::parse(cleaned).map_err(|_| ParseError::Version {
        version: s.to_string(),
    })?;
    Ok(Some((cleaned.to_string(), ver)))
}

pub fn gem_locked(raw: &str) -> Result<Option<Version>, ParseError> {
    let s = trim(raw);
    if s.is_empty() {
        return Ok(None);
    }
    // Strip platform suffix like -x86_64-linux, -java, -mswin32
    let cleaned = if let Some(dash_pos) = s.find('-') {
        let base = &s[..dash_pos];
        if base.matches('.').count() >= 1 {
            base
        } else {
            s
        }
    } else {
        s
    };

    let truncated = truncate_to_3_segments(cleaned);
    let v = Version::parse(&truncated).map_err(|_| ParseError::Version {
        version: s.to_string(),
    })?;
    Ok(Some(v))
}

// ── Gradle ────────────────────────────────────────────────────────────────────

pub fn gradle_locked(raw: &str) -> Result<Option<Version>, ParseError> {
    let s = trim(raw);
    if s.is_empty() {
        return Ok(None);
    }
    // Skip property references and dynamic versions
    if s.starts_with('$') || s.contains("${") {
        return Ok(None);
    }
    if s.eq_ignore_ascii_case("latest.release")
        || s.eq_ignore_ascii_case("latest.integration")
        || s.eq_ignore_ascii_case("release")
        || s.eq_ignore_ascii_case("latest")
    {
        return Ok(None);
    }
    let cleaned = strip_prefixes(s, &["^", "~", ">=", "<=", ">", "<", "="]);
    let cleaned = trim(cleaned);

    // Handle floating versions like 1.+, 1.2.+
    if cleaned.ends_with('+') {
        return Ok(None);
    }
    // Handle ranges like [1.0, 2.0)
    let cleaned = if (cleaned.starts_with('[') || cleaned.starts_with('('))
        && (cleaned.ends_with(']') || cleaned.ends_with(')'))
    {
        let inner = &cleaned[1..cleaned.len() - 1];
        let parts: Vec<&str> = inner.split(',').map(str::trim).collect();
        let chosen = parts.first().and_then(|p| {
            if !p.is_empty() {
                Some(*p)
            } else {
                parts.get(1).copied()
            }
        });
        chosen.unwrap_or(cleaned)
    } else {
        cleaned
    };

    // Strip classifier suffix like -jre, -android
    let cleaned = if let Some(dash_pos) = cleaned.find('-') {
        let base = &cleaned[..dash_pos];
        if base.matches('.').count() >= 1 {
            base
        } else {
            cleaned
        }
    } else {
        cleaned
    };

    let cleaned = trim(cleaned);
    if cleaned.is_empty() {
        return Ok(None);
    }
    let v = Version::parse(cleaned).map_err(|_| ParseError::Version {
        version: s.to_string(),
    })?;
    Ok(Some(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── npm ──

    #[test]
    fn test_npm_exact() {
        let (cleaned, ver) = npm("1.2.3").unwrap().unwrap();
        assert_eq!(cleaned, "1.2.3");
        assert_eq!(ver, Version::parse("1.2.3").unwrap());
    }

    #[test]
    fn test_npm_caret() {
        let (cleaned, _) = npm("^1.2.3").unwrap().unwrap();
        assert_eq!(cleaned, "1.2.3");
    }

    #[test]
    fn test_npm_tilde() {
        let (cleaned, _) = npm("~1.2.3").unwrap().unwrap();
        assert_eq!(cleaned, "1.2.3");
    }

    #[test]
    fn test_npm_comparison() {
        let (cleaned, _) = npm(">=1.2.3").unwrap().unwrap();
        assert_eq!(cleaned, "1.2.3");
    }

    #[test]
    fn test_npm_url_skipped() {
        assert!(
            npm("https://github.com/user/repo/tarball/master")
                .unwrap()
                .is_none()
        );
        assert!(
            npm("git+https://github.com/user/repo.git")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_npm_wildcard() {
        assert!(npm("*").unwrap().is_none());
        assert!(npm("latest").unwrap().is_none());
    }

    #[test]
    fn test_npm_range_with_space() {
        let (cleaned, _) = npm("1.0.0 - 2.0.0").unwrap().unwrap();
        assert_eq!(cleaned, "1.0.0");
    }

    #[test]
    fn test_npm_or_condition() {
        let (cleaned, _) = npm("1.0.0 || 2.0.0").unwrap().unwrap();
        assert_eq!(cleaned, "1.0.0");
    }

    #[test]
    fn test_npm_workspace_skipped() {
        assert!(npm("workspace:*").unwrap().is_none());
        assert!(npm("workspace:^").unwrap().is_none());
    }

    #[test]
    fn test_npm_locked() {
        let ver = npm_locked("4.17.1").unwrap().unwrap();
        assert_eq!(ver, Version::parse("4.17.1").unwrap());
    }

    #[test]
    fn test_npm_locked_url_skipped() {
        assert!(
            npm_locked("https://github.com/user/repo/tarball/master")
                .unwrap()
                .is_none()
        );
    }

    // ── Cargo ──

    #[test]
    fn test_cargo_exact() {
        let (cleaned, _) = cargo("1.0").unwrap().unwrap();
        assert_eq!(cleaned, "1.0");
    }

    #[test]
    fn test_cargo_caret() {
        let (cleaned, _) = cargo("^1.0").unwrap().unwrap();
        assert_eq!(cleaned, "1.0");
    }

    #[test]
    fn test_cargo_tilde() {
        let (cleaned, _) = cargo("~3.2").unwrap().unwrap();
        assert_eq!(cleaned, "3.2");
    }

    #[test]
    fn test_cargo_comparison() {
        let (cleaned, _) = cargo(">=1.0").unwrap().unwrap();
        assert_eq!(cleaned, "1.0");
    }

    #[test]
    fn test_cargo_range() {
        let (cleaned, _) = cargo(">=1.0, <2.0").unwrap().unwrap();
        assert_eq!(cleaned, "1.0");
    }

    #[test]
    fn test_cargo_wildcard() {
        assert!(cargo("*").unwrap().is_none());
    }

    #[test]
    fn test_cargo_locked() {
        let ver = cargo_locked("1.0.136").unwrap().unwrap();
        assert_eq!(ver, Version::parse("1.0.136").unwrap());
    }

    // ── Go ──

    #[test]
    fn test_go_locked_simple() {
        let ver = go_locked("v1.8.1").unwrap().unwrap();
        assert_eq!(ver, Version::parse("1.8.1").unwrap());
    }

    #[test]
    fn test_go_locked_incompatible() {
        let ver = go_locked("v2.0.0+incompatible").unwrap().unwrap();
        assert_eq!(ver, Version::parse("2.0.0").unwrap());
    }

    #[test]
    fn test_go_locked_pseudo_version() {
        let ver = go_locked("v0.0.0-20220622213112-05595931fe9d")
            .unwrap()
            .unwrap();
        assert_eq!(ver, Version::parse("0.0.0").unwrap());
    }

    #[test]
    fn test_go_locked_no_v_prefix() {
        let ver = go_locked("1.8.1").unwrap().unwrap();
        assert_eq!(ver, Version::parse("1.8.1").unwrap());
    }

    // ── Python ──

    #[test]
    fn test_python_exact() {
        let (cleaned, _) = python("==2.25.1").unwrap().unwrap();
        assert_eq!(cleaned, "2.25.1");
    }

    #[test]
    fn test_python_comparison() {
        let (cleaned, _) = python(">=1.1.0").unwrap().unwrap();
        assert_eq!(cleaned, "1.1.0");
    }

    #[test]
    fn test_python_compatible() {
        let (cleaned, _) = python("~=3.2.0").unwrap().unwrap();
        assert_eq!(cleaned, "3.2.0");
    }

    #[test]
    fn test_python_range() {
        let (cleaned, _) = python(">=2.25.1,<3.0.0").unwrap().unwrap();
        assert_eq!(cleaned, "2.25.1");
    }

    #[test]
    fn test_python_wildcard() {
        assert!(python("*").unwrap().is_none());
    }

    #[test]
    fn test_python_alpha_prerelease() {
        let (_, ver) = python("1.0a1").unwrap().unwrap();
        assert_eq!(ver, Version::parse("1.0.0-alpha.1").unwrap());
    }

    #[test]
    fn test_python_beta_prerelease() {
        let (_, ver) = python("21.5b0").unwrap().unwrap();
        assert_eq!(ver, Version::parse("21.5.0-beta.0").unwrap());
    }

    #[test]
    fn test_python_rc_prerelease() {
        let (_, ver) = python("2.0rc1").unwrap().unwrap();
        assert_eq!(ver, Version::parse("2.0.0-rc.1").unwrap());
    }

    #[test]
    fn test_python_locked() {
        let ver = python_locked("2.31.0").unwrap().unwrap();
        assert_eq!(ver, Version::parse("2.31.0").unwrap());
    }

    #[test]
    fn test_python_locked_with_v() {
        let ver = python_locked("v2.31.0").unwrap().unwrap();
        assert_eq!(ver, Version::parse("2.31.0").unwrap());
    }

    // ── Composer ──

    #[test]
    fn test_composer_caret() {
        let (cleaned, _) = composer("^5.4").unwrap().unwrap();
        assert_eq!(cleaned, "5.4");
    }

    #[test]
    fn test_composer_tilde() {
        let (cleaned, _) = composer("~7.0").unwrap().unwrap();
        assert_eq!(cleaned, "7.0");
    }

    #[test]
    fn test_composer_comparison() {
        let (cleaned, _) = composer(">=2.0").unwrap().unwrap();
        assert_eq!(cleaned, "2.0");
    }

    #[test]
    fn test_composer_pipe_or() {
        let (cleaned, _) = composer("^1.0|^2.0").unwrap().unwrap();
        assert_eq!(cleaned, "1.0");
    }

    #[test]
    fn test_composer_stability() {
        let (cleaned, _) = composer("2.5.0-dev").unwrap().unwrap();
        assert_eq!(cleaned, "2.5.0");
    }

    #[test]
    fn test_composer_wildcard() {
        assert!(composer("*").unwrap().is_none());
    }

    #[test]
    fn test_composer_locked() {
        let ver = composer_locked("v5.4.8").unwrap().unwrap();
        assert_eq!(ver, Version::parse("5.4.8").unwrap());
    }

    // ── NuGet ──

    #[test]
    fn test_nuget_locked_simple() {
        let ver = nuget_locked("13.0.1").unwrap().unwrap();
        assert_eq!(ver, Version::parse("13.0.1").unwrap());
    }

    #[test]
    fn test_nuget_locked_range() {
        let ver = nuget_locked("[2.10.0,3.0.0)").unwrap().unwrap();
        assert_eq!(ver, Version::parse("2.10.0").unwrap());
    }

    #[test]
    fn test_nuget_locked_prerelease() {
        let ver = nuget_locked("1.2.3-rc1").unwrap().unwrap();
        assert_eq!(ver, Version::parse("1.2.3-rc1").unwrap());
    }

    #[test]
    fn test_nuget_locked_property_ref_skipped() {
        assert!(nuget_locked("$(SomeVar)").unwrap().is_none());
    }

    #[test]
    fn test_nuget_locked_4_segment() {
        let ver = nuget_locked("1.2.3.4").unwrap().unwrap();
        assert_eq!(ver, Version::parse("1.2.3").unwrap());
    }

    // ── Maven ──

    #[test]
    fn test_maven_simple() {
        let cleaned = maven("5.3.21", &HashMap::new()).unwrap().unwrap();
        assert_eq!(cleaned, "5.3.21");
    }

    #[test]
    fn test_maven_property_resolution() {
        let mut props = HashMap::new();
        props.insert("spring.version".to_string(), "6.1.5".to_string());
        let cleaned = maven("${spring.version}", &props).unwrap().unwrap();
        assert_eq!(cleaned, "6.1.5");
    }

    #[test]
    fn test_maven_range() {
        let cleaned = maven("[1.0,2.0)", &HashMap::new()).unwrap().unwrap();
        assert_eq!(cleaned, "1.0");
    }

    #[test]
    fn test_maven_unresolved_property() {
        let result = maven("${unknown.property}", &HashMap::new());
        assert!(result.is_err());
    }

    // ── RubyGem ──

    #[test]
    fn test_gem_manifest_simple() {
        let (cleaned, _) = gem_manifest("6.1.0").unwrap().unwrap();
        assert_eq!(cleaned, "6.1.0");
    }

    #[test]
    fn test_gem_manifest_pessimistic() {
        let (cleaned, _) = gem_manifest("~> 6.1.0").unwrap().unwrap();
        assert_eq!(cleaned, "6.1.0");
    }

    #[test]
    fn test_gem_manifest_comparison() {
        let (cleaned, _) = gem_manifest(">= 5.0").unwrap().unwrap();
        assert_eq!(cleaned, "5.0");
    }

    #[test]
    fn test_gem_locked_simple() {
        let ver = gem_locked("13.0.1").unwrap().unwrap();
        assert_eq!(ver, Version::parse("13.0.1").unwrap());
    }

    #[test]
    fn test_gem_locked_platform_suffix() {
        let ver = gem_locked("1.14.0-x86_64-linux").unwrap().unwrap();
        assert_eq!(ver, Version::parse("1.14.0").unwrap());
    }

    #[test]
    fn test_gem_locked_4_segment() {
        let ver = gem_locked("6.1.7.1").unwrap().unwrap();
        assert_eq!(ver, Version::parse("6.1.7").unwrap());
    }

    // ── Gradle ──

    #[test]
    fn test_gradle_locked_simple() {
        let ver = gradle_locked("5.3.21").unwrap().unwrap();
        assert_eq!(ver, Version::parse("5.3.21").unwrap());
    }

    #[test]
    fn test_gradle_locked_property_ref_skipped() {
        assert!(gradle_locked("$someVar").unwrap().is_none());
        assert!(gradle_locked("${someVar}").unwrap().is_none());
    }

    #[test]
    fn test_gradle_locked_floating_skipped() {
        assert!(gradle_locked("1.+").unwrap().is_none());
        assert!(gradle_locked("1.2.+").unwrap().is_none());
    }

    #[test]
    fn test_gradle_locked_range() {
        let ver = gradle_locked("[1.2,2.0)").unwrap().unwrap();
        assert_eq!(ver, Version::parse("1.2").unwrap());
    }

    #[test]
    fn test_gradle_locked_dynamic_skipped() {
        assert!(gradle_locked("latest.release").unwrap().is_none());
        assert!(gradle_locked("latest.integration").unwrap().is_none());
    }

    #[test]
    fn test_gradle_locked_classifier_suffix() {
        let ver = gradle_locked("31.1-jre").unwrap().unwrap();
        assert_eq!(ver, Version::parse("31.1").unwrap());
    }
}
