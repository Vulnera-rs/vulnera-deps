//! Java ecosystem parsers

#![allow(clippy::collapsible_if)]

use super::traits::{FilePattern, PackageFileParser, ParseResult, SourceType};
use crate::application::errors::ParseError;
use crate::domain::vulnerability::{
    entities::Package,
    value_objects::{Ecosystem, Version},
};
use quick_xml::Reader;
use quick_xml::events::Event;
use std::collections::HashMap;
use tree_sitter::{Language, Node, Parser, TreeCursor};

use super::version_extractor;

/// Parser for Maven pom.xml files
pub struct MavenParser;

impl Default for MavenParser {
    fn default() -> Self {
        Self::new()
    }
}

impl MavenParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract dependencies from XML content using quick-xml
    fn extract_maven_dependencies(
        &self,
        content: &str,
        root_package: &Package,
        properties: &HashMap<String, String>,
    ) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();

        let mut reader = Reader::from_str(content);

        let mut buf = Vec::new();
        let mut in_dependency = false;
        let mut current_tag: Option<String> = None;

        let mut group_id: Option<String> = None;
        let mut artifact_id: Option<String> = None;
        let mut version_str: Option<String> = None;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if name == "dependency" {
                        in_dependency = true;
                        group_id = None;
                        artifact_id = None;
                        version_str = None;
                        current_tag = None;
                    } else if in_dependency {
                        current_tag = Some(name);
                    }
                }
                Ok(Event::End(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if name == "dependency" && in_dependency {
                        // finalize this dependency
                        if let (Some(g), Some(a)) = (group_id.as_ref(), artifact_id.as_ref()) {
                            let pkg_name = format!("{}:{}", g, a);
                            // Clean version via centralized extractor
                            let version = match version_extractor::maven(
                                version_str.as_deref().unwrap_or("0.0.0"),
                                properties,
                            ) {
                                Ok(Some(cleaned)) => {
                                    Version::parse(&cleaned).map_err(|_| ParseError::Version {
                                        version: version_str.clone().unwrap_or_default(),
                                    })?
                                }
                                Ok(None) => {
                                    in_dependency = false;
                                    current_tag = None;
                                    continue;
                                }
                                Err(_) => {
                                    tracing::warn!(
                                        package = %pkg_name,
                                        version = %version_str.clone().unwrap_or_default(),
                                        "Skipping Maven dependency with unresolved version property reference"
                                    );
                                    in_dependency = false;
                                    current_tag = None;
                                    continue;
                                }
                            };
                            let package = Package::new(pkg_name, version, Ecosystem::Maven)
                                .map_err(|e| ParseError::MissingField { field: e })?;
                            packages.push(package.clone());

                            dependencies.push(
                                crate::domain::vulnerability::entities::Dependency::new(
                                    root_package.clone(),
                                    package,
                                    version_str.clone().unwrap_or_else(|| "0.0.0".to_string()),
                                    false, // Direct dependency from manifest
                                ),
                            );
                        }
                        in_dependency = false;
                        current_tag = None;
                    } else if in_dependency {
                        current_tag = None;
                    }
                }
                Ok(Event::Text(t)) => {
                    if in_dependency && let Some(tag) = current_tag.as_deref() {
                        let txt = reader
                            .decoder()
                            .decode(t.as_ref())
                            .unwrap_or_default()
                            .trim()
                            .to_string();
                        match tag {
                            "groupId" => group_id = Some(txt.trim().to_string()),
                            "artifactId" => artifact_id = Some(txt.trim().to_string()),
                            "version" => version_str = Some(txt.trim().to_string()),
                            _ => {}
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ParseError::MissingField {
                        field: format!("XML parse error: {}", e),
                    });
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(ParseResult {
            packages,
            dependencies,
            source_type: SourceType::Manifest,
        })
    }

    /// Extract root package information from pom.xml
    fn extract_root_package(
        &self,
        content: &str,
        properties: &HashMap<String, String>,
    ) -> Result<Package, ParseError> {
        let mut reader = Reader::from_str(content);
        let mut buf = Vec::new();
        let mut depth = 0;

        let mut group_id: Option<String> = None;
        let mut artifact_id: Option<String> = None;
        let mut version: Option<String> = None;

        let mut parent_group_id: Option<String> = None;
        let mut parent_version: Option<String> = None;

        let mut current_tag: Option<String> = None;
        let mut in_parent = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    depth += 1;
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if depth == 2 {
                        if name.ends_with("parent") {
                            in_parent = true;
                        }
                        current_tag = Some(name);
                    } else if depth == 3 && in_parent {
                        current_tag = Some(name);
                    }
                }
                Ok(Event::End(_)) => {
                    depth -= 1;
                    current_tag = None;
                    if depth == 1 {
                        in_parent = false;
                    }
                }
                Ok(Event::Text(t)) => {
                    if let Some(tag) = current_tag.as_deref() {
                        let txt = reader
                            .decoder()
                            .decode(t.as_ref())
                            .unwrap_or_default()
                            .trim()
                            .to_string();
                        if !txt.is_empty() {
                            match tag {
                                "groupId" if !in_parent => group_id = Some(txt),
                                "artifactId" if !in_parent => artifact_id = Some(txt),
                                "version" if !in_parent => version = Some(txt),
                                "groupId" if in_parent => parent_group_id = Some(txt),
                                "version" if in_parent => parent_version = Some(txt),
                                _ => {}
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                _ => {}
            }
            buf.clear();
            if depth > 3 {
                continue;
            }
        }

        let g = group_id
            .or(parent_group_id)
            .unwrap_or_else(|| "unknown".to_string());
        let a = artifact_id.unwrap_or_else(|| "root".to_string());
        let v_str = version
            .or(parent_version)
            .unwrap_or_else(|| "0.0.0".to_string());
        let cleaned_v = match version_extractor::maven(&v_str, properties)? {
            Some(s) => s,
            None => "0.0.0".to_string(),
        };
        let v = Version::parse(&cleaned_v).unwrap_or_else(|_| Version::new(0, 0, 0));

        Package::new(format!("{}:{}", g, a), v, Ecosystem::Maven)
            .map_err(|e| ParseError::MissingField { field: e })
    }

    fn extract_maven_properties(
        &self,
        content: &str,
    ) -> Result<HashMap<String, String>, ParseError> {
        let mut properties = HashMap::new();
        let mut reader = Reader::from_str(content);
        let mut buf = Vec::new();

        let mut stack: Vec<String> = Vec::new();
        let mut current_property: Option<String> = None;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    stack.push(name.clone());
                    if stack.len() == 3
                        && stack[0].ends_with("project")
                        && stack[1].ends_with("properties")
                    {
                        current_property = Some(name);
                    }
                }
                Ok(Event::Text(t)) => {
                    let value = reader
                        .decoder()
                        .decode(t.as_ref())
                        .unwrap_or_default()
                        .trim()
                        .to_string();

                    if let Some(property) = current_property.as_ref()
                        && !value.is_empty()
                    {
                        properties.insert(property.clone(), value.clone());
                    }

                    // project.version and shorthand version
                    if stack.len() == 2
                        && stack[0].ends_with("project")
                        && stack[1].ends_with("version")
                        && !value.is_empty()
                    {
                        properties.insert("project.version".to_string(), value.clone());
                        properties.insert("version".to_string(), value.clone());
                    }

                    // project.groupId
                    if stack.len() == 2
                        && stack[0].ends_with("project")
                        && stack[1].ends_with("groupId")
                        && !value.is_empty()
                    {
                        properties.insert("project.groupId".to_string(), value.clone());
                    }

                    // project.artifactId
                    if stack.len() == 2
                        && stack[0].ends_with("project")
                        && stack[1].ends_with("artifactId")
                        && !value.is_empty()
                    {
                        properties.insert("project.artifactId".to_string(), value.clone());
                    }

                    // project.name
                    if stack.len() == 2
                        && stack[0].ends_with("project")
                        && stack[1].ends_with("name")
                        && !value.is_empty()
                    {
                        properties.insert("project.name".to_string(), value.clone());
                    }

                    // project.parent.version
                    if stack.len() == 3
                        && stack[0].ends_with("project")
                        && stack[1].ends_with("parent")
                        && stack[2].ends_with("version")
                        && !value.is_empty()
                    {
                        properties.insert("project.parent.version".to_string(), value.clone());
                    }

                    // project.parent.groupId
                    if stack.len() == 3
                        && stack[0].ends_with("project")
                        && stack[1].ends_with("parent")
                        && stack[2].ends_with("groupId")
                        && !value.is_empty()
                    {
                        properties.insert("project.parent.groupId".to_string(), value);
                    }
                }
                Ok(Event::End(_)) => {
                    if stack.len() == 3
                        && stack[0].ends_with("project")
                        && stack[1].ends_with("properties")
                    {
                        current_property = None;
                    }
                    stack.pop();
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ParseError::MissingField {
                        field: format!("XML parse error: {}", e),
                    });
                }
                _ => {}
            }
            buf.clear();
        }

        // Add Maven built-in version fallback
        properties
            .entry("maven.version".to_string())
            .or_insert_with(|| "3.9.0".to_string());

        Ok(properties)
    }
}

impl PackageFileParser for MavenParser {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError> {
        let properties = self.extract_maven_properties(content)?;
        let root_package = self.extract_root_package(content, &properties)?;
        self.extract_maven_dependencies(content, &root_package, &properties)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Maven
    }

    fn patterns(&self) -> &[FilePattern] {
        &[FilePattern::Name("pom.xml")]
    }
}

const GRADLE_CONFIGS: &[&str] = &[
    "implementation",
    "api",
    "compile",
    "compileOnly",
    "runtimeOnly",
    "testImplementation",
    "testCompile",
    "testCompileOnly",
    "testRuntimeOnly",
    "annotationProcessor",
    "provided",
    "kapt",
    "ksp",
];

fn is_gradle_config(name: &str) -> bool {
    GRADLE_CONFIGS.contains(&name)
}

fn coord_string_to_package(s: &str) -> Option<Package> {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() < 3 {
        return None;
    }
    let group = parts[0].trim();
    let artifact = parts[1].trim();
    let version_str = parts[2].trim();
    if group.is_empty() || artifact.is_empty() || version_str.is_empty() {
        return None;
    }
    let pkg_name = format!("{}:{}", group, artifact);
    let version = version_extractor::gradle_locked(version_str).ok()??;
    Package::new(pkg_name, version, Ecosystem::Maven).ok()
}

fn get_string_value(node: &Node, content: &str) -> Option<String> {
    if let Ok(text) = node.utf8_text(content.as_bytes()) {
        let kind = node.kind();
        if kind == "string_content" {
            return Some(text.to_string());
        }
        if (text.starts_with('\'') && text.ends_with('\''))
            || (text.starts_with('"') && text.ends_with('"'))
        {
            let inner = &text[1..text.len() - 1];
            if !inner.is_empty() {
                return Some(inner.to_string());
            }
        }
    }
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            if let Some(v) = get_string_value(&cursor.node(), content) {
                return Some(v);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    None
}

fn has_platform_project_ancestor(mut node: Node, content: &str) -> bool {
    while let Some(parent) = node.parent() {
        if is_call_kind(parent.kind()) {
            if let Some(first) = parent.named_child(0) {
                if let Ok(name) = first.utf8_text(content.as_bytes()) {
                    if matches!(name, "platform" | "project") {
                        return true;
                    }
                }
            }
        }
        node = parent;
    }
    false
}

fn collect_strings_from_args(node: &Node, content: &str, strings: &mut Vec<String>) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            let kind = child.kind();
            if let Ok(text) = child.utf8_text(content.as_bytes()) {
                let is_platform_or_project = is_call_kind(kind)
                    && child.named_child(0).is_some()
                    && matches!(
                        child
                            .named_child(0)
                            .and_then(|n| n.utf8_text(content.as_bytes()).ok()),
                        Some("platform" | "project")
                    );

                if !is_platform_or_project {
                    if kind == "string_content" {
                        strings.push(text.to_string());
                    } else if (text.starts_with('\'') && text.ends_with('\''))
                        || (text.starts_with('"') && text.ends_with('"'))
                    {
                        let inner = &text[1..text.len() - 1];
                        if !inner.is_empty() {
                            strings.push(inner.to_string());
                        }
                    } else if child.child_count() > 0 {
                        collect_strings_from_args(&child, content, strings);
                    }
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn is_call_kind(kind: &str) -> bool {
    matches!(kind, "call_expression" | "juxt_function_call")
}

fn walk_call_expressions(cursor: &mut TreeCursor, content: &str, packages: &mut Vec<Package>) {
    let node = cursor.node();
    let kind = node.kind();
    if is_call_kind(kind) {
        try_extract_dep(&node, content, packages);
    }
    if cursor.goto_first_child() {
        loop {
            walk_call_expressions(cursor, content, packages);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

fn try_extract_dep(node: &Node, content: &str, packages: &mut Vec<Package>) {
    let fn_name = match node
        .named_child(0)
        .and_then(|n| n.utf8_text(content.as_bytes()).ok())
    {
        Some(n) => n,
        None => return,
    };
    if !is_gradle_config(fn_name) {
        return;
    }
    // Skip if this call_expression is itself wrapped in platform/project
    if has_platform_project_ancestor(*node, content) {
        return;
    }
    // Try direct coordinate string
    let mut strings = Vec::new();
    collect_strings_from_args(node, content, &mut strings);
    for s in &strings {
        if let Some(pkg) = coord_string_to_package(s) {
            packages.push(pkg);
            return;
        }
    }
    // Try named parameters
    try_extract_named(node, content, packages);
}

fn named_children_vec<'tree>(node: &Node<'tree>) -> Vec<Node<'tree>> {
    let mut children = Vec::new();
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i as u32) {
            children.push(child);
        }
    }
    children
}

fn try_extract_named(node: &Node, content: &str, packages: &mut Vec<Package>) {
    let named = named_children_vec(node);
    let mut group = None;
    let mut artifact = None;
    let mut version = None;

    let mut i = 1;
    while i < named.len() {
        let child = &named[i];
        let kind = child.kind();
        if let Ok(text) = child.utf8_text(content.as_bytes()) {
            if kind == "argument_list" || kind == "value_arguments" || kind == "call_suffix" {
                // Recurse into argument containers for both Groovy and Kotlin
                let inner = named_children_vec(child);
                try_extract_named_from_slice(&inner, content, &mut group, &mut artifact, &mut version);
            } else if kind == "map_item" {
                // Groovy named params: group: 'g', name: 'a', version: 'v'
                let inner = named_children_vec(child);
                if inner.len() >= 2 {
                    if let Ok(k) = inner[0].utf8_text(content.as_bytes()) {
                        if let Some(v) = get_string_value(&inner[1], content) {
                            match k {
                                "group" => group = Some(v),
                                "name" => artifact = Some(v),
                                "version" => version = Some(v),
                                _ => {}
                            }
                        }
                    }
                }
            } else if kind == "value_argument" || kind == "named_argument" {
                // Kotlin named params: group = "g", name = "a", version = "v"
                let inner = named_children_vec(child);
                if inner.len() >= 2 {
                    if let Ok(k) = inner[0].utf8_text(content.as_bytes()) {
                        if let Some(v) = get_string_value(&inner[inner.len() - 1], content) {
                            match k {
                                "group" => group = Some(v),
                                "name" => artifact = Some(v),
                                "version" => version = Some(v),
                                _ => {}
                            }
                        }
                    }
                }
            } else if text == "group" || text == "name" || text == "version" {
                // Groovy-style key with value as next named sibling
                if let Some(next) = named.get(i + 1) {
                    if let Some(val) = get_string_value(next, content) {
                        match text {
                            "group" => group = Some(val),
                            "name" => artifact = Some(val),
                            "version" => version = Some(val),
                            _ => {}
                        }
                        i += 1;
                    }
                }
            }
        }
        i += 1;
    }

    fn try_extract_named_from_slice(
        named: &[Node],
        content: &str,
        group: &mut Option<String>,
        artifact: &mut Option<String>,
        version: &mut Option<String>,
    ) {
        for child in named {
            let kind = child.kind();
            if let Ok(text) = child.utf8_text(content.as_bytes()) {
                if kind == "map_item" {
                    let inner = named_children_vec(child);
                    if inner.len() >= 2 {
                        if let Ok(k) = inner[0].utf8_text(content.as_bytes()) {
                            if let Some(v) = get_string_value(&inner[1], content) {
                                match k {
                                    "group" => *group = Some(v),
                                    "name" => *artifact = Some(v),
                                    "version" => *version = Some(v),
                                    _ => {}
                                }
                            }
                        }
                    }
                } else if kind == "value_argument" || kind == "named_argument" {
                    let inner = named_children_vec(child);
                    if inner.len() >= 2 {
                        if let Ok(k) = inner[0].utf8_text(content.as_bytes()) {
                            if let Some(v) = get_string_value(&inner[inner.len() - 1], content) {
                                match k {
                                    "group" => *group = Some(v),
                                    "name" => *artifact = Some(v),
                                    "version" => *version = Some(v),
                                    _ => {}
                                }
                            }
                        }
                    }
                } else if text == "group" || text == "name" || text == "version" {
                    // Fallback: key identifiers may be direct named children
                    // handled by looking at their string sibling
                }
            }
        }
    }

    if let (Some(g), Some(a)) = (group, artifact) {
        let pkg_name = format!("{}:{}", g, a);
        if let Some(v) = version {
            if let Ok(Some(parsed)) = version_extractor::gradle_locked(&v) {
                if let Ok(pkg) = Package::new(pkg_name, parsed, Ecosystem::Maven) {
                    packages.push(pkg);
                }
            }
        }
    }
}

/// Parser for Gradle build files using tree-sitter AST parsing.
/// Supports both Groovy DSL and Kotlin DSL build files.
pub struct GradleParser;

impl Default for GradleParser {
    fn default() -> Self {
        Self::new()
    }
}

impl GradleParser {
    pub fn new() -> Self {
        Self
    }

    fn extract_dependencies(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let kotlin = Self::try_language(content, tree_sitter_kotlin_sqry::language());
        if let Ok(ref pkgs) = kotlin {
            if !pkgs.is_empty() {
                return kotlin;
            }
        }
        let groovy = Self::try_language(content, tree_sitter_groovy_sqry::language());
        if let Ok(ref pkgs) = groovy {
            if !pkgs.is_empty() {
                return groovy;
            }
        }
        if kotlin.is_ok() {
            return kotlin;
        }
        groovy
    }

    fn try_language(content: &str, language: Language) -> Result<Vec<Package>, ParseError> {
        let mut parser = Parser::new();
        if parser.set_language(&language).is_err() {
            return Ok(Vec::new());
        }
        let tree = match parser.parse(content, None) {
            Some(t) => t,
            None => return Ok(Vec::new()),
        };
        let mut packages = Vec::new();
        let root = tree.root_node();
        let mut cursor = root.walk();
        walk_call_expressions(&mut cursor, content, &mut packages);
        Ok(packages)
    }
}

impl PackageFileParser for GradleParser {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError> {
        let packages = self.extract_dependencies(content)?;
        Ok(ParseResult {
            packages,
            dependencies: Vec::new(),
            source_type: SourceType::Manifest,
        })
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Maven
    }

    fn patterns(&self) -> &[FilePattern] {
        &[
            FilePattern::Name("build.gradle"),
            FilePattern::Name("build.gradle.kts"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maven_parser() {
        let parser = MavenParser::new();
        let content = r#"
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.21</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 2);

        let spring_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "org.springframework:spring-core")
            .unwrap();
        assert_eq!(spring_pkg.version, Version::parse("5.3.21").unwrap());
        assert_eq!(spring_pkg.ecosystem, Ecosystem::Maven);
    }

    #[test]
    fn test_gradle_parser() {
        let parser = GradleParser::new();
        let content = r#"
dependencies {
    implementation 'org.springframework:spring-core:5.3.21'
    testImplementation 'junit:junit:4.13.2'
    api group: 'com.google.guava', name: 'guava', version: '31.1-jre'
    compile 'org.apache.commons:commons-lang3:3.12.0'
}
        "#;

        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 4);

        let spring_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "org.springframework:spring-core")
            .unwrap();
        assert_eq!(spring_pkg.version, Version::parse("5.3.21").unwrap());

        let guava_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "com.google.guava:guava")
            .unwrap();
        assert_eq!(guava_pkg.version, Version::parse("31.1").unwrap()); // -jre suffix handled
    }

    #[test]
    fn test_maven_parser_resolves_properties_from_pom() {
        let parser = MavenParser::new();
        let content = r#"
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
    <properties>
        <spring.version>6.1.5</spring.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>${spring.version}</version>
        </dependency>
    </dependencies>
</project>
        "#;

        let result = parser.parse(content).unwrap();
        assert!(result.packages.iter().any(
            |p| p.name == "org.springframework:spring-core" && p.version.to_string() == "6.1.5"
        ));
    }

    #[test]
    fn test_parser_patterns() {
        let maven_parser = MavenParser::new();
        let gradle_parser = GradleParser::new();

        assert_eq!(maven_parser.patterns(), &[FilePattern::Name("pom.xml")]);
        assert_eq!(
            gradle_parser.patterns(),
            &[
                FilePattern::Name("build.gradle"),
                FilePattern::Name("build.gradle.kts"),
            ]
        );
    }

    #[test]
    fn test_gradle_ast_parser_groovy() {
        let parser = GradleParser::new();
        let content = r#"
dependencies {
    implementation 'org.springframework:spring-core:5.3.21'
    testImplementation 'junit:junit:4.13.2'
    api 'com.google.guava:guava:31.1-jre'
    compileOnly 'org.projectlombok:lombok:1.18.24'
    runtimeOnly 'ch.qos.logback:logback-classic:1.4.5'
}
        "#;
        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 5);
    }

    #[test]
    fn test_gradle_ast_parser_kotlin() {
        let parser = GradleParser::new();
        let content = r#"
dependencies {
    implementation("org.springframework:spring-core:5.3.21")
    testImplementation("junit:junit:4.13.2")
    implementation(platform("org.springframework.boot:spring-boot-dependencies:2.7.0"))
    compileOnly("org.projectlombok:lombok:1.18.24")
}
        "#;
        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 3);
    }

    #[test]
    fn test_gradle_ast_parser_named_params_groovy() {
        let parser = GradleParser::new();
        let content = r#"
dependencies {
    implementation group: 'com.google.guava', name: 'guava', version: '31.1-jre'
}
        "#;
        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 1);
        let pkg = &result.packages[0];
        assert_eq!(pkg.name, "com.google.guava:guava");
        assert_eq!(pkg.version, Version::parse("31.1").unwrap());
    }

    #[test]
    fn test_gradle_ast_parser_patterns() {
        let parser = GradleParser::new();
        assert_eq!(
            parser.patterns(),
            &[
                FilePattern::Name("build.gradle"),
                FilePattern::Name("build.gradle.kts"),
            ]
        );
        assert_eq!(parser.ecosystem(), Ecosystem::Maven);
    }

    #[test]
    fn test_gradle_ast_parser_skips_project_refs() {
        let parser = GradleParser::new();
        let content = r#"
dependencies {
    implementation project(':common')
    implementation 'org.example:lib:1.0.0'
}
        "#;
        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 1);
        assert_eq!(result.packages[0].name, "org.example:lib");
    }

    #[test]
    fn test_gradle_ast_parser_empty() {
        let parser = GradleParser::new();
        let content = "";
        let result = parser.parse(content).unwrap();
        assert!(result.packages.is_empty());
    }

    #[test]
    fn test_gradle_ast_parser_no_deps() {
        let parser = GradleParser::new();
        let content = r#"
plugins {
    id 'java'
}
repositories {
    mavenCentral()
}
        "#;
        let result = parser.parse(content).unwrap();
        assert!(result.packages.is_empty());
    }

    #[test]
    fn test_gradle_ast_parser_with_config_names() {
        let parser = GradleParser::new();
        let content = r#"
dependencies {
    implementation 'a:b:1.0'
    api 'c:d:2.0'
    compile 'e:f:3.0'
    compileOnly 'g:h:4.0'
    runtimeOnly 'i:j:5.0'
    testImplementation 'k:l:6.0'
    testCompile 'm:n:7.0'
    annotationProcessor 'o:p:8.0'
    provided 'q:r:9.0'
}
        "#;
        let result = parser.parse(content).unwrap();
        assert_eq!(result.packages.len(), 9);
    }
}
