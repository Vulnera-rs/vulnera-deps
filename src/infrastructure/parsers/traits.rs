use std::sync::Arc;

use crate::application::errors::ParseError;
use crate::domain::vulnerability::entities::{Dependency, Package};
use crate::domain::vulnerability::value_objects::Ecosystem;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilePattern {
    Name(&'static str),
    Extension(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum SourceType {
    #[default]
    Manifest,
    LockFile,
}


#[derive(Debug, Default)]
pub struct ParseResult {
    pub packages: Vec<Package>,
    pub dependencies: Vec<Dependency>,
    pub source_type: SourceType,
}

pub trait PackageFileParser: Send + Sync {
    fn parse(&self, content: &str) -> Result<ParseResult, ParseError>;
    fn ecosystem(&self) -> Ecosystem;
    fn patterns(&self) -> &[FilePattern];
}

pub struct ParserFactory {
    entries: Vec<ParserEntry>,
}

struct ParserEntry {
    parser: Arc<dyn PackageFileParser>,
    name_patterns: Vec<&'static str>,
    ext_patterns: Vec<&'static str>,
    priority: u8,
    ecosystem: Ecosystem,
}

impl ParserFactory {
    pub fn new() -> Self {
        Self::builtin()
    }

    /// Create an empty factory for custom registration (builder pattern).
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            entries: Vec::with_capacity(cap),
        }
    }

    pub fn register(mut self, parser: Arc<dyn PackageFileParser>) -> Self {
        let patterns = parser.patterns();
        let eco = parser.ecosystem();
        let mut name_patterns = Vec::new();
        let mut ext_patterns = Vec::new();
        for p in patterns.iter() {
            match p {
                FilePattern::Name(n) => name_patterns.push(*n),
                FilePattern::Extension(e) => ext_patterns.push(*e),
            }
        }
        self.entries.push(ParserEntry {
            parser,
            name_patterns,
            ext_patterns,
            priority: 0,
            ecosystem: eco,
        });
        self
    }

    pub fn register_with_priority(
        mut self,
        parser: Arc<dyn PackageFileParser>,
        priority: u8,
    ) -> Self {
        let patterns = parser.patterns();
        let eco = parser.ecosystem();
        let mut name_patterns = Vec::new();
        let mut ext_patterns = Vec::new();
        for p in patterns.iter() {
            match p {
                FilePattern::Name(n) => name_patterns.push(*n),
                FilePattern::Extension(e) => ext_patterns.push(*e),
            }
        }
        self.entries.push(ParserEntry {
            parser,
            name_patterns,
            ext_patterns,
            priority,
            ecosystem: eco,
        });
        self
    }

    pub fn builtin() -> Self {
        let mut factory = Self::with_capacity(24);

        // npm
        factory = factory.register(Arc::new(super::npm::NpmParser));
        factory = factory.register(Arc::new(super::npm::PackageLockParser));
        factory = factory.register(Arc::new(super::npm::YarnLockParser));

        // python
        factory = factory.register(Arc::new(super::python::RequirementsTxtParser));
        factory = factory.register(Arc::new(super::python::PipfileParser));
        factory = factory.register(Arc::new(super::python::PyProjectTomlParser));

        // uv
        factory = factory.register(Arc::new(super::python_uv::UvLockParser));

        // maven
        factory = factory.register(Arc::new(super::java::MavenParser));

        // gradle - tree-sitter AST parser
        factory = factory.register(Arc::new(super::java::GradleParser));

        // cargo
        factory = factory.register(Arc::new(super::rust::CargoParser));
        factory = factory.register(Arc::new(super::rust::CargoLockParser));

        // go
        factory = factory.register(Arc::new(super::go::GoModParser));
        factory = factory.register(Arc::new(super::go::GoSumParser));

        // php
        factory = factory.register(Arc::new(super::php::ComposerParser));
        factory = factory.register(Arc::new(super::php::ComposerLockParser));

        // ruby
        factory = factory.register(Arc::new(super::ruby::GemfileParser));
        factory = factory.register(Arc::new(super::ruby::GemfileLockParser));

        // nuget
        factory = factory.register(Arc::new(super::nuget::NuGetPackagesConfigParser));
        factory = factory.register(Arc::new(super::nuget::NuGetProjectXmlParser));

        factory
    }

    pub fn create_parser(&self, path: &str) -> Option<Arc<dyn PackageFileParser>> {
        let path = std::path::Path::new(path);
        let file_name = path.file_name().and_then(|n| n.to_str());
        let extension = path.extension().and_then(|e| e.to_str());

        let mut candidates: Vec<&ParserEntry> = Vec::new();

        for entry in &self.entries {
            if let Some(fname) = file_name
                && entry.name_patterns.contains(&fname) {
                    candidates.push(entry);
                    continue;
                }
            if let Some(ext) = extension
                && entry.ext_patterns.contains(&ext) {
                    candidates.push(entry);
                }
        }

        candidates
            .into_iter()
            .max_by_key(|e| e.priority)
            .map(|e| e.parser.clone())
    }

    pub fn detect_ecosystem(&self, path: &str) -> Option<Ecosystem> {
        let path = std::path::Path::new(path);
        let file_name = path.file_name().and_then(|n| n.to_str());
        let extension = path.extension().and_then(|e| e.to_str());

        let mut best_priority: u8 = 0;
        let mut best_ecosystem: Option<Ecosystem> = None;

        for entry in &self.entries {
            let matches = match (file_name, extension) {
                (Some(fname), _) if entry.name_patterns.contains(&fname) => true,
                (_, Some(ext)) if entry.ext_patterns.contains(&ext) => true,
                _ => false,
            };

            if matches && entry.priority > best_priority {
                best_priority = entry.priority;
                best_ecosystem = Some(entry.ecosystem.clone());
            }
        }

        best_ecosystem
    }
}

impl Default for ParserFactory {
    fn default() -> Self {
        Self::builtin()
    }
}
