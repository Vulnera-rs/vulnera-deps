//! Dependency file parsers for different ecosystems
//!
//! Each parser implements the `PackageFileParser` trait, declares its file
//! patterns, and uses the centralized `version_extractor` for deterministic
//! version handling.

pub mod go;
pub mod java;
pub mod npm;
pub mod nuget;
pub mod php;
//merge python and python_uv to support more python ecosystems
pub mod python;
pub mod python_uv;
pub mod ruby;
pub mod rust;
pub mod traits;
pub mod version_extractor;

pub use traits::*;
pub use version_extractor::*;
