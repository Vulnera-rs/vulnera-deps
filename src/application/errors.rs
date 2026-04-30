//! Application layer error types

use thiserror::Error;

use crate::domain::errors::ParseError;
use crate::domain::vulnerability::errors::VulnerabilityDomainError;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum ApiError {
    #[error("HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("API error: {0}")]
    Other(String),
}

#[derive(Error, Debug, Clone, PartialEq)]
pub enum VulnerabilityError {
    #[error("API error: {0}")]
    Api(#[from] ApiError),
    #[error("Domain creation error: {message}")]
    DomainCreation { message: String },
    #[error("Repository error: {message}")]
    Repository { message: String },
    #[error("Vulnerability error: {0}")]
    Other(String),
}

#[derive(Error, Debug, Clone, PartialEq)]
pub enum ApplicationError {
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),
    #[error("Vulnerability error: {0}")]
    Vulnerability(#[from] VulnerabilityError),
    #[error("Invalid ecosystem: {ecosystem}")]
    InvalidEcosystem { ecosystem: String },
    #[error("Not found: {resource} ({id})")]
    NotFound { resource: String, id: String },
    #[error("Rate limited: {message}")]
    RateLimited { message: String },
    #[error("Configuration error: {message}")]
    Configuration { message: String },
    #[error("Domain error: {0}")]
    Domain(#[from] VulnerabilityDomainError),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("{0}")]
    Other(String),
}

pub type ValidationError = String;
