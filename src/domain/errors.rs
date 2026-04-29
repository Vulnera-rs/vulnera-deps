use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum ParseError {
    #[error("Invalid content: {0}")]
    InvalidContent(String),
    #[error("Missing required field: {field}")]
    MissingField { field: String },
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
    #[error("Invalid version: {version}")]
    Version { version: String },
    #[error("Parse error: {0}")]
    Other(String),
}

impl From<serde_json::Error> for ParseError {
    fn from(e: serde_json::Error) -> Self {
        ParseError::InvalidContent(e.to_string())
    }
}

impl From<toml::de::Error> for ParseError {
    fn from(e: toml::de::Error) -> Self {
        ParseError::InvalidContent(e.to_string())
    }
}
