use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid detector pattern: {0}")]
    Regex(#[from] regex::Error),

    #[error("invalid TOML configuration: {0}")]
    TomlDe(#[from] toml::de::Error),

    #[error("failed to serialize TOML configuration: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("hash mode requires a non-empty key; set environment variable `{env}` or pass an explicit key")]
    MissingHashKey { env: String },

    #[error("failed to serialize JSON value while hashing")]
    JsonForHash(#[source] serde_json::Error),

    #[error("failed to initialize HMAC-SHA256")]
    InvalidHmacKey,
}
