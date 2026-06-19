use crate::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Mask,
    Hash,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorKind {
    Email,
    Ip,
    Jwt,
    BearerToken,
    ApiKey,
    Cookie,
    CreditCard,
    Iban,
    UrlSensitiveParams,
}

impl DetectorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Ip => "ip",
            Self::Jwt => "jwt",
            Self::BearerToken => "bearer_token",
            Self::ApiKey => "api_key",
            Self::Cookie => "cookie",
            Self::CreditCard => "credit_card",
            Self::Iban => "iban",
            Self::UrlSensitiveParams => "url_sensitive_params",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    pub redact: Vec<DetectorKind>,
    pub fields_deny: Vec<String>,
    pub fields_allow: Vec<String>,
    pub hash_env: String,
    pub sample_limit: usize,
    pub max_line_bytes: usize,
    pub max_body_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Mask,
            redact: all_detectors(),
            fields_deny: default_fields_deny(),
            fields_allow: default_fields_allow(),
            hash_env: "PRIVACY_PROXY_HASH_KEY".to_owned(),
            sample_limit: 10_000,
            max_line_bytes: 1_048_576,
            max_body_bytes: 10_485_760,
        }
    }
}

impl Config {
    pub fn from_toml_str(input: &str) -> Result<Self> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    pub fn to_toml_string(&self) -> Result<String> {
        self.validate()?;
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn validate(&self) -> Result<()> {
        if self.hash_env.trim().is_empty() {
            return Err(Error::InvalidConfig("hash_env cannot be empty".to_owned()));
        }

        if self.max_line_bytes == 0 {
            return Err(Error::InvalidConfig(
                "max_line_bytes must be greater than zero".to_owned(),
            ));
        }

        if self.max_body_bytes == 0 {
            return Err(Error::InvalidConfig(
                "max_body_bytes must be greater than zero".to_owned(),
            ));
        }

        Ok(())
    }

    pub fn example_toml() -> &'static str {
        r#"mode = "mask"

redact = [
  "email",
  "ip",
  "jwt",
  "bearer_token",
  "api_key",
  "cookie",
  "credit_card",
  "iban",
  "url_sensitive_params"
]

fields_deny = [
  "password",
  "token",
  "secret",
  "apiKey",
  "authorization",
  "cookie",
  "set-cookie"
]

fields_allow = [
  "trace_id",
  "span_id",
  "request_id"
]

hash_env = "PRIVACY_PROXY_HASH_KEY"
sample_limit = 10000
max_line_bytes = 1048576
max_body_bytes = 10485760
"#
    }
}

fn all_detectors() -> Vec<DetectorKind> {
    vec![
        DetectorKind::Email,
        DetectorKind::Ip,
        DetectorKind::Jwt,
        DetectorKind::BearerToken,
        DetectorKind::ApiKey,
        DetectorKind::Cookie,
        DetectorKind::CreditCard,
        DetectorKind::Iban,
        DetectorKind::UrlSensitiveParams,
    ]
}

fn default_fields_deny() -> Vec<String> {
    [
        "password",
        "passcode",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "secret",
        "client_secret",
        "apiKey",
        "api_key",
        "authorization",
        "cookie",
        "set-cookie",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn default_fields_allow() -> Vec<String> {
    ["trace_id", "span_id", "request_id"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_config() {
        let config = Config::from_toml_str(Config::example_toml()).expect("example config parses");

        assert_eq!(config.mode, Mode::Mask);
        assert!(config.redact.contains(&DetectorKind::Email));
        assert!(config.fields_deny.iter().any(|field| field == "apiKey"));
        assert_eq!(config.max_line_bytes, 1_048_576);
    }

    #[test]
    fn rejects_empty_hash_env() {
        let input = r#"
mode = "mask"
hash_env = ""
"#;

        let error = Config::from_toml_str(input).expect_err("empty hash_env is invalid");

        assert!(error.to_string().contains("hash_env"));
    }

    #[test]
    fn rejects_zero_limits() {
        let input = r#"
mode = "mask"
max_line_bytes = 0
"#;

        let error = Config::from_toml_str(input).expect_err("zero line limit is invalid");

        assert!(error.to_string().contains("max_line_bytes"));
    }
}
