use crate::{Config, DetectorKind, Error, Mode, Result, ScanReport};
use hmac::{Hmac, KeyInit, Mac};
use regex::{Captures, Regex};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactResult {
    pub value: Value,
    pub stats: ScanReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactTextResult {
    pub text: String,
    pub stats: ScanReport,
}

#[derive(Debug, Clone)]
pub struct Engine {
    config: Config,
    enabled: HashSet<DetectorKind>,
    field_rules: FieldRules,
    patterns: Patterns,
}

impl Engine {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let enabled = config.redact.iter().copied().collect();
        let field_rules = FieldRules::new(&config);
        let patterns = Patterns::new()?;

        Ok(Self {
            config,
            enabled,
            field_rules,
            patterns,
        })
    }

    pub fn redact_value(&self, value: Value) -> Result<RedactResult> {
        let policy = ReplacementPolicy::from_config(&self.config)?;
        self.redact_value_with_policy(value, &policy)
    }

    pub fn redact_value_with_hash_key(
        &self,
        value: Value,
        hash_key: impl AsRef<[u8]>,
    ) -> Result<RedactResult> {
        let policy = ReplacementPolicy::from_config_with_key(&self.config, hash_key.as_ref())?;
        self.redact_value_with_policy(value, &policy)
    }

    pub fn scan_value(&self, value: &Value) -> Result<ScanReport> {
        self.scan_value_inner(value)
    }

    pub fn redact_str(&self, input: &str) -> Result<RedactTextResult> {
        let policy = ReplacementPolicy::from_config(&self.config)?;
        self.redact_str_with_policy(input, &policy)
    }

    pub fn redact_str_with_hash_key(
        &self,
        input: &str,
        hash_key: impl AsRef<[u8]>,
    ) -> Result<RedactTextResult> {
        let policy = ReplacementPolicy::from_config_with_key(&self.config, hash_key.as_ref())?;
        self.redact_str_with_policy(input, &policy)
    }

    pub fn scan_str(&self, input: &str) -> Result<ScanReport> {
        let scan_policy = ReplacementPolicy::scan();
        let result = self.redact_str_with_policy(input, &scan_policy)?;
        Ok(result.stats)
    }

    fn is_enabled(&self, kind: DetectorKind) -> bool {
        self.enabled.contains(&kind)
    }

    fn redact_value_with_policy(
        &self,
        value: Value,
        policy: &ReplacementPolicy,
    ) -> Result<RedactResult> {
        let (value, stats) = self.redact_value_inner(value, policy)?;
        Ok(RedactResult { value, stats })
    }

    fn redact_value_inner(
        &self,
        value: Value,
        policy: &ReplacementPolicy,
    ) -> Result<(Value, ScanReport)> {
        match value {
            Value::Object(map) => self.redact_object(map, policy),
            Value::Array(items) => self.redact_array(items, policy),
            Value::String(text) => {
                let result = self.redact_str_with_policy(&text, policy)?;
                Ok((Value::String(result.text), result.stats))
            }
            other => Ok((other, ScanReport::default())),
        }
    }

    fn redact_object(
        &self,
        map: Map<String, Value>,
        policy: &ReplacementPolicy,
    ) -> Result<(Value, ScanReport)> {
        let mut output = Map::new();
        let mut stats = ScanReport::default();

        for (key, value) in map {
            if let Some(kind) = self.field_rules.kind_for_field(&key) {
                if self.is_enabled(kind) {
                    stats.record(kind);

                    if policy.mode == Mode::Drop {
                        continue;
                    }

                    let material = value_hash_material(&value)?;
                    let replacement = policy.replacement(kind, &material)?;
                    output.insert(key, Value::String(replacement));
                    continue;
                }
            }

            let (redacted, child_stats) = self.redact_value_inner(value, policy)?;
            stats.merge(child_stats);
            output.insert(key, redacted);
        }

        Ok((Value::Object(output), stats))
    }

    fn redact_array(
        &self,
        items: Vec<Value>,
        policy: &ReplacementPolicy,
    ) -> Result<(Value, ScanReport)> {
        let mut output = Vec::with_capacity(items.len());
        let mut stats = ScanReport::default();

        for item in items {
            let (redacted, child_stats) = self.redact_value_inner(item, policy)?;
            output.push(redacted);
            stats.merge(child_stats);
        }

        Ok((Value::Array(output), stats))
    }

    fn scan_value_inner(&self, value: &Value) -> Result<ScanReport> {
        match value {
            Value::Object(map) => {
                let mut stats = ScanReport::default();

                for (key, value) in map {
                    if let Some(kind) = self.field_rules.kind_for_field(key) {
                        if self.is_enabled(kind) {
                            stats.record(kind);
                            continue;
                        }
                    }

                    stats.merge(self.scan_value_inner(value)?);
                }

                Ok(stats)
            }
            Value::Array(items) => {
                let mut stats = ScanReport::default();

                for item in items {
                    stats.merge(self.scan_value_inner(item)?);
                }

                Ok(stats)
            }
            Value::String(text) => self.scan_str(text),
            _ => Ok(ScanReport::default()),
        }
    }

    fn redact_str_with_policy(
        &self,
        input: &str,
        policy: &ReplacementPolicy,
    ) -> Result<RedactTextResult> {
        let mut text = input.to_owned();
        let mut stats = ScanReport::default();

        if self.is_enabled(DetectorKind::BearerToken) {
            text = self.replace_bearer_tokens(&text, policy, &mut stats)?;
        }

        if self.is_enabled(DetectorKind::Cookie) {
            text = self.replace_cookie_headers(&text, policy, &mut stats)?;
            text = self.replace_cookie_assignments(&text, policy, &mut stats)?;
        }

        if self.is_enabled(DetectorKind::UrlSensitiveParams) {
            text = self.replace_sensitive_url_params(&text, policy, &mut stats)?;
        }

        if self.is_enabled(DetectorKind::Jwt) {
            text = self.replace_jwts(&text, policy, &mut stats)?;
        }

        if self.is_enabled(DetectorKind::Email) {
            text = self.replace_emails(&text, policy, &mut stats)?;
        }

        if self.is_enabled(DetectorKind::Ip) {
            text = self.replace_ipv4_addresses(&text, policy, &mut stats)?;
            text = self.replace_ipv6_addresses(&text, policy, &mut stats)?;
        }

        if self.is_enabled(DetectorKind::Iban) {
            text = self.replace_ibans(&text, policy, &mut stats)?;
        }

        if self.is_enabled(DetectorKind::CreditCard) {
            text = self.replace_credit_cards(&text, policy, &mut stats)?;
        }

        Ok(RedactTextResult { text, stats })
    }

    fn replace_bearer_tokens(
        &self,
        input: &str,
        policy: &ReplacementPolicy,
        stats: &mut ScanReport,
    ) -> Result<String> {
        replace_matches(input, &self.patterns.bearer, stats, |captures, stats| {
            let Some(prefix) = captures.get(1) else {
                return Ok(None);
            };
            let Some(token) = captures.get(2) else {
                return Ok(None);
            };

            stats.record(DetectorKind::BearerToken);
            Ok(Some(format!(
                "{}{}",
                prefix.as_str(),
                policy.replacement(DetectorKind::BearerToken, token.as_str())?
            )))
        })
    }

    fn replace_cookie_headers(
        &self,
        input: &str,
        policy: &ReplacementPolicy,
        stats: &mut ScanReport,
    ) -> Result<String> {
        replace_matches(
            input,
            &self.patterns.cookie_header,
            stats,
            |captures, stats| {
                let Some(header) = captures.get(1) else {
                    return Ok(None);
                };
                let Some(body) = captures.get(2) else {
                    return Ok(None);
                };

                let Some(redacted_body) = redact_cookie_body(body.as_str(), policy, stats)? else {
                    return Ok(None);
                };

                Ok(Some(format!("{}: {}", header.as_str(), redacted_body)))
            },
        )
    }

    fn replace_cookie_assignments(
        &self,
        input: &str,
        policy: &ReplacementPolicy,
        stats: &mut ScanReport,
    ) -> Result<String> {
        replace_matches(
            input,
            &self.patterns.cookie_assignment,
            stats,
            |captures, stats| {
                let Some(prefix) = captures.get(1) else {
                    return Ok(None);
                };
                let Some(body) = captures.get(2) else {
                    return Ok(None);
                };

                let Some(redacted_body) = redact_cookie_body(body.as_str(), policy, stats)? else {
                    return Ok(None);
                };

                Ok(Some(format!("{}{}", prefix.as_str(), redacted_body)))
            },
        )
    }

    fn replace_sensitive_url_params(
        &self,
        input: &str,
        policy: &ReplacementPolicy,
        stats: &mut ScanReport,
    ) -> Result<String> {
        replace_matches(input, &self.patterns.url, stats, |captures, stats| {
            let Some(url) = captures.get(0) else {
                return Ok(None);
            };

            redact_sensitive_url(url.as_str(), policy, stats)
        })
    }

    fn replace_jwts(
        &self,
        input: &str,
        policy: &ReplacementPolicy,
        stats: &mut ScanReport,
    ) -> Result<String> {
        replace_matches(input, &self.patterns.jwt, stats, |captures, stats| {
            let Some(candidate) = captures.get(0) else {
                return Ok(None);
            };

            if !looks_like_jwt(candidate.as_str()) {
                return Ok(None);
            }

            stats.record(DetectorKind::Jwt);
            Ok(Some(
                policy.replacement(DetectorKind::Jwt, candidate.as_str())?,
            ))
        })
    }

    fn replace_emails(
        &self,
        input: &str,
        policy: &ReplacementPolicy,
        stats: &mut ScanReport,
    ) -> Result<String> {
        replace_matches(input, &self.patterns.email, stats, |captures, stats| {
            let Some(email) = captures.get(0) else {
                return Ok(None);
            };

            stats.record(DetectorKind::Email);
            Ok(Some(
                policy.replacement(DetectorKind::Email, email.as_str())?,
            ))
        })
    }

    fn replace_ipv4_addresses(
        &self,
        input: &str,
        policy: &ReplacementPolicy,
        stats: &mut ScanReport,
    ) -> Result<String> {
        replace_matches(input, &self.patterns.ipv4, stats, |captures, stats| {
            let Some(candidate) = captures.get(0) else {
                return Ok(None);
            };

            if Ipv4Addr::from_str(candidate.as_str()).is_err() {
                return Ok(None);
            }

            stats.record(DetectorKind::Ip);
            Ok(Some(
                policy.replacement(DetectorKind::Ip, candidate.as_str())?,
            ))
        })
    }

    fn replace_ipv6_addresses(
        &self,
        input: &str,
        policy: &ReplacementPolicy,
        stats: &mut ScanReport,
    ) -> Result<String> {
        replace_matches(input, &self.patterns.ipv6, stats, |captures, stats| {
            let Some(candidate) = captures.get(0) else {
                return Ok(None);
            };

            if Ipv6Addr::from_str(candidate.as_str()).is_err() {
                return Ok(None);
            }

            stats.record(DetectorKind::Ip);
            Ok(Some(
                policy.replacement(DetectorKind::Ip, candidate.as_str())?,
            ))
        })
    }

    fn replace_ibans(
        &self,
        input: &str,
        policy: &ReplacementPolicy,
        stats: &mut ScanReport,
    ) -> Result<String> {
        let mut output = String::with_capacity(input.len());
        let mut last_end = 0;
        let mut changed = false;

        for candidate_start in self.patterns.iban.find_iter(input) {
            if candidate_start.start() < last_end {
                continue;
            }

            let Some(span_len) = valid_iban_span(&input[candidate_start.start()..]) else {
                continue;
            };
            let end = candidate_start.start() + span_len;
            let candidate = &input[candidate_start.start()..end];

            output.push_str(&input[last_end..candidate_start.start()]);
            stats.record(DetectorKind::Iban);
            output.push_str(&policy.replacement(DetectorKind::Iban, &normalize_iban(candidate))?);
            last_end = end;
            changed = true;
        }

        if changed {
            output.push_str(&input[last_end..]);
            Ok(output)
        } else {
            Ok(input.to_owned())
        }
    }

    fn replace_credit_cards(
        &self,
        input: &str,
        policy: &ReplacementPolicy,
        stats: &mut ScanReport,
    ) -> Result<String> {
        replace_matches(
            input,
            &self.patterns.credit_card,
            stats,
            |captures, stats| {
                let Some(candidate) = captures.get(0) else {
                    return Ok(None);
                };
                let digits = digits_only(candidate.as_str());

                if !(13..=19).contains(&digits.len()) || !is_luhn_valid(&digits) {
                    return Ok(None);
                }

                stats.record(DetectorKind::CreditCard);
                Ok(Some(policy.replacement(DetectorKind::CreditCard, &digits)?))
            },
        )
    }
}

pub fn redact_value(value: Value, config: &Config) -> Result<RedactResult> {
    Engine::new(config.clone())?.redact_value(value)
}

pub fn scan_value(value: &Value, config: &Config) -> Result<ScanReport> {
    Engine::new(config.clone())?.scan_value(value)
}

pub fn redact_str(input: &str, config: &Config) -> Result<RedactTextResult> {
    Engine::new(config.clone())?.redact_str(input)
}

pub fn scan_str(input: &str, config: &Config) -> Result<ScanReport> {
    Engine::new(config.clone())?.scan_str(input)
}

#[derive(Debug, Clone)]
struct Patterns {
    bearer: Regex,
    cookie_header: Regex,
    cookie_assignment: Regex,
    credit_card: Regex,
    email: Regex,
    iban: Regex,
    ipv4: Regex,
    ipv6: Regex,
    jwt: Regex,
    url: Regex,
}

impl Patterns {
    fn new() -> Result<Self> {
        Ok(Self {
            bearer: Regex::new(r"(?i)\b(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})\b")?,
            cookie_header: Regex::new(r"(?i)\b(set-cookie|cookie)\s*:\s*([^\r\n]+)")?,
            cookie_assignment: Regex::new(
                r"(?i)\b(cookie\s+)([A-Za-z0-9_.-]+=[^;\s]+(?:\s*;\s*[A-Za-z0-9_.-]+=[^;\s]+)*)",
            )?,
            credit_card: Regex::new(r"\b\d(?:[ -]?\d){12,18}\b")?,
            email: Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")?,
            iban: Regex::new(r"(?i)\b[A-Z]{2}\d{2}")?,
            ipv4: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")?,
            ipv6: Regex::new(r"(?i)(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}")?,
            jwt: Regex::new(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")?,
            url: Regex::new(r#"(?i)\bhttps?://[^\s"'<>]+"#)?,
        })
    }
}

#[derive(Debug, Clone)]
struct FieldRules {
    deny: Vec<String>,
    allow: HashSet<String>,
}

impl FieldRules {
    fn new(config: &Config) -> Self {
        let deny = config
            .fields_deny
            .iter()
            .map(|field| normalize_field_name(field))
            .filter(|field| !field.is_empty())
            .collect();
        let allow = config
            .fields_allow
            .iter()
            .map(|field| normalize_field_name(field))
            .filter(|field| !field.is_empty())
            .collect();

        Self { deny, allow }
    }

    fn kind_for_field(&self, field: &str) -> Option<DetectorKind> {
        let normalized = normalize_field_name(field);

        if normalized.is_empty() || self.allow.contains(&normalized) {
            return None;
        }

        let matched = self
            .deny
            .iter()
            .any(|deny| normalized == *deny || (deny.len() >= 5 && normalized.contains(deny)));

        if !matched {
            return None;
        }

        if normalized.contains("cookie") {
            Some(DetectorKind::Cookie)
        } else if normalized.contains("authorization") || normalized.contains("bearer") {
            Some(DetectorKind::BearerToken)
        } else {
            Some(DetectorKind::ApiKey)
        }
    }
}

#[derive(Debug, Clone)]
struct ReplacementPolicy {
    mode: Mode,
    hmac_key: Option<Vec<u8>>,
    hash_env: String,
}

impl ReplacementPolicy {
    fn scan() -> Self {
        Self {
            mode: Mode::Mask,
            hmac_key: None,
            hash_env: "PRIVACY_PROXY_HASH_KEY".to_owned(),
        }
    }

    fn from_config(config: &Config) -> Result<Self> {
        let hmac_key = if config.mode == Mode::Hash {
            Some(load_hash_key(&config.hash_env)?)
        } else {
            None
        };

        Ok(Self {
            mode: config.mode,
            hmac_key,
            hash_env: config.hash_env.clone(),
        })
    }

    fn from_config_with_key(config: &Config, key: &[u8]) -> Result<Self> {
        let hmac_key = if config.mode == Mode::Hash {
            if key.is_empty() {
                return Err(Error::MissingHashKey {
                    env: config.hash_env.clone(),
                });
            }
            Some(key.to_vec())
        } else {
            None
        };

        Ok(Self {
            mode: config.mode,
            hmac_key,
            hash_env: config.hash_env.clone(),
        })
    }

    fn replacement(&self, kind: DetectorKind, secret: &str) -> Result<String> {
        match self.mode {
            Mode::Mask => Ok(format!("[REDACTED:{}]", kind.as_str())),
            Mode::Drop => Ok(format!("[DROPPED:{}]", kind.as_str())),
            Mode::Hash => {
                let Some(key) = self.hmac_key.as_deref() else {
                    return Err(Error::MissingHashKey {
                        env: self.hash_env.clone(),
                    });
                };

                let mut mac = HmacSha256::new_from_slice(key).map_err(|_| Error::InvalidHmacKey)?;
                mac.update(secret.as_bytes());
                let digest = mac.finalize().into_bytes();
                Ok(format!(
                    "[HASHED:{}:{}]",
                    kind.as_str(),
                    hex_lower(digest.as_slice())
                ))
            }
        }
    }
}

fn load_hash_key(env_name: &str) -> Result<Vec<u8>> {
    match std::env::var(env_name) {
        Ok(value) if !value.is_empty() => Ok(value.into_bytes()),
        _ => Err(Error::MissingHashKey {
            env: env_name.to_owned(),
        }),
    }
}

fn replace_matches<F>(
    input: &str,
    regex: &Regex,
    stats: &mut ScanReport,
    mut replacement: F,
) -> Result<String>
where
    F: FnMut(&Captures<'_>, &mut ScanReport) -> Result<Option<String>>,
{
    let mut output = String::with_capacity(input.len());
    let mut last_end = 0;
    let mut changed = false;

    for captures in regex.captures_iter(input) {
        let Some(full_match) = captures.get(0) else {
            continue;
        };

        if full_match.start() < last_end {
            continue;
        }

        let Some(replacement) = replacement(&captures, stats)? else {
            continue;
        };

        output.push_str(&input[last_end..full_match.start()]);
        output.push_str(&replacement);
        last_end = full_match.end();
        changed = true;
    }

    if changed {
        output.push_str(&input[last_end..]);
        Ok(output)
    } else {
        Ok(input.to_owned())
    }
}

fn redact_cookie_body(
    body: &str,
    policy: &ReplacementPolicy,
    stats: &mut ScanReport,
) -> Result<Option<String>> {
    let mut output = String::with_capacity(body.len());
    let mut changed = false;

    for (index, part) in body.split(';').enumerate() {
        if index > 0 {
            output.push(';');
        }

        let Some(eq_index) = part.find('=') else {
            output.push_str(part);
            continue;
        };

        let (name_and_eq, value) = part.split_at(eq_index + 1);
        if value.trim().is_empty() {
            output.push_str(part);
            continue;
        }

        stats.record(DetectorKind::Cookie);
        output.push_str(name_and_eq);
        output.push_str(&policy.replacement(DetectorKind::Cookie, value.trim())?);
        changed = true;
    }

    if changed {
        Ok(Some(output))
    } else {
        Ok(None)
    }
}

fn redact_sensitive_url(
    input: &str,
    policy: &ReplacementPolicy,
    stats: &mut ScanReport,
) -> Result<Option<String>> {
    let (url, trailing) = split_trailing_url_punctuation(input);
    let Some(query_start) = url.find('?') else {
        return Ok(None);
    };

    let base = &url[..query_start];
    let query_and_fragment = &url[query_start + 1..];
    let (query, fragment) = match query_and_fragment.find('#') {
        Some(index) => (&query_and_fragment[..index], &query_and_fragment[index..]),
        None => (query_and_fragment, ""),
    };

    let mut changed = false;
    let mut redacted_query = String::with_capacity(query.len());

    for (index, param) in query.split('&').enumerate() {
        if index > 0 {
            redacted_query.push('&');
        }

        let (key, value, had_equals) = match param.find('=') {
            Some(eq_index) => (&param[..eq_index], &param[eq_index + 1..], true),
            None => (param, "", false),
        };

        if is_sensitive_url_param(key) {
            stats.record(DetectorKind::UrlSensitiveParams);
            redacted_query.push_str(key);
            redacted_query.push('=');
            redacted_query.push_str(&policy.replacement(DetectorKind::UrlSensitiveParams, value)?);
            changed = true;
        } else {
            redacted_query.push_str(param);
            if had_equals && param.ends_with('=') {
                continue;
            }
        }
    }

    if !changed {
        return Ok(None);
    }

    Ok(Some(format!("{base}?{redacted_query}{fragment}{trailing}")))
}

fn split_trailing_url_punctuation(input: &str) -> (&str, &str) {
    let mut end = input.len();

    while end > 0 {
        let Some(ch) = input[..end].chars().next_back() else {
            break;
        };

        if matches!(ch, '.' | ',' | ';' | '!') {
            end -= ch.len_utf8();
        } else {
            break;
        }
    }

    (&input[..end], &input[end..])
}

fn is_sensitive_url_param(key: &str) -> bool {
    let normalized = normalize_field_name(key);
    matches!(
        normalized.as_str(),
        "token" | "key" | "secret" | "password" | "code" | "session"
    ) || normalized.ends_with("token")
        || normalized.ends_with("key")
        || normalized.ends_with("secret")
        || normalized.ends_with("password")
        || normalized.ends_with("code")
        || normalized.ends_with("session")
}

fn looks_like_jwt(candidate: &str) -> bool {
    let mut parts = candidate.split('.');
    let Some(header) = parts.next() else {
        return false;
    };
    let Some(payload) = parts.next() else {
        return false;
    };
    let Some(signature) = parts.next() else {
        return false;
    };

    parts.next().is_none()
        && header.starts_with("eyJ")
        && payload.len() >= 8
        && signature.len() >= 8
}

fn digits_only(input: &str) -> String {
    input.chars().filter(|ch| ch.is_ascii_digit()).collect()
}

fn normalize_iban(input: &str) -> String {
    input
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .flat_map(char::to_uppercase)
        .collect()
}

fn valid_iban_span(input: &str) -> Option<usize> {
    let mut normalized_len = 0_usize;
    let mut best_end = None;

    for (offset, ch) in input.char_indices() {
        if ch.is_ascii_alphanumeric() {
            normalized_len += 1;
        } else if !ch.is_ascii_whitespace() {
            break;
        }

        if normalized_len > 34 {
            break;
        }

        let end = offset + ch.len_utf8();
        if ch.is_ascii_alphanumeric() && normalized_len >= 15 && is_valid_iban(&input[..end]) {
            best_end = Some(end);
        }
    }

    best_end
}

fn is_valid_iban(input: &str) -> bool {
    let iban = normalize_iban(input);
    let bytes = iban.as_bytes();

    if !(15..=34).contains(&bytes.len()) {
        return false;
    }

    if !bytes[0].is_ascii_uppercase()
        || !bytes[1].is_ascii_uppercase()
        || !bytes[2].is_ascii_digit()
        || !bytes[3].is_ascii_digit()
    {
        return false;
    }

    let rearranged = format!("{}{}", &iban[4..], &iban[..4]);
    let mut remainder = 0_u32;

    for ch in rearranged.chars() {
        if let Some(digit) = ch.to_digit(10) {
            remainder = (remainder * 10 + digit) % 97;
        } else if ch.is_ascii_uppercase() {
            let value = u32::from(ch) - u32::from('A') + 10;
            remainder = (remainder * 10 + value / 10) % 97;
            remainder = (remainder * 10 + value % 10) % 97;
        } else {
            return false;
        }
    }

    remainder == 1
}

fn is_luhn_valid(digits: &str) -> bool {
    let mut sum = 0_u32;
    let mut double = false;

    for ch in digits.chars().rev() {
        let Some(mut digit) = ch.to_digit(10) else {
            return false;
        };

        if double {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }

        sum += digit;
        double = !double;
    }

    sum % 10 == 0
}

fn normalize_field_name(input: &str) -> String {
    input
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn value_hash_material(value: &Value) -> Result<String> {
    match value {
        Value::String(text) => Ok(text.clone()),
        _ => serde_json::to_string(value).map_err(Error::JsonForHash),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_nested_json_without_touching_allowed_ids() {
        let config = Config::default();
        let input = json!({
            "email": "alice@example.com",
            "password": "correct-horse-battery-staple",
            "trace_id": "00f067aa0ba902b7",
            "nested": {
                "message": "login from 203.0.113.10 with card 4111 1111 1111 1111",
                "callback": "https://example.test/cb?token=abc123&safe=true"
            }
        });

        let result = redact_value(input, &config).expect("redaction succeeds");
        let output = serde_json::to_string(&result.value).expect("serialize redacted JSON");

        assert!(!output.contains("alice@example.com"));
        assert!(!output.contains("correct-horse-battery-staple"));
        assert!(!output.contains("4111 1111 1111 1111"));
        assert!(!output.contains("abc123"));
        assert!(output.contains("00f067aa0ba902b7"));
        assert!(output.contains("[REDACTED:email]"));
        assert!(output.contains("[REDACTED:api_key]"));
        assert!(output.contains("[REDACTED:credit_card]"));
        assert!(output.contains("[REDACTED:url_sensitive_params]"));
    }

    #[test]
    fn drop_mode_removes_sensitive_json_fields() {
        let config = Config {
            mode: Mode::Drop,
            ..Config::default()
        };
        let input = json!({
            "user": "alice",
            "token": "secret-token",
            "nested": {
                "authorization": "Bearer abcdefghijk"
            }
        });

        let result = redact_value(input, &config).expect("redaction succeeds");

        assert!(result.value.get("token").is_none());
        assert_eq!(result.value["user"], "alice");
        assert!(result.value["nested"].get("authorization").is_none());
    }

    #[test]
    fn hash_mode_is_deterministic_with_explicit_key() {
        let config = Config {
            mode: Mode::Hash,
            ..Config::default()
        };
        let engine = Engine::new(config).expect("engine builds");

        let first = engine
            .redact_str_with_hash_key("alice@example.com", b"test-key")
            .expect("hash redaction succeeds");
        let second = engine
            .redact_str_with_hash_key("alice@example.com", b"test-key")
            .expect("hash redaction succeeds");

        assert_eq!(first.text, second.text);
        assert!(!first.text.contains("alice@example.com"));
        assert!(first.text.starts_with("[HASHED:email:"));
    }

    #[test]
    fn scan_reports_counts_only() {
        let report = scan_str(
            "Bearer abcdefghijk and bob@example.com from 2001:db8::1",
            &Config::default(),
        )
        .expect("scan succeeds");

        assert_eq!(report.total, 3);
        assert_eq!(report.by_type.get("bearer_token"), Some(&1));
        assert_eq!(report.by_type.get("email"), Some(&1));
        assert_eq!(report.by_type.get("ip"), Some(&1));
    }

    #[test]
    fn validates_iban_before_redaction() {
        let result = redact_str(
            "iban ES91 2100 0418 4502 0005 1332 and invalid ES00 0000",
            &Config::default(),
        )
        .expect("redaction succeeds");

        assert!(result.text.contains("[REDACTED:iban]"));
        assert!(result.text.contains("ES00 0000"));
    }

    #[test]
    fn redacts_cookie_assignments_in_free_text() {
        let result = redact_str(
            "browser sent cookie session=abc123; theme=light",
            &Config::default(),
        )
        .expect("redaction succeeds");

        assert!(!result.text.contains("abc123"));
        assert!(!result.text.contains("theme=light"));
        assert!(result.text.contains("session=[REDACTED:cookie]"));
        assert_eq!(result.stats.by_type.get("cookie"), Some(&2));
    }
}
