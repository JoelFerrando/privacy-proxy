#![forbid(unsafe_code)]

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::header::{
    ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, TRANSFER_ENCODING,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use privacy_proxy_core::{Config, DetectorKind, Engine, Error as CoreError, ScanReport};
use serde::Serialize;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::{info, warn};
use url::Url;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid target URL: {0}")]
    InvalidTarget(#[from] url::ParseError),

    #[error("failed to bind proxy listener: {0}")]
    Bind(#[source] std::io::Error),

    #[error("proxy server failed: {0}")]
    Server(#[source] std::io::Error),

    #[error("failed to initialize privacy engine: {0}")]
    Engine(#[from] CoreError),
}

#[derive(Debug, Clone)]
pub struct ServeOptions {
    pub listen: SocketAddr,
    pub target: String,
    pub config: Config,
}

pub async fn serve(options: ServeOptions) -> Result<()> {
    let target = Url::parse(&options.target)?;
    let engine = Engine::new(options.config.clone())?;
    let state = ProxyState {
        target,
        client: reqwest::Client::new(),
        engine,
        config: options.config,
        metrics: Arc::new(ProxyMetrics::default()),
    };
    let listen = options.listen;
    let target_label = safe_target_label(&state.target).into_owned();
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(Error::Bind)?;

    info!(
        %listen,
        target = %target_label,
        "privacy proxy listening"
    );
    axum::serve(listener, app).await.map_err(Error::Server)
}

fn router(state: ProxyState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/metrics/prometheus", get(prometheus_metrics))
        .fallback(proxy)
        .with_state(state)
}

#[derive(Clone)]
struct ProxyState {
    target: Url,
    client: reqwest::Client,
    engine: Engine,
    config: Config,
    metrics: Arc<ProxyMetrics>,
}

#[derive(Debug, Default)]
struct ProxyMetrics {
    requests: AtomicU64,
    upstream_errors: AtomicU64,
    rejected_payloads: AtomicU64,
    request_bytes: AtomicU64,
    forwarded_bytes: AtomicU64,
    redactions_total: AtomicU64,
    redactions_by_type: Mutex<BTreeMap<String, u64>>,
}

#[derive(Debug, Serialize)]
struct MetricsSnapshot {
    requests: u64,
    upstream_errors: u64,
    rejected_payloads: u64,
    request_bytes: u64,
    forwarded_bytes: u64,
    redactions_total: u64,
    redactions_by_type: BTreeMap<String, u64>,
}

impl ProxyMetrics {
    fn record_report(&self, report: ScanReport) {
        self.redactions_total
            .fetch_add(report.total, Ordering::Relaxed);

        if report.by_type.is_empty() {
            return;
        }

        let Ok(mut by_type) = self.redactions_by_type.lock() else {
            return;
        };

        for (kind, count) in report.by_type {
            let current = by_type.entry(kind).or_insert(0);
            *current = current.saturating_add(count);
        }
    }

    fn record_kind(&self, kind: DetectorKind) {
        self.redactions_total.fetch_add(1, Ordering::Relaxed);

        let Ok(mut by_type) = self.redactions_by_type.lock() else {
            return;
        };
        let current = by_type.entry(kind.as_str().to_owned()).or_insert(0);
        *current = current.saturating_add(1);
    }

    fn snapshot(&self) -> MetricsSnapshot {
        let redactions_by_type = self
            .redactions_by_type
            .lock()
            .map(|by_type| by_type.clone())
            .unwrap_or_default();

        MetricsSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            upstream_errors: self.upstream_errors.load(Ordering::Relaxed),
            rejected_payloads: self.rejected_payloads.load(Ordering::Relaxed),
            request_bytes: self.request_bytes.load(Ordering::Relaxed),
            forwarded_bytes: self.forwarded_bytes.load(Ordering::Relaxed),
            redactions_total: self.redactions_total.load(Ordering::Relaxed),
            redactions_by_type,
        }
    }
}

async fn healthz() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}

async fn metrics(State(state): State<ProxyState>) -> impl IntoResponse {
    (StatusCode::OK, axum::Json(state.metrics.snapshot()))
}

async fn prometheus_metrics(State(state): State<ProxyState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )],
        render_prometheus_metrics(&state.metrics.snapshot()),
    )
}

async fn proxy(State(state): State<ProxyState>, request: Request<Body>) -> Response<Body> {
    state.metrics.requests.fetch_add(1, Ordering::Relaxed);

    let (parts, body) = request.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let headers = parts.headers;
    let content_type = headers.get(CONTENT_TYPE).cloned();
    let target_url = target_url(&state.target, uri.path(), uri.query());
    let request_bytes = match to_bytes(body, state.config.max_body_bytes).await {
        Ok(bytes) => bytes,
        Err(error) => {
            state
                .metrics
                .rejected_payloads
                .fetch_add(1, Ordering::Relaxed);
            warn!(%error, "request body rejected");
            return plain_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds configured max_body_bytes\n",
            );
        }
    };

    state
        .metrics
        .request_bytes
        .fetch_add(request_bytes.len() as u64, Ordering::Relaxed);

    let redacted = match redact_body(&state.engine, &request_bytes, content_type.as_ref()) {
        Ok(redacted) => redacted,
        Err(BodyRedactionError::InvalidUtf8) => {
            state
                .metrics
                .rejected_payloads
                .fetch_add(1, Ordering::Relaxed);
            return plain_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "only UTF-8 JSON, JSONL, and text bodies are supported\n",
            );
        }
        Err(BodyRedactionError::Core(error)) => {
            state
                .metrics
                .upstream_errors
                .fetch_add(1, Ordering::Relaxed);
            warn!(%error, "body redaction failed");
            return plain_response(StatusCode::BAD_REQUEST, "request body redaction failed\n");
        }
        Err(BodyRedactionError::JsonSerialize(error)) => {
            state
                .metrics
                .upstream_errors
                .fetch_add(1, Ordering::Relaxed);
            warn!(%error, "body serialization failed");
            return plain_response(StatusCode::BAD_REQUEST, "request body redaction failed\n");
        }
    };
    state.metrics.record_report(redacted.stats);
    state
        .metrics
        .forwarded_bytes
        .fetch_add(redacted.body.len() as u64, Ordering::Relaxed);

    let mut builder = state
        .client
        .request(convert_method(method), target_url.as_str())
        .body(redacted.body);
    builder = apply_headers(builder, &headers, &state.engine, &state.metrics);

    match builder.send().await {
        Ok(response) => into_axum_response(response).await,
        Err(error) => {
            state
                .metrics
                .upstream_errors
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                error_kind = safe_reqwest_error_kind(&error),
                "upstream request failed"
            );
            plain_response(StatusCode::BAD_GATEWAY, "upstream request failed\n")
        }
    }
}

fn convert_method(method: Method) -> reqwest::Method {
    reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET)
}

fn apply_headers(
    mut builder: reqwest::RequestBuilder,
    headers: &HeaderMap,
    engine: &Engine,
    metrics: &ProxyMetrics,
) -> reqwest::RequestBuilder {
    for (name, value) in headers {
        if should_skip_header(name) {
            continue;
        }

        if let Some(kind) = sensitive_header_kind(name) {
            metrics.record_kind(kind);
            builder = builder.header(name.as_str(), HeaderValue::from_static("[REDACTED:header]"));
            continue;
        }

        if let Ok(raw) = value.to_str() {
            if let Ok(result) = engine.redact_str(raw) {
                metrics.record_report(result.stats);
                builder = builder.header(name.as_str(), result.text);
                continue;
            }
        }

        builder = builder.header(name.as_str(), value.clone());
    }

    builder
}

async fn into_axum_response(response: reqwest::Response) -> Response<Body> {
    let status = response.status();
    let headers = response.headers().clone();
    let body = match response.bytes().await {
        Ok(bytes) => Body::from(bytes),
        Err(error) => {
            warn!(
                error_kind = safe_reqwest_error_kind(&error),
                "failed to read upstream response body"
            );
            Body::from("failed to read upstream response\n")
        }
    };
    let mut builder = Response::builder().status(status);

    if let Some(output_headers) = builder.headers_mut() {
        for (name, value) in &headers {
            if should_skip_response_header(name) {
                continue;
            }
            output_headers.insert(name, value.clone());
        }
    }

    match builder.body(body) {
        Ok(response) => response,
        Err(error) => {
            warn!(%error, "failed to build proxy response");
            plain_response(StatusCode::BAD_GATEWAY, "failed to build proxy response\n")
        }
    }
}

fn plain_response(status: StatusCode, body: &'static str) -> Response<Body> {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
}

fn render_prometheus_metrics(snapshot: &MetricsSnapshot) -> String {
    let mut output = String::new();

    push_counter(
        &mut output,
        "privacy_proxy_requests_total",
        "Total HTTP requests handled by the proxy.",
        snapshot.requests,
    );
    push_counter(
        &mut output,
        "privacy_proxy_upstream_errors_total",
        "Total upstream or proxy forwarding errors.",
        snapshot.upstream_errors,
    );
    push_counter(
        &mut output,
        "privacy_proxy_rejected_payloads_total",
        "Total payloads rejected before forwarding.",
        snapshot.rejected_payloads,
    );
    push_counter(
        &mut output,
        "privacy_proxy_request_bytes_total",
        "Total request body bytes received before redaction.",
        snapshot.request_bytes,
    );
    push_counter(
        &mut output,
        "privacy_proxy_forwarded_bytes_total",
        "Total request body bytes forwarded after redaction.",
        snapshot.forwarded_bytes,
    );
    push_counter(
        &mut output,
        "privacy_proxy_redactions_total",
        "Total redactions applied by the proxy.",
        snapshot.redactions_total,
    );

    output.push_str(
        "# HELP privacy_proxy_redactions_by_type_total Total redactions by detector type.\n",
    );
    output.push_str("# TYPE privacy_proxy_redactions_by_type_total counter\n");
    for (detector, count) in &snapshot.redactions_by_type {
        let detector = prometheus_escape_label_value(detector);
        let _ = writeln!(
            output,
            "privacy_proxy_redactions_by_type_total{{detector=\"{detector}\"}} {count}"
        );
    }

    output
}

fn push_counter(output: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(output, "# HELP {name} {help}");
    let _ = writeln!(output, "# TYPE {name} counter");
    let _ = writeln!(output, "{name} {value}");
}

fn prometheus_escape_label_value(input: &str) -> String {
    let mut output = String::with_capacity(input.len());

    for ch in input.chars() {
        match ch {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            other => output.push(other),
        }
    }

    output
}

#[derive(Debug)]
struct RedactedBody {
    body: Bytes,
    stats: ScanReport,
}

#[derive(Debug, Error)]
enum BodyRedactionError {
    #[error("request body is not valid UTF-8")]
    InvalidUtf8,

    #[error("request body redaction failed: {0}")]
    Core(#[from] CoreError),

    #[error("request body serialization failed")]
    JsonSerialize(#[source] serde_json::Error),
}

fn redact_body(
    engine: &Engine,
    body: &[u8],
    content_type: Option<&HeaderValue>,
) -> std::result::Result<RedactedBody, BodyRedactionError> {
    if body.is_empty() {
        return Ok(RedactedBody {
            body: Bytes::new(),
            stats: ScanReport::default(),
        });
    }

    let input = std::str::from_utf8(body).map_err(|_| BodyRedactionError::InvalidUtf8)?;
    let media_type = content_type
        .and_then(|value| value.to_str().ok())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();

    if is_json_media_type(&media_type) {
        return match serde_json::from_str::<Value>(input) {
            Ok(value) => {
                let result = engine.redact_value(value)?;
                let output =
                    serde_json::to_vec(&result.value).map_err(BodyRedactionError::JsonSerialize)?;
                Ok(RedactedBody {
                    body: Bytes::from(output),
                    stats: result.stats,
                })
            }
            Err(_) => redact_jsonl_or_text(engine, input, true),
        };
    }

    if is_jsonl_media_type(&media_type) {
        return redact_jsonl_or_text(engine, input, true);
    }

    let result = engine.redact_str(input)?;
    Ok(RedactedBody {
        body: Bytes::from(result.text),
        stats: result.stats,
    })
}

fn redact_jsonl_or_text(
    engine: &Engine,
    input: &str,
    prefer_jsonl: bool,
) -> std::result::Result<RedactedBody, BodyRedactionError> {
    if prefer_jsonl || input.contains('\n') {
        let mut output = String::with_capacity(input.len());
        let mut stats = ScanReport::default();
        let mut parsed_any_json = false;

        for line in input.split_inclusive('\n') {
            let (content, newline) = split_line_ending(line);
            if content.trim().is_empty() {
                output.push_str(content);
                output.push_str(newline);
                continue;
            }

            match serde_json::from_str::<Value>(content) {
                Ok(value) => {
                    parsed_any_json = true;
                    let result = engine.redact_value(value)?;
                    let line = serde_json::to_string(&result.value)
                        .map_err(BodyRedactionError::JsonSerialize)?;
                    stats.merge(result.stats);
                    output.push_str(&line);
                    output.push_str(newline);
                }
                Err(_) if prefer_jsonl => {
                    let result = engine.redact_str(content)?;
                    stats.merge(result.stats);
                    output.push_str(&result.text);
                    output.push_str(newline);
                }
                Err(_) => {
                    let result = engine.redact_str(input)?;
                    return Ok(RedactedBody {
                        body: Bytes::from(result.text),
                        stats: result.stats,
                    });
                }
            }
        }

        if parsed_any_json || prefer_jsonl {
            return Ok(RedactedBody {
                body: Bytes::from(output),
                stats,
            });
        }
    }

    let result = engine.redact_str(input)?;
    Ok(RedactedBody {
        body: Bytes::from(result.text),
        stats: result.stats,
    })
}

fn target_url(base: &Url, path: &str, query: Option<&str>) -> Url {
    let mut output = base.clone();
    let base_path = base.path().trim_end_matches('/');
    let request_path = path.trim_start_matches('/');
    let combined = if base_path.is_empty() {
        format!("/{request_path}")
    } else if request_path.is_empty() {
        base_path.to_owned()
    } else {
        format!("{base_path}/{request_path}")
    };

    let combined_query = match (base.query(), query) {
        (Some(base_query), Some(request_query)) => Some(format!("{base_query}&{request_query}")),
        (Some(base_query), None) => Some(base_query.to_owned()),
        (None, Some(request_query)) => Some(request_query.to_owned()),
        (None, None) => None,
    };

    output.set_path(&combined);
    output.set_query(combined_query.as_deref());
    output
}

fn should_skip_header(name: &HeaderName) -> bool {
    matches!(
        name,
        &HOST | &CONTENT_LENGTH | &TRANSFER_ENCODING | &ACCEPT_ENCODING | &CONTENT_ENCODING
    )
}

fn should_skip_response_header(name: &HeaderName) -> bool {
    matches!(
        name,
        &CONTENT_LENGTH | &TRANSFER_ENCODING | &CONTENT_ENCODING
    )
}

fn sensitive_header_kind(name: &HeaderName) -> Option<DetectorKind> {
    let normalized = normalize_header_name(name.as_str());

    if normalized.contains("cookie") {
        Some(DetectorKind::Cookie)
    } else if normalized.contains("authorization") {
        Some(DetectorKind::BearerToken)
    } else if normalized.contains("apikey")
        || normalized.ends_with("token")
        || normalized.contains("secret")
        || normalized.contains("password")
        || normalized.contains("session")
    {
        Some(DetectorKind::ApiKey)
    } else {
        None
    }
}

fn safe_reqwest_error_kind(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() {
        "body"
    } else if error.is_decode() {
        "decode"
    } else if error.is_request() {
        "request"
    } else {
        "unknown"
    }
}

fn safe_target_label(target: &Url) -> Cow<'_, str> {
    let Some(host) = target.host_str() else {
        return Cow::Borrowed("<invalid-target>");
    };

    let mut label = format!("{}://{}", target.scheme(), host);
    if let Some(port) = target.port() {
        label.push(':');
        label.push_str(&port.to_string());
    }

    Cow::Owned(label)
}

fn normalize_header_name(input: &str) -> String {
    input
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn is_json_media_type(media_type: &str) -> bool {
    media_type.starts_with("application/json") || media_type.contains("+json")
}

fn is_jsonl_media_type(media_type: &str) -> bool {
    media_type.contains("jsonl")
        || media_type.contains("ndjson")
        || media_type.starts_with("application/x-ndjson")
}

fn split_line_ending(line: &str) -> (&str, &str) {
    if let Some(content) = line.strip_suffix("\r\n") {
        (content, "\r\n")
    } else if let Some(content) = line.strip_suffix('\n') {
        (content, "\n")
    } else {
        (line, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, Uri};
    use axum::routing::any;
    use privacy_proxy_core::Config;
    use std::sync::MutexGuard;
    use tower::ServiceExt;

    fn engine() -> Engine {
        Engine::new(Config::default()).expect("engine builds")
    }

    fn state(config: Config) -> ProxyState {
        ProxyState {
            target: Url::parse("http://upstream.example.test/collect").expect("url parses"),
            client: reqwest::Client::new(),
            engine: Engine::new(config.clone()).expect("engine builds"),
            config,
            metrics: Arc::new(ProxyMetrics::default()),
        }
    }

    #[derive(Clone, Default)]
    struct UpstreamCapture {
        received: Arc<Mutex<Option<ReceivedRequest>>>,
    }

    #[derive(Debug)]
    struct ReceivedRequest {
        path_and_query: String,
        authorization: Option<String>,
        cookie: Option<String>,
        x_session_id: Option<String>,
        body: String,
    }

    impl UpstreamCapture {
        fn lock(&self) -> MutexGuard<'_, Option<ReceivedRequest>> {
            self.received.lock().expect("capture lock is not poisoned")
        }

        fn take(&self) -> ReceivedRequest {
            self.lock()
                .take()
                .expect("upstream should receive one request")
        }
    }

    async fn upstream_handler(
        State(capture): State<UpstreamCapture>,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> impl IntoResponse {
        let body = String::from_utf8(body.to_vec()).expect("proxy forwards utf-8 body");
        let request = ReceivedRequest {
            path_and_query: uri
                .path_and_query()
                .map(|value| value.as_str().to_owned())
                .unwrap_or_else(|| uri.path().to_owned()),
            authorization: header_to_string(&headers, "authorization"),
            cookie: header_to_string(&headers, "cookie"),
            x_session_id: header_to_string(&headers, "x-session-id"),
            body,
        };

        *capture.lock() = Some(request);

        StatusCode::NO_CONTENT
    }

    fn header_to_string(headers: &HeaderMap, name: &'static str) -> Option<String> {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }

    #[test]
    fn redacts_json_body() {
        let content_type = HeaderValue::from_static("application/json");
        let result = redact_body(
            &engine(),
            br#"{"email":"alice@example.test","trace_id":"abc"}"#,
            Some(&content_type),
        )
        .expect("redacts body");
        let output = std::str::from_utf8(&result.body).expect("utf-8 body");

        assert!(output.contains("[REDACTED:email]"));
        assert!(output.contains("trace_id"));
        assert!(!output.contains("alice@example.test"));
    }

    #[test]
    fn redacts_jsonl_body() {
        let content_type = HeaderValue::from_static("application/x-ndjson");
        let result = redact_body(
            &engine(),
            b"{\"email\":\"alice@example.test\"}\nplain bob@example.test\n",
            Some(&content_type),
        )
        .expect("redacts body");
        let output = std::str::from_utf8(&result.body).expect("utf-8 body");

        assert_eq!(result.stats.by_type.get("email"), Some(&2));
        assert!(!output.contains("alice@example.test"));
        assert!(!output.contains("bob@example.test"));
    }

    #[test]
    fn detects_sensitive_headers() {
        assert_eq!(
            sensitive_header_kind(&HeaderName::from_static("authorization")),
            Some(DetectorKind::BearerToken)
        );
        assert_eq!(
            sensitive_header_kind(&HeaderName::from_static("x-api-key")),
            Some(DetectorKind::ApiKey)
        );
        assert_eq!(
            sensitive_header_kind(&HeaderName::from_static("cookie")),
            Some(DetectorKind::Cookie)
        );
        assert_eq!(
            sensitive_header_kind(&HeaderName::from_static("x-session-id")),
            Some(DetectorKind::ApiKey)
        );
    }

    #[test]
    fn builds_target_url_with_path_and_query() {
        let base = Url::parse("https://logs.example.test/api?license=abc").expect("url parses");
        let output = target_url(&base, "/v1/events", Some("source=test"));

        assert_eq!(
            output.as_str(),
            "https://logs.example.test/api/v1/events?license=abc&source=test"
        );
    }

    #[test]
    fn safe_target_label_omits_credentials_path_and_query() {
        let target = Url::parse("https://user:secret@logs.example.test:8443/api/token?key=value")
            .expect("url parses");

        let label = safe_target_label(&target);

        assert_eq!(label, "https://logs.example.test:8443");
    }

    #[tokio::test]
    async fn rejects_oversized_body_without_echoing_content() {
        let config = Config {
            max_body_bytes: 8,
            ..Config::default()
        };
        let request = Request::builder()
            .method("POST")
            .uri("/logs")
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::from("secret-token-value"))
            .expect("request builds");

        let response = router(state(config))
            .oneshot(request)
            .await
            .expect("router responds");
        let status = response.status();
        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("body reads");
        let body = std::str::from_utf8(&body).expect("body is utf-8");

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(body.contains("max_body_bytes"));
        assert!(!body.contains("secret-token-value"));
    }

    #[tokio::test]
    async fn forwards_redacted_request_to_real_upstream_and_records_metrics() {
        let capture = UpstreamCapture::default();
        let upstream = Router::new()
            .fallback(any(upstream_handler))
            .with_state(capture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream listener");
        let upstream_addr = listener.local_addr().expect("read upstream address");
        let upstream_server = tokio::spawn(async move { axum::serve(listener, upstream).await });

        let config = Config::default();
        let proxy_state = ProxyState {
            target: Url::parse(&format!("http://{upstream_addr}/collect")).expect("url parses"),
            client: reqwest::Client::new(),
            engine: Engine::new(config.clone()).expect("engine builds"),
            config,
            metrics: Arc::new(ProxyMetrics::default()),
        };
        let app = router(proxy_state);
        let request = Request::builder()
            .method("POST")
            .uri("/ingest?source=test")
            .header(CONTENT_TYPE, "application/json")
            .header("authorization", "Bearer live-token-value-123456")
            .header("cookie", "session=live-cookie; theme=dark")
            .header("x-session-id", "session-secret-value")
            .body(Body::from(
                r#"{"email":"alice@example.test","authorization":"Bearer example-token-value-123456","message":"card 4111 1111 1111 1111"}"#,
            ))
            .expect("request builds");

        let response = app.clone().oneshot(request).await.expect("proxy responds");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let received = capture.take();
        assert_eq!(received.path_and_query, "/collect/ingest?source=test");
        assert_eq!(received.authorization.as_deref(), Some("[REDACTED:header]"));
        assert_eq!(received.cookie.as_deref(), Some("[REDACTED:header]"));
        assert_eq!(received.x_session_id.as_deref(), Some("[REDACTED:header]"));
        assert!(received.body.contains("[REDACTED:email]"));
        assert!(received.body.contains("[REDACTED:bearer_token]"));
        assert!(received.body.contains("[REDACTED:credit_card]"));
        assert!(!received.body.contains("alice@example.test"));
        assert!(!received.body.contains("example-token-value"));
        assert!(!received.body.contains("4111 1111 1111 1111"));

        let metrics_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("metrics request builds"),
            )
            .await
            .expect("metrics respond");
        let metrics_body = to_bytes(metrics_response.into_body(), 4096)
            .await
            .expect("metrics body reads");
        let metrics: Value =
            serde_json::from_slice(&metrics_body).expect("metrics response is JSON");

        assert_eq!(metrics["requests"], 1);
        assert_eq!(metrics["upstream_errors"], 0);
        assert_eq!(metrics["rejected_payloads"], 0);
        assert_eq!(metrics["redactions_by_type"]["email"], 1);
        assert_eq!(metrics["redactions_by_type"]["credit_card"], 1);
        assert_eq!(metrics["redactions_by_type"]["cookie"], 1);
        assert_eq!(metrics["redactions_by_type"]["api_key"], 1);
        assert_eq!(metrics["redactions_by_type"]["bearer_token"], 2);

        let prometheus_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics/prometheus")
                    .body(Body::empty())
                    .expect("prometheus metrics request builds"),
            )
            .await
            .expect("prometheus metrics respond");
        let prometheus_body = to_bytes(prometheus_response.into_body(), 8192)
            .await
            .expect("prometheus metrics body reads");
        let prometheus = std::str::from_utf8(&prometheus_body).expect("metrics are utf-8");

        assert!(prometheus.contains("privacy_proxy_requests_total 1"));
        assert!(prometheus.contains("privacy_proxy_redactions_by_type_total{detector=\"email\"} 1"));
        assert!(prometheus
            .contains("privacy_proxy_redactions_by_type_total{detector=\"bearer_token\"} 2"));
        assert!(!prometheus.contains("alice@example.test"));
        assert!(!prometheus.contains("example-token-value"));
        assert!(!prometheus.contains("4111 1111 1111 1111"));

        upstream_server.abort();
    }

    #[test]
    fn prometheus_label_values_are_escaped() {
        assert_eq!(
            prometheus_escape_label_value("line\nquote\"slash\\"),
            "line\\nquote\\\"slash\\\\"
        );
    }
}
