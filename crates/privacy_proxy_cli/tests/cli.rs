use privacy_proxy_core::Config;
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_privacy-proxy"))
}

fn write_config(dir: &Path) -> PathBuf {
    let path = dir.join("privacy-proxy.toml");
    fs::write(&path, Config::example_toml()).expect("write test config");
    path
}

fn fixture() -> &'static str {
    include_str!("fixtures/logs.jsonl")
}

fn observability_fixture() -> &'static str {
    include_str!("fixtures/observability.jsonl")
}

#[test]
fn init_writes_default_config() {
    let dir = tempdir().expect("tempdir");
    let config = dir.path().join("privacy-proxy.toml");

    let output = Command::new(bin())
        .args(["--config", config.to_str().expect("utf-8 path"), "init"])
        .output()
        .expect("run init");

    assert!(output.status.success());
    let written = fs::read_to_string(config).expect("read config");
    assert!(written.contains("mode = \"mask\""));
    assert!(written.contains("fields_deny"));
    assert!(written.contains("max_line_bytes"));
}

#[test]
fn demo_runs_without_config_file() {
    let output = Command::new(bin()).arg("demo").output().expect("run demo");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");

    assert!(stdout.contains("privacy-proxy demo"));
    assert!(stdout.contains("[REDACTED:email]"));
    assert!(stdout.contains("scan statistics"));
    assert!(stdout.contains("\"detections\""));
}

#[test]
fn serve_help_documents_target_and_listen_flags() {
    let output = Command::new(bin())
        .args(["serve", "--help"])
        .output()
        .expect("run serve help");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");

    assert!(stdout.contains("--target"));
    assert!(stdout.contains("--listen"));
}

#[test]
fn completions_generate_shell_scripts_without_config_file() {
    let bash = Command::new(bin())
        .args(["completions", "bash"])
        .output()
        .expect("run bash completions");

    assert!(bash.status.success());
    let bash_stdout = String::from_utf8(bash.stdout).expect("bash stdout is utf-8");
    assert!(bash_stdout.contains("privacy-proxy"));
    assert!(bash_stdout.contains("_privacy"));

    let zsh = Command::new(bin())
        .args(["completions", "zsh"])
        .output()
        .expect("run zsh completions");

    assert!(zsh.status.success());
    let zsh_stdout = String::from_utf8(zsh.stdout).expect("zsh stdout is utf-8");
    assert!(zsh_stdout.contains("#compdef privacy-proxy"));
    assert!(zsh_stdout.contains("redact"));
}

#[test]
fn completions_help_lists_supported_shells() {
    let output = Command::new(bin())
        .args(["completions", "--help"])
        .output()
        .expect("run completions help");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");

    assert!(stdout.contains("bash"));
    assert!(stdout.contains("zsh"));
    assert!(stdout.contains("powershell"));
}

#[test]
fn redact_file_masks_sensitive_values() {
    let dir = tempdir().expect("tempdir");
    let config = write_config(dir.path());
    let input = dir.path().join("logs.jsonl");
    let output_path = dir.path().join("clean.jsonl");
    fs::write(&input, fixture()).expect("write fixture");

    let output = Command::new(bin())
        .args([
            "--config",
            config.to_str().expect("utf-8 path"),
            "redact",
            "--input",
            input.to_str().expect("utf-8 path"),
            "--output",
            output_path.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("run redact");

    assert!(output.status.success());
    let clean = fs::read_to_string(output_path).expect("read redacted output");

    assert!(!clean.contains("alice@example.com"));
    assert!(!clean.contains("abc123"));
    assert!(!clean.contains("4111 1111 1111 1111"));
    assert!(clean.contains("[REDACTED:email]"));
    assert!(clean.contains("[REDACTED:credit_card]"));
    assert!(clean.contains("[REDACTED:url_sensitive_params]"));
}

#[test]
fn redact_reads_from_stdin() {
    let dir = tempdir().expect("tempdir");
    let config = write_config(dir.path());
    let mut child = Command::new(bin())
        .args(["--config", config.to_str().expect("utf-8 path"), "redact"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn redact");

    let Some(mut stdin) = child.stdin.take() else {
        panic!("stdin is piped");
    };
    stdin
        .write_all(fixture().as_bytes())
        .expect("write fixture to stdin");
    drop(stdin);

    let output = child.wait_with_output().expect("wait for redact");

    assert!(output.status.success());
    let clean = String::from_utf8(output.stdout).expect("stdout is utf-8");
    assert!(!clean.contains("bob@example.com"));
    assert!(clean.contains("[REDACTED:email]"));
}

#[test]
fn scan_prints_statistics_without_sensitive_values() {
    let dir = tempdir().expect("tempdir");
    let config = write_config(dir.path());
    let input = dir.path().join("logs.jsonl");
    fs::write(&input, fixture()).expect("write fixture");

    let output = Command::new(bin())
        .args([
            "--config",
            config.to_str().expect("utf-8 path"),
            "scan",
            "--input",
            input.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("run scan");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");

    assert!(!stdout.contains("alice@example.com"));
    assert!(!stdout.contains("abc123"));
    assert!(!stdout.contains("4111 1111 1111 1111"));

    let report: Value = serde_json::from_str(&stdout).expect("scan output is JSON");
    assert_eq!(report["lines_scanned"], 3);
    assert!(report["detections"]["total"].as_u64().expect("total") >= 6);
    assert_eq!(report["detections"]["by_type"]["email"], 2);
}

#[test]
fn assert_fails_without_printing_sensitive_values() {
    let dir = tempdir().expect("tempdir");
    let config = write_config(dir.path());
    let input = dir.path().join("logs.jsonl");
    fs::write(&input, fixture()).expect("write fixture");

    let output = Command::new(bin())
        .args([
            "--config",
            config.to_str().expect("utf-8 path"),
            "assert",
            "--input",
            input.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("run assert");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf-8");

    assert!(!stdout.contains("alice@example.com"));
    assert!(!stderr.contains("alice@example.com"));
    assert!(!stdout.contains("abc123"));
    assert!(!stderr.contains("abc123"));
    assert!(stderr.contains("privacy assertion failed"));

    let report: Value = serde_json::from_str(&stdout).expect("assert output is JSON");
    assert!(report["detections"]["total"].as_u64().expect("total") > 0);
}

#[test]
fn assert_passes_for_clean_logs() {
    let dir = tempdir().expect("tempdir");
    let config = write_config(dir.path());
    let input = dir.path().join("clean.jsonl");
    fs::write(
        &input,
        r#"{"message":"health check","trace_id":"00f067aa0ba902b7","request_id":"req-123"}"#,
    )
    .expect("write clean fixture");

    let output = Command::new(bin())
        .args([
            "--config",
            config.to_str().expect("utf-8 path"),
            "assert",
            "--input",
            input.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("run assert");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    let report: Value = serde_json::from_str(&stdout).expect("assert output is JSON");
    assert_eq!(report["detections"]["total"], 0);
}

#[test]
fn realistic_observability_fixture_redacts_without_leaks() {
    let dir = tempdir().expect("tempdir");
    let config = write_config(dir.path());
    let input = dir.path().join("observability.jsonl");
    let output_path = dir.path().join("clean.jsonl");
    fs::write(&input, observability_fixture()).expect("write observability fixture");

    let output = Command::new(bin())
        .args([
            "--config",
            config.to_str().expect("utf-8 path"),
            "redact",
            "--input",
            input.to_str().expect("utf-8 path"),
            "--output",
            output_path.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("run redact");

    assert!(output.status.success());
    let clean = fs::read_to_string(output_path).expect("read redacted output");

    for sensitive in [
        "sentry-user@example.test",
        "sentry-session",
        "loki-token",
        "datadog-code",
        "elastic-api-key-value",
        "otlp-token-value-123456",
        "4111 1111 1111 1111",
        "GB82 WEST 1234 5698 7654 32",
    ] {
        assert!(!clean.contains(sensitive), "leaked {sensitive}");
    }

    assert!(clean.contains("[REDACTED:email]"));
    assert!(clean.contains("[REDACTED:url_sensitive_params]"));
    assert!(clean.contains("[REDACTED:bearer_token]"));
}

#[test]
fn oversized_line_error_does_not_echo_line_content() {
    let dir = tempdir().expect("tempdir");
    let config = dir.path().join("privacy-proxy.toml");
    fs::write(&config, "mode = \"mask\"\nmax_line_bytes = 8\n").expect("write config");
    let input = dir.path().join("too-large.jsonl");
    fs::write(&input, "secret-token-value\n").expect("write oversized line");

    let output = Command::new(bin())
        .args([
            "--config",
            config.to_str().expect("utf-8 path"),
            "scan",
            "--input",
            input.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("run scan");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf-8");

    assert!(stdout.is_empty());
    assert!(stderr.contains("max_line_bytes"));
    assert!(!stderr.contains("secret-token-value"));
}
