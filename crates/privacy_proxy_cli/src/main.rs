#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use privacy_proxy_core::{Config, Engine, ScanReport};
use privacy_proxy_proxy::ServeOptions;
use serde::Serialize;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tracing::debug;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "privacy-proxy")]
#[command(version)]
#[command(about = "Redact sensitive data from logs before forwarding them.")]
struct Cli {
    #[arg(
        long,
        global = true,
        default_value = "privacy-proxy.toml",
        value_name = "FILE"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show a built-in redaction demo without reading files or config.
    Demo,

    /// Write a starter privacy-proxy.toml file.
    Init {
        /// Replace an existing config file.
        #[arg(long)]
        force: bool,
    },

    /// Redact JSONL or plain text lines.
    Redact {
        /// Input JSONL file. Reads stdin when omitted.
        #[arg(long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// Output file. Writes stdout when omitted.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },

    /// Scan JSONL or plain text lines and print aggregate statistics only.
    Scan {
        /// Input JSONL file. Reads stdin when omitted.
        #[arg(long, value_name = "FILE")]
        input: Option<PathBuf>,
    },

    /// Fail if sensitive data is detected. Intended for CI privacy tests.
    Assert {
        /// Input JSONL file. Reads stdin when omitted.
        #[arg(long, value_name = "FILE")]
        input: Option<PathBuf>,
    },

    /// Run an HTTP proxy that redacts request bodies and sensitive headers.
    Serve {
        /// Upstream URL to forward requests to.
        #[arg(long, value_name = "URL")]
        target: String,

        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:8080", value_name = "ADDR")]
        listen: SocketAddr,
    },
}

#[derive(Debug, Serialize)]
struct ScanOutput {
    lines_scanned: u64,
    truncated: bool,
    sample_limit: usize,
    max_line_bytes: usize,
    detections: ScanReport,
}

#[tokio::main]
async fn main() {
    init_tracing();

    if let Err(error) = run().await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let filter = match EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => EnvFilter::new("warn"),
    };

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .without_time()
        .with_target(false)
        .try_init();
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Demo => run_demo(),
        Command::Init { force } => init_config(&cli.config, force),
        Command::Redact { input, output } => {
            if let (Some(input), Some(output)) = (&input, &output) {
                if input == output {
                    bail!("input and output paths must be different");
                }
            }

            let config = load_config(&cli.config)?;
            let max_line_bytes = config.max_line_bytes;
            let engine = Engine::new(config)?;
            let reader = open_reader(input.as_deref())?;
            let writer = open_writer(output.as_deref())?;

            debug!("starting redaction");
            redact_jsonl(reader, writer, &engine, max_line_bytes)
        }
        Command::Scan { input } => {
            let config = load_config(&cli.config)?;
            let sample_limit = config.sample_limit;
            let max_line_bytes = config.max_line_bytes;
            let engine = Engine::new(config)?;
            let reader = open_reader(input.as_deref())?;
            let output = scan_jsonl(reader, &engine, sample_limit, max_line_bytes)?;
            write_scan_output(&output)?;

            Ok(())
        }
        Command::Assert { input } => {
            let config = load_config(&cli.config)?;
            let sample_limit = config.sample_limit;
            let max_line_bytes = config.max_line_bytes;
            let engine = Engine::new(config)?;
            let reader = open_reader(input.as_deref())?;
            let output = scan_jsonl(reader, &engine, sample_limit, max_line_bytes)?;
            let detected = output.detections.total;

            write_scan_output(&output)?;

            if detected > 0 {
                bail!("privacy assertion failed: sensitive data detected");
            }

            Ok(())
        }
        Command::Serve { target, listen } => {
            let config = load_config(&cli.config)?;
            privacy_proxy_proxy::serve(ServeOptions {
                listen,
                target,
                config,
            })
            .await?;

            Ok(())
        }
    }
}

fn run_demo() -> Result<()> {
    const DEMO_LOGS: &[&str] = &[
        r#"{"level":"error","email":"alice@example.test","authorization":"Bearer example-token-value-123456","url":"https://app.example.test/reset?token=reset-token","message":"card 4111 1111 1111 1111 from 203.0.113.10","trace_id":"00f067aa0ba902b7"}"#,
        r#"plain text from bob@example.test with Cookie: session=demo-cookie; theme=light"#,
        r#"bank transfer iban GB82 WEST 1234 5698 7654 32"#,
    ];

    let config = Config::default();
    let engine = Engine::new(config.clone())?;
    let mut scan = ScanReport::default();

    println!("privacy-proxy demo");
    println!();
    println!("input:");
    for line in DEMO_LOGS {
        println!("{line}");
    }

    println!();
    println!("redacted:");
    for line in DEMO_LOGS {
        let redacted = redact_line(line, &engine)?;
        println!("{redacted}");
        scan.merge(scan_line(line, &engine)?);
    }

    println!();
    println!("scan statistics:");
    let output = ScanOutput {
        lines_scanned: DEMO_LOGS.len() as u64,
        truncated: false,
        sample_limit: config.sample_limit,
        max_line_bytes: config.max_line_bytes,
        detections: scan,
    };
    serde_json::to_writer_pretty(io::stdout(), &output)
        .context("failed to serialize demo scan statistics")?;
    println!();

    Ok(())
}

fn init_config(path: &Path, force: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create config directory `{}`", parent.display())
            })?;
        }
    }

    let mut file = if force {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
    } else {
        OpenOptions::new().write(true).create_new(true).open(path)
    }
    .with_context(|| {
        if force {
            format!("failed to open config `{}`", path.display())
        } else {
            format!(
                "failed to create config `{}`; use --force to replace it",
                path.display()
            )
        }
    })?;

    file.write_all(Config::example_toml().as_bytes())
        .with_context(|| format!("failed to write config `{}`", path.display()))?;

    println!("wrote {}", path.display());
    Ok(())
}

fn load_config(path: &Path) -> Result<Config> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config `{}`", path.display()))?;
    let config = Config::from_toml_str(&raw)
        .with_context(|| format!("failed to parse config `{}`", path.display()))?;

    debug!(path = %path.display(), "loaded config");
    Ok(config)
}

fn open_reader(path: Option<&Path>) -> Result<Box<dyn BufRead>> {
    match path {
        Some(path) => {
            let file = File::open(path)
                .with_context(|| format!("failed to open input `{}`", path.display()))?;
            Ok(Box::new(BufReader::new(file)))
        }
        None => Ok(Box::new(BufReader::new(io::stdin()))),
    }
}

fn open_writer(path: Option<&Path>) -> Result<Box<dyn Write>> {
    match path {
        Some(path) => {
            let file = File::create(path)
                .with_context(|| format!("failed to create output `{}`", path.display()))?;
            Ok(Box::new(file))
        }
        None => Ok(Box::new(io::stdout())),
    }
}

fn write_scan_output(output: &ScanOutput) -> Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    serde_json::to_writer_pretty(&mut handle, output)
        .context("failed to serialize scan statistics")?;
    handle
        .write_all(b"\n")
        .context("failed to write scan statistics")?;

    Ok(())
}

fn redact_jsonl<R, W>(
    mut reader: R,
    mut writer: W,
    engine: &Engine,
    max_line_bytes: usize,
) -> Result<()>
where
    R: BufRead,
    W: Write,
{
    let mut line = Vec::new();
    let mut line_number = 0_u64;

    loop {
        let bytes_read = read_limited_line(&mut reader, &mut line, max_line_bytes)
            .with_context(|| format!("failed to read line {}", line_number.saturating_add(1)))?;

        if bytes_read == 0 {
            break;
        }

        line_number = line_number.saturating_add(1);
        let line = std::str::from_utf8(&line)
            .with_context(|| format!("line {line_number} is not valid UTF-8"))?;
        let (content, newline) = split_line_ending(line);
        let redacted = redact_line(content, engine)
            .with_context(|| format!("failed to redact line {line_number}"))?;

        writer
            .write_all(redacted.as_bytes())
            .with_context(|| format!("failed to write redacted line {line_number}"))?;
        writer
            .write_all(newline.as_bytes())
            .with_context(|| format!("failed to write line ending for line {line_number}"))?;
    }

    writer.flush().context("failed to flush output")?;
    Ok(())
}

fn scan_jsonl<R>(
    mut reader: R,
    engine: &Engine,
    sample_limit: usize,
    max_line_bytes: usize,
) -> Result<ScanOutput>
where
    R: BufRead,
{
    let mut line = Vec::new();
    let mut lines_scanned = 0_u64;
    let mut detections = ScanReport::default();
    let mut truncated = false;

    loop {
        if sample_limit > 0 && lines_scanned >= sample_limit as u64 {
            truncated = !reader
                .fill_buf()
                .context("failed to inspect input after sample limit")?
                .is_empty();
            break;
        }

        let bytes_read = read_limited_line(&mut reader, &mut line, max_line_bytes)
            .with_context(|| format!("failed to read line {}", lines_scanned.saturating_add(1)))?;

        if bytes_read == 0 {
            break;
        }

        let line = std::str::from_utf8(&line)
            .with_context(|| format!("line {} is not valid UTF-8", lines_scanned + 1))?;
        let (content, _) = split_line_ending(line);
        detections.merge(scan_line(content, engine)?);
        lines_scanned = lines_scanned.saturating_add(1);
    }

    Ok(ScanOutput {
        lines_scanned,
        truncated,
        sample_limit,
        max_line_bytes,
        detections,
    })
}

fn read_limited_line<R>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    max_line_bytes: usize,
) -> Result<usize>
where
    R: BufRead,
{
    buffer.clear();

    loop {
        let available = reader.fill_buf().context("failed to read input")?;

        if available.is_empty() {
            return Ok(buffer.len());
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |position| position + 1);

        if buffer.len().saturating_add(take) > max_line_bytes {
            bail!("input line exceeds configured max_line_bytes ({max_line_bytes})");
        }

        buffer.extend_from_slice(&available[..take]);
        reader.consume(take);

        if newline.is_some() {
            return Ok(buffer.len());
        }
    }
}

fn redact_line(content: &str, engine: &Engine) -> Result<String> {
    if content.trim().is_empty() {
        return Ok(content.to_owned());
    }

    match serde_json::from_str::<Value>(content) {
        Ok(value) => {
            let result = engine.redact_value(value)?;
            serde_json::to_string(&result.value).context("failed to serialize redacted JSON line")
        }
        Err(_) => Ok(engine.redact_str(content)?.text),
    }
}

fn scan_line(content: &str, engine: &Engine) -> Result<ScanReport> {
    if content.trim().is_empty() {
        return Ok(ScanReport::default());
    }

    match serde_json::from_str::<Value>(content) {
        Ok(value) => Ok(engine.scan_value(&value)?),
        Err(_) => Ok(engine.scan_str(content)?),
    }
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
    use privacy_proxy_core::Mode;
    use serde_json::json;

    #[test]
    fn redact_line_handles_json_and_text() {
        let engine = Engine::new(Config::default()).expect("engine builds");

        let json_output =
            redact_line(r#"{"email":"alice@example.com"}"#, &engine).expect("redacts JSON");
        let text_output = redact_line("alice@example.com", &engine).expect("redacts text");

        assert!(json_output.contains("[REDACTED:email]"));
        assert!(text_output.contains("[REDACTED:email]"));
        assert!(!json_output.contains("alice@example.com"));
        assert!(!text_output.contains("alice@example.com"));
    }

    #[test]
    fn scan_line_counts_json() {
        let engine = Engine::new(Config::default()).expect("engine builds");
        let value = json!({"token":"hidden", "message":"bob@example.com"});
        let line = serde_json::to_string(&value).expect("serialize test JSON");

        let report = scan_line(&line, &engine).expect("scan succeeds");

        assert_eq!(report.total, 2);
        assert_eq!(report.by_type.get("api_key"), Some(&1));
        assert_eq!(report.by_type.get("email"), Some(&1));
    }

    #[test]
    fn drop_mode_text_uses_safe_placeholder() {
        let config = Config {
            mode: Mode::Drop,
            ..Config::default()
        };
        let engine = Engine::new(config).expect("engine builds");

        let redacted = redact_line("bob@example.com", &engine).expect("redacts text");

        assert_eq!(redacted, "[DROPPED:email]");
    }

    #[test]
    fn read_limited_line_rejects_oversized_input_without_content() {
        let mut reader = BufReader::new("secret-token-value\n".as_bytes());
        let mut buffer = Vec::new();

        let error =
            read_limited_line(&mut reader, &mut buffer, 8).expect_err("oversized line should fail");
        let message = error.to_string();

        assert!(message.contains("max_line_bytes"));
        assert!(!message.contains("secret-token-value"));
    }
}
