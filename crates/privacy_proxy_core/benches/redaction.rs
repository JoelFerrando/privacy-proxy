use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use privacy_proxy_core::{Config, Engine, Mode};
use serde_json::{json, Value};
use std::hint::black_box;

const HASH_KEY: &[u8] = b"criterion-benchmark-key";

fn mixed_text() -> &'static str {
    "user=alice@example.test ip=203.0.113.10 auth=Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123 url=https://example.test/callback?token=abc123&safe=true card=4111 1111 1111 1111 iban=GB82 WEST 1234 5698 7654 32"
}

fn nested_json() -> Value {
    json!({
        "timestamp": "2026-06-19T10:15:00Z",
        "level": "info",
        "trace_id": "00f067aa0ba902b7",
        "span_id": "b7ad6b7169203331",
        "email": "alice@example.test",
        "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123",
        "request": {
            "ip": "203.0.113.10",
            "url": "https://example.test/callback?token=abc123&safe=true",
            "headers": {
                "cookie": "session=abc123; theme=light"
            }
        },
        "events": [
            {"message": "card 4111 1111 1111 1111"},
            {"message": "iban GB82 WEST 1234 5698 7654 32"},
            {"message": "ipv6 2001:db8::1 from bob@example.test"}
        ]
    })
}

fn jsonl_lines(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| {
            json!({
                "timestamp": "2026-06-19T10:15:00Z",
                "level": "info",
                "request_id": format!("req-{index}"),
                "email": format!("user{index}@example.test"),
                "message": format!("login from 203.0.113.{} with card 4111 1111 1111 1111", index % 255),
                "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123",
                "url": "https://example.test/callback?token=abc123&safe=true"
            })
            .to_string()
        })
        .collect()
}

fn config_for_mode(mode: Mode) -> Config {
    Config {
        mode,
        ..Config::default()
    }
}

fn redact_jsonl_lines(engine: &Engine, mode: Mode, lines: &[String]) -> (usize, u64) {
    let mut output_bytes = 0_usize;
    let mut detections = 0_u64;

    for line in lines {
        let value: Value = serde_json::from_str(black_box(line)).expect("parse JSONL line");
        let result = if mode == Mode::Hash {
            engine
                .redact_value_with_hash_key(value, HASH_KEY)
                .expect("hash redact JSONL value")
        } else {
            engine.redact_value(value).expect("redact JSONL value")
        };
        let serialized = serde_json::to_string(&result.value).expect("serialize redacted line");
        output_bytes += serialized.len();
        detections += result.stats.total;
    }

    black_box((output_bytes, detections))
}

fn bench_redaction(c: &mut Criterion) {
    let engine = Engine::new(Config::default()).expect("default config builds");

    let text = mixed_text();
    let mut text_group = c.benchmark_group("text");
    text_group.throughput(Throughput::Bytes(text.len() as u64));
    text_group.bench_function("redact_mixed_text", |b| {
        b.iter(|| engine.redact_str(black_box(text)).expect("redact text"))
    });
    text_group.bench_function("scan_mixed_text", |b| {
        b.iter(|| engine.scan_str(black_box(text)).expect("scan text"))
    });
    text_group.finish();

    let value = nested_json();
    let serialized_len = serde_json::to_string(&value)
        .expect("serialize benchmark value")
        .len();
    let mut json_group = c.benchmark_group("json");
    json_group.throughput(Throughput::Bytes(serialized_len as u64));
    json_group.bench_function("redact_nested_json", |b| {
        b.iter(|| {
            engine
                .redact_value(black_box(value.clone()))
                .expect("redact JSON")
        })
    });
    json_group.bench_function("scan_nested_json", |b| {
        b.iter(|| engine.scan_value(black_box(&value)).expect("scan JSON"))
    });
    json_group.finish();

    let mut jsonl_group = c.benchmark_group("jsonl");
    for line_count in [100_usize, 1_000, 10_000] {
        let lines = jsonl_lines(line_count);
        let bytes = lines.iter().map(String::len).sum::<usize>() as u64;
        jsonl_group.throughput(Throughput::Bytes(bytes));

        for mode in [Mode::Mask, Mode::Hash, Mode::Drop] {
            let mode_engine = Engine::new(config_for_mode(mode)).expect("benchmark engine builds");
            jsonl_group.bench_function(format!("{mode:?}_{line_count}_lines"), |b| {
                b.iter(|| redact_jsonl_lines(&mode_engine, mode, black_box(&lines)))
            });
        }
    }
    jsonl_group.finish();
}

criterion_group!(benches, bench_redaction);
criterion_main!(benches);
