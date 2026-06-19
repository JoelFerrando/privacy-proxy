#![no_main]

use libfuzzer_sys::fuzz_target;
use privacy_proxy_core::{redact_value, scan_value, Config};
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    let config = Config::default();
    let _ = scan_value(&value, &config);
    let _ = redact_value(value, &config);
});

