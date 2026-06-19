#![no_main]

use libfuzzer_sys::fuzz_target;
use privacy_proxy_core::{redact_str, scan_str, Config};

fuzz_target!(|data: &str| {
    let config = Config::default();
    let _ = scan_str(data, &config);
    let _ = redact_str(data, &config);
});

