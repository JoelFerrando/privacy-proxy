use privacy_proxy_core::{redact_str, redact_value, scan_str, Config};
use proptest::prelude::*;
use serde_json::{Map, Number, Value};
use std::collections::BTreeMap;

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|number| Value::Number(Number::from(number))),
        ".*".prop_map(Value::String),
    ];

    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            prop::collection::btree_map("[A-Za-z0-9_\\-]{0,24}", inner, 0..8)
                .prop_map(btree_to_json_object),
        ]
    })
}

fn btree_to_json_object(input: BTreeMap<String, Value>) -> Value {
    Value::Object(input.into_iter().collect::<Map<String, Value>>())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn redacting_valid_json_keeps_json_valid(value in arb_json()) {
        let config = Config::default();
        let result = redact_value(value, &config)?;
        let serialized = serde_json::to_string(&result.value)?;
        let reparsed: Value = serde_json::from_str(&serialized)?;

        prop_assert_eq!(result.value, reparsed);
    }

    #[test]
    fn mask_redaction_is_idempotent_for_valid_json(value in arb_json()) {
        let config = Config::default();
        let first = redact_value(value, &config)?;
        let second = redact_value(first.value.clone(), &config)?;

        prop_assert_eq!(first.value, second.value);
    }

    #[test]
    fn arbitrary_utf8_strings_do_not_panic(input in ".{0,4096}") {
        let config = Config::default();
        let redacted = redact_str(&input, &config)?;
        let report = scan_str(&input, &config)?;

        prop_assert!(redacted.stats.total <= report.total);
    }
}
