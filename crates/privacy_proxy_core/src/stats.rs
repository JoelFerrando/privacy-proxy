use crate::DetectorKind;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub total: u64,
    pub by_type: BTreeMap<String, u64>,
}

impl ScanReport {
    pub(crate) fn record(&mut self, kind: DetectorKind) {
        self.total = self.total.saturating_add(1);
        let count = self.by_type.entry(kind.as_str().to_owned()).or_insert(0);
        *count = count.saturating_add(1);
    }

    pub fn merge(&mut self, other: Self) {
        self.total = self.total.saturating_add(other.total);
        for (kind, count) in other.by_type {
            let current = self.by_type.entry(kind).or_insert(0);
            *current = current.saturating_add(count);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
}
