#![no_main]

use libfuzzer_sys::fuzz_target;
use memlineage_core::{Context, MemoryRecord, Policy, Provenance, SourceKind, TrustLevel};
use std::collections::BTreeSet;
use uuid::Uuid;

const POLICY: &str = include_str!("../../tests/fixtures/memlineage.yaml");

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(policy) = Policy::from_yaml(POLICY) else {
        return;
    };
    let record = MemoryRecord {
        id: Uuid::nil(),
        store: "mem0".to_string(),
        namespace: vec!["lessons".to_string()],
        key: None,
        content: text.to_string(),
        provenance: Provenance {
            source_kind: SourceKind::Web,
            source_ref: "https://example.test".to_string(),
            trust: TrustLevel::Untrusted,
            principal: "user-42".to_string(),
            session_id: "s".to_string(),
            parent_ids: Vec::new(),
            content_sha256: [0; 32],
            taint: BTreeSet::from(["web".to_string()]),
        },
        version: 1,
    };
    let _ = policy.check(&record, &Context::new("user-42", "s"));
});
