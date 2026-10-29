use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

/// How far a writer is trusted.
///
/// The order runs from least trusted to most trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    Hostile,
    Untrusted,
    Verified,
    Trusted,
}

/// Kind of place a memory was written from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    User,
    System,
    Tool,
    Web,
    Document,
    Agent,
    Unknown,
}

/// Origin stored with one memory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub source_kind: SourceKind,
    pub source_ref: String,
    pub trust: TrustLevel,
    pub principal: String,
    pub session_id: String,
    pub parent_ids: Vec<Uuid>,
    pub content_sha256: [u8; 32],
    pub taint: BTreeSet<String>,
}

/// One memory and the provenance that arrived with it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRecord {
    pub id: Uuid,
    pub store: String,
    pub namespace: Vec<String>,
    pub key: Option<String>,
    pub content: String,
    pub provenance: Provenance,
    pub version: u32,
}

/// What a policy does with a write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Quarantine,
    Block,
}

/// Outcome of one policy check.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub action: Action,
    pub rule_id: String,
    pub retrieval_weight: Option<f32>,
}

/// Principal and session of the current reader or writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub principal: String,
    pub session_id: String,
}

impl Context {
    /// Build a context for one check.
    pub fn new(principal: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
            session_id: session_id.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_runs_from_hostile_to_trusted() {
        assert!(TrustLevel::Hostile < TrustLevel::Untrusted);
        assert!(TrustLevel::Untrusted < TrustLevel::Verified);
        assert!(TrustLevel::Verified < TrustLevel::Trusted);
    }

    #[test]
    fn enums_serialize_as_snake_case() {
        let trust = serde_json::to_string(&TrustLevel::Untrusted).expect("json");
        let kind = serde_json::to_string(&SourceKind::Unknown).expect("json");
        let action = serde_json::to_string(&Action::Quarantine).expect("json");
        assert_eq!(trust, "\"untrusted\"");
        assert_eq!(kind, "\"unknown\"");
        assert_eq!(action, "\"quarantine\"");
    }

    #[test]
    fn taint_serializes_in_sorted_order() {
        let mut taint = BTreeSet::new();
        taint.insert("web".to_string());
        taint.insert("tool:email_read".to_string());
        let provenance = Provenance {
            source_kind: SourceKind::Agent,
            source_ref: String::new(),
            trust: TrustLevel::Untrusted,
            principal: "user-42".to_string(),
            session_id: "s-1".to_string(),
            parent_ids: Vec::new(),
            content_sha256: [0; 32],
            taint,
        };
        let json = serde_json::to_string(&provenance).expect("json");
        let web = json.find("web").expect("web tag");
        let tool = json.find("tool:email_read").expect("tool tag");
        assert!(tool < web);
    }
}
