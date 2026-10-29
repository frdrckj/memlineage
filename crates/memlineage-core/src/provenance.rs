use crate::hash::content_sha256;
use crate::model::{Provenance, SourceKind, TrustLevel};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// A trust-map value. `Inherit` takes the lowest parent trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustAssign {
    Level(TrustLevel),
    Inherit,
}

/// Trust assignments from a policy file.
///
/// Keys look like `user`, `document`, or `tool:browser`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustTable {
    entries: BTreeMap<String, TrustAssign>,
}

impl TrustTable {
    /// Build a table from parsed policy entries.
    pub fn new(entries: BTreeMap<String, TrustAssign>) -> Self {
        Self { entries }
    }

    /// Look up one key.
    pub fn get(&self, key: &str) -> Option<TrustAssign> {
        self.entries.get(key).copied()
    }
}

/// Source mark placed around a write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceMark {
    pub kind: SourceKind,
    pub source_ref: String,
}

impl SourceMark {
    /// The principal's own message.
    pub fn user() -> Self {
        Self::bare(SourceKind::User)
    }

    /// Operator or system config.
    pub fn system() -> Self {
        Self::bare(SourceKind::System)
    }

    /// A page the agent read.
    pub fn web(url: impl Into<String>) -> Self {
        Self::named(SourceKind::Web, url)
    }

    /// A file the agent read.
    pub fn document(path: impl Into<String>) -> Self {
        Self::named(SourceKind::Document, path)
    }

    /// Output of one tool. `name` becomes the taint tag `tool:<name>`.
    pub fn tool(name: impl Into<String>) -> Self {
        Self::named(SourceKind::Tool, name)
    }

    /// Text the agent wrote. Trust and taint come from the parents when the
    /// policy says `inherit`.
    pub fn agent() -> Self {
        Self::bare(SourceKind::Agent)
    }

    fn bare(kind: SourceKind) -> Self {
        Self {
            kind,
            source_ref: String::new(),
        }
    }

    fn named(kind: SourceKind, source_ref: impl Into<String>) -> Self {
        Self {
            kind,
            source_ref: source_ref.into(),
        }
    }
}

/// One input a write was derived from.
#[derive(Clone, Debug)]
pub struct ParentRef {
    pub id: Uuid,
    pub provenance: Provenance,
}

/// Provenance for one write.
///
/// No `source` means `SourceKind::Unknown`, trust `Untrusted`, and no taint of
/// its own. Parent taint is always copied in, so a rewrite does not clear it.
/// A missing trust-map key is `Untrusted`. `Inherit` with no parents is
/// `Untrusted`.
pub fn build_provenance(
    source: Option<&SourceMark>,
    principal: &str,
    session_id: &str,
    parents: &[ParentRef],
    content: &str,
    trust: &TrustTable,
) -> Provenance {
    let (kind, source_ref) = match source {
        Some(mark) => (mark.kind, mark.source_ref.clone()),
        None => (SourceKind::Unknown, String::new()),
    };
    Provenance {
        trust: resolve_trust(kind, &source_ref, parents, trust),
        taint: union_taint(kind, &source_ref, parents),
        source_kind: kind,
        source_ref,
        principal: principal.to_string(),
        session_id: session_id.to_string(),
        parent_ids: parents.iter().map(|parent| parent.id).collect(),
        content_sha256: content_sha256(content),
    }
}

fn trust_key(kind: SourceKind, source_ref: &str) -> String {
    match kind {
        SourceKind::User => "user".to_string(),
        SourceKind::System => "system".to_string(),
        SourceKind::Web => "web".to_string(),
        SourceKind::Document => "document".to_string(),
        SourceKind::Agent => "agent".to_string(),
        SourceKind::Unknown => "unknown".to_string(),
        SourceKind::Tool => format!("tool:{source_ref}"),
    }
}

fn own_tag(kind: SourceKind, source_ref: &str) -> Option<String> {
    match kind {
        SourceKind::Web => Some("web".to_string()),
        SourceKind::Document => Some("document".to_string()),
        SourceKind::Tool => Some(format!("tool:{source_ref}")),
        SourceKind::User | SourceKind::System | SourceKind::Agent | SourceKind::Unknown => None,
    }
}

fn union_taint(kind: SourceKind, source_ref: &str, parents: &[ParentRef]) -> BTreeSet<String> {
    let mut taint = BTreeSet::new();
    if let Some(tag) = own_tag(kind, source_ref) {
        taint.insert(tag);
    }
    for parent in parents {
        taint.extend(parent.provenance.taint.iter().cloned());
    }
    taint
}

fn resolve_trust(
    kind: SourceKind,
    source_ref: &str,
    parents: &[ParentRef],
    table: &TrustTable,
) -> TrustLevel {
    match table.get(&trust_key(kind, source_ref)) {
        Some(TrustAssign::Level(level)) => level,
        Some(TrustAssign::Inherit) => lowest_parent_trust(parents),
        None => TrustLevel::Untrusted,
    }
}

fn lowest_parent_trust(parents: &[ParentRef]) -> TrustLevel {
    parents
        .iter()
        .map(|parent| parent.provenance.trust)
        .min()
        .unwrap_or(TrustLevel::Untrusted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample_table() -> TrustTable {
        let mut entries = BTreeMap::new();
        entries.insert("user".to_string(), TrustAssign::Level(TrustLevel::Trusted));
        entries.insert(
            "system".to_string(),
            TrustAssign::Level(TrustLevel::Trusted),
        );
        entries.insert(
            "tool:browser".to_string(),
            TrustAssign::Level(TrustLevel::Untrusted),
        );
        entries.insert("agent".to_string(), TrustAssign::Inherit);
        TrustTable::new(entries)
    }

    fn parent(trust: TrustLevel, tags: &[&str]) -> ParentRef {
        let mut taint = BTreeSet::new();
        for tag in tags {
            taint.insert((*tag).to_string());
        }
        ParentRef {
            id: Uuid::now_v7(),
            provenance: Provenance {
                source_kind: SourceKind::Web,
                source_ref: "https://example.test".to_string(),
                trust,
                principal: "user-42".to_string(),
                session_id: "s".to_string(),
                parent_ids: Vec::new(),
                content_sha256: [1; 32],
                taint,
            },
        }
    }

    #[test]
    fn missing_source_is_unknown_and_untrusted() {
        let built = build_provenance(None, "user-42", "s-1", &[], "hello", &sample_table());
        assert_eq!(built.source_kind, SourceKind::Unknown);
        assert_eq!(built.trust, TrustLevel::Untrusted);
        assert!(built.taint.is_empty());
        assert!(built.parent_ids.is_empty());
        assert_eq!(built.content_sha256, content_sha256("hello"));
    }

    #[test]
    fn user_mark_is_trusted_and_untainted() {
        let built = build_provenance(
            Some(&SourceMark::user()),
            "user-42",
            "s-1",
            &[],
            "I prefer Bahasa",
            &sample_table(),
        );
        assert_eq!(built.source_kind, SourceKind::User);
        assert_eq!(built.trust, TrustLevel::Trusted);
        assert!(built.taint.is_empty());
    }

    #[test]
    fn web_and_tool_add_their_tags() {
        let table = sample_table();
        let page = build_provenance(
            Some(&SourceMark::web("https://example.test/a")),
            "user-42",
            "s-1",
            &[],
            "page",
            &table,
        );
        let tool = build_provenance(
            Some(&SourceMark::tool("browser")),
            "user-42",
            "s-1",
            &[],
            "page",
            &table,
        );
        assert_eq!(page.taint.iter().collect::<Vec<_>>(), vec!["web"]);
        assert_eq!(page.trust, TrustLevel::Untrusted);
        assert_eq!(page.source_ref, "https://example.test/a");
        assert!(tool.taint.contains("tool:browser"));
        assert_eq!(tool.trust, TrustLevel::Untrusted);
    }

    #[test]
    fn agent_inherits_lowest_trust_and_union_of_taint() {
        let parents = vec![
            parent(TrustLevel::Trusted, &["web"]),
            parent(TrustLevel::Hostile, &["document"]),
        ];
        let built = build_provenance(
            Some(&SourceMark::agent()),
            "user-42",
            "s-1",
            &parents,
            "rewrite",
            &sample_table(),
        );
        assert_eq!(built.trust, TrustLevel::Hostile);
        assert!(built.taint.contains("web"));
        assert!(built.taint.contains("document"));
        assert_eq!(built.parent_ids.len(), 2);
        assert!(!built.taint.contains("agent"));
    }

    #[test]
    fn agent_with_no_parents_is_untrusted() {
        let built = build_provenance(
            Some(&SourceMark::agent()),
            "user-42",
            "s-1",
            &[],
            "note",
            &sample_table(),
        );
        assert_eq!(built.trust, TrustLevel::Untrusted);
        assert!(built.taint.is_empty());
    }

    #[test]
    fn a_rewrite_keeps_parent_taint() {
        let parents = vec![parent(TrustLevel::Untrusted, &["web"])];
        let built = build_provenance(
            Some(&SourceMark::user()),
            "user-42",
            "s-1",
            &parents,
            "cleaned",
            &sample_table(),
        );
        assert_eq!(built.trust, TrustLevel::Trusted);
        assert!(built.taint.contains("web"));
    }

    proptest! {
        #[test]
        fn taint_is_a_superset_of_every_parent(
            parent_tags in proptest::collection::vec(
                proptest::collection::btree_set("[a-z]{1,6}", 0..4),
                0..4,
            )
        ) {
            let parents: Vec<ParentRef> = parent_tags
                .iter()
                .map(|tags| {
                    let owned: Vec<&str> = tags.iter().map(String::as_str).collect();
                    parent(TrustLevel::Untrusted, &owned)
                })
                .collect();
            let built = build_provenance(
                Some(&SourceMark::agent()),
                "p",
                "s",
                &parents,
                "body",
                &sample_table(),
            );
            for parent in &parents {
                for tag in &parent.provenance.taint {
                    prop_assert!(built.taint.contains(tag));
                }
            }
        }

        #[test]
        fn agent_trust_is_never_above_the_lowest_parent(
            levels in proptest::collection::vec(0u8..4, 0..6)
        ) {
            let parents: Vec<ParentRef> = levels
                .iter()
                .map(|level| parent(level_from(*level), &[]))
                .collect();
            let built = build_provenance(
                Some(&SourceMark::agent()),
                "p",
                "s",
                &parents,
                "body",
                &sample_table(),
            );
            if parents.is_empty() {
                prop_assert_eq!(built.trust, TrustLevel::Untrusted);
            } else {
                let lowest = parents.iter().map(|parent| parent.provenance.trust).min().unwrap();
                prop_assert_eq!(built.trust, lowest);
                for parent in &parents {
                    prop_assert!(built.trust <= parent.provenance.trust);
                }
            }
        }
    }

    fn level_from(value: u8) -> TrustLevel {
        match value {
            0 => TrustLevel::Hostile,
            1 => TrustLevel::Untrusted,
            2 => TrustLevel::Verified,
            _ => TrustLevel::Trusted,
        }
    }
}
