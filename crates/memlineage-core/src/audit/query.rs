use crate::audit::log::{AuditError, AuditLog, StoredEvent};
use crate::model::{Action, Decision, MemoryRecord, Provenance};
use std::collections::BTreeMap;
use uuid::Uuid;

/// One stored decision, newest write for a record or one event in the chain.
#[derive(Clone, Debug, PartialEq)]
pub struct LogRecord {
    pub event_id: i64,
    pub record_id: Uuid,
    pub store: String,
    pub namespace: Vec<String>,
    pub key: Option<String>,
    pub content: String,
    pub provenance: Provenance,
    pub version: u32,
    pub action: String,
    pub rule_id: String,
    pub created_at: String,
}

impl AuditLog {
    /// Latest event for each record, filtered by store, principal, and action.
    pub fn latest(
        &self,
        store: Option<&str>,
        principal: Option<&str>,
        action: Option<&str>,
    ) -> Result<Vec<LogRecord>, AuditError> {
        let mut newest: BTreeMap<Uuid, LogRecord> = BTreeMap::new();
        for event in self.events()? {
            let record = to_log(event)?;
            match newest.get(&record.record_id) {
                Some(current) if current.event_id > record.event_id => {}
                _ => {
                    newest.insert(record.record_id, record);
                }
            }
        }
        let mut records: Vec<LogRecord> = newest
            .into_values()
            .filter(|record| store.is_none_or(|want| record.store == want))
            .filter(|record| principal.is_none_or(|want| record.provenance.principal == want))
            .filter(|record| action.is_none_or(|want| record.action == want))
            .collect();
        records.sort_by_key(|record| record.event_id);
        Ok(records)
    }

    /// Latest event for one record id.
    pub fn show(&self, id: Uuid) -> Result<Option<LogRecord>, AuditError> {
        Ok(self
            .latest(None, None, None)?
            .into_iter()
            .find(|record| record.record_id == id))
    }

    /// Events whose timestamp is at or after `since`.
    ///
    /// `since` is compared as text with the stored UTC timestamp.
    pub fn changed_since(&self, since: &str) -> Result<Vec<LogRecord>, AuditError> {
        let cutoff = normalize_cutoff(since);
        let mut records = self
            .events()?
            .into_iter()
            .map(to_log)
            .collect::<Result<Vec<_>, _>>()?;
        records.retain(|record| record.created_at.as_str() >= cutoff.as_str());
        Ok(records)
    }

    /// Later records whose provenance lists `id` as a parent, then theirs, and so on.
    pub fn trace(&self, id: Uuid) -> Result<Vec<LogRecord>, AuditError> {
        let all = self.latest(None, None, None)?;
        let mut seen = Vec::new();
        let mut frontier = vec![id];
        let mut out = Vec::new();
        while let Some(parent) = frontier.pop() {
            for record in &all {
                if seen.contains(&record.record_id) || record.record_id == id {
                    continue;
                }
                if record.provenance.parent_ids.contains(&parent) {
                    seen.push(record.record_id);
                    frontier.push(record.record_id);
                    out.push(record.clone());
                }
            }
        }
        Ok(out)
    }

    /// Records waiting in the quarantine table.
    pub fn pending(&self) -> Result<Vec<LogRecord>, AuditError> {
        let mut stmt = self.conn.prepare(
            "SELECT record_id FROM quarantine WHERE status = 'quarantine' ORDER BY event_id",
        )?;
        let ids = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut waiting = Vec::new();
        for id in ids {
            let id = Uuid::parse_str(&id?).map_err(|_| AuditError::Corrupt(0))?;
            if let Some(record) = self.show(id)? {
                waiting.push(record);
            }
        }
        Ok(waiting)
    }

    /// Append a block event for allowed records newer than `cutoff` that carry `taint`.
    ///
    /// Old rows stay. The new events use rule id `rollback`.
    pub fn rollback(&self, cutoff: &str, taint: &str) -> Result<Vec<Uuid>, AuditError> {
        let cutoff = normalize_cutoff(cutoff);
        let mut rolled = Vec::new();
        for record in self.latest(None, None, Some("allow"))? {
            if record.created_at.as_str() <= cutoff.as_str() {
                continue;
            }
            if !record.provenance.taint.iter().any(|tag| tag == taint) {
                continue;
            }
            let memory = MemoryRecord {
                id: record.record_id,
                store: record.store.clone(),
                namespace: record.namespace.clone(),
                key: record.key.clone(),
                content: record.content.clone(),
                provenance: record.provenance.clone(),
                version: record.version.saturating_add(1),
            };
            self.append(
                &memory,
                &Decision {
                    action: Action::Block,
                    rule_id: "rollback".to_string(),
                    retrieval_weight: None,
                },
            )?;
            rolled.push(record.record_id);
        }
        Ok(rolled)
    }
}

fn to_log(event: StoredEvent) -> Result<LogRecord, AuditError> {
    let record_id = Uuid::parse_str(&event.record_id).map_err(|_| AuditError::Corrupt(event.id))?;
    let namespace =
        serde_json::from_str(&event.namespace).map_err(|_| AuditError::Corrupt(event.id))?;
    let provenance =
        serde_json::from_str(&event.provenance).map_err(|_| AuditError::Corrupt(event.id))?;
    Ok(LogRecord {
        event_id: event.id,
        record_id,
        store: event.store,
        namespace,
        key: event.key,
        content: event.content,
        provenance,
        version: event.version,
        action: event.action,
        rule_id: event.rule_id,
        created_at: event.created_at,
    })
}

fn normalize_cutoff(raw: &str) -> String {
    if raw.len() == 10 {
        format!("{raw}T00:00:00Z")
    } else if raw.len() == 16 {
        format!("{raw}:00Z")
    } else {
        raw.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Context, SourceKind, TrustLevel};
    use crate::provenance::{build_provenance, ParentRef, SourceMark, TrustTable};
    use crate::Firewall;
    fn open() -> (tempfile::TempDir, Firewall) {
        let dir = tempfile::tempdir().expect("tempdir");
        let firewall = Firewall::open(
            include_str!("../../tests/fixtures/memlineage.yaml"),
            &dir.path().join("audit.db"),
        )
        .expect("open");
        (dir, firewall)
    }

    fn record(
        content: &str,
        namespace: &str,
        source: Option<&SourceMark>,
        parents: &[ParentRef],
    ) -> MemoryRecord {
        let provenance = build_provenance(
            source,
            "user-42",
            "s",
            parents,
            content,
            &TrustTable::default(),
        );
        MemoryRecord {
            id: Uuid::now_v7(),
            store: "mem0".to_string(),
            namespace: vec![namespace.to_string()],
            key: None,
            content: content.to_string(),
            provenance,
            version: 1,
        }
    }

    #[test]
    fn latest_filters_store_principal_and_action() {
        let (_dir, firewall) = open();
        let reader = Context::new("user-42", "s");
        let lesson = record(
            "a phone number",
            "lessons",
            Some(&SourceMark::web("https://example.test").with_extra_taint(["web"])),
            &[],
        );
        // web tag comes from the mark. with_extra is redundant but fine.
        let mut lesson = lesson;
        lesson.provenance.taint.insert("web".to_string());
        lesson.provenance.trust = TrustLevel::Untrusted;
        lesson.provenance.source_kind = SourceKind::Web;
        firewall.check_and_log(&lesson, &reader).expect("log");

        let mut other = record("hello", "preferences", Some(&SourceMark::user()), &[]);
        other.store = "langgraph".to_string();
        other.provenance.principal = "user-7".to_string();
        other.provenance.trust = TrustLevel::Trusted;
        other.provenance.source_kind = SourceKind::User;
        firewall
            .check_and_log(&other, &Context::new("user-7", "s"))
            .expect("log");

        let log = AuditLog::open(&_dir.path().join("audit.db")).expect("reopen");
        // WAL allows a second connection.
        let quarantined = log
            .latest(Some("mem0"), Some("user-42"), Some("quarantine"))
            .expect("list");
        assert_eq!(quarantined.len(), 1);
        assert_eq!(quarantined[0].record_id, lesson.id);
        assert!(log
            .latest(Some("langgraph"), Some("user-42"), None)
            .expect("list")
            .is_empty());
    }

    #[test]
    fn trace_follows_parent_ids_and_rollback_keeps_old_rows() {
        let (dir, firewall) = open();
        let reader = Context::new("user-42", "s");
        let mut parent = record(
            "page",
            "facts",
            Some(&SourceMark::web("https://example.test")),
            &[],
        );
        parent.provenance.taint.insert("web".to_string());
        parent.provenance.trust = TrustLevel::Trusted;
        parent.provenance.source_kind = SourceKind::User;
        parent.namespace = vec!["preferences".to_string()];
        firewall.check_and_log(&parent, &reader).expect("log");

        let mut child = record(
            "derived",
            "preferences",
            Some(&SourceMark::user()),
            &[ParentRef {
                id: parent.id,
                provenance: parent.provenance.clone(),
            }],
        );
        child.provenance.taint.insert("web".to_string());
        firewall.check_and_log(&child, &reader).expect("log");

        let log = AuditLog::open(&dir.path().join("audit.db")).expect("reopen");
        let traced = log.trace(parent.id).expect("trace");
        assert_eq!(traced.len(), 1);
        assert_eq!(traced[0].record_id, child.id);

        let before = log.events().expect("events").len();
        let rolled = log
            .rollback("1970-01-01T00:00:00Z", "web")
            .expect("rollback");
        assert!(rolled.contains(&parent.id) || rolled.contains(&child.id));
        let after = log.events().expect("events");
        assert!(after.len() > before);
        assert!(after.iter().any(|event| event.rule_id == "rollback"));
        assert!(log.verify().expect("verify").is_none());
    }

    #[test]
    fn minute_precision_cutoff_is_expanded() {
        assert_eq!(normalize_cutoff("2026-11-03T10:00"), "2026-11-03T10:00:00Z");
        assert_eq!(normalize_cutoff("2026-11-03"), "2026-11-03T00:00:00Z");
    }
}
