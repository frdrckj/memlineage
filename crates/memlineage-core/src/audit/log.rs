use crate::hash::{canonical_json, chain_hash, HashError};
use crate::model::{Action, Decision, MemoryRecord, Provenance};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id TEXT NOT NULL,
    store TEXT NOT NULL,
    namespace TEXT NOT NULL,
    key TEXT,
    content TEXT NOT NULL,
    provenance TEXT NOT NULL,
    version INTEGER NOT NULL,
    action TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    retrieval_weight TEXT,
    prev_hash BLOB NOT NULL,
    hash BLOB NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS events_no_update
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS events_no_delete
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events is append-only');
END;

CREATE TABLE IF NOT EXISTS quarantine (
    record_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
";

/// Failure from the audit log.
#[derive(Debug, Error)]
pub enum AuditError {
    /// SQLite returned an error.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Creating the database directory failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A value could not be hashed.
    #[error("{0}")]
    Hash(#[from] HashError),
    /// `approve` or `reject` was asked for a row that is not waiting.
    #[error("record {0} is not quarantined")]
    NotQuarantined(Uuid),
    /// A stored row could not be read back as a memory.
    #[error("stored event {0} is not valid")]
    Corrupt(i64),
}

/// Append-only hash-chained log of policy decisions.
pub struct AuditLog {
    conn: Connection,
}

pub(crate) struct StoredEvent {
    pub id: i64,
    pub record_id: String,
    pub store: String,
    pub namespace: String,
    pub key: Option<String>,
    pub content: String,
    pub provenance: String,
    pub version: u32,
    pub action: String,
    pub rule_id: String,
    pub retrieval_weight: Option<String>,
    pub prev_hash: Vec<u8>,
    pub hash: Vec<u8>,
    pub created_at: String,
}

impl AuditLog {
    /// Open or create a log. The parent directory is created when it is missing.
    /// The file uses WAL mode. `events` rejects UPDATE and DELETE.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Append one decision. Quarantine and block also land in the quarantine table.
    /// Allow clears a previous quarantine row for the same record.
    pub fn append(&self, record: &MemoryRecord, decision: &Decision) -> Result<i64, AuditError> {
        let id = self.insert_event(record, decision)?;
        let stamp = now_rfc3339();
        match decision.action {
            Action::Quarantine | Action::Block => {
                self.upsert_quarantine(&record.id, action_name(decision.action), id, &stamp)?;
            }
            Action::Allow => {
                self.conn.execute(
                    "UPDATE quarantine
                     SET status = 'allow', event_id = ?1, updated_at = ?2
                     WHERE record_id = ?3",
                    params![id, stamp, record.id.to_string()],
                )?;
            }
        }
        Ok(id)
    }

    /// Release a quarantined record. Writes a new allow event. Does not edit old rows.
    pub fn approve(&self, id: Uuid) -> Result<(), AuditError> {
        self.review(id, Action::Allow, "approve", "approved")
    }

    /// Keep a quarantined record out. Writes a new block event. Does not edit old rows.
    pub fn reject(&self, id: Uuid) -> Result<(), AuditError> {
        self.review(id, Action::Block, "reject", "rejected")
    }

    pub(crate) fn events(&self) -> Result<Vec<StoredEvent>, AuditError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, record_id, store, namespace, key, content, provenance, version,
                    action, rule_id, retrieval_weight, prev_hash, hash, created_at
             FROM events ORDER BY id",
        )?;
        let rows = stmt.query_map([], read_event)?;
        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    fn review(
        &self,
        id: Uuid,
        action: Action,
        rule_id: &str,
        status: &str,
    ) -> Result<(), AuditError> {
        let row = self.quarantine(id)?;
        if row.status != "quarantine" {
            return Err(AuditError::NotQuarantined(id));
        }
        let record = self.record_at(row.event_id)?;
        let decision = Decision {
            action,
            rule_id: rule_id.to_string(),
            retrieval_weight: None,
        };
        let event_id = self.insert_event(&record, &decision)?;
        self.upsert_quarantine(&id, status, event_id, &now_rfc3339())?;
        Ok(())
    }

    fn insert_event(&self, record: &MemoryRecord, decision: &Decision) -> Result<i64, AuditError> {
        let prev = self.tip_hash()?;
        let created_at = now_rfc3339();
        let namespace = serde_json::to_string(&record.namespace)
            .map_err(|err| HashError::Json(err.to_string()))?;
        let provenance = canonical_json(&record.provenance)?;
        let weight = weight_token(decision.retrieval_weight)?;
        let record_id = record.id.to_string();
        let prev_hex = hex_encode(&prev);
        let fields = ChainFields {
            record_id: &record_id,
            store: &record.store,
            namespace: &record.namespace,
            key: record.key.as_deref(),
            content: &record.content,
            provenance: &record.provenance,
            version: record.version,
            action: action_name(decision.action),
            rule_id: &decision.rule_id,
            retrieval_weight: weight.as_deref(),
            prev_hash: &prev_hex,
            created_at: &created_at,
        };
        let body = chain_body(&fields)?;
        let digest = chain_hash(&prev, &body);
        self.conn.execute(
            "INSERT INTO events (
                record_id, store, namespace, key, content, provenance, version,
                action, rule_id, retrieval_weight, prev_hash, hash, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                record.id.to_string(),
                record.store,
                namespace,
                record.key,
                record.content,
                provenance,
                record.version,
                action_name(decision.action),
                decision.rule_id,
                weight,
                prev.as_slice(),
                digest.as_slice(),
                created_at,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    fn tip_hash(&self) -> Result<[u8; 32], AuditError> {
        let hash: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT hash FROM events ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match hash {
            Some(bytes) if bytes.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Ok(out)
            }
            Some(_) => Err(AuditError::Corrupt(0)),
            None => Ok([0u8; 32]),
        }
    }

    fn upsert_quarantine(
        &self,
        id: &Uuid,
        status: &str,
        event_id: i64,
        updated_at: &str,
    ) -> Result<(), AuditError> {
        self.conn.execute(
            "INSERT INTO quarantine (record_id, status, event_id, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(record_id) DO UPDATE SET
                status = excluded.status,
                event_id = excluded.event_id,
                updated_at = excluded.updated_at",
            params![id.to_string(), status, event_id, updated_at],
        )?;
        Ok(())
    }

    fn quarantine(&self, id: Uuid) -> Result<QuarantineRow, AuditError> {
        let row = self
            .conn
            .query_row(
                "SELECT status, event_id FROM quarantine WHERE record_id = ?1",
                params![id.to_string()],
                |row| {
                    Ok(QuarantineRow {
                        status: row.get(0)?,
                        event_id: row.get(1)?,
                    })
                },
            )
            .optional()?;
        row.ok_or(AuditError::NotQuarantined(id))
    }

    fn record_at(&self, event_id: i64) -> Result<MemoryRecord, AuditError> {
        let event = self.event(event_id)?;
        let namespace: Vec<String> =
            serde_json::from_str(&event.namespace).map_err(|_| AuditError::Corrupt(event_id))?;
        let provenance: Provenance =
            serde_json::from_str(&event.provenance).map_err(|_| AuditError::Corrupt(event_id))?;
        let id = Uuid::parse_str(&event.record_id).map_err(|_| AuditError::Corrupt(event_id))?;
        Ok(MemoryRecord {
            id,
            store: event.store,
            namespace,
            key: event.key,
            content: event.content,
            provenance,
            version: event.version,
        })
    }

    fn event(&self, id: i64) -> Result<StoredEvent, AuditError> {
        self.conn
            .query_row(
                "SELECT id, record_id, store, namespace, key, content, provenance, version,
                        action, rule_id, retrieval_weight, prev_hash, hash, created_at
                 FROM events WHERE id = ?1",
                params![id],
                read_event,
            )
            .map_err(|_| AuditError::Corrupt(id))
    }
}

struct QuarantineRow {
    status: String,
    event_id: i64,
}

struct ChainFields<'a> {
    record_id: &'a str,
    store: &'a str,
    namespace: &'a [String],
    key: Option<&'a str>,
    content: &'a str,
    provenance: &'a Provenance,
    version: u32,
    action: &'a str,
    rule_id: &'a str,
    retrieval_weight: Option<&'a str>,
    prev_hash: &'a str,
    created_at: &'a str,
}

pub(crate) fn chain_body_from_stored(event: &StoredEvent) -> Result<String, HashError> {
    let namespace: Vec<String> =
        serde_json::from_str(&event.namespace).map_err(|err| HashError::Json(err.to_string()))?;
    let provenance: Provenance =
        serde_json::from_str(&event.provenance).map_err(|err| HashError::Json(err.to_string()))?;
    if event.prev_hash.len() != 32 {
        return Err(HashError::Json("prev_hash length".to_string()));
    }
    let mut prev = [0u8; 32];
    prev.copy_from_slice(&event.prev_hash);
    let prev_hex = hex_encode(&prev);
    let fields = ChainFields {
        record_id: &event.record_id,
        store: &event.store,
        namespace: &namespace,
        key: event.key.as_deref(),
        content: &event.content,
        provenance: &provenance,
        version: event.version,
        action: &event.action,
        rule_id: &event.rule_id,
        retrieval_weight: event.retrieval_weight.as_deref(),
        prev_hash: &prev_hex,
        created_at: &event.created_at,
    };
    chain_body(&fields)
}

fn chain_body(fields: &ChainFields<'_>) -> Result<String, HashError> {
    let provenance =
        serde_json::to_value(fields.provenance).map_err(|err| HashError::Json(err.to_string()))?;
    let weight = match fields.retrieval_weight {
        Some(token) => {
            serde_json::from_str::<Value>(token).map_err(|err| HashError::Json(err.to_string()))?
        }
        None => Value::Null,
    };
    let value = serde_json::json!({
        "action": fields.action,
        "content": fields.content,
        "created_at": fields.created_at,
        "key": fields.key,
        "namespace": fields.namespace,
        "prev_hash": fields.prev_hash,
        "provenance": provenance,
        "record_id": fields.record_id,
        "retrieval_weight": weight,
        "rule_id": fields.rule_id,
        "store": fields.store,
        "version": fields.version,
    });
    canonical_json(&value)
}

fn weight_token(weight: Option<f32>) -> Result<Option<String>, HashError> {
    match weight {
        None => Ok(None),
        Some(value) if value.is_finite() => Ok(Some(
            serde_json::to_string(&value).map_err(|err| HashError::Json(err.to_string()))?,
        )),
        Some(_) => Err(HashError::NonFinite),
    }
}

fn action_name(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Quarantine => "quarantine",
        Action::Block => "block",
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format_unix_secs(secs)
}

fn format_unix_secs(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as u32;
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    (year as i32, month as u32, day as u32)
}

fn read_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEvent> {
    Ok(StoredEvent {
        id: row.get(0)?,
        record_id: row.get(1)?,
        store: row.get(2)?,
        namespace: row.get(3)?,
        key: row.get(4)?,
        content: row.get(5)?,
        provenance: row.get(6)?,
        version: row.get(7)?,
        action: row.get(8)?,
        rule_id: row.get(9)?,
        retrieval_weight: row.get(10)?,
        prev_hash: row.get(11)?,
        hash: row.get(12)?,
        created_at: row.get(13)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Context, SourceKind, TrustLevel};
    use crate::policy::Policy;
    use crate::provenance::{build_provenance, SourceMark, TrustTable};
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn sample_record(content: &str) -> MemoryRecord {
        let provenance = build_provenance(
            Some(&SourceMark::web("https://example.test")),
            "user-42",
            "s-1",
            &[],
            content,
            &TrustTable::default(),
        );
        MemoryRecord {
            id: Uuid::now_v7(),
            store: "mem0".to_string(),
            namespace: vec!["facts".to_string()],
            key: Some("k".to_string()),
            content: content.to_string(),
            provenance,
            version: 1,
        }
    }

    fn decision(action: Action, rule_id: &str, weight: Option<f32>) -> Decision {
        Decision {
            action,
            rule_id: rule_id.to_string(),
            retrieval_weight: weight,
        }
    }

    fn open_log() -> (tempfile::TempDir, AuditLog) {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = AuditLog::open(&dir.path().join("audit.db")).expect("open");
        (dir, log)
    }

    #[test]
    fn unix_epoch_formats() {
        assert_eq!(format_unix_secs(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_secs(1_609_459_200), "2021-01-01T00:00:00Z");
        assert_eq!(format_unix_secs(1_735_689_600), "2025-01-01T00:00:00Z");
    }

    #[test]
    fn first_event_uses_a_zero_prev_hash_and_the_chain_verifies() {
        let (_dir, log) = open_log();
        let record = sample_record("one");
        log.append(&record, &decision(Action::Allow, "allow-user", None))
            .expect("append");
        let second = sample_record("two");
        log.append(&second, &decision(Action::Quarantine, "default", Some(0.3)))
            .expect("append");
        let events = log.events().expect("events");
        assert_eq!(events[0].prev_hash, vec![0u8; 32]);
        assert_eq!(events[1].prev_hash, events[0].hash);
        assert!(log.verify().expect("verify").is_none());
    }

    #[test]
    fn events_reject_update_and_delete() {
        let (_dir, log) = open_log();
        let record = sample_record("one");
        log.append(&record, &decision(Action::Block, "block", None))
            .expect("append");
        let updated = log.conn.execute("UPDATE events SET content = 'x'", []);
        let deleted = log.conn.execute("DELETE FROM events", []);
        assert!(updated.is_err());
        assert!(deleted.is_err());
        assert!(log.verify().expect("verify").is_none());
    }

    #[test]
    fn approve_and_reject_append_and_do_not_rewrite() {
        let (_dir, log) = open_log();
        let waiting = sample_record("hold");
        log.append(&waiting, &decision(Action::Quarantine, "default", None))
            .expect("append");
        let blocked = sample_record("nope");
        log.append(&blocked, &decision(Action::Block, "block", None))
            .expect("append");

        log.approve(waiting.id).expect("approve");
        let err = log.approve(waiting.id).expect_err("second approve");
        assert!(matches!(err, AuditError::NotQuarantined(_)));
        let err = log.reject(blocked.id).expect_err("reject block");
        assert!(matches!(err, AuditError::NotQuarantined(_)));
        let missing = Uuid::now_v7();
        assert!(matches!(
            log.approve(missing).expect_err("missing"),
            AuditError::NotQuarantined(_)
        ));

        let rejected = sample_record("later");
        log.append(&rejected, &decision(Action::Quarantine, "default", None))
            .expect("append");
        log.reject(rejected.id).expect("reject");

        let events = log.events().expect("events");
        assert_eq!(events.len(), 5);
        assert_eq!(events[2].rule_id, "approve");
        assert_eq!(events[2].action, "allow");
        assert_eq!(events[4].rule_id, "reject");
        assert_eq!(events[4].action, "block");
        assert_eq!(events[0].content, "hold");
        assert!(log.verify().expect("verify").is_none());
    }

    #[test]
    fn a_changed_byte_breaks_verify_on_that_event() {
        let (_dir, log) = open_log();
        let first = sample_record("alpha");
        let second = sample_record("beta");
        let first_id = log
            .append(&first, &decision(Action::Allow, "allow-user", None))
            .expect("append");
        log.append(&second, &decision(Action::Allow, "allow-user", None))
            .expect("append");
        log.conn
            .execute_batch("DROP TRIGGER IF EXISTS events_no_update;")
            .expect("drop");
        log.conn
            .execute(
                "UPDATE events SET content = 'alphb' WHERE id = ?1",
                params![first_id],
            )
            .expect("tamper");
        let broken = log.verify().expect("verify").expect("broken");
        assert_eq!(broken.event_id, first_id);
        assert_eq!(broken.reason, "hash mismatch");
    }

    #[test]
    fn policy_weight_round_trips_inside_the_chain() {
        let policy =
            Policy::from_yaml(include_str!("../../tests/fixtures/memlineage.yaml")).expect("yaml");
        let mut record = sample_record("the office opens at 09:00");
        record.namespace = vec!["facts".to_string()];
        record.provenance.taint = BTreeSet::from(["web".to_string()]);
        record.provenance.source_kind = SourceKind::Web;
        record.provenance.trust = TrustLevel::Untrusted;
        record.provenance.principal = "user-42".to_string();
        let decision = policy.check(&record, &Context::new("user-42", "s"));
        let (_dir, log) = open_log();
        log.append(&record, &decision).expect("append");
        assert!(log.verify().expect("verify").is_none());
        let events = log.events().expect("events");
        assert_eq!(events[0].retrieval_weight.as_deref(), Some("0.3"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn a_valid_chain_always_verifies(bodies in proptest::collection::vec("[a-z]{1,12}", 1..8)) {
            let (_dir, log) = open_log();
            for body in &bodies {
                let record = sample_record(body);
                log.append(&record, &decision(Action::Allow, "allow-user", None)).expect("append");
            }
            prop_assert!(log.verify().expect("verify").is_none());
        }

        #[test]
        fn one_byte_change_fails_verify(
            bodies in proptest::collection::vec("[a-z]{1,12}", 1..6),
            which in 0usize..6,
        ) {
            let (_dir, log) = open_log();
            let mut ids = Vec::new();
            for body in &bodies {
                let record = sample_record(body);
                ids.push(log.append(&record, &decision(Action::Quarantine, "default", None)).expect("append"));
            }
            let index = which % bodies.len();
            let target = ids[index];
            let mut tampered = bodies[index].clone();
            let bytes = bump_ascii(tampered.as_bytes());
            tampered = String::from_utf8(bytes).expect("utf8");
            log.conn.execute_batch("DROP TRIGGER IF EXISTS events_no_update;").expect("drop");
            log.conn.execute(
                "UPDATE events SET content = ?1 WHERE id = ?2",
                params![tampered, target],
            ).expect("tamper");
            let broken = log.verify().expect("verify").expect("broken");
            prop_assert!(broken.event_id <= target);
        }
    }

    fn bump_ascii(bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        if let Some(first) = out.first_mut() {
            *first = if *first == b'z' {
                b'a'
            } else {
                first.wrapping_add(1)
            };
        }
        out
    }
}
