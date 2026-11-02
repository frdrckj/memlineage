use crate::audit::log::{
    chain_body_from_stored, expected_status, status_needs_row, AuditError, AuditLog,
};
use crate::hash::chain_hash;
use std::collections::BTreeMap;

/// The first event whose hash or previous-hash link does not check out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokenLink {
    pub event_id: i64,
    pub reason: String,
}

impl AuditLog {
    /// Walk the chain from the first event. `Ok(None)` means the chain holds.
    pub fn verify(&self) -> Result<Option<BrokenLink>, AuditError> {
        let events = self.events()?;
        let mut previous = [0u8; 32];
        for event in events {
            if event.prev_hash.as_slice() != previous {
                return Ok(Some(BrokenLink {
                    event_id: event.id,
                    reason: "prev_hash mismatch".to_string(),
                }));
            }
            let Ok(body) = chain_body_from_stored(&event) else {
                return Ok(Some(BrokenLink {
                    event_id: event.id,
                    reason: "stored event is not valid json".to_string(),
                }));
            };
            let digest = chain_hash(&previous, &body);
            if event.hash.as_slice() != digest {
                return Ok(Some(BrokenLink {
                    event_id: event.id,
                    reason: "hash mismatch".to_string(),
                }));
            }
            previous = digest;
        }
        self.quarantine_drift()
    }

    fn quarantine_drift(&self) -> Result<Option<BrokenLink>, AuditError> {
        let mut rows = BTreeMap::new();
        let mut stmt = self
            .conn
            .prepare("SELECT record_id, status, event_id FROM quarantine")?;
        let mapped = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in mapped {
            let (record_id, status, event_id) = row?;
            rows.insert(record_id, (status, event_id));
        }
        for record in self.latest(None, None, None)? {
            let key = record.record_id.to_string();
            let expected = expected_status(&record.action, &record.rule_id);
            match rows.remove(&key) {
                Some((status, event_id)) => {
                    if status != expected || event_id != record.event_id {
                        return Ok(Some(BrokenLink {
                            event_id,
                            reason: "quarantine row does not match events".to_string(),
                        }));
                    }
                }
                None if status_needs_row(&record.action, &record.rule_id) => {
                    return Ok(Some(BrokenLink {
                        event_id: record.event_id,
                        reason: "quarantine row does not match events".to_string(),
                    }));
                }
                None => {}
            }
        }
        if let Some((_, event_id)) = rows.into_values().next() {
            return Ok(Some(BrokenLink {
                event_id,
                reason: "quarantine row does not match events".to_string(),
            }));
        }
        Ok(None)
    }
}
