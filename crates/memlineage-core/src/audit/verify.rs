use crate::audit::log::{chain_body_from_stored, AuditError, AuditLog};
use crate::hash::chain_hash;

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
        Ok(None)
    }
}
