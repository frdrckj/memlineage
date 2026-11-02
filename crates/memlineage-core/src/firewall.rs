use crate::audit::LogRecord;
use crate::audit::{AuditError, AuditLog, BrokenLink};
use crate::model::{Context, Decision, MemoryRecord, Provenance, Review};
use crate::policy::{fail_closed, Policy};
use crate::provenance::{build_provenance, ParentRef, SourceMark, TrustTable};
use std::path::Path;
use uuid::Uuid;

enum LoadedPolicy {
    Ready(Policy),
    Closed,
}

/// A policy tied to an audit log.
///
/// A policy file that does not parse still opens the log. Every write is then
/// quarantined with rule id `policy-error`.
pub struct Firewall {
    policy: LoadedPolicy,
    log: AuditLog,
}

impl Firewall {
    /// Open the log at `db_path` and load `policy_yaml`.
    pub fn open(policy_yaml: &str, db_path: &Path) -> Result<Self, AuditError> {
        let policy = match Policy::from_yaml(policy_yaml) {
            Ok(policy) => LoadedPolicy::Ready(policy),
            Err(_) => LoadedPolicy::Closed,
        };
        Ok(Self {
            policy,
            log: AuditLog::open(db_path)?,
        })
    }

    /// Decide and append the decision to the log.
    pub fn check_and_log(
        &self,
        record: &MemoryRecord,
        ctx: &Context,
    ) -> Result<Decision, AuditError> {
        let decision = self.decide(record, ctx);
        self.log.append(record, &decision)?;
        Ok(decision)
    }

    /// Release a quarantined record.
    pub fn approve(&self, id: Uuid, review: &Review) -> Result<(), AuditError> {
        self.log.approve(id, review)
    }

    /// Keep a quarantined record out.
    pub fn reject(&self, id: Uuid, review: &Review) -> Result<(), AuditError> {
        self.log.reject(id, review)
    }

    /// Records still held, when the quarantine row agrees with the log.
    pub fn pending(&self) -> Result<Vec<LogRecord>, AuditError> {
        self.log.pending()
    }

    /// Approved records for one store that have not been applied.
    pub fn released(&self, store: &str) -> Result<Vec<LogRecord>, AuditError> {
        self.log.released(store)
    }

    /// Record that the adapter wrote a released record into the store.
    pub fn mark_applied(&self, id: Uuid, store: &str) -> Result<(), AuditError> {
        self.log.mark_applied(id, store)
    }

    /// Apply `reads.hide` and `max_untrusted_per_query`.
    ///
    /// A broken policy file hides every record.
    pub fn filter_reads(&self, records: &[MemoryRecord], ctx: &Context) -> Vec<MemoryRecord> {
        match &self.policy {
            LoadedPolicy::Ready(policy) => policy.filter_reads(records, ctx),
            LoadedPolicy::Closed => Vec::new(),
        }
    }

    /// Walk the hash chain.
    pub fn verify(&self) -> Result<Option<BrokenLink>, AuditError> {
        self.log.verify()
    }

    /// Build provenance from the loaded trust map.
    ///
    /// A broken policy file uses an empty trust map, so missing keys stay
    /// `untrusted`. The write is still quarantined by `check_and_log`.
    pub fn provenance_for(
        &self,
        content: &str,
        source: Option<&SourceMark>,
        principal: &str,
        session_id: &str,
        parents: &[ParentRef],
    ) -> Provenance {
        self.with_trust(|table| {
            build_provenance(source, principal, session_id, parents, content, table)
        })
    }

    fn with_trust<T>(&self, use_table: impl FnOnce(&TrustTable) -> T) -> T {
        match &self.policy {
            LoadedPolicy::Ready(policy) => use_table(policy.trust()),
            LoadedPolicy::Closed => use_table(&TrustTable::default()),
        }
    }

    fn decide(&self, record: &MemoryRecord, ctx: &Context) -> Decision {
        match &self.policy {
            LoadedPolicy::Ready(policy) => policy.check(record, ctx),
            LoadedPolicy::Closed => fail_closed(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SourceKind;
    use crate::provenance::SourceMark;

    #[test]
    fn provenance_for_uses_the_policy_trust_map() {
        let dir = tempfile::tempdir().expect("tempdir");
        let firewall = Firewall::open(
            include_str!("../tests/fixtures/memlineage.yaml"),
            &dir.path().join("audit.db"),
        )
        .expect("open");
        let mark = SourceMark::web("https://example.test").with_extra_taint(["document"]);
        let provenance = firewall.provenance_for("page", Some(&mark), "user-42", "s", &[]);
        assert_eq!(provenance.source_kind, SourceKind::Web);
        assert_eq!(provenance.trust, crate::model::TrustLevel::Untrusted);
        assert!(provenance.taint.contains("web"));
        assert!(provenance.taint.contains("document"));
    }
}
