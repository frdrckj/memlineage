use crate::audit::{AuditError, AuditLog, BrokenLink};
use crate::model::{Context, Decision, MemoryRecord};
use crate::policy::{fail_closed, Policy};
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
    pub fn approve(&self, id: Uuid) -> Result<(), AuditError> {
        self.log.approve(id)
    }

    /// Keep a quarantined record out.
    pub fn reject(&self, id: Uuid) -> Result<(), AuditError> {
        self.log.reject(id)
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

    fn decide(&self, record: &MemoryRecord, ctx: &Context) -> Decision {
        match &self.policy {
            LoadedPolicy::Ready(policy) => policy.check(record, ctx),
            LoadedPolicy::Closed => fail_closed(),
        }
    }
}
