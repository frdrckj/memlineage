//! Named attack scenarios. The files live in `attacks/scenarios/`.

use crate::model::{Action, Context, Decision, MemoryRecord};
use crate::provenance::{ParentRef, SourceMark};
use crate::{AuditLog, Firewall};
use rusqlite::params;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

const POLICY: &str = include_str!("../tests/fixtures/memlineage.yaml");

/// One scenario file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    pub title: String,
    pub suite: String,
    pub kind: ScenarioKind,
    pub input: String,
    pub source: ScenarioSource,
    #[serde(default = "default_namespace")]
    pub namespace: Vec<String>,
    #[serde(default = "default_principal")]
    pub principal: String,
    #[serde(default)]
    pub reader: Option<String>,
    #[serde(default = "default_session")]
    pub session: String,
    #[serde(default)]
    pub parent: Option<ScenarioParent>,
    pub expected: String,
}

/// How the runner applies the scenario.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioKind {
    Write,
    Read,
    Derive,
    Tamper,
}

/// Source block for a scenario.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioSource {
    pub kind: String,
    #[serde(default)]
    pub r#ref: String,
}

/// A parent write whose taint the child must keep.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioParent {
    pub input: String,
    pub source: ScenarioSource,
    pub namespace: Vec<String>,
}

/// Result of running one scenario against one store name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioReport {
    pub id: String,
    pub title: String,
    pub store: String,
    pub expected: String,
    pub actual: String,
}

impl ScenarioReport {
    /// Whether the actual decision matches the file.
    pub fn passed(&self) -> bool {
        self.actual == self.expected
    }
}

/// A scenario file or a run failed.
#[derive(Debug, Error)]
pub enum AttackError {
    /// The directory or a file could not be read.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// YAML did not match the scenario schema.
    #[error("scenario yaml: {0}")]
    Yaml(String),
    /// The firewall or the log returned an error.
    #[error("{0}")]
    Run(String),
}

/// Load `suite` from YAML files in `dir`, sorted by id.
pub fn load_suite(dir: &Path, suite: &str) -> Result<Vec<Scenario>, AttackError> {
    let mut scenarios = Vec::new();
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)?
        .map(|entry| entry.map(|item| item.path()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    for path in paths {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.ends_with(".yaml") {
            continue;
        }
        let text = fs::read_to_string(&path)?;
        let scenario: Scenario =
            serde_norway::from_str(&text).map_err(|err| AttackError::Yaml(err.to_string()))?;
        if scenario.suite == suite {
            scenarios.push(scenario);
        }
    }
    Ok(scenarios)
}

/// Run every scenario in its own database.
pub fn run_suite(scenarios: &[Scenario], store: &str) -> Result<Vec<ScenarioReport>, AttackError> {
    scenarios
        .iter()
        .map(|scenario| run_scenario(scenario, store))
        .collect()
}

/// Run one scenario with the built-in sample policy.
pub fn run_scenario(scenario: &Scenario, store: &str) -> Result<ScenarioReport, AttackError> {
    let dir = std::env::temp_dir().join(format!("memlineage-{}", Uuid::now_v7()));
    fs::create_dir_all(&dir)?;
    let db = dir.join("audit.db");
    let report = run_in(&db, scenario, store);
    let _ = fs::remove_dir_all(&dir);
    report
}

fn run_in(db: &Path, scenario: &Scenario, store: &str) -> Result<ScenarioReport, AttackError> {
    let firewall = Firewall::open(POLICY, db).map_err(|err| AttackError::Run(err.to_string()))?;
    let actual = match scenario.kind {
        ScenarioKind::Tamper => tamper(&firewall, scenario, store, db)?,
        ScenarioKind::Derive => derive(&firewall, scenario, store)?,
        ScenarioKind::Write | ScenarioKind::Read => {
            action_name(decide(&firewall, scenario, store)?).to_string()
        }
    };
    Ok(ScenarioReport {
        id: scenario.id.clone(),
        title: scenario.title.clone(),
        store: store.to_string(),
        expected: scenario.expected.clone(),
        actual,
    })
}

fn decide(firewall: &Firewall, scenario: &Scenario, store: &str) -> Result<Decision, AttackError> {
    let record = memory(
        firewall,
        scenario,
        store,
        &scenario.input,
        &scenario.source,
        None,
    )?;
    let reader = scenario.reader.as_deref().unwrap_or(&scenario.principal);
    firewall
        .check_and_log(&record, &Context::new(reader, &scenario.session))
        .map_err(|err| AttackError::Run(err.to_string()))
}

fn derive(firewall: &Firewall, scenario: &Scenario, store: &str) -> Result<String, AttackError> {
    let parent = scenario
        .parent
        .as_ref()
        .ok_or_else(|| AttackError::Run(format!("{} needs a parent", scenario.id)))?;
    let parent_record = memory(
        firewall,
        scenario,
        store,
        &parent.input,
        &parent.source,
        Some(&parent.namespace),
    )?;
    firewall
        .check_and_log(
            &parent_record,
            &Context::new(&scenario.principal, &scenario.session),
        )
        .map_err(|err| AttackError::Run(err.to_string()))?;
    let child_source = source_mark(&scenario.source)?;
    let provenance = firewall.provenance_for(
        &scenario.input,
        child_source.as_ref(),
        &scenario.principal,
        &scenario.session,
        &[ParentRef {
            id: parent_record.id,
            provenance: parent_record.provenance.clone(),
        }],
    );
    let child = MemoryRecord {
        id: Uuid::now_v7(),
        store: store.to_string(),
        namespace: scenario.namespace.clone(),
        key: None,
        content: scenario.input.clone(),
        provenance,
        version: 1,
    };
    let decision = firewall
        .check_and_log(
            &child,
            &Context::new(&scenario.principal, &scenario.session),
        )
        .map_err(|err| AttackError::Run(err.to_string()))?;
    Ok(action_name(decision).to_string())
}

fn tamper(
    firewall: &Firewall,
    scenario: &Scenario,
    store: &str,
    db: &Path,
) -> Result<String, AttackError> {
    let record = memory(
        firewall,
        scenario,
        store,
        &scenario.input,
        &scenario.source,
        None,
    )?;
    firewall
        .check_and_log(
            &record,
            &Context::new(&scenario.principal, &scenario.session),
        )
        .map_err(|err| AttackError::Run(err.to_string()))?;
    let log = AuditLog::open(db).map_err(|err| AttackError::Run(err.to_string()))?;
    log.conn
        .execute_batch("DROP TRIGGER IF EXISTS events_no_update;")
        .map_err(|err| AttackError::Run(err.to_string()))?;
    let content: String = log
        .conn
        .query_row(
            "SELECT content FROM events ORDER BY id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .map_err(|err| AttackError::Run(err.to_string()))?;
    let mut bytes = content.into_bytes();
    if let Some(byte) = bytes.first_mut() {
        *byte = if *byte == b'z' {
            b'a'
        } else {
            byte.wrapping_add(1)
        };
    }
    let edited = String::from_utf8(bytes).map_err(|err| AttackError::Run(err.to_string()))?;
    log.conn
        .execute(
            "UPDATE events SET content = ?1 WHERE id = (SELECT MIN(id) FROM events)",
            params![edited],
        )
        .map_err(|err| AttackError::Run(err.to_string()))?;
    match log
        .verify()
        .map_err(|err| AttackError::Run(err.to_string()))?
    {
        Some(_) => Ok("hash_mismatch".to_string()),
        None => Ok("ok".to_string()),
    }
}

fn memory(
    firewall: &Firewall,
    scenario: &Scenario,
    store: &str,
    input: &str,
    source: &ScenarioSource,
    namespace: Option<&[String]>,
) -> Result<MemoryRecord, AttackError> {
    let mark = source_mark(source)?;
    let provenance = firewall.provenance_for(
        input,
        mark.as_ref(),
        &scenario.principal,
        &scenario.session,
        &[],
    );
    Ok(MemoryRecord {
        id: Uuid::now_v7(),
        store: store.to_string(),
        namespace: namespace
            .map(|items| items.to_vec())
            .unwrap_or_else(|| scenario.namespace.clone()),
        key: None,
        content: input.to_string(),
        provenance,
        version: 1,
    })
}

fn source_mark(source: &ScenarioSource) -> Result<Option<SourceMark>, AttackError> {
    let mark = match source.kind.as_str() {
        "user" => SourceMark::user(),
        "system" => SourceMark::system(),
        "web" => SourceMark::web(&source.r#ref),
        "document" => SourceMark::document(&source.r#ref),
        "tool" => SourceMark::tool(&source.r#ref),
        "agent" => SourceMark::agent(),
        "unknown" => return Ok(None),
        other => return Err(AttackError::Run(format!("unknown source {other}"))),
    };
    Ok(Some(mark))
}

fn action_name(decision: Decision) -> &'static str {
    match decision.action {
        Action::Allow => "allow",
        Action::Quarantine => "quarantine",
        Action::Block => "block",
    }
}

fn default_namespace() -> Vec<String> {
    vec!["memories".to_string()]
}

fn default_principal() -> String {
    "user-42".to_string()
}

fn default_session() -> String {
    "s-1".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suite_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../attacks/scenarios")
    }

    #[test]
    fn core_suite_passes_for_each_store() {
        let scenarios = load_suite(&suite_dir(), "core").expect("suite");
        assert_eq!(scenarios.len(), 10);
        for store in ["mem0", "langgraph", "mcp-memory"] {
            let reports = run_suite(&scenarios, store).expect("run");
            let failed: Vec<_> = reports.iter().filter(|report| !report.passed()).collect();
            assert!(failed.is_empty(), "{store} failed: {failed:?}");
        }
    }
}
