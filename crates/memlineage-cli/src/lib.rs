use clap::{Parser, Subcommand};
use memlineage_core::{load_suite, run_suite, AuditLog, LogRecord};
use std::path::PathBuf;
use std::process::ExitCode;
use uuid::Uuid;

/// Inspect the memlineage audit log.
#[derive(Parser)]
#[command(name = "memlineage")]
struct Cli {
    /// Path to the audit database.
    #[arg(long, global = true, default_value = ".memlineage/audit.db")]
    db: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List the latest decision for each record.
    Ls {
        #[arg(long)]
        store: Option<String>,
        #[arg(long)]
        principal: Option<String>,
        #[arg(long)]
        decision: Option<String>,
    },
    /// Show one record, its provenance, and the rule that fired.
    Show { id: String },
    /// Changes at or after a timestamp, grouped by source.
    Diff {
        #[arg(long)]
        since: String,
    },
    /// List quarantined records, or approve or reject one.
    Review {
        #[command(subcommand)]
        action: Option<ReviewAction>,
    },
    /// Append rollback events for allowed writes after a time that carry a taint tag.
    Rollback {
        #[arg(long)]
        to: String,
        #[arg(long)]
        taint: String,
    },
    /// Records derived from this one.
    Trace { id: String },
    /// Walk the hash chain.
    Verify,
    /// Run a named attack suite.
    Attack {
        #[command(subcommand)]
        action: AttackCmd,
    },
}

#[derive(Subcommand)]
enum AttackCmd {
    /// Run the suite against one store name.
    Run {
        #[arg(long, default_value = "core")]
        suite: String,
        #[arg(long)]
        store: String,
        #[arg(long, default_value = "attacks/scenarios")]
        scenarios: PathBuf,
    },
}

#[derive(Subcommand)]
enum ReviewAction {
    /// Release a quarantined record.
    Approve { id: String },
    /// Keep a quarantined record out.
    Reject { id: String },
}

/// Run the command line and print the result.
pub fn run() -> ExitCode {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "memlineage".to_string());
    let rest: Vec<String> = args.collect();
    let mut full = Vec::with_capacity(rest.len() + 1);
    full.push(program);
    full.extend(rest);
    let borrowed: Vec<&str> = full.iter().map(String::as_str).collect();
    match execute(&borrowed) {
        Ok(text) => {
            if !text.is_empty() {
                print!("{text}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

/// Run one invocation and return the text it would print.
pub fn execute(args: &[&str]) -> Result<String, String> {
    let cli = Cli::try_parse_from(args).map_err(|err| err.to_string())?;
    let log = AuditLog::open(&cli.db).map_err(|err| err.to_string())?;
    match cli.command {
        Command::Ls {
            store,
            principal,
            decision,
        } => {
            let records = log
                .latest(store.as_deref(), principal.as_deref(), decision.as_deref())
                .map_err(|err| err.to_string())?;
            Ok(records.iter().map(format_row).collect())
        }
        Command::Show { id } => {
            let id = parse_id(&id)?;
            let Some(record) = log.show(id).map_err(|err| err.to_string())? else {
                return Err(format!("no record {id}"));
            };
            Ok(format_show(&record))
        }
        Command::Diff { since } => {
            let records = log.changed_since(&since).map_err(|err| err.to_string())?;
            Ok(format_diff(&records))
        }
        Command::Review { action } => match action {
            None => {
                let records = log.pending().map_err(|err| err.to_string())?;
                if records.is_empty() {
                    Ok("none\n".to_string())
                } else {
                    Ok(records.iter().map(format_review).collect())
                }
            }
            Some(ReviewAction::Approve { id }) => {
                log.approve(parse_id(&id)?).map_err(|err| err.to_string())?;
                Ok(format!("approved {id}\n"))
            }
            Some(ReviewAction::Reject { id }) => {
                log.reject(parse_id(&id)?).map_err(|err| err.to_string())?;
                Ok(format!("rejected {id}\n"))
            }
        },
        Command::Rollback { to, taint } => {
            let ids = log.rollback(&to, &taint).map_err(|err| err.to_string())?;
            if ids.is_empty() {
                Ok("none\n".to_string())
            } else {
                Ok(ids.iter().map(|id| format!("rolled back {id}\n")).collect())
            }
        }
        Command::Trace { id } => {
            let records = log.trace(parse_id(&id)?).map_err(|err| err.to_string())?;
            if records.is_empty() {
                Ok("none\n".to_string())
            } else {
                Ok(records.iter().map(format_row).collect())
            }
        }
        Command::Verify => match log.verify().map_err(|err| err.to_string())? {
            None => Ok("ok\n".to_string()),
            Some(broken) => Err(format!("broken {} {}", broken.event_id, broken.reason)),
        },
        Command::Attack { action } => match action {
            AttackCmd::Run {
                suite,
                store,
                scenarios,
            } => run_attack(&suite, &store, &scenarios),
        },
    }
}

fn run_attack(suite: &str, store: &str, scenarios: &std::path::Path) -> Result<String, String> {
    let loaded = load_suite(scenarios, suite).map_err(|err| err.to_string())?;
    let reports = run_suite(&loaded, store).map_err(|err| err.to_string())?;
    let mut text = String::new();
    let mut failed = 0usize;
    for report in &reports {
        let mark = if report.passed() { "ok" } else { "fail" };
        if !report.passed() {
            failed += 1;
        }
        text.push_str(&format!(
            "{} {} {} {} {}\n",
            report.id, report.store, report.expected, report.actual, mark
        ));
    }
    text.push_str(&format!("{} passed\n", reports.len() - failed));
    if failed > 0 {
        return Err(text);
    }
    Ok(text)
}

fn parse_id(text: &str) -> Result<Uuid, String> {
    Uuid::parse_str(text).map_err(|_| format!("invalid record id {text}"))
}

fn format_review(record: &LogRecord) -> String {
    format!(
        "{} {} {} {} {}\n",
        record.record_id,
        record.action,
        record.rule_id,
        record.provenance.source_ref,
        record.provenance.principal
    )
}

fn format_row(record: &LogRecord) -> String {
    let taint = record
        .provenance
        .taint
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{} {} {} {} {} {}\n",
        record.record_id,
        record.action,
        record.rule_id,
        record.store,
        record.provenance.principal,
        taint
    )
}

fn format_show(record: &LogRecord) -> String {
    let parents = record
        .provenance
        .parent_ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let taint = record
        .provenance
        .taint
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "id: {}\nstore: {}\nnamespace: {}\naction: {}\nrule: {}\nsource: {:?} {}\ntrust: {:?}\nprincipal: {}\nsession: {}\ntaint: {}\nparents: {}\ncontent:\n{}\n",
        record.record_id,
        record.store,
        record.namespace.join("/"),
        record.action,
        record.rule_id,
        record.provenance.source_kind,
        record.provenance.source_ref,
        record.provenance.trust,
        record.provenance.principal,
        record.provenance.session_id,
        taint,
        parents,
        record.content
    )
}

fn format_diff(records: &[LogRecord]) -> String {
    if records.is_empty() {
        return "none\n".to_string();
    }
    let mut lines = String::new();
    let mut current = String::new();
    let mut ordered = records.to_vec();
    ordered.sort_by(|left, right| {
        source_name(left)
            .cmp(&source_name(right))
            .then(left.created_at.cmp(&right.created_at))
    });
    for record in ordered {
        let source = source_name(&record);
        if source != current {
            lines.push_str(&source);
            lines.push('\n');
            current = source;
        }
        lines.push_str(&format!(
            "  {} {} {}\n",
            record.created_at, record.record_id, record.action
        ));
    }
    lines
}

fn source_name(record: &LogRecord) -> String {
    format!("{:?}", record.provenance.source_kind).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memlineage_core::{build_provenance, TrustTable};
    use memlineage_core::{Context, Firewall, MemoryRecord, SourceKind, SourceMark, TrustLevel};

    fn seed(dir: &std::path::Path) -> Uuid {
        let firewall = Firewall::open(
            include_str!("../../memlineage-core/tests/fixtures/memlineage.yaml"),
            &dir.join("audit.db"),
        )
        .expect("open");
        let mut record = MemoryRecord {
            id: uuid::Uuid::now_v7(),
            store: "mem0".to_string(),
            namespace: vec!["lessons".to_string()],
            key: None,
            content: "a phone number".to_string(),
            provenance: build_provenance(
                Some(&SourceMark::web("https://example.test")),
                "user-42",
                "s",
                &[],
                "a phone number",
                &TrustTable::default(),
            ),
            version: 1,
        };
        record.provenance.trust = TrustLevel::Untrusted;
        record.provenance.source_kind = SourceKind::Web;
        record.provenance.taint.insert("web".to_string());
        firewall
            .check_and_log(&record, &Context::new("user-42", "s"))
            .expect("log");
        record.id
    }

    #[test]
    fn ls_show_review_and_verify() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = seed(dir.path());
        let db = dir.path().join("audit.db");
        let db = db.to_str().expect("utf8");
        let listed =
            execute(&["memlineage", "--db", db, "ls", "--decision", "quarantine"]).expect("ls");
        assert!(listed.contains(&id.to_string()));
        assert!(listed.contains("quarantine"));

        let shown = execute(&["memlineage", "--db", db, "show", &id.to_string()]).expect("show");
        assert!(shown.contains("a phone number"));
        assert!(shown.contains("rule:"));

        let pending = execute(&["memlineage", "--db", db, "review"]).expect("review");
        assert!(pending.contains(&id.to_string()));
        let approved = execute(&[
            "memlineage",
            "--db",
            db,
            "review",
            "approve",
            &id.to_string(),
        ])
        .expect("approve");
        assert!(approved.contains("approved"));

        let verified = execute(&["memlineage", "--db", db, "verify"]).expect("verify");
        assert_eq!(verified, "ok\n");

        let pending = execute(&["memlineage", "--db", db, "review"]).expect("empty");
        assert_eq!(pending, "none\n");
    }

    #[test]
    fn attack_suite_passes_for_langgraph() {
        let scenarios =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../attacks/scenarios");
        let text = execute(&[
            "memlineage",
            "attack",
            "run",
            "--suite",
            "core",
            "--store",
            "langgraph",
            "--scenarios",
            scenarios.to_str().expect("utf8"),
        ])
        .expect("attack");
        assert!(text.contains("ML-010"));
        assert!(text.contains("10 passed"));
    }
}
