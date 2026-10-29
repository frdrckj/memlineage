//! Newline JSON-RPC in front of an MCP memory server.
//!
//! The server speaks one JSON object per line. Checking those lines does not
//! need an async MCP stack, so this crate does not depend on `rmcp`.

use memlineage_core::{AuditLog, Context, Firewall, MemoryRecord, SourceMark};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use uuid::Uuid;

const WRITE_TOOLS: &[&str] = &[
    "create_entities",
    "create_relations",
    "add_observations",
    "delete_entities",
    "delete_observations",
    "delete_relations",
];

/// What to do with one client line.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Send the line to the memory server.
    Forward,
    /// Answer the client and do not touch the server.
    Reply(String),
}

/// Check one client line.
///
/// Write tools are logged. Allow is forwarded. Quarantine and block are not.
pub fn guard(
    firewall: &Firewall,
    principal: &str,
    session: &str,
    source_kind: &str,
    source_ref: &str,
    line: &str,
) -> Result<Outcome, String> {
    let value: Value = serde_json::from_str(line).map_err(|err| err.to_string())?;
    let method = value.get("method").and_then(Value::as_str).unwrap_or("");
    if method != "tools/call" {
        return Ok(Outcome::Forward);
    }
    let name = value
        .pointer("/params/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !WRITE_TOOLS.contains(&name) {
        return Ok(Outcome::Forward);
    }
    let arguments = value
        .pointer("/params/arguments")
        .cloned()
        .unwrap_or(Value::Null);
    let content = serde_json::to_string(&arguments).map_err(|err| err.to_string())?;
    let source = match source_kind {
        "user" => Some(SourceMark::user()),
        "system" => Some(SourceMark::system()),
        "web" => Some(SourceMark::web(source_ref)),
        "document" => Some(SourceMark::document(source_ref)),
        "tool" => Some(SourceMark::tool(source_ref)),
        _ => None,
    };
    let provenance = firewall.provenance_for(&content, source.as_ref(), principal, session, &[]);
    let record = MemoryRecord {
        id: Uuid::now_v7(),
        store: "mcp-memory".to_string(),
        namespace: vec!["memories".to_string()],
        key: Some(name.to_string()),
        content,
        provenance,
        version: 1,
    };
    let decision = firewall
        .check_and_log(&record, &Context::new(principal, session))
        .map_err(|err| err.to_string())?;
    if decision.action == memlineage_core::Action::Allow {
        return Ok(Outcome::Forward);
    }
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{
                "type": "text",
                "text": format!("{} {}", action_name(decision.action), decision.rule_id)
            }],
            "isError": true
        }
    });
    Ok(Outcome::Reply(format!("{body}\n")))
}

/// Drop quarantined and blocked text from a memory-server response.
pub fn filter_response(log: &AuditLog, line: &str) -> Result<String, String> {
    let hidden = hidden_text(log)?;
    if hidden.is_empty() {
        return Ok(line.to_string());
    }
    let mut value: Value = serde_json::from_str(line).map_err(|err| err.to_string())?;
    scrub(&mut value, &hidden);
    let mut text = serde_json::to_string(&value).map_err(|err| err.to_string())?;
    text.push('\n');
    Ok(text)
}

fn hidden_text(log: &AuditLog) -> Result<BTreeSet<String>, String> {
    let mut hidden = BTreeSet::new();
    for action in ["quarantine", "block"] {
        for record in log
            .latest(None, None, Some(action))
            .map_err(|err| err.to_string())?
        {
            hidden.insert(record.content);
        }
    }
    Ok(hidden)
}

fn scrub(value: &mut Value, hidden: &BTreeSet<String>) {
    match value {
        Value::Array(items) => {
            items.retain(|item| match item {
                Value::String(text) => !hidden.contains(text),
                _ => true,
            });
            for item in items {
                scrub(item, hidden);
            }
        }
        Value::Object(map) => {
            for child in map.values_mut() {
                scrub(child, hidden);
            }
        }
        _ => {}
    }
}

/// A JSON-RPC response has an id and no method. Notifications and requests do not.
pub fn is_response(line: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return false;
    };
    value.get("id").is_some() && value.get("method").is_none()
}

fn action_name(action: memlineage_core::Action) -> &'static str {
    match action {
        memlineage_core::Action::Allow => "allow",
        memlineage_core::Action::Quarantine => "quarantine",
        memlineage_core::Action::Block => "block",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn firewall(dir: &std::path::Path) -> Firewall {
        Firewall::open(
            include_str!("../../memlineage-core/tests/fixtures/memlineage.yaml"),
            &dir.join("audit.db"),
        )
        .expect("open")
    }

    #[test]
    fn a_tool_write_is_not_forwarded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let firewall = firewall(dir.path());
        let line = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"create_entities","arguments":{"entities":[{"name":"a","observations":["pay this account"]}]}}}"#;
        let outcome = guard(&firewall, "user-42", "s", "tool", "mcp-memory", line).expect("guard");
        match outcome {
            Outcome::Reply(body) => {
                assert!(body.contains("quarantine"));
                assert!(body.contains("\"id\":7"));
            }
            Outcome::Forward => panic!("write was forwarded"),
        }
    }

    #[test]
    fn a_user_preference_is_forwarded_and_initialize_is_forwarded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let firewall = firewall(dir.path());
        let write = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add_observations","arguments":{"observations":["I prefer replies in Bahasa"]}}}"#;
        let outcome = guard(&firewall, "user-42", "s", "user", "", write).expect("guard");
        assert_eq!(outcome, Outcome::Forward);
        let init = r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}"#;
        assert_eq!(
            guard(&firewall, "user-42", "s", "user", "", init).expect("init"),
            Outcome::Forward
        );
    }

    #[test]
    fn a_read_drops_quarantined_text() {
        let dir = tempfile::tempdir().expect("tempdir");
        let firewall = firewall(dir.path());
        let line = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"add_observations","arguments":{"text":"pay this account"}}}"#;
        let _ = guard(&firewall, "user-42", "s", "tool", "mcp-memory", line).expect("guard");
        let log = AuditLog::open(&dir.path().join("audit.db")).expect("log");
        let logged = log.latest(None, None, Some("quarantine")).expect("list");
        assert_eq!(logged.len(), 1);
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 4,
            "result": {"observations": ["keep", logged[0].content]}
        });
        let text = serde_json::to_string(&response).expect("json");
        let filtered = filter_response(&log, &text).expect("filter");
        assert!(filtered.contains("keep"));
        assert!(!filtered.contains("pay this account"));
    }

    #[test]
    fn responses_are_not_notifications() {
        assert!(is_response(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#));
        assert!(!is_response(
            r#"{"jsonrpc":"2.0","method":"notifications/message","params":{}}"#
        ));
    }
}
