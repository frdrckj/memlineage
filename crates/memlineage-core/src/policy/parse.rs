use crate::policy::schema::{Policy, PolicyFile, Reads, Rule, When};
use thiserror::Error;

/// A policy file that could not be parsed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    /// YAML pointed at a line.
    #[error("policy yaml at line {line}, column {column}: {message}")]
    Located {
        line: usize,
        column: usize,
        message: String,
    },
    /// YAML failed without a location.
    #[error("policy yaml: {0}")]
    Yaml(String),
    /// `version` was not 1.
    #[error("unsupported policy version {0}")]
    Version(u32),
}

impl Policy {
    /// Parse a policy file. Unknown keys, actions, and matchers are errors.
    pub fn from_yaml(src: &str) -> Result<Self, PolicyError> {
        let file: PolicyFile = serde_norway::from_str(src).map_err(locate)?;
        if file.version != 1 {
            return Err(PolicyError::Version(file.version));
        }
        let rules = file
            .rules
            .into_iter()
            .map(|rule| Rule {
                id: rule.id,
                when: When {
                    principal_mismatch: rule.when.principal_mismatch,
                    taint_any: rule.when.taint_any,
                    namespace_prefix: rule.when.namespace_prefix,
                    source_kind: rule.when.source_kind,
                    content_matches: rule.when.content_matches,
                },
                action: rule.action,
                retrieval_weight: rule.annotate.and_then(|note| note.retrieval_weight),
            })
            .collect();
        Ok(Self::from_parts(
            file.default,
            file.trust,
            rules,
            Reads {
                hide: file.reads.hide,
                max_untrusted_per_query: file.reads.max_untrusted_per_query,
            },
        ))
    }
}

fn locate(err: serde_norway::Error) -> PolicyError {
    let message = err.to_string();
    match err.location() {
        Some(location) => PolicyError::Located {
            line: location.line(),
            column: location.column(),
            message,
        },
        None => PolicyError::Yaml(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Action;
    use crate::provenance::TrustAssign;
    use crate::TrustLevel;

    const SAMPLE: &str = r#"
version: 1
default: quarantine
trust:
  user: trusted
  system: trusted
  tool:browser: untrusted
  tool:email_read: untrusted
  document: untrusted
  agent: inherit
rules:
  - id: block-cross-principal
    when: { principal_mismatch: true }
    action: block
  - id: allow-untrusted-facts-low-weight
    when: { taint_any: [web], namespace_prefix: [facts] }
    action: allow
    annotate: { retrieval_weight: 0.3 }
reads:
  hide: [quarantine, block]
  max_untrusted_per_query: 2
"#;

    #[test]
    fn sample_policy_parses() {
        let policy = Policy::from_yaml(SAMPLE).expect("policy");
        assert_eq!(policy.default_action(), Action::Quarantine);
        assert_eq!(
            policy.trust().get("user"),
            Some(TrustAssign::Level(TrustLevel::Trusted))
        );
        assert_eq!(policy.trust().get("agent"), Some(TrustAssign::Inherit));
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.rules[1].retrieval_weight, Some(0.3));
        assert_eq!(policy.reads.hide, vec![Action::Quarantine, Action::Block]);
        assert_eq!(policy.reads.max_untrusted_per_query, Some(2));
    }

    #[test]
    fn version_other_than_one_is_an_error() {
        let err = Policy::from_yaml("version: 2\ndefault: allow\n").expect_err("version");
        assert_eq!(err, PolicyError::Version(2));
    }

    #[test]
    fn unknown_key_is_an_error() {
        let err = Policy::from_yaml("version: 1\ndefault: allow\nextra: 1\n").expect_err("key");
        let PolicyError::Located { line, message, .. } = err else {
            panic!("expected a located error, got {err}");
        };
        assert!(line >= 1);
        assert!(message.contains("unknown field"));
    }

    #[test]
    fn unknown_action_is_an_error() {
        let src = "version: 1\ndefault: drop\n";
        let err = Policy::from_yaml(src).expect_err("action");
        assert!(matches!(err, PolicyError::Located { .. }));
    }

    #[test]
    fn unknown_matcher_is_an_error() {
        let src = r#"
version: 1
default: quarantine
rules:
  - id: bad
    when: { mood: calm }
    action: allow
"#;
        let err = Policy::from_yaml(src).expect_err("matcher");
        assert!(matches!(err, PolicyError::Located { .. }));
    }

    #[test]
    fn unknown_trust_word_is_an_error() {
        let src = "version: 1\ndefault: allow\ntrust:\n  user: friend\n";
        let err = Policy::from_yaml(src).expect_err("trust");
        assert!(matches!(err, PolicyError::Located { .. }));
    }

    #[test]
    fn broken_yaml_reports_a_line() {
        let err = Policy::from_yaml("@\n").expect_err("yaml");
        let PolicyError::Located { line, column, .. } = err else {
            panic!("expected a located error, got {err}");
        };
        assert_eq!(line, 1);
        assert_eq!(column, 1);
    }
}
