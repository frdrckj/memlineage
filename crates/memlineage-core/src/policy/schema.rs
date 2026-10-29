use crate::model::{Action, SourceKind};
use crate::provenance::{TrustAssign, TrustTable};
use serde::Deserialize;
use std::collections::BTreeMap;

/// A parsed policy.
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    pub(crate) default_action: Action,
    pub(crate) trust: TrustTable,
    pub(crate) rules: Vec<Rule>,
    pub(crate) reads: Reads,
}

/// One rule, already checked for unknown fields.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Rule {
    pub id: String,
    pub when: When,
    pub action: Action,
    pub retrieval_weight: Option<f32>,
}

/// Conditions inside one `when`. Every set field must hold.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct When {
    pub principal_mismatch: Option<bool>,
    pub taint_any: Option<Vec<String>>,
    pub namespace_prefix: Option<Vec<String>>,
    pub source_kind: Option<SourceKind>,
    pub content_matches: Option<ContentMatch>,
}

/// Matchers that look at the memory text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ContentMatch {
    Instruction,
}

/// Read-path limits from the policy file.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Reads {
    pub hide: Vec<Action>,
    pub max_untrusted_per_query: Option<u32>,
}

impl Policy {
    pub(crate) fn from_parts(
        default_action: Action,
        trust: BTreeMap<String, TrustAssign>,
        rules: Vec<Rule>,
        reads: Reads,
    ) -> Self {
        Self {
            default_action,
            trust: TrustTable::new(trust),
            rules,
            reads,
        }
    }

    /// Action used when no rule matches.
    pub fn default_action(&self) -> Action {
        self.default_action
    }

    /// Trust map used when a write is tagged.
    pub fn trust(&self) -> &TrustTable {
        &self.trust
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyFile {
    pub version: u32,
    pub default: Action,
    #[serde(default)]
    pub trust: BTreeMap<String, TrustAssign>,
    #[serde(default)]
    pub rules: Vec<RuleFile>,
    #[serde(default)]
    pub reads: ReadsFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleFile {
    pub id: String,
    pub when: WhenFile,
    pub action: Action,
    #[serde(default)]
    pub annotate: Option<AnnotateFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WhenFile {
    #[serde(default)]
    pub principal_mismatch: Option<bool>,
    #[serde(default)]
    pub taint_any: Option<Vec<String>>,
    #[serde(default)]
    pub namespace_prefix: Option<Vec<String>>,
    #[serde(default)]
    pub source_kind: Option<SourceKind>,
    #[serde(default)]
    pub content_matches: Option<ContentMatch>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnnotateFile {
    #[serde(default)]
    pub retrieval_weight: Option<f32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReadsFile {
    #[serde(default)]
    pub hide: Vec<Action>,
    #[serde(default)]
    pub max_untrusted_per_query: Option<u32>,
}
