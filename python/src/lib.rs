use memlineage_core::{
    content_sha256, Action, AuditError, Context, Firewall as CoreFirewall, MemoryRecord, ParentRef,
    Provenance, SourceKind, SourceMark, TrustLevel,
};
use pyo3::exceptions::{PyFileNotFoundError, PyOSError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use uuid::Uuid;

pyo3::create_exception!(_core, MemlineageError, PyRuntimeError);

/// One policy decision.
#[pyclass]
#[derive(Clone)]
struct Decision {
    #[pyo3(get)]
    action: String,
    #[pyo3(get)]
    rule_id: String,
    #[pyo3(get)]
    retrieval_weight: Option<f32>,
}

#[pymethods]
impl Decision {
    fn __repr__(&self) -> String {
        format!(
            "Decision(action={:?}, rule_id={:?}, retrieval_weight={:?})",
            self.action, self.rule_id, self.retrieval_weight
        )
    }
}

/// The core firewall. Context blocks live on the Python wrapper.
#[pyclass(unsendable)]
struct Firewall {
    inner: CoreFirewall,
}

#[pymethods]
impl Firewall {
    /// Load a policy file and open `.memlineage/audit.db` in the working directory.
    ///
    /// A policy file that does not parse still opens. Later checks quarantine.
    #[staticmethod]
    fn from_file(path: &str) -> PyResult<Self> {
        let yaml = fs::read_to_string(path).map_err(io_error)?;
        let db = PathBuf::from(".memlineage").join("audit.db");
        let inner = CoreFirewall::open(&yaml, &db).map_err(audit_error)?;
        Ok(Self { inner })
    }

    /// Check a record and append the decision.
    ///
    /// Pass `provenance` to use it as given. Otherwise the `_source_*` and
    /// `_extra_taint` fields, filled by the Python context, build it.
    fn check(&self, record: &Bound<'_, PyDict>) -> PyResult<Decision> {
        let memory = memory_from_dict(&self.inner, record)?;
        let ctx = Context::new(
            dict_string(record, "_principal")?,
            dict_string(record, "_session")?,
        );
        let decision = self
            .inner
            .check_and_log(&memory, &ctx)
            .map_err(audit_error)?;
        Ok(Decision::from_core(decision))
    }

    /// Release a quarantined record.
    fn approve(&self, id: &str) -> PyResult<()> {
        self.inner.approve(parse_id(id)?).map_err(audit_error)
    }

    /// Keep a quarantined record out.
    fn reject(&self, id: &str) -> PyResult<()> {
        self.inner.reject(parse_id(id)?).map_err(audit_error)
    }
}

impl Decision {
    fn from_core(decision: memlineage_core::Decision) -> Self {
        Self {
            action: action_name(decision.action).to_string(),
            rule_id: decision.rule_id,
            retrieval_weight: decision.retrieval_weight,
        }
    }
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Firewall>()?;
    m.add_class::<Decision>()?;
    m.add("MemlineageError", m.py().get_type::<MemlineageError>())?;
    Ok(())
}

fn memory_from_dict(firewall: &CoreFirewall, record: &Bound<'_, PyDict>) -> PyResult<MemoryRecord> {
    let content = required_string(record, "content")?;
    let store = dict_string(record, "store")?;
    let namespace = string_list(record, "namespace")?;
    let key = optional_string(record, "key")?;
    let version = optional_u32(record, "version")?.unwrap_or(1);
    let id = match optional_string(record, "id")? {
        Some(text) => parse_id(&text)?,
        None => Uuid::now_v7(),
    };
    let provenance = match record.get_item("provenance")? {
        Some(value) if !value.is_none() => {
            let dict = value
                .cast::<PyDict>()
                .map_err(|_| PyValueError::new_err("provenance must be a dict"))?;
            provenance_from_dict(dict, &content)?
        }
        _ => {
            let kind = dict_string(record, "_source_kind")?;
            let source_ref = dict_string(record, "_source_ref")?;
            let extra = string_list(record, "_extra_taint")?;
            let principal = dict_string(record, "_principal")?;
            let session = dict_string(record, "_session")?;
            let parents = parents_from_dict(record)?;
            let source = source_mark(&kind, &source_ref, extra)?;
            firewall.provenance_for(&content, source.as_ref(), &principal, &session, &parents)
        }
    };
    Ok(MemoryRecord {
        id,
        store,
        namespace,
        key,
        content,
        provenance,
        version,
    })
}

fn provenance_from_dict(dict: &Bound<'_, PyDict>, content: &str) -> PyResult<Provenance> {
    let source_kind = parse_kind(&required_string(dict, "source_kind")?)?;
    let trust = parse_trust(&required_string(dict, "trust")?)?;
    let parent_ids = uuid_list(dict, "parent_ids")?;
    let taint = string_list(dict, "taint")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let hash = match dict.get_item("content_sha256")? {
        Some(value) if !value.is_none() => hash_from_list(&value)?,
        _ => content_sha256(content),
    };
    Ok(Provenance {
        source_kind,
        source_ref: dict_string(dict, "source_ref")?,
        trust,
        principal: dict_string(dict, "principal")?,
        session_id: dict_string(dict, "session_id")?,
        parent_ids,
        content_sha256: hash,
        taint,
    })
}

fn parents_from_dict(record: &Bound<'_, PyDict>) -> PyResult<Vec<ParentRef>> {
    let Some(value) = record.get_item("parents")? else {
        return Ok(Vec::new());
    };
    if value.is_none() {
        return Ok(Vec::new());
    }
    let list = value
        .cast::<PyList>()
        .map_err(|_| PyValueError::new_err("parents must be a list"))?;
    let mut parents = Vec::new();
    for item in list.iter() {
        let dict = item
            .cast::<PyDict>()
            .map_err(|_| PyValueError::new_err("each parent must be a dict"))?;
        let id = parse_id(&required_string(dict, "id")?)?;
        let provenance_value = dict
            .get_item("provenance")?
            .ok_or_else(|| PyValueError::new_err("parent provenance is required"))?;
        let provenance_dict = provenance_value
            .cast::<PyDict>()
            .map_err(|_| PyValueError::new_err("parent provenance must be a dict"))?;
        let parent_content = optional_string(dict, "content")?.unwrap_or_default();
        parents.push(ParentRef {
            id,
            provenance: provenance_from_dict(provenance_dict, &parent_content)?,
        });
    }
    Ok(parents)
}

fn source_mark(kind: &str, source_ref: &str, extra: Vec<String>) -> PyResult<Option<SourceMark>> {
    if kind.is_empty() || kind == "unknown" {
        return Ok(None);
    }
    let parsed = parse_kind(kind)?;
    let mark = match parsed {
        SourceKind::User => SourceMark::user(),
        SourceKind::System => SourceMark::system(),
        SourceKind::Web => SourceMark::web(source_ref),
        SourceKind::Document => SourceMark::document(source_ref),
        SourceKind::Tool => SourceMark::tool(source_ref),
        SourceKind::Agent => SourceMark::agent(),
        SourceKind::Unknown => return Ok(None),
    };
    Ok(Some(mark.with_extra_taint(extra)))
}

fn parse_kind(text: &str) -> PyResult<SourceKind> {
    serde_json::from_value(Value::String(text.to_string()))
        .map_err(|_| PyValueError::new_err(format!("unknown source kind {text}")))
}

fn parse_trust(text: &str) -> PyResult<TrustLevel> {
    serde_json::from_value(Value::String(text.to_string()))
        .map_err(|_| PyValueError::new_err(format!("unknown trust {text}")))
}

fn parse_id(text: &str) -> PyResult<Uuid> {
    Uuid::parse_str(text).map_err(|_| PyValueError::new_err(format!("invalid record id {text}")))
}

fn hash_from_list(value: &Bound<'_, PyAny>) -> PyResult<[u8; 32]> {
    let numbers: Vec<u16> = value.extract()?;
    if numbers.len() != 32 {
        return Err(PyValueError::new_err("content_sha256 must be 32 bytes"));
    }
    let mut hash = [0u8; 32];
    for (slot, number) in hash.iter_mut().zip(numbers) {
        *slot = u8::try_from(number)
            .map_err(|_| PyValueError::new_err("content_sha256 must be 32 bytes"))?;
    }
    Ok(hash)
}

fn required_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<String> {
    match optional_string(dict, key)? {
        Some(text) => Ok(text),
        None => Err(PyValueError::new_err(format!("{key} is required"))),
    }
}

fn optional_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    match dict.get_item(key)? {
        Some(value) if value.is_none() => Ok(None),
        Some(value) => Ok(Some(value.extract()?)),
        None => Ok(None),
    }
}

fn dict_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<String> {
    Ok(optional_string(dict, key)?.unwrap_or_default())
}

fn string_list(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<String>> {
    match dict.get_item(key)? {
        Some(value) if value.is_none() => Ok(Vec::new()),
        Some(value) => Ok(value.extract()?),
        None => Ok(Vec::new()),
    }
}

fn uuid_list(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<Uuid>> {
    string_list(dict, key)?
        .iter()
        .map(|text| parse_id(text))
        .collect()
}

fn optional_u32(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u32>> {
    match dict.get_item(key)? {
        Some(value) if value.is_none() => Ok(None),
        Some(value) => Ok(Some(value.extract()?)),
        None => Ok(None),
    }
}

fn action_name(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Quarantine => "quarantine",
        Action::Block => "block",
    }
}

fn io_error(err: std::io::Error) -> PyErr {
    if err.kind() == ErrorKind::NotFound {
        PyFileNotFoundError::new_err(err.to_string())
    } else {
        PyOSError::new_err(err.to_string())
    }
}

fn audit_error(err: AuditError) -> PyErr {
    match err {
        AuditError::NotQuarantined(id) => {
            MemlineageError::new_err(format!("record {id} is not quarantined"))
        }
        other => MemlineageError::new_err(other.to_string()),
    }
}
