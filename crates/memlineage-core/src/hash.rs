use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Failure while building a canonical JSON string or a hash input.
#[derive(Debug, Error)]
pub enum HashError {
    /// `serde_json` rejected the value.
    #[error("json: {0}")]
    Json(String),
    /// JSON has no encoding for NaN or infinity.
    #[error("non-finite number")]
    NonFinite,
}

/// SHA-256 of the memory text, as UTF-8 bytes.
pub fn content_sha256(content: &str) -> [u8; 32] {
    digest_bytes(content.as_bytes())
}

/// JSON with sorted object keys and no extra whitespace.
///
/// The same value always produces the same string. Object key order in the
/// input does not change the result. Floats use `serde_json` number formatting.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<String, HashError> {
    let raw = serde_json::to_value(value).map_err(|err| HashError::Json(err.to_string()))?;
    let canon = canonicalize(raw)?;
    serde_json::to_string(&canon).map_err(|err| HashError::Json(err.to_string()))
}

/// `sha256(prev_hash || canonical_json)`.
pub fn chain_hash(prev: &[u8; 32], canonical: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(canonical.as_bytes());
    finalize(hasher)
}

fn canonicalize(value: Value) -> Result<Value, HashError> {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            let mut sorted = Map::new();
            for key in keys {
                let Some(child) = map.get(&key) else {
                    continue;
                };
                sorted.insert(key, canonicalize(child.clone())?);
            }
            Ok(Value::Object(sorted))
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(canonicalize(item)?);
            }
            Ok(Value::Array(out))
        }
        Value::Number(number) => {
            if let Some(float) = number.as_f64() {
                if !float.is_finite() {
                    return Err(HashError::NonFinite);
                }
            }
            Ok(Value::Number(number))
        }
        other => Ok(other),
    }
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    finalize(hasher)
}

fn finalize(hasher: Sha256) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn content_hash_matches_sha256_of_abc() {
        let hash = content_sha256("abc");
        let hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn content_hash_changes_when_the_text_changes() {
        assert_ne!(content_sha256("a"), content_sha256("b"));
    }

    #[test]
    fn canonical_json_is_stable_across_key_order() {
        let left = canonical_json(&json!({"b": 1, "a": {"d": 2, "c": 3}})).expect("json");
        let right = canonical_json(&json!({"a": {"c": 3, "d": 2}, "b": 1})).expect("json");
        assert_eq!(left, right);
        assert_eq!(left, r#"{"a":{"c":3,"d":2},"b":1}"#);
    }

    #[test]
    fn canonical_json_repeats() {
        let value = json!({"z": 0.3, "a": [1, 2]});
        let first = canonical_json(&value).expect("json");
        let second = canonical_json(&value).expect("json");
        assert_eq!(first, second);
        assert!(!first.contains(' '));
    }

    #[test]
    fn float_formatting_is_stable() {
        let value = json!({"w": 0.3, "n": 1.0});
        let first = canonical_json(&value).expect("json");
        let second = canonical_json(&value).expect("json");
        assert_eq!(first, second);
        assert_eq!(first, r#"{"n":1.0,"w":0.3}"#);
    }

    #[test]
    fn chain_hash_covers_prev_and_body() {
        let zeros = [0u8; 32];
        let body = r#"{"n":1}"#;
        let first = chain_hash(&zeros, body);
        let changed_body = chain_hash(&zeros, r#"{"n":2}"#);
        let changed_prev = chain_hash(&first, body);
        assert_ne!(first, changed_body);
        assert_ne!(first, changed_prev);
        assert_eq!(first, chain_hash(&zeros, body));
    }
}
