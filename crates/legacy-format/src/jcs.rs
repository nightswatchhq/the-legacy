//! Canonical JSON (RFC 8785, JCS).
//!
//! RFC-0001 §8.1 picks JSON for the manifest because it is universally tooled and a human can audit
//! it, and JCS because a hash over a document is meaningless unless the document has exactly one
//! byte encoding. Keys are sorted, whitespace is absent, strings use minimal escapes.
//!
//! **Conformant subset, stated plainly.** Full JCS serialises numbers with the ECMAScript
//! `Number::toString` algorithm, which covers doubles. The Legacy's documents contain only
//! integers - block numbers, byte sizes, row counts - so this implementation *rejects* any
//! non-integer number rather than quietly emitting something a strict JCS implementation would
//! disagree with. A canonicalisation that is wrong in one place is worse than one that refuses.
//!
//! Key ordering is by UTF-16 code unit, as JCS requires. For the ASCII keys this format actually
//! uses that is the same order as byte ordering, but getting it right costs nothing and stops the
//! day someone adds a non-ASCII key from being interesting.

use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JcsError {
    #[error("non-integer number {0} in a canonical document; see the subset note in jcs.rs")]
    NonIntegerNumber(String),

    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Canonicalise any serialisable value to JCS bytes.
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, JcsError> {
    let v = serde_json::to_value(value)?;
    Ok(to_canonical_string(&v)?.into_bytes())
}

/// Canonicalise an already-parsed `Value`.
pub fn to_canonical_string(value: &Value) -> Result<String, JcsError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<(), JcsError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => write_object(map, out)?,
    }
    Ok(())
}

fn write_object(map: &Map<String, Value>, out: &mut String) -> Result<(), JcsError> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by_key(|k| utf16_units(k));

    out.push('{');
    for (i, key) in keys.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_string(key, out);
        out.push(':');
        write_value(&map[key], out)?;
    }
    out.push('}');
    Ok(())
}

fn utf16_units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn write_number(n: &serde_json::Number, out: &mut String) -> Result<(), JcsError> {
    if let Some(u) = n.as_u64() {
        out.push_str(&u.to_string());
    } else if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
    } else {
        return Err(JcsError::NonIntegerNumber(n.to_string()));
    }
    Ok(())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_sorted_and_whitespace_is_gone() {
        let v = json!({ "zeta": 1, "alpha": { "b": 2, "a": 3 }, "Beta": 4 });
        // Capitals sort before lowercase, because the ordering is over code units and not over
        // anything as civilised as a locale.
        assert_eq!(
            to_canonical_string(&v).unwrap(),
            r#"{"Beta":4,"alpha":{"a":3,"b":2},"zeta":1}"#
        );
    }

    #[test]
    fn array_order_is_preserved() {
        let v = json!({ "files": [{ "b": 1, "a": 2 }, { "a": 3 }] });
        assert_eq!(
            to_canonical_string(&v).unwrap(),
            r#"{"files":[{"a":2,"b":1},{"a":3}]}"#
        );
    }

    #[test]
    fn strings_use_minimal_escapes() {
        let v = json!({ "s": "a\"b\\c\nd\u{1}e\u{00e9}" });
        assert_eq!(
            to_canonical_string(&v).unwrap(),
            "{\"s\":\"a\\\"b\\\\c\\nd\\u0001e\u{00e9}\"}"
        );
    }

    #[test]
    fn floats_are_refused_rather_than_guessed_at() {
        let v = json!({ "price": 0.1 });
        assert!(matches!(
            to_canonical_string(&v),
            Err(JcsError::NonIntegerNumber(_))
        ));
    }

    #[test]
    fn large_u64_survives_the_round_trip() {
        let v = json!({ "byte_size": u64::MAX });
        assert_eq!(
            to_canonical_string(&v).unwrap(),
            format!("{{\"byte_size\":{}}}", u64::MAX)
        );
    }

    #[test]
    fn two_spellings_of_one_document_canonicalise_identically() {
        let a: Value = serde_json::from_str(r#"{"b":  2,   "a": 1}"#).unwrap();
        let b: Value = serde_json::from_str("{\n  \"a\": 1,\n  \"b\": 2\n}").unwrap();
        assert_eq!(
            to_canonical_string(&a).unwrap(),
            to_canonical_string(&b).unwrap()
        );
    }
}
