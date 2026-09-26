//! Schema-directed canonical row bytes (RFC-0001 §11.1).
//!
//! Types and field order come from the table schema, not from tags in the byte stream. Every
//! field has a presence byte, including required fields. Variable-width payloads have a u64
//! big-endian length, so null, empty, and adjacent byte strings cannot alias.

use thiserror::Error;

#[derive(Clone, Copy, Debug)]
pub enum Value<'a> {
    Null,
    Bool(bool),
    U8(u8),
    U32(u32),
    U64(u64),
    /// The caller must enforce the width declared by the table schema.
    Fixed(&'a [u8]),
    Bytes(&'a [u8]),
    /// Minimal big-endian magnitude; zero is the empty slice, never `[0]`.
    Uint256(&'a [u8]),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncodingError {
    #[error("uint256 must be at most 32 bytes with no leading zero")]
    InvalidUint256,
}

/// Encode one row. The caller supplies schema order, widths, and nullability.
pub fn encode_row(fields: &[Value<'_>]) -> Result<Vec<u8>, EncodingError> {
    let mut out = Vec::new();
    for field in fields {
        if matches!(field, Value::Null) {
            out.push(0);
            continue;
        }
        out.push(1);
        match field {
            Value::Null => unreachable!(),
            Value::Bool(value) => out.push(u8::from(*value)),
            Value::U8(value) => out.push(*value),
            Value::U32(value) => out.extend_from_slice(&value.to_be_bytes()),
            Value::U64(value) => out.extend_from_slice(&value.to_be_bytes()),
            Value::Fixed(value) => out.extend_from_slice(value),
            Value::Bytes(value) | Value::Uint256(value) => {
                if matches!(field, Value::Uint256(_))
                    && (value.len() > 32 || value.first() == Some(&0))
                {
                    return Err(EncodingError::InvalidUint256);
                }
                out.extend_from_slice(&(value.len() as u64).to_be_bytes());
                out.extend_from_slice(value);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_vector() {
        let bytes = encode_row(&[
            Value::Null,
            Value::Bool(false),
            Value::Bool(true),
            Value::U8(255),
            Value::U32(0x01020304),
            Value::U64(0x0102030405060708),
            Value::Fixed(&[0xaa, 0xbb]),
            Value::Bytes(&[]),
            Value::Bytes(&[0xcc, 0xdd]),
            Value::Uint256(&[]),
            Value::Uint256(&[0x80]),
        ])
        .unwrap();
        assert_eq!(
            hex::encode(bytes),
            concat!(
                "00",
                "0100",
                "0101",
                "01ff",
                "0101020304",
                "010102030405060708",
                "01aabb",
                "010000000000000000",
                "010000000000000002ccdd",
                "010000000000000000",
                "01000000000000000180"
            )
        );
    }

    #[test]
    fn variable_fields_cannot_alias() {
        assert_ne!(encode_row(&[Value::Null]), encode_row(&[Value::Bytes(&[])]));
        assert_ne!(
            encode_row(&[Value::Bytes(b"a"), Value::Bytes(b"bc")]),
            encode_row(&[Value::Bytes(b"ab"), Value::Bytes(b"c")])
        );
    }

    #[test]
    fn uint256_rejects_nonminimal_and_oversized_magnitudes() {
        for invalid in [&[0][..], &[0, 1], &[1; 33]] {
            assert_eq!(
                encode_row(&[Value::Uint256(invalid)]),
                Err(EncodingError::InvalidUint256)
            );
        }
        assert!(encode_row(&[Value::Uint256(&[255; 32])]).is_ok());
    }
}
