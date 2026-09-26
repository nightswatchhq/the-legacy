//! The flat logs table, independent of its Parquet representation.

use thiserror::Error;

use crate::canonical::{encode_row, EncodingError, Value};
use crate::Hash32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRow {
    pub block_number: u64,
    pub transaction_index: u32,
    pub log_index: u32,
    pub transaction_hash: [u8; 32],
    pub address: [u8; 20],
    /// Zero to four topics; absent trailing columns become null, never zero hashes.
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LogError {
    #[error("log has {0} topics; at most four are allowed")]
    TooManyTopics(usize),
    #[error("logs must be strictly ordered by (block_number, transaction_index, log_index)")]
    OutOfOrder,
    #[error("log_index must increase within a block, including across transactions")]
    InvalidLogIndex,
    #[error(transparent)]
    Encoding(#[from] EncodingError),
}

impl LogRow {
    pub fn sort_key(&self) -> (u64, u32, u32) {
        (self.block_number, self.transaction_index, self.log_index)
    }

    pub fn validate(&self) -> Result<(), LogError> {
        if self.topics.len() > 4 {
            return Err(LogError::TooManyTopics(self.topics.len()));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LogError> {
        self.validate()?;
        let topic = |index: usize| {
            self.topics
                .get(index)
                .map_or(Value::Null, |v| Value::Fixed(v.as_slice()))
        };
        Ok(encode_row(&[
            Value::U64(self.block_number),
            Value::U32(self.transaction_index),
            Value::U32(self.log_index),
            Value::Fixed(&self.transaction_hash),
            Value::Fixed(&self.address),
            topic(0),
            topic(1),
            topic(2),
            topic(3),
            Value::Bytes(&self.data),
        ])?)
    }
}

/// Validate rather than sort: silently sorting would conceal a broken producer.
pub fn validate_rows(rows: &[LogRow]) -> Result<(), LogError> {
    for row in rows {
        row.validate()?;
    }
    for pair in rows.windows(2) {
        let (prev, next) = (&pair[0], &pair[1]);
        if prev.sort_key() >= next.sort_key() {
            return Err(LogError::OutOfOrder);
        }
        if prev.block_number == next.block_number && prev.log_index >= next.log_index {
            return Err(LogError::InvalidLogIndex);
        }
    }
    Ok(())
}

/// Hash canonical row bytes in schema sort order, with no Parquet framing or manifest metadata.
pub fn content_hash(rows: &[LogRow]) -> Result<Hash32, LogError> {
    validate_rows(rows)?;
    let mut hasher = blake3::Hasher::new();
    for row in rows {
        hasher.update(&row.canonical_bytes()?);
    }
    Ok(Hash32::new(*hasher.finalize().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> LogRow {
        LogRow {
            block_number: 1,
            transaction_index: 2,
            log_index: 3,
            transaction_hash: [0x11; 32],
            address: [0x22; 20],
            topics: vec![[0; 32]],
            data: vec![0xaa, 0xbb],
        }
    }

    #[test]
    fn log_vector_in_schema_order() {
        assert_eq!(
            content_hash(&[row()]).unwrap().to_hex(),
            "1a77818c3eb6c463d58910d9f901847abec90ed0d79a4a2c2d291ab6400b7a20"
        );
        assert_eq!(
            hex::encode(row().canonical_bytes().unwrap()),
            concat!(
                "010000000000000001",
                "0100000002",
                "0100000003",
                "011111111111111111111111111111111111111111111111111111111111111111",
                "012222222222222222222222222222222222222222",
                "010000000000000000000000000000000000000000000000000000000000000000",
                "000000",
                "010000000000000002aabb"
            )
        );
    }

    #[test]
    fn empty_table_has_the_blake3_empty_digest() {
        assert_eq!(
            content_hash(&[]).unwrap().to_hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn missing_and_zero_topics_have_different_identity() {
        let mut absent = row();
        absent.topics.clear();
        assert_ne!(
            content_hash(&[row()]).unwrap(),
            content_hash(&[absent]).unwrap()
        );
    }

    #[test]
    fn duplicates_disorder_and_non_block_level_indices_are_rejected() {
        let first = row();
        assert_eq!(
            content_hash(&[first.clone(), first.clone()]),
            Err(LogError::OutOfOrder)
        );
        let mut next = first.clone();
        next.transaction_index += 1;
        assert_eq!(
            content_hash(&[first.clone(), next.clone()]),
            Err(LogError::InvalidLogIndex)
        );
        next.log_index += 1;
        assert!(content_hash(&[first.clone(), next.clone()]).is_ok());
        assert_eq!(content_hash(&[next, first]), Err(LogError::OutOfOrder));
    }

    #[test]
    fn fifth_topic_is_rejected() {
        let mut row = row();
        row.topics = vec![[0; 32]; 5];
        assert_eq!(row.canonical_bytes(), Err(LogError::TooManyTopics(5)));
    }
}
