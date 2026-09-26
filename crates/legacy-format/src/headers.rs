//! Header rows and their stored linkage. These checks do not reconstruct RLP or Keccak hashes.

use thiserror::Error;

use crate::canonical::{encode_row, EncodingError, Value};
use crate::{BlockRange, Boundary, Hash32};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderRow {
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub ommers_hash: [u8; 32],
    pub beneficiary: [u8; 20],
    pub state_root: [u8; 32],
    pub transactions_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub logs_bloom: [u8; 256],
    pub difficulty: Vec<u8>,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash: [u8; 32],
    pub nonce: [u8; 8],
    pub base_fee_per_gas: Option<Vec<u8>>,
    pub withdrawals_root: Option<[u8; 32]>,
    pub blob_gas_used: Option<u64>,
    pub excess_blob_gas: Option<u64>,
    pub parent_beacon_block_root: Option<[u8; 32]>,
    pub requests_hash: Option<[u8; 32]>,
    pub total_difficulty: Option<Vec<u8>>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HeaderError {
    #[error("headers must be strictly ordered by block_number")]
    OutOfOrder,
    #[error("headers must cover every block in the relic range exactly once")]
    IncompleteCoverage,
    #[error("stored header parent link is broken at block {0}")]
    StoredLinkage(u64),
    #[error("stored header hashes do not match the manifest boundary")]
    Boundary,
    #[error(transparent)]
    Encoding(#[from] EncodingError),
}

impl HeaderRow {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HeaderError> {
        fn hash(value: &Option<[u8; 32]>) -> Value<'_> {
            value.as_ref().map_or(Value::Null, |v| Value::Fixed(v))
        }
        fn uint256(value: &Option<Vec<u8>>) -> Value<'_> {
            value.as_deref().map_or(Value::Null, Value::Uint256)
        }
        Ok(encode_row(&[
            Value::U64(self.block_number),
            Value::Fixed(&self.block_hash),
            Value::Fixed(&self.parent_hash),
            Value::Fixed(&self.ommers_hash),
            Value::Fixed(&self.beneficiary),
            Value::Fixed(&self.state_root),
            Value::Fixed(&self.transactions_root),
            Value::Fixed(&self.receipts_root),
            Value::Fixed(&self.logs_bloom),
            Value::Uint256(&self.difficulty),
            Value::U64(self.gas_limit),
            Value::U64(self.gas_used),
            Value::U64(self.timestamp),
            Value::Bytes(&self.extra_data),
            Value::Fixed(&self.mix_hash),
            Value::Fixed(&self.nonce),
            uint256(&self.base_fee_per_gas),
            hash(&self.withdrawals_root),
            self.blob_gas_used.map_or(Value::Null, Value::U64),
            self.excess_blob_gas.map_or(Value::Null, Value::U64),
            hash(&self.parent_beacon_block_root),
            hash(&self.requests_hash),
            uint256(&self.total_difficulty),
        ])?)
    }
}

pub fn validate_rows(rows: &[HeaderRow]) -> Result<(), HeaderError> {
    for row in rows {
        row.canonical_bytes()?;
    }
    if rows
        .windows(2)
        .any(|pair| pair[0].block_number >= pair[1].block_number)
    {
        return Err(HeaderError::OutOfOrder);
    }
    Ok(())
}

pub fn content_hash(rows: &[HeaderRow]) -> Result<Hash32, HeaderError> {
    validate_rows(rows)?;
    let mut hasher = blake3::Hasher::new();
    for row in rows {
        hasher.update(&row.canonical_bytes()?);
    }
    Ok(Hash32::new(*hasher.finalize().as_bytes()))
}

/// Check claimed hashes against one another and against the manifest, not against header RLP.
pub fn verify_relic_rows(
    rows: &[HeaderRow],
    range: BlockRange,
    boundary: Boundary,
) -> Result<(), HeaderError> {
    validate_rows(rows)?;
    let expected_len = range
        .end
        .checked_sub(range.start)
        .and_then(|n| n.checked_add(1));
    if expected_len != Some(rows.len() as u64) || rows.is_empty() {
        return Err(HeaderError::IncompleteCoverage);
    }
    for (offset, row) in rows.iter().enumerate() {
        if range.start.checked_add(offset as u64) != Some(row.block_number) {
            return Err(HeaderError::IncompleteCoverage);
        }
    }
    for pair in rows.windows(2) {
        if pair[1].parent_hash != pair[0].block_hash {
            return Err(HeaderError::StoredLinkage(pair[1].block_number));
        }
    }
    let first = &rows[0];
    let last = &rows[rows.len() - 1];
    if first.block_hash != *boundary.start_block_hash.as_bytes()
        || first.parent_hash != *boundary.parent_hash_of_start.as_bytes()
        || last.block_hash != *boundary.end_block_hash.as_bytes()
    {
        return Err(HeaderError::Boundary);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> HeaderRow {
        HeaderRow {
            block_number: 1,
            block_hash: [0x11; 32],
            parent_hash: [0x22; 32],
            ommers_hash: [0x33; 32],
            beneficiary: [0x44; 20],
            state_root: [0x55; 32],
            transactions_root: [0x66; 32],
            receipts_root: [0x77; 32],
            logs_bloom: [0x88; 256],
            difficulty: vec![1, 0],
            gas_limit: 30_000_000,
            gas_used: 21_000,
            timestamp: 123,
            extra_data: vec![0xaa, 0xbb],
            mix_hash: [0x99; 32],
            nonce: [0xaa; 8],
            base_fee_per_gas: Some(vec![]),
            withdrawals_root: Some([0xbb; 32]),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(1),
            parent_beacon_block_root: Some([0xcc; 32]),
            requests_hash: Some([0xdd; 32]),
            total_difficulty: None,
        }
    }

    #[test]
    fn header_encoding_matches_independent_byte_vector() {
        assert_eq!(
            hex::encode(row().canonical_bytes().unwrap()),
            include_str!("../tests/fixtures/header_v1.hex").trim()
        );
    }

    #[test]
    fn null_zero_and_nonminimal_magnitudes_are_distinct() {
        let present_zero = row();
        let mut absent = present_zero.clone();
        absent.base_fee_per_gas = None;
        assert_ne!(
            content_hash(std::slice::from_ref(&present_zero)).unwrap(),
            content_hash(&[absent]).unwrap()
        );
        for field in ["difficulty", "base_fee", "total_difficulty"] {
            for bytes in [vec![0], vec![0, 1], vec![1; 33]] {
                let mut bad = present_zero.clone();
                match field {
                    "difficulty" => bad.difficulty = bytes,
                    "base_fee" => bad.base_fee_per_gas = Some(bytes),
                    _ => bad.total_difficulty = Some(bytes),
                }
                assert!(bad.canonical_bytes().is_err());
            }
        }
    }

    #[test]
    fn stored_links_coverage_and_boundaries_are_checked_separately() {
        let first = row();
        let mut second = first.clone();
        second.block_number = 2;
        second.parent_hash = first.block_hash;
        second.block_hash = [0xff; 32];
        let boundary = Boundary {
            start_block_hash: Hash32::new(first.block_hash),
            parent_hash_of_start: Hash32::new(first.parent_hash),
            end_block_hash: Hash32::new(second.block_hash),
        };
        let range = BlockRange::new(1, 2);
        assert!(verify_relic_rows(&[first.clone(), second.clone()], range, boundary).is_ok());
        assert_eq!(
            verify_relic_rows(std::slice::from_ref(&first), range, boundary),
            Err(HeaderError::IncompleteCoverage)
        );
        assert_eq!(
            verify_relic_rows(&[], range, boundary),
            Err(HeaderError::IncompleteCoverage)
        );
        assert_eq!(
            validate_rows(&[first.clone(), first.clone()]),
            Err(HeaderError::OutOfOrder)
        );
        let mut gap = second.clone();
        gap.block_number = 3;
        assert_eq!(
            verify_relic_rows(&[first.clone(), gap], range, boundary),
            Err(HeaderError::IncompleteCoverage)
        );
        let mut broken = second.clone();
        broken.parent_hash = [0; 32];
        assert_eq!(
            verify_relic_rows(&[first.clone(), broken], range, boundary),
            Err(HeaderError::StoredLinkage(2))
        );
        let wrong_boundary = Boundary {
            end_block_hash: Hash32::ZERO,
            ..boundary
        };
        assert_eq!(
            verify_relic_rows(&[first, second], range, wrong_boundary),
            Err(HeaderError::Boundary)
        );
    }
}
