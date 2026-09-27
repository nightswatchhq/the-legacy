//! Era1 SSZ accumulator (RFC-0001 §10.5).
//!
//! `hash_tree_root(List[HeaderRecord, 8192])` where `HeaderRecord` is
//! `{block_hash: Bytes32, total_difficulty: Uint256}`. The row stores total difficulty as a
//! minimal big-endian magnitude; the SSZ uint256 is 32-byte little-endian. Padding leaves are
//! the zero hash, not the hash of an empty record, and the length mixed in is the real count.

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::headers::HeaderRow;
use crate::Hash32;

pub const ERA1_EPOCH: usize = 8192;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Era1Error {
    #[error("era1 accumulator has {0} records; the epoch limit is {ERA1_EPOCH}")]
    TooLong(usize),
    #[error("block {0} has no total_difficulty, so its era1 record cannot be built")]
    MissingDifficulty(u64),
    #[error("block {0} total_difficulty is not a minimal uint256")]
    Difficulty(u64),
    #[error("recomputed era1 accumulator {computed} does not match {expected}")]
    Root { expected: String, computed: String },
}

/// Little-endian 32-byte era1 total difficulty, as the row's minimal big-endian magnitude.
/// Zero is an empty vector.
pub fn total_difficulty_bytes(little_endian: &[u8; 32]) -> Vec<u8> {
    let mut big = *little_endian;
    big.reverse();
    match big.iter().position(|byte| *byte != 0) {
        Some(start) => big[start..].to_vec(),
        None => Vec::new(),
    }
}

/// Recompute the accumulator over header rows in order.
///
/// This compares stored pairs with the claimed root. It does not reconstruct header RLP, and it
/// does not decide whether the range is pre-merge.
pub fn verify(headers: &[HeaderRow], expected: Hash32) -> Result<(), Era1Error> {
    let computed = accumulator_from_headers(headers)?;
    if computed != *expected.as_bytes() {
        return Err(Era1Error::Root {
            expected: expected.to_hex(),
            computed: hex::encode(computed),
        });
    }
    Ok(())
}

pub fn accumulator_from_headers(headers: &[HeaderRow]) -> Result<[u8; 32], Era1Error> {
    if headers.len() > ERA1_EPOCH {
        return Err(Era1Error::TooLong(headers.len()));
    }
    let mut records = Vec::with_capacity(headers.len());
    for header in headers {
        let magnitude = header
            .total_difficulty
            .as_deref()
            .ok_or(Era1Error::MissingDifficulty(header.block_number))?;
        records.push((
            header.block_hash,
            difficulty_le(header.block_number, magnitude)?,
        ));
    }
    accumulator_root(&records)
}

/// `records` are `(block_hash, total_difficulty_le)`. Length must be at most one epoch.
pub fn accumulator_root(records: &[([u8; 32], [u8; 32])]) -> Result<[u8; 32], Era1Error> {
    if records.len() > ERA1_EPOCH {
        return Err(Era1Error::TooLong(records.len()));
    }
    let mut leaves = vec![[0u8; 32]; ERA1_EPOCH];
    for (index, (block_hash, difficulty)) in records.iter().enumerate() {
        let mut record = [0u8; 64];
        record[..32].copy_from_slice(block_hash);
        record[32..].copy_from_slice(difficulty);
        leaves[index] = sha256(&record);
    }
    let mut layer = leaves;
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.as_chunks::<2>().0 {
            let mut joined = [0u8; 64];
            joined[..32].copy_from_slice(&pair[0]);
            joined[32..].copy_from_slice(&pair[1]);
            next.push(sha256(&joined));
        }
        layer = next;
    }
    let mut mixed = [0u8; 64];
    mixed[..32].copy_from_slice(&layer[0]);
    mixed[32..40].copy_from_slice(&(records.len() as u64).to_le_bytes());
    Ok(sha256(&mixed))
}

fn difficulty_le(block: u64, magnitude: &[u8]) -> Result<[u8; 32], Era1Error> {
    if magnitude.len() > 32 || magnitude.first() == Some(&0) {
        return Err(Era1Error::Difficulty(block));
    }
    let mut little = [0u8; 32];
    little[32 - magnitude.len()..].copy_from_slice(magnitude);
    little.reverse();
    Ok(little)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(hash_byte: u8, difficulty: Vec<u8>) -> HeaderRow {
        HeaderRow {
            block_number: 0,
            block_hash: [hash_byte; 32],
            parent_hash: [0; 32],
            ommers_hash: [0; 32],
            beneficiary: [0; 20],
            state_root: [0; 32],
            transactions_root: [0; 32],
            receipts_root: [0; 32],
            logs_bloom: [0; 256],
            difficulty: vec![],
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: vec![],
            mix_hash: [0; 32],
            nonce: [0; 8],
            base_fee_per_gas: None,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
            total_difficulty: Some(difficulty),
        }
    }

    #[test]
    fn little_endian_difficulty_becomes_a_minimal_magnitude() {
        let mut little = [0u8; 32];
        little[0] = 1;
        assert_eq!(total_difficulty_bytes(&little), vec![1]);
        assert_eq!(total_difficulty_bytes(&[0; 32]), Vec::<u8>::new());
    }

    #[test]
    fn accumulator_matches_an_independent_sha256_merkleization() {
        // Computed outside this crate from the SSZ rules: sha256 record roots, zero-hash
        // padding to 8192, then mix in the little-endian length.
        let one = header(0x11, vec![1]);
        assert_eq!(
            hex::encode(accumulator_from_headers(std::slice::from_ref(&one)).unwrap()),
            "68f664ee8839c8184dbf9965371145a76550428705a169ae3ef2b14af83a53da"
        );
        assert_eq!(
            hex::encode(accumulator_root(&[]).unwrap()),
            "4a8c3a07c8d23adc5bac61157555c3c784d53d9bc110c1370809bd23cd93777d"
        );
        let full = vec![([0u8; 32], [0u8; 32]); ERA1_EPOCH];
        assert_eq!(
            hex::encode(accumulator_root(&full).unwrap()),
            "f6af3054fd2f4e7da2b4346b31feb69fb1f0ca95b4d95bc2e55f125f9a79d037"
        );
    }

    #[test]
    fn a_claimed_root_must_match_and_needs_every_difficulty() {
        let row = header(0x11, vec![1]);
        let root = Hash32::new(accumulator_from_headers(std::slice::from_ref(&row)).unwrap());
        verify(std::slice::from_ref(&row), root).unwrap();
        let wrong = Hash32::new([0xab; 32]);
        assert!(matches!(
            verify(std::slice::from_ref(&row), wrong),
            Err(Era1Error::Root { .. })
        ));
        let mut missing = row.clone();
        missing.total_difficulty = None;
        assert!(matches!(
            verify(std::slice::from_ref(&missing), root),
            Err(Era1Error::MissingDifficulty(0))
        ));
    }
}
