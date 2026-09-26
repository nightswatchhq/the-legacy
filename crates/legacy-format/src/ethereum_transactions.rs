//! Ethereum transaction trie values and roots through type 4.
//!
//! The raw envelope is retained in the transaction table precisely for this check. Structured
//! field agreement, signature recovery and fork activation are intentionally separate work.

use crate::{consistency::ConsistencyError, headers::HeaderRow, transactions::TransactionRow};
use sha3::{Digest, Keccak256};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransactionEncodingError {
    #[error("transaction trie rows are outside block {0} or indices are not contiguous from zero")]
    BlockRows(u64),
    #[error("transaction at block {0}, index {1} has no raw Ethereum envelope")]
    MissingEnvelope(u64, u32),
    #[error("transaction at block {0}, index {1} has an invalid Ethereum envelope profile")]
    Envelope(u64, u32),
    #[error("transaction hash differs from its raw envelope at block {0}, index {1}")]
    Hash(u64, u32),
    #[error("reconstructed transaction root differs from header at block {0}")]
    Root(u64),
    #[error(transparent)]
    Consistency(#[from] ConsistencyError),
}

/// Validate the small envelope profile needed to use stored raw bytes as a trie value.
/// This does not decode transaction fields or recover a signer.
fn envelope(row: &TransactionRow) -> Result<&[u8], TransactionEncodingError> {
    let raw = row
        .raw_envelope
        .as_deref()
        .ok_or(TransactionEncodingError::MissingEnvelope(
            row.block_number,
            row.transaction_index,
        ))?;
    let rlp_list = |encoded: &[u8]| {
        let mut remaining = encoded;
        alloy_rlp::Header::decode(&mut remaining)
            .is_ok_and(|header| header.list && remaining.len() == header.payload_length)
    };
    let valid = match row.tx_type {
        0 => rlp_list(raw),
        1..=4 => raw.first() == Some(&row.tx_type) && rlp_list(&raw[1..]),
        _ => false,
    };
    if !valid {
        return Err(TransactionEncodingError::Envelope(
            row.block_number,
            row.transaction_index,
        ));
    }
    if transaction_hash(raw) != row.transaction_hash {
        return Err(TransactionEncodingError::Hash(
            row.block_number,
            row.transaction_index,
        ));
    }
    Ok(raw)
}

/// Keccak hash of the canonical envelope, as committed by Ethereum transaction rows.
pub fn transaction_hash(raw_envelope: &[u8]) -> [u8; 32] {
    Keccak256::digest(raw_envelope).into()
}

/// Rebuild one block's ordered transaction trie from raw EIP-2718 envelopes.
pub fn transaction_root(
    block: u64,
    transactions: &[TransactionRow],
) -> Result<[u8; 32], TransactionEncodingError> {
    crate::transactions::validate_rows(transactions).map_err(ConsistencyError::from)?;
    if transactions.iter().enumerate().any(|(index, transaction)| {
        transaction.block_number != block
            || u64::from(transaction.transaction_index) != index as u64
    }) {
        return Err(TransactionEncodingError::BlockRows(block));
    }
    let values: Result<Vec<_>, _> = transactions.iter().map(envelope).collect();
    Ok(alloy_trie::root::ordered_trie_root_encoded(&values?).into())
}

/// Compare rebuilt transaction roots with supplied headers. Header authentication is separate.
pub fn verify_transaction_roots(
    headers: &[HeaderRow],
    transactions: &[TransactionRow],
) -> Result<(), TransactionEncodingError> {
    crate::headers::validate_rows(headers).map_err(ConsistencyError::from)?;
    crate::transactions::validate_rows(transactions).map_err(ConsistencyError::from)?;
    let mut cursor = 0;
    for header in headers {
        let start = cursor;
        while let Some(transaction) = transactions.get(cursor) {
            if transaction.block_number < header.block_number {
                return Err(ConsistencyError::MissingHeader(transaction.block_number).into());
            }
            if transaction.block_number != header.block_number {
                break;
            }
            cursor += 1;
        }
        if transaction_root(header.block_number, &transactions[start..cursor])?
            != header.transactions_root
        {
            return Err(TransactionEncodingError::Root(header.block_number));
        }
    }
    if let Some(transaction) = transactions.get(cursor) {
        return Err(ConsistencyError::MissingHeader(transaction.block_number).into());
    }
    Ok(())
}
