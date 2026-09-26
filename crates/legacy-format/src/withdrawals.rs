//! The withdrawals table (RFC-0001 §6.7). Amounts remain in Gwei, with no unit conversion.

use thiserror::Error;

use crate::canonical::{encode_row, EncodingError, Value};
use crate::Hash32;

pub const CANONICAL_ROW_BYTES: usize = 4 * (1 + 8) + (1 + 20);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithdrawalRow {
    pub block_number: u64,
    /// The global withdrawal index, not the per-block trie key.
    pub index: u64,
    pub validator_index: u64,
    pub address: [u8; 20],
    pub amount: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WithdrawalError {
    #[error("withdrawal amount must be nonzero Gwei")]
    ZeroAmount,
    #[error("withdrawals must be strictly ordered by (block_number, index)")]
    OutOfOrder,
    #[error("withdrawal indices must increase globally, including across blocks")]
    InvalidIndex,
    #[error(transparent)]
    Encoding(#[from] EncodingError),
}

impl WithdrawalRow {
    pub fn validate(&self) -> Result<(), WithdrawalError> {
        if self.amount == 0 {
            return Err(WithdrawalError::ZeroAmount);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WithdrawalError> {
        self.validate()?;
        Ok(encode_row(&[
            Value::U64(self.block_number),
            Value::U64(self.index),
            Value::U64(self.validator_index),
            Value::Fixed(&self.address),
            Value::U64(self.amount),
        ])?)
    }
}

/// Ordering and row shape only. Gaps may occur in a slice; full chain completeness needs headers.
pub fn validate_rows(rows: &[WithdrawalRow]) -> Result<(), WithdrawalError> {
    for row in rows {
        row.validate()?;
    }
    for pair in rows.windows(2) {
        let (prev, next) = (&pair[0], &pair[1]);
        if (prev.block_number, prev.index) >= (next.block_number, next.index) {
            return Err(WithdrawalError::OutOfOrder);
        }
        if prev.index >= next.index {
            return Err(WithdrawalError::InvalidIndex);
        }
    }
    Ok(())
}

pub fn content_hash(rows: &[WithdrawalRow]) -> Result<Hash32, WithdrawalError> {
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

    fn row() -> WithdrawalRow {
        WithdrawalRow {
            block_number: 1,
            index: 2,
            validator_index: 3,
            address: [0x11; 20],
            amount: 4,
        }
    }

    #[test]
    fn golden_bytes_preserve_field_order_and_gwei() {
        assert_eq!(row().canonical_bytes().unwrap().len(), CANONICAL_ROW_BYTES);
        assert_eq!(
            hex::encode(row().canonical_bytes().unwrap()),
            concat!(
                "010000000000000001",
                "010000000000000002",
                "010000000000000003",
                "011111111111111111111111111111111111111111",
                "010000000000000004"
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
    fn rejects_zero_amount_duplicates_and_backwards_global_indices() {
        let mut zero = row();
        zero.amount = 0;
        assert_eq!(zero.canonical_bytes(), Err(WithdrawalError::ZeroAmount));
        assert_eq!(
            validate_rows(&[row(), row()]),
            Err(WithdrawalError::OutOfOrder)
        );
        let mut next_block = row();
        next_block.block_number += 1;
        assert_eq!(
            validate_rows(&[row(), next_block.clone()]),
            Err(WithdrawalError::InvalidIndex)
        );
        next_block.index += 1;
        assert!(validate_rows(&[row(), next_block.clone()]).is_ok());
        assert_eq!(
            validate_rows(&[next_block, row()]),
            Err(WithdrawalError::OutOfOrder)
        );
    }
}
