//! Receipt rows and canonical content identity. No trie, bloom or cross-table verification.

use crate::canonical::{encode_row, EncodingError, Value};
use crate::Hash32;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRow {
    pub block_number: u64,
    pub transaction_index: u32,
    pub transaction_hash: [u8; 32],
    pub tx_type: u8,
    pub status: Option<u8>,
    pub post_state: Option<[u8; 32]>,
    pub cumulative_gas_used: u64,
    pub logs_bloom: [u8; 256],
    pub gas_used: Option<u64>,
    pub contract_address: Option<[u8; 20]>,
    pub effective_gas_price: Option<Vec<u8>>,
    pub blob_gas_used: Option<u64>,
    pub blob_gas_price: Option<Vec<u8>>,
    pub deposit_nonce: Option<u64>,
    pub deposit_receipt_version: Option<u8>,
    pub l1_fee: Option<Vec<u8>>,
    pub l1_gas_used: Option<Vec<u8>>,
    pub l1_gas_price: Option<Vec<u8>>,
    pub l1_fee_scalar: Option<Vec<u8>>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReceiptError {
    #[error("receipts must be strictly ordered by (block_number, transaction_index)")]
    OutOfOrder,
    #[error("receipt must contain exactly one of status or post_state")]
    Outcome,
    #[error("receipt status must be 0 or 1")]
    Status,
    #[error(transparent)]
    Encoding(#[from] EncodingError),
}

impl ReceiptRow {
    pub fn sort_key(&self) -> (u64, u32) {
        (self.block_number, self.transaction_index)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReceiptError> {
        if self.status.is_some() == self.post_state.is_some() {
            return Err(ReceiptError::Outcome);
        }
        if self.status.is_some_and(|status| status > 1) {
            return Err(ReceiptError::Status);
        }
        Ok(encode_row(&[
            Value::U64(self.block_number),
            Value::U32(self.transaction_index),
            Value::Fixed(&self.transaction_hash),
            Value::U8(self.tx_type),
            self.status.map_or(Value::Null, Value::U8),
            self.post_state
                .as_ref()
                .map_or(Value::Null, |v| Value::Fixed(v)),
            Value::U64(self.cumulative_gas_used),
            Value::Fixed(&self.logs_bloom),
            self.gas_used.map_or(Value::Null, Value::U64),
            self.contract_address
                .as_ref()
                .map_or(Value::Null, |v| Value::Fixed(v)),
            self.effective_gas_price
                .as_deref()
                .map_or(Value::Null, Value::Uint256),
            self.blob_gas_used.map_or(Value::Null, Value::U64),
            self.blob_gas_price
                .as_deref()
                .map_or(Value::Null, Value::Uint256),
            self.deposit_nonce.map_or(Value::Null, Value::U64),
            self.deposit_receipt_version.map_or(Value::Null, Value::U8),
            self.l1_fee.as_deref().map_or(Value::Null, Value::Uint256),
            self.l1_gas_used
                .as_deref()
                .map_or(Value::Null, Value::Uint256),
            self.l1_gas_price
                .as_deref()
                .map_or(Value::Null, Value::Uint256),
            self.l1_fee_scalar
                .as_deref()
                .map_or(Value::Null, Value::Bytes),
        ])?)
    }
}

pub fn validate_rows(rows: &[ReceiptRow]) -> Result<(), ReceiptError> {
    for row in rows {
        row.canonical_bytes()?;
    }
    if rows
        .windows(2)
        .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
    {
        return Err(ReceiptError::OutOfOrder);
    }
    Ok(())
}

pub fn content_hash(rows: &[ReceiptRow]) -> Result<Hash32, ReceiptError> {
    validate_rows(rows)?;
    let mut hasher = blake3::Hasher::new();
    for row in rows {
        hasher.update(&row.canonical_bytes()?);
    }
    Ok(Hash32::new(*hasher.finalize().as_bytes()))
}
