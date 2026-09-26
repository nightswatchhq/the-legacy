//! Transaction table rows. No signature, envelope, sender or trie verification.

use crate::canonical::{encode_row, EncodingError, Value};
use crate::Hash32;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionRow {
    pub block_number: u64,
    pub transaction_index: u32,
    pub transaction_hash: [u8; 32],
    pub tx_type: u8,
    pub nonce: u64,
    pub from: [u8; 20],
    pub to: Option<[u8; 20]>,
    pub value: Vec<u8>,
    pub gas_limit: u64,
    pub gas_price: Option<Vec<u8>>,
    pub max_fee_per_gas: Option<Vec<u8>>,
    pub max_priority_fee_per_gas: Option<Vec<u8>>,
    pub max_fee_per_blob_gas: Option<Vec<u8>>,
    pub input: Vec<u8>,
    pub access_list: Option<Vec<u8>>,
    pub blob_versioned_hashes: Option<Vec<u8>>,
    pub authorization_list: Option<Vec<u8>>,
    /// Legacy without chain_id: 27/28; protected legacy and typed signatures: 0/1.
    pub v_or_y_parity: Option<u8>,
    pub r: Option<[u8; 32]>,
    pub s: Option<[u8; 32]>,
    pub chain_id: Option<u64>,
    pub source_hash: Option<[u8; 32]>,
    pub mint: Option<Vec<u8>>,
    pub is_system_tx: Option<bool>,
    /// Preserved by storage but excluded from content identity. Agreement is not checked here.
    pub raw_envelope: Option<Vec<u8>>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransactionError {
    #[error("transactions must be strictly ordered by (block_number, transaction_index)")]
    OutOfOrder,
    #[error("invalid normalized transaction signature parity")]
    Parity,
    #[error(transparent)]
    Encoding(#[from] EncodingError),
}

impl TransactionRow {
    pub fn sort_key(&self) -> (u64, u32) {
        (self.block_number, self.transaction_index)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        if let Some(parity) = self.v_or_y_parity {
            let valid = if self.tx_type == 0 && self.chain_id.is_none() {
                matches!(parity, 27 | 28)
            } else {
                parity <= 1
            };
            if !valid {
                return Err(TransactionError::Parity);
            }
        }
        Ok(encode_row(&[
            Value::U64(self.block_number),
            Value::U32(self.transaction_index),
            Value::Fixed(&self.transaction_hash),
            Value::U8(self.tx_type),
            Value::U64(self.nonce),
            Value::Fixed(&self.from),
            self.to.as_ref().map_or(Value::Null, |v| Value::Fixed(v)),
            Value::Uint256(&self.value),
            Value::U64(self.gas_limit),
            self.gas_price
                .as_deref()
                .map_or(Value::Null, Value::Uint256),
            self.max_fee_per_gas
                .as_deref()
                .map_or(Value::Null, Value::Uint256),
            self.max_priority_fee_per_gas
                .as_deref()
                .map_or(Value::Null, Value::Uint256),
            self.max_fee_per_blob_gas
                .as_deref()
                .map_or(Value::Null, Value::Uint256),
            Value::Bytes(&self.input),
            self.access_list
                .as_deref()
                .map_or(Value::Null, Value::Bytes),
            self.blob_versioned_hashes
                .as_deref()
                .map_or(Value::Null, Value::Bytes),
            self.authorization_list
                .as_deref()
                .map_or(Value::Null, Value::Bytes),
            self.v_or_y_parity.map_or(Value::Null, Value::U8),
            self.r.as_ref().map_or(Value::Null, |v| Value::Fixed(v)),
            self.s.as_ref().map_or(Value::Null, |v| Value::Fixed(v)),
            self.chain_id.map_or(Value::Null, Value::U64),
            self.source_hash
                .as_ref()
                .map_or(Value::Null, |v| Value::Fixed(v)),
            self.mint.as_deref().map_or(Value::Null, Value::Uint256),
            self.is_system_tx.map_or(Value::Null, Value::Bool),
            // The same structured transaction has one identity with or without this cache.
            Value::Null,
        ])?)
    }
}

pub fn validate_rows(rows: &[TransactionRow]) -> Result<(), TransactionError> {
    for row in rows {
        row.canonical_bytes()?;
    }
    if rows
        .windows(2)
        .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
    {
        return Err(TransactionError::OutOfOrder);
    }
    Ok(())
}

pub fn content_hash(rows: &[TransactionRow]) -> Result<Hash32, TransactionError> {
    validate_rows(rows)?;
    let mut hasher = blake3::Hasher::new();
    for row in rows {
        hasher.update(&row.canonical_bytes()?);
    }
    Ok(Hash32::new(*hasher.finalize().as_bytes()))
}
