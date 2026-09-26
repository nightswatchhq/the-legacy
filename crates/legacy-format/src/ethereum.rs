//! Ethereum header preimages through Prague. This is not consensus or checkpoint verification.

use alloy_rlp::Encodable;
use sha3::{Digest, Keccak256};
use thiserror::Error;

use crate::headers::{HeaderError, HeaderRow};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error(transparent)]
    Row(#[from] HeaderError),
    #[error("block {0}: unsupported Ethereum header extension shape (supported through Prague)")]
    Extensions(u64),
    #[error("block {0}: reconstructed Ethereum header hash does not match block_hash")]
    Hash(u64),
}

/// Encode a pre-London, London, Shanghai, Cancun or Prague header layout.
/// Presence determines the layout, not a fork schedule. Other EVM chains need their own profile.
/// `block_hash` and `total_difficulty` are metadata, never part of the preimage.
pub fn header_rlp(row: &HeaderRow) -> Result<Vec<u8>, Error> {
    row.canonical_bytes()?;
    let extensions = [
        row.base_fee_per_gas.is_some(),
        row.withdrawals_root.is_some(),
        row.blob_gas_used.is_some(),
        row.excess_blob_gas.is_some(),
        row.parent_beacon_block_root.is_some(),
        row.requests_hash.is_some(),
    ];
    let count = extensions.iter().take_while(|&&present| present).count();
    if extensions[count..].iter().any(|&present| present) || !matches!(count, 0 | 1 | 2 | 5 | 6) {
        return Err(Error::Extensions(row.block_number));
    }
    let mut payload = Vec::new();
    for bytes in [
        row.parent_hash.as_slice(),
        &row.ommers_hash,
        &row.beneficiary,
        &row.state_root,
        &row.transactions_root,
        &row.receipts_root,
        &row.logs_bloom,
        &row.difficulty,
    ] {
        bytes.encode(&mut payload);
    }
    for number in [row.block_number, row.gas_limit, row.gas_used, row.timestamp] {
        number.encode(&mut payload);
    }
    row.extra_data.as_slice().encode(&mut payload);
    row.mix_hash.as_slice().encode(&mut payload);
    row.nonce.as_slice().encode(&mut payload);
    if let Some(value) = &row.base_fee_per_gas {
        value.as_slice().encode(&mut payload);
    }
    if let Some(value) = &row.withdrawals_root {
        value.as_slice().encode(&mut payload);
    }
    if let Some(value) = row.blob_gas_used {
        value.encode(&mut payload);
    }
    if let Some(value) = row.excess_blob_gas {
        value.encode(&mut payload);
    }
    if let Some(value) = &row.parent_beacon_block_root {
        value.as_slice().encode(&mut payload);
    }
    if let Some(value) = &row.requests_hash {
        value.as_slice().encode(&mut payload);
    }
    let mut encoded = Vec::new();
    alloy_rlp::Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut encoded);
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

pub fn header_hash(row: &HeaderRow) -> Result<[u8; 32], Error> {
    Ok(Keccak256::digest(header_rlp(row)?).into())
}

pub fn verify_header(row: &HeaderRow) -> Result<(), Error> {
    if header_hash(row)? != row.block_hash {
        return Err(Error::Hash(row.block_number));
    }
    Ok(())
}
