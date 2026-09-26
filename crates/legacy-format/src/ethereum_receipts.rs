//! Ethereum receipt trie values and roots through type 4. No checkpoint or execution validation.

use crate::{
    consistency::{self, ConsistencyError},
    logs::LogRow,
    receipts::ReceiptRow,
};
use alloy_rlp::Encodable;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReceiptEncodingError {
    #[error("receipt trie rows are outside block {0} or indices are not contiguous from zero")]
    BlockRows(u64),
    #[error("reconstructed receipt root differs from header at block {0}")]
    Root(u64),
    #[error("unsupported Ethereum receipt type {0:#x}; supported types are 0 through 4")]
    UnsupportedType(u8),
    #[error("typed Ethereum receipts require status, not a pre-Byzantium state root")]
    TypedState,
    #[error(transparent)]
    Consistency(#[from] ConsistencyError),
}

fn list(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    alloy_rlp::Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut out);
    out.extend_from_slice(payload);
    out
}

/// Encode exactly one receipt and its logs as the trie value, without a transport RLP wrapper.
/// Type 0 has no prefix; types 1..=4 prepend one raw type byte to the receipt RLP list.
/// Checks row shape, log order and key/hash references. The supplied bloom is encoded as-is;
/// bloom reconstruction, log completeness, fork activation and trie roots are separate checks.
pub fn receipt_envelope(
    receipt: &ReceiptRow,
    logs: &[LogRow],
) -> Result<Vec<u8>, ReceiptEncodingError> {
    if receipt.tx_type > 4 {
        return Err(ReceiptEncodingError::UnsupportedType(receipt.tx_type));
    }
    consistency::log_receipt_links(logs, std::slice::from_ref(receipt))?;
    if receipt.tx_type != 0 && receipt.post_state.is_some() {
        return Err(ReceiptEncodingError::TypedState);
    }
    let mut payload = Vec::new();
    if let Some(state) = receipt.post_state {
        state.as_slice().encode(&mut payload);
    } else if let Some(status) = receipt.status {
        status.encode(&mut payload);
    }
    receipt.cumulative_gas_used.encode(&mut payload);
    receipt.logs_bloom.as_slice().encode(&mut payload);
    let mut encoded_logs = Vec::new();
    for log in logs {
        let mut fields = Vec::new();
        log.address.as_slice().encode(&mut fields);
        let mut topics = Vec::new();
        for topic in &log.topics {
            topic.as_slice().encode(&mut topics);
        }
        fields.extend_from_slice(&list(&topics));
        log.data.as_slice().encode(&mut fields);
        encoded_logs.extend_from_slice(&list(&fields));
    }
    payload.extend_from_slice(&list(&encoded_logs));
    let mut out = Vec::new();
    if receipt.tx_type != 0 {
        out.push(receipt.tx_type);
    }
    out.extend_from_slice(&list(&payload));
    Ok(out)
}

/// Trie keys use the receipt's transaction index, not block number, log index or transaction hash.
pub fn receipt_trie_entry(
    receipt: &ReceiptRow,
    logs: &[LogRow],
) -> Result<(Vec<u8>, Vec<u8>), ReceiptEncodingError> {
    let value = receipt_envelope(receipt, logs)?;
    let mut key = Vec::new();
    receipt.transaction_index.encode(&mut key);
    Ok((key, value))
}

/// Rebuild one block's ordered receipt trie. Empty blocks have Ethereum's empty trie root.
/// Indices must be contiguous from zero because the trie builder keys values by slice position.
pub fn receipt_root(
    block: u64,
    receipts: &[ReceiptRow],
    logs: &[LogRow],
) -> Result<[u8; 32], ReceiptEncodingError> {
    consistency::log_receipt_links(logs, receipts)?;
    if receipts
        .iter()
        .enumerate()
        .any(|(i, r)| r.block_number != block || u64::from(r.transaction_index) != i as u64)
        || logs.iter().any(|log| log.block_number != block)
    {
        return Err(ReceiptEncodingError::BlockRows(block));
    }
    let mut values = Vec::with_capacity(receipts.len());
    let mut cursor = 0;
    for receipt in receipts {
        let start = cursor;
        while cursor < logs.len() && logs[cursor].transaction_index == receipt.transaction_index {
            cursor += 1;
        }
        values.push(receipt_envelope(receipt, &logs[start..cursor])?);
    }
    Ok(alloy_trie::root::ordered_trie_root_encoded(&values).into())
}

/// Compare rebuilt roots with supplied headers. Header authentication is a separate check.
pub fn verify_receipt_roots(
    headers: &[crate::headers::HeaderRow],
    receipts: &[ReceiptRow],
    logs: &[LogRow],
) -> Result<(), ReceiptEncodingError> {
    crate::headers::validate_rows(headers).map_err(ConsistencyError::from)?;
    consistency::log_receipt_links(logs, receipts)?;
    let (mut receipt_cursor, mut log_cursor) = (0, 0);
    for header in headers {
        let receipt_start = receipt_cursor;
        while let Some(receipt) = receipts.get(receipt_cursor) {
            if receipt.block_number < header.block_number {
                return Err(ConsistencyError::MissingHeader(receipt.block_number).into());
            }
            if receipt.block_number != header.block_number {
                break;
            }
            receipt_cursor += 1;
        }
        let log_start = log_cursor;
        while log_cursor < logs.len() && logs[log_cursor].block_number == header.block_number {
            log_cursor += 1;
        }
        let root = receipt_root(
            header.block_number,
            &receipts[receipt_start..receipt_cursor],
            &logs[log_start..log_cursor],
        )?;
        if root != header.receipts_root {
            return Err(ReceiptEncodingError::Root(header.block_number));
        }
    }
    if let Some(receipt) = receipts.get(receipt_cursor) {
        return Err(ConsistencyError::MissingHeader(receipt.block_number).into());
    }
    Ok(())
}
