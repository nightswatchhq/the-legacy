//! Ethereum receipt trie values through type 4. No trie construction or chain authentication.

use crate::{
    consistency::{self, ConsistencyError},
    logs::LogRow,
    receipts::ReceiptRow,
};
use alloy_rlp::Encodable;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReceiptEncodingError {
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
