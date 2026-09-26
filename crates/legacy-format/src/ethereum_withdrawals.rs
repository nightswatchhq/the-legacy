//! Ethereum withdrawal trie values and roots after EIP-4895.

use crate::{consistency::ConsistencyError, headers::HeaderRow, withdrawals::WithdrawalRow};
use alloy_rlp::Encodable;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WithdrawalEncodingError {
    #[error("withdrawal trie rows are outside block {0}")]
    BlockRows(u64),
    #[error("header withdrawal-root presence differs from supplied withdrawals at block {0}")]
    Presence(u64),
    #[error("reconstructed withdrawal root differs from header at block {0}")]
    Root(u64),
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

/// Encode EIP-4895's `Withdrawal(index, validator_index, address, amount)` list.
/// The row's global index is a value. The ordered trie builder supplies the per-block key.
pub fn withdrawal_envelope(row: &WithdrawalRow) -> Result<Vec<u8>, WithdrawalEncodingError> {
    row.validate().map_err(ConsistencyError::from)?;
    let mut payload = Vec::new();
    row.index.encode(&mut payload);
    row.validator_index.encode(&mut payload);
    row.address.as_slice().encode(&mut payload);
    row.amount.encode(&mut payload);
    Ok(list(&payload))
}

/// Rebuild one block's ordered withdrawal trie. Empty post-Shapella blocks use the empty root.
pub fn withdrawal_root(
    block: u64,
    withdrawals: &[WithdrawalRow],
) -> Result<[u8; 32], WithdrawalEncodingError> {
    crate::withdrawals::validate_rows(withdrawals).map_err(ConsistencyError::from)?;
    if withdrawals
        .iter()
        .any(|withdrawal| withdrawal.block_number != block)
    {
        return Err(WithdrawalEncodingError::BlockRows(block));
    }
    let values: Result<Vec<_>, _> = withdrawals.iter().map(withdrawal_envelope).collect();
    Ok(alloy_trie::root::ordered_trie_root_encoded(&values?).into())
}

/// Compare rebuilt post-Shapella roots with supplied headers. Header authentication is separate.
pub fn verify_withdrawal_roots(
    headers: &[HeaderRow],
    withdrawals: &[WithdrawalRow],
) -> Result<(), WithdrawalEncodingError> {
    crate::headers::validate_rows(headers).map_err(ConsistencyError::from)?;
    crate::withdrawals::validate_rows(withdrawals).map_err(ConsistencyError::from)?;
    let mut cursor = 0;
    for header in headers {
        let start = cursor;
        while let Some(withdrawal) = withdrawals.get(cursor) {
            if withdrawal.block_number < header.block_number {
                return Err(ConsistencyError::MissingHeader(withdrawal.block_number).into());
            }
            if withdrawal.block_number != header.block_number {
                break;
            }
            cursor += 1;
        }
        let rows = &withdrawals[start..cursor];
        match header.withdrawals_root {
            Some(expected) => {
                if withdrawal_root(header.block_number, rows)? != expected {
                    return Err(WithdrawalEncodingError::Root(header.block_number));
                }
            }
            None if !rows.is_empty() => {
                return Err(WithdrawalEncodingError::Presence(header.block_number))
            }
            None => {}
        }
    }
    if let Some(withdrawal) = withdrawals.get(cursor) {
        return Err(ConsistencyError::MissingHeader(withdrawal.block_number).into());
    }
    Ok(())
}
