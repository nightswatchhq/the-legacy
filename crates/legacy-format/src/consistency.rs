//! Agreement between supplied tables, not completeness or authenticated chain membership.

use crate::{logs::LogRow, receipts::ReceiptRow, transactions::TransactionRow};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsistencyError {
    #[error("receipt gas accounting at block {0}, transaction {1}: {2}")]
    ReceiptGas(u64, u32, &'static str),
    #[error("header gas total differs from receipts or exceeds gas_limit at block {0}")]
    HeaderGas(u64),
    #[error(transparent)]
    Headers(#[from] crate::headers::HeaderError),
    #[error("header bloom differs from supplied receipts at block {0}")]
    HeaderBloom(u64),
    #[error("receipt references missing header at block {0}")]
    MissingHeader(u64),
    #[error(transparent)]
    Transactions(#[from] crate::transactions::TransactionError),
    #[error(transparent)]
    Receipts(#[from] crate::receipts::ReceiptError),
    #[error(transparent)]
    Logs(#[from] crate::logs::LogError),
    #[error("transaction and receipt row counts differ")]
    Count,
    #[error("receipt bloom differs from supplied logs at block {0}, transaction {1}")]
    Bloom(u64, u32),
    #[error("transaction/receipt key, hash or type differs at block {0}, transaction {1}")]
    Receipt(u64, u32),
    #[error("log has no matching {table} key/hash at block {block}, transaction {transaction}")]
    Log {
        table: &'static str,
        block: u64,
        transaction: u32,
    },
}

pub fn transaction_receipt_links(
    transactions: &[TransactionRow],
    receipts: &[ReceiptRow],
) -> Result<(), ConsistencyError> {
    crate::transactions::validate_rows(transactions)?;
    crate::receipts::validate_rows(receipts)?;
    if transactions.len() != receipts.len() {
        return Err(ConsistencyError::Count);
    }
    for (tx, receipt) in transactions.iter().zip(receipts) {
        if tx.sort_key() != receipt.sort_key()
            || tx.transaction_hash != receipt.transaction_hash
            || tx.tx_type != receipt.tx_type
        {
            return Err(ConsistencyError::Receipt(
                tx.block_number,
                tx.transaction_index,
            ));
        }
    }
    Ok(())
}

pub fn log_transaction_links(
    logs: &[LogRow],
    transactions: &[TransactionRow],
) -> Result<(), ConsistencyError> {
    crate::logs::validate_rows(logs)?;
    crate::transactions::validate_rows(transactions)?;
    log_links(logs, "transaction", |key| {
        transactions
            .binary_search_by_key(&key, TransactionRow::sort_key)
            .ok()
            .map(|index| transactions[index].transaction_hash)
    })
}

pub fn log_receipt_links(logs: &[LogRow], receipts: &[ReceiptRow]) -> Result<(), ConsistencyError> {
    crate::logs::validate_rows(logs)?;
    crate::receipts::validate_rows(receipts)?;
    log_links(logs, "receipt", |key| {
        receipts
            .binary_search_by_key(&key, ReceiptRow::sort_key)
            .ok()
            .map(|index| receipts[index].transaction_hash)
    })
}

fn log_links(
    logs: &[LogRow],
    table: &'static str,
    lookup: impl Fn((u64, u32)) -> Option<[u8; 32]>,
) -> Result<(), ConsistencyError> {
    for log in logs {
        if lookup((log.block_number, log.transaction_index)) != Some(log.transaction_hash) {
            return Err(ConsistencyError::Log {
                table,
                block: log.block_number,
                transaction: log.transaction_index,
            });
        }
    }
    Ok(())
}

/// Ethereum execution gas accounting over whole supplied blocks, not arbitrary receipt slices.
/// Checks arithmetic and stored totals, not execution, fees, transaction gas limits or trie roots.
pub fn ethereum_receipt_gas(
    headers: &[crate::headers::HeaderRow],
    receipts: &[ReceiptRow],
) -> Result<(), ConsistencyError> {
    crate::headers::validate_rows(headers)?;
    crate::receipts::validate_rows(receipts)?;
    let mut cursor = 0;
    for header in headers {
        let mut cumulative = 0u64;
        let mut index = 0u64;
        while let Some(receipt) = receipts.get(cursor) {
            if receipt.block_number < header.block_number {
                return Err(ConsistencyError::MissingHeader(receipt.block_number));
            }
            if receipt.block_number != header.block_number {
                break;
            }
            let fail = |reason| {
                ConsistencyError::ReceiptGas(header.block_number, receipt.transaction_index, reason)
            };
            if u64::from(receipt.transaction_index) != index {
                return Err(fail("indices must start at zero and be contiguous"));
            }
            let used = receipt
                .cumulative_gas_used
                .checked_sub(cumulative)
                .ok_or_else(|| fail("cumulative gas decreased"))?;
            if receipt.gas_used.is_some_and(|stored| stored != used) {
                return Err(fail("gas_used differs from cumulative difference"));
            }
            cumulative = receipt.cumulative_gas_used;
            index += 1;
            cursor += 1;
        }
        if header.gas_used != cumulative || header.gas_used > header.gas_limit {
            return Err(ConsistencyError::HeaderGas(header.block_number));
        }
    }
    if let Some(receipt) = receipts.get(cursor) {
        return Err(ConsistencyError::MissingHeader(receipt.block_number));
    }
    Ok(())
}
