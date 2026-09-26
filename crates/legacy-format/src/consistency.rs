//! Agreement between supplied tables, not completeness or authenticated chain membership.

use crate::{logs::LogRow, receipts::ReceiptRow, transactions::TransactionRow};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsistencyError {
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
