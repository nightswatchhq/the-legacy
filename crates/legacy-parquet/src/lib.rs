//! Parquet codecs for RFC-0001 tables. Headers, transactions, logs and withdrawals are implemented.
//!
//! These are in-memory table codecs, not a relic sealer or a chain verifier. A matching content
//! hash says nothing about whether logs match receipts or an authenticated block header.

pub mod headers;
pub mod logs;
pub mod transactions;
pub mod verify;
pub mod withdrawals;
pub mod writer;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Arrow(#[from] arrow_schema::ArrowError),
    #[error(transparent)]
    Parquet(#[from] parquet::errors::ParquetError),
    #[error(transparent)]
    Logs(#[from] legacy_format::logs::LogError),
    #[error(transparent)]
    Headers(#[from] legacy_format::headers::HeaderError),
    #[error(transparent)]
    Withdrawals(#[from] legacy_format::withdrawals::WithdrawalError),
    #[error(transparent)]
    Transactions(#[from] legacy_format::transactions::TransactionError),
    #[error("invalid table schema: {0}")]
    Schema(String),
    #[error("invalid table row: {0}")]
    Row(String),
    #[error("row-group count exceeds the manifest's u32 limit")]
    TooManyRowGroups,
    #[error("file verification failed: {0}")]
    Verification(String),
}

pub type Result<T> = std::result::Result<T, Error>;
