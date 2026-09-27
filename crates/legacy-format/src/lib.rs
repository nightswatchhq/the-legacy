//! The Legacy, format layer.
//!
//! This crate is the executable half of RFC-0001 (`docs/rfcs/0001-the-legacy.md`): relic geometry,
//! the canonical-JSON manifest, and the pact hash chain. It deliberately knows nothing about
//! Parquet, object storage or JSON-RPC. Table codecs live in `legacy-parquet`; ingestion and
//! serving belong to `shadow` and `solo`, and
//! both of them agree on what a relic *is* by depending on this crate rather than by convention.
//!
//! The spec constants that matter are in [`relic`]: a relic is 8192 blocks, so the block-to-relic
//! mapping is a shift rather than a division.

pub mod bloom;
pub mod canonical;
pub mod consistency;
pub mod era1;
pub mod error;
pub mod ethereum;
pub mod ethereum_receipts;
pub mod ethereum_transactions;
pub mod ethereum_withdrawals;
pub mod hash;
pub mod headers;
pub mod jcs;
pub mod logs;
pub mod manifest;
pub mod pact;
pub mod receipts;
pub mod registry;
pub mod relic;
pub mod transactions;
pub mod withdrawals;

pub use error::Error;
pub use hash::Hash32;
pub use manifest::{Boundary, FileEntry, Manifest, Producer, SignatureScheme, Table};
pub use relic::{relic_index, relic_range, BlockRange, BLOCKS_PER_RELIC, RELIC_SHIFT};

/// The spec version this build produces and understands.
///
/// A manifest carries its own `spec_version`; cleaning uses the version in the manifest, not this
/// one (RFC-0001 §12.5). Sealed relics are never rewritten, so a pact chain may span versions.
pub const SPEC_VERSION: u32 = 1;

/// The only hash algorithm v1 defines. Recorded in every manifest so a later version can migrate.
pub const HASH_ALGO: &str = "blake3";

pub type Result<T> = std::result::Result<T, Error>;
