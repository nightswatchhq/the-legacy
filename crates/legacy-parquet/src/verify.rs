//! Verification against a manifest's claims, not against an authenticated chain.

use bytes::Bytes;
use legacy_format::hash::blake3;
use legacy_format::{FileEntry, Manifest, Table, SPEC_VERSION};
use parquet::file::reader::{FileReader, SerializedFileReader};

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodedChecks {
    /// Schema, row order, content hash, decoded count and block bounds all passed.
    Passed,
    /// Decoded checks plus complete header coverage, stored parent links and manifest boundaries.
    /// Hash reconstruction is separately reported for the supported chain profile.
    HeadersPassed { hashes: bool },
    /// Only file bytes and Parquet metadata were checked; the table codec is not implemented.
    NotImplemented,
}

/// Check the same byte buffer for integrity, footer counts, and supported table contents.
/// Only header row coverage is checked; other-table completeness, finality, trie roots and
/// checkpoint trust are not. Only chain ID 1 uses the Ethereum through-Prague hash profile.
pub fn verify_file(bytes: Bytes, entry: &FileEntry, manifest: &Manifest) -> Result<DecodedChecks> {
    let range = manifest.block_range;
    let bad = |message: &str| Error::Verification(format!("{}: {message}", entry.name));
    if manifest.spec_version != SPEC_VERSION {
        return Err(bad("unsupported spec_version for table verification"));
    }
    if entry.name != entry.table.file_name() {
        return Err(bad("file name does not match the table's canonical name"));
    }
    if range.end < range.start {
        return Err(bad("block range runs backwards"));
    }
    if bytes.len() as u64 != entry.byte_size {
        return Err(bad("byte_size does not match the manifest"));
    }
    if blake3(&bytes) != entry.blake3 {
        return Err(bad("BLAKE3 does not match the manifest"));
    }
    let reader = SerializedFileReader::new(bytes.clone())?;
    let metadata = reader.metadata();
    if u64::try_from(metadata.file_metadata().num_rows()).ok() != Some(entry.row_count) {
        return Err(bad("row_count does not match the Parquet footer"));
    }
    if u32::try_from(metadata.num_row_groups()).ok() != Some(entry.row_groups) {
        return Err(bad("row_groups does not match the Parquet footer"));
    }
    let group_rows = metadata.row_groups().iter().try_fold(0u64, |total, group| {
        total.checked_add(u64::try_from(group.num_rows()).ok()?)
    });
    if group_rows != Some(entry.row_count) {
        return Err(bad("row-group counts do not sum to the file row count"));
    }
    let (hash, count, in_range) = match entry.table {
        Table::Headers => {
            let rows = crate::headers::read_headers(bytes)?;
            legacy_format::headers::verify_relic_rows(&rows, range, manifest.boundary)?;
            if manifest.chain_id == 1 {
                for row in &rows {
                    legacy_format::ethereum::verify_header(row).map_err(|e| bad(&e.to_string()))?;
                }
            }
            (
                legacy_format::headers::content_hash(&rows)?,
                rows.len(),
                true,
            )
        }
        Table::Logs => {
            let rows = crate::logs::read_logs(bytes)?;
            (
                legacy_format::logs::content_hash(&rows)?,
                rows.len(),
                rows.iter().all(|r| range.contains(r.block_number)),
            )
        }
        Table::Withdrawals => {
            let rows = crate::withdrawals::read_withdrawals(bytes)?;
            (
                legacy_format::withdrawals::content_hash(&rows)?,
                rows.len(),
                rows.iter().all(|r| range.contains(r.block_number)),
            )
        }
        _ => return Ok(DecodedChecks::NotImplemented),
    };
    if hash != entry.content_hash {
        return Err(bad("content_hash does not match decoded canonical rows"));
    }
    if count as u64 != entry.row_count {
        return Err(bad("decoded row count does not match the manifest"));
    }
    if !in_range {
        return Err(bad("decoded block number is outside the relic range"));
    }
    Ok(if entry.table == Table::Headers {
        DecodedChecks::HeadersPassed {
            hashes: manifest.chain_id == 1,
        }
    } else {
        DecodedChecks::Passed
    })
}
