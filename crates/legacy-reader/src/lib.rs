//! Native reads from a locally mirrored, sealed Legacy corpus.
//!
//! This first surface is intentionally local only. Each table is decoded from the same immutable
//! bytes whose BLAKE3 and canonical content hash are checked against the sealed manifest before
//! rows are returned. Remote object stores and JSON-RPC belong above this layer.

use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

use legacy_format::{manifest::Manifest, pact, Table};
use legacy_parquet::verify::{verify_file_with_rows, VerifiedRows};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("reading manifest {path}: {source}")]
    ManifestIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing manifest {path}: {source}")]
    ManifestJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error(transparent)]
    Pact(#[from] legacy_format::Error),
    #[error("manifest {0} has no parent directory")]
    ManifestParent(PathBuf),
    #[error("relic {relic} has no {table:?} table")]
    MissingTable { relic: u64, table: Table },
    #[error("reading relic {relic} {table:?}: {source}")]
    TableIo {
        relic: u64,
        table: Table,
        #[source]
        source: std::io::Error,
    },
    #[error("verifying relic {relic} {table:?}: {source}")]
    TableVerify {
        relic: u64,
        table: Table,
        #[source]
        source: legacy_parquet::Error,
    },
    #[error("reader expected {expected} rows for relic {relic}, found another table type")]
    WrongRows { relic: u64, expected: &'static str },
}

/// Logs from one relic, with this file's row-group framing.
pub struct GroupedLogs {
    pub relic: u64,
    pub block_start: u64,
    pub block_end: u64,
    pub rows: Vec<legacy_parquet::logs::GroupedLog>,
}

struct LocalRelic {
    manifest: Manifest,
    directory: PathBuf,
}

/// A pact-verified local mirror. Files are verified on every read, so opening one does not turn a
/// subsequently modified directory into trusted data.
pub struct Corpus {
    relics: Vec<LocalRelic>,
}

impl Corpus {
    /// Open manifests in ascending relic order. A run beginning after genesis is not accepted yet:
    /// callers must include the predecessor context so the whole local view has one verified pact.
    pub fn open_local(paths: &[impl AsRef<Path>]) -> Result<Self, Error> {
        let mut relics = Vec::with_capacity(paths.len());
        for path in paths {
            let path = path.as_ref().to_path_buf();
            let text = std::fs::read_to_string(&path).map_err(|source| Error::ManifestIo {
                path: path.clone(),
                source,
            })?;
            let manifest = serde_json::from_str(&text).map_err(|source| Error::ManifestJson {
                path: path.clone(),
                source,
            })?;
            let directory = path
                .parent()
                .map(Path::to_path_buf)
                .ok_or_else(|| Error::ManifestParent(path.clone()))?;
            relics.push(LocalRelic {
                manifest,
                directory,
            });
        }
        let manifests: Vec<_> = relics.iter().map(|relic| relic.manifest.clone()).collect();
        pact::verify_chain(None, &manifests)?;
        Ok(Self { relics })
    }

    pub fn chain_id(&self) -> Option<u64> {
        self.relics.first().map(|relic| relic.manifest.chain_id)
    }

    pub fn sealed_head(&self) -> Option<u64> {
        self.relics
            .last()
            .map(|relic| relic.manifest.block_range.end)
    }

    pub fn manifests(&self) -> impl Iterator<Item = &Manifest> {
        self.relics.iter().map(|relic| &relic.manifest)
    }

    /// Read logs intersecting `range`. A missing logs table is an error rather than an assertion
    /// that the range is empty.
    pub fn logs(
        &self,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<legacy_format::logs::LogRow>, Error> {
        let mut out = Vec::new();
        for relic in &self.relics {
            if relic.manifest.block_range.end < *range.start()
                || relic.manifest.block_range.start > *range.end()
            {
                continue;
            }
            let rows = self.rows(relic, Table::Logs)?;
            let VerifiedRows::Logs(rows) = rows else {
                return Err(Error::WrongRows {
                    relic: relic.manifest.relic_index(),
                    expected: "logs",
                });
            };
            out.extend(
                rows.into_iter()
                    .filter(|row| range.contains(&row.block_number)),
            );
        }
        Ok(out)
    }

    /// Read headers intersecting `range` after verifying every contributing headers file.
    pub fn headers(
        &self,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<legacy_format::headers::HeaderRow>, Error> {
        let mut out = Vec::new();
        for relic in self.overlapping(&range) {
            let VerifiedRows::Headers(rows) = self.rows(relic, Table::Headers)? else {
                return Err(Error::WrongRows {
                    relic: relic.manifest.relic_index(),
                    expected: "headers",
                });
            };
            out.extend(
                rows.into_iter()
                    .filter(|row| range.contains(&row.block_number)),
            );
        }
        Ok(out)
    }

    /// Read transactions intersecting `range` after verifying every contributing transaction file.
    pub fn transactions(
        &self,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<legacy_format::transactions::TransactionRow>, Error> {
        let mut out = Vec::new();
        for relic in self.overlapping(&range) {
            let VerifiedRows::Transactions(rows) = self.rows(relic, Table::Transactions)? else {
                return Err(Error::WrongRows {
                    relic: relic.manifest.relic_index(),
                    expected: "transactions",
                });
            };
            out.extend(
                rows.into_iter()
                    .filter(|row| range.contains(&row.block_number)),
            );
        }
        Ok(out)
    }

    /// Read receipts intersecting `range` after verifying every contributing receipt file.
    pub fn receipts(
        &self,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<legacy_format::receipts::ReceiptRow>, Error> {
        let mut out = Vec::new();
        for relic in self.overlapping(&range) {
            let VerifiedRows::Receipts(rows) = self.rows(relic, Table::Receipts)? else {
                return Err(Error::WrongRows {
                    relic: relic.manifest.relic_index(),
                    expected: "receipts",
                });
            };
            out.extend(
                rows.into_iter()
                    .filter(|row| range.contains(&row.block_number)),
            );
        }
        Ok(out)
    }

    /// Read withdrawals intersecting `range` after verifying every contributing withdrawal file.
    pub fn withdrawals(
        &self,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<legacy_format::withdrawals::WithdrawalRow>, Error> {
        let mut out = Vec::new();
        for relic in self.overlapping(&range) {
            let VerifiedRows::Withdrawals(rows) = self.rows(relic, Table::Withdrawals)? else {
                return Err(Error::WrongRows {
                    relic: relic.manifest.relic_index(),
                    expected: "withdrawals",
                });
            };
            out.extend(
                rows.into_iter()
                    .filter(|row| range.contains(&row.block_number)),
            );
        }
        Ok(out)
    }

    /// Logs with their Parquet row-group and row numbers, for relics that have a logs file.
    ///
    /// The file BLAKE3 and the canonical content hash are both checked. Row-group numbers describe
    /// this file's framing, not the canonical rows.
    pub fn grouped_logs(&self) -> Result<Vec<GroupedLogs>, Error> {
        let mut out = Vec::new();
        for relic in &self.relics {
            let Some(entry) = relic
                .manifest
                .files
                .iter()
                .find(|entry| entry.table == Table::Logs)
            else {
                continue;
            };
            let bytes = self.log_bytes(relic, entry)?;
            let grouped =
                legacy_parquet::logs::read_logs_grouped(bytes.into()).map_err(|source| {
                    Error::TableVerify {
                        relic: relic.manifest.relic_index(),
                        table: Table::Logs,
                        source,
                    }
                })?;
            let plain: Vec<_> = grouped.iter().map(|row| row.log.clone()).collect();
            let hash =
                legacy_format::logs::content_hash(&plain).map_err(|error| Error::TableVerify {
                    relic: relic.manifest.relic_index(),
                    table: Table::Logs,
                    source: legacy_parquet::Error::Verification(error.to_string()),
                })?;
            if hash != entry.content_hash {
                return Err(Error::TableVerify {
                    relic: relic.manifest.relic_index(),
                    table: Table::Logs,
                    source: legacy_parquet::Error::Verification(
                        "content hash does not match the manifest".into(),
                    ),
                });
            }
            out.push(GroupedLogs {
                relic: relic.manifest.relic_index(),
                block_start: relic.manifest.block_range.start,
                block_end: relic.manifest.block_range.end,
                rows: grouped,
            });
        }
        Ok(out)
    }

    /// Decode selected log row groups after the file BLAKE3 matches the manifest.
    ///
    /// The content hash is not recomputed: a partial decode cannot. The byte hash binds these
    /// bytes to the manifest entry whose content hash was checked when the log index was built.
    pub fn logs_in_groups(
        &self,
        relic_index: u64,
        groups: &[u32],
    ) -> Result<Vec<legacy_parquet::logs::GroupedLog>, Error> {
        let relic = self
            .relics
            .iter()
            .find(|relic| relic.manifest.relic_index() == relic_index)
            .ok_or_else(|| Error::MissingTable {
                relic: relic_index,
                table: Table::Logs,
            })?;
        let entry = relic
            .manifest
            .files
            .iter()
            .find(|entry| entry.table == Table::Logs)
            .ok_or(Error::MissingTable {
                relic: relic_index,
                table: Table::Logs,
            })?;
        if groups.is_empty() {
            self.log_bytes(relic, entry)?;
            return Ok(Vec::new());
        }
        let bytes = self.log_bytes(relic, entry)?;
        let wanted: Vec<usize> = groups
            .iter()
            .map(|group| usize::try_from(*group))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::TableVerify {
                relic: relic_index,
                table: Table::Logs,
                source: legacy_parquet::Error::Verification("row group index overflow".into()),
            })?;
        legacy_parquet::logs::read_log_groups(bytes.into(), &wanted).map_err(|source| {
            Error::TableVerify {
                relic: relic_index,
                table: Table::Logs,
                source,
            }
        })
    }

    fn log_bytes(
        &self,
        relic: &LocalRelic,
        entry: &legacy_format::manifest::FileEntry,
    ) -> Result<Vec<u8>, Error> {
        let bytes =
            std::fs::read(relic.directory.join(&entry.name)).map_err(|source| Error::TableIo {
                relic: relic.manifest.relic_index(),
                table: Table::Logs,
                source,
            })?;
        if bytes.len() as u64 != entry.byte_size
            || legacy_format::hash::blake3(&bytes) != entry.blake3
        {
            return Err(Error::TableVerify {
                relic: relic.manifest.relic_index(),
                table: Table::Logs,
                source: legacy_parquet::Error::Verification(
                    "logs file bytes do not match the manifest".into(),
                ),
            });
        }
        Ok(bytes)
    }

    fn overlapping<'a>(
        &'a self,
        range: &'a RangeInclusive<u64>,
    ) -> impl Iterator<Item = &'a LocalRelic> + 'a {
        self.relics.iter().filter(move |relic| {
            relic.manifest.block_range.end >= *range.start()
                && relic.manifest.block_range.start <= *range.end()
        })
    }

    fn rows(&self, relic: &LocalRelic, table: Table) -> Result<VerifiedRows, Error> {
        let entry = relic
            .manifest
            .files
            .iter()
            .find(|entry| entry.table == table)
            .ok_or(Error::MissingTable {
                relic: relic.manifest.relic_index(),
                table,
            })?;
        let bytes =
            std::fs::read(relic.directory.join(&entry.name)).map_err(|source| Error::TableIo {
                relic: relic.manifest.relic_index(),
                table,
                source,
            })?;
        verify_file_with_rows(bytes.into(), entry, &relic.manifest)
            .map(|(_, rows)| rows)
            .map_err(|source| Error::TableVerify {
                relic: relic.manifest.relic_index(),
                table,
                source,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use legacy_format::manifest::{Boundary, FileEntry, Manifest};
    use legacy_format::Hash32;

    fn log(block_number: u64) -> legacy_format::logs::LogRow {
        legacy_format::logs::LogRow {
            block_number,
            transaction_index: 0,
            log_index: 0,
            transaction_hash: [0x11; 32],
            address: [0x22; 20],
            topics: vec![[0x33; 32]],
            data: vec![0xaa],
        }
    }

    #[test]
    fn local_reader_returns_only_manifest_verified_rows() {
        let directory = std::env::temp_dir().join(format!("legacy-reader-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let (bytes, entry) = legacy_parquet::logs::write_logs(&[log(2)]).unwrap();
        std::fs::write(directory.join(&entry.name), bytes).unwrap();
        let mut manifest = Manifest::new(
            1,
            "test",
            0,
            Boundary {
                start_block_hash: Hash32::ZERO,
                end_block_hash: Hash32::ZERO,
                parent_hash_of_start: Hash32::ZERO,
            },
        );
        manifest.files.push(FileEntry {
            name: Table::Headers.file_name().into(),
            table: Table::Headers,
            byte_size: 1,
            blake3: Hash32::ZERO,
            content_hash: Hash32::ZERO,
            row_count: 1,
            row_groups: 1,
        });
        manifest.files.push(entry);
        legacy_format::pact::seal_chain(None, std::slice::from_mut(&mut manifest)).unwrap();
        let manifest_path = directory.join("manifest.json");
        std::fs::write(&manifest_path, manifest.to_canonical_bytes().unwrap()).unwrap();

        let corpus = Corpus::open_local(std::slice::from_ref(&manifest_path)).unwrap();
        assert_eq!(corpus.chain_id(), Some(1));
        assert_eq!(corpus.sealed_head(), Some(8191));
        assert_eq!(corpus.logs(2..=2).unwrap(), vec![log(2)]);
        assert!(corpus.logs(0..=1).unwrap().is_empty());

        std::fs::write(directory.join("logs.parquet"), b"changed").unwrap();
        assert!(matches!(corpus.logs(2..=2), Err(Error::TableVerify { .. })));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
