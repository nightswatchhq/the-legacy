//! Local files are resolved beside each manifest, never from an endpoint or a manifest-supplied URL.

use std::path::PathBuf;

use legacy_format::{Manifest, Table, SPEC_VERSION};
use legacy_parquet::verify::{verify_file_with_rows, DecodedChecks, VerifiedRows};
use serde::Serialize;

const PASS: &str = "pass";
const NO_CODEC: &str = "not checked (table codec not implemented)";

#[derive(Debug, Serialize)]
pub struct FileReport {
    pub relic_index: u64,
    pub name: String,
    pub table: Table,
    pub checks: FileChecks,
}

#[derive(Debug, Serialize)]
pub struct FileChecks {
    pub byte_size: &'static str,
    pub blake3: &'static str,
    pub parquet_counts: &'static str,
    pub schema: &'static str,
    pub row_order: &'static str,
    pub content_hash: &'static str,
    pub decoded_row_count: &'static str,
    pub block_range: &'static str,
    pub header_coverage: &'static str,
    pub stored_header_linkage: &'static str,
    pub header_hashes: &'static str,
    pub manifest_boundary: &'static str,
}

#[derive(Debug, Default)]
pub struct LocalReport {
    pub files: Vec<FileReport>,
    pub relics: Vec<RelicReport>,
}

#[derive(Debug, Serialize)]
pub struct RelicReport {
    pub relic_index: u64,
    pub transaction_receipt_links: &'static str,
    pub log_transaction_links: &'static str,
    pub log_receipt_links: &'static str,
}

pub fn summarize(
    relics: &[RelicReport],
    field: impl Fn(&RelicReport) -> &'static str,
) -> &'static str {
    let passed = relics.iter().filter(|r| field(r) == PASS).count();
    if relics.is_empty() {
        "not checked (no relic data read)"
    } else if passed == relics.len() {
        PASS
    } else if passed == 0 {
        "not checked (required tables absent; see per-relic checks)"
    } else {
        "partial (required tables absent in some relics; see per-relic checks)"
    }
}

/// Run after pact/manifest validation. No success report is emitted until all files pass.
pub fn check(
    paths: &[PathBuf],
    manifests: &[Manifest],
) -> Result<LocalReport, Box<dyn std::error::Error>> {
    let mut reports = LocalReport::default();
    for (path, manifest) in paths.iter().zip(manifests) {
        if manifest.spec_version != SPEC_VERSION {
            return Err(format!(
                "{}: unsupported spec_version {} for file checks",
                path.display(),
                manifest.spec_version
            )
            .into());
        }
        let directory = path.parent().ok_or("manifest has no parent directory")?;
        let mut transactions = None;
        let mut receipts = None;
        let mut logs = None;
        for entry in &manifest.files {
            // Keep the path invariant here too: this module must remain safe if a future caller
            // forgets the manifest-validation step.
            if entry.name != entry.table.file_name() {
                return Err(format!(
                    "{}: invalid table file name {:?}",
                    path.display(),
                    entry.name
                )
                .into());
            }
            let file_path = directory.join(&entry.name);
            let metadata = std::fs::symlink_metadata(&file_path)
                .map_err(|e| format!("reading {}: {e}", file_path.display()))?;
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "{}: expected a regular file, not a symlink or special file",
                    file_path.display()
                )
                .into());
            }
            if metadata.len() != entry.byte_size {
                return Err(format!(
                    "{}: byte_size is {}, manifest claims {}",
                    file_path.display(),
                    metadata.len(),
                    entry.byte_size
                )
                .into());
            }
            // Verify one immutable byte buffer throughout; reopening for decoding could check
            // the hash of one file and the rows of a replacement.
            let bytes = std::fs::read(&file_path)
                .map_err(|e| format!("reading {}: {e}", file_path.display()))?;
            let (decoded, rows) = verify_file_with_rows(bytes.into(), entry, manifest)
                .map_err(|e| format!("{}: {e}", file_path.display()))?;
            match rows {
                VerifiedRows::Transactions(rows) => transactions = Some(rows),
                VerifiedRows::Receipts(rows) => receipts = Some(rows),
                VerifiedRows::Logs(rows) => logs = Some(rows),
                VerifiedRows::Other => {}
            }
            let table_status = match decoded {
                DecodedChecks::Passed | DecodedChecks::HeadersPassed { .. } => PASS,
                DecodedChecks::NotImplemented => NO_CODEC,
            };
            reports.files.push(FileReport {
                relic_index: manifest.relic_index(),
                name: entry.name.clone(),
                table: entry.table,
                checks: FileChecks {
                    header_hashes: match decoded {
                        DecodedChecks::HeadersPassed { hashes: true } => PASS,
                        DecodedChecks::HeadersPassed { hashes: false } => {
                            "not checked (unsupported chain header profile)"
                        }
                        _ => "n/a (not headers)",
                    },
                    byte_size: PASS,
                    blake3: PASS,
                    parquet_counts: PASS,
                    schema: table_status,
                    row_order: table_status,
                    content_hash: table_status,
                    decoded_row_count: table_status,
                    block_range: table_status,
                    header_coverage: if matches!(decoded, DecodedChecks::HeadersPassed { .. }) {
                        PASS
                    } else {
                        "n/a (not headers)"
                    },
                    stored_header_linkage: if matches!(decoded, DecodedChecks::HeadersPassed { .. })
                    {
                        PASS
                    } else {
                        "n/a (not headers)"
                    },
                    manifest_boundary: if matches!(decoded, DecodedChecks::HeadersPassed { .. }) {
                        PASS
                    } else {
                        "n/a (not headers)"
                    },
                },
            });
        }
        let mut relational = RelicReport {
            relic_index: manifest.relic_index(),
            transaction_receipt_links: "not checked (transactions or receipts absent)",
            log_transaction_links: "not checked (logs or transactions absent)",
            log_receipt_links: "not checked (logs or receipts absent)",
        };
        let context = |error| format!("relic {}: {error}", manifest.relic_index());
        if let (Some(tx), Some(receipts)) = (&transactions, &receipts) {
            legacy_format::consistency::transaction_receipt_links(tx, receipts).map_err(context)?;
            relational.transaction_receipt_links = PASS;
        }
        if let (Some(logs), Some(tx)) = (&logs, &transactions) {
            legacy_format::consistency::log_transaction_links(logs, tx).map_err(context)?;
            relational.log_transaction_links = PASS;
        }
        if let (Some(logs), Some(receipts)) = (&logs, &receipts) {
            legacy_format::consistency::log_receipt_links(logs, receipts).map_err(context)?;
            relational.log_receipt_links = PASS;
        }
        reports.relics.push(relational);
    }
    Ok(reports)
}
