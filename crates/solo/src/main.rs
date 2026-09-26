//! Solo: the serving binary.
//!
//! The finished article (RFC-0001 §13) is a splitting proxy - finalized reads answered from relics
//! in object storage, the tip forwarded to a small pruned upstream node, historical-state calls
//! rejected outright rather than answered wrongly. None of the serving exists yet.
//!
//! `solo clean` recomputes the pact chain; `--files` adds local byte integrity and implemented
//! table checks. Both say exactly which checks they did and did not perform. A
//! report that implies more than it verified would be worse than no report.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use legacy_format::{manifest::Manifest, pact, relic, SPEC_VERSION};

mod clean_files;

#[derive(Parser)]
#[command(
    name = "solo",
    version,
    about = "The Legacy: serve sealed history, verify what you are served"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve finalized history over JSON-RPC. Not implemented yet.
    Serve {
        #[arg(long, default_value = "solo.toml")]
        config: PathBuf,
    },

    /// Verify a run of relic manifests: structure, linkage, and the pact chain.
    Clean {
        /// Manifest files, in ascending relic order.
        manifests: Vec<PathBuf>,

        /// The already-sealed manifest this run continues from. Omit only when the run starts at
        /// the genesis relic.
        #[arg(long)]
        after: Option<PathBuf>,

        /// Emit the report as JSON rather than prose.
        #[arg(long)]
        json: bool,

        /// Check local table files beside each manifest: bytes, footer counts, and implemented
        /// table codecs. Does not verify trie roots, finality, signatures or checkpoint trust.
        #[arg(long)]
        files: bool,
    },

    /// Where a block lives: relic index, block range, object prefix.
    Relic {
        block: u64,

        #[arg(long, default_value_t = 1)]
        chain_id: u64,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("solo: {e}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Serve { config } => Err(format!(
            "serving is not implemented yet (RFC-0001 §13; config would be {}). \
             Until it is, point erpc or proxyd at a node.",
            config.display()
        )
        .into()),

        Command::Relic { block, chain_id } => {
            let index = relic::relic_index(block);
            let range = relic::relic_range(index);
            println!("block       {block}");
            println!("relic       {index}  ({})", relic::relic_dir_name(index));
            println!("blocks      {range}");
            println!(
                "prefix      {}",
                relic::relic_prefix(SPEC_VERSION, chain_id, index)
            );
            Ok(())
        }

        Command::Clean {
            manifests,
            after,
            json,
            files,
        } => clean(&manifests, after.as_deref(), json, files),
    }
}

fn clean(
    paths: &[PathBuf],
    after: Option<&std::path::Path>,
    json: bool,
    files: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if paths.is_empty() {
        return Err("no manifests given".into());
    }

    let previous = after.map(load).transpose()?;
    let manifests: Vec<Manifest> = paths.iter().map(|p| load(p)).collect::<Result<_, _>>()?;

    let head = pact::verify_chain(previous.as_ref(), &manifests)?;
    let file_reports = if files {
        clean_files::check(paths, &manifests)?
    } else {
        Vec::new()
    };
    let byte_status = if files {
        "pass"
    } else {
        "not checked (no relic data read)"
    };
    let content_status = if !files {
        "not checked (no relic data read)"
    } else if file_reports.iter().all(|r| r.checks.content_hash == "pass") {
        "pass"
    } else if file_reports.iter().all(|r| r.checks.content_hash != "pass") {
        "not checked (no implemented table codec in these manifests)"
    } else {
        "partial (see per-file checks; some table codecs not implemented)"
    };
    let header_hash_status = if !files {
        "not checked (no relic data read)"
    } else if file_reports
        .iter()
        .filter(|r| r.table == legacy_format::Table::Headers)
        .all(|r| r.checks.header_hashes == "pass")
    {
        "pass"
    } else {
        "not checked (unsupported chain header profile)"
    };
    let traces = manifests
        .iter()
        .filter(|m| m.has_unverifiable_tier())
        .count();

    if json {
        let report = serde_json::json!({
            "chain_id": manifests[0].chain_id,
            "relics": manifests.len(),
            "block_range": {
                "start": manifests[0].block_range.start,
                "end": manifests[manifests.len() - 1].block_range.end,
            },
            "checks": {
                "manifest_structure": "pass",
                "relic_linkage": "pass",
                "pact_chain": "pass",
                "file_hashes": byte_status,
                "file_sizes": byte_status,
                "parquet_counts": byte_status,
                "content_hashes": content_status,
                "header_coverage": byte_status,
                "stored_header_linkage": byte_status,
                "manifest_boundary": byte_status,
                "header_hashes": header_hash_status,
                "header_linkage": header_hash_status,
                "consensus_rules": "not checked (including fork activation schedule)",
                "table_completeness": "not checked (not implemented)",
                "producer_signatures": "not checked (not implemented)",
                "era1_accumulator": "not checked (not implemented)",
                "finality": "not checked (not implemented)",
                "index_sidecars": "not checked (not implemented)",
                "transaction_envelopes": "not checked (RLP semantics, hash and raw/structured agreement not implemented)",
                "transaction_signatures": "not checked (signature validity and sender recovery not implemented)",
                "transactions_root": "not checked (not implemented)",
                "receipt_consistency": "not checked (transaction/log agreement, blooms and derived fields not implemented)",
                "receipts_root": "not checked (not implemented)",
                "withdrawals_root": "not checked (not implemented)",
                "checkpoint_anchor": "not checked (not implemented)",
                "traces": if traces > 0 {
                    "unverifiable (not header-committed)"
                } else {
                    "n/a (no traces tier)"
                },
            },
            "pact_root": head.to_hex(),
            "files": file_reports,
            "scope": "requested manifests only; --after supplies predecessor context, not verified file coverage",
            "cleaned_by": concat!("solo/", env!("CARGO_PKG_VERSION")),
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "{} relic(s), blocks {}..={}, chain {}",
            manifests.len(),
            manifests[0].block_range.start,
            manifests[manifests.len() - 1].block_range.end,
            manifests[0].chain_id
        );
        println!("pact root   {head}");
        println!("checked     manifest structure, relic linkage, pact chain");
        if files {
            println!("checked     local file sizes, BLAKE3 hashes, Parquet footer counts");
            println!(
                "checked     complete header coverage, stored parent links, manifest boundaries"
            );
            for file in &file_reports {
                println!(
                    "table       relic {} {}: schema/rows/content hash/block bounds: {}",
                    file.relic_index, file.name, file.checks.content_hash
                );
            }
        } else {
            println!("NOT checked file sizes, file hashes, Parquet metadata or table contents");
        }
        println!("header hashes/linkage: {header_hash_status} (Ethereum layout through Prague; requested files only)");
        println!("NOT checked consensus rules/fork schedule, other table completeness, transactions/receipts/withdrawals roots, checkpoint anchor, producer signatures");
        println!("NOT checked transaction envelopes, RLP semantics, transaction hashes, signatures or sender recovery");
        println!("NOT checked receipt transaction/log agreement, blooms or derived fields");
        println!("NOT checked era1 accumulator, finality, index sidecars");
        println!("scope       requested manifests only; --after supplies predecessor context, not verified file coverage");
        if traces > 0 {
            println!(
                "note        {traces} relic(s) carry a traces tier, which no header commits to \
                 and nothing here can verify"
            );
        }
    }
    Ok(())
}

fn load(path: &std::path::Path) -> Result<Manifest, Box<dyn std::error::Error>> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let manifest: Manifest =
        serde_json::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
    Ok(manifest)
}
