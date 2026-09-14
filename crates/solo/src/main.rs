//! Solo: the serving binary.
//!
//! The finished article (RFC-0001 §13) is a splitting proxy - finalized reads answered from relics
//! in object storage, the tip forwarded to a small pruned upstream node, historical-state calls
//! rejected outright rather than answered wrongly. None of the serving exists yet.
//!
//! What does exist is the half of cleaning that needs no block data: `solo clean` recomputes the
//! pact chain over a set of manifests and says exactly which checks it did and did not perform. A
//! report that implies more than it verified would be worse than no report.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use legacy_format::{manifest::Manifest, pact, relic, SPEC_VERSION};

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
        } => clean(&manifests, after.as_deref(), json),
    }
}

fn clean(
    paths: &[PathBuf],
    after: Option<&std::path::Path>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if paths.is_empty() {
        return Err("no manifests given".into());
    }

    let previous = after.map(load).transpose()?;
    let manifests: Vec<Manifest> = paths.iter().map(|p| load(p)).collect::<Result<_, _>>()?;

    let head = pact::verify_chain(previous.as_ref(), &manifests)?;
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
                "file_hashes": "not checked (no relic data read)",
                "transactions_root": "not checked (not implemented)",
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
        println!(
            "NOT checked file hashes, transactions/receipts/withdrawals roots, checkpoint anchor"
        );
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
