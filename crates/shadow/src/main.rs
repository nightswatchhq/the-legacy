//! Shadow: the ingesters.
//!
//! Six sources (RFC-0001 §11) - archive JSON-RPC, Reth static files, Erigon `.seg` snapshots, era1,
//! Firehose merged blocks, and a Reth ExEx for the steady state - all producing the same relic
//! format. None of them is implemented yet.
//!
//! `shadow plan` is what exists: given a block range it prints the relics that range covers and
//! where each one belongs in object storage. It is the cheapest possible check that the geometry
//! in the spec and the geometry in the code are the same geometry.

use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use legacy_format::{relic, SPEC_VERSION};

#[derive(Parser)]
#[command(
    name = "shadow",
    version,
    about = "The Legacy: transcode chain history into sealed relics"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Source {
    /// Archive JSON-RPC. Bootstrapping only: slow, rate-limited, and holds the raw bytes.
    Rpc,
    /// Reth static files (NippyJar segments).
    Reth,
    /// Erigon 3 block snapshots (`.seg`). State domains are out of scope.
    Erigon,
    /// era1 files. Pre-merge only, and the accumulator root carries into the manifest.
    Era1,
    /// Firehose merged blocks. The only source with call trees, so the only traces source.
    Firehose,
    /// A Reth Execution Extension. The continuous producer, sealing at finality.
    Exex,
}

#[derive(Subcommand)]
enum Command {
    /// Print the relics a block range covers, and where they live.
    Plan {
        #[arg(long)]
        from: u64,
        #[arg(long)]
        to: u64,
        #[arg(long, default_value_t = 1)]
        chain_id: u64,
    },

    /// Transcode a block range into relics. Not implemented yet.
    Seal {
        #[arg(long, value_enum)]
        source: Source,
        #[arg(long)]
        from: u64,
        #[arg(long)]
        to: u64,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("shadow: {e}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Plan { from, to, chain_id } => {
            if to < from {
                return Err(format!("block range {from}..{to} runs backwards").into());
            }
            let indices = relic::relics_for_range(from, to);
            let (first, last) = (*indices.start(), *indices.end());
            println!(
                "blocks {from}..={to} cover {} relic(s), {first}..={last}",
                last - first + 1
            );
            for index in indices {
                let range = relic::relic_range(index);
                // A relic is sealed whole or not at all, so a range that stops mid-relic is a
                // partial one and saying so now is cheaper than discovering it after the transcode.
                let partial = if range.start < from || range.end > to {
                    "  (partial: the relic is sealed only once its whole range is past finality)"
                } else {
                    ""
                };
                println!(
                    "  {}  blocks {range}  {}{partial}",
                    relic::relic_dir_name(index),
                    relic::relic_prefix(SPEC_VERSION, chain_id, index)
                );
            }
            Ok(())
        }

        Command::Seal { source, from, to } => Err(format!(
            "the {source:?} shadow is not implemented yet (RFC-0001 §11); \
             blocks {from}..={to} stay where they are"
        )
        .into()),
    }
}
