//! Shadow: the ingesters.
//!
//! Six sources (RFC-0001 §11) - archive JSON-RPC, Reth static files, Erigon `.seg` snapshots, era1,
//! Firehose merged blocks, and a Reth ExEx for the steady state - all producing the same relic
//! format. None of them is implemented yet.
//!
//! `shadow plan` prints the relics a block range covers. `shadow seal --source era1` reads one
//! era1 file and writes one relic. The other five sources are still skeleton.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use legacy_format::{relic, SPEC_VERSION};

mod decode;
mod era1;

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

    /// Transcode one source range into a relic.
    Seal {
        #[arg(long, value_enum)]
        source: Source,

        #[arg(long)]
        from: u64,

        #[arg(long)]
        to: u64,

        /// Era1 file. Required for `--source era1`.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Empty directory the relic is written into. Required for `--source era1`.
        #[arg(long)]
        out: Option<PathBuf>,

        /// Predecessor manifest. Required for any relic after genesis.
        #[arg(long)]
        after: Option<PathBuf>,

        /// Recorded on the manifest. An era1 file does not carry a chain id.
        #[arg(long, default_value_t = 1)]
        chain_id: u64,

        /// Recorded on the manifest. An era1 file does not carry a silo name.
        #[arg(long, default_value = "ethereum")]
        silo: String,
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

        Command::Seal {
            source,
            from,
            to,
            file,
            out,
            after,
            chain_id,
            silo,
        } => {
            if source != Source::Era1 {
                return Err(format!(
                    "the {source:?} shadow is not implemented yet (RFC-0001 §11); \
                     blocks {from}..={to} stay where they are"
                )
                .into());
            }
            let sealed = era1::seal(&era1::SealRequest {
                file: file.ok_or("era1 seal needs --file")?,
                out: out.ok_or("era1 seal needs --out")?,
                from,
                to,
                chain_id,
                silo,
                predecessor: after,
            })?;
            report(&sealed);
            Ok(())
        }
    }
}

fn report(sealed: &era1::Sealed) {
    println!(
        "relic       {}  ({})",
        sealed.relic_index,
        relic::relic_dir_name(sealed.relic_index)
    );
    println!("blocks      {}..={}", sealed.start, sealed.end);
    println!("chain       {}", sealed.chain_id);
    println!("accumulator {}", sealed.accumulator.to_hex());
    println!("pact root   {}", sealed.pact_root.to_hex());
    println!("directory   {}", sealed.directory.display());
    println!("wrote       headers, transactions, receipts, logs");
    println!(
        "checked     era1 framing and block index, accumulator root, header round-trip, \
         ommers hash, transaction and receipt tries, blooms, execution gas"
    );
    println!(
        "NOT checked signature fork rules (sender was recovered into `from`), \
         fee or contract-address agreement, finality, checkpoint anchor"
    );
    if sealed.chain_id != 1 {
        println!(
            "note        solo clean repeats header hashes and trie roots for chain id 1 only; \
             chain {} leaves that profile unchecked",
            sealed.chain_id
        );
    }
}
