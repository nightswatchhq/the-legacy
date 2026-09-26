//! A synthetic withdrawals table, entirely in memory and without an RPC endpoint.

use legacy_format::withdrawals::{content_hash, WithdrawalRow};
use legacy_parquet::withdrawals::{read_withdrawals, write_withdrawals};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rows = vec![WithdrawalRow {
        block_number: 17_000_000,
        index: 1_000_000,
        validator_index: 7,
        address: [0x11; 20],
        amount: 32_000_000_000,
    }];
    let (bytes, entry) = write_withdrawals(&rows)?;
    let decoded = read_withdrawals(bytes.into())?;
    if decoded != rows || content_hash(&decoded)? != entry.content_hash {
        return Err("withdrawals round trip changed the canonical rows".into());
    }
    println!(
        "synthetic withdrawals: {} row(s), {} row group(s)",
        entry.row_count, entry.row_groups
    );
    println!("file bytes    {}", entry.byte_size);
    println!("file hash     {}", entry.blake3);
    println!("content hash  {}", entry.content_hash);
    println!("checked       local Parquet round trip and canonical content identity");
    println!("NOT checked   withdrawal root, fork activation, finality or checkpoint trust");
    Ok(())
}
