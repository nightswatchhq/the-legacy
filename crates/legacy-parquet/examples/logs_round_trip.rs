//! An entirely local, synthetic table round trip. No endpoint, filesystem output or sealed relic.

use legacy_format::logs::{content_hash, LogRow};
use legacy_parquet::logs::{read_logs, write_logs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rows = vec![LogRow {
        block_number: 1,
        transaction_index: 2,
        log_index: 3,
        transaction_hash: [0x11; 32],
        address: [0x22; 20],
        topics: vec![[0; 32]],
        data: vec![0xaa, 0xbb],
    }];
    let (bytes, entry) = write_logs(&rows)?;
    let decoded = read_logs(bytes.into())?;
    if decoded != rows || content_hash(&decoded)? != entry.content_hash {
        return Err("logs round trip changed the canonical rows".into());
    }
    println!(
        "synthetic logs: {} row(s), {} row group(s)",
        entry.row_count, entry.row_groups
    );
    println!("file bytes    {}", entry.byte_size);
    println!("file hash     {}", entry.blake3);
    println!("content hash  {}", entry.content_hash);
    println!("checked       local Parquet round trip and canonical content identity");
    println!("NOT checked   receipt inclusion, header commitments, finality or checkpoint trust");
    Ok(())
}
