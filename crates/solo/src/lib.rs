//! Local sealed-history JSON-RPC, and the cleaner.
//!
//! This is not the splitting proxy in RFC-0001 §13. There is no upstream and no object storage.
//! Log bitmaps and hash indexes are rebuilt in memory from the admitted files. They are not
//! sealed into the manifest. A hash-index hit still reads that relic's table and checks the hash.

pub mod clean_files;
pub mod config;
pub mod hash_index;
pub mod http;
pub mod log_index;
pub mod rpc;

use std::path::Path;

pub fn serve(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = config::load(config_path)?;
    http::serve(&config)
}
