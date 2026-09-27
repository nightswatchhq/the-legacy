//! Local sealed-history JSON-RPC, and the cleaner.
//!
//! This is not the splitting proxy in RFC-0001 §13. There is no upstream and no object storage.
//! Log address and topic bitmaps are rebuilt in memory from the logs file. They are not sealed
//! into the manifest. Transaction and block hash lookups still read whole relic files.

pub mod clean_files;
pub mod config;
pub mod http;
pub mod log_index;
pub mod rpc;

use std::path::Path;

pub fn serve(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = config::load(config_path)?;
    http::serve(&config)
}
