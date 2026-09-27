//! The fields this server actually reads. An `upstream` table is refused: forwarding is not built,
//! and ignoring the key would look like sealed-only while the file asked for a proxy.

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    pub manifests: Vec<PathBuf>,
    pub limits: Limits,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Limits {
    #[serde(default = "default_blocks")]
    pub getlogs_max_blocks: u64,
    #[serde(default = "default_results")]
    pub getlogs_max_results: u64,
    #[serde(default = "default_batch")]
    pub batch_max: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            getlogs_max_blocks: default_blocks(),
            getlogs_max_results: default_results(),
            batch_max: default_batch(),
        }
    }
}

fn default_blocks() -> u64 {
    100_000
}
fn default_results() -> u64 {
    100_000
}
fn default_batch() -> usize {
    1000
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default = "default_bind")]
    bind: String,
    #[serde(default)]
    manifests: Vec<PathBuf>,
    #[serde(default)]
    limits: Limits,
    upstream: Option<toml::Value>,
}

fn default_bind() -> String {
    "127.0.0.1:8545".into()
}

pub fn load(path: &Path) -> Result<Config, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("reading {}: {error}", path.display()))?;
    let file: File =
        toml::from_str(&text).map_err(|error| format!("parsing {}: {error}", path.display()))?;
    if file.upstream.is_some() {
        return Err(
            "upstream forwarding is not implemented; remove [upstream] for sealed-only serving"
                .into(),
        );
    }
    if file.limits.getlogs_max_blocks == 0 || file.limits.getlogs_max_results == 0 {
        return Err("getlogs limits must be at least 1".into());
    }
    if file.limits.batch_max == 0 {
        return Err("batch_max must be at least 1".into());
    }
    Ok(Config {
        bind: file.bind,
        manifests: file.manifests,
        limits: file.limits,
    })
}
