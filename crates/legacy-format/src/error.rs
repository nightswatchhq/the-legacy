use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("canonical JSON: {0}")]
    Jcs(#[from] crate::jcs::JcsError),

    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("bad hex for a 32-byte hash: {0}")]
    Hex(String),

    #[error("manifest is not spec-conformant: {0}")]
    Manifest(String),

    #[error("pact chain broken at relic {index}: {reason}")]
    Pact { index: u64, reason: String },
}
