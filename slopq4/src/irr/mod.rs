pub mod client;
pub mod parser;

pub use client::{fetch_routes_with_rpki, IrrClient, IrrConfig};
pub use parser::{IrrFrame, IrrRoute};

#[derive(Debug, thiserror::Error)]
pub enum IrrError {
    #[error("TCP I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("IRR server error: {0}")]
    Server(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("route objects returned without rpki-ov-state; use --rpki-json for local RPKI validation")]
    MissingRpkiState,
}
