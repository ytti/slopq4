pub mod client;
pub mod parser;

pub use client::{IrrClient, IrrConfig};
pub use parser::IrrFrame;

#[derive(Debug, thiserror::Error)]
pub enum IrrError {
    #[error("TCP I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("IRR server error: {0}")]
    Server(String),
    #[error("Parse error: {0}")]
    Parse(String),
}
