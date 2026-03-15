pub mod fetch;
pub mod index;
pub mod parser;

pub use fetch::load_rpki_json;
pub use index::RpkiDb;
pub use parser::parse_rpki_json;

#[derive(Debug, thiserror::Error)]
pub enum RpkiError {
    #[error("HTTP fetch error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Decompression error: {0}")]
    Decompress(String),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Parse error: {0}")]
    Parse(String),
}
