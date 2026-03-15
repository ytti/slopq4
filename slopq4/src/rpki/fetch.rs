use std::io::Read;
use std::path::Path;

use flate2::read::GzDecoder;

use super::RpkiError;

const RPKI_JSON_URL: &str = "https://console.rpki-client.org/rpki.json.gz";

/// Load rpki-client JSON data.
///
/// - `Some(path)` — read from local file (plain JSON or gzipped by extension)
/// - `None`       — fetch `rpki.json.gz` from the internet, decompress in memory
pub async fn load_rpki_json(path: Option<&Path>) -> Result<Vec<u8>, RpkiError> {
    match path {
        Some(p) => read_local(p).await,
        None => fetch_remote().await,
    }
}

async fn read_local(path: &Path) -> Result<Vec<u8>, RpkiError> {
    let bytes = tokio::fs::read(path).await?;
    // Decompress if the file is gzipped
    if path.extension().and_then(|e| e.to_str()) == Some("gz") {
        decompress(&bytes)
    } else {
        Ok(bytes)
    }
}

async fn fetch_remote() -> Result<Vec<u8>, RpkiError> {
    let bytes = reqwest::get(RPKI_JSON_URL).await?.bytes().await?;
    decompress(&bytes)
}

fn decompress(data: &[u8]) -> Result<Vec<u8>, RpkiError> {
    let mut decoder = GzDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| RpkiError::Decompress(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_local_plain_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpki.json");
        tokio::fs::write(&path, br#"{"roas":[]}"# as &[u8]).await.unwrap();
        let data = load_rpki_json(Some(&path)).await.unwrap();
        assert_eq!(data, br#"{"roas":[]}"#);
    }

    #[tokio::test]
    async fn reads_local_gzipped_json() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpki.json.gz");
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(br#"{"roas":[]}"#).unwrap();
        let compressed = enc.finish().unwrap();
        tokio::fs::write(&path, compressed.as_slice()).await.unwrap();
        let data = load_rpki_json(Some(&path)).await.unwrap();
        assert_eq!(data, br#"{"roas":[]}"#);
    }
}
