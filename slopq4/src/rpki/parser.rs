use serde::Deserialize;

use crate::model::{Asn, Roa};

use super::RpkiError;

/// Raw JSON shape as produced by rpki-client.
#[derive(Deserialize)]
struct RpkiJson {
    roas: Vec<RoaRaw>,
}

#[derive(Deserialize)]
struct RoaRaw {
    asn: Asn,
    prefix: String,
    #[serde(rename = "maxLength")]
    max_length: u8,
    ta: String,
}

impl RoaRaw {
    fn into_roa(self) -> Result<Roa, RpkiError> {
        let prefix = self
            .prefix
            .parse()
            .map_err(|e| RpkiError::Parse(format!("invalid prefix {:?}: {}", self.prefix, e)))?;
        Ok(Roa { asn: self.asn, prefix, max_length: self.max_length, ta: self.ta })
    }
}

/// Deserialise rpki-client JSON bytes into a list of ROAs.
pub fn parse_rpki_json(data: &[u8]) -> Result<Vec<Roa>, RpkiError> {
    let raw: RpkiJson = serde_json::from_slice(data)?;
    raw.roas.into_iter().map(RoaRaw::into_roa).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = br#"{
        "metadata": { "generated": 1700000000, "valid": 1700086400 },
        "roas": [
            { "asn": 15562, "prefix": "193.0.0.0/21", "maxLength": 21, "ta": "ripe" },
            { "asn": 64501, "prefix": "192.0.2.0/24", "maxLength": 24, "ta": "arin" }
        ]
    }"#;

    #[test]
    fn parses_roas() {
        let roas = parse_rpki_json(FIXTURE).unwrap();
        assert_eq!(roas.len(), 2);
        assert_eq!(roas[0].asn, 15562);
        assert_eq!(roas[0].prefix.to_string(), "193.0.0.0/21");
        assert_eq!(roas[0].max_length, 21);
        assert_eq!(roas[0].ta, "ripe");
        assert_eq!(roas[1].asn, 64501);
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(parse_rpki_json(b"not json").is_err());
    }

    #[test]
    fn rejects_bad_prefix() {
        let bad = br#"{"roas":[{"asn":64500,"prefix":"not-a-prefix","maxLength":8,"ta":"x"}]}"#;
        assert!(parse_rpki_json(bad).is_err());
    }
}
