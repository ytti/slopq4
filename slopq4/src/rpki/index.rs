use std::collections::HashMap;

use ipnet::IpNet;

use crate::model::{Asn, Roa, RpkiStatus};

/// In-memory index of ROAs for fast validation lookups.
pub struct RpkiDb {
    roas: Vec<Roa>,
    /// Maps ASN → indices into `roas` for O(1) existence check.
    by_asn: HashMap<Asn, Vec<usize>>,
}

impl RpkiDb {
    /// Build the index from a list of ROAs.
    pub fn build(roas: Vec<Roa>) -> Self {
        let mut by_asn: HashMap<Asn, Vec<usize>> = HashMap::new();
        for (i, roa) in roas.iter().enumerate() {
            by_asn.entry(roa.asn).or_default().push(i);
        }
        Self { roas, by_asn }
    }

    /// Validate a (prefix, origin_asn) pair against the ROA database.
    ///
    /// - `Valid`   — a covering ROA exists with matching ASN and length ≤ maxLength
    /// - `Invalid` — a covering ROA exists but ASN or length doesn't match
    /// - `Unknown` — no ROA covers the prefix at all
    pub fn validate(&self, prefix: IpNet, origin: Asn) -> RpkiStatus {
        let mut covered = false;

        for roa in &self.roas {
            if roa.prefix.contains(&prefix) {
                covered = true;
                if roa.asn == origin && prefix.prefix_len() <= roa.max_length {
                    return RpkiStatus::Valid;
                }
            }
        }

        if covered { RpkiStatus::Invalid } else { RpkiStatus::Unknown }
    }

    /// Return `true` if any ROA exists with this ASN as origin.
    pub fn asn_has_roa(&self, asn: Asn) -> bool {
        self.by_asn.contains_key(&asn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Roa;

    fn roa(asn: Asn, prefix: &str, max_length: u8) -> Roa {
        Roa { asn, prefix: prefix.parse().unwrap(), max_length, ta: "test".into() }
    }

    fn db() -> RpkiDb {
        RpkiDb::build(vec![
            roa(64501, "192.0.2.0/24", 24),
            roa(64502, "198.51.100.0/24", 26),
            roa(64503, "203.0.113.0/24", 24),
        ])
    }

    #[test]
    fn valid_exact_match() {
        assert_eq!(
            db().validate("192.0.2.0/24".parse().unwrap(), 64501),
            RpkiStatus::Valid
        );
    }

    #[test]
    fn valid_more_specific_within_max_length() {
        // ROA covers /24 with maxLength 26; a /25 should be valid for the same ASN
        let d = RpkiDb::build(vec![roa(64501, "192.0.2.0/24", 26)]);
        assert_eq!(
            d.validate("192.0.2.0/25".parse().unwrap(), 64501),
            RpkiStatus::Valid
        );
    }

    #[test]
    fn invalid_wrong_asn() {
        assert_eq!(
            db().validate("192.0.2.0/24".parse().unwrap(), 99999),
            RpkiStatus::Invalid
        );
    }

    #[test]
    fn invalid_too_specific() {
        // ROA maxLength is 26; /27 is more specific → invalid
        assert_eq!(
            db().validate("198.51.100.0/27".parse().unwrap(), 64502),
            RpkiStatus::Invalid
        );
    }

    #[test]
    fn unknown_no_covering_roa() {
        assert_eq!(
            db().validate("10.0.0.0/8".parse().unwrap(), 64501),
            RpkiStatus::Unknown
        );
    }

    #[test]
    fn asn_has_roa_present() {
        assert!(db().asn_has_roa(64501));
    }

    #[test]
    fn asn_has_roa_absent() {
        assert!(!db().asn_has_roa(99999));
    }

    #[test]
    fn supernet_covers_more_specific() {
        // ROA is /21; route is /24 inside it
        let d = RpkiDb::build(vec![roa(15562, "193.0.0.0/21", 24)]);
        assert_eq!(
            d.validate("193.0.0.0/24".parse().unwrap(), 15562),
            RpkiStatus::Valid
        );
    }
}
