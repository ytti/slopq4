use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// A 32-bit Autonomous System Number.
pub type Asn = u32;

/// Address-family discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Afi {
    V4,
    V6,
}

/// Dedup key: one unit of work = (AFI, ASN).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkKey {
    pub afi: Afi,
    pub asn: Asn,
}

/// A single IRR route object (prefix + declaring origin ASN).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteObject {
    pub prefix: IpNet,
    pub origin: Asn,
}

/// RPKI validity outcome for a (prefix, origin_asn) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpkiStatus {
    Valid,
    Invalid,
    Unknown,
}

/// A route object annotated with its RPKI status.
#[derive(Debug, Clone)]
pub struct AnnotatedRoute {
    pub route: RouteObject,
    pub rpki: RpkiStatus,
}

/// A single ROA entry as parsed from rpki.json.
#[derive(Debug, Clone)]
pub struct Roa {
    pub asn: Asn,
    pub prefix: IpNet,
    pub max_length: u8,
    pub ta: String,
}

/// The final aggregated report — the library's public output value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub as_set: String,
    #[serde(rename = "as")]
    pub asns: AsnReport,
    pub prefix: PrefixReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnReport {
    pub valid: Vec<Asn>,
    pub invalid: Vec<Asn>,
}

/// Prefix entries serialise as `[prefix_string, origin_asn]` JSON arrays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixReport {
    pub valid: Vec<(String, Asn)>,
    pub unknown: Vec<(String, Asn)>,
    pub invalid: Vec<(String, Asn)>,
}

impl Report {
    pub fn empty() -> Self {
        Self {
            as_set: String::new(),
            asns: AsnReport { valid: vec![], invalid: vec![] },
            prefix: PrefixReport { valid: vec![], unknown: vec![], invalid: vec![] },
        }
    }
}
