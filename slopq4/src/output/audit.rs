use serde::Serialize;

use crate::model::{Asn, Report};

use super::{Formatter, OutputError};

pub struct AuditFormatter;

#[derive(Serialize)]
struct AuditReport<'a> {
    valid_asn_count: usize,
    valid_prefix_count: usize,
    unknown_prefix_count: usize,
    invalid_asns: &'a [Asn],
    invalid_prefixes: &'a [(String, Asn)],
}

impl Formatter for AuditFormatter {
    fn format(&self, report: &Report) -> Result<String, OutputError> {
        let audit = AuditReport {
            valid_asn_count: report.asns.valid.len(),
            valid_prefix_count: report.prefix.valid.len(),
            unknown_prefix_count: report.prefix.unknown.len(),
            invalid_asns: &report.asns.invalid,
            invalid_prefixes: &report.prefix.invalid,
        };
        serde_json::to_string_pretty(&audit).map_err(|e| OutputError::Format(e.to_string()))
    }

    fn file_extension(&self) -> &str {
        "audit.json"
    }

    fn name(&self) -> &str {
        "audit"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AsnReport, PrefixReport, Report};

    fn report() -> Report {
        Report {
            as_set: "AS-TEST".into(),
            asns: AsnReport { valid: vec![1, 2], invalid: vec![99, 100] },
            prefix: PrefixReport {
                valid: vec![("203.0.113.0/24".into(), 1)],
                unknown: vec![("10.0.0.0/8".into(), 1), ("10.1.0.0/16".into(), 2)],
                invalid: vec![("192.0.2.0/24".into(), 99)],
            },
        }
    }

    #[test]
    fn counts_and_invalids() {
        let out = AuditFormatter.format(&report()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["valid_asn_count"], 2);
        assert_eq!(v["valid_prefix_count"], 1);
        assert_eq!(v["unknown_prefix_count"], 2);
        assert_eq!(v["invalid_asns"], serde_json::json!([99, 100]));
        assert_eq!(v["invalid_prefixes"][0][0], "192.0.2.0/24");
    }

    #[test]
    fn valid_prefixes_not_listed() {
        let out = AuditFormatter.format(&report()).unwrap();
        assert!(!out.contains("203.0.113.0/24"));
    }

    #[test]
    fn empty_invalids() {
        let report = Report {
            as_set: "AS-TEST".into(),
            asns: AsnReport { valid: vec![1], invalid: vec![] },
            prefix: PrefixReport { valid: vec![], unknown: vec![], invalid: vec![] },
        };
        let out = AuditFormatter.format(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["valid_asn_count"], 1);
        assert_eq!(v["valid_prefix_count"], 0);
        assert_eq!(v["unknown_prefix_count"], 0);
        assert_eq!(v["invalid_asns"], serde_json::json!([]));
        assert_eq!(v["invalid_prefixes"], serde_json::json!([]));
    }

    #[test]
    fn metadata() {
        assert_eq!(AuditFormatter.file_extension(), "audit.json");
        assert_eq!(AuditFormatter.name(), "audit");
    }
}
