use serde::Serialize;

use crate::model::{Asn, Report};

use super::{Formatter, OutputError};

pub struct AuditFormatter;

#[derive(Serialize)]
struct AuditReport<'a> {
    invalid_asns: &'a [Asn],
    invalid_prefixes: &'a [(String, Asn)],
}

impl Formatter for AuditFormatter {
    fn format(&self, report: &Report) -> Result<String, OutputError> {
        let audit = AuditReport {
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

    #[test]
    fn shows_only_invalid() {
        let report = Report {
            as_set: "AS-TEST".into(),
            asns: AsnReport { valid: vec![1, 2], invalid: vec![99, 100] },
            prefix: PrefixReport {
                unknown: vec![("10.0.0.0/8".into(), 1)],
                invalid: vec![("192.0.2.0/24".into(), 99)],
            },
        };
        let out = AuditFormatter.format(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["invalid_asns"], serde_json::json!([99, 100]));
        assert_eq!(v["invalid_prefixes"][0][0], "192.0.2.0/24");
        assert_eq!(v["invalid_prefixes"][0][1], 99);
        // valid ASNs and unknown prefixes must not appear
        assert!(!out.contains("\"1\"") && !out.contains(": 1\n"));
        assert!(!out.contains("10.0.0.0/8"));
    }

    #[test]
    fn empty_invalids() {
        let report = Report {
            as_set: "AS-TEST".into(),
            asns: AsnReport { valid: vec![1], invalid: vec![] },
            prefix: PrefixReport { unknown: vec![], invalid: vec![] },
        };
        let out = AuditFormatter.format(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["invalid_asns"], serde_json::json!([]));
        assert_eq!(v["invalid_prefixes"], serde_json::json!([]));
    }

    #[test]
    fn metadata() {
        assert_eq!(AuditFormatter.file_extension(), "audit.json");
        assert_eq!(AuditFormatter.name(), "audit");
    }
}
