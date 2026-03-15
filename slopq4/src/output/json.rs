use crate::model::Report;

use super::{Formatter, OutputError};

pub struct JsonFormatter;

impl Formatter for JsonFormatter {
    fn format(&self, report: &Report) -> Result<String, OutputError> {
        serde_json::to_string_pretty(report)
            .map_err(|e| OutputError::Format(e.to_string()))
    }

    fn file_extension(&self) -> &str {
        "json"
    }

    fn name(&self) -> &str {
        "json"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AsnReport, PrefixReport, Report};

    #[test]
    fn formats_report_as_valid_json() {
        let report = Report {
            as_set: "AS-TEST".into(),
            asns: AsnReport { valid: vec![42, 500], invalid: vec![] },
            prefix: PrefixReport {
                unknown: vec![("1.2.3.0/24".into(), 42)],
                invalid: vec![],
            },
        };
        let out = JsonFormatter.format(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["as"]["valid"][0], 42);
        assert_eq!(parsed["prefix"]["unknown"][0][0], "1.2.3.0/24");
        assert_eq!(parsed["prefix"]["unknown"][0][1], 42);
    }

    #[test]
    fn round_trips_through_serde() {
        let report = Report {
            as_set: "AS-TEST".into(),
            asns: AsnReport { valid: vec![1], invalid: vec![2] },
            prefix: PrefixReport { unknown: vec![], invalid: vec![("10.0.0.0/8".into(), 1)] },
        };
        let json = JsonFormatter.format(&report).unwrap();
        let back: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(back.asns.valid, vec![1]);
        assert_eq!(back.asns.invalid, vec![2]);
        assert_eq!(back.prefix.invalid[0].0, "10.0.0.0/8");
    }
}
