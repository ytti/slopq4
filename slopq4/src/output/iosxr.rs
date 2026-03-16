use crate::model::Report;

use super::{Formatter, OutputError};

pub struct IosXrFormatter;

impl Formatter for IosXrFormatter {
    fn format(&self, report: &Report) -> Result<String, OutputError> {
        let mut asns = report.asns.valid.clone();
        asns.sort_unstable();

        let mut lines: Vec<String> = vec![format!("as-set {}", report.as_set)];
        let n = asns.len();
        for (i, asn) in asns.iter().enumerate() {
            if i < n - 1 {
                lines.push(format!("  {},", asn));
            } else {
                lines.push(format!("  {}", asn));
            }
        }
        lines.push("end-set".to_string());
        Ok(lines.join("\n"))
    }

    fn file_extension(&self) -> &str {
        "iosxr"
    }

    fn name(&self) -> &str {
        "iosxr"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AsnReport, PrefixReport, Report};

    fn report(valid: Vec<u32>) -> Report {
        Report {
            as_set: "AS-TEST".into(),
            asns: AsnReport { valid, invalid: vec![] },
            prefix: PrefixReport { valid: vec![], unknown: vec![], invalid: vec![] },
        }
    }

    #[test]
    fn comma_placement() {
        let r = report(vec![100, 200, 300]);
        let out = IosXrFormatter.format(&r).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "as-set AS-TEST");
        assert_eq!(lines[1], "  100,");
        assert_eq!(lines[2], "  200,");
        assert_eq!(lines[3], "  300");   // no trailing comma
        assert_eq!(lines[4], "end-set");
    }

    #[test]
    fn single_asn() {
        let r = report(vec![42]);
        let out = IosXrFormatter.format(&r).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[1], "  42"); // no trailing comma
    }

    #[test]
    fn empty_valid() {
        let r = report(vec![]);
        let out = IosXrFormatter.format(&r).unwrap();
        assert_eq!(out, "as-set AS-TEST\nend-set");
    }

    #[test]
    fn metadata() {
        assert_eq!(IosXrFormatter.file_extension(), "iosxr");
        assert_eq!(IosXrFormatter.name(), "iosxr");
    }
}
