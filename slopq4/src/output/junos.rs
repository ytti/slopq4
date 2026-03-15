use crate::model::{Asn, Report};

use super::{Formatter, OutputError};

pub struct JunosFormatter;

/// Compress a slice of ASNs into (start, end) inclusive ranges.
/// Input need not be sorted — the function sorts internally.
pub fn compress_ranges(asns: &[Asn]) -> Vec<(Asn, Asn)> {
    if asns.is_empty() {
        return vec![];
    }
    let mut sorted = asns.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut ranges: Vec<(Asn, Asn)> = vec![];
    let mut start = sorted[0];
    let mut end = sorted[0];

    for &asn in &sorted[1..] {
        if asn == end + 1 {
            end = asn;
        } else {
            ranges.push((start, end));
            start = asn;
            end = asn;
        }
    }
    ranges.push((start, end));
    ranges
}

impl Formatter for JunosFormatter {
    fn format(&self, report: &Report) -> Result<String, OutputError> {
        let ranges = compress_ranges(&report.asns.valid);
        let mut lines: Vec<String> = Vec::with_capacity(ranges.len());
        for (i, (start, end)) in ranges.iter().enumerate() {
            let members = if start == end {
                format!("{}", start)
            } else {
                format!("{}-{}", start, end)
            };
            lines.push(format!("    as-list l{} members {};", i + 1, members));
        }
        Ok(format!(
            "as-list-group {} {{\n{}\n}}",
            report.as_set,
            lines.join("\n")
        ))
    }

    fn file_extension(&self) -> &str {
        "junos"
    }

    fn name(&self) -> &str {
        "junos"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AsnReport, PrefixReport, Report};

    fn report(valid: Vec<Asn>) -> Report {
        Report {
            as_set: "AS-TEST".into(),
            asns: AsnReport { valid, invalid: vec![] },
            prefix: PrefixReport { unknown: vec![], invalid: vec![] },
        }
    }

    #[test]
    fn compress_empty() {
        assert_eq!(compress_ranges(&[]), vec![]);
    }

    #[test]
    fn compress_single() {
        assert_eq!(compress_ranges(&[42]), vec![(42, 42)]);
    }

    #[test]
    fn compress_consecutive_run() {
        assert_eq!(compress_ranges(&[1, 2, 3]), vec![(1, 3)]);
    }

    #[test]
    fn compress_gaps() {
        assert_eq!(
            compress_ranges(&[1, 3, 4, 10, 11, 12]),
            vec![(1, 1), (3, 4), (10, 12)]
        );
    }

    #[test]
    fn compress_unsorted_input() {
        assert_eq!(compress_ranges(&[5, 1, 2, 3]), vec![(1, 3), (5, 5)]);
    }

    #[test]
    fn format_output() {
        let r = report(vec![1, 2, 3, 10, 20, 21]);
        let out = JunosFormatter.format(&r).unwrap();
        assert!(out.starts_with("as-list-group AS-TEST {"));
        assert!(out.contains("as-list l1 members 1-3;"));
        assert!(out.contains("as-list l2 members 10;"));
        assert!(out.contains("as-list l3 members 20-21;"));
        assert!(out.ends_with('}'));
    }

    #[test]
    fn format_empty_valid() {
        let r = report(vec![]);
        let out = JunosFormatter.format(&r).unwrap();
        assert_eq!(out, "as-list-group AS-TEST {\n\n}");
    }

    #[test]
    fn metadata() {
        assert_eq!(JunosFormatter.file_extension(), "junos");
        assert_eq!(JunosFormatter.name(), "junos");
    }
}
