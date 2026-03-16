use ipnet::IpNet;
use serde::Serialize;

use crate::model::Report;

use super::{Formatter, OutputError};

pub struct SlurmFormatter;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Slurm {
    slurm_version: u8,
    validation_output_filters: ValidationOutputFilters,
    locally_added_assertions: LocallyAddedAssertions,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidationOutputFilters {
    prefix_filters: Vec<serde_json::Value>,
    bgpsec_filters: Vec<serde_json::Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocallyAddedAssertions {
    prefix_assertions: Vec<PrefixAssertion>,
    bgpsec_assertions: Vec<serde_json::Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrefixAssertion {
    asn: u32,
    prefix: String,
    max_prefix_length: u8,
}

impl Formatter for SlurmFormatter {
    fn format(&self, report: &Report) -> Result<String, OutputError> {
        let prefix_assertions = report
            .prefix
            .unknown
            .iter()
            .map(|(prefix_str, asn)| {
                let net: IpNet = prefix_str
                    .parse()
                    .map_err(|e| OutputError::Format(format!("invalid prefix {prefix_str}: {e}")))?;
                Ok(PrefixAssertion {
                    asn: *asn,
                    prefix: prefix_str.clone(),
                    max_prefix_length: net.prefix_len(),
                })
            })
            .collect::<Result<Vec<_>, OutputError>>()?;

        let slurm = Slurm {
            slurm_version: 1,
            validation_output_filters: ValidationOutputFilters {
                prefix_filters: vec![],
                bgpsec_filters: vec![],
            },
            locally_added_assertions: LocallyAddedAssertions {
                prefix_assertions,
                bgpsec_assertions: vec![],
            },
        };

        serde_json::to_string_pretty(&slurm).map_err(|e| OutputError::Format(e.to_string()))
    }

    fn file_extension(&self) -> &str {
        "slurm.json"
    }

    fn name(&self) -> &str {
        "slurm"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AsnReport, PrefixReport, Report};

    fn report(unknown: Vec<(String, u32)>) -> Report {
        Report {
            as_set: "AS-TEST".into(),
            asns: AsnReport { valid: vec![], invalid: vec![] },
            prefix: PrefixReport { valid: vec![], unknown, invalid: vec![] },
        }
    }

    #[test]
    fn empty_unknown() {
        let r = report(vec![]);
        let out = SlurmFormatter.format(&r).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["slurmVersion"], 1);
        assert_eq!(v["locallyAddedAssertions"]["prefixAssertions"], serde_json::json!([]));
    }

    #[test]
    fn ipv4_and_ipv6() {
        let r = report(vec![
            ("199.200.48.0/22".into(), 23286),
            ("2001:db8::/32".into(), 23286),
        ]);
        let out = SlurmFormatter.format(&r).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let assertions = &v["locallyAddedAssertions"]["prefixAssertions"];
        assert_eq!(assertions.as_array().unwrap().len(), 2);
        assert_eq!(assertions[0]["maxPrefixLength"], 22);
        assert_eq!(assertions[1]["maxPrefixLength"], 32);
    }

    #[test]
    fn round_trips() {
        let r = report(vec![("10.0.0.0/8".into(), 64496)]);
        let out = SlurmFormatter.format(&r).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["locallyAddedAssertions"]["prefixAssertions"][0]["asn"], 64496);
        assert_eq!(v["locallyAddedAssertions"]["prefixAssertions"][0]["prefix"], "10.0.0.0/8");
        assert_eq!(v["locallyAddedAssertions"]["prefixAssertions"][0]["maxPrefixLength"], 8);
    }

    #[test]
    fn metadata() {
        assert_eq!(SlurmFormatter.file_extension(), "slurm.json");
        assert_eq!(SlurmFormatter.name(), "slurm");
    }
}
