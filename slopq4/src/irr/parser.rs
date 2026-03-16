use ipnet::IpNet;

use crate::model::Asn;

use super::IrrError;

/// Parsed response frame from the IRR whois protocol.
#[derive(Debug, PartialEq, Eq)]
pub enum IrrFrame {
    Found(String),
    NotFound,
    Error(String),
}

/// Parse a complete raw response from the IRR server into a frame.
///
/// Protocol:
/// - `A<n>\n<data>C\n` — found, <n> bytes of data
/// - `D\n`             — not found
/// - `F <msg>\n`       — error
pub fn parse_frame(raw: &str) -> Result<IrrFrame, IrrError> {
    if raw.starts_with('D') {
        return Ok(IrrFrame::NotFound);
    }
    if let Some(rest) = raw.strip_prefix('F') {
        return Ok(IrrFrame::Error(rest.trim().to_owned()));
    }
    if let Some(rest) = raw.strip_prefix('A') {
        let newline = rest
            .find('\n')
            .ok_or_else(|| IrrError::Parse("missing newline after A<n>".into()))?;
        let len_str = &rest[..newline];
        let len: usize = len_str
            .trim()
            .parse()
            .map_err(|_| IrrError::Parse(format!("invalid length field: {:?}", len_str)))?;
        let data_start = newline + 1;
        if rest.len() < data_start + len {
            return Err(IrrError::Parse("frame truncated".into()));
        }
        let data = &rest[data_start..data_start + len];
        return Ok(IrrFrame::Found(data.to_owned()));
    }
    Err(IrrError::Parse(format!("unrecognised frame: {:?}", &raw[..raw.len().min(32)])))
}

/// Parse a Found frame payload into a list of ASNs.
///
/// Handles both space-separated (`AS1 AS2`) and newline-separated formats.
/// Tokens without `AS` prefix (bare numbers) are also accepted.
pub fn parse_asn_list(data: &str) -> Vec<Asn> {
    data.split_whitespace()
        .filter_map(|tok| {
            let num = tok.strip_prefix("AS").unwrap_or(tok);
            num.parse::<Asn>().ok()
        })
        .collect()
}

/// A route object returned by IRRd4, with optional inline RPKI validation state.
#[derive(Debug, PartialEq, Eq)]
pub struct IrrRoute {
    pub prefix: IpNet,
    /// Value of the `rpki-ov-state:` attribute, or `None` if absent.
    pub rpki_ov_state: Option<String>,
}

/// Parse a Found frame payload containing RPSL route objects into `IrrRoute` entries.
///
/// Objects are separated by blank lines. Each object must have a `route:` or
/// `route6:` attribute; objects without a parseable prefix are silently skipped.
///
/// Handles CRLF line endings and strips inline RPSL comments (`# ...`).
pub fn parse_route_objects(data: &str) -> Vec<IrrRoute> {
    // Normalise CRLF → LF so blank-line splitting works regardless of server line endings.
    let normalised;
    let data = if data.contains('\r') {
        normalised = data.replace("\r\n", "\n").replace('\r', "\n");
        &*normalised
    } else {
        data
    };

    data.split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .filter_map(|block| {
            let mut prefix: Option<IpNet> = None;
            let mut rpki_ov_state: Option<String> = None;
            let mut source: Option<String> = None;

            for line in block.lines() {
                // Helper: strip inline comment and surrounding whitespace.
                let value_of = |rest: &str| -> String {
                    rest.trim().split('#').next().unwrap_or("").trim().to_owned()
                };

                if let Some(rest) = line.strip_prefix("route6:").or_else(|| line.strip_prefix("route:")) {
                    if prefix.is_none() {
                        let v = value_of(rest);
                        prefix = v.parse::<IpNet>().ok();
                    }
                } else if let Some(rest) = line.strip_prefix("rpki-ov-state:") {
                    let v = value_of(rest);
                    if !v.is_empty() {
                        rpki_ov_state = Some(v);
                    }
                } else if let Some(rest) = line.strip_prefix("source:") {
                    let v = value_of(rest);
                    if !v.is_empty() {
                        source = Some(v);
                    }
                }
            }

            // Objects with `source: RPKI` are auto-generated from ROA data — implicitly valid.
            if source.as_deref().map(|s| s.eq_ignore_ascii_case("RPKI")).unwrap_or(false) {
                rpki_ov_state = Some("valid".to_owned());
            }

            prefix.map(|p| IrrRoute { prefix: p, rpki_ov_state })
        })
        .collect()
}

/// Parse a Found frame payload into a list of IP prefixes.
pub fn parse_prefix_list(data: &str) -> Result<Vec<IpNet>, IrrError> {
    data.split_whitespace()
        .map(|tok| {
            tok.parse::<IpNet>()
                .map_err(|e| IrrError::Parse(format!("invalid prefix {:?}: {}", tok, e)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_found_frame() {
        let raw = "A15\nAS64501 AS64502\nC\n";
        let frame = parse_frame(raw).unwrap();
        assert_eq!(frame, IrrFrame::Found("AS64501 AS64502".to_owned()));
    }

    #[test]
    fn parse_not_found() {
        assert_eq!(parse_frame("D\n").unwrap(), IrrFrame::NotFound);
    }

    #[test]
    fn parse_error_frame() {
        match parse_frame("F no such set\n").unwrap() {
            IrrFrame::Error(msg) => assert_eq!(msg, "no such set"),
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn parse_asn_list_space_separated() {
        let asns = parse_asn_list("AS64501 AS64502 AS65000");
        assert_eq!(asns, vec![64501, 64502, 65000]);
    }

    #[test]
    fn parse_asn_list_newline_separated() {
        let asns = parse_asn_list("AS1\nAS2\nAS3\n");
        assert_eq!(asns, vec![1, 2, 3]);
    }

    #[test]
    fn parse_asn_list_bare_numbers() {
        let asns = parse_asn_list("64501 64502");
        assert_eq!(asns, vec![64501, 64502]);
    }

    #[test]
    fn parse_prefix_list_v4() {
        let prefixes = parse_prefix_list("192.0.2.0/24 198.51.100.0/24").unwrap();
        assert_eq!(prefixes.len(), 2);
        assert_eq!(prefixes[0].to_string(), "192.0.2.0/24");
    }

    #[test]
    fn parse_prefix_list_v6() {
        let prefixes = parse_prefix_list("2001:db8::/32").unwrap();
        assert_eq!(prefixes[0].to_string(), "2001:db8::/32");
    }

    #[test]
    fn parse_prefix_list_invalid() {
        assert!(parse_prefix_list("not-a-prefix").is_err());
    }

    #[test]
    fn parse_frame_truncated() {
        // A says 100 bytes but only 3 are present
        assert!(parse_frame("A100\nabc").is_err());
    }

    #[test]
    fn parse_frame_unknown() {
        assert!(parse_frame("X something\n").is_err());
    }

    // --- parse_route_objects ---

    const RPSL_V4: &str = "\
route:          192.0.2.0/24\n\
descr:          Test\n\
origin:         AS64496\n\
rpki-ov-state:  valid\n";

    const RPSL_V6: &str = "\
route6:         2001:db8::/32\n\
origin:         AS64496\n\
rpki-ov-state:  not_found\n";

    #[test]
    fn route_objects_single_v4_valid() {
        let routes = parse_route_objects(RPSL_V4);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix.to_string(), "192.0.2.0/24");
        assert_eq!(routes[0].rpki_ov_state, Some("valid".into()));
    }

    #[test]
    fn route_objects_single_v6_not_found() {
        let routes = parse_route_objects(RPSL_V6);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix.to_string(), "2001:db8::/32");
        assert_eq!(routes[0].rpki_ov_state, Some("not_found".into()));
    }

    #[test]
    fn route_objects_no_rpki_state() {
        let data = "route:          10.0.0.0/8\norigin:         AS64496\n";
        let routes = parse_route_objects(data);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].rpki_ov_state, None);
    }

    #[test]
    fn route_objects_multiple() {
        let data = format!("{}\n{}", RPSL_V4, RPSL_V6);
        let routes = parse_route_objects(&data);
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn route_objects_trailing_blank_line() {
        let data = format!("{}\n\n", RPSL_V4);
        let routes = parse_route_objects(&data);
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn route_objects_empty_input() {
        assert_eq!(parse_route_objects(""), vec![]);
    }

    #[test]
    fn route_objects_crlf_line_endings() {
        let data = "route:          192.0.2.0/24\r\norigin:         AS64496\r\nrpki-ov-state:  valid\r\n\r\nroute:          198.51.100.0/24\r\norigin:         AS64496\r\nrpki-ov-state:  not_found\r\n";
        let routes = parse_route_objects(data);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].rpki_ov_state.as_deref(), Some("valid"));
        assert_eq!(routes[1].rpki_ov_state.as_deref(), Some("not_found"));
    }

    #[test]
    fn route_objects_inline_comment_stripped() {
        let data = "route:          192.0.2.0/24\norigin:         AS64496\nrpki-ov-state:  not_found # No ROAs found, or RPKI validation not enabled for source\n";
        let routes = parse_route_objects(data);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].rpki_ov_state.as_deref(), Some("not_found"));
    }

    #[test]
    fn route_objects_rpki_source_is_valid() {
        let data = "\
route:          192.0.2.0/24\n\
origin:         AS64496\n\
source:         RPKI\n";
        let routes = parse_route_objects(data);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].rpki_ov_state.as_deref(), Some("valid"));
    }

    #[test]
    fn route_objects_rpki_source_with_comment() {
        let data = "\
route:          192.0.2.0/24\n\
origin:         AS64496\n\
source:         RPKI  # Trust Anchor: apnic\n";
        let routes = parse_route_objects(data);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].rpki_ov_state.as_deref(), Some("valid"));
    }

    #[test]
    fn route_objects_irr_source_unaffected() {
        let data = "\
route:          192.0.2.0/24\n\
origin:         AS64496\n\
source:         APNIC\n\
rpki-ov-state:  not_found\n";
        let routes = parse_route_objects(data);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].rpki_ov_state.as_deref(), Some("not_found"));
    }
}
