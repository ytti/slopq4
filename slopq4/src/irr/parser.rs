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
}
