use ipnet::IpNet;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;

use crate::model::{Afi, Asn};

use super::{
    parser::{parse_asn_list, parse_prefix_list, parse_route_objects, IrrFrame, IrrRoute},
    IrrError,
};

/// Connection configuration for an IRR whois server.
#[derive(Debug, Clone)]
pub struct IrrConfig {
    pub host: String,
    pub port: u16,
}

impl Default for IrrConfig {
    fn default() -> Self {
        Self { host: "rr.ntt.net".into(), port: 43 }
    }
}

/// Async IRR whois client over a persistent TCP connection.
pub struct IrrClient {
    stream: BufStream<TcpStream>,
}

impl IrrClient {
    /// Open a TCP connection and enable multi-query mode with `!!`.
    pub async fn connect(cfg: &IrrConfig) -> Result<Self, IrrError> {
        let tcp = TcpStream::connect((&*cfg.host, cfg.port)).await?;
        let mut stream = BufStream::new(tcp);
        // Enable persistent multi-query mode
        stream.write_all(b"!!\n").await?;
        stream.flush().await?;
        Ok(Self { stream })
    }

    /// Expand an AS-SET recursively into a flat list of ASNs.
    /// Sends `!i<set_name>,1`.
    pub async fn expand_as_set(&mut self, set_name: &str) -> Result<Vec<Asn>, IrrError> {
        let cmd = format!("!i{},1", set_name);
        match self.query(&cmd).await? {
            IrrFrame::Found(data) => Ok(parse_asn_list(&data)),
            IrrFrame::NotFound => Ok(vec![]),
            IrrFrame::Error(msg) => Err(IrrError::Server(msg)),
        }
    }

    /// Fetch IPv4 route objects for an ASN. Sends `!gAS<asn>`.
    pub async fn routes_v4(&mut self, asn: Asn) -> Result<Vec<IpNet>, IrrError> {
        let cmd = format!("!gAS{}", asn);
        self.fetch_routes(&cmd).await
    }

    /// Fetch IPv6 route objects for an ASN. Sends `!6AS<asn>`.
    pub async fn routes_v6(&mut self, asn: Asn) -> Result<Vec<IpNet>, IrrError> {
        let cmd = format!("!6AS{}", asn);
        self.fetch_routes(&cmd).await
    }

    async fn fetch_routes(&mut self, cmd: &str) -> Result<Vec<IpNet>, IrrError> {
        match self.query(cmd).await? {
            IrrFrame::Found(data) => parse_prefix_list(&data),
            IrrFrame::NotFound => Ok(vec![]),
            IrrFrame::Error(msg) => Err(IrrError::Server(msg)),
        }
    }

    /// Send one command and read back a complete framed response.
    async fn query(&mut self, cmd: &str) -> Result<IrrFrame, IrrError> {
        // Send command
        self.stream.write_all(cmd.as_bytes()).await?;
        self.stream.write_all(b"\r\n").await?;
        self.stream.flush().await?;

        // Read first line to determine frame type and length
        let mut first_line = String::new();
        self.stream.read_line(&mut first_line).await?;
        let first = first_line.trim_end_matches(['\r', '\n']);

        if first.starts_with('D') {
            return Ok(IrrFrame::NotFound);
        }
        if let Some(rest) = first.strip_prefix('F') {
            return Ok(IrrFrame::Error(rest.trim().to_owned()));
        }
        if let Some(len_str) = first.strip_prefix('A') {
            let len: usize = len_str
                .trim()
                .parse()
                .map_err(|_| IrrError::Parse(format!("invalid A-frame length: {:?}", len_str)))?;

            let mut data = vec![0u8; len];
            self.stream.read_exact(&mut data).await?;

            // Consume trailing "C\n" or "C\r\n"
            let mut trailer = String::new();
            self.stream.read_line(&mut trailer).await?;

            let text = String::from_utf8(data)
                .map_err(|e| IrrError::Parse(format!("non-UTF8 response: {}", e)))?;
            return Ok(IrrFrame::Found(text));
        }

        Err(IrrError::Parse(format!("unrecognised response line: {:?}", first)))
    }
}

/// Fetch route objects with inline RPKI state for one (ASN, AFI) pair.
///
/// Uses a **non-persistent** (no `!!`) connection so that the server closes
/// after responding, making it safe to `read_to_string` the raw RPSL text.
/// A-frame framing is NOT used for RPSL text queries; only `!` commands are
/// A-frame encoded by IRRd.
///
/// Returns `Err(IrrError::MissingRpkiState)` if any returned object lacks
/// `rpki-ov-state`, signalling that the server does not support inline RPKI.
pub async fn fetch_routes_with_rpki(
    cfg: &IrrConfig,
    asn: Asn,
    afi: Afi,
) -> Result<Vec<IrrRoute>, IrrError> {
    let type_name = match afi {
        Afi::V4 => "route",
        Afi::V6 => "route6",
    };
    let query = format!("-T {} -i origin AS{}\r\n", type_name, asn);

    let tcp = TcpStream::connect((&*cfg.host, cfg.port)).await?;
    let mut stream = BufStream::new(tcp);
    stream.write_all(query.as_bytes()).await?;
    stream.flush().await?;

    // Server closes the connection after the response in non-persistent mode.
    let mut text = String::new();
    stream.read_to_string(&mut text).await?;

    // `%` lines are comment/error markers (e.g. "% No entries found"); skip them.
    // If the entire response is `%`-only or empty, there are no route objects.
    let has_objects = text.lines().any(|l| !l.starts_with('%') && !l.trim().is_empty());
    if !has_objects {
        return Ok(vec![]);
    }

    Ok(deduplicate_routes(parse_route_objects(&text)))
}

/// Deduplicate route objects by prefix, keeping the highest-priority `rpki_ov_state`.
///
/// Priority: `valid` (3) > `not_found` (2) > `None` (1) > other/invalid (0).
/// This collapses IRR + RPKI duplicate entries for the same prefix into one.
fn deduplicate_routes(routes: Vec<IrrRoute>) -> Vec<IrrRoute> {
    use std::collections::HashMap;
    let rank = |s: Option<&str>| match s {
        Some("valid")     => 3,
        Some("not_found") => 2,
        None              => 1,
        _                 => 0,
    };
    let mut best: HashMap<ipnet::IpNet, Option<String>> = HashMap::new();
    for r in routes {
        let entry = best.entry(r.prefix).or_insert(None);
        if rank(r.rpki_ov_state.as_deref()) > rank(entry.as_deref()) {
            *entry = r.rpki_ov_state;
        }
    }
    best.into_iter().map(|(prefix, rpki_ov_state)| IrrRoute { prefix, rpki_ov_state }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Spin up a minimal TCP server that sends a canned response then closes.
    async fn serve_once(response: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Drain whatever the client sends (the query line)
            let mut buf = [0u8; 256];
            let _ = sock.read(&mut buf).await;
            sock.write_all(response.as_bytes()).await.unwrap();
            // Drop sock → TCP FIN → client read_to_string returns
        });
        port
    }

    #[tokio::test]
    async fn fetch_routes_rpki_valid_and_unknown() {
        let body = "\
route:          192.0.2.0/24\n\
origin:         AS64496\n\
rpki-ov-state:  valid\n\
\n\
route:          198.51.100.0/24\n\
origin:         AS64496\n\
rpki-ov-state:  not_found\n\
";
        let port = serve_once(body).await;
        let cfg = IrrConfig { host: "127.0.0.1".into(), port };
        let mut routes = fetch_routes_with_rpki(&cfg, 64496, Afi::V4).await.unwrap();
        routes.sort_by_key(|r| r.prefix.to_string());
        assert_eq!(routes.len(), 2);
        // 192.0.2.0/24 < 198.51.100.0/24
        assert_eq!(routes[0].rpki_ov_state.as_deref(), Some("valid"));
        assert_eq!(routes[1].rpki_ov_state.as_deref(), Some("not_found"));
    }

    #[tokio::test]
    async fn fetch_routes_rpki_empty_percent_response() {
        let port = serve_once("% No entries found\n\n").await;
        let cfg = IrrConfig { host: "127.0.0.1".into(), port };
        let routes = fetch_routes_with_rpki(&cfg, 64496, Afi::V4).await.unwrap();
        assert!(routes.is_empty());
    }

    #[tokio::test]
    async fn fetch_routes_rpki_missing_state_becomes_none() {
        let body = "route:          192.0.2.0/24\norigin:         AS64496\n\n";
        let port = serve_once(body).await;
        let cfg = IrrConfig { host: "127.0.0.1".into(), port };
        let routes = fetch_routes_with_rpki(&cfg, 64496, Afi::V4).await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].rpki_ov_state, None);
    }

    #[tokio::test]
    async fn fetch_routes_rpki_crlf_and_inline_comment() {
        // Simulate a real rr.ntt.net response with CRLF and inline comment
        let body = "route:          192.0.2.0/24\r\norigin:         AS64496\r\nrpki-ov-state:  not_found # No ROAs found\r\n\r\n";
        let port = serve_once(body).await;
        let cfg = IrrConfig { host: "127.0.0.1".into(), port };
        let routes = fetch_routes_with_rpki(&cfg, 64496, Afi::V4).await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].rpki_ov_state.as_deref(), Some("not_found"));
    }

    #[tokio::test]
    async fn fetch_routes_dedup_irr_plus_rpki_source() {
        // IRRd4 real-world: same prefix returned twice — IRR object (not_found) + RPKI object (implicit valid)
        let body = "\
route:          123.253.124.0/22\n\
origin:         AS133469\n\
source:         APNIC\n\
rpki-ov-state:  valid\n\
\n\
route:          123.253.124.0/22\n\
origin:         AS133469\n\
source:         RPKI  # Trust Anchor: apnic\n\
\n";
        let port = serve_once(body).await;
        let cfg = IrrConfig { host: "127.0.0.1".into(), port };
        let routes = fetch_routes_with_rpki(&cfg, 133469, Afi::V4).await.unwrap();
        // Must deduplicate to exactly one entry with the best status
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].rpki_ov_state.as_deref(), Some("valid"));
    }

    #[tokio::test]
    async fn fetch_routes_dedup_rpki_only_beats_not_found() {
        let body = "\
route:          10.0.0.0/8\n\
origin:         AS64496\n\
source:         APNIC\n\
rpki-ov-state:  not_found\n\
\n\
route:          10.0.0.0/8\n\
origin:         AS64496\n\
source:         RPKI\n\
\n";
        let port = serve_once(body).await;
        let cfg = IrrConfig { host: "127.0.0.1".into(), port };
        let routes = fetch_routes_with_rpki(&cfg, 64496, Afi::V4).await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].rpki_ov_state.as_deref(), Some("valid"));
    }
}
