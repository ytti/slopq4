use ipnet::IpNet;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;

use crate::model::Asn;

use super::{
    parser::{parse_asn_list, parse_prefix_list, IrrFrame},
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
