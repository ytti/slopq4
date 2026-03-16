use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use slopq4::{
    output::{self, FileSink, StdoutSink},
    IrrConfig, Resolver, RpkiDb, load_rpki_json, parse_rpki_json,
};

#[derive(Debug, Clone, ValueEnum)]
enum Format {
    Json,
}

#[derive(Parser)]
#[command(name = "slopq4", about = "Resolve an IRR AS-SET into an RPKI-validated report")]
struct Cli {
    /// AS-SET name to resolve (e.g. AS-EXAMPLE)
    as_set: String,

    /// IRR server host
    #[arg(long, default_value = "rr.ntt.net")]
    irr_host: String,

    /// IRR server port
    #[arg(long, default_value_t = 43)]
    irr_port: u16,

    /// Path to rpki.json or rpki.json.gz for local RPKI validation (overrides IRRd4 rpki-ov-state)
    #[arg(long)]
    rpki_json: Option<PathBuf>,

    /// Output format
    #[arg(long, default_value = "json", value_enum)]
    format: Format,

    /// Output file path (stdout if omitted); supports %AS-SET%, %FORMAT% placeholders
    #[arg(long)]
    output: Option<String>,

    /// Maximum concurrent IRR worker connections
    #[arg(long, default_value_t = 100)]
    workers: usize,

    /// Include RPKI-valid prefixes in JSON output
    #[arg(long)]
    valid_prefixes: bool,

    /// NOS-specific output formats written to {AS-SET}.{ext} files (comma-separated: junos,iosxr)
    #[arg(long, value_delimiter = ',')]
    nos: Vec<String>,

    /// Write RFC 8416 SLURM JSON for unknown prefixes to {AS-SET}.slurm.json
    #[arg(long)]
    slurm: bool,

    /// Write audit JSON (invalid ASNs + invalid prefixes) to {AS-SET}.audit.json
    #[arg(long)]
    audit: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Load local RPKI database only when --rpki-json is explicitly given.
    // Without it, IRRd4's inline rpki-ov-state is used instead.
    let rpki_db: Option<RpkiDb> = match cli.rpki_json.as_deref() {
        Some(path) => {
            let bytes = load_rpki_json(Some(path))
                .await
                .unwrap_or_else(|e| { eprintln!("error: failed to load rpki.json: {e}"); std::process::exit(1) });
            let roas = parse_rpki_json(&bytes)
                .unwrap_or_else(|e| { eprintln!("error: failed to parse rpki.json: {e}"); std::process::exit(1) });
            Some(RpkiDb::build(roas))
        }
        None => None,
    };

    // Resolve AS-SET
    let irr_cfg = IrrConfig { host: cli.irr_host, port: cli.irr_port };
    let resolver = Resolver::new(irr_cfg, rpki_db, cli.workers);

    let mut report = resolver.resolve(&cli.as_set).await.unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1)
    });

    // Select formatter
    let fmt = output::formatter_for(match cli.format {
        Format::Json => "json",
    })
    .unwrap();

    // Strip valid prefixes unless explicitly requested
    if !cli.valid_prefixes {
        report.prefix.valid.clear();
    }

    let has_file_output = !cli.nos.is_empty() || cli.slurm || cli.audit;

    // Default format — stdout (or explicit --output path), skipped when file outputs are requested
    if !has_file_output {
        match &cli.output {
            None => {
                output::render(&report, &*fmt, &mut StdoutSink).unwrap_or_else(|e| {
                    eprintln!("error: output failed: {e}");
                    std::process::exit(1)
                });
            }
            Some(pattern) => {
                use std::collections::HashMap;
                use slopq4::output::custom::TemplateNamer;
                let vars: HashMap<&str, &str> = [
                    ("AS-SET", cli.as_set.as_str()),
                    ("FORMAT", fmt.file_extension()),
                ]
                .into_iter()
                .collect();
                let path = TemplateNamer::new(pattern).resolve(&vars);
                write_file(&report, fmt, path.to_str().unwrap_or_default());
            }
        }
    }

    // NOS formats — each written to {AS-SET}.{extension}
    for nos_name in &cli.nos {
        let nos_fmt = output::formatter_for(nos_name).unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1)
        });
        let filename = format!("{}.{}", cli.as_set, nos_fmt.file_extension());
        write_file(&report, nos_fmt, &filename);
    }

    // SLURM — RFC 8416 JSON for unknown prefixes
    if cli.slurm {
        let filename = format!("{}.slurm.json", cli.as_set);
        write_file(&report, output::formatter_for("slurm").unwrap(), &filename);
    }

    // Audit — invalid ASNs + invalid prefixes
    if cli.audit {
        let filename = format!("{}.audit.json", cli.as_set);
        write_file(&report, output::formatter_for("audit").unwrap(), &filename);
    }
}

fn write_file(report: &slopq4::Report, fmt: Box<dyn output::Formatter>, path: &str) {
    use output::Sink as _;
    let mut sink = FileSink::create(std::path::Path::new(path)).unwrap_or_else(|e| {
        eprintln!("error: cannot open {path}: {e}");
        std::process::exit(1)
    });
    output::render(report, &*fmt, &mut sink).unwrap_or_else(|e| {
        eprintln!("error: output failed for {path}: {e}");
        std::process::exit(1)
    });
    sink.write_str("\n").unwrap_or_else(|e| {
        eprintln!("error: write failed for {path}: {e}");
        std::process::exit(1)
    });
    sink.flush().unwrap_or_else(|e| {
        eprintln!("error: flush failed for {path}: {e}");
        std::process::exit(1)
    });
    eprintln!("wrote {path}");
}
