pub mod audit;
pub mod custom;
pub mod iosxr;
pub mod json;
pub mod junos;
pub mod slurm;

use std::io::{self, BufWriter, Write};

use crate::model::Report;

pub use audit::AuditFormatter;
pub use custom::TemplateNamer;
pub use iosxr::IosXrFormatter;
pub use json::JsonFormatter;
pub use junos::JunosFormatter;
pub use slurm::SlurmFormatter;

#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Format error: {0}")]
    Format(String),
    #[error("Unknown format: {0}")]
    UnknownFormat(String),
}

/// Converts a `Report` into a formatted string.
pub trait Formatter: Send + Sync {
    fn format(&self, report: &Report) -> Result<String, OutputError>;
    fn file_extension(&self) -> &str;
    fn name(&self) -> &str;
}

/// Accepts rendered output.
pub trait Sink: Send {
    fn write_str(&mut self, data: &str) -> Result<(), OutputError>;
    fn flush(&mut self) -> Result<(), OutputError>;
}

/// Render a report through a formatter into a sink.
pub fn render(
    report: &Report,
    fmt: &dyn Formatter,
    sink: &mut dyn Sink,
) -> Result<(), OutputError> {
    let text = fmt.format(report)?;
    sink.write_str(&text)?;
    sink.flush()
}

/// Look up a formatter by name.
pub fn formatter_for(name: &str) -> Result<Box<dyn Formatter>, OutputError> {
    match name {
        "json"  => Ok(Box::new(JsonFormatter)),
        "junos" => Ok(Box::new(JunosFormatter)),
        "iosxr" => Ok(Box::new(IosXrFormatter)),
        "slurm" => Ok(Box::new(SlurmFormatter)),
        "audit" => Ok(Box::new(AuditFormatter)),
        other   => Err(OutputError::UnknownFormat(other.to_owned())),
    }
}

// --- Concrete sinks ---

/// Writes to stdout.
pub struct StdoutSink;

impl Sink for StdoutSink {
    fn write_str(&mut self, data: &str) -> Result<(), OutputError> {
        print!("{}", data);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), OutputError> {
        io::stdout().flush().map_err(Into::into)
    }
}

/// Writes to a file via a buffered writer.
pub struct FileSink {
    inner: BufWriter<std::fs::File>,
}

impl FileSink {
    pub fn create(path: &std::path::Path) -> Result<Self, OutputError> {
        let f = std::fs::File::create(path)?;
        Ok(Self { inner: BufWriter::new(f) })
    }
}

impl Sink for FileSink {
    fn write_str(&mut self, data: &str) -> Result<(), OutputError> {
        self.inner.write_all(data.as_bytes()).map_err(Into::into)
    }
    fn flush(&mut self) -> Result<(), OutputError> {
        self.inner.flush().map_err(Into::into)
    }
}
