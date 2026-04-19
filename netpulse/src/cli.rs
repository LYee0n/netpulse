//! Command-line interface definition.

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "netpulse",
    about = "Per-process network traffic monitor (eBPF-powered)",
    version,
    author
)]
pub struct Cli {
    /// Operation mode.
    #[arg(short, long, value_enum, default_value_t = Mode::Tui)]
    pub mode: Mode,

    // -----------------------------------------------------------------------
    // Log / export mode
    // -----------------------------------------------------------------------
    /// File path for log/export output (log mode).
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Output format for log mode.
    #[arg(short = 'f', long, value_enum, default_value_t = LogFormat::Json)]
    pub format: LogFormat,

    // -----------------------------------------------------------------------
    // Prometheus mode
    // -----------------------------------------------------------------------
    /// Port for the built-in Prometheus HTTP server (metrics mode).
    #[arg(short = 'p', long, default_value_t = 9100)]
    pub prometheus_port: u16,

    // -----------------------------------------------------------------------
    // Aggregation / filtering
    // -----------------------------------------------------------------------
    /// Aggregate traffic per PID only (omit per-IP breakdown).
    /// Recommended to avoid label cardinality explosion in Prometheus.
    #[arg(long)]
    pub agg_pid: bool,

    /// Only track processes whose name matches this substring (case-insensitive).
    #[arg(long, value_name = "NAME")]
    pub filter_comm: Option<String>,

    // -----------------------------------------------------------------------
    // eBPF map poll interval
    // -----------------------------------------------------------------------
    /// How often (in milliseconds) to poll the eBPF map.
    #[arg(long, default_value_t = 500)]
    pub poll_ms: u64,

    // -----------------------------------------------------------------------
    // Debug / verbosity
    // -----------------------------------------------------------------------
    /// Enable verbose logging (RUST_LOG=debug equivalent).
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Mode {
    /// Interactive TUI (default).
    Tui,
    /// Continuously append records to a file.
    Log,
    /// Expose a Prometheus /metrics endpoint.
    Metrics,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum LogFormat {
    /// Newline-delimited JSON objects.
    Json,
    /// Human-readable ASCII table rows.
    Table,
}
