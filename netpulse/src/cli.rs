//! Command-line interface definition.

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "netpulse",
    about = "Per-process network traffic monitor (eBPF-powered)",
    long_about = "NetPulse attaches kprobes to tcp_sendmsg, tcp_recvmsg, udp_sendmsg, udp_recvmsg \
                  and records cumulative byte counts per (pid, remote_ip, remote_port, proto).\n\n\
                  Requires root or CAP_BPF + CAP_NET_ADMIN.  Linux kernel ≥ 5.8.",
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

    /// Default time window (seconds) for the /metrics endpoint.
    ///
    /// When set, GET /metrics returns only connections first seen within
    /// the last N seconds by default (equivalent to ?window=N).
    /// Individual requests can still override with ?window=<secs>.
    /// 0 = all connections since monitoring start (the default behaviour).
    #[arg(long, default_value_t = 0, value_name = "SECS")]
    pub metrics_window: u64,

    // -----------------------------------------------------------------------
    // Aggregation / filtering
    // -----------------------------------------------------------------------
    /// Aggregate traffic per PID only (omit per-IP breakdown).
    /// Recommended to avoid label cardinality explosion in Prometheus.
    #[arg(long)]
    pub agg_pid: bool,

    /// Only track processes whose name or cmdline matches this substring
    /// (case-insensitive).  Can also be set interactively in TUI with [/].
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
