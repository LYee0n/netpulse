//! File log / export mode.
//!
//! Appends a snapshot of all connection records to a file every `poll_ms`
//! milliseconds.  Supports JSON (newline-delimited) and formatted Table output.

use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
    path::PathBuf,
    time::Duration,
};

use anyhow::Result;
use log::info;
use tokio::time;

use crate::{
    cli::LogFormat,
    model::{GlobalStore, format_bytes},
};

pub async fn run(
    store: GlobalStore,
    output: PathBuf,
    format: LogFormat,
    poll_ms: u64,
) -> Result<()> {
    info!("log exporter writing to {}", output.display());

    let mut interval = time::interval(Duration::from_millis(poll_ms));

    loop {
        interval.tick().await;

        let records = store.snapshot(true);
        if records.is_empty() {
            continue;
        }

        let file = OpenOptions::new().create(true).append(true).open(&output)?;
        let mut writer = BufWriter::new(file);

        match format {
            LogFormat::Json => {
                for r in &records {
                    let line = serde_json::to_string(r)?;
                    writeln!(writer, "{line}")?;
                }
            }
            LogFormat::Table => {
                // Header once per snapshot.
                writeln!(
                    writer,
                    "{:<8} {:<16} {:<21} {:<6} {:<5} {:<14} {:<14}  {}",
                    "PID", "COMM", "REMOTE IP", "PORT", "PROTO", "TX", "RX", "LAST SEEN"
                )?;
                for r in &records {
                    writeln!(
                        writer,
                        "{:<8} {:<16} {:<21} {:<6} {:<5} {:<14} {:<14}  {}",
                        r.pid,
                        r.comm,
                        r.remote_ip,
                        r.remote_port,
                        r.proto.as_str(),
                        format_bytes(r.tx_bytes),
                        format_bytes(r.rx_bytes),
                        r.last_seen.format("%H:%M:%S%.3f"),
                    )?;
                }
                writeln!(writer, "---")?;
            }
        }

        writer.flush()?;
    }
}
