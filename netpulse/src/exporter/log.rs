//! File log / export mode.
//!
//! Appends a snapshot of all connection records to a file every `poll_ms`
//! milliseconds.  Supports JSON (newline-delimited) and formatted Table output.
//!
//! For Table format the column header is written **once** at the start of each
//! run (not repeated on every snapshot), and a blank separator line is inserted
//! between snapshots so the output is easy to `grep` and `tail`.

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
    let mut header_written = false;

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
                // Write the column header once per run.
                if !header_written {
                    writeln!(
                        writer,
                        "{:<8} {:<16} {:<40} {:<15} {:<6} {:<5} {:<11} {:<12} {:<12}  {:#?}",
                        "PID",
                        "COMM",
                        "CMDLINE",
                        "REMOTE IP",
                        "PORT",
                        "PROTO",
                        "STATE",
                        "TX",
                        "RX",
                        "LAST SEEN",
                    )?;
                    writeln!(writer, "{}", "-".repeat(140))?;
                    header_written = true;
                }

                for r in &records {
                    let state_str = r
                        .tcp_state
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_else(|| "-".to_string());

                    // Truncate cmdline so the table stays readable.
                    let cmdline = if r.cmdline.len() > 38 {
                        format!("{}…", &r.cmdline[..37])
                    } else {
                        r.cmdline.clone()
                    };

                    writeln!(
                        writer,
                        "{:<8} {:<16} {:<40} {:<15} {:<6} {:<5} {:<11} {:<12} {:<12}  {}",
                        r.pid,
                        r.comm,
                        cmdline,
                        r.remote_ip,
                        r.remote_port,
                        r.proto.as_str(),
                        state_str,
                        format_bytes(r.tx_bytes),
                        format_bytes(r.rx_bytes),
                        r.last_seen.format("%H:%M:%S%.3f"),
                    )?;
                }
                // Blank line between snapshots.
                writeln!(writer)?;
            }
        }

        writer.flush()?;
    }
}
