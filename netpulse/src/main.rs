//! NetPulse — per-process network traffic monitor.
//!
//! Requires: Linux, root / CAP_BPF + CAP_NET_ADMIN, kernel ≥ 5.8.

mod cli;
mod exporter;
mod loader;
mod model;
mod tui;

use anyhow::{Context, Result, bail};
use clap::Parser;
use log::info;
use tokio::signal;

use cli::{Cli, Mode};
use model::GlobalStore;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialise logger (RUST_LOG env or --verbose flag).
    if cli.verbose {
        // SAFETY: called before any threads are spawned (single-threaded at this point).
        unsafe { std::env::set_var("RUST_LOG", "debug") };
    } else if std::env::var("RUST_LOG").is_err() {
        unsafe { std::env::set_var("RUST_LOG", "info") };
    }
    env_logger::init();

    // Verify we have sufficient privileges.
    check_privileges()?;

    // Shared in-process state.
    let store = GlobalStore::new();

    // Start the eBPF loader + map poller in a background task.
    info!("loading eBPF programs…");
    let _bpf_handle = loader::start(store.clone(), cli.poll_ms)
        .context("failed to start eBPF loader")?;
    info!("eBPF programs loaded and kprobes attached");

    // Dispatch to the chosen operating mode.
    match cli.mode {
        Mode::Tui => {
            tui::run(store.clone(), cli.filter_comm.clone()).await?;
        }

        Mode::Log => {
            let output = cli
                .output
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("netpulse.log"));
            info!("log mode → writing to {}", output.display());

            tokio::select! {
                res = exporter::log::run(
                    store.clone(),
                    output,
                    cli.format.clone(),
                    cli.poll_ms,
                ) => { res?; }
                _ = signal::ctrl_c() => {
                    info!("interrupted");
                }
            }
        }

        Mode::Metrics => {
            info!(
                "metrics mode → http://0.0.0.0:{}/metrics",
                cli.prometheus_port
            );
            tokio::select! {
                res = exporter::prometheus::run(
                    store.clone(),
                    cli.prometheus_port,
                    cli.agg_pid,
                    cli.poll_ms,
                ) => { res?; }
                _ = signal::ctrl_c() => {
                    info!("interrupted");
                }
            }
        }
    }

    info!("netpulse exiting");
    Ok(())
}

/// Die early with a clear message if we don't have the required capabilities.
fn check_privileges() -> Result<()> {
    // A simple heuristic: effective UID == 0 is always fine.
    // TODO: check CAP_BPF + CAP_NET_ADMIN via the `caps` crate for non-root use.
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        bail!(
            "netpulse must run as root (or with CAP_BPF + CAP_NET_ADMIN).\n\
             Try: sudo netpulse"
        );
    }
    Ok(())
}
