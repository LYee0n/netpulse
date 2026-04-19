//! Prometheus metrics exporter.
//!
//! Exposes a `/metrics` HTTP endpoint (default :9100) compatible with the
//! Prometheus text exposition format.
//!
//! Metric names follow the OpenMetrics convention:
//!   process_network_transmit_bytes_total{pid,comm,remote_ip,remote_port,proto}
//!   process_network_receive_bytes_total{pid,comm,remote_ip,remote_port,proto}
//!
//! When `--agg-pid` is set, the `remote_ip` / `remote_port` labels are omitted
//! and byte counts are summed per PID to avoid cardinality explosion.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{Router, extract::State, routing::get};
use log::info;
use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};
use tokio::time;

use crate::model::{GlobalStore, Protocol};

// ---------------------------------------------------------------------------
// Label sets
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct TrafficLabels {
    pid: String,
    comm: String,
    remote_ip: String,
    remote_port: String,
    proto: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct TrafficLabelsPidOnly {
    pid: String,
    comm: String,
}

// ---------------------------------------------------------------------------
// Shared app state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    registry: Arc<parking_lot::RwLock<Registry>>,
    store: GlobalStore,
    agg_pid: bool,

    // Full-label families
    tx_family: Family<TrafficLabels, Counter>,
    rx_family: Family<TrafficLabels, Counter>,

    // PID-only aggregated families
    tx_agg: Family<TrafficLabelsPidOnly, Counter>,
    rx_agg: Family<TrafficLabelsPidOnly, Counter>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn run(store: GlobalStore, port: u16, agg_pid: bool, poll_ms: u64) -> Result<()> {
    let mut registry = Registry::default();

    let tx_family: Family<TrafficLabels, Counter> = Family::default();
    let rx_family: Family<TrafficLabels, Counter> = Family::default();
    let tx_agg: Family<TrafficLabelsPidOnly, Counter> = Family::default();
    let rx_agg: Family<TrafficLabelsPidOnly, Counter> = Family::default();

    if agg_pid {
        registry.register(
            "process_network_transmit_bytes",
            "Total bytes transmitted by process (PID-aggregated)",
            tx_agg.clone(),
        );
        registry.register(
            "process_network_receive_bytes",
            "Total bytes received by process (PID-aggregated)",
            rx_agg.clone(),
        );
    } else {
        registry.register(
            "process_network_transmit_bytes",
            "Total bytes transmitted by process per remote endpoint",
            tx_family.clone(),
        );
        registry.register(
            "process_network_receive_bytes",
            "Total bytes received by process per remote endpoint",
            rx_family.clone(),
        );
    }

    let state = AppState {
        registry: Arc::new(parking_lot::RwLock::new(registry)),
        store,
        agg_pid,
        tx_family,
        rx_family,
        tx_agg,
        rx_agg,
    };

    // Background task: sync store → prometheus counters every poll_ms.
    let sync_state = state.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_millis(poll_ms));
        loop {
            interval.tick().await;
            sync_metrics(&sync_state);
        }
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Prometheus metrics available at http://{addr}/metrics");

    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(|| async { "ok" }))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

async fn metrics_handler(State(state): State<AppState>) -> String {
    let registry = state.registry.read();
    let mut buf = String::new();
    encode(&mut buf, &*registry).unwrap_or_default();
    buf
}

// ---------------------------------------------------------------------------
// Metric sync
// ---------------------------------------------------------------------------

/// Sync the GlobalStore snapshot into Prometheus counter families.
///
/// Prometheus counters are monotonically increasing, so we derive the delta
/// from the stored "last observed" value and add only the increment.
fn sync_metrics(state: &AppState) {
    let records = state.store.snapshot(true);

    for r in records {
        let pid_s = r.pid.to_string();
        let comm_s = r.comm.clone();
        let ip_s = r.remote_ip.to_string();
        let port_s = r.remote_port.to_string();
        let proto_s = match r.proto {
            Protocol::Tcp => "tcp".to_string(),
            Protocol::Udp => "udp".to_string(),
            Protocol::Unknown(n) => n.to_string(),
        };

        if state.agg_pid {
            let labels = TrafficLabelsPidOnly {
                pid: pid_s,
                comm: comm_s,
            };
            // Counters only go up; we set the absolute value by computing
            // how much the stored counter lags behind the eBPF total.
            add_to_counter(&state.tx_agg.get_or_create(&labels), r.tx_bytes);
            add_to_counter(&state.rx_agg.get_or_create(&labels), r.rx_bytes);
        } else {
            let labels = TrafficLabels {
                pid: pid_s,
                comm: comm_s,
                remote_ip: ip_s,
                remote_port: port_s,
                proto: proto_s,
            };
            add_to_counter(&state.tx_family.get_or_create(&labels), r.tx_bytes);
            add_to_counter(&state.rx_family.get_or_create(&labels), r.rx_bytes);
        }
    }
}

/// Advance a `Counter` to at least `target` by adding the delta.
/// If the counter has already passed `target` (e.g. after a reset) we leave
/// it alone — Prometheus counters must never decrease.
fn add_to_counter(counter: &Counter, target: u64) {
    let current = counter.get();
    if target > current {
        counter.inc_by(target - current);
    }
}
