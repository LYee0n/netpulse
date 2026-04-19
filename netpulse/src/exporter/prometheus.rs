//! Prometheus metrics exporter.
//!
//! Exposes a `/metrics` HTTP endpoint (default :9100) compatible with the
//! Prometheus text exposition format.
//!
//! ## Metric names
//!
//!   process_network_transmit_bytes_total{pid,comm,remote_ip,remote_port,proto}
//!   process_network_receive_bytes_total{pid,comm,remote_ip,remote_port,proto}
//!
//! When `--agg-pid` is set, the `remote_ip` / `remote_port` labels are omitted
//! and byte counts are summed per PID to avoid cardinality explosion.
//!
//! ## Time window
//!
//! The `/metrics` endpoint accepts an optional `window` query parameter:
//!
//!   GET /metrics?window=5          → only connections seen in the last 5 s
//!   GET /metrics?window=30         → last 30 s
//!   GET /metrics                   → all connections since monitoring start
//!
//! This lets Prometheus users choose between a "recent activity" view and a
//! monotonically-accumulating total.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Router,
    extract::{Query, State},
    routing::get,
};
use log::info;
use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};
use serde::Deserialize;
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
    /// The store used for the "all time" (no window) default view.
    store: GlobalStore,
    agg_pid: bool,
    /// Default window in seconds for /metrics requests with no ?window= param.
    /// 0 means "all connections since start".
    default_window: u64,

    // Full-label families (all-time cumulative)
    tx_family: Family<TrafficLabels, Counter>,
    rx_family: Family<TrafficLabels, Counter>,

    // PID-only aggregated families (all-time cumulative)
    tx_agg: Family<TrafficLabelsPidOnly, Counter>,
    rx_agg: Family<TrafficLabelsPidOnly, Counter>,

    // We hold a separate registry for the synced counters.
    registry: Arc<parking_lot::RwLock<Registry>>,
}

// ---------------------------------------------------------------------------
// Query parameters
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct MetricsQuery {
    /// Optional time window in seconds.  If provided, only connections first
    /// seen within the last `window` seconds are included.
    window: Option<u64>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn run(
    store: GlobalStore,
    port: u16,
    agg_pid: bool,
    poll_ms: u64,
    default_window: u64,
) -> Result<()> {
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
        store,
        agg_pid,
        default_window,
        tx_family,
        rx_family,
        tx_agg,
        rx_agg,
        registry: Arc::new(parking_lot::RwLock::new(registry)),
    };

    // Background task: sync store → prometheus counters every poll_ms.
    let sync_state = state.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_millis(poll_ms));
        loop {
            interval.tick().await;
            let window = if sync_state.default_window > 0 {
                Some(sync_state.default_window)
            } else {
                None
            };
            sync_metrics(&sync_state, window);
        }
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Prometheus metrics available at http://{addr}/metrics");
    info!("  Options: /metrics?window=<secs>  (only connections from last N seconds)");

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

async fn metrics_handler(
    State(state): State<AppState>,
    Query(params): Query<MetricsQuery>,
) -> String {
    // Resolve effective window: explicit query param → default_window → all-time.
    let effective_window = params.window.or(if state.default_window > 0 {
        Some(state.default_window)
    } else {
        None
    });

    if let Some(window_secs) = effective_window {
        // For windowed requests we build a fresh on-the-fly registry so that
        // we return only the snapshot for that window without polluting the
        // main background-synced registry.
        build_windowed_metrics(&state, window_secs)
    } else {
        // Return the background-synced all-time registry.
        let registry = state.registry.read();
        let mut buf = String::new();
        encode(&mut buf, &*registry).unwrap_or_default();
        buf
    }
}

/// Build a Prometheus text payload for connections first seen within the last
/// `window_secs` seconds — without touching the persistent families.
fn build_windowed_metrics(state: &AppState, window_secs: u64) -> String {
    let mut registry = Registry::default();

    let tx_family: Family<TrafficLabels, Counter> = Family::default();
    let rx_family: Family<TrafficLabels, Counter> = Family::default();
    let tx_agg: Family<TrafficLabelsPidOnly, Counter> = Family::default();
    let rx_agg: Family<TrafficLabelsPidOnly, Counter> = Family::default();

    if state.agg_pid {
        registry.register(
            "process_network_transmit_bytes",
            &format!("TX bytes (last {window_secs}s window)"),
            tx_agg.clone(),
        );
        registry.register(
            "process_network_receive_bytes",
            &format!("RX bytes (last {window_secs}s window)"),
            rx_agg.clone(),
        );
    } else {
        registry.register(
            "process_network_transmit_bytes",
            &format!("TX bytes per endpoint (last {window_secs}s window)"),
            tx_family.clone(),
        );
        registry.register(
            "process_network_receive_bytes",
            &format!("RX bytes per endpoint (last {window_secs}s window)"),
            rx_family.clone(),
        );
    }

    let records = state.store.snapshot_window(true, window_secs);
    for r in records {
        let pid_s = r.pid.to_string();
        let comm_s = r.comm.clone();
        let ip_s = r.remote_ip.to_string();
        let port_s = r.remote_port.to_string();
        let proto_s = proto_str(r.proto);

        if state.agg_pid {
            let labels = TrafficLabelsPidOnly {
                pid: pid_s,
                comm: comm_s,
            };
            add_to_counter(&tx_agg.get_or_create(&labels), r.tx_bytes);
            add_to_counter(&rx_agg.get_or_create(&labels), r.rx_bytes);
        } else {
            let labels = TrafficLabels {
                pid: pid_s,
                comm: comm_s,
                remote_ip: ip_s,
                remote_port: port_s,
                proto: proto_s,
            };
            add_to_counter(&tx_family.get_or_create(&labels), r.tx_bytes);
            add_to_counter(&rx_family.get_or_create(&labels), r.rx_bytes);
        }
    }

    let mut buf = String::new();
    encode(&mut buf, &registry).unwrap_or_default();
    buf
}

// ---------------------------------------------------------------------------
// Background metric sync
// ---------------------------------------------------------------------------

/// Sync the GlobalStore snapshot into Prometheus counter families.
///
/// Prometheus counters are monotonically increasing, so we derive the delta
/// from the stored "last observed" value and add only the increment.
///
/// When `window_secs` is `Some`, only connections first seen within that
/// window are considered.
fn sync_metrics(state: &AppState, window_secs: Option<u64>) {
    let records = match window_secs {
        Some(w) => state.store.snapshot_window(true, w),
        None => state.store.snapshot(true),
    };

    for r in records {
        let pid_s = r.pid.to_string();
        let comm_s = r.comm.clone();
        let ip_s = r.remote_ip.to_string();
        let port_s = r.remote_port.to_string();
        let proto_s = proto_str(r.proto);

        if state.agg_pid {
            let labels = TrafficLabelsPidOnly {
                pid: pid_s,
                comm: comm_s,
            };
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn proto_str(proto: Protocol) -> String {
    match proto {
        Protocol::Tcp => "tcp".to_string(),
        Protocol::Udp => "udp".to_string(),
        Protocol::Unknown(n) => n.to_string(),
    }
}

/// Advance a `Counter` to at least `target` by adding the delta.
/// If the counter has already passed `target` we leave it alone — Prometheus
/// counters must never decrease.
fn add_to_counter(counter: &Counter, target: u64) {
    let current = counter.get();
    if target > current {
        counter.inc_by(target - current);
    }
}
