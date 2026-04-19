//! In-process data model.
//!
//! The `GlobalStore` keeps a permanent history of every observed connection
//! keyed by `(pid, remote_ip, remote_port, proto)`.  Entries are never
//! evicted while the process is running so that short-lived connections
//! (curl, nslookup …) are not lost between TUI refresh cycles.

use std::{collections::HashMap, net::Ipv4Addr, sync::Arc, time::Instant};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::Serialize;

use netpulse_common::{
    PROTO_TCP, PROTO_UDP, TCP_CLOSE, TCP_CLOSE_WAIT, TCP_CLOSING, TCP_ESTABLISHED, TCP_FIN_WAIT1,
    TCP_FIN_WAIT2, TCP_LAST_ACK, TCP_LISTEN, TCP_SYN_RECV, TCP_SYN_SENT, TCP_TIME_WAIT, TrafficKey,
    TrafficValue,
};

// ---------------------------------------------------------------------------
// TCP state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TcpState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Unknown(u8),
}

impl TcpState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TcpState::Established => "ESTABLISHED",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynRecv => "SYN_RECV",
            TcpState::FinWait1 => "FIN_WAIT1",
            TcpState::FinWait2 => "FIN_WAIT2",
            TcpState::TimeWait => "TIME_WAIT",
            TcpState::Close => "CLOSE",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::LastAck => "LAST_ACK",
            TcpState::Listen => "LISTEN",
            TcpState::Closing => "CLOSING",
            TcpState::Unknown(_) => "?",
        }
    }
}

impl From<u8> for TcpState {
    fn from(v: u8) -> Self {
        match v {
            TCP_ESTABLISHED => TcpState::Established,
            TCP_SYN_SENT => TcpState::SynSent,
            TCP_SYN_RECV => TcpState::SynRecv,
            TCP_FIN_WAIT1 => TcpState::FinWait1,
            TCP_FIN_WAIT2 => TcpState::FinWait2,
            TCP_TIME_WAIT => TcpState::TimeWait,
            TCP_CLOSE => TcpState::Close,
            TCP_CLOSE_WAIT => TcpState::CloseWait,
            TCP_LAST_ACK => TcpState::LastAck,
            TCP_LISTEN => TcpState::Listen,
            TCP_CLOSING => TcpState::Closing,
            other => TcpState::Unknown(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Public connection record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionRecord {
    pub pid: u32,
    /// Short process name from `comm` (up to 15 chars, always available).
    pub comm: String,
    /// Full command line from `/proc/<pid>/cmdline`; falls back to `comm`.
    pub cmdline: String,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub local_port: u16,
    pub proto: Protocol,
    /// TCP connection state; `None` for UDP or unknown.
    pub tcp_state: Option<TcpState>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    /// Cumulative TX at the time of the last manual reset (for delta display).
    pub tx_bytes_at_reset: u64,
    /// Cumulative RX at the time of the last manual reset (for delta display).
    pub rx_bytes_at_reset: u64,
    /// Wall-clock time of the last eBPF event for this entry.
    pub last_seen: DateTime<Utc>,
    /// Monotonic instant when this record was first inserted.
    #[serde(skip)]
    pub first_seen: Instant,
}

#[allow(dead_code)]
impl ConnectionRecord {
    pub fn remote_addr(&self) -> String {
        format!("{}:{}", self.remote_ip, self.remote_port)
    }

    /// Bytes transmitted since the last reset.
    pub fn tx_delta(&self) -> u64 {
        self.tx_bytes.saturating_sub(self.tx_bytes_at_reset)
    }

    /// Bytes received since the last reset.
    pub fn rx_delta(&self) -> u64 {
        self.rx_bytes.saturating_sub(self.rx_bytes_at_reset)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Unknown(u8),
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Unknown(_) => "???",
        }
    }
}

impl From<u8> for Protocol {
    fn from(v: u8) -> Self {
        match v {
            PROTO_TCP => Protocol::Tcp,
            PROTO_UDP => Protocol::Udp,
            other => Protocol::Unknown(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Unique connection key (mirrors TrafficKey but uses std types)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnKey {
    pub pid: u32,
    pub remote_ip4: u32,
    pub remote_port: u16,
    pub local_port: u16,
    pub proto: u8,
}

impl From<&TrafficKey> for ConnKey {
    fn from(k: &TrafficKey) -> Self {
        Self {
            pid: k.pid,
            remote_ip4: k.remote_ip4,
            remote_port: u16::from_be(k.remote_port),
            local_port: k.local_port,
            proto: k.proto,
        }
    }
}

// ---------------------------------------------------------------------------
// Global store
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Inner {
    /// All connections ever seen during this run.
    pub records: HashMap<ConnKey, ConnectionRecord>,
}

/// Thread-safe, cheaply cloneable handle to the shared store.
#[derive(Debug, Clone, Default)]
pub struct GlobalStore(pub Arc<RwLock<Inner>>);

impl GlobalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge a batch of (key, value) pairs read from the eBPF map.
    pub fn merge_batch(&self, batch: Vec<(TrafficKey, TrafficValue)>) {
        let mut guard = self.0.write();
        for (k, v) in batch {
            let conn_key = ConnKey::from(&k);
            let comm = comm_to_string(&v.comm);
            let remote_ip = Ipv4Addr::from(u32::from_be(k.remote_ip4));
            let remote_port = u16::from_be(k.remote_port);
            let tcp_state = if k.proto == PROTO_TCP && v.tcp_state != 0 {
                Some(TcpState::from(v.tcp_state))
            } else {
                None
            };

            guard
                .records
                .entry(conn_key)
                .and_modify(|r| {
                    r.tx_bytes = v.tx_bytes;
                    r.rx_bytes = v.rx_bytes;
                    r.comm = comm.clone();
                    r.last_seen = Utc::now();
                    if let Some(s) = tcp_state {
                        r.tcp_state = Some(s);
                    }
                    // Try to refresh cmdline if we only have comm so far.
                    if (r.cmdline == r.comm || r.cmdline.is_empty())
                        && let Some(cl) = read_cmdline(k.pid)
                    {
                        r.cmdline = cl;
                    }
                })
                .or_insert_with(|| {
                    // Read cmdline immediately on first observation so we
                    // capture it even for short-lived processes.
                    let cmdline = read_cmdline(k.pid).unwrap_or_else(|| comm.clone());
                    ConnectionRecord {
                        pid: k.pid,
                        comm: comm.clone(),
                        cmdline,
                        remote_ip,
                        remote_port,
                        local_port: k.local_port,
                        proto: Protocol::from(k.proto),
                        tcp_state,
                        tx_bytes: v.tx_bytes,
                        rx_bytes: v.rx_bytes,
                        tx_bytes_at_reset: 0,
                        rx_bytes_at_reset: 0,
                        last_seen: Utc::now(),
                        first_seen: Instant::now(),
                    }
                });
        }
    }

    /// Return a sorted snapshot of all records (from monitoring start).
    /// `sort_by_tx = true`  → descending TX; `false` → descending RX.
    pub fn snapshot(&self, sort_by_tx: bool) -> Vec<ConnectionRecord> {
        let guard = self.0.read();
        let mut v: Vec<_> = guard.records.values().cloned().collect();
        if sort_by_tx {
            v.sort_unstable_by_key(|b| std::cmp::Reverse(b.tx_bytes));
        } else {
            v.sort_unstable_by_key(|b| std::cmp::Reverse(b.rx_bytes));
        }
        v
    }

    /// Return a snapshot of records whose **first_seen** is within the last
    /// `secs` seconds (i.e. new connections opened within the window).
    pub fn snapshot_window(&self, sort_by_tx: bool, secs: u64) -> Vec<ConnectionRecord> {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(secs);
        let guard = self.0.read();
        let mut v: Vec<_> = guard
            .records
            .values()
            .filter(|r| now.duration_since(r.first_seen) <= window)
            .cloned()
            .collect();
        if sort_by_tx {
            v.sort_unstable_by_key(|b| std::cmp::Reverse(b.tx_bytes));
        } else {
            v.sort_unstable_by_key(|b| std::cmp::Reverse(b.rx_bytes));
        }
        v
    }

    /// Mark the current cumulative byte counts as the baseline (reset delta).
    /// Does NOT modify the eBPF-side counters — those only grow monotonically.
    /// The Prometheus exporter already handles the delta correctly, so it is
    /// unaffected by this call.
    pub fn reset(&self) {
        let mut guard = self.0.write();
        for r in guard.records.values_mut() {
            r.tx_bytes_at_reset = r.tx_bytes;
            r.rx_bytes_at_reset = r.rx_bytes;
        }
    }

    /// Total number of tracked connections since start.
    pub fn len(&self) -> usize {
        self.0.read().records.len()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn comm_to_string(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

/// Read the full command line for `pid` from `/proc/<pid>/cmdline`.
///
/// Returns `None` if the process has already exited or `/proc` is unavailable.
/// NUL separators (argv delimiters) are replaced with spaces.
pub fn read_cmdline(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/cmdline");
    let raw = std::fs::read(&path).ok()?;
    if raw.is_empty() {
        return None;
    }
    // Trim trailing NULs.
    let end = raw
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(raw.len());
    let s: String = raw[..end]
        .iter()
        .map(|&b| if b == 0 { ' ' } else { b as char })
        .collect();
    Some(s)
}

/// Format a byte count into a human-readable string (B / KB / MB / GB).
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    match bytes {
        b if b >= GB => format!("{:.2} GB", b as f64 / GB as f64),
        b if b >= MB => format!("{:.2} MB", b as f64 / MB as f64),
        b if b >= KB => format!("{:.2} KB", b as f64 / KB as f64),
        b => format!("{} B", b),
    }
}
