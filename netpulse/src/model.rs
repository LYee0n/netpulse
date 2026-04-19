//! In-process data model.
//!
//! The `GlobalStore` keeps a permanent history of every observed connection
//! keyed by `(pid, remote_ip, remote_port, proto)`.  Entries are never
//! evicted while the process is running so that short-lived connections
//! (curl, nslookup …) are not lost between TUI refresh cycles.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::Arc,
};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::Serialize;

use netpulse_common::{TrafficKey, TrafficValue, PROTO_TCP, PROTO_UDP};

// ---------------------------------------------------------------------------
// Public connection record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionRecord {
    pub pid:         u32,
    pub comm:        String,
    pub remote_ip:   Ipv4Addr,
    pub remote_port: u16,
    pub local_port:  u16,
    pub proto:       Protocol,
    pub tx_bytes:    u64,
    pub rx_bytes:    u64,
    /// Wall-clock time of the last eBPF event for this entry.
    pub last_seen:   DateTime<Utc>,
}

impl ConnectionRecord {
    /// Human-readable TX rate string (just raw bytes for now; callers may
    /// compute a rate by diffing snapshots).
    pub fn remote_addr(&self) -> String {
        format!("{}:{}", self.remote_ip, self.remote_port)
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
            other     => Protocol::Unknown(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Unique connection key (mirrors TrafficKey but uses std types)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnKey {
    pub pid:         u32,
    pub remote_ip4:  u32,
    pub remote_port: u16,
    pub local_port:  u16,
    pub proto:       u8,
}

impl From<&TrafficKey> for ConnKey {
    fn from(k: &TrafficKey) -> Self {
        Self {
            pid:         k.pid,
            remote_ip4:  k.remote_ip4,
            remote_port: u16::from_be(k.remote_port),
            local_port:  k.local_port,
            proto:       k.proto,
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

            guard.records
                .entry(conn_key)
                .and_modify(|r| {
                    r.tx_bytes  = v.tx_bytes;
                    r.rx_bytes  = v.rx_bytes;
                    r.comm      = comm.clone();
                    r.last_seen = Utc::now();
                })
                .or_insert_with(|| ConnectionRecord {
                    pid:         k.pid,
                    comm,
                    remote_ip,
                    remote_port,
                    local_port:  k.local_port,
                    proto:       Protocol::from(k.proto),
                    tx_bytes:    v.tx_bytes,
                    rx_bytes:    v.rx_bytes,
                    last_seen:   Utc::now(),
                });
        }
    }

    /// Return a sorted snapshot of all records.
    /// `sort_by_tx = true`  → descending TX; `false` → descending RX.
    pub fn snapshot(&self, sort_by_tx: bool) -> Vec<ConnectionRecord> {
        let guard = self.0.read();
        let mut v: Vec<_> = guard.records.values().cloned().collect();
        if sort_by_tx {
            v.sort_unstable_by(|a, b| b.tx_bytes.cmp(&a.tx_bytes));
        } else {
            v.sort_unstable_by(|a, b| b.rx_bytes.cmp(&a.rx_bytes));
        }
        v
    }

    /// Reset all accumulated counters (keeps entries, zeros bytes).
    pub fn reset(&self) {
        let mut guard = self.0.write();
        for r in guard.records.values_mut() {
            r.tx_bytes = 0;
            r.rx_bytes = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn comm_to_string(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&comm[..end]).into_owned()
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
        b            => format!("{} B", b),
    }
}
