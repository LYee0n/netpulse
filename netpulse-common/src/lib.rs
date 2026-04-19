//! Shared data types between the eBPF kernel programs and the userspace loader.
//!
//! This crate is compiled for both `bpfel-unknown-none` (no_std) and the host
//! target, so every type here must be `#[repr(C)]` and use only primitive types.

#![no_std]
#![allow(non_camel_case_types)]

/// Key used in the per-connection BPF hash map.
///
/// Identifies a unique (pid, remote_ip, remote_port, protocol) tuple.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct TrafficKey {
    /// Process ID in the network namespace.
    pub pid: u32,
    /// Remote IPv4 address in network byte-order.
    pub remote_ip4: u32,
    /// Remote port in network byte-order.
    pub remote_port: u16,
    /// Local port in network byte-order.
    pub local_port: u16,
    /// Protocol: 6 = TCP, 17 = UDP.
    pub proto: u8,
    /// Padding to align the struct.
    pub _pad: [u8; 3],
}

/// Value stored for each `TrafficKey` in the BPF map.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct TrafficValue {
    /// Cumulative bytes transmitted (send path).
    pub tx_bytes: u64,
    /// Cumulative bytes received (recv path).
    pub rx_bytes: u64,
    /// Process name (comm), up to 16 bytes, null-terminated.
    pub comm: [u8; 16],
    /// Timestamp of the last update (nanoseconds since boot, from bpf_ktime_get_ns).
    pub last_seen_ns: u64,
    /// TCP socket state at last update (see TCP_* constants below); 0 = unknown/UDP.
    pub tcp_state: u8,
    /// Padding to maintain 8-byte alignment.
    pub _pad2: [u8; 7],
}

// TCP state constants (mirrors kernel tcp_states enum)
pub const TCP_ESTABLISHED: u8 = 1;
pub const TCP_SYN_SENT: u8 = 2;
pub const TCP_SYN_RECV: u8 = 3;
pub const TCP_FIN_WAIT1: u8 = 4;
pub const TCP_FIN_WAIT2: u8 = 5;
pub const TCP_TIME_WAIT: u8 = 6;
pub const TCP_CLOSE: u8 = 7;
pub const TCP_CLOSE_WAIT: u8 = 8;
pub const TCP_LAST_ACK: u8 = 9;
pub const TCP_LISTEN: u8 = 10;
pub const TCP_CLOSING: u8 = 11;

/// Marker constants for protocol field.
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

// --- userspace-only impls ---------------------------------------------------

#[cfg(feature = "user")]
unsafe impl aya::Pod for TrafficKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TrafficValue {}
