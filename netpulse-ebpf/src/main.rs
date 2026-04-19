//! NetPulse eBPF kernel program.
//!
//! Attaches kprobes to the four core kernel send/receive functions and records
//! per-(pid, remote-ip, remote-port, proto) byte counts into a shared BPF hash
//! map that the userspace loader polls asynchronously.

#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_int,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, map},
    maps::HashMap,
    programs::ProbeContext,
};
use aya_log_ebpf::debug;
use core::ffi::c_void;
use netpulse_common::{PROTO_TCP, PROTO_UDP, TrafficKey, TrafficValue};

/// Maximum number of concurrent tracked connections.
const MAX_ENTRIES: u32 = 65536;

/// Primary per-connection traffic map shared with userspace.
///
/// Key  : `TrafficKey`  (pid + remote addr + proto)
/// Value: `TrafficValue` (tx_bytes, rx_bytes, comm, last_seen)
#[map]
static TRAFFIC_MAP: HashMap<TrafficKey, TrafficValue> =
    HashMap::<TrafficKey, TrafficValue>::with_max_entries(MAX_ENTRIES, 0);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read the current process comm string into a `[u8; 16]` array.
#[inline(always)]
fn current_comm() -> [u8; 16] {
    bpf_get_current_comm().unwrap_or([0u8; 16])
}

/// Extract tgid (user-visible PID) from the combined pid_tgid value.
#[inline(always)]
fn current_pid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

/// Update the map entry for a given key, adding `delta_tx` / `delta_rx` bytes.
#[inline(always)]
unsafe fn record_bytes(key: &TrafficKey, delta_tx: u64, delta_rx: u64, comm: [u8; 16]) {
    let now = unsafe { bpf_ktime_get_ns() };
    match TRAFFIC_MAP.get_ptr_mut(key) {
        Some(val) => unsafe {
            (*val).tx_bytes += delta_tx;
            (*val).rx_bytes += delta_rx;
            (*val).last_seen_ns = now;
            // Refresh comm on every event (process may exec).
            (*val).comm = comm;
        },
        None => {
            let new_val = TrafficValue {
                tx_bytes: delta_tx,
                rx_bytes: delta_rx,
                comm,
                last_seen_ns: now,
            };
            // Ignore insert errors (map full); we prefer not to crash.
            let _ = TRAFFIC_MAP.insert(key, &new_val, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// TCP send  — tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
// ---------------------------------------------------------------------------

#[kprobe]
pub fn kprobe_tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg(ctx) {
        Ok(r) => r,
        Err(_) => 0,
    }
}

fn try_tcp_sendmsg(ctx: ProbeContext) -> Result<u32, i64> {
    // arg0 = struct sock *, arg2 = size_t size
    let sk: *const c_void = ctx.arg(0).ok_or(0i64)?;
    let size: usize = ctx.arg(2).ok_or(0i64)?;
    if size == 0 {
        return Ok(0);
    }

    let (remote_ip4, remote_port, local_port) = unsafe { read_sock_addrs(sk) };
    let pid = current_pid();
    let comm = current_comm();

    let key = TrafficKey {
        pid,
        remote_ip4,
        remote_port,
        local_port,
        proto: PROTO_TCP,
        _pad: [0; 3],
    };

    debug!(
        &ctx,
        "tcp_sendmsg pid={} size={} dst={}", pid, size as u64, remote_ip4
    );
    unsafe { record_bytes(&key, size as u64, 0, comm) };
    Ok(0)
}

// ---------------------------------------------------------------------------
// TCP recv  — tcp_recvmsg(struct sock *sk, …, int len, …)
//             We probe the return path (kretprobe) to capture actual bytes read.
//             For simplicity we use the entry probe with arg `len` as upper bound.
// ---------------------------------------------------------------------------

#[kprobe]
pub fn kprobe_tcp_recvmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_recvmsg(ctx) {
        Ok(r) => r,
        Err(_) => 0,
    }
}

fn try_tcp_recvmsg(ctx: ProbeContext) -> Result<u32, i64> {
    let sk: *const c_void = ctx.arg(0).ok_or(0i64)?;
    let len: c_int = ctx.arg(2).ok_or(0i64)?;
    if len <= 0 {
        return Ok(0);
    }

    let (remote_ip4, remote_port, local_port) = unsafe { read_sock_addrs(sk) };
    let pid = current_pid();
    let comm = current_comm();

    let key = TrafficKey {
        pid,
        remote_ip4,
        remote_port,
        local_port,
        proto: PROTO_TCP,
        _pad: [0; 3],
    };

    unsafe { record_bytes(&key, 0, len as u64, comm) };
    Ok(0)
}

// ---------------------------------------------------------------------------
// UDP send  — udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
// ---------------------------------------------------------------------------

#[kprobe]
pub fn kprobe_udp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_udp_sendmsg(ctx) {
        Ok(r) => r,
        Err(_) => 0,
    }
}

fn try_udp_sendmsg(ctx: ProbeContext) -> Result<u32, i64> {
    let sk: *const c_void = ctx.arg(0).ok_or(0i64)?;
    let size: usize = ctx.arg(2).ok_or(0i64)?;
    if size == 0 {
        return Ok(0);
    }

    // For UDP the "remote" address comes from the msghdr, but for connected UDP
    // sockets we can still read it from sock.__sk_common.skc_daddr.
    let (remote_ip4, remote_port, local_port) = unsafe { read_sock_addrs(sk) };
    let pid = current_pid();
    let comm = current_comm();

    let key = TrafficKey {
        pid,
        remote_ip4,
        remote_port,
        local_port,
        proto: PROTO_UDP,
        _pad: [0; 3],
    };

    unsafe { record_bytes(&key, size as u64, 0, comm) };
    Ok(0)
}

// ---------------------------------------------------------------------------
// UDP recv  — udp_recvmsg(struct sock *sk, …, int len, …)
// ---------------------------------------------------------------------------

#[kprobe]
pub fn kprobe_udp_recvmsg(ctx: ProbeContext) -> u32 {
    match try_udp_recvmsg(ctx) {
        Ok(r) => r,
        Err(_) => 0,
    }
}

fn try_udp_recvmsg(ctx: ProbeContext) -> Result<u32, i64> {
    let sk: *const c_void = ctx.arg(0).ok_or(0i64)?;
    let len: c_int = ctx.arg(2).ok_or(0i64)?;
    if len <= 0 {
        return Ok(0);
    }

    let (remote_ip4, remote_port, local_port) = unsafe { read_sock_addrs(sk) };
    let pid = current_pid();
    let comm = current_comm();

    let key = TrafficKey {
        pid,
        remote_ip4,
        remote_port,
        local_port,
        proto: PROTO_UDP,
        _pad: [0; 3],
    };

    unsafe { record_bytes(&key, 0, len as u64, comm) };
    Ok(0)
}

// ---------------------------------------------------------------------------
// Kernel struct field offsets
//
// We read `__sk_common.skc_daddr` (remote IPv4) and `__sk_common.skc_dport`
// (remote port) plus `__sk_common.skc_num` (local port) using BTF-backed
// bpf_probe_read_kernel. Offsets are from the standard stable ABI layout.
//
//   struct sock_common {
//     union { __be32 skc_daddr; … };   // +0
//     union { __be32 skc_rcv_saddr; }; // +4
//     union { __be16 skc_dport; … };   // +12
//     __u16          skc_num;           // +14
//     …
//   };
// ---------------------------------------------------------------------------

#[inline(always)]
unsafe fn read_sock_addrs(sk: *const c_void) -> (u32, u16, u16) {
    // SAFETY: bpf_probe_read_kernel validates the pointer in kernel space.
    use aya_ebpf::helpers::bpf_probe_read_kernel;

    let base = sk as *const u8;

    // skc_daddr  at offset 0
    let remote_ip4: u32 = unsafe { bpf_probe_read_kernel(base.add(0) as *const u32).unwrap_or(0) };
    // skc_dport  at offset 12
    let remote_port: u16 =
        unsafe { bpf_probe_read_kernel(base.add(12) as *const u16).unwrap_or(0) };
    // skc_num    at offset 14  (host byte order)
    let local_port: u16 = unsafe { bpf_probe_read_kernel(base.add(14) as *const u16).unwrap_or(0) };

    (remote_ip4, remote_port, local_port)
}

// ---------------------------------------------------------------------------
// Mandatory panic handler for no_std eBPF programs
// ---------------------------------------------------------------------------

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
