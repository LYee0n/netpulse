# NetPulse

> Per-process network traffic monitor powered by eBPF + Rust

NetPulse attaches kprobes to the Linux kernel's TCP/UDP send and receive
functions and records cumulative byte counts for every `(pid, remote_ip,
remote_port, protocol)` tuple — including connections that last only a few
milliseconds.

---

## Features

| Feature | Details |
|---|---|
| **Byte-level accuracy** | kprobes on `tcp_sendmsg`, `tcp_recvmsg`, `udp_sendmsg`, `udp_recvmsg` |
| **Persistent history** | Short-lived processes (`curl`, `nslookup` …) are never lost between refresh cycles |
| **TCP state tracking** | Live `sk_state` read per connection (ESTABLISHED, TIME_WAIT, CLOSE_WAIT …) |
| **Full command line** | `/proc/<pid>/cmdline` resolved on first event; falls back to `comm` for ephemeral PIDs |
| **TUI mode** | Two-tab htop-style interface: Active (60 s window) + History (all-time); inline `/` filter |
| **Log mode** | Continuous JSON or formatted-table file append with one-time header |
| **Metrics mode** | Prometheus `/metrics` endpoint with PID/IP labels + `?window=N` time-window parameter |
| **Low overhead** | All hot-path work happens in eBPF; userspace polls maps asynchronously |

---

## Architecture

```
┌────────────────────── Kernel Space ──────────────────────┐
│                                                           │
│  kprobe: tcp_sendmsg ──┐                                  │
│  kprobe: tcp_recvmsg ──┼──► record_bytes() ──► TRAFFIC_MAP (BPF_HASH)  │
│  kprobe: udp_sendmsg ──┤    (bytes + comm + sk_state)     │
│  kprobe: udp_recvmsg ──┘                                  │
└───────────────────────────────────────────────────────────┘
                              │  poll every N ms
                              ▼
┌────────────────────── User Space ─────────────────────────┐
│                                                           │
│  loader.rs  ──── merge_batch() ──► GlobalStore (RwLock)   │
│                  (+ /proc/<pid>/cmdline lookup)            │
│                         │                                 │
│             ┌───────────┼───────────┐                     │
│             ▼           ▼           ▼                     │
│          tui/       exporter/   exporter/                 │
│        (Ratatui)    log.rs    prometheus.rs               │
│      2-tab layout  JSON/Table  axum + ?window=N           │
└───────────────────────────────────────────────────────────┘
```

---

## Requirements

| Requirement | Version |
|---|---|
| Linux kernel | ≥ 5.8 (BTF + `bpf_probe_read_kernel`) |
| Rust toolchain | stable (2024 edition) + nightly for eBPF target |
| `bpf-linker` | latest (`cargo install bpf-linker`) |
| Capabilities | `CAP_BPF` + `CAP_NET_ADMIN` (or root) |

---

## Build

```bash
# 1. Install Rust (stable + nightly)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly --component rust-src

# 2. Add the eBPF cross-compilation target
rustup target add bpfel-unknown-none

# 3. Install the eBPF linker
cargo install bpf-linker --locked

# 4. Install kernel headers (Debian/Ubuntu)
sudo apt-get install linux-headers-$(uname -r) libbpf-dev llvm clang

# 5. Build
cargo build --release
```

The build system compiles the eBPF program automatically via `build.rs` and
embeds it into the userspace binary — no separate `.o` file is needed at
runtime.

---

## Usage

### TUI mode (default)

```bash
sudo ./target/release/netpulse
```

The TUI has two tabs:

| Tab | Contents |
|---|---|
| **[1] Active (60s)** | Connections first seen in the last 60 seconds |
| **[2] History (all)** | Every connection recorded since monitoring started |

Key bindings:

| Key | Action |
|---|---|
| `1` / `2` | Switch tab |
| `s` | Toggle sort TX ↓ / RX ↓ |
| `r` | Reset byte-counter baseline (delta display) |
| `/` | Enter filter mode — type to filter by comm, cmdline, or IP |
| `Esc` / `Enter` | Exit filter mode |
| `↑ ↓` / `j k` | Scroll |
| `q` | Quit |

The **STATE** column shows the TCP connection state for TCP connections
(ESTABLISHED, TIME_WAIT, CLOSE_WAIT, etc.) and `-` for UDP.

### Log mode

```bash
# JSON (default) — newline-delimited JSON objects
sudo ./target/release/netpulse --mode log --output /var/log/netpulse.jsonl

# Human-readable table (header written once, blank line between snapshots)
sudo ./target/release/netpulse --mode log --output traffic.log --format table
```

### Prometheus metrics mode

```bash
sudo ./target/release/netpulse --mode metrics --prometheus-port 9100
```

Metrics exposed:

```
# HELP process_network_transmit_bytes_total …
process_network_transmit_bytes_total{pid="1234",comm="curl",remote_ip="1.1.1.1",remote_port="443",proto="tcp"} 5120

# HELP process_network_receive_bytes_total …
process_network_receive_bytes_total{pid="1234",comm="curl",remote_ip="1.1.1.1",remote_port="443",proto="tcp"} 18432
```

#### Time-window parameter

The `/metrics` endpoint accepts a `?window=<secs>` query parameter to restrict
the response to connections first seen within the last N seconds:

```bash
# Only connections from the last 5 seconds
curl http://localhost:9100/metrics?window=5

# Only connections from the last 30 seconds
curl http://localhost:9100/metrics?window=30

# All connections since monitoring start (default)
curl http://localhost:9100/metrics
```

You can also set a default window at startup so every scrape uses it unless
overridden:

```bash
sudo ./target/release/netpulse --mode metrics --metrics-window 10
```

#### Avoid label cardinality explosion

Use `--agg-pid` to roll up per-IP into per-PID counters:

```bash
sudo ./target/release/netpulse --mode metrics --agg-pid
```

---

## CLI reference

```
Usage: netpulse [OPTIONS]

Options:
  -m, --mode <MODE>               tui | log | metrics  [default: tui]
  -o, --output <FILE>             Output file (log mode)
  -f, --format <FORMAT>           json | table         [default: json]
  -p, --prometheus-port <PORT>    Prometheus HTTP port [default: 9100]
      --metrics-window <SECS>     Default /metrics time window in seconds [default: 0 = all]
      --agg-pid                   Aggregate by PID only (no remote-IP labels)
      --filter-comm <NAME>        Only track processes matching NAME
      --poll-ms <MS>              eBPF map poll interval [default: 500]
  -v, --verbose                   Enable debug logging
  -h, --help                      Print help
  -V, --version                   Print version
```

---

## Project layout

```
netpulse/
├── Cargo.toml                 workspace manifest
├── netpulse-common/           #[no_std] shared types (TrafficKey, TrafficValue, TCP_* consts)
├── netpulse-ebpf/             eBPF kernel programs (4 kprobes + sk_state reader)
└── netpulse/
    └── src/
        ├── main.rs            entry point, mode dispatch
        ├── cli.rs             clap CLI definition
        ├── model.rs           GlobalStore, ConnectionRecord, TcpState, read_cmdline
        ├── loader.rs          eBPF load + kprobe attach + map poller
        ├── tui/               Ratatui 2-tab interface with inline filter
        └── exporter/
            ├── log.rs         JSON / table file appender (one-time header)
            └── prometheus.rs  axum HTTP + prometheus-client + ?window= support
```

---

## Known limitations / future work

- **IPv6:** `TrafficKey` currently stores only IPv4 (`remote_ip4`).  IPv6 support
  requires extending the key to a `[u8; 16]` union.
- **BTF / CO-RE offsets:** `sk_state` and `skc_daddr` are read at fixed offsets
  that are stable on kernels ≥ 4.1.  Full BTF CO-RE via `aya-btf-maps` would
  make this portable across kernel variants without recompiling.
- **UDP unconnected sockets:** `udp_sendmsg` on unconnected sockets reads
  `skc_daddr` from the sock struct which may be 0; the destination is in the
  `msghdr` instead and requires reading the user-space struct via
  `bpf_probe_read_user`.

---

## License

MIT OR Apache-2.0
