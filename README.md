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
| **Persistent history** | Short-lived processes (curl, nslookup …) are never lost between refresh cycles |
| **TUI mode** | htop-style interface with live sort, filter, and reset |
| **Log mode** | Continuous JSON or formatted-table file append |
| **Metrics mode** | Prometheus `/metrics` endpoint with PID/IP labels |
| **Low overhead** | All hot-path work happens in eBPF; userspace polls maps asynchronously |

---

## Architecture

```
┌────────────────────── Kernel Space ──────────────────────┐
│                                                           │
│  kprobe: tcp_sendmsg ──┐                                  │
│  kprobe: tcp_recvmsg ──┼──► record_bytes() ──► TRAFFIC_MAP (BPF_HASH) │
│  kprobe: udp_sendmsg ──┤         ▲                        │
│  kprobe: udp_recvmsg ──┘         │                        │
│                            (pid, remote_ip,               │
│                             remote_port, proto)           │
└───────────────────────────────────────────────────────────┘
                              │  poll every N ms
                              ▼
┌────────────────────── User Space ─────────────────────────┐
│                                                           │
│  loader.rs  ──── merge_batch() ──► GlobalStore (RwLock)   │
│                                         │                 │
│                         ┌───────────────┼───────────────┐ │
│                         ▼               ▼               ▼ │
│                      tui/          exporter/        exporter/ │
│                    (Ratatui)        log.rs         prometheus.rs │
│                                  (JSON/Table)    (axum HTTP) │
└───────────────────────────────────────────────────────────┘
```

---

## Requirements

| Requirement | Version |
|---|---|
| Linux kernel | ≥ 5.8 (BTF + `bpf_probe_read_kernel`) |
| Rust toolchain | stable (2024 edition) |
| `bpf-linker` | latest (`cargo install bpf-linker`) |
| Capabilities | `CAP_BPF` + `CAP_NET_ADMIN` (or root) |

---

## Build

```bash

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain nightly
sudo apt update && sudo apt-get install -y llvm-dev libclang-dev zlib1g-dev libelf-dev tree linux-tools-6.17.0-20-generic && cargo install bpf-linker && rustup toolchain install nightly --component rust-src

# 1. Add the eBPF cross-compilation target
rustup target add bpfel-unknown-none

# 2. Install the eBPF linker
cargo install bpf-linker --locked

# 3. Install kernel headers (Debian/Ubuntu)
sudo apt-get install linux-headers-$(uname -r) libbpf-dev llvm clang

# 4. Build
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

| Key | Action |
|---|---|
| `s` | Toggle sort TX ↓ / RX ↓ |
| `r` | Reset all byte counters |
| `↑ ↓` / `j k` | Scroll |
| `q` | Quit |

### Log mode

```bash
# JSON (default)
sudo ./target/release/netpulse --mode log --output /var/log/netpulse.jsonl

# Human-readable table
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

Use `--agg-pid` to roll up per-IP into per-PID counters and avoid label
cardinality explosion:

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
├── netpulse-common/           #[no_std] shared types (TrafficKey, TrafficValue)
├── netpulse-ebpf/             eBPF kernel programs (4 kprobes)
└── netpulse/
    └── src/
        ├── main.rs            entry point, mode dispatch
        ├── cli.rs             clap CLI definition
        ├── model.rs           GlobalStore, ConnectionRecord
        ├── loader.rs          eBPF load + kprobe attach + map poller
        ├── tui/               Ratatui interactive interface
        └── exporter/
            ├── log.rs         JSON / table file appender
            └── prometheus.rs  axum HTTP + prometheus-client
```

---

## Roadmap

- [ ] **Phase 5** — integration tests with a VM that runs real `curl`/`nslookup` traffic
- [ ] IPv6 support (`skc_v6_daddr`)
- [ ] TCP state tracking (`sk_state` field)
- [ ] `/proc/<pid>/fd` correlation for full command line
- [ ] `--top N` flag to limit TUI rows
- [ ] Grafana dashboard JSON

---

## License

MIT OR Apache-2.0


