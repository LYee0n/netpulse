//! eBPF program loader and map poller.
//!
//! * Loads the compiled `netpulse` eBPF object.
//! * Bumps memlock rlimit for older kernels.
//! * Attaches four kprobes (tcp/udp × send/recv).
//! * Spawns a Tokio task that polls `TRAFFIC_MAP` every `poll_ms` milliseconds
//!   and merges results into the `GlobalStore`.

use std::time::Duration;

use anyhow::{Context, Result};
use aya::{Ebpf, maps::HashMap as BpfHashMap, programs::KProbe};
use aya_log::EbpfLogger;
use log::{debug, info, warn};
use tokio::{task::JoinHandle, time};

use netpulse_common::{TrafficKey, TrafficValue};

use crate::model::GlobalStore;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Load the eBPF object, attach all kprobes, and launch a background poller.
///
/// Returns the `JoinHandle` for the polling task; dropping it cancels the task.
pub fn start(store: GlobalStore, poll_ms: u64) -> Result<JoinHandle<()>> {
    // 1. Bump memlock rlimit (needed on kernels < 5.11).
    bump_memlock_rlimit();

    // 2. Load the eBPF object embedded at compile time.
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/netpulse"
    )))
    .context("failed to load eBPF object")?;

    // 3. Initialise eBPF logger.
    match EbpfLogger::init(&mut ebpf) {
        Ok(logger) => {
            let mut af =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::spawn(async move {
                loop {
                    let mut g = af.readable_mut().await.unwrap();
                    g.get_inner_mut().flush();
                    g.clear_ready();
                }
            });
        }
        Err(e) => warn!("eBPF logger init failed (no log statements?): {e}"),
    }

    // 4. Attach kprobes.
    attach_kprobe(&mut ebpf, "kprobe_tcp_sendmsg", "tcp_sendmsg")?;
    attach_kprobe(&mut ebpf, "kprobe_tcp_recvmsg", "tcp_recvmsg")?;
    attach_kprobe(&mut ebpf, "kprobe_udp_sendmsg", "udp_sendmsg")?;
    attach_kprobe(&mut ebpf, "kprobe_udp_recvmsg", "udp_recvmsg")?;
    info!("all kprobes attached");

    // 5. Obtain a handle to the shared map.
    let map_data = ebpf
        .take_map("TRAFFIC_MAP")
        .context("TRAFFIC_MAP not found in eBPF object")?;
    let traffic_map: BpfHashMap<_, TrafficKey, TrafficValue> =
        BpfHashMap::try_from(map_data).context("TRAFFIC_MAP type mismatch")?;

    // 6. Spawn the polling task.  `ebpf` must be kept alive for the programs
    //    to remain loaded, so we move it (along with the map) into the task.
    let handle = tokio::spawn(async move {
        // Keep `ebpf` alive inside the task.
        let _ebpf_owner = ebpf;
        let mut interval = time::interval(Duration::from_millis(poll_ms));
        loop {
            interval.tick().await;

            let batch: Vec<(TrafficKey, TrafficValue)> =
                traffic_map.iter().filter_map(|res| res.ok()).collect();

            debug!("polled eBPF map: {} entries", batch.len());
            store.merge_batch(batch);
        }
    });

    Ok(handle)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn attach_kprobe(ebpf: &mut Ebpf, prog_name: &str, fn_name: &str) -> Result<()> {
    let prog: &mut KProbe = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("program `{prog_name}` not found"))?
        .try_into()
        .with_context(|| format!("program `{prog_name}` is not a kprobe"))?;
    prog.load().with_context(|| format!("load `{prog_name}`"))?;
    prog.attach(fn_name, 0)
        .with_context(|| format!("attach `{prog_name}` -> `{fn_name}`"))?;
    debug!("kprobe {prog_name} → {fn_name} attached");
    Ok(())
}

fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("setrlimit(MEMLOCK, INFINITY) failed (ret={ret}); may fail on old kernels");
    }
}
