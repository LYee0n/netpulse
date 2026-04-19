use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    // Compile the eBPF crate and embed it into OUT_DIR so the loader can do:
    //   aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/netpulse"))
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;

    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "netpulse-ebpf")
        .ok_or_else(|| anyhow!("netpulse-ebpf package not found in workspace"))?;

    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;

    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };

    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
