use std::{
    collections::HashMap,
    fs::File,
    net::Ipv4Addr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use aya::{
    maps::HashMap as BpfHashMap,
    programs::{CgroupAttachMode, KProbe, ProgramError, SockOps},
    Bpf,
};
use caretta_common::{ConnectionIdentifier, ConnectionThroughputStats};
use log::info;

fn main() -> Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        ctrlc::set_handler(move || {
            stop.store(true, Ordering::SeqCst);
        })?;
    }

    let object_path = PathBuf::from(env!("CARETTA_EBPF_OBJECT"));
    let mut bpf = Bpf::load_file(&object_path)
        .with_context(|| format!("failed to load eBPF object from {}", object_path.display()))?;

    attach_sock_ops(&mut bpf, cgroup_path())?;
    attach_kprobe(&mut bpf, "handle_tcp_data_queue", "tcp_data_queue")?;

    let mut connections: BpfHashMap<_, ConnectionIdentifier, ConnectionThroughputStats> =
        BpfHashMap::try_from(bpf.map_mut("connections").context("missing connections map")?)
            .context("failed to open connections map")?;

    info!("caretta-go-rust started, polling eBPF map");

    while !stop.load(Ordering::SeqCst) {
        dump_connections(&mut connections)?;
        thread::sleep(Duration::from_secs(5));
    }

    Ok(())
}

fn attach_sock_ops(bpf: &mut Bpf, cgroup: File) -> Result<()> {
    let program: &mut SockOps = bpf
        .program_mut("handle_sock_ops")
        .context("program handle_sock_ops not found")?
        .try_into()
        .map_err(|error: ProgramError| anyhow::anyhow!(error))?;

    program
        .load()
        .context("failed to load handle_sock_ops")?;
    program
        .attach(cgroup, CgroupAttachMode::Single)
        .context("failed to attach handle_sock_ops to the cgroup")?;

    Ok(())
}

fn attach_kprobe(bpf: &mut Bpf, program_name: &str, kernel_symbol: &str) -> Result<()> {
    let program: &mut KProbe = bpf
        .program_mut(program_name)
        .with_context(|| format!("program {program_name} not found"))?
        .try_into()
        .map_err(|error: ProgramError| anyhow::anyhow!(error))?;

    program
        .load()
        .with_context(|| format!("failed to load {program_name}"))?;
    program
        .attach(kernel_symbol, 0)
        .with_context(|| format!("failed to attach {program_name} to {kernel_symbol}"))?;

    Ok(())
}

fn dump_connections(
    connections: &mut BpfHashMap<_, ConnectionIdentifier, ConnectionThroughputStats>,
) -> Result<()> {
    let mut totals: HashMap<String, u64> = HashMap::new();

    for entry in connections.iter() {
        let (conn, stats) = entry.context("failed to read a connection entry")?;
        let key = format!(
            "{}:{} -> {}:{}",
            ipv4_to_string(conn.tuple.src_ip),
            conn.tuple.src_port,
            ipv4_to_string(conn.tuple.dst_ip),
            conn.tuple.dst_port
        );
        totals.insert(key, stats.bytes_sent);
    }

    if totals.is_empty() {
        info!("no active connections observed yet");
        return Ok(());
    }

    info!("observed {} connections", totals.len());
    for (connection, bytes_sent) in totals {
        info!("{connection} bytes_sent={bytes_sent}");
    }

    Ok(())
}

fn ipv4_to_string(ip: u32) -> String {
    Ipv4Addr::from(u32::from_le(ip)).to_string()
}

fn cgroup_path() -> File {
    let path = std::env::var("CARETTA_CGROUP_PATH").unwrap_or_else(|_| "/sys/fs/cgroup".to_string());
    File::open(&path).unwrap_or_else(|error| {
        panic!("failed to open cgroup path {}: {}", path, error);
    })
}
