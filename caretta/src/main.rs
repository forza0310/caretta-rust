//! Entry point for Caretta userspace runtime.
//!
//! This file now focuses on orchestration only: loading eBPF, wiring resolver + HTTP server,
//! and running the polling loop. Domain logic is split into dedicated modules.

mod config;
mod http_server;
mod metrics;
mod resolver;
mod types;

use anyhow::Context as _;
use aya::maps::HashMap as BpfHashMap;
use aya::programs::{KProbe, TracePoint};
use config::Opt;
use log::{info, warn};
use resolver::{IpResolver, K8sResolver, StaticResolver};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::watch;
use types::{
    ConnectionIdentifier, ConnectionThroughputStats, NetworkLink, TraceOffsets, TcpConnection,
    is_loopback, parse_tracepoint_offsets, reduce_connection_to_link, reduce_connection_to_tcp,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let opt = Opt::from_env_and_args();

    // Load eBPF object file produced by the build script.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/caretta"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let kprobe: &mut KProbe = ebpf
        .program_mut("handle_tcp_sendmsg")
        .context("kprobe program handle_tcp_sendmsg not found")?
        .try_into()?;
    kprobe.load()?;
    kprobe.attach("tcp_sendmsg", 0)?;

    let kprobe_recv: &mut KProbe = ebpf
        .program_mut("handle_tcp_cleanup_rbuf")
        .context("kprobe program handle_tcp_cleanup_rbuf not found")?
        .try_into()?;
    kprobe_recv.load()?;
    kprobe_recv.attach("tcp_cleanup_rbuf", 0)?;

    // Resolve tracepoint field offsets dynamically to avoid kernel-version-specific hardcoding.
    let offsets =
        parse_tracepoint_offsets("/sys/kernel/tracing/events/sock/inet_sock_set_state/format")?;
    let offsets_key = 0u32;
    let mut offsets_map: BpfHashMap<_, u32, TraceOffsets> = BpfHashMap::try_from(
        ebpf.map_mut("TRACEPOINT_OFFSETS")
            .context("TRACEPOINT_OFFSETS map not found")?,
    )?;
    offsets_map.insert(offsets_key, offsets, 0)?;

    let tracepoint: &mut TracePoint = ebpf
        .program_mut("handle_sock_set_state")
        .context("tracepoint program handle_sock_set_state not found")?
        .try_into()?;
    tracepoint.load()?;

    tracepoint.attach("sock", "inet_sock_set_state")?;

    let connections_map = ebpf
        .take_map("CONNECTIONS")
        .context("CONNECTIONS map not found")?;
    let mut connections: BpfHashMap<_, ConnectionIdentifier, ConnectionThroughputStats> =
        BpfHashMap::try_from(connections_map)?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let metrics_addr = SocketAddr::from(([0, 0, 0, 0], opt.prometheus_port));
    let endpoint = opt.normalized_prometheus_endpoint();
    let debug_resolver_endpoint = opt.normalized_debug_resolver_endpoint();

    let owner_kind_allowlist = opt.owner_kind_allowlist();
    let owner_kind_priority = opt.owner_kind_priority();

    if opt.resolve_dns {
        info!("reverse DNS enabled (cache size={})", opt.dns_cache_size);
    } else {
        info!("reverse DNS disabled");
    }

    let resolver: Arc<dyn IpResolver> = match K8sResolver::try_new(
        opt.resolve_dns,
        opt.dns_cache_size,
        opt.traverse_up_hierarchy,
        owner_kind_allowlist,
        owner_kind_priority,
    )
    .await
    {
        Ok(r) => {
            info!("kubernetes resolver enabled");
            r
        }
        Err(err) => {
            warn!("kubernetes resolver unavailable, fallback to static resolver: {err}");
            Arc::new(StaticResolver::new(opt.resolve_dns, opt.dns_cache_size))
        }
    };
    if opt.debug_resolver_enabled {
        info!("debug resolver endpoint enabled at {}", debug_resolver_endpoint);
    }
    let metrics_task = tokio::spawn(http_server::run_metrics_server(
        metrics_addr,
        endpoint.clone(),
        opt.debug_resolver_enabled,
        debug_resolver_endpoint,
        Arc::clone(&resolver),
        shutdown_rx,
    ));
    info!("metrics server listening on {}{}", metrics_addr, endpoint);
    let mut past_links: HashMap<NetworkLink, u64> = HashMap::new();
    let mut ticker = tokio::time::interval(Duration::from_secs(opt.poll_interval.max(1)));

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("received shutdown signal");
                let _ = shutdown_tx.send(true);
                break;
            }
            _ = ticker.tick() => {
                metrics::mark_poll();

                let mut current_links: HashMap<NetworkLink, u64> = HashMap::new();
                let mut current_tcp_connections: Vec<TcpConnection> = Vec::new();
                let mut to_delete: Vec<ConnectionIdentifier> = Vec::new();
                let mut loopback_counter = 0u64;
                let mut items_counter = 0u64;

                let mut entries = connections.iter();
                while let Some(entry) = entries.next() {
                    let (conn, throughput) = match entry {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("failed to iterate map entry: {e}");
                            continue;
                        }
                    };
                    items_counter += 1;

                    if throughput.is_active == 0 {
                        to_delete.push(conn);
                    }

                    if conn.tuple.src_ip == conn.tuple.dst_ip && is_loopback(conn.tuple.dst_ip) {
                        loopback_counter += 1;
                        continue;
                    }

                    let link = match reduce_connection_to_link(resolver.as_ref(), conn) {
                        Ok(link) => link,
                        Err(_) => continue,
                    };

                    let tcp = match reduce_connection_to_tcp(resolver.as_ref(), conn, throughput) {
                        Ok(tcp) => tcp,
                        Err(_) => continue,
                    };

                    *current_links.entry(link).or_insert(0) +=
                        throughput.bytes_sent.saturating_add(throughput.bytes_received);
                    current_tcp_connections.push(tcp);
                }

                metrics::set_map_size(items_counter);
                metrics::set_filtered_loopback_connections(loopback_counter);

                for (past_link, past_throughput) in &past_links {
                    *current_links.entry(past_link.clone()).or_insert(0) += *past_throughput;
                }

                for conn in to_delete {
                    let throughput = match connections.get(&conn, 0) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("Error retrieving connection to delete, skipping it: {e}");
                            metrics::mark_failed_connection_deletion();
                            continue;
                        }
                    };

                    if let Err(e) = connections.remove(&conn) {
                        warn!("Error deleting connection from map: {e}");
                        metrics::mark_failed_connection_deletion();
                        continue;
                    }

                    if let Ok(link) = reduce_connection_to_link(resolver.as_ref(), conn) {
                        *past_links.entry(link).or_insert(0) +=
                            throughput.bytes_sent.saturating_add(throughput.bytes_received);
                    }
                    metrics::mark_map_deletion();
                }

                for (link, throughput) in current_links {
                    metrics::handle_link_metric(&link, throughput);
                }

                for tcp in current_tcp_connections {
                    metrics::handle_tcp_metric(&tcp);
                }
            }
        }
    }

    match metrics_task.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) if e.downcast_ref::<io::Error>().is_some() => {
            warn!("metrics server stopped with io error: {e}");
        }
        Ok(Err(e)) => {
            return Err(e);
        }
        Err(e) => {
            return Err(anyhow::anyhow!("metrics server task join error: {e}"));
        }
    }

    Ok(())
}
