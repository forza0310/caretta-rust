//! Entry point for Caretta userspace runtime.
//!
//! This file now focuses on orchestration only: loading eBPF, wiring resolver + HTTP server,
//! and running the polling loop. Domain logic is split into dedicated modules.

mod btf;
mod config;
mod http_server;
mod metrics;
mod per_cpu;
mod resolver;
mod types;

use anyhow::Context as _;
use aya::Btf;
use aya::maps::{HashMap as BpfHashMap, PerCpuHashMap as BpfPerCpuHashMap};
use aya::programs::{BtfTracePoint, FEntry};
use btf::parse_sock_offsets;
use config::Opt;
use log::{info, warn};
use resolver::{IpResolver, K8sResolver, StaticResolver};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::sync::{oneshot, watch};
use tokio::time::MissedTickBehavior;
use types::{
    ConnectionIdentifier, ConnectionThroughputStats, NetworkLink, SockOffsets, TcpConnection,
    TcpConnectionKey, aggregate_per_cpu_throughput, is_loopback,
    reduce_connection_to_link, reduce_connection_to_tcp,
};

/// 一条 link 在最后一次观测到流量后多久没活动就 GC 掉对应的 prometheus series + 用户态记账。
///
/// 选 5 分钟的考虑：
///   - prometheus 默认 staleness 窗口 5 分钟。在窗口内 series 消失，PromQL 仍能用
///     最近一次 sample 平滑过渡；窗口外才真正"消失"。提前删掉等价于 staleness 自然到期。
///   - 短连接抖动场景：滚动更新等突发但回不来的 link 在 5 分钟后才回收，足够 dashboard
///     的 5m rate 窗口算完最后一笔；再短就可能算到 partial 区间。
///   - 真正长尾活跃但稀疏的 link（每 10 分钟才一次心跳）会被反复 GC + 重建，prometheus
///     会出现 series gap。如果业务里有这种链路，把 TTL 调到能覆盖最长心跳间隔即可——
///     5 分钟是给"业务流量持续 ≥ 1Hz 级"的 caretta 默认环境的一个保守值。
const LINK_GC_TTL: Duration = Duration::from_secs(300);

/// 一条 TCP series 连续多少个 tick 没在 eBPF map 里出现就 GC。
///
/// 与 LINK_GC_TTL 形态不同：tcp_states 是 gauge 不是 counter，没有"差分基准要保留"的
/// 顾虑，删掉再重新出现就是 gauge 重新有值，不会有数值毛刺。窗口可以更激进一些——
/// 这里取 12 个 tick（默认 poll 1s ≈ 12s 没出现就删）。tick 数而不是绝对时间是因为
/// poll_interval 可配置。
const TCP_GC_MISSED_TICKS: u32 = 12;

/// past_links 表里每条 link 的状态。
struct LinkState {
    /// 自启动以来这条 link 的累计字节数（活着的 + 已死亡部分）。
    /// 每次 poll 用它合并出 current_links。
    cumulative_bytes: u64,
    /// 最近一次"还在产生流量"的时间。GC 用 now() - last_active > TTL 判定回收。
    /// 任何让 cumulative_bytes 变大的写入都要刷新这里。
    last_active: Instant,
}

/// tcp_states 表里每条连接的 GC 状态。
struct TcpState {
    /// 上一次在本 tick 看到这条连接时的 TcpConnection 快照——GC 时需要拿它去删 series。
    /// 也用于在 main loop 里 push 到 current_tcp_connections 上报。
    last_seen_conn: TcpConnection,
    /// 自上次出现以来连续没出现的 tick 数；超过 TCP_GC_MISSED_TICKS 就 forget。
    missed_ticks: u32,
}

fn ensure_vmlinux_btf_available() -> anyhow::Result<aya::Btf> {
    // 加载内核暴露的 vmlinux BTF。fentry / tp_btf 程序在 verifier attach 时需要 kernel
    // BTF 做 type 检查;同一份 BTF 我们启动期也用来解 sock_common 字段偏移。
    Btf::from_sys_fs().with_context(|| {
        "vmlinux BTF not available; kernel must be built with CONFIG_DEBUG_INFO_BTF=y \
         (linux ≥ 5.5). K8s hint: mount host /sys/kernel/btf into the container at \
         /sys/kernel/btf (readOnly)."
            .to_string()
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let opt = Opt::from_env_and_args();

    // Load eBPF object file produced by the build script.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/caretta"
    )))?;

    // 同一份 BTF 给三类 program 用:fentry/tp_btf 在 attach 时会按 BTF 校验 args,
    // 之后还要再用同一份 BTF 解 sock_common 字段偏移。
    let btf = ensure_vmlinux_btf_available()?;

    let kprobe: &mut FEntry = ebpf
        .program_mut("handle_tcp_sendmsg")
        .context("fentry program handle_tcp_sendmsg not found")?
        .try_into()?;
    kprobe.load("tcp_sendmsg", &btf)?;
    kprobe.attach()?;

    let kprobe_recv: &mut FEntry = ebpf
        .program_mut("handle_tcp_cleanup_rbuf")
        .context("fentry program handle_tcp_cleanup_rbuf not found")?
        .try_into()?;
    kprobe_recv.load("tcp_cleanup_rbuf", &btf)?;
    kprobe_recv.attach()?;

    // SOCK_OFFSETS:从 vmlinux BTF 解出的 sock_common 字段偏移,推到 eBPF 端给
    // try_handle_sock_set_state 走 bpf_probe_read_kernel 用。
    let offsets = parse_sock_offsets()?;
    let offsets_key = 0u32;
    let mut offsets_map: BpfHashMap<_, u32, SockOffsets> = BpfHashMap::try_from(
        ebpf.map_mut("SOCK_OFFSETS")
            .context("SOCK_OFFSETS map not found")?,
    )?;
    offsets_map.insert(offsets_key, offsets, 0)?;

    let tracepoint: &mut BtfTracePoint = ebpf
        .program_mut("handle_sock_set_state")
        .context("btf_tracepoint program handle_sock_set_state not found")?
        .try_into()?;
    tracepoint.load("inet_sock_set_state", &btf)?;
    tracepoint.attach()?;

    // 三个 program 全部 attach 成功 ⇔ verifier 已通过、kernel 侧 hook 已挂上、
    // 之后任何 tcp_sendmsg / tcp_cleanup_rbuf / inet_sock_set_state 都会触发我们的
    // ebpf 程序。把这条日志放在最后一次 attach() 之后,出现即代表 ebpf 侧上线。
    info!(
        "eBPF programs attached: fentry tcp_sendmsg + fentry tcp_cleanup_rbuf + tp_btf inet_sock_set_state"
    );

    // EbpfLogger::init 必须放在所有 program.load() 之后
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let connections_map = ebpf
        .take_map("CONNECTIONS")
        .context("CONNECTIONS map not found")?;
    //每个 CPU 一份独立的 ConnectionThroughputStats 实例
    let mut connections: BpfPerCpuHashMap<_, ConnectionIdentifier, ConnectionThroughputStats> =
        BpfPerCpuHashMap::try_from(connections_map)?;

    let states_map = ebpf
        .take_map("CONNECTION_STATES")
        .context("CONNECTION_STATES map not found")?;
    // 与 CONNECTIONS 解耦的状态表:0=closed,非 0=active。只有 sock_set_state 路径写它,
    // 用户态把它当一张普通 HashMap 读即可。
    let mut connection_states: BpfHashMap<_, ConnectionIdentifier, u64> =
        BpfHashMap::try_from(states_map)?;

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

    let (metrics_startup_tx, metrics_startup_rx) = oneshot::channel();
    let metrics_task = tokio::spawn(http_server::run_metrics_server(
        metrics_addr,
        endpoint.clone(),
        opt.debug_resolver_enabled,
        debug_resolver_endpoint,
        Arc::clone(&resolver),
        metrics_startup_tx,
        shutdown_rx,
    ));

    match metrics_startup_rx.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "metrics server startup signal dropped: {e}"
            ));
        }
    }

    info!("metrics server listening on {}{}", metrics_addr, endpoint);
    // 为什么这张表必须存在（即使 prometheus 自己也是个 KV 存储）：
    //   - caretta_links_observed 是 Counter，对外语义"自启动以来累计字节"，单调不减。
    //   - 字节的真源头在 eBPF CONNECTIONS map 里：每条 4-tuple 对应一份 bytes_sent
    //     /bytes_received 计数。但连接关闭后这份计数会被用户态在收割阶段从 map 删除
    //     —— 那一瞬间，该 link 在 eBPF 视角"消失"。
    //   - 如果不在用户态把已死连接的字节数记住，下一个 tick 上报时这条 link 的累计
    //     字节数会跌到 0，prometheus 看到 Counter 倒退会触发 reset 处理，PromQL 的
    //     rate()/increase() 全部失真。
    //
    // 为什么需要 GC：
    // 短连接抖动、滚动更新换 IP、外部 IP 大量进出，都会让表无界膨胀——同时同步泄漏
    // LAST_LINK_TOTALS 和 LINKS_METRICS 的 prometheus series。GC 用
    // LINK_GC_TTL 给一条 link 没活动后 N 分钟的宽限，过期后调 metrics::forget_link
    // 一并清掉所有相关状态。
    let mut links: HashMap<NetworkLink, LinkState> = HashMap::new();

    // TCP series 生命周期跟踪：记录"每条连接最近 N 个 tick 的可见性"，连续 missed_ticks > 阈值就调
    // metrics::forget_tcp 把 series 真正从注册表里抠掉。
    let mut tcp_states: HashMap<TcpConnectionKey, TcpState> = HashMap::new();

    let mut ticker = tokio::time::interval(Duration::from_secs(opt.poll_interval.max(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip); // 不在压力大时堆积过多 tick，反正每个 tick 都是全量扫描。

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("received shutdown signal");
                let _ = shutdown_tx.send(true);
                break;
            }
            _ = ticker.tick() => {
                metrics::mark_poll();
                let now = Instant::now();

                let mut current_links: HashMap<NetworkLink, u64> = HashMap::new();
                // 本 tick 在 eBPF map 里实际见到（活跃或刚关闭）的 link 集合——只有
                // 这些 link 在 GC 端会被刷新 last_active。已经从 eBPF map 消失、仅靠
                // past 累计值留在 links 表里的 link 不在此集合中，它们会自然老化。
                let mut link_seen_this_tick: std::collections::HashSet<NetworkLink> =
                    std::collections::HashSet::new();
                // 本 tick 看到的 TCP 连接 key 集合——GC 用它来增 missed_ticks 计数。
                let mut tcp_seen_this_tick: std::collections::HashSet<TcpConnectionKey> =
                    std::collections::HashSet::new();
                let mut current_tcp_connections: Vec<TcpConnection> = Vec::new();
                let mut to_delete: Vec<ConnectionIdentifier> = Vec::new();
                let mut loopback_counter = 0u64;
                let mut items_counter = 0u64;

                let mut entries = connection_states.iter();
                // Pass 1:同步收集所有 entry,顺手处理 to_delete / loopback / items_counter。
                // resolver 调用全推到 Pass 2 走并发
                // 主循环以 CONNECTION_STATES 为权威连接清单——它在 sock_set_state 路径上
                // open 时写 1、close 时写 0
                let mut pending: Vec<(ConnectionIdentifier, u64, ConnectionThroughputStats)> =
                    Vec::new();
                while let Some(entry) = entries.next() {
                    let (conn, is_active) = match entry {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("failed to iterate map entry: {e}");
                            continue;
                        }
                    };
                    items_counter += 1;

                    // 把每个 CPU 上累加的 bytes_sent / bytes_received 各自求和才是这条连接的真实累计。
                    // KeyNotFound 是合法的——open 之后还没传过字节,按零计。
                    let throughput = match connections.get(&conn, 0) {
                        Ok(per_cpu) => aggregate_per_cpu_throughput(per_cpu.iter().copied()),
                        Err(_) => ConnectionThroughputStats {
                            bytes_sent: 0,
                            bytes_received: 0,
                        },
                    };

                    if is_active == 0 {
                        to_delete.push(conn);
                    }

                    if conn.tuple.src_ip == conn.tuple.dst_ip && is_loopback(conn.tuple.dst_ip) {
                        loopback_counter += 1;
                        continue;
                    }

                    pending.push((conn, is_active, throughput));
                }

                // Pass 2:resolver 调用并发 fan-out。
                let resolver_ref = resolver.as_ref();
                let resolved = futures_util::future::join_all(pending.into_iter().map(
                    |(conn, is_active, throughput)| async move {
                        let link = reduce_connection_to_link(resolver_ref, conn).await.ok()?;
                        let tcp =
                            reduce_connection_to_tcp(resolver_ref, conn, throughput, is_active)
                                .await
                                .ok()?;
                        Some((link, tcp, throughput))
                    },
                ))
                .await;

                for (link, tcp, throughput) in resolved.into_iter().flatten() {
                    let bytes = throughput.bytes_sent.saturating_add(throughput.bytes_received);
                    *current_links.entry(link.clone()).or_insert(0) += bytes;
                    link_seen_this_tick.insert(link);
                    tcp_seen_this_tick.insert(TcpConnectionKey::from(&tcp));
                    current_tcp_connections.push(tcp);
                }

                metrics::set_map_size(items_counter);
                metrics::set_filtered_loopback_connections(loopback_counter);

                // 把已死亡 link 的累计字节数合并进本 tick 的 current_links。注意只读
                // 不写——last_active 不在这里刷新，否则一条死了一小时的 link 仍会每
                // tick 被"复活"，GC 永远不触发。真正活着的证据只有两条：本 tick 在
                // eBPF map 里看到（link_seen_this_tick），或被加入 to_delete（下面）。
                for (past_link, past_state) in &links {
                    *current_links.entry(past_link.clone()).or_insert(0) +=
                        past_state.cumulative_bytes;
                }

                // remove 前对候选再查一次 CONNECTION_STATES,只放行仍 is_active==0 的。
                // 防同 4-tuple+pid 在 iter 与 remove 窗口里被 eBPF 复用,错误移除新连接。
                let to_purge = caretta::purge::still_dead_keys(to_delete, |conn| {
                    matches!(connection_states.get(conn, 0), Ok(0u64))
                });

                for conn in to_purge {
                    // PerCpuHashMap.get 返回 N 个 CPU 副本,这里把它们 fold 成一份累计快照,
                    // 用于把 dying link 的最后一段字节合并进 links。
                    // 若 connections 里压根没这条 entry(open 之后 close 之前一字节没传),
                    // 走零吞吐分支,但 connection_states 里仍然必须删掉这条 entry,
                    // 否则下个 tick 又会被列回 to_delete,死循环占位。
                    let throughput = match connections.get(&conn, 0) {
                        Ok(per_cpu) => aggregate_per_cpu_throughput(per_cpu.iter().copied()),
                        Err(_) => ConnectionThroughputStats {
                            bytes_sent: 0,
                            bytes_received: 0,
                        },
                    };

                    // CONNECTIONS 表的 remove 失败只是 best-effort 清理——可能本来就没 entry。
                    // CONNECTION_STATES 的 remove 才是关键路径,删失败下个 tick 会把它重新
                    // 列回 to_delete,需要 mark 一条失败计数。
                    let _ = connections.remove(&conn);

                    if let Err(e) = connection_states.remove(&conn) {
                        warn!("Error deleting connection state from map: {e}");
                        metrics::mark_failed_connection_deletion();
                        continue;
                    }

                    if let Ok(link) = reduce_connection_to_link(resolver.as_ref(), conn).await {
                        let bytes = throughput.bytes_sent.saturating_add(throughput.bytes_received);
                        // 写入即"还活着的证据"——刷新 last_active 让 GC 重新计时。
                        let entry = links.entry(link).or_insert_with(|| LinkState {
                            cumulative_bytes: 0,
                            last_active: now,
                        });
                        entry.cumulative_bytes = entry.cumulative_bytes.saturating_add(bytes);
                        entry.last_active = now;
                    }
                    metrics::mark_map_deletion();
                }

                // 上报 link counter。同时对"本 tick 真正看到的"link 刷新 last_active
                // ——已死、靠 past 累计值进 current_links 的 link 不进 link_seen，
                // 不被刷新，也就不会逃过 GC。
                for (link, throughput) in current_links {
                    metrics::handle_link_metric(&link, throughput);
                    if link_seen_this_tick.contains(&link) {
                        links
                            .entry(link)
                            .and_modify(|s| s.last_active = now)
                            .or_insert(LinkState {
                                cumulative_bytes: 0,
                                last_active: now,
                            });
                    }
                }

                for tcp in current_tcp_connections {
                    metrics::handle_tcp_metric(&tcp);
                    let key = TcpConnectionKey::from(&tcp);
                    tcp_states
                        .entry(key)
                        .and_modify(|s| {
                            s.last_seen_conn = tcp.clone();
                            s.missed_ticks = 0;
                        })
                        .or_insert(TcpState {
                            last_seen_conn: tcp,
                            missed_ticks: 0,
                        });
                }

                // ---- GC: link series ----
                // 把 last_active 早于 (now - LINK_GC_TTL) 的 link 全部清掉，并同步删除
                // 它们在 prometheus 注册表 + LAST_LINK_TOTALS 里的状态。
                let ttl = LINK_GC_TTL;
                links.retain(|link, state| {
                    if now.duration_since(state.last_active) > ttl {
                        metrics::forget_link(link);
                        false
                    } else {
                        true
                    }
                });

                // ---- GC: tcp series ----
                // 本 tick 没看到的连接 missed_ticks +1；超过阈值的 forget 并从表里抹去。
                // 修问题：connection 被 ebpf map 删除后仍保留 series。
                tcp_states.retain(|key, state| {
                    if tcp_seen_this_tick.contains(key) {
                        // 在本 tick 已被上面的 entry().and_modify() 重置过 missed_ticks
                        // 与 last_seen_conn——这里只需保留即可。
                        true
                    } else {
                        state.missed_ticks = state.missed_ticks.saturating_add(1);
                        if state.missed_ticks > TCP_GC_MISSED_TICKS {
                            metrics::forget_tcp(key);
                            false
                        } else {
                            true
                        }
                    }
                });
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
