//! Prometheus metric definitions and update helpers for links and TCP states.

use crate::types::{NetworkLink, TcpConnection, TcpConnectionKey, fnv_hash_parts};
use log::warn;
use once_cell::sync::Lazy;
use prometheus::{CounterVec, Gauge, GaugeVec, IntCounter, Opts};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static LINKS_METRICS: Lazy<CounterVec> = Lazy::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "caretta_links_observed",
            "total bytes transferred (bytes_sent + bytes_received) observed per link since launch",
        ),
        &[
            "link_id",
            "client_id",
            "client_ip",
            "client_name",
            "client_namespace",
            "client_kind",
            "client_owner",
            "server_id",
            "server_ip",
            "server_port",
            "server_name",
            "server_namespace",
            "server_kind",
            "role",
        ],
    )
    .expect("create caretta_links_observed");
    prometheus::default_registry()
        .register(Box::new(c.clone()))
        .expect("register caretta_links_observed");
    c
});

// 每条 link 上次上报到的累计字节数。
//
// 生命周期管理：与 main.rs `links` 表一一对应。链路 GC 时（main.rs 的 retain）调
// metrics::forget_link()，forget_link 会同时把这里的 entry 也抹掉，避免泄漏。
static LAST_LINK_TOTALS: Lazy<Mutex<HashMap<String, u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static TCP_STATE_METRICS: Lazy<GaugeVec> = Lazy::new(|| {
    let g = GaugeVec::new(
        Opts::new(
            "caretta_tcp_states",
            "state of TCP connections observed by caretta since its launch",
        ),
        &[
            "link_id",
            "client_id",
            "client_name",
            "client_namespace",
            "client_kind",
            "client_owner",
            "server_id",
            "server_name",
            "server_namespace",
            "server_kind",
            "server_port",
            "role",
        ],
    )
    .expect("create caretta_tcp_states");
    prometheus::default_registry()
        .register(Box::new(g.clone()))
        .expect("register caretta_tcp_states");
    g
});

static POLLS_MADE: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new("caretta_polls_made", "Counter of polls made by caretta")
        .expect("create caretta_polls_made");
    prometheus::default_registry()
        .register(Box::new(c.clone()))
        .expect("register caretta_polls_made");
    c
});

static FAILED_CONNECTION_DELETION: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new(
        "caretta_failed_deletions",
        "Counter of failed deletion of closed connection from map",
    )
    .expect("create caretta_failed_deletions");
    prometheus::default_registry()
        .register(Box::new(c.clone()))
        .expect("register caretta_failed_deletions");
    c
});

static FILTERED_LOOPBACK_CONNECTIONS: Lazy<Gauge> = Lazy::new(|| {
    let g = Gauge::new(
        "caretta_current_loopback_connections",
        "Number of loopback connections observed in the last iteration",
    )
    .expect("create caretta_current_loopback_connections");
    prometheus::default_registry()
        .register(Box::new(g.clone()))
        .expect("register caretta_current_loopback_connections");
    g
});

static MAP_SIZE: Lazy<Gauge> = Lazy::new(|| {
    let g = Gauge::new(
        "caretta_ebpf_connections_map_size",
        "number of items in the connections map iterated from user space per iteration",
    )
    .expect("create caretta_ebpf_connections_map_size");
    prometheus::default_registry()
        .register(Box::new(g.clone()))
        .expect("register caretta_ebpf_connections_map_size");
    g
});

static MAP_DELETIONS: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new(
        "caretta_connection_deletions",
        "total number of deletions from the map done by the userspace",
    )
    .expect("create caretta_connection_deletions");
    prometheus::default_registry()
        .register(Box::new(c.clone()))
        .expect("register caretta_connection_deletions");
    c
});

// Watch 心跳:每条 watch 上次收到任意流量(Added/Modified/Deleted/Bookmark 都算)的
// unix 时间戳。
static K8S_WATCH_LAST_ACTIVE_UNIX_SECONDS: Lazy<GaugeVec> = Lazy::new(|| {
    let g = GaugeVec::new(
        Opts::new(
            "caretta_k8s_watch_last_active_unix_seconds",
            "unix timestamp of the most recent watch-stream activity (any kind) per Kubernetes object type",
        ),
        &["object_type"],
    )
    .expect("create caretta_k8s_watch_last_active_unix_seconds");
    prometheus::default_registry()
        .register(Box::new(g.clone()))
        .expect("register caretta_k8s_watch_last_active_unix_seconds");
    g
});

pub fn mark_poll() {
    POLLS_MADE.inc();
}

pub fn set_map_size(items_counter: u64) {
    MAP_SIZE.set(items_counter as f64);
}

pub fn set_filtered_loopback_connections(loopback_counter: u64) {
    FILTERED_LOOPBACK_CONNECTIONS.set(loopback_counter as f64);
}

pub fn mark_failed_connection_deletion() {
    FAILED_CONNECTION_DELETION.inc();
}

pub fn mark_map_deletion() {
    MAP_DELETIONS.inc();
}

/// 刷新某条 watch 的"上次任意活动"时间戳,用于存活监控。bookmark / Added / Modified /
/// Deleted 都会触发刷新。
pub fn mark_k8s_watch_alive(object_type: &str) {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    K8S_WATCH_LAST_ACTIVE_UNIX_SECONDS
        .with_label_values(&[object_type])
        .set(now_secs);
}

/// 构造 `caretta_links_observed` 这条 series 的全部 label values。
/// 返回 14 元素数组，顺序与 LINKS_METRICS 注册时的 label 顺序严格一一对应。
///
/// 用 `Cow` 而不是 `String`:14 个里只有 link_id/client_id/server_id/server_port/role
/// 这 5 个是现算的(Owned),其余 9 个本就是 `NetworkLink` 里现成的串,直接借引用
/// (Borrowed),省掉每条 link 每 tick 的 9 次 clone。
fn link_label_values(link: &NetworkLink) -> [Cow<'_, str>; 14] {
    let link_id = (fnv_hash_parts(&[
        link.client.name.as_str(),
        link.client.namespace.as_str(),
        link.server.name.as_str(),
        link.server.namespace.as_str(),
    ]) ^ link.role.wrapping_mul(0x9E3779B1))
    .to_string();
    // ("a","bcd") 撞同一串；role 用 wrapping_mul 一个 32-bit 黄金比例常数后再 xor，
    // 让不同 role 的 link_id 在所有 bit 上充分发散，而不是只差最低位。
    let client_id =
        fnv_hash_parts(&[link.client.name.as_str(), link.client.namespace.as_str()]).to_string();
    let server_id =
        fnv_hash_parts(&[link.server.name.as_str(), link.server.namespace.as_str()]).to_string();
    [
        Cow::Owned(link_id),
        Cow::Owned(client_id),
        Cow::Borrowed(link.client_ip.as_str()),
        Cow::Borrowed(link.client.name.as_str()),
        Cow::Borrowed(link.client.namespace.as_str()),
        Cow::Borrowed(link.client.kind.as_str()),
        Cow::Borrowed(link.client.owner.as_str()),
        Cow::Owned(server_id),
        Cow::Borrowed(link.server_ip.as_str()),
        Cow::Owned(link.server_port.to_string()),
        Cow::Borrowed(link.server.name.as_str()),
        Cow::Borrowed(link.server.namespace.as_str()),
        Cow::Borrowed(link.server.kind.as_str()),
        Cow::Owned(link.role.to_string()),
    ]
}

/// 把 `[Cow<str>; N]` 借成 `[&str; N]` 喂给 prometheus 的 with/remove_label_values
/// 与 totals key join——栈上定长数组,不再 collect 一个临时 `Vec<&str>`。
fn as_str_array<'a, const N: usize>(values: &'a [Cow<'_, str>; N]) -> [&'a str; N] {
    std::array::from_fn(|i| &*values[i])
}

/// 把 label values 拼成 LAST_LINK_TOTALS 的 key。同样和 produce 路径共用。
fn link_totals_key(refs: &[&str; 14]) -> String {
    refs.join("\x1f")
}

/// Update the link throughput counter for a single normalized link.
pub fn handle_link_metric(link: &NetworkLink, throughput: u64) {
    let label_values = link_label_values(link);
    let refs = as_str_array(&label_values);
    let link_key = link_totals_key(&refs);

    let delta = if let Ok(mut seen) = LAST_LINK_TOTALS.lock() {
        let previous = seen.get(&link_key).copied().unwrap_or(0);
        seen.insert(link_key, throughput);
        throughput.saturating_sub(previous)
    } else {
        0
    };

    if delta == 0 {
        return;
    }

    LINKS_METRICS.with_label_values(&refs).inc_by(delta as f64);
}

/// 清理一条 link 占用的所有用户态/Prometheus 状态。GC 必须把 LAST_LINK_TOTALS 里
/// 的"上次值"和 LINKS_METRICS 里的 series 一起删
///
/// 调用方需要保证：传入的 link 至少已经 N 个 tick 没有流量（main.rs 的 GC 阈值
/// LINK_GC_TTL 控制，默认 5 分钟）。
pub fn forget_link(link: &NetworkLink) {
    let label_values = link_label_values(link);
    let refs = as_str_array(&label_values);
    let link_key = link_totals_key(&refs);

    if let Ok(mut seen) = LAST_LINK_TOTALS.lock() {
        seen.remove(&link_key);
    }

    // remove_label_values 失败一律 warn:大部分会是"GC 端在 series 从未注册过的
    // 边界条件下进来"(delta 一直是 0、从未 inc_by → not-found),不算 bug 但也是
    // 信号;真正要警惕的是 cardinality drift 这类开发期 bug——同一条日志路径处理。
    if let Err(e) = LINKS_METRICS.remove_label_values(&refs) {
        warn!("forget caretta_links_observed series failed: {e} (labels: {refs:?})");
    }
}

/// 构造 `caretta_tcp_states` 这条 series 的全部 label values。
///
/// 与 link_label_values 同理——给 handle_tcp_metric 和 forget_tcp 共用,同样用 Cow
/// 借引用省 clone。注意签名收的是 TcpConnectionKey 而不是 TcpConnection：state 不参与
/// label 集合（state 在 GaugeVec 里是值不是 label），不该影响 label 拼装。
fn tcp_label_values(key: &TcpConnectionKey) -> [Cow<'_, str>; 12] {
    let link_id = (fnv_hash_parts(&[
        key.client.name.as_str(),
        key.client.namespace.as_str(),
        key.server.name.as_str(),
        key.server.namespace.as_str(),
    ]) ^ key.role.wrapping_mul(0x9E3779B1))
    .to_string();
    let client_id =
        fnv_hash_parts(&[key.client.name.as_str(), key.client.namespace.as_str()]).to_string();
    let server_id =
        fnv_hash_parts(&[key.server.name.as_str(), key.server.namespace.as_str()]).to_string();
    [
        Cow::Owned(link_id),
        Cow::Owned(client_id),
        Cow::Borrowed(key.client.name.as_str()),
        Cow::Borrowed(key.client.namespace.as_str()),
        Cow::Borrowed(key.client.kind.as_str()),
        Cow::Borrowed(key.client.owner.as_str()),
        Cow::Owned(server_id),
        Cow::Borrowed(key.server.name.as_str()),
        Cow::Borrowed(key.server.namespace.as_str()),
        Cow::Borrowed(key.server.kind.as_str()),
        Cow::Owned(key.server_port.to_string()),
        Cow::Owned(key.role.to_string()),
    ]
}

/// Update the state gauge for a single TCP connection observation.
pub fn handle_tcp_metric(connection: &TcpConnection) {
    let key = TcpConnectionKey::from(connection);
    let label_values = tcp_label_values(&key);
    let refs = as_str_array(&label_values);
    TCP_STATE_METRICS
        .with_label_values(&refs)
        .set(connection.state as f64);
}

/// 清理一条 TCP series。GC 端调用，删除条件由 main.rs 维护：
/// 连续 N 个 tick 在 eBPF map 里没看到这条连接 + 已经处于 CLOSED 状态。
///
/// 否则 TCP series 仍会泄漏：handle_tcp_metric 把 state 写成
/// CLOSED_STATE=3 是把 gauge 值改了，**series 本身依旧存活**，cardinality 一路涨。
pub fn forget_tcp(key: &TcpConnectionKey) {
    let label_values = tcp_label_values(key);
    let refs = as_str_array(&label_values);
    if let Err(e) = TCP_STATE_METRICS.remove_label_values(&refs) {
        warn!("forget caretta_tcp_states series failed: {e} (labels: {refs:?})");
    }
}

#[cfg(test)]
mod tests {
    //! 这一组测试聚焦"用户态状态表无界增长 → 进程内存 + Prometheus cardinality 泄漏"
    //! 修复的边界条件，不重复测 happy-path 数值正确性
    //! ——那部分由 review_regressions.rs 的源码守卫 + 集成路径覆盖。
    //!
    //! 关键不变量（修复必须保住的）：
    //!   I1. produce 路径与 forget 路径用完全相同的 label 集合，否则 forget 漏删 → 泄漏依旧。
    //!   I2. forget_link 必须同时清空差分基准 LAST_LINK_TOTALS，否则同名 link 复活时
    //!       会把"复活后的绝对值"全量灌入 Counter，造成毛刺。
    //!   I3. forget 对从未注册过的 series 必须无副作用（GC 在边界条件下可能重复调）。
    //!   I4. link_id 的 FNV 拼接要使用分隔符，且 role 要被充分混入——否则
    //!       ("ab","cd") vs ("a","bcd") 或不同 role 会撞 link_id。

    use super::*;
    use crate::types::{ROLE_CLIENT, ROLE_SERVER, Workload};

    fn mk_workload(ns: &str, name: &str) -> Workload {
        Workload {
            name: name.to_string(),
            namespace: ns.to_string(),
            kind: "Pod".to_string(),
            owner: String::new(),
        }
    }

    fn mk_link(client_name: &str, server_name: &str, role: u32) -> NetworkLink {
        NetworkLink {
            client: mk_workload("ns", client_name),
            server: mk_workload("ns", server_name),
            client_ip: "10.0.0.1".to_string(),
            server_ip: "10.0.0.2".to_string(),
            server_port: 80,
            role,
        }
    }

    // forget 后再 produce 同样字节数，差分基准应为 0 → delta = throughput
    // 全量重新上报。如果 forget 没清 LAST_LINK_TOTALS，这里 delta 会是 0。
    #[test]
    fn forget_link_should_reset_delta_baseline() {
        let link = mk_link("uniq-client-A", "uniq-server-A", ROLE_CLIENT);

        handle_link_metric(&link, 1000);
        // 第一次 1000 → delta 1000，基准记到 1000。
        handle_link_metric(&link, 1000);
        // 第二次同值 → delta 0，handle 早退；基准仍是 1000。

        forget_link(&link);

        handle_link_metric(&link, 1000);
        // 如果 forget 漏清基准：previous=1000, throughput=1000 → delta=0；series
        // 不会被重新创建。下面这次 forget 找不到 series 也悄悄 no-op，测试通过——
        // 这正是修复前的"泄漏 + 漂移"行为，所以我们要从相反方向断言：第二次 forget
        // 必须真的找到 series 才能删（remove_label_values 成功）。
        let label_values = link_label_values(&link);
        let refs = as_str_array(&label_values);
        // remove_label_values 成功 → series 存在 → forget 后 produce 重建成功 →
        // 基准真被清空。
        assert!(
            LINKS_METRICS.remove_label_values(&refs).is_ok(),
            "forget_link must reset baseline so subsequent produce re-registers series"
        );
    }

    // forget 对从未存在的 link 是 no-op，不应 panic / 不应污染状态。
    #[test]
    fn forget_link_should_be_noop_for_never_seen_link() {
        let link = mk_link("never-existed-x", "never-existed-y", ROLE_CLIENT);
        // 不 produce，直接 forget——多次也应安全。
        forget_link(&link);
        forget_link(&link);
    }

    // 验证拼 link_id 时 ("ab","cd") 与 ("a","bcd") 不会撞——分隔符防撞守卫。
    #[test]
    fn link_label_should_disambiguate_concatenated_names() {
        let link_a = NetworkLink {
            client: mk_workload("ab", "x"),
            server: mk_workload("cd", "y"),
            client_ip: "1.1.1.1".to_string(),
            server_ip: "2.2.2.2".to_string(),
            server_port: 80,
            role: ROLE_CLIENT,
        };
        let link_b = NetworkLink {
            client: mk_workload("a", "x"),
            server: mk_workload("bcd", "y"),
            client_ip: "1.1.1.1".to_string(),
            server_ip: "2.2.2.2".to_string(),
            server_port: 80,
            role: ROLE_CLIENT,
        };
        let id_a = &link_label_values(&link_a)[0];
        let id_b = &link_label_values(&link_b)[0];
        assert_ne!(
            id_a, id_b,
            "link_id must disambiguate name/namespace concatenation"
        );
    }

    // 同 4-tuple 不同 role 的 link_id 必须在 hash 高位也分开，而不是只差最低位。
    // 我们不能直接断言"差很多 bit"，但可以验证 ROLE_CLIENT/SERVER
    // 之间的 id 完全不同。
    #[test]
    fn link_id_should_diverge_across_roles() {
        let client_link = mk_link("c", "s", ROLE_CLIENT);
        let server_link = mk_link("c", "s", ROLE_SERVER);
        let id_c = &link_label_values(&client_link)[0];
        let id_s = &link_label_values(&server_link)[0];
        assert_ne!(id_c, id_s, "different role must produce different link_id");
    }

    // forget_tcp 对从未存在的 series 应 no-op。
    #[test]
    fn forget_tcp_should_be_noop_for_never_seen_key() {
        let key = TcpConnectionKey {
            client: mk_workload("ns", "uniq-tcp-x"),
            server: mk_workload("ns", "uniq-tcp-y"),
            server_port: 9999,
            role: ROLE_CLIENT,
        };
        forget_tcp(&key);
        forget_tcp(&key);
    }

    // TcpConnectionKey 不依赖 state，同一连接的 OPEN/CLOSED 写法应映射
    // 到同一组 label —— 否则 GC 会按 state 分裂出多条 series。
    #[test]
    fn tcp_key_should_be_state_independent() {
        let conn_open = TcpConnection {
            client: mk_workload("ns", "tcp-open-x"),
            server: mk_workload("ns", "tcp-open-y"),
            server_port: 80,
            role: ROLE_CLIENT,
            state: 1, // OPEN
        };
        let conn_closed = TcpConnection {
            state: 3, // CLOSED
            ..conn_open.clone()
        };
        let key_open = TcpConnectionKey::from(&conn_open);
        let key_closed = TcpConnectionKey::from(&conn_closed);
        assert_eq!(
            key_open, key_closed,
            "TcpConnectionKey must collapse state variants to a single GC entry"
        );
        assert_eq!(
            tcp_label_values(&key_open),
            tcp_label_values(&key_closed),
            "label values must be identical regardless of state"
        );
    }
}
