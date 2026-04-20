//! Prometheus metric definitions and update helpers for links and TCP states.

use crate::types::{NetworkLink, TcpConnection, fnv_hash};
use once_cell::sync::Lazy;
use prometheus::{Gauge, GaugeVec, IntCounter, IntCounterVec, Opts};

static LINKS_METRICS: Lazy<GaugeVec> = Lazy::new(|| {
    let g = GaugeVec::new(
        Opts::new(
            "caretta_links_observed",
            "total bytes transferred (bytes_sent + bytes_received) observed per link since launch",
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
    .expect("create caretta_links_observed");
    prometheus::default_registry()
        .register(Box::new(g.clone()))
        .expect("register caretta_links_observed");
    g
});

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

// Counts all processed watch stream events by Kubernetes object type.
// This helps quantify watcher churn and event pressure during control-plane instability.
// 量化事件压力：当控制平面（如 API Server 或 etcd）发生故障或网络抖动时，短时间内可能触发大量资源更新。该指标的陡增能直接反映“事件风暴”。
// 发现异常波动：如果一个平时事件量很少的控制器突然收到海量事件，可能是上游系统（如 HPA）频繁修改资源，或者集群发生了大规模驱逐。
static WATCHER_EVENTS_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "caretta_watcher_events_count",
            "total number of Kubernetes watcher events processed by object type",
        ),
        &["object_type"],
    )
    .expect("create caretta_watcher_events_count");
    prometheus::default_registry()
        .register(Box::new(c.clone()))
        .expect("register caretta_watcher_events_count");
    c
});

// Counts successful watch stream re-establishments by object type.
// The initial watch start is excluded; only reconnects are counted.
// 当 Watch 长连接断开后，客户端成功与 API Server 重新建立连接并恢复监听的次数。
// 衡量连接稳定性：频繁的重连意味着客户端与 API Server 之间的网络不稳定，或者 API Server 负载过高导致超时。
static WATCHER_RESETS_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "caretta_watcher_resets_count",
            "total number of Kubernetes watcher reconnects by object type",
        ),
        &["object_type"],
    )
    .expect("create caretta_watcher_resets_count");
    prometheus::default_registry()
        .register(Box::new(c.clone()))
        .expect("register caretta_watcher_resets_count");
    c
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

// Record one watcher event for the given object type label.
pub fn mark_watcher_event(object_type: &str) {
    WATCHER_EVENTS_COUNT
        .with_label_values(&[object_type])
        .inc();
}

    // Record one watcher reconnect/reset for the given object type label.
pub fn mark_watcher_reset(object_type: &str) {
    WATCHER_RESETS_COUNT
        .with_label_values(&[object_type])
        .inc();
}

/// Update the link throughput gauge for a single normalized link.
pub fn handle_link_metric(link: &NetworkLink, throughput: u64) {
    let link_id = (fnv_hash(
        &(link.client.name.clone()
            + &link.client.namespace
            + &link.server.name
            + &link.server.namespace),
    ) + link.role)
        .to_string();
    let client_id = fnv_hash(&(link.client.name.clone() + &link.client.namespace)).to_string();
    let server_id = fnv_hash(&(link.server.name.clone() + &link.server.namespace)).to_string();
    let server_port = link.server_port.to_string();
    let role = link.role.to_string();

    LINKS_METRICS
        .with_label_values(&[
            &link_id,
            &client_id,
            &link.client.name,
            &link.client.namespace,
            &link.client.kind,
            &link.client.owner,
            &server_id,
            &link.server.name,
            &link.server.namespace,
            &link.server.kind,
            &server_port,
            &role,
        ])
        .set(throughput as f64);
}

/// Update the state gauge for a single TCP connection observation.
pub fn handle_tcp_metric(connection: &TcpConnection) {
    let link_id = (fnv_hash(
        &(connection.client.name.clone()
            + &connection.client.namespace
            + &connection.server.name
            + &connection.server.namespace),
    ) + connection.role)
        .to_string();
    let client_id =
        fnv_hash(&(connection.client.name.clone() + &connection.client.namespace)).to_string();
    let server_id =
        fnv_hash(&(connection.server.name.clone() + &connection.server.namespace)).to_string();
    let server_port = connection.server_port.to_string();
    let role = connection.role.to_string();

    TCP_STATE_METRICS
        .with_label_values(&[
            &link_id,
            &client_id,
            &connection.client.name,
            &connection.client.namespace,
            &connection.client.kind,
            &connection.client.owner,
            &server_id,
            &connection.server.name,
            &connection.server.namespace,
            &connection.server.kind,
            &server_port,
            &role,
        ])
        .set(connection.state as f64);
}
