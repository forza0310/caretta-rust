//! Prometheus metric definitions and update helpers for links and TCP states.

use crate::types::{NetworkLink, TcpConnection, fnv_hash};
use once_cell::sync::Lazy;
use prometheus::{Gauge, GaugeVec, IntCounter, Opts};

static LINKS_METRICS: Lazy<GaugeVec> = Lazy::new(|| {
    let g = GaugeVec::new(
        Opts::new(
            "caretta_links_observed",
            "total bytes_sent value of links observed by caretta since its launch",
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
