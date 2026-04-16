use anyhow::Context as _;
use aya::maps::HashMap as BpfHashMap;
use aya::programs::{KProbe, TracePoint};
use clap::Parser;
use k8s_openapi::api::core::v1::{Node, Pod, Service};
use kube::api::ListParams;
use kube::{Api, Client};
use log::{info, warn};
use once_cell::sync::Lazy;
use prometheus::{Encoder, Gauge, GaugeVec, IntCounter, Opts, TextEncoder};
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::watch;

const DEFAULT_PROMETHEUS_ENDPOINT: &str = "/metrics";
const DEFAULT_PROMETHEUS_PORT: u16 = 7117;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

const ROLE_CLIENT: u32 = 1;
const ROLE_SERVER: u32 = 2;

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

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Default)]
struct ConnectionTuple {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Default)]
struct ConnectionIdentifier {
    id: u32,
    pid: u32,
    tuple: ConnectionTuple,
    role: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct ConnectionThroughputStats {
    bytes_sent: u64,
    bytes_received: u64,
    is_active: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct TraceOffsets {
    skaddr_off: u32,
    newstate_off: u32,
    sport_off: u32,
    dport_off: u32,
    saddr_off: u32,
    daddr_off: u32,
}

unsafe impl aya::Pod for ConnectionTuple {}
unsafe impl aya::Pod for ConnectionIdentifier {}
unsafe impl aya::Pod for ConnectionThroughputStats {}
unsafe impl aya::Pod for TraceOffsets {}

fn parse_tracepoint_offsets(path: &str) -> anyhow::Result<TraceOffsets> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read tracepoint format: {path}"))?;

    fn find_offset(content: &str, field_name: &str) -> anyhow::Result<u32> {
        for line in content.lines() {
            if !line.contains("field:") || !line.contains(field_name) || !line.contains("offset:") {
                continue;
            }
            if let Some(pos) = line.find("offset:") {
                let rest = &line[(pos + "offset:".len())..];
                let digits: String = rest
                    .chars()
                    .skip_while(|c| c.is_ascii_whitespace())
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if !digits.is_empty() {
                    return digits
                        .parse::<u32>()
                        .with_context(|| format!("invalid offset for field {field_name}"));
                }
            }
        }
        anyhow::bail!("field offset not found in tracepoint format: {field_name}")
    }

    Ok(TraceOffsets {
        skaddr_off: find_offset(&content, "skaddr")?,
        newstate_off: find_offset(&content, "newstate")?,
        sport_off: find_offset(&content, "sport")?,
        dport_off: find_offset(&content, "dport")?,
        saddr_off: find_offset(&content, "saddr")?,
        daddr_off: find_offset(&content, "daddr")?,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct Workload {
    name: String,
    namespace: String,
    kind: String,
    owner: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NetworkLink {
    client: Workload,
    server: Workload,
    server_port: u16,
    role: u32,
}

impl Hash for NetworkLink {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.client.hash(state);
        self.server.hash(state);
        self.server_port.hash(state);
        self.role.hash(state);
    }
}

#[derive(Clone, Debug)]
struct TcpConnection {
    client: Workload,
    server: Workload,
    server_port: u16,
    role: u32,
    state: u32,
}

const TCP_CONNECTION_OPEN_STATE: u32 = 1;
const TCP_CONNECTION_ACCEPT_STATE: u32 = 2;
const TCP_CONNECTION_CLOSED_STATE: u32 = 3;

#[derive(Debug, Clone, Parser)]
struct Opt {
    #[clap(long, default_value_t = DEFAULT_PROMETHEUS_PORT)]
    prometheus_port: u16,
    #[clap(long, default_value = DEFAULT_PROMETHEUS_ENDPOINT)]
    prometheus_endpoint: String,
    #[clap(long, default_value_t = DEFAULT_POLL_INTERVAL_SECS)]
    poll_interval: u64,
}

impl Opt {
    fn from_env_and_args() -> Self {
        let mut opt = Self::parse();

        if let Ok(v) = std::env::var("PROMETHEUS_PORT") {
            if let Ok(p) = v.parse::<u16>() {
                opt.prometheus_port = p;
            }
        }
        if let Ok(v) = std::env::var("PROMETHEUS_ENDPOINT") {
            if !v.is_empty() {
                opt.prometheus_endpoint = v;
            }
        }
        if let Ok(v) = std::env::var("POLL_INTERVAL") {
            if let Ok(i) = v.parse::<u64>() {
                opt.poll_interval = i.max(1);
            }
        }

        opt
    }
}

trait IpResolver: Send + Sync {
    fn resolve_ip(&self, ip: u32) -> Workload;
}

struct StaticResolver;

impl IpResolver for StaticResolver {
    fn resolve_ip(&self, ip: u32) -> Workload {
        Workload {
            name: Ipv4Addr::from(u32::from_le(ip)).to_string(),
            namespace: "external".to_string(),
            kind: "external".to_string(),
            owner: String::new(),
        }
    }
}

struct K8sResolver {
    ips: std::sync::RwLock<HashMap<u32, Workload>>,
}

impl K8sResolver {
    async fn try_new() -> anyhow::Result<Arc<Self>> {
        let resolver = Arc::new(Self {
            ips: std::sync::RwLock::new(HashMap::new()),
        });

        let client = Client::try_default()
            .await
            .context("failed to create Kubernetes client")?;

        resolver
            .refresh_with_client(&client)
            .await
            .context("failed to load initial Kubernetes snapshot")?;

        let resolver_clone = Arc::clone(&resolver);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                if let Err(err) = resolver_clone.refresh_with_client(&client).await {
                    warn!("failed to refresh Kubernetes snapshot: {err}");
                }
            }
        });

        Ok(resolver)
    }

    async fn refresh_with_client(&self, client: &Client) -> anyhow::Result<()> {
        let mut next = HashMap::new();

        let pods: Api<Pod> = Api::all(client.clone());
        let pod_list = pods.list(&ListParams::default()).await?;
        for pod in pod_list.items {
            let namespace = pod.metadata.namespace.clone().unwrap_or_default();
            let name = pod.metadata.name.clone().unwrap_or_default();
            let owner = pod
                .metadata
                .owner_references
                .as_ref()
                .and_then(|refs| refs.first())
                .map(|r| r.name.clone())
                .unwrap_or_default();

            let workload = Workload {
                name,
                namespace,
                kind: "Pod".to_string(),
                owner,
            };

            if let Some(status) = pod.status {
                if let Some(pod_ips) = status.pod_ips {
                    for ip in pod_ips {
                        if let Some(parsed) = parse_ipv4_to_u32(&ip.ip) {
                            next.insert(parsed, workload.clone());
                        }
                    }
                } else if let Some(pod_ip) = status.pod_ip {
                    if let Some(parsed) = parse_ipv4_to_u32(&pod_ip) {
                        next.insert(parsed, workload.clone());
                    }
                }
            }
        }

        let services: Api<Service> = Api::all(client.clone());
        let service_list = services.list(&ListParams::default()).await?;
        for svc in service_list.items {
            let namespace = svc.metadata.namespace.clone().unwrap_or_default();
            let name = svc.metadata.name.clone().unwrap_or_default();
            let workload = Workload {
                name,
                namespace,
                kind: "Service".to_string(),
                owner: String::new(),
            };

            if let Some(spec) = svc.spec {
                if let Some(cluster_ip) = spec.cluster_ip {
                    if let Some(parsed) = parse_ipv4_to_u32(&cluster_ip) {
                        next.insert(parsed, workload.clone());
                    }
                }
                if let Some(cluster_ips) = spec.cluster_ips {
                    for ip in cluster_ips {
                        if let Some(parsed) = parse_ipv4_to_u32(&ip) {
                            next.insert(parsed, workload.clone());
                        }
                    }
                }
            }
        }

        let nodes: Api<Node> = Api::all(client.clone());
        let node_list = nodes.list(&ListParams::default()).await?;
        for node in node_list.items {
            let name = node.metadata.name.clone().unwrap_or_default();
            let workload = Workload {
                name,
                namespace: "node".to_string(),
                kind: "Node".to_string(),
                owner: String::new(),
            };

            if let Some(status) = node.status {
                for addr in status.addresses.unwrap_or_default() {
                    if let Some(parsed) = parse_ipv4_to_u32(&addr.address) {
                        next.insert(parsed, workload.clone());
                    }
                }
            }
        }

        if let Ok(mut guard) = self.ips.write() {
            *guard = next;
        }

        Ok(())
    }
}

impl IpResolver for K8sResolver {
    fn resolve_ip(&self, ip: u32) -> Workload {
        if let Ok(guard) = self.ips.read() {
            if let Some(workload) = guard.get(&ip) {
                return workload.clone();
            }
        }

        Workload {
            name: Ipv4Addr::from(u32::from_le(ip)).to_string(),
            namespace: "external".to_string(),
            kind: "external".to_string(),
            owner: String::new(),
        }
    }
}

fn parse_ipv4_to_u32(ip: &str) -> Option<u32> {
    ip.parse::<Ipv4Addr>().ok().map(|v| u32::from(v).to_le())
}

impl fmt::Display for NetworkLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({}) -> {}({}) : {} role={}",
            self.client.name,
            self.client.namespace,
            self.server.name,
            self.server.namespace,
            self.server_port,
            self.role
        )
    }
}

fn fnv_hash(s: &str) -> u32 {
    let mut hash = 0x811C9DC5u32;
    for b in s.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn reduce_connection_to_link(
    resolver: &dyn IpResolver,
    conn: ConnectionIdentifier,
) -> anyhow::Result<NetworkLink> {
    let src = resolver.resolve_ip(conn.tuple.src_ip);
    let dst = resolver.resolve_ip(conn.tuple.dst_ip);

    match conn.role {
        ROLE_CLIENT => Ok(NetworkLink {
            client: src,
            server: dst,
            server_port: conn.tuple.dst_port,
            role: conn.role,
        }),
        ROLE_SERVER => Ok(NetworkLink {
            client: dst,
            server: src,
            server_port: conn.tuple.src_port,
            role: conn.role,
        }),
        _ => anyhow::bail!("unknown connection role"),
    }
}

fn reduce_connection_to_tcp(
    resolver: &dyn IpResolver,
    conn: ConnectionIdentifier,
    throughput: ConnectionThroughputStats,
) -> anyhow::Result<TcpConnection> {
    let src = resolver.resolve_ip(conn.tuple.src_ip);
    let dst = resolver.resolve_ip(conn.tuple.dst_ip);

    let mut connection = match conn.role {
        ROLE_CLIENT => TcpConnection {
            client: src,
            server: dst,
            server_port: conn.tuple.dst_port,
            role: conn.role,
            state: TCP_CONNECTION_OPEN_STATE,
        },
        ROLE_SERVER => TcpConnection {
            client: dst,
            server: src,
            server_port: conn.tuple.src_port,
            role: conn.role,
            state: TCP_CONNECTION_ACCEPT_STATE,
        },
        _ => anyhow::bail!("unknown connection role"),
    };

    if throughput.is_active == 0 {
        connection.state = TCP_CONNECTION_CLOSED_STATE;
    }

    Ok(connection)
}

fn is_loopback(ip: u32) -> bool {
    Ipv4Addr::from(u32::from_le(ip)).is_loopback()
}

fn handle_link_metric(link: &NetworkLink, throughput: u64) {
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

fn handle_tcp_metric(connection: &TcpConnection) {
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

async fn run_metrics_server(
    addr: SocketAddr,
    endpoint: String,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind metrics server at {addr}"))?;

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (mut stream, _) = accepted?;
                let endpoint = endpoint.clone();
                tokio::spawn(async move {
                    let mut req = [0u8; 1024];
                    let n = match stream.read(&mut req).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };

                    let first_line = String::from_utf8_lossy(&req[..n]);
                    let expected = format!("GET {endpoint} ");
                    let (status, body, content_type) = if first_line.starts_with(&expected) {
                        let encoder = TextEncoder::new();
                        let mf = prometheus::gather();
                        let mut buffer = Vec::new();
                        if encoder.encode(&mf, &mut buffer).is_err() {
                            (
                                "500 Internal Server Error",
                                b"failed to encode metrics".to_vec(),
                                String::from("text/plain"),
                            )
                        } else {
                            ("200 OK", buffer, encoder.format_type().to_string())
                        }
                    } else {
                        (
                            "404 Not Found",
                            b"not found".to_vec(),
                            String::from("text/plain"),
                        )
                    };

                    let header = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );

                    if stream.write_all(header.as_bytes()).await.is_err() {
                        return;
                    }
                    let _ = stream.write_all(&body).await;
                });
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // env_logger::init();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let opt = Opt::from_env_and_args();

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

    let offsets = parse_tracepoint_offsets("/sys/kernel/tracing/events/sock/inet_sock_set_state/format")?;
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
    let endpoint = if opt.prometheus_endpoint.starts_with('/') {
        opt.prometheus_endpoint.clone()
    } else {
        format!("/{}", opt.prometheus_endpoint)
    };

    let metrics_task = tokio::spawn(run_metrics_server(metrics_addr, endpoint.clone(), shutdown_rx));
    info!("metrics server listening on {}{}", metrics_addr, endpoint);

    let resolver: Arc<dyn IpResolver> = match K8sResolver::try_new().await {
        Ok(r) => {
            info!("kubernetes resolver enabled");
            r
        }
        Err(err) => {
            warn!("kubernetes resolver unavailable, fallback to static resolver: {err}");
            Arc::new(StaticResolver)
        }
    };
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
                POLLS_MADE.inc();

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

                    *current_links.entry(link).or_insert(0) += throughput.bytes_sent;
                    current_tcp_connections.push(tcp);
                }

                MAP_SIZE.set(items_counter as f64);
                FILTERED_LOOPBACK_CONNECTIONS.set(loopback_counter as f64);

                for (past_link, past_throughput) in &past_links {
                    *current_links.entry(past_link.clone()).or_insert(0) += *past_throughput;
                }

                for conn in to_delete {
                    let throughput = match connections.get(&conn, 0) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("Error retrieving connection to delete, skipping it: {e}");
                            FAILED_CONNECTION_DELETION.inc();
                            continue;
                        }
                    };

                    if let Err(e) = connections.remove(&conn) {
                        warn!("Error deleting connection from map: {e}");
                        FAILED_CONNECTION_DELETION.inc();
                        continue;
                    }

                    if let Ok(link) = reduce_connection_to_link(resolver.as_ref(), conn) {
                        *past_links.entry(link).or_insert(0) += throughput.bytes_sent;
                    }
                    MAP_DELETIONS.inc();
                }

                for (link, throughput) in current_links {
                    handle_link_metric(&link, throughput);
                }

                for tcp in current_tcp_connections {
                    handle_tcp_metric(&tcp);
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
