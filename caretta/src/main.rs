use anyhow::Context as _;
use aya::maps::HashMap as BpfHashMap;
use aya::programs::{KProbe, TracePoint};
use clap::Parser;
use futures_util::StreamExt;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::batch::v1::{CronJob, Job};
use k8s_openapi::api::core::v1::{Node, Pod, Service};
use kube::api::{ListParams, WatchEvent, WatchParams};
use kube::{Api, Client};
use log::{info, warn};
use once_cell::sync::Lazy;
use prometheus::{Encoder, Gauge, GaugeVec, IntCounter, Opts, TextEncoder};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{RwLock, mpsc, watch};

const DEFAULT_PROMETHEUS_ENDPOINT: &str = "/metrics";
const DEFAULT_PROMETHEUS_PORT: u16 = 7117;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
const DEFAULT_DEBUG_RESOLVER_ENDPOINT: &str = "/debug/resolver";
const DEFAULT_DEBUG_RESOLVER_ENABLED: bool = false;
const DEFAULT_TRAVERSE_UP_HIERARCHY: bool = true;
const DEFAULT_OWNER_RESOLVE_KIND_ALLOWLIST: &str = "";
const DEFAULT_OWNER_KIND_PRIORITY: &str = "";

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
    #[clap(long, default_value_t = DEFAULT_DEBUG_RESOLVER_ENABLED)]
    debug_resolver_enabled: bool,
    #[clap(long, default_value = DEFAULT_DEBUG_RESOLVER_ENDPOINT)]
    debug_resolver_endpoint: String,
    #[clap(long, default_value_t = DEFAULT_TRAVERSE_UP_HIERARCHY)]
    traverse_up_hierarchy: bool,
    #[clap(long, default_value = DEFAULT_OWNER_RESOLVE_KIND_ALLOWLIST)]
    owner_resolve_kind_allowlist: String,
    #[clap(long, default_value = DEFAULT_OWNER_KIND_PRIORITY)]
    owner_kind_priority: String,
}

impl Opt {
    fn parse_csv_values(raw: &str) -> Vec<String> {
        raw.split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string)
            .collect()
    }

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
        if let Ok(v) = std::env::var("DEBUG_RESOLVER_ENABLED") {
            if let Ok(enabled) = v.parse::<bool>() {
                opt.debug_resolver_enabled = enabled;
            }
        }
        if let Ok(v) = std::env::var("DEBUG_RESOLVER_ENDPOINT") {
            if !v.is_empty() {
                opt.debug_resolver_endpoint = v;
            }
        }
        if let Ok(v) = std::env::var("TRAVERSE_UP_HIERARCHY") {
            if let Ok(enabled) = v.parse::<bool>() {
                opt.traverse_up_hierarchy = enabled;
            }
        }
        if let Ok(v) = std::env::var("OWNER_RESOLVE_KIND_ALLOWLIST") {
            opt.owner_resolve_kind_allowlist = v;
        }
        if let Ok(v) = std::env::var("OWNER_KIND_PRIORITY") {
            opt.owner_kind_priority = v;
        }

        opt
    }

    fn owner_kind_allowlist(&self) -> HashSet<String> {
        Self::parse_csv_values(&self.owner_resolve_kind_allowlist)
            .into_iter()
            .collect()
    }

    fn owner_kind_priority(&self) -> HashMap<String, usize> {
        Self::parse_csv_values(&self.owner_kind_priority)
            .into_iter()
            .enumerate()
            .map(|(idx, kind)| (kind, idx))
            .collect()
    }
}

trait IpResolver: Send + Sync {
    fn resolve_ip(&self, ip: u32) -> Workload;
    fn debug_snapshot(&self) -> Option<String> {
        None
    }
}

struct StaticResolver;

impl IpResolver for StaticResolver {
    fn resolve_ip(&self, ip: u32) -> Workload {
        Workload {
            name: Ipv4Addr::from(ip).to_string(),
            namespace: "external".to_string(),
            kind: "external".to_string(),
            owner: String::new(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash)]
struct OwnerKey {
    namespace: String,
    kind: String,
    name: String,
}

#[derive(Clone)]
struct OwnerTarget {
    kind: String,
    name: String,
}

#[derive(Serialize)]
struct DebugResolverEntry {
    ip: String,
    name: String,
    namespace: String,
    kind: String,
    owner: String,
}

struct K8sResolver {
    client: Client,
    ips: RwLock<HashMap<u32, Workload>>,
    traverse_up_hierarchy: bool,
    owner_kind_allowlist: HashSet<String>,
    owner_kind_priority: HashMap<String, usize>,
    watch_events: AtomicU64,
}

impl K8sResolver {
    async fn try_new(
        traverse_up_hierarchy: bool,
        owner_kind_allowlist: HashSet<String>,
        owner_kind_priority: HashMap<String, usize>,
    ) -> anyhow::Result<Arc<Self>> {
        let client = Client::try_default()
            .await
            .context("failed to create Kubernetes client")?;

        let resolver = Arc::new(Self {
            client,
            ips: RwLock::new(HashMap::new()),
            traverse_up_hierarchy,
            owner_kind_allowlist,
            owner_kind_priority,
            watch_events: AtomicU64::new(0),
        });

        resolver
            .refresh_snapshot()
            .await
            .context("failed to load initial Kubernetes snapshot")?;

        resolver.spawn_watch_and_refresh_tasks();
        Ok(resolver)
    }

    fn spawn_watch_and_refresh_tasks(self: &Arc<Self>) {
        let (tx, mut rx) = mpsc::unbounded_channel::<()>();

        let refresh_resolver = Arc::clone(self);
        tokio::spawn(async move {
            while rx.recv().await.is_some() {
                if let Err(err) = refresh_resolver.refresh_snapshot().await {
                    warn!("failed to refresh Kubernetes snapshot from watch event: {err}");
                }
            }
        });

        let periodic_resolver = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                if let Err(err) = periodic_resolver.refresh_snapshot().await {
                    warn!("failed to refresh Kubernetes snapshot on periodic tick: {err}");
                }
            }
        });

        Self::spawn_watch::<Pod>(Arc::clone(self), tx.clone(), "pods");
        Self::spawn_watch::<Service>(Arc::clone(self), tx.clone(), "services");
        Self::spawn_watch::<Node>(Arc::clone(self), tx.clone(), "nodes");
        Self::spawn_watch::<ReplicaSet>(Arc::clone(self), tx.clone(), "replicasets");
        Self::spawn_watch::<Deployment>(Arc::clone(self), tx.clone(), "deployments");
        Self::spawn_watch::<StatefulSet>(Arc::clone(self), tx.clone(), "statefulsets");
        Self::spawn_watch::<DaemonSet>(Arc::clone(self), tx.clone(), "daemonsets");
        Self::spawn_watch::<Job>(Arc::clone(self), tx.clone(), "jobs");
        Self::spawn_watch::<CronJob>(Arc::clone(self), tx, "cronjobs");
    }

    fn spawn_watch<K>(resolver: Arc<Self>, tx: mpsc::UnboundedSender<()>, watch_name: &'static str)
    where
        K: Clone
            + core::fmt::Debug
            + serde::de::DeserializeOwned
            + kube::Resource<DynamicType = ()>
            + Send
            + Sync
            + 'static,
    {
        tokio::spawn(async move {
            let api: Api<K> = Api::all(resolver.client.clone());
            loop {
                let mut stream = match api.watch(&WatchParams::default(), "0").await {
                    Ok(stream) => stream.boxed(),
                    Err(err) => {
                        warn!("failed to start watch for {watch_name}: {err}");
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    }
                };

                while let Some(event) = stream.next().await {
                    match event {
                        Ok(WatchEvent::Added(_))
                        | Ok(WatchEvent::Modified(_))
                        | Ok(WatchEvent::Deleted(_))
                        | Ok(WatchEvent::Bookmark(_)) => {
                            resolver.watch_events.fetch_add(1, Ordering::Relaxed);
                            let _ = tx.send(());
                        }
                        Ok(WatchEvent::Error(e)) => {
                            warn!("watch error event for {watch_name}: {:?}", e);
                            break;
                        }
                        Err(err) => {
                            warn!("watch stream error for {watch_name}: {err}");
                            break;
                        }
                    }
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    fn first_owner_target<T>(obj: &T) -> Option<OwnerTarget>
    where
        T: kube::Resource,
    {
        obj.meta()
            .owner_references
            .as_ref()
            .and_then(|refs| refs.first())
            .map(|r| OwnerTarget {
                kind: r.kind.clone(),
                name: r.name.clone(),
            })
    }

    fn owner_key(namespace: &str, kind: &str, name: &str) -> OwnerKey {
        OwnerKey {
            namespace: namespace.to_string(),
            kind: kind.to_string(),
            name: name.to_string(),
        }
    }

    fn trace_owner_hierarchy(
        &self,
        namespace: &str,
        initial: Option<OwnerTarget>,
        owners_index: &HashMap<OwnerKey, OwnerTarget>,
    ) -> (String, String, String) {
        let mut immediate_owner = String::new();
        let mut final_kind = "Pod".to_string();
        let mut final_name = String::new();

        if let Some(first) = initial.clone() {
            immediate_owner = first.name.clone();
            final_kind = first.kind.clone();
            final_name = first.name.clone();
        }

        if !self.traverse_up_hierarchy {
            return (final_kind, final_name, immediate_owner);
        }

        let mut chain: Vec<OwnerTarget> = Vec::new();
        let mut cur = initial;
        for _ in 0..8 {
            let Some(owner) = cur.clone() else {
                break;
            };
            chain.push(owner.clone());
            final_kind = owner.kind.clone();
            final_name = owner.name.clone();

            let key = Self::owner_key(namespace, &owner.kind, &owner.name);
            cur = owners_index.get(&key).cloned();
            if cur.is_none() {
                break;
            }
        }

        if let Some(selected) = self.select_owner_from_chain(&chain) {
            final_kind = selected.kind.clone();
            final_name = selected.name.clone();
        }

        (final_kind, final_name, immediate_owner)
    }

    fn select_owner_from_chain<'a>(&self, chain: &'a [OwnerTarget]) -> Option<&'a OwnerTarget> {
        if chain.is_empty() {
            return None;
        }

        let allow_all = self.owner_kind_allowlist.is_empty();
        let mut best: Option<(usize, usize)> = None;

        for (idx, owner) in chain.iter().enumerate() {
            if !allow_all && !self.owner_kind_allowlist.contains(&owner.kind) {
                continue;
            }

            let rank = self
                .owner_kind_priority
                .get(&owner.kind)
                .copied()
                .unwrap_or(usize::MAX);

            match best {
                None => best = Some((idx, rank)),
                Some((best_idx, best_rank)) => {
                    if rank < best_rank || (rank == best_rank && idx > best_idx) {
                        best = Some((idx, rank));
                    }
                }
            }
        }

        if let Some((idx, _)) = best {
            return chain.get(idx);
        }

        if allow_all {
            chain.last()
        } else {
            chain.first()
        }
    }

    async fn refresh_snapshot(&self) -> anyhow::Result<()> {
        let mut next = HashMap::new();
        let mut owners_index: HashMap<OwnerKey, OwnerTarget> = HashMap::new();

        let replicasets: Api<ReplicaSet> = Api::all(self.client.clone());
        for rs in replicasets.list(&ListParams::default()).await?.items {
            if let (Some(ns), Some(name), Some(parent)) = (
                rs.metadata.namespace.clone(),
                rs.metadata.name.clone(),
                Self::first_owner_target(&rs),
            ) {
                owners_index.insert(Self::owner_key(&ns, "ReplicaSet", &name), parent);
            }
        }

        let deployments: Api<Deployment> = Api::all(self.client.clone());
        for d in deployments.list(&ListParams::default()).await?.items {
            if let (Some(ns), Some(name), Some(parent)) = (
                d.metadata.namespace.clone(),
                d.metadata.name.clone(),
                Self::first_owner_target(&d),
            ) {
                owners_index.insert(Self::owner_key(&ns, "Deployment", &name), parent);
            }
        }

        let statefulsets: Api<StatefulSet> = Api::all(self.client.clone());
        for s in statefulsets.list(&ListParams::default()).await?.items {
            if let (Some(ns), Some(name), Some(parent)) = (
                s.metadata.namespace.clone(),
                s.metadata.name.clone(),
                Self::first_owner_target(&s),
            ) {
                owners_index.insert(Self::owner_key(&ns, "StatefulSet", &name), parent);
            }
        }

        let daemonsets: Api<DaemonSet> = Api::all(self.client.clone());
        for d in daemonsets.list(&ListParams::default()).await?.items {
            if let (Some(ns), Some(name), Some(parent)) = (
                d.metadata.namespace.clone(),
                d.metadata.name.clone(),
                Self::first_owner_target(&d),
            ) {
                owners_index.insert(Self::owner_key(&ns, "DaemonSet", &name), parent);
            }
        }

        let jobs: Api<Job> = Api::all(self.client.clone());
        for j in jobs.list(&ListParams::default()).await?.items {
            if let (Some(ns), Some(name), Some(parent)) = (
                j.metadata.namespace.clone(),
                j.metadata.name.clone(),
                Self::first_owner_target(&j),
            ) {
                owners_index.insert(Self::owner_key(&ns, "Job", &name), parent);
            }
        }

        let cronjobs: Api<CronJob> = Api::all(self.client.clone());
        for c in cronjobs.list(&ListParams::default()).await?.items {
            if let (Some(ns), Some(name), Some(parent)) = (
                c.metadata.namespace.clone(),
                c.metadata.name.clone(),
                Self::first_owner_target(&c),
            ) {
                owners_index.insert(Self::owner_key(&ns, "CronJob", &name), parent);
            }
        }

        let pods: Api<Pod> = Api::all(self.client.clone());
        for pod in pods.list(&ListParams::default()).await?.items {
            let namespace = pod.metadata.namespace.clone().unwrap_or_default();
            let pod_name = pod.metadata.name.clone().unwrap_or_default();
            let owner_ref = Self::first_owner_target(&pod);
            let (resolved_kind, resolved_name, immediate_owner) =
                self.trace_owner_hierarchy(&namespace, owner_ref, &owners_index);

            let workload = Workload {
                name: if resolved_name.is_empty() {
                    pod_name
                } else {
                    resolved_name
                },
                namespace,
                kind: resolved_kind,
                owner: immediate_owner,
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

        let services: Api<Service> = Api::all(self.client.clone());
        for svc in services.list(&ListParams::default()).await?.items {
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

        let nodes: Api<Node> = Api::all(self.client.clone());
        for node in nodes.list(&ListParams::default()).await?.items {
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

        let mut guard = self.ips.write().await;
        *guard = next;

        Ok(())
    }
}

impl IpResolver for K8sResolver {
    fn resolve_ip(&self, ip: u32) -> Workload {
        if let Ok(guard) = self.ips.try_read() {
            if let Some(workload) = guard.get(&ip) {
                return workload.clone();
            }
        }

        Workload {
            name: Ipv4Addr::from(ip).to_string(),
            namespace: "external".to_string(),
            kind: "external".to_string(),
            owner: String::new(),
        }
    }

    fn debug_snapshot(&self) -> Option<String> {
        let guard = self.ips.try_read().ok()?;
        let mut entries: Vec<DebugResolverEntry> = guard
            .iter()
            .map(|(ip, workload)| DebugResolverEntry {
                ip: Ipv4Addr::from(*ip).to_string(),
                name: workload.name.clone(),
                namespace: workload.namespace.clone(),
                kind: workload.kind.clone(),
                owner: workload.owner.clone(),
            })
            .collect();
        entries.sort_by(|a, b| a.ip.cmp(&b.ip));

        Some(
            serde_json::json!({
                "watch_events": self.watch_events.load(Ordering::Relaxed),
                "count": entries.len(),
                "entries": entries,
            })
            .to_string(),
        )
    }
}

fn parse_ipv4_to_u32(ip: &str) -> Option<u32> {
    ip.parse::<Ipv4Addr>().ok().map(u32::from)
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
    Ipv4Addr::from(ip).is_loopback()
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
    debug_resolver_enabled: bool,
    debug_resolver_endpoint: String,
    resolver: Arc<dyn IpResolver>,
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
                let debug_resolver_endpoint = debug_resolver_endpoint.clone();
                let resolver = Arc::clone(&resolver);
                tokio::spawn(async move {
                    let mut req = [0u8; 1024];
                    let n = match stream.read(&mut req).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };

                    let first_line = String::from_utf8_lossy(&req[..n]);
                    let expected = format!("GET {endpoint} ");
                    let debug_expected = format!("GET {debug_resolver_endpoint} ");
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
                    } else if debug_resolver_enabled && first_line.starts_with(&debug_expected) {
                        if let Some(snapshot) = resolver.debug_snapshot() {
                            (
                                "200 OK",
                                snapshot.into_bytes(),
                                String::from("application/json"),
                            )
                        } else {
                            (
                                "503 Service Unavailable",
                                b"resolver snapshot unavailable".to_vec(),
                                String::from("text/plain"),
                            )
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

    let kprobe_recv: &mut KProbe = ebpf
        .program_mut("handle_tcp_cleanup_rbuf")
        .context("kprobe program handle_tcp_cleanup_rbuf not found")?
        .try_into()?;
    kprobe_recv.load()?;
    kprobe_recv.attach("tcp_cleanup_rbuf", 0)?;

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
    let debug_resolver_endpoint = if opt.debug_resolver_endpoint.starts_with('/') {
        opt.debug_resolver_endpoint.clone()
    } else {
        format!("/{}", opt.debug_resolver_endpoint)
    };

    let owner_kind_allowlist = opt.owner_kind_allowlist();
    let owner_kind_priority = opt.owner_kind_priority();

    let resolver: Arc<dyn IpResolver> = match K8sResolver::try_new(
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
            Arc::new(StaticResolver)
        }
    };
    if opt.debug_resolver_enabled {
        info!("debug resolver endpoint enabled at {}", debug_resolver_endpoint);
    }
    let metrics_task = tokio::spawn(run_metrics_server(
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

                    *current_links.entry(link).or_insert(0) +=
                        throughput.bytes_sent.saturating_add(throughput.bytes_received);
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
                        *past_links.entry(link).or_insert(0) +=
                            throughput.bytes_sent.saturating_add(throughput.bytes_received);
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
