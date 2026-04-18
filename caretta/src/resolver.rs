//! Kubernetes and static IP resolvers used to map connection IPs into workload identities.

use anyhow::Context as _;
use dns_lookup::lookup_addr;
use futures_util::StreamExt;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::batch::v1::{CronJob, Job};
use k8s_openapi::api::core::v1::{Node, Pod, Service};
use kube::api::{ListParams, WatchEvent, WatchParams};
use kube::{Api, Client};
use log::warn;
use lru::LruCache;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};

use crate::types::Workload;

pub trait IpResolver: Send + Sync {
    fn resolve_ip(&self, ip: u32) -> Workload;
    fn debug_snapshot(&self) -> Option<String> {
        None
    }
}

pub struct DnsCache {
    enabled: bool,
    cache: Mutex<LruCache<u32, String>>,
}

impl DnsCache {
    pub fn new(enabled: bool, cache_size: usize) -> Self {
        let cache_size = NonZeroUsize::new(cache_size.max(1)).expect("non-zero dns cache size");
        Self {
            enabled,
            cache: Mutex::new(LruCache::new(cache_size)),
        }
    }

    /// Resolve IPv4 to hostname with LRU caching, returning the IP string on miss/failure.
    pub fn resolve_name(&self, ip: u32) -> String {
        let fallback = Ipv4Addr::from(ip).to_string();
        if !self.enabled {
            return fallback;
        }

        if let Ok(mut cache) = self.cache.lock() {
            if let Some(host) = cache.get(&ip) {
                return host.clone();
            }
        }

        let host = lookup_addr(&IpAddr::V4(Ipv4Addr::from(ip))).unwrap_or_else(|_| fallback.clone());

        if let Ok(mut cache) = self.cache.lock() {
            cache.put(ip, host.clone());
        }

        host
    }
}

pub struct StaticResolver {
    dns_cache: DnsCache,
}

impl StaticResolver {
    pub fn new(resolve_dns: bool, dns_cache_size: usize) -> Self {
        Self {
            dns_cache: DnsCache::new(resolve_dns, dns_cache_size),
        }
    }
}

impl IpResolver for StaticResolver {
    fn resolve_ip(&self, ip: u32) -> Workload {
        Workload {
            name: self.dns_cache.resolve_name(ip),
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

pub struct K8sResolver {
    client: Client,
    ips: RwLock<HashMap<u32, Workload>>,
    dns_cache: DnsCache,
    traverse_up_hierarchy: bool,
    owner_kind_allowlist: HashSet<String>,
    owner_kind_priority: HashMap<String, usize>,
    watch_events: AtomicU64,
}

impl K8sResolver {
    /// Build resolver, perform initial snapshot, then start background watch/refresh tasks.
    pub async fn try_new(
        resolve_dns: bool,
        dns_cache_size: usize,
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
            dns_cache: DnsCache::new(resolve_dns, dns_cache_size),
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
        // Coalesce bursty watch events into a small bounded queue.
        // If a refresh signal is already pending, dropping extra signals is acceptable because
        // refresh_snapshot is a full rebuild of current cluster state.
        let (tx, mut rx) = mpsc::channel::<()>(1);

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

    fn spawn_watch<K>(resolver: Arc<Self>, tx: mpsc::Sender<()>, watch_name: &'static str)
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
                            let _ = tx.try_send(());
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

    /// Trace owner chain and pick final workload using traversal + allowlist/priority strategy.
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

    /// Rebuild in-memory IP mapping from current Kubernetes snapshot.
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
            name: self.dns_cache.resolve_name(ip),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_cache_returns_ip_string_when_disabled() {
        let cache = DnsCache::new(false, 8);
        let ip = u32::from(Ipv4Addr::new(8, 8, 8, 8));

        let name = cache.resolve_name(ip);
        assert_eq!(name, "8.8.8.8");
    }

    #[test]
    fn static_resolver_falls_back_to_external_with_ip_name_when_dns_disabled() {
        let resolver = StaticResolver::new(false, 8);
        let ip = u32::from(Ipv4Addr::new(1, 2, 3, 4));

        let workload = resolver.resolve_ip(ip);
        assert_eq!(workload.name, "1.2.3.4");
        assert_eq!(workload.namespace, "external");
        assert_eq!(workload.kind, "external");
    }

    #[test]
    fn dns_cache_size_zero_is_normalized() {
        let cache = DnsCache::new(false, 0);
        let ip = u32::from(Ipv4Addr::new(127, 0, 0, 1));

        // The constructor should normalize invalid zero sizes instead of panicking.
        assert_eq!(cache.resolve_name(ip), "127.0.0.1");
    }
}
