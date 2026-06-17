//! Kubernetes 解析器:维护 IP→Workload 的内存快照,通过 watch 增量刷新 + 30s 周期
//! 兜底刷新。读路径用 ArcSwap 做无锁快照切换,写路径在后台 task 中重建整张快照后
//! 一次性原子替换。

use anyhow::Context as _;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use futures_util::StreamExt;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::batch::v1::{CronJob, Job};
use k8s_openapi::api::core::v1::{Node, Pod, Service};
use kube::api::{ListParams, WatchEvent, WatchParams};
use kube::{Api, Client};
use log::warn;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};

use super::IpResolver;
use super::dns::DnsCache;
use crate::metrics;
use crate::types::Workload;

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
    // IP→Workload 映射使用 ArcSwap 而非 RwLock，因为本场景具备三个适合 ArcSwap 的特征：
    //
    //   1) 读多写少：resolve_ip 在每次 poll tick 里被每条连接调用（每秒可达上千次），而
    //      refresh_snapshot 仅在 watch 事件触发或 30s 定时刷新时执行。
    //   2) 写是整体替换：refresh_snapshot 始终在本地构建一张全新的 HashMap，最后整体替换，
    //      没有局部增量修改的需求——这正是 ArcSwap 的 store(Arc::new(...)) 模型。
    //   3) 读路径在 sync 上下文：trait IpResolver::resolve_ip 是同步方法，无法 .await。
    //      若使用 tokio::sync::RwLock，sync 路径只能在 try_read（拿不到立刻 Err）和
    //      blocking_read（卡住 tokio worker 线程）之间二选一，二者皆不理想。
    //
    // 读写时序示意（V1 是旧快照，V2 是新快照）：
    //
    //   T0  reader A 调 ips.load() -> 拿到 Arc<HashMap V1>，开始 lookup
    //   T1  writer  调 ips.store(Arc::new(V2))，原子替换槽位指针
    //                |- reader A 仍持有 V1 的 Arc，V1 不会被回收
    //   T2  reader B 调 ips.load() -> 拿到 Arc<HashMap V2>
    //   T3  reader A 用完 drop V1 的 Arc -> 引用计数归零 -> V1 被释放
    //
    // 关键性质：
    //   - load() 永不阻塞、永不返回 Err，从根上消除"读拿不到锁→误归类为 external"
    //     这条 failure path（这是替换 RwLock 的核心动机）。
    //   - 写者切换指针的瞬间不会打断 reader：每个 reader 在自己的 load() 调用周期内
    //     看到的是某个一致的版本，不存在读到半截 HashMap 的可能。
    //   - 写瞬间内存中可能同时存在 V1 和 V2，待最后一个 V1 reader 释放后 V1 才被回收；
    //     因 IP→Workload 表规模有限（数千~数万条），这点额外内存可以接受。
    //   - reader 看到的是"某个略早的一致快照"。resolver 数据本身就是异步刷新，读到的
    //     workload 信息天然容许毫秒级滞后，无需读取最新版本。
    ips: ArcSwap<HashMap<u32, Workload>>,
    dns_cache: DnsCache,
    traverse_up_hierarchy: bool,
    owner_kind_allowlist: HashSet<String>,
    owner_kind_priority: HashMap<String, usize>,
    refresh_lock: Mutex<()>,
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
            ips: ArcSwap::from_pointee(HashMap::new()),
            dns_cache: DnsCache::new(resolve_dns, dns_cache_size),
            traverse_up_hierarchy,
            owner_kind_allowlist,
            owner_kind_priority,
            refresh_lock: Mutex::new(()),
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
                        Ok(WatchEvent::Added(_)) => {
                            metrics::mark_k8s_event(watch_name, "added");
                            resolver.watch_events.fetch_add(1, Ordering::Relaxed);
                            let _ = tx.try_send(());
                        }
                        Ok(WatchEvent::Modified(_)) => {
                            metrics::mark_k8s_event(watch_name, "modified");
                            resolver.watch_events.fetch_add(1, Ordering::Relaxed);
                            let _ = tx.try_send(());
                        }
                        Ok(WatchEvent::Deleted(_)) => {
                            metrics::mark_k8s_event(watch_name, "deleted");
                            resolver.watch_events.fetch_add(1, Ordering::Relaxed);
                            let _ = tx.try_send(());
                        }
                        Ok(WatchEvent::Bookmark(_)) => {
                            metrics::mark_k8s_event(watch_name, "bookmark");
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
        // Watch 触发和 30s 兜底是两个后台 task。refresh 是全量重建,必须串行化；
        // 否则更早开始但更晚完成的旧快照会覆盖较新的 watch 刷新结果。
        let _refresh_guard = self.refresh_lock.lock().await;

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
        // pods_by_ns 留住每个 Pod 已经过完 owner 上卷的 Workload + 其 labels,
        // 让接下来的 Service 循环按 namespace 反查 selector 命中的 Pod, 直接复用
        // 同一份 Workload, 避免 ClusterIP 与 Pod IP 在 prometheus 上产生
        // {kind=Service} / {kind=Deployment} 双 series。
        let mut pods_by_ns: HashMap<String, Vec<PodSummary>> = HashMap::new();
        for pod in pods.list(&ListParams::default()).await?.items {
            let namespace = pod.metadata.namespace.clone().unwrap_or_default();
            let pod_name = pod.metadata.name.clone().unwrap_or_default();
            let labels = pod.metadata.labels.clone().unwrap_or_default();
            let owner_ref = Self::first_owner_target(&pod);
            let (resolved_kind, resolved_name, immediate_owner) =
                self.trace_owner_hierarchy(&namespace, owner_ref, &owners_index);

            let workload = Workload {
                name: if resolved_name.is_empty() {
                    pod_name
                } else {
                    resolved_name
                },
                namespace: namespace.clone(),
                kind: resolved_kind,
                owner: immediate_owner,
            };

            pods_by_ns.entry(namespace).or_default().push(PodSummary {
                labels,
                workload: workload.clone(),
            });

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
            let svc_name = svc.metadata.name.clone().unwrap_or_default();

            let Some(spec) = svc.spec else { continue };

            // ClusterIP 上卷: 有 selector + 在本 namespace 下能找到匹配的 Pod →
            // 直接复用 Pod 已经过完 owner 上卷的 Workload (两端视角同 key,
            // prometheus 单 series); 否则 (ExternalName / 无 selector / selector
            // 暂时选不到 Pod) 退回 caretta-go 行为的 kind=Service workload。
            let workload = match spec.selector.as_ref() {
                Some(selector) if !selector.is_empty() => pods_by_ns
                    .get(&namespace)
                    .and_then(|pods| pods.iter().find(|p| selector_matches(selector, &p.labels)))
                    .map(|p| p.workload.clone())
                    .unwrap_or_else(|| service_fallback_workload(&svc_name, &namespace)),
                _ => service_fallback_workload(&svc_name, &namespace),
            };

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

        // 整体替换 IP→Workload 快照：原子地把槽位指向新 Arc。在此瞬间正在执行
        // resolve_ip 的 reader 会继续看到旧快照，待其 load() 出来的 Arc drop 时旧
        // HashMap 才会被回收，写者无需等待任何 reader。
        self.ips.store(Arc::new(next));

        Ok(())
    }
}

#[async_trait]
impl IpResolver for K8sResolver {
    async fn resolve_ip(&self, ip: u32) -> Workload {
        // load() 是无锁原子读，永不阻塞、永不失败：拿到的是当前发布的快照 Arc。
        // 这是用 ArcSwap 替换 RwLock 的核心收益——sync trait 方法不再有"拿不到锁
        // 就走 fallback"的歧义路径，None 分支只可能因 map 中真的没有该 IP 才进入。
        let snapshot = self.ips.load();
        if let Some(workload) = snapshot.get(&ip) {
            return workload.clone();
        }

        // 命中 fallback 时才走 DNS 反查；resolve_name 内部已经是 async + 带超时上限。
        Workload {
            name: self.dns_cache.resolve_name(ip).await,
            namespace: "external".to_string(),
            kind: "external".to_string(),
            owner: String::new(),
        }
    }

    async fn debug_snapshot(&self) -> Option<String> {
        let snapshot = self.ips.load();
        let mut entries: Vec<DebugResolverEntry> = snapshot
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

/// Snapshot of a Pod 内 refresh_snapshot 周期里需要的两个事实:它的 labels (用来
/// 给 Service.spec.selector 反查命中) 与它已经 owner 上卷过的 Workload。
struct PodSummary {
    labels: BTreeMap<String, String>,
    workload: Workload,
}

/// k8s Service selector 是 equality-based (AND 语义): selector 中每一对 (k, v)
/// 都必须在 pod labels 中存在且值相等。Pod 多出来的 label 不破坏匹配。
/// 调用方已过滤掉 empty selector,这里不再特判。
fn selector_matches(
    selector: &BTreeMap<String, String>,
    labels: &BTreeMap<String, String>,
) -> bool {
    selector.iter().all(|(k, v)| labels.get(k) == Some(v))
}

/// 当 Service 没有 selector 或 selector 选不到任何 Pod 时,保留 caretta-go 行为:
/// 把 ClusterIP 标成 kind=Service。覆盖 ExternalName / 手动 Endpoints / Pod 还没
/// ready 等 corner case,**不引入新 bug**——退化路径与现有 caretta-go 完全一致。
fn service_fallback_workload(name: &str, namespace: &str) -> Workload {
    Workload {
        name: name.to_string(),
        namespace: namespace.to_string(),
        kind: "Service".to_string(),
        owner: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // selector AND-semantics: 所有 (k, v) 都需要在 pod labels 中存在且值相等。
    #[test]
    fn selector_should_match_when_all_keys_present_with_equal_values() {
        let mut selector = BTreeMap::new();
        selector.insert("app".to_string(), "user".to_string());
        selector.insert("tier".to_string(), "backend".to_string());

        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "user".to_string());
        labels.insert("tier".to_string(), "backend".to_string());

        assert!(selector_matches(&selector, &labels));
    }

    // 任何一个 key 的 value 不一致就不算匹配。
    #[test]
    fn selector_should_not_match_when_value_differs() {
        let mut selector = BTreeMap::new();
        selector.insert("app".to_string(), "user".to_string());

        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "biz".to_string());

        assert!(!selector_matches(&selector, &labels));
    }

    // selector 要求的 key 在 pod 上不存在,直接 fail。
    #[test]
    fn selector_should_not_match_when_pod_missing_required_key() {
        let mut selector = BTreeMap::new();
        selector.insert("app".to_string(), "user".to_string());

        let labels = BTreeMap::new();
        assert!(!selector_matches(&selector, &labels));
    }

    // selector 是 AND 语义,Pod 多出来的 label 不应破坏匹配——这是真实集群里
    // 最常见的情形(K8s 自动注入 pod-template-hash 等)。
    #[test]
    fn selector_should_match_when_pod_has_extra_labels() {
        let mut selector = BTreeMap::new();
        selector.insert("app".to_string(), "user".to_string());

        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "user".to_string());
        labels.insert("pod-template-hash".to_string(), "abc123".to_string());
        labels.insert("version".to_string(), "v2".to_string());

        assert!(selector_matches(&selector, &labels));
    }

    // 退化路径:无 selector / selector 选不到 Pod 时,fallback 仍然要产出
    // kind=Service 的 workload, 保留 caretta-go 行为, ExternalName / 手动
    // Endpoints / Pod 还没 ready 都走这条。
    #[test]
    fn fallback_workload_should_have_service_kind_for_external_name_pattern() {
        let workload = service_fallback_workload("external-svc", "ns-a");
        assert_eq!(workload.name, "external-svc");
        assert_eq!(workload.namespace, "ns-a");
        assert_eq!(workload.kind, "Service");
        assert_eq!(workload.owner, "");
    }
}
