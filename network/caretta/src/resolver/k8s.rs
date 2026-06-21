//! Kubernetes 解析器:维护 IP→Workload 的内存快照,通过 watch 增量刷新 + 30s 周期
//! 兜底刷新。读路径用 ArcSwap 做无锁快照切换,写路径在后台 task 中重建整张快照后
//! 一次性原子替换。

use anyhow::Context as _;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use caretta_k8s_core::owner::{
    first_owner_target, owner_key, trace_owner_hierarchy, OwnerKey, OwnerResolveConfig, OwnerTarget,
};
use caretta_k8s_core::supervisor::supervise;
use caretta_k8s_core::watch::{spawn_watch, ChangeKind, WatchObserver};
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::batch::v1::{CronJob, Job};
use k8s_openapi::api::core::v1::{Node, Pod, Service};
use kube::api::ListParams;
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

#[derive(Serialize)]
struct DebugResolverEntry {
    ip: String,
    name: String,
    namespace: String,
    kind: String,
    owner: String,
}

/// 把 存活心跳指标 + 触发 refresh 注入到 caretta-k8s-core
/// 的 watch loop。
///
/// `Arc<K8sResolver>` 形成 resolver→observer→resolver 的 Arc 环,但 observer 仅存活在
/// spawned watch task 内、与 resolver 进程级同生命周期,不构成实际泄漏。
struct ResolverWatchObserver {
    resolver: Arc<K8sResolver>,
    tx: mpsc::Sender<()>,
}

impl<K> WatchObserver<K> for ResolverWatchObserver {
    fn on_change(&self, _kind: ChangeKind, _obj: &K) {
        // 把 watch 事件合并成一个刷新信号:refresh_snapshot 是全量重建,队列满
        // (已有待处理信号)时丢弃多余信号是可接受的。
        let _ = self.tx.try_send(());
    }

    fn on_active(&self, watch_name: &'static str) {
        // 任意流量(含 Bookmark)都刷新存活心跳与计数,证明这条 watch 还活着。
        metrics::mark_k8s_watch_alive(watch_name);
        self.resolver.watch_events.fetch_add(1, Ordering::Relaxed);
    }
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
        let (tx, rx) = mpsc::channel::<()>(1);

        // refresh consumer 持有 mpsc::Receiver——它没法 clone,所以放进 Arc<Mutex<_>>。
        // panic 时 MutexGuard 跟着 future 一起 drop,锁释放,supervise 下一轮重新 lock,
        // 接着消费同一个 rx 队列;不需要重建 channel(否则 9 个 watch 持有的 tx 就指空了)。
        let rx = Arc::new(Mutex::new(rx));
        let refresh_resolver = Arc::clone(self);
        let rx_for_supervise = Arc::clone(&rx);
        tokio::spawn(supervise("k8s:refresh-on-event", move || {
            let resolver = Arc::clone(&refresh_resolver);
            let rx = Arc::clone(&rx_for_supervise);
            async move {
                let mut rx = rx.lock().await;
                while rx.recv().await.is_some() {
                    if let Err(err) = resolver.refresh_snapshot().await {
                        warn!("failed to refresh Kubernetes snapshot from watch event: {err}");
                    }
                }
            }
        }));

        let periodic_resolver = Arc::clone(self);
        tokio::spawn(supervise("k8s:refresh-periodic", move || {
            let resolver = Arc::clone(&periodic_resolver);
            async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(30));
                loop {
                    ticker.tick().await;
                    if let Err(err) = resolver.refresh_snapshot().await {
                        warn!("failed to refresh Kubernetes snapshot on periodic tick: {err}");
                    }
                }
            }
        }));

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

    /// 起一条对 `K` 的 watch:复用 caretta-k8s-core 的通用 watch loop,把 caretta 特有的
    /// 副作用(存活心跳 + 刷新信号)经 [`ResolverWatchObserver`] 注入。
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
        let client = resolver.client.clone();
        let observer = Arc::new(ResolverWatchObserver { resolver, tx });
        spawn_watch::<K, _>(client, watch_name, observer);
    }

    async fn refresh_snapshot(&self) -> anyhow::Result<()> {
        // Watch 触发和 30s 兜底是两个后台 task。refresh 是全量重建,必须串行化；
        // 否则更早开始但更晚完成的旧快照会覆盖较新的 watch 刷新结果。
        let _refresh_guard = self.refresh_lock.lock().await;

        let replicasets: Api<ReplicaSet> = Api::all(self.client.clone());
        let deployments: Api<Deployment> = Api::all(self.client.clone());
        let statefulsets: Api<StatefulSet> = Api::all(self.client.clone());
        let daemonsets: Api<DaemonSet> = Api::all(self.client.clone());
        let jobs: Api<Job> = Api::all(self.client.clone());
        let cronjobs: Api<CronJob> = Api::all(self.client.clone());
        let pods: Api<Pod> = Api::all(self.client.clone());
        let services: Api<Service> = Api::all(self.client.clone());
        let nodes: Api<Node> = Api::all(self.client.clone());

        // 9 个 list 一次性并发发出去——总时延 = max(单条 list),不再 sum;
        // refresh_lock 的持锁时间也同步缩短。处理阶段(下面那段串行 for 循环)
        // 是纯内存操作,成本可忽略,所以即便 Pod / Service 阶段在依赖上必须等
        // owners_index / pods_by_ns 建好,这里先把数据全部抽回来再处理也不亏。
        let lp = ListParams::default();
        let (rs_res, dep_res, ss_res, ds_res, job_res, cj_res, pod_res, svc_res, node_res) = tokio::join!(
            replicasets.list(&lp),
            deployments.list(&lp),
            statefulsets.list(&lp),
            daemonsets.list(&lp),
            jobs.list(&lp),
            cronjobs.list(&lp),
            pods.list(&lp),
            services.list(&lp),
            nodes.list(&lp),
        );
        // 任一 list 失败整体返回 Err,旧快照保持不动——这与改造前每条 `?` 的语义一致。
        let rs_list = rs_res?;
        let dep_list = dep_res?;
        let ss_list = ss_res?;
        let ds_list = ds_res?;
        let job_list = job_res?;
        let cj_list = cj_res?;
        let pod_list = pod_res?;
        let svc_list = svc_res?;
        let node_list = node_res?;

        let mut next = HashMap::new();
        let mut owners_index: HashMap<OwnerKey, OwnerTarget> = HashMap::new();

        // owner 上卷策略:从 self 的运行配置现场组装,按引用传给 core 的纯函数。
        let owner_cfg = OwnerResolveConfig {
            traverse_up_hierarchy: self.traverse_up_hierarchy,
            allowlist: &self.owner_kind_allowlist,
            priority: &self.owner_kind_priority,
        };

        for rs in rs_list.items {
            if let (Some(ns), Some(name), Some(parent)) = (
                rs.metadata.namespace.clone(),
                rs.metadata.name.clone(),
                first_owner_target(&rs),
            ) {
                owners_index.insert(owner_key(&ns, "ReplicaSet", &name), parent);
            }
        }

        for d in dep_list.items {
            if let (Some(ns), Some(name), Some(parent)) = (
                d.metadata.namespace.clone(),
                d.metadata.name.clone(),
                first_owner_target(&d),
            ) {
                owners_index.insert(owner_key(&ns, "Deployment", &name), parent);
            }
        }

        for s in ss_list.items {
            if let (Some(ns), Some(name), Some(parent)) = (
                s.metadata.namespace.clone(),
                s.metadata.name.clone(),
                first_owner_target(&s),
            ) {
                owners_index.insert(owner_key(&ns, "StatefulSet", &name), parent);
            }
        }

        for d in ds_list.items {
            if let (Some(ns), Some(name), Some(parent)) = (
                d.metadata.namespace.clone(),
                d.metadata.name.clone(),
                first_owner_target(&d),
            ) {
                owners_index.insert(owner_key(&ns, "DaemonSet", &name), parent);
            }
        }

        for j in job_list.items {
            if let (Some(ns), Some(name), Some(parent)) = (
                j.metadata.namespace.clone(),
                j.metadata.name.clone(),
                first_owner_target(&j),
            ) {
                owners_index.insert(owner_key(&ns, "Job", &name), parent);
            }
        }

        for c in cj_list.items {
            if let (Some(ns), Some(name), Some(parent)) = (
                c.metadata.namespace.clone(),
                c.metadata.name.clone(),
                first_owner_target(&c),
            ) {
                owners_index.insert(owner_key(&ns, "CronJob", &name), parent);
            }
        }

        // pods_by_ns 留住每个 Pod 已经过完 owner 上卷的 Workload + 其 labels,
        // 让接下来的 Service 循环按 namespace 反查 selector 命中的 Pod, 直接复用
        // 同一份 Workload, 避免 ClusterIP 与 Pod IP 在 prometheus 上产生
        // {kind=Service} / {kind=Deployment} 双 series。
        let mut pods_by_ns: HashMap<String, Vec<PodSummary>> = HashMap::new();
        for pod in pod_list.items {
            let namespace = pod.metadata.namespace.clone().unwrap_or_default();
            let pod_name = pod.metadata.name.clone().unwrap_or_default();
            let labels = pod.metadata.labels.clone().unwrap_or_default();
            let owner_ref = first_owner_target(&pod);
            let (resolved_kind, resolved_name, immediate_owner) =
                trace_owner_hierarchy(&owner_cfg, &namespace, owner_ref, &owners_index);

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

        for svc in svc_list.items {
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
