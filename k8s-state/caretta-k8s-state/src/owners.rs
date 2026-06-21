//! owners 索引:周期 list 工作负载资源,维护 (kind,ns,name) → owner 映射,
//! 供 Event 的 involvedObject 上卷到稳定 workload。
//!
//! 链路遍历/挑选复用 [`caretta_k8s_core::owner`],周期刷新复用
//! [`caretta_k8s_core::supervisor::supervise`]。

use arc_swap::ArcSwap;
use caretta_k8s_core::owner::{
    OwnerKey, OwnerResolveConfig, OwnerTarget, first_owner_target, owner_key, trace_owner_hierarchy,
};
use caretta_k8s_core::supervisor::supervise;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::batch::v1::{CronJob, Job};
use k8s_openapi::api::core::v1::Pod;
use kube::api::ListParams;
use kube::{Api, Client};
use log::{info, warn};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

/// 一份 owner 拓扑快照,整体替换(ArcSwap),读侧拿到自洽的一份。
#[derive(Default)]
pub struct OwnerSnapshot {
    /// 控制器层 (ns,kind,name) → 父 owner。覆盖 RS/Deploy/STS/DS/Job/CronJob。
    owners_index: HashMap<OwnerKey, OwnerTarget>,
    /// (namespace, pod_name) → Pod 直接 owner,作为上卷链路起点。
    pods_owner: HashMap<(String, String), OwnerTarget>,
}

/// 持有 client + owner 策略 + 当前快照。
pub struct OwnerIndex {
    client: Client,
    snapshot: ArcSwap<OwnerSnapshot>,
    traverse_up_hierarchy: bool,
    allowlist: HashSet<String>,
    priority: HashMap<String, usize>,
}

impl OwnerIndex {
    pub fn new(
        client: Client,
        traverse_up_hierarchy: bool,
        allowlist: HashSet<String>,
        priority: HashMap<String, usize>,
    ) -> Arc<Self> {
        Arc::new(Self {
            client,
            snapshot: ArcSwap::from_pointee(OwnerSnapshot::default()),
            traverse_up_hierarchy,
            allowlist,
            priority,
        })
    }

    /// 全量 list 7 类资源重建快照并整体替换。任一 list 失败则整体 Err、保留旧快照。
    pub async fn refresh_once(&self) -> anyhow::Result<()> {
        let lp = ListParams::default();
        let pods: Api<Pod> = Api::all(self.client.clone());
        let replicasets: Api<ReplicaSet> = Api::all(self.client.clone());
        let deployments: Api<Deployment> = Api::all(self.client.clone());
        let statefulsets: Api<StatefulSet> = Api::all(self.client.clone());
        let daemonsets: Api<DaemonSet> = Api::all(self.client.clone());
        let jobs: Api<Job> = Api::all(self.client.clone());
        let cronjobs: Api<CronJob> = Api::all(self.client.clone());

        let (pod_res, rs_res, dep_res, ss_res, ds_res, job_res, cj_res) = tokio::join!(
            pods.list(&lp),
            replicasets.list(&lp),
            deployments.list(&lp),
            statefulsets.list(&lp),
            daemonsets.list(&lp),
            jobs.list(&lp),
            cronjobs.list(&lp),
        );
        let pod_list = pod_res?;
        let rs_list = rs_res?;
        let dep_list = dep_res?;
        let ss_list = ss_res?;
        let ds_list = ds_res?;
        let job_list = job_res?;
        let cj_list = cj_res?;

        let mut owners_index: HashMap<OwnerKey, OwnerTarget> = HashMap::new();
        let mut pods_owner: HashMap<(String, String), OwnerTarget> = HashMap::new();

        // 控制器层:每类资源把自身 (ns,kind,name) → 其父 owner 灌进 owners_index。
        index_workload(&mut owners_index, "ReplicaSet", rs_list.items);
        index_workload(&mut owners_index, "Deployment", dep_list.items);
        index_workload(&mut owners_index, "StatefulSet", ss_list.items);
        index_workload(&mut owners_index, "DaemonSet", ds_list.items);
        index_workload(&mut owners_index, "Job", job_list.items);
        index_workload(&mut owners_index, "CronJob", cj_list.items);

        // Pod 层:记 (ns,name) → 直接 owner,作为上卷链路起点。
        for pod in pod_list.items {
            if let (Some(ns), Some(name), Some(parent)) = (
                pod.metadata.namespace.clone(),
                pod.metadata.name.clone(),
                first_owner_target(&pod),
            ) {
                pods_owner.insert((ns, name), parent);
            }
        }

        let n_owners = owners_index.len();
        let n_pods = pods_owner.len();
        self.snapshot.store(Arc::new(OwnerSnapshot {
            owners_index,
            pods_owner,
        }));
        info!("owners index refreshed: {n_owners} controllers, {n_pods} pods");
        Ok(())
    }

    /// 起后台周期刷新 task,被 supervise 包裹(panic 自动重启)。
    pub fn spawn_refresh(self: Arc<Self>, interval: Duration) {
        tokio::spawn(supervise("owners-refresh", move || {
            let this = Arc::clone(&self);
            async move {
                let mut ticker = tokio::time::interval(interval);
                loop {
                    ticker.tick().await;
                    if let Err(e) = this.refresh_once().await {
                        warn!("owners index refresh failed: {e}");
                    }
                }
            }
        }));
    }

    /// 把 involvedObject 上卷成 (workload_kind, workload_name)。
    ///   - Pod → 用其直接 owner 起链;其他 → 从对象自身起链。
    ///   - 索引未命中(刚建/已删/裸 Pod)→ 回退 involvedObject 自身,不丢事件。
    pub fn resolve(
        &self,
        involved_kind: &str,
        involved_namespace: &str,
        involved_name: &str,
    ) -> (String, String) {
        let snapshot = self.snapshot.load();
        let cfg = OwnerResolveConfig {
            traverse_up_hierarchy: self.traverse_up_hierarchy,
            allowlist: &self.allowlist,
            priority: &self.priority,
        };
        resolve_in_snapshot(&snapshot, &cfg, involved_kind, involved_namespace, involved_name)
    }
}

/// 在给定快照+策略下做上卷。抽成自由函数:被 [`OwnerIndex::resolve`] 复用,
/// 也让单测脱离 `kube::Client`(resolve 不触碰 client)。
fn resolve_in_snapshot(
    snapshot: &OwnerSnapshot,
    cfg: &OwnerResolveConfig,
    involved_kind: &str,
    involved_namespace: &str,
    involved_name: &str,
) -> (String, String) {
    let initial = if involved_kind == "Pod" {
        snapshot
            .pods_owner
            .get(&(involved_namespace.to_string(), involved_name.to_string()))
            .cloned()
    } else if !involved_kind.is_empty() && !involved_name.is_empty() {
        Some(OwnerTarget {
            kind: involved_kind.to_string(),
            name: involved_name.to_string(),
        })
    } else {
        None
    };

    let (kind, name, _owner) =
        trace_owner_hierarchy(cfg, involved_namespace, initial, &snapshot.owners_index);

    // 解析不出有效名字(裸 Pod、空 involvedObject)→ 回退到 involvedObject 自身。
    if name.is_empty() {
        (involved_kind.to_string(), involved_name.to_string())
    } else {
        (kind, name)
    }
}

/// 把一批工作负载对象按 `kind` 灌进 owners_index:(ns,kind,name) → 其第一个 owner。
fn index_workload<T>(index: &mut HashMap<OwnerKey, OwnerTarget>, kind: &str, items: Vec<T>)
where
    T: kube::Resource,
{
    for item in items {
        if let (Some(ns), Some(name), Some(parent)) = (
            item.meta().namespace.clone(),
            item.meta().name.clone(),
            first_owner_target(&item),
        ) {
            index.insert(owner_key(&ns, kind, &name), parent);
        }
    }
}

#[cfg(test)]
mod tests {
    //! 验证 OwnerIndex 这层的接线(链路遍历正确性由 caretta-k8s-core::owner 单测保证):
    //! Pod 上卷到 Deployment;Node 原样透传;未知 Pod 回退 involvedObject。

    use super::*;

    fn mk_index() -> OwnerSnapshot {
        let mut owners_index = HashMap::new();
        owners_index.insert(
            owner_key("ns", "ReplicaSet", "rs-1"),
            OwnerTarget {
                kind: "Deployment".to_string(),
                name: "dep-1".to_string(),
            },
        );
        let mut pods_owner = HashMap::new();
        pods_owner.insert(
            ("ns".to_string(), "pod-1".to_string()),
            OwnerTarget {
                kind: "ReplicaSet".to_string(),
                name: "rs-1".to_string(),
            },
        );
        OwnerSnapshot {
            owners_index,
            pods_owner,
        }
    }

    fn resolve(snapshot: &OwnerSnapshot, kind: &str, ns: &str, name: &str) -> (String, String) {
        let allowlist = HashSet::new();
        let priority = HashMap::new();
        let cfg = OwnerResolveConfig {
            traverse_up_hierarchy: true,
            allowlist: &allowlist,
            priority: &priority,
        };
        resolve_in_snapshot(snapshot, &cfg, kind, ns, name)
    }

    #[test]
    fn pod_rolls_up_to_deployment() {
        let (kind, name) = resolve(&mk_index(), "Pod", "ns", "pod-1");
        assert_eq!(kind, "Deployment");
        assert_eq!(name, "dep-1");
    }

    #[test]
    fn node_passes_through() {
        let (kind, name) = resolve(&mk_index(), "Node", "", "node-a");
        assert_eq!(kind, "Node");
        assert_eq!(name, "node-a");
    }

    #[test]
    fn unknown_pod_falls_back_to_involved() {
        // 索引里没有 pod-x → pods_owner 命中失败 → initial=None → trace 返回空名
        // → 回退 involvedObject 自身。
        let (kind, name) = resolve(&mk_index(), "Pod", "ns", "pod-x");
        assert_eq!(kind, "Pod");
        assert_eq!(name, "pod-x");
    }
}
