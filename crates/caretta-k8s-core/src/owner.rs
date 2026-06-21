//! Owner 上卷:从一个 Pod 的 owner reference 沿 owners_index 往上爬到最终归并目标
//! (Pod → ReplicaSet → Deployment 等),按 allowlist + priority 策略挑选。
//!
//! 这里是纯函数 + 纯数据:不依赖 caretta 的 `Workload`、不依赖 async runtime,只用
//! `std` 集合 + `kube::Resource`(仅 [`first_owner_target`] 一个桥接函数触碰)。配置
//! ([`OwnerResolveConfig`])由调用方传入而非读 `&self`,因此可被任意 K8s collector 复用。

use std::collections::{HashMap, HashSet};

/// owners_index 的 key:(namespace, kind, name) 三元组。namespace 由子资源继承
/// 传入,所以 [`OwnerTarget`] 本身不带 namespace。
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct OwnerKey {
    pub namespace: String,
    pub kind: String,
    pub name: String,
}

/// 一个父 owner 的指向。
#[derive(Clone)]
pub struct OwnerTarget {
    pub kind: String,
    pub name: String,
}

/// owner 上卷策略配置。由调用方从自己的运行配置组装后按引用传入。
pub struct OwnerResolveConfig<'a> {
    /// 是否沿 owner 链继续上卷到更稳定的工作负载;false 时只返回 immediate owner。
    pub traverse_up_hierarchy: bool,
    /// 允许作为最终归并目标的 Kind 集合;空集合表示不限制(全放行)。
    pub allowlist: &'a HashSet<String>,
    /// Kind → 优先级 rank(越小越优先);未列出的 Kind 视作 `usize::MAX`。
    pub priority: &'a HashMap<String, usize>,
}

/// 从任意 K8s 对象取第一个 owner reference,折叠成 [`OwnerTarget`]。
pub fn first_owner_target<T>(obj: &T) -> Option<OwnerTarget>
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

/// 拼一个 owners_index 的 key。
pub fn owner_key(namespace: &str, kind: &str, name: &str) -> OwnerKey {
    OwnerKey {
        namespace: namespace.to_string(),
        kind: kind.to_string(),
        name: name.to_string(),
    }
}

/// 沿 owner 链上卷并按策略挑选最终 workload。
///
/// 返回 `(final_kind, final_name, immediate_owner)`:
///   - `final_kind` / `final_name`:经遍历 + 挑选后的归并目标(无 owner 链时默认
///     `("Pod", "")`)。
///   - `immediate_owner`:最近一层 owner 的 name(无 owner 时为 `""`)。
pub fn trace_owner_hierarchy(
    cfg: &OwnerResolveConfig,
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

    if !cfg.traverse_up_hierarchy {
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

        let key = owner_key(namespace, &owner.kind, &owner.name);
        cur = owners_index.get(&key).cloned();
        if cur.is_none() {
            break;
        }
    }

    if let Some(selected) = select_owner_from_chain(cfg, &chain) {
        final_kind = selected.kind.clone();
        final_name = selected.name.clone();
    }

    (final_kind, final_name, immediate_owner)
}

/// 在已建好的 owner 链上按 allowlist + priority 挑一个归并目标。
///
/// 规则:
///   - allowlist 非空时,只考虑 kind 在 allowlist 里的条目。
///   - 在候选里挑 priority rank 最小者;同 rank 取链中更深(更靠根)的那个。
///   - 没有任何条目过 allowlist 时:allowlist 为空(全放行)取链尾(最远祖先),
///     否则取链首(immediate owner)。
fn select_owner_from_chain<'a>(
    cfg: &OwnerResolveConfig,
    chain: &'a [OwnerTarget],
) -> Option<&'a OwnerTarget> {
    if chain.is_empty() {
        return None;
    }

    let allow_all = cfg.allowlist.is_empty();
    let mut best: Option<(usize, usize)> = None;

    for (idx, owner) in chain.iter().enumerate() {
        if !allow_all && !cfg.allowlist.contains(&owner.kind) {
            continue;
        }

        let rank = cfg.priority.get(&owner.kind).copied().unwrap_or(usize::MAX);

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

#[cfg(test)]
mod tests {
    //! owner 上卷在抽成纯函数后首次具备可单测性。覆盖几条关键不变量:
    //!   - allowlist 为空 = 全放行,取链尾(最远祖先)。
    //!   - priority 排名:rank 小者优先,同 rank 取链中更深者。
    //!   - allowlist 非空但无人匹配时退回 immediate owner(链首)。
    //!   - depth-8 截断:owner 链超过 8 层只走 8 步。
    //!   - 空 owner / 不上卷的早退路径。

    use super::*;

    fn cfg<'a>(
        traverse: bool,
        allow: &'a HashSet<String>,
        prio: &'a HashMap<String, usize>,
    ) -> OwnerResolveConfig<'a> {
        OwnerResolveConfig {
            traverse_up_hierarchy: traverse,
            allowlist: allow,
            priority: prio,
        }
    }

    fn target(kind: &str, name: &str) -> OwnerTarget {
        OwnerTarget {
            kind: kind.to_string(),
            name: name.to_string(),
        }
    }

    // Pod → ReplicaSet → Deployment;allowlist 空 = 全放行,取链尾 Deployment。
    #[test]
    fn empty_allowlist_picks_chain_tail() {
        let allow = HashSet::new();
        let prio = HashMap::new();
        let mut index = HashMap::new();
        index.insert(
            owner_key("ns", "ReplicaSet", "rs-1"),
            target("Deployment", "dep-1"),
        );

        let (kind, name, immediate) = trace_owner_hierarchy(
            &cfg(true, &allow, &prio),
            "ns",
            Some(target("ReplicaSet", "rs-1")),
            &index,
        );

        assert_eq!(kind, "Deployment");
        assert_eq!(name, "dep-1");
        assert_eq!(immediate, "rs-1");
    }

    // 不上卷时只返回 immediate owner,不碰 owners_index。
    #[test]
    fn no_traverse_returns_immediate_owner() {
        let allow = HashSet::new();
        let prio = HashMap::new();
        let index = HashMap::new();

        let (kind, name, immediate) = trace_owner_hierarchy(
            &cfg(false, &allow, &prio),
            "ns",
            Some(target("ReplicaSet", "rs-1")),
            &index,
        );

        assert_eq!(kind, "ReplicaSet");
        assert_eq!(name, "rs-1");
        assert_eq!(immediate, "rs-1");
    }

    // 无 owner reference 的裸 Pod:默认 ("Pod", "")。
    #[test]
    fn no_owner_defaults_to_pod() {
        let allow = HashSet::new();
        let prio = HashMap::new();
        let index = HashMap::new();

        let (kind, name, immediate) =
            trace_owner_hierarchy(&cfg(true, &allow, &prio), "ns", None, &index);

        assert_eq!(kind, "Pod");
        assert_eq!(name, "");
        assert_eq!(immediate, "");
    }

    // allowlist 只放行 Deployment:链上 ReplicaSet 被跳过,选中 Deployment。
    #[test]
    fn allowlist_filters_to_allowed_kind() {
        let allow: HashSet<String> = ["Deployment".to_string()].into_iter().collect();
        let prio = HashMap::new();
        let mut index = HashMap::new();
        index.insert(
            owner_key("ns", "ReplicaSet", "rs-1"),
            target("Deployment", "dep-1"),
        );

        let (kind, name, _) = trace_owner_hierarchy(
            &cfg(true, &allow, &prio),
            "ns",
            Some(target("ReplicaSet", "rs-1")),
            &index,
        );

        assert_eq!(kind, "Deployment");
        assert_eq!(name, "dep-1");
    }

    // allowlist 非空但链上无人匹配 → 退回链首(immediate owner)。
    #[test]
    fn allowlist_no_match_falls_back_to_chain_head() {
        let allow: HashSet<String> = ["Installation".to_string()].into_iter().collect();
        let prio = HashMap::new();
        let mut index = HashMap::new();
        index.insert(
            owner_key("ns", "ReplicaSet", "rs-1"),
            target("Deployment", "dep-1"),
        );

        let (kind, name, _) = trace_owner_hierarchy(
            &cfg(true, &allow, &prio),
            "ns",
            Some(target("ReplicaSet", "rs-1")),
            &index,
        );

        assert_eq!(kind, "ReplicaSet");
        assert_eq!(name, "rs-1");
    }

    // priority 让低 rank 的 Kind 胜出,即使它在链中更靠前。
    #[test]
    fn priority_rank_wins_over_chain_depth() {
        let allow = HashSet::new();
        let prio: HashMap<String, usize> = [("Installation".to_string(), 0)].into_iter().collect();
        // Pod → ReplicaSet → Deployment → Installation
        let mut index = HashMap::new();
        index.insert(
            owner_key("ns", "ReplicaSet", "rs-1"),
            target("Deployment", "dep-1"),
        );
        index.insert(
            owner_key("ns", "Deployment", "dep-1"),
            target("Installation", "inst-1"),
        );

        let (kind, name, _) = trace_owner_hierarchy(
            &cfg(true, &allow, &prio),
            "ns",
            Some(target("ReplicaSet", "rs-1")),
            &index,
        );

        assert_eq!(kind, "Installation");
        assert_eq!(name, "inst-1");
    }

    // owner 链成环(自指)时 depth-8 截断,不死循环。
    #[test]
    fn cyclic_chain_terminates_at_depth_limit() {
        let allow = HashSet::new();
        let prio = HashMap::new();
        // A → A,自指环。
        let mut index = HashMap::new();
        index.insert(owner_key("ns", "Loop", "a"), target("Loop", "a"));

        let (kind, name, _) = trace_owner_hierarchy(
            &cfg(true, &allow, &prio),
            "ns",
            Some(target("Loop", "a")),
            &index,
        );

        // 不 panic / 不挂死;最终落在环上的节点。
        assert_eq!(kind, "Loop");
        assert_eq!(name, "a");
    }
}
