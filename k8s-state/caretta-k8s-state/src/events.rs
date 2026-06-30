//! Event watch observer:按 owner 上卷后,以 count-delta 累加到 Prometheus 计数器。
//!
//! K8s 把重复事件聚合到一条 Event 上(`count` 计次),watch 先 Added 再多次 Modified。
//! 某些 Event 受 apiserver TTL GC 后会以【新 uid】重建（如helm事件）,但携带之前的历史 count,故不能按 uid 去重
//! (否则每次重建都把累计 count 重新灌入)。需要按 Event 自身 namespace/name 记水位:
//! name 形如 `<obj>.<hex(firstTimestamp)>`,在 namespace 内稳定、跨重建不变。
//! 只累加超过水位的增量,Delete 不清理水位(留给 LRU 容量淘汰),让重建后能续算。

use crate::metrics;
use crate::owners::OwnerIndex;
use caretta_k8s_core::watch::{ChangeKind, WatchObserver};
use k8s_openapi::api::core::v1::Event;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

pub struct EventObserver {
    owners: Arc<OwnerIndex>,
    /// "namespace/name" → 数到过的最高 count
    watermark: Mutex<LruCache<String, i32>>,
}

impl EventObserver {
    pub fn new(owners: Arc<OwnerIndex>, capacity: usize) -> Arc<Self> {
        let capacity = NonZeroUsize::new(capacity.max(1)).expect("capacity >= 1");
        Arc::new(Self {
            owners,
            watermark: Mutex::new(LruCache::new(capacity)),
        })
    }
}

impl WatchObserver<Event> for EventObserver {
    fn on_active(&self, watch_name: &'static str) {
        metrics::mark_watch_alive(watch_name);
    }

    fn on_change(&self, kind: ChangeKind, event: &Event) {
        // Delete 不动水位:如果 Event 以新 uid 重建并续带 count,删水位会导致重复计入。
        if matches!(kind, ChangeKind::Deleted) {
            return;
        }

        // Added / Modified:按 Event 自身 namespace/name 算增量。无 name 没法去重,
        // 退化为按 count 一次性计入。
        let key = event_key(event);
        let delta = match key {
            Some(key) => {
                let mut seen = match self.watermark.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                let (delta, new_last) = count_delta(seen.get(&key).copied(), event.count);
                seen.put(key, new_last);
                delta
            }
            None => event.count.unwrap_or(1).max(1),
        };

        if delta <= 0 {
            return;
        }

        let involved = &event.involved_object;
        let involved_kind = involved.kind.as_deref().unwrap_or_default();
        let involved_name = involved.name.as_deref().unwrap_or_default();
        // namespace 优先 involvedObject;cluster-scoped 对象退回 Event 自身,再退空。
        let namespace = involved
            .namespace
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(event.metadata.namespace.as_deref())
            .unwrap_or_default();

        let (workload_kind, workload_name) =
            self.owners.resolve(involved_kind, namespace, involved_name);

        let event_type = label_or_unknown(event.type_.as_deref().unwrap_or_default());
        let reason = label_or_unknown(event.reason.as_deref().unwrap_or_default());

        metrics::add_events(
            namespace,
            event_type,
            reason,
            &workload_kind,
            &workload_name,
            delta as f64,
        );
    }
}

/// Event 去重 key:"namespace/name"。name 跨 TTL 重建稳定;缺 name 返回 None。
fn event_key(event: &Event) -> Option<String> {
    let name = event.metadata.name.as_deref().filter(|s| !s.is_empty())?;
    let namespace = event.metadata.namespace.as_deref().unwrap_or_default();
    Some(format!("{namespace}/{name}"))
}

/// 按上次/当前 count 算增量,返回 (delta, 更新后的 last)。
///   - count=None 视作 1;delta = max(0, current-last);last 单调不减(取 max)。
fn count_delta(last_seen: Option<i32>, current: Option<i32>) -> (i32, i32) {
    let current = current.unwrap_or(1).max(1);
    let last = last_seen.unwrap_or(0);
    let delta = (current - last).max(0);
    let new_last = current.max(last);
    (delta, new_last)
}

/// 空 label 用 "Unknown" 占位,避免 Prometheus 出现空字符串 label。
fn label_or_unknown(s: &str) -> &str {
    if s.is_empty() { "Unknown" } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn event_named(namespace: Option<&str>, name: Option<&str>) -> Event {
        Event {
            metadata: ObjectMeta {
                namespace: namespace.map(ToString::to_string),
                name: name.map(ToString::to_string),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn first_seen_adds_full_count() {
        let (delta, last) = count_delta(None, Some(3));
        assert_eq!(delta, 3);
        assert_eq!(last, 3);
    }

    #[test]
    fn modified_adds_increment() {
        let (delta, last) = count_delta(Some(3), Some(5));
        assert_eq!(delta, 2);
        assert_eq!(last, 5);
    }

    #[test]
    fn equal_count_adds_nothing() {
        let (delta, _) = count_delta(Some(5), Some(5));
        assert_eq!(delta, 0);
    }

    #[test]
    fn decreasing_count_adds_nothing_and_keeps_last() {
        // count 回退(不该发生)→ delta 0 且 last 保持高水位,防后续重复计入。
        let (delta, last) = count_delta(Some(5), Some(3));
        assert_eq!(delta, 0);
        assert_eq!(last, 5);
    }

    #[test]
    fn missing_count_treated_as_one() {
        let (delta, last) = count_delta(None, None);
        assert_eq!(delta, 1);
        assert_eq!(last, 1);
    }

    #[test]
    fn empty_label_becomes_unknown() {
        assert_eq!(label_or_unknown(""), "Unknown");
        assert_eq!(label_or_unknown("Warning"), "Warning");
    }

    #[test]
    fn event_key_joins_namespace_and_name() {
        let e = event_named(Some("kube-system"), Some("rke2-calico-crd.18ba34cda7377e8d"));
        assert_eq!(
            event_key(&e).as_deref(),
            Some("kube-system/rke2-calico-crd.18ba34cda7377e8d")
        );
    }

    #[test]
    fn event_key_without_name_is_none() {
        assert_eq!(event_key(&event_named(Some("ns"), None)), None);
    }

    #[test]
    fn event_key_distinguishes_events_on_same_resource() {
        // 同一资源的不同事件名各自独立,不应共用水位。
        let a = event_named(Some("ns"), Some("pod-x.aaaa"));
        let b = event_named(Some("ns"), Some("pod-x.bbbb"));
        assert_ne!(event_key(&a), event_key(&b));
    }

    #[test]
    fn recreation_with_stable_key_only_adds_increment() {
        // Event TTL 后以新 uid 重建,但 name 不变、count 续带:按 name 记水位只计增量。
        let key = "ns/evt.abcd".to_string();
        let mut wm: LruCache<String, i32> = LruCache::new(NonZeroUsize::new(8).unwrap());

        // 重建前数到 687。
        let (d1, last1) = count_delta(wm.get(&key).copied(), Some(687));
        wm.put(key.clone(), last1);
        assert_eq!(d1, 687);

        // 删除事件到达:水位刻意保留(on_change 对 Delete 直接 return)。

        // 重建后仍是 687 → delta 0,不重复灌入。
        let (d2, _) = count_delta(wm.get(&key).copied(), Some(687));
        assert_eq!(d2, 0);
    }

    #[test]
    fn count_one_delete_then_recreate_at_two_adds_only_one() {
        // count=1 即入水位;漏掉 Delete、重建到 count=2 时只补 1,不会多计。
        let key = "ns/evt.abcd".to_string();
        let mut wm: LruCache<String, i32> = LruCache::new(NonZeroUsize::new(8).unwrap());

        let (d1, last1) = count_delta(wm.get(&key).copied(), Some(1));
        wm.put(key.clone(), last1);
        assert_eq!(d1, 1);

        let (d2, _) = count_delta(wm.get(&key).copied(), Some(2));
        assert_eq!(d2, 1);
    }
}
