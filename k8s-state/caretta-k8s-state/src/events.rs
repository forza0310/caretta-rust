//! Event watch observer:按 owner 上卷后,以 count-delta 累加到 Prometheus 计数器。
//!
//! K8s 把重复事件聚合到一条 Event 上(`count` 计次),watch 先 Added 再多次 Modified。
//! 按 uid 记住上次 count、只累加增量,避免少计或重复灌入(同 caretta LAST_LINK_TOTALS)。

use crate::metrics;
use crate::owners::OwnerIndex;
use caretta_k8s_core::watch::{ChangeKind, WatchObserver};
use k8s_openapi::api::core::v1::Event;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct EventObserver {
    owners: Arc<OwnerIndex>,
    /// uid → 上次累加用过的 count 绝对值。Deleted 时清除(Event ~1h TTL,自然收敛)。
    last_count: Mutex<HashMap<String, i32>>,
}

impl EventObserver {
    pub fn new(owners: Arc<OwnerIndex>) -> Arc<Self> {
        Arc::new(Self {
            owners,
            last_count: Mutex::new(HashMap::new()),
        })
    }
}

impl WatchObserver<Event> for EventObserver {
    fn on_active(&self, watch_name: &'static str) {
        metrics::mark_watch_alive(watch_name);
    }

    fn on_change(&self, kind: ChangeKind, event: &Event) {
        let uid = event.metadata.uid.clone().unwrap_or_default();

        if matches!(kind, ChangeKind::Deleted) {
            if !uid.is_empty()
                && let Ok(mut seen) = self.last_count.lock()
            {
                seen.remove(&uid);
            }
            return;
        }

        // Added / Modified:算增量。无 uid 没法差分,退化为按 count 一次性计入。
        let delta = if uid.is_empty() {
            event.count.unwrap_or(1).max(1)
        } else {
            let mut seen = match self.last_count.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            let (delta, new_last) = count_delta(seen.get(&uid).copied(), event.count);
            seen.insert(uid, new_last);
            delta
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
}
