//! caretta-k8s-state 的 Prometheus 指标:K8s Event 计数 + watch 存活心跳。

use once_cell::sync::Lazy;
use prometheus::{CounterVec, GaugeVec, Opts};
use std::time::{SystemTime, UNIX_EPOCH};

// 每条 Event 上卷后,按 (namespace,type,reason,workload_kind,workload_name)
// 聚合的发生次数,按 Event 的 count 做 delta 累加(见 events.rs)。
static EVENTS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "caretta_k8s_events_total",
            "total Kubernetes events observed since launch, rolled up to the owning workload",
        ),
        &[
            "namespace",
            "type",
            "reason",
            "workload_kind",
            "workload_name",
        ],
    )
    .expect("create caretta_k8s_events_total");
    prometheus::default_registry()
        .register(Box::new(c.clone()))
        .expect("register caretta_k8s_events_total");
    c
});

// Watch 心跳:每条 watch 上次任意活动的 unix 时间戳,给存活监控用。
static WATCH_LAST_ACTIVE_UNIX_SECONDS: Lazy<GaugeVec> = Lazy::new(|| {
    let g = GaugeVec::new(
        Opts::new(
            "caretta_k8s_state_watch_last_active_unix_seconds",
            "unix timestamp of the most recent watch-stream activity (any kind) per object type",
        ),
        &["object_type"],
    )
    .expect("create caretta_k8s_state_watch_last_active_unix_seconds");
    prometheus::default_registry()
        .register(Box::new(g.clone()))
        .expect("register caretta_k8s_state_watch_last_active_unix_seconds");
    g
});

/// 按 delta 累加一条 Event series 的发生次数。delta 由 events.rs 的 count-delta 跟踪算出。
pub fn add_events(
    namespace: &str,
    event_type: &str,
    reason: &str,
    workload_kind: &str,
    workload_name: &str,
    delta: f64,
) {
    if delta <= 0.0 {
        return;
    }
    EVENTS_TOTAL
        .with_label_values(&[namespace, event_type, reason, workload_kind, workload_name])
        .inc_by(delta);
}

/// 刷新某条 watch 的"上次任意活动"时间戳。
pub fn mark_watch_alive(object_type: &str) {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    WATCH_LAST_ACTIVE_UNIX_SECONDS
        .with_label_values(&[object_type])
        .set(now_secs);
}
