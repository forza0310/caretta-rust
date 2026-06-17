//! resolver 层不变量:refresh 信号合流 + ClusterIP → Pod 上卷。

use std::fs;
use std::path::PathBuf;

fn read_k8s() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("caretta/src/resolver/k8s.rs");
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// watch 事件突发时 refresh 信号必须被合流为容量 1 的 mpsc + try_send,
/// 否则一秒成千上万次 ListPod 把 apiserver 打挂。
#[test]
fn should_coalesce_refresh_signals_when_watch_events_burst() {
    let src = read_k8s();

    assert!(
        src.contains("mpsc::channel::<()>(1)"),
        "resolver refresh queue should be bounded to 1"
    );
    assert!(
        src.contains("tx.try_send(())"),
        "watch event handler should coalesce by try_send"
    );
    assert!(
        !src.contains("mpsc::unbounded_channel::<()>()"),
        "unbounded refresh queue should not be used"
    );
}

/// ClusterIP 必须先按 spec.selector 反查同 ns 的 Pod,复用 Pod 已经过完 owner
/// 上卷的 Workload。否则 CLIENT 视角打 kind=Service、SERVER 视角打 kind=Deployment,
/// prometheus 上同一逻辑链路双 series,grafana 拓扑面板抖。
#[test]
fn should_resolve_clusterip_to_pod_workload_when_service_has_selector() {
    let src = read_k8s();

    assert!(
        src.contains("fn selector_matches("),
        "Service path must expose selector_matches helper for ClusterIP→Pod backing resolution"
    );
    assert!(
        src.contains("selector_matches(selector,"),
        "Service iteration must consult Pod labels via selector_matches before falling back to kind=Service"
    );
    // ExternalName / 无 selector / Pod 还没 ready 等 corner case 仍要有 fallback,不能引入新 bug。
    assert!(
        src.contains("fn service_fallback_workload("),
        "Service fallback for selectorless services (ExternalName etc.) must be preserved"
    );
}
