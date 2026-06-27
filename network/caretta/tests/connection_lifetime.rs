//! 守卫:连接 lifetime 直方图通路。
//!
//! eBPF 端必须声明 CLOSED_LIFETIMES + CONNECTION_OPEN_TS 两张 map,close 路径必须
//! 投递 (key, lifetime_ns)、open 路径必须写起始时间戳。用户态必须收割并 observe
//! 到 caretta_tcp_connection_lifetime_seconds 直方图,该 series 在 TcpTable GC 时
//! 必须随 caretta_tcp_states 一并 forget——不然 cardinality 跟着 close 风暴一路涨。

use std::fs;
use std::path::PathBuf;

fn read(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn should_declare_lifetime_maps_in_ebpf() {
    let src = read("caretta-ebpf/src/main.rs");
    assert!(
        src.contains("static CONNECTION_OPEN_TS"),
        "ebpf must declare CONNECTION_OPEN_TS to record SYN_SENT/SYN_RECV timestamp"
    );
    assert!(
        src.contains("static CLOSED_LIFETIMES"),
        "ebpf must declare CLOSED_LIFETIMES delivery map for close path"
    );
}

#[test]
fn should_record_open_timestamp_on_state_open() {
    let src = read("caretta-ebpf/src/main.rs");
    // open 路径必须用 ktime_get_ns 写起始戳到 CONNECTION_OPEN_TS。
    assert!(
        src.contains("bpf_ktime_get_ns"),
        "ebpf must call bpf_ktime_get_ns to capture open timestamp"
    );
    assert!(
        src.contains("CONNECTION_OPEN_TS.insert"),
        "ebpf open path must populate CONNECTION_OPEN_TS"
    );
}

#[test]
fn should_deliver_lifetime_on_state_close() {
    let src = read("caretta-ebpf/src/main.rs");
    // close 路径计算 now-open_ts 并写入投递桶。
    assert!(
        src.contains("CLOSED_LIFETIMES.insert"),
        "ebpf close path must deliver computed lifetime via CLOSED_LIFETIMES"
    );
    assert!(
        src.contains("CONNECTION_OPEN_TS.remove"),
        "ebpf close path must clean up CONNECTION_OPEN_TS so sock reuse doesn't collide"
    );
}

#[test]
fn should_drain_closed_lifetimes_in_userspace() {
    let src = read("caretta/src/main.rs");
    assert!(
        src.contains("CLOSED_LIFETIMES"),
        "userspace must take CLOSED_LIFETIMES map"
    );
    assert!(
        src.contains("handle_tcp_lifetime"),
        "userspace poll loop must observe drained lifetimes into histogram"
    );
}

#[test]
fn should_register_lifetime_histogram_with_tcp_state_labels() {
    let src = read("caretta/src/metrics.rs");
    assert!(
        src.contains("caretta_tcp_connection_lifetime_seconds"),
        "metrics must register caretta_tcp_connection_lifetime_seconds histogram"
    );
    // forget_tcp 必须同时清掉 lifetime 直方图 series,否则 GC 漏删 → cardinality 泄漏。
    let forget_block = src
        .split("pub fn forget_tcp")
        .nth(1)
        .expect("forget_tcp must exist");
    assert!(
        forget_block.contains("TCP_LIFETIME_METRICS.remove_label_values"),
        "forget_tcp must also forget the lifetime histogram series"
    );
}
