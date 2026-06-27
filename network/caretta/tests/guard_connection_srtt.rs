//! 守卫:TCP srtt 采样直方图通路。
//!
//! eBPF 端必须声明 TCP_SOCK_OFFSETS + SOCK_SAMPLES 两张 map,cleanup_rbuf 路径必须
//! 按 BTF 偏移读 srtt_us 并 last-writer-wins 写入采样表;close 路径必须随 sock 一起
//! 抹掉这条采样,避免 sock 复用串味。用户态必须启动期把 TCP_SOCK_OFFSETS 灌好,
//! 主 poll loop 必须按连接 lookup 后 observe 到 caretta_tcp_srtt_seconds 直方图,
//! 该 series 在 TcpTable GC 时必须随 caretta_tcp_states 一并 forget——和 lifetime
//! 一样,只清 gauge 不清 histogram 等于 cardinality 跟着连接数一路涨。

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
fn should_declare_srtt_maps_in_ebpf() {
    let src = read("caretta-ebpf/src/main.rs");
    assert!(
        src.contains("static TCP_SOCK_OFFSETS"),
        "ebpf must declare TCP_SOCK_OFFSETS so userspace can populate srtt_us offset"
    );
    assert!(
        src.contains("static SOCK_SAMPLES"),
        "ebpf must declare SOCK_SAMPLES gauge snapshot map"
    );
}

#[test]
fn should_sample_srtt_in_cleanup_rbuf() {
    let src = read("caretta-ebpf/src/main.rs");
    // cleanup_rbuf 路径必须从 TCP_SOCK_OFFSETS 取偏移、读字段、写采样表。
    assert!(
        src.contains("TCP_SOCK_OFFSETS.get"),
        "cleanup_rbuf must look up the srtt_us offset before reading sock"
    );
    assert!(
        src.contains("SOCK_SAMPLES.insert"),
        "cleanup_rbuf must write the sampled srtt into SOCK_SAMPLES"
    );
}

#[test]
fn should_purge_sock_samples_on_close() {
    let src = read("caretta-ebpf/src/main.rs");
    // 同 CONNECTION_OPEN_TS:eBPF 端 close 路径要主动抹采样,避免 sock 复用串味。
    let close_block = src
        .split("fn mark_connection_closed")
        .nth(1)
        .expect("mark_connection_closed must exist");
    assert!(
        close_block.contains("SOCK_SAMPLES.remove"),
        "mark_connection_closed must clean up SOCK_SAMPLES so reused sock doesn't carry stale srtt"
    );
}

#[test]
fn should_populate_tcp_sock_offsets_at_startup() {
    let src = read("caretta/src/main.rs");
    // 用户态启动期必须解 BTF + 灌 map;漏掉任一步,eBPF 端 lookup 永远 miss,srtt
    // 通路静默熄火。
    assert!(
        src.contains("parse_tcp_sock_offsets"),
        "userspace must parse tcp_sock offsets from BTF at startup"
    );
    assert!(
        src.contains("TCP_SOCK_OFFSETS"),
        "userspace must populate the TCP_SOCK_OFFSETS map"
    );
}

#[test]
fn should_take_sock_samples_and_observe_srtt() {
    let src = read("caretta/src/main.rs");
    assert!(
        src.contains("SOCK_SAMPLES"),
        "userspace must take SOCK_SAMPLES map"
    );
    assert!(
        src.contains("handle_tcp_srtt"),
        "poll loop must observe sampled srtt into the histogram via handle_tcp_srtt"
    );
    // 单位换算公式锁死:kernel 端 srtt_us 是 us<<3,所以必须先 /8 再 /1e6 转秒。
    assert!(
        src.contains("/ 8.0 / 1_000_000.0") || src.contains("/ 8.0/1_000_000.0"),
        "userspace must convert srtt_us via `>> 3` then `/ 1e6` to seconds"
    );
}

#[test]
fn should_register_srtt_histogram_with_tcp_state_labels() {
    let src = read("caretta/src/metrics.rs");
    assert!(
        src.contains("caretta_tcp_srtt_seconds"),
        "metrics must register caretta_tcp_srtt_seconds histogram"
    );
    // forget_tcp 必须同时清 srtt 直方图 series,否则 GC 漏删 → cardinality 泄漏。
    let forget_block = src
        .split("pub fn forget_tcp")
        .nth(1)
        .expect("forget_tcp must exist");
    assert!(
        forget_block.contains("TCP_SRTT_METRICS.remove_label_values"),
        "forget_tcp must also forget the srtt histogram series"
    );
}

#[test]
fn should_purge_sock_samples_in_userspace_gc_path() {
    // 对称于 CONNECTION_OPEN_TS:用户态 purge dying connection 时,SOCK_SAMPLES
    // 必须跟着清,避免 131072 上限被孤儿化 entry 慢慢撑爆。eBPF close 路径已经清过
    // 一次,但用户态 GC 窗口可能先到——多删一次是 best-effort 兜底。
    let src = read("caretta/src/main.rs");
    assert!(
        src.contains("sock_samples.remove"),
        "purge path must remove SOCK_SAMPLES entry alongside connection_states"
    );
}
