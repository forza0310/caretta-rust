//! 守卫:TCP segs_in / segs_out 采样通路。
//!
//! 复用 srtt 已搭好的 TCP_SOCK_OFFSETS + SOCK_SAMPLES 通道:BTF 端额外解两个偏移、
//! 快照结构体多带两个 u32、用户态把它们当 throughput 镜像走 Counter delta。
//! forget_link 必须同步清两条 series + 两张基准表,否则 cardinality 泄漏 + 同名 link
//! 复活时 counter 毛刺,与 retransmits 同款风险。

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
fn should_carry_segs_offsets_in_tcp_sock_offsets() {
    // ABI 守卫:两侧 TcpSockOffsets 字段排布钉死。srtt_us 在 0,segs_in 在 4,
    // segs_out 在 8;改任一处都得同步两侧,编译期断言兜底,这条守卫只是早预警。
    let ebpf = read("caretta-ebpf/src/main.rs");
    let user = read("caretta/src/types.rs");
    for (label, src) in [("ebpf", &ebpf), ("user", &user)] {
        assert!(
            src.contains("offset_of!(TcpSockOffsets, segs_in_off) == 4"),
            "{label} must assert segs_in_off offset 4"
        );
        assert!(
            src.contains("offset_of!(TcpSockOffsets, segs_out_off) == 8"),
            "{label} must assert segs_out_off offset 8"
        );
    }
}

#[test]
fn should_carry_segs_fields_in_sock_sample_snapshot() {
    // 同上:SockSampleSnapshot 多带 last_segs_in / last_segs_out 两个 u32,
    // 偏移 4 / 8 与 TcpSockOffsets 一一对应。
    let ebpf = read("caretta-ebpf/src/main.rs");
    let user = read("caretta/src/types.rs");
    for (label, src) in [("ebpf", &ebpf), ("user", &user)] {
        assert!(
            src.contains("offset_of!(SockSampleSnapshot, last_segs_in) == 4"),
            "{label} must assert last_segs_in offset 4"
        );
        assert!(
            src.contains("offset_of!(SockSampleSnapshot, last_segs_out) == 8"),
            "{label} must assert last_segs_out offset 8"
        );
    }
}

#[test]
fn should_sample_segs_in_cleanup_rbuf() {
    let src = read("caretta-ebpf/src/main.rs");
    // cleanup_rbuf 路径必须读到 segs_in / segs_out 才能写入快照,光读 srtt 通不过。
    assert!(
        src.contains("segs_in_off"),
        "cleanup_rbuf must read segs_in via the BTF offset"
    );
    assert!(
        src.contains("segs_out_off"),
        "cleanup_rbuf must read segs_out via the BTF offset"
    );
    assert!(
        src.contains("last_segs_in") && src.contains("last_segs_out"),
        "cleanup_rbuf must populate both segs fields into the snapshot"
    );
}

#[test]
fn should_resolve_segs_offsets_from_btf() {
    let src = read("caretta/src/btf/lookup.rs");
    // parse_tcp_sock_offsets 漏掉任一字段都会让 eBPF 端读 0,Counter 永远 0,
    // 必须把字段名钉在源码守卫里。
    assert!(
        src.contains("\"segs_in\""),
        "parse_tcp_sock_offsets must resolve segs_in"
    );
    assert!(
        src.contains("\"segs_out\""),
        "parse_tcp_sock_offsets must resolve segs_out"
    );
}

#[test]
fn should_register_segs_counters_with_link_labels() {
    let src = read("caretta/src/metrics.rs");
    assert!(
        src.contains("caretta_tcp_segs_in_total"),
        "metrics must register caretta_tcp_segs_in_total"
    );
    assert!(
        src.contains("caretta_tcp_segs_out_total"),
        "metrics must register caretta_tcp_segs_out_total"
    );
    assert!(
        src.contains("LAST_LINK_SEGS_IN_TOTALS"),
        "metrics must keep a segs_in delta baseline mirroring LAST_LINK_TOTALS"
    );
    assert!(
        src.contains("LAST_LINK_SEGS_OUT_TOTALS"),
        "metrics must keep a segs_out delta baseline mirroring LAST_LINK_TOTALS"
    );
    let forget_block = src
        .split("pub fn forget_link")
        .nth(1)
        .expect("forget_link must exist");
    assert!(
        forget_block.contains("LINKS_SEGS_IN_METRICS.remove_label_values"),
        "forget_link must drop the segs_in series"
    );
    assert!(
        forget_block.contains("LINKS_SEGS_OUT_METRICS.remove_label_values"),
        "forget_link must drop the segs_out series"
    );
    assert!(
        forget_block.contains("LAST_LINK_SEGS_IN_TOTALS")
            && forget_block.contains("LAST_LINK_SEGS_OUT_TOTALS"),
        "forget_link must clear both segs baselines"
    );
}

#[test]
fn should_wire_segs_through_poll_loop() {
    let src = read("caretta/src/main.rs");
    assert!(
        src.contains("handle_link_segs_in"),
        "main poll loop must call metrics::handle_link_segs_in"
    );
    assert!(
        src.contains("handle_link_segs_out"),
        "main poll loop must call metrics::handle_link_segs_out"
    );
    // segs 来自 sock 采样而非 throughput,所以累加路径必须读 last_segs_in/out 字段,
    // 防止有人误把 segs 接到 throughput 上。
    assert!(
        src.contains("last_segs_in") && src.contains("last_segs_out"),
        "main poll loop must accumulate segs from the sock sample snapshot"
    );
}
