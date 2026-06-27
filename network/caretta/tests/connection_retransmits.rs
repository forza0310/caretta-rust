//! 守卫:TCP 重传通路。
//!
//! eBPF 端必须挂 tcp_retransmit_skb 的 fentry、ConnectionThroughputStats 必须新增
//! retransmits 字段、用户态收割侧必须把 segs 求和并作为 prometheus counter delta 上
//! 报。forget_link 必须同步清 LINKS_RETRANSMITS_METRICS series + LAST_LINK_RETRANS_TOTALS
//! 基准——否则两件事都会出 bug:cardinality 泄漏 + 同名 link 复活时 counter 毛刺。

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
fn should_declare_retransmit_fentry_in_ebpf() {
    let src = read("caretta-ebpf/src/main.rs");
    assert!(
        src.contains("#[fentry(function = \"tcp_retransmit_skb\")]"),
        "ebpf must attach fentry to tcp_retransmit_skb"
    );
    assert!(
        src.contains("handle_tcp_retransmit_skb"),
        "ebpf must define handle_tcp_retransmit_skb"
    );
}

#[test]
fn should_carry_retransmits_field_with_locked_layout() {
    // ABI 守卫:两侧镜像结构体都必须把 retransmits 钉到 offset 16,size 24,align 8。
    // 任意一侧改了都会编译期炸,但留这条 wiring guard 让审稿人一眼就能看到红线。
    let ebpf = read("caretta-ebpf/src/main.rs");
    let user = read("caretta/src/types.rs");
    for (label, src) in [("ebpf", &ebpf), ("user", &user)] {
        assert!(
            src.contains("offset_of!(ConnectionThroughputStats, retransmits) == 16"),
            "{label} must assert retransmits offset 16"
        );
        assert!(
            src.contains("size_of::<ConnectionThroughputStats>() == 24"),
            "{label} must assert struct size 24"
        );
    }
}

#[test]
fn should_register_retransmits_counter_with_link_labels() {
    let src = read("caretta/src/metrics.rs");
    assert!(
        src.contains("caretta_tcp_retransmits_total"),
        "metrics must register caretta_tcp_retransmits_total"
    );
    assert!(
        src.contains("LAST_LINK_RETRANS_TOTALS"),
        "metrics must keep a delta baseline for retransmits like LAST_LINK_TOTALS"
    );
    // forget_link 必须同时清 LINKS_RETRANSMITS_METRICS + LAST_LINK_RETRANS_TOTALS。
    let forget_block = src
        .split("pub fn forget_link")
        .nth(1)
        .expect("forget_link must exist");
    assert!(
        forget_block.contains("LINKS_RETRANSMITS_METRICS.remove_label_values"),
        "forget_link must drop the retransmits series"
    );
    assert!(
        forget_block.contains("LAST_LINK_RETRANS_TOTALS"),
        "forget_link must clear the retransmits baseline"
    );
}

#[test]
fn should_wire_retransmits_through_poll_loop() {
    let src = read("caretta/src/main.rs");
    assert!(
        src.contains("handle_link_retransmits"),
        "main poll loop must call metrics::handle_link_retransmits"
    );
    assert!(
        src.contains("throughput.retransmits"),
        "main poll loop must read the retransmits field from per-CPU aggregate"
    );
}

#[test]
fn should_load_and_attach_retransmit_fentry() {
    // 漏掉 load/attach 是 Phase 2 实测踩过的坑:eBPF 函数声明了,但用户态不挂载,
    // 整条计数器永远为 0、毫无报错——只能靠源码守卫挡住回归。
    let src = read("caretta/src/main.rs");
    assert!(
        src.contains("\"handle_tcp_retransmit_skb\""),
        "main must fetch the handle_tcp_retransmit_skb program by name"
    );
    assert!(
        src.contains(".load(\"tcp_retransmit_skb\""),
        "main must FEntry::load with kernel symbol tcp_retransmit_skb"
    );
}
