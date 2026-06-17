//! link metric 聚合语义守卫。
//!
//! help text 必须如实描述 runtime 实际聚合方式(`bytes_sent + bytes_received`),
//! poll loop 也必须真的按这个公式合并 —— 否则 metric 文档与数据语义会对不上。

use std::fs;
use std::path::PathBuf;

fn read(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn should_describe_bidirectional_bytes_in_links_metric_help_text() {
    let src = read("caretta/src/metrics.rs");

    assert!(
        src.contains("bytes_sent + bytes_received"),
        "metric help text should describe the actual aggregation"
    );
}

#[test]
fn should_aggregate_sent_and_received_bytes_in_userspace_poll_loop() {
    let src = read("caretta/src/main.rs");

    assert!(
        src.contains("throughput.bytes_sent.saturating_add(throughput.bytes_received)"),
        "poll loop should aggregate sent+received bytes into link throughput"
    );
}
