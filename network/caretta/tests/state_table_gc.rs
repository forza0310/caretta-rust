//! 用户态 link / tcp 状态表的 GC 不变量。
//!
//! 旧 bug:`links` / `tcp_states` 没有 GC,长跑下来进程内存 + Prometheus
//! cardinality 双向泄漏。修复后必须保住:
//!   - 非零 GC 常量(零 TTL 等于"立刻过期"或"永不过期",都还原成 bug);
//!   - poll loop 真的调 forget_link / forget_tcp + retain 兜底;
//!   - links 表有可配置硬上限,超限按 last_active 淘汰最老 entry;
//!   - forget_* 同时清 series 和差分基准 LAST_LINK_TOTALS(只清一边等于没清);
//!   - produce 路径和 forget 路径用同一个 label 构造 helper(防漂移);
//!   - last_active 只刷新本 tick 真见到的 link,不能刷 cumulative 合并视图里的死 link。
//!
//! 行为正确性由 metrics.rs 的 unit tests 覆盖,这里专门钉源码层 wiring。

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
fn should_define_nonzero_gc_constants_for_link_and_tcp() {
    let src = read("caretta/src/main.rs");

    assert!(
        src.contains("const LINK_GC_TTL"),
        "main should define LINK_GC_TTL constant for link series GC"
    );
    assert!(
        src.contains("const TCP_GC_MISSED_TICKS"),
        "main should define TCP_GC_MISSED_TICKS constant for tcp series GC"
    );
    // 零 TTL 等价于禁用 GC 或立刻过期,都把 bug 复活。
    assert!(
        !src.contains("LINK_GC_TTL: Duration = Duration::from_secs(0)")
            && !src.contains("LINK_GC_TTL: Duration = Duration::from_millis(0)"),
        "LINK_GC_TTL must be a non-zero duration"
    );
}

#[test]
fn should_invoke_forget_helpers_during_poll_loop_gc() {
    let src = read("caretta/src/main.rs");

    assert!(
        src.contains("metrics::forget_link("),
        "poll loop must call metrics::forget_link to clean up expired link series"
    );
    assert!(
        src.contains("metrics::forget_tcp("),
        "poll loop must call metrics::forget_tcp to clean up stale tcp series"
    );
    assert!(
        src.contains("links.retain(") && src.contains("tcp_states.retain("),
        "poll loop must run retain-based GC on both state tables"
    );
}

#[test]
fn should_cap_link_state_table_by_configured_max_links() {
    let main_src = read("caretta/src/main.rs");
    let config_src = read("caretta/src/config.rs");

    assert!(
        config_src.contains("DEFAULT_MAX_LINKS")
            && config_src.contains("pub max_links: usize")
            && config_src.contains("MAX_LINKS"),
        "config should expose MAX_LINKS as a positive env/CLI setting"
    );
    assert!(
        main_src.contains("fn enforce_max_links(")
            && main_src.contains("sort_unstable_by_key")
            && main_src.contains("state.last_active")
            && main_src.contains("metrics::forget_link(&link)")
            && main_src.contains("links.remove(&link)"),
        "poll loop should evict oldest links and clear prometheus state when max_links is exceeded"
    );
    assert!(
        main_src.contains("enforce_max_links(&mut links, opt.max_links)"),
        "poll loop should apply max_links after normal TTL GC"
    );
}

#[test]
fn should_clear_prometheus_series_and_baseline_in_forget_helpers() {
    let src = read("caretta/src/metrics.rs");

    assert!(
        src.contains("pub fn forget_link("),
        "metrics module should expose forget_link helper"
    );
    assert!(
        src.contains("pub fn forget_tcp("),
        "metrics module should expose forget_tcp helper"
    );
    assert!(
        src.contains("LINKS_METRICS.remove_label_values"),
        "forget_link must remove the prometheus series for the link"
    );
    assert!(
        src.contains("TCP_STATE_METRICS.remove_label_values"),
        "forget_tcp must remove the prometheus series for the tcp connection"
    );
    // 只删 series 不清基准 → 同名 link 复活时把"复活后的绝对值"全量灌入 Counter,毛刺。
    assert!(
        src.contains("LAST_LINK_TOTALS") && src.matches("LAST_LINK_TOTALS").count() >= 2,
        "forget_link must also clear the diff baseline in LAST_LINK_TOTALS"
    );
}

#[test]
fn should_share_label_construction_between_produce_and_forget_paths() {
    let src = read("caretta/src/metrics.rs");

    // produce 与 forget 各拼一遍 label 是经典漂移源 —— 改了 produce 忘了改 forget,
    // forget 找不到 series → 漏删 → 泄漏依旧。
    assert!(
        src.contains("fn link_label_values("),
        "metrics module should centralize link label construction in link_label_values"
    );
    assert!(
        src.contains("fn tcp_label_values("),
        "metrics module should centralize tcp label construction in tcp_label_values"
    );
}

#[test]
fn should_refresh_link_last_active_only_for_freshly_observed_links() {
    let src = read("caretta/src/main.rs");

    // current_links 是"活的 + 累计的"合并视图,刷它会让早就死掉、只剩 cumulative
    // 累计值的 link 永远逃过 GC。link_seen_this_tick 只装本 tick 真见过的。
    assert!(
        src.contains("link_seen_this_tick"),
        "poll loop should track which links were observed in this tick"
    );
    assert!(
        src.contains("link_seen_this_tick.contains(&link)"),
        "poll loop should gate last_active refresh on link_seen_this_tick"
    );
}
