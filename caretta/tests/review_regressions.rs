use std::fs;
use std::path::PathBuf;

// Integration-level source assertions that lock in fixes for previously reviewed regressions.

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("caretta crate should have workspace parent")
        .to_path_buf()
}

fn read_repo_file(path_from_repo_root: &str) -> String {
    let path = repo_root().join(path_from_repo_root);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

    // Ensures close-path key lookup cannot drift from open-path key construction.
#[test]
    fn should_use_socket_lookup_key_when_closing_connection() {
    let src = read_repo_file("caretta-ebpf/src/main.rs");

    assert!(
        src.contains("fn mark_connection_closed(cookie: u64)"),
        "close helper should look up the original key by sock cookie"
    );
    assert!(
        src.contains("SOCK_TO_CONNECTION.get(&cookie)"),
        "close path should look up original key from SOCK_TO_CONNECTION"
    );
    assert!(
        !src.contains("pid: 0,"),
        "close path should not construct a pid=0 key"
    );
}

// ---- review 问题 6:struct sock 内存复用导致的 reverse-map race ----
//
// SOCK_TO_CONNECTION 不能用 raw `struct sock *` 地址做 key——sock 被 free 后内核会把同一片
// slab 内存重新分配给新连接,导致两代 sock 共用同一个 skaddr,旧 close 与新 sendmsg 互相
// 串扰。修复方案是改用 bpf_get_socket_cookie(struct sock *)(kernel >= 5.7),它对每个 sock
// 实例返回一个一生一码的 64-bit 标识,sock free 后不会复用。
//
// 这组守卫钉死三件事:
//   1. helper 真的被引入(import 进来,不被未来的 cleanup 误删)。
//   2. SOCK_TO_CONNECTION 的反查 key 全部走 cookie 而不是 skaddr。
//   3. cookie==0 的 fallback 路径存在(避免 helper 不可用时多 sock 在 0 上碰撞)。
#[test]
fn should_key_socket_reverse_map_by_cookie_not_raw_address() {
    let src = read_repo_file("caretta-ebpf/src/main.rs");

    assert!(
        src.contains("bpf_get_socket_cookie"),
        "ebpf prog should call bpf_get_socket_cookie helper"
    );
    assert!(
        src.contains("fn sock_cookie(skaddr: u64) -> u64"),
        "ebpf prog should expose a sock_cookie() wrapper"
    );
    // 反查表插入路径必须用 cookie。
    assert!(
        src.contains("SOCK_TO_CONNECTION.insert(&cookie, &key, 0)"),
        "open path should insert into SOCK_TO_CONNECTION keyed by cookie"
    );
    // sendmsg/recvmsg 都必须先取 cookie 再查表。
    let cookie_lookup_count = src.matches("SOCK_TO_CONNECTION.get(&cookie)").count();
    assert!(
        cookie_lookup_count >= 3,
        "close + sendmsg + recvmsg should each look up by cookie (got {cookie_lookup_count})"
    );
    // 任何残留的 skaddr-as-key 用法都应当被拔除。
    assert!(
        !src.contains("SOCK_TO_CONNECTION.insert(&skaddr"),
        "no path should still insert into SOCK_TO_CONNECTION keyed by skaddr"
    );
    assert!(
        !src.contains("SOCK_TO_CONNECTION.get(&skaddr)"),
        "no path should still look up SOCK_TO_CONNECTION by skaddr"
    );
}

#[test]
fn should_skip_when_socket_cookie_is_unavailable() {
    let src = read_repo_file("caretta-ebpf/src/main.rs");

    // cookie==0 表示 helper 不可用或 sock NULL。直接 return 而不是把多 sock 都映射到 key=0。
    let zero_guard_count = src.matches("if cookie == 0 {").count();
    assert!(
        zero_guard_count >= 4,
        "every cookie consumer should bail out on cookie==0 (got {zero_guard_count})"
    );
}

// Ensures byte counters only reflect tcp_sendmsg/tcp_cleanup_rbuf accounting paths.
#[test]
fn should_not_mutate_byte_counters_when_processing_state_transition() {
    let src = read_repo_file("caretta-ebpf/src/main.rs");

    assert!(
        !src.contains("throughput.bytes_sent = throughput.bytes_sent.saturating_add(1);"),
        "state transition should not add synthetic bytes_sent"
    );
}

// ---- review #6 修复后:程序类型迁移到 BPF_PROG_TYPE_TRACING ----
//
// `bpf_get_socket_cookie()` helper 在 verifier 里按 program type 白名单注册,只有
// BPF_PROG_TYPE_TRACING 系(fentry / fexit / tp_btf)能用。要让 cookie 修复落地,三个
// 程序都必须迁到 TRACING:
//   - tcp_sendmsg / tcp_cleanup_rbuf 走 fentry
//   - inet_sock_set_state 走 tp_btf(同一个内核 hook,程序类型从 legacy tracepoint
//     升级到 TRACING)
// 这组守卫确保未来 cleanup / refactor 不会把它们悄悄退回 legacy 类型——退一步就让
// cookie 修复整体失效,但表面看不到任何错(verifier 直接拒载入而不是运行时漂移)。

#[test]
fn should_use_fentry_for_byte_accounting_probes() {
    let src = read_repo_file("caretta-ebpf/src/main.rs");

    assert!(
        src.contains("#[fentry(function = \"tcp_sendmsg\")]"),
        "tcp_sendmsg accounting must run on fentry (BPF_PROG_TYPE_TRACING) for cookie helper"
    );
    assert!(
        src.contains("#[fentry(function = \"tcp_cleanup_rbuf\")]"),
        "tcp_cleanup_rbuf accounting must run on fentry for cookie helper"
    );
    // 守住 legacy kprobe 攻击面——cleanup 时手贱误改回 #[kprobe] 会让 cookie helper
    // verifier 直接拒载入。
    assert!(
        !src.contains("#[kprobe]"),
        "byte accounting must not run on legacy kprobe — cookie helper would fail verifier"
    );
}

#[test]
fn should_use_btf_tracepoint_for_state_transitions() {
    let src = read_repo_file("caretta-ebpf/src/main.rs");

    assert!(
        src.contains("#[btf_tracepoint(function = \"inet_sock_set_state\")]"),
        "inet_sock_set_state must use tp_btf (BPF_PROG_TYPE_TRACING) for cookie helper"
    );
    assert!(
        !src.contains("#[tracepoint]"),
        "state transition probe must not use legacy tracepoint — cookie helper would fail verifier"
    );
}

#[test]
fn should_load_programs_via_fentry_and_btf_tracepoint_in_userspace() {
    let src = read_repo_file("caretta/src/main.rs");

    // 用户态加载侧:必须走 FEntry / BtfTracePoint 而不是 KProbe / TracePoint。
    assert!(
        src.contains("FEntry") && src.contains("BtfTracePoint"),
        "userspace must load FEntry + BtfTracePoint to match the new program types"
    );
    assert!(
        src.contains("Btf::from_sys_fs"),
        "userspace must read kernel BTF from /sys/kernel/btf for fentry/tp_btf attach"
    );
    // 防御:legacy 加载 API 不该再出现在 main.rs。出现就意味着新程序类型回退了。
    assert!(
        !src.contains("KProbe") && !src.contains("TracePoint;"),
        "userspace must not still reference KProbe / TracePoint loaders"
    );
    // 旧 tracefs format 解析路径整体下线。
    assert!(
        !src.contains("parse_tracepoint_offsets"),
        "tracefs format parsing must be removed; sock_common offsets come from BTF now"
    );
}

#[test]
fn should_resolve_sock_field_offsets_from_vmlinux_btf() {
    let main_src = read_repo_file("caretta/src/main.rs");
    let types_src = read_repo_file("caretta/src/types.rs");
    let ebpf_src = read_repo_file("caretta-ebpf/src/main.rs");

    // sock_common 偏移走 BTF 解析,推到 eBPF 端的 SOCK_OFFSETS 这张 map。
    assert!(
        main_src.contains("parse_sock_offsets") && main_src.contains("SOCK_OFFSETS"),
        "main.rs must parse sock_common offsets and push them via SOCK_OFFSETS map"
    );
    assert!(
        types_src.contains("pub fn parse_sock_offsets"),
        "types.rs must expose parse_sock_offsets backed by the BTF parser"
    );
    assert!(
        ebpf_src.contains("static SOCK_OFFSETS"),
        "ebpf side must declare SOCK_OFFSETS map for sock_common offsets"
    );
    // 旧的 TRACEPOINT_OFFSETS / TRACEPOINT_FORMAT_PATH 必须整体下线。
    assert!(
        !main_src.contains("TRACEPOINT_OFFSETS") && !main_src.contains("TRACEPOINT_FORMAT_PATH"),
        "tracepoint offset path must be fully removed; SOCK_OFFSETS replaces it"
    );
}

// Ensures resolver refresh signaling remains bounded under watch-event bursts.
#[test]
fn should_coalesce_refresh_signals_when_watch_events_burst() {
    let src = read_repo_file("caretta/src/resolver.rs");

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

// Ensures metric help text matches runtime aggregation semantics.
#[test]
fn should_describe_bidirectional_bytes_in_links_metric_help_text() {
    let src = read_repo_file("caretta/src/metrics.rs");

    assert!(
        src.contains("bytes_sent + bytes_received"),
        "metric help text should describe the actual aggregation"
    );
}

// Ensures userspace link aggregation keeps bidirectional throughput behavior.
#[test]
fn should_aggregate_sent_and_received_bytes_in_userspace_poll_loop() {
    let src = read_repo_file("caretta/src/main.rs");

    assert!(
        src.contains("throughput.bytes_sent.saturating_add(throughput.bytes_received)"),
        "poll loop should aggregate sent+received bytes into link throughput"
    );
}

// Ensures closed entries are both detected and removed during userspace polling.
#[test]
fn should_mark_and_delete_inactive_entries_in_userspace_poll_loop() {
    let src = read_repo_file("caretta/src/main.rs");

    assert!(
        src.contains("if throughput.is_active == 0") && src.contains("to_delete.push(conn)"),
        "poll loop should identify inactive entries for deletion"
    );
    assert!(
        src.contains("connections.remove(&conn)"),
        "poll loop should remove inactive entries from the eBPF map"
    );
}

// ---- review 问题 3/4：用户态状态表无界增长导致进程内存 + Prometheus cardinality 泄漏 ----
//
// 这一组守卫断言修复后的不变量。它们检查源码层的特征——比起单元测试，源码守卫更适合
// 钉死"实现路径必须包含某些步骤"这类结构性要求；行为正确性则在 metrics.rs 的 unit
// tests 和 main.rs 的 poll loop 设计里检查。

// 守卫 GC 配置常量存在且不为零——零 TTL 等于"永不过期"或"立刻过期"，两者都会还原成
// 修复前的行为或导致 series gap，必须看见显式的非零数值。
#[test]
fn should_define_nonzero_gc_constants_for_link_and_tcp() {
    let src = read_repo_file("caretta/src/main.rs");

    assert!(
        src.contains("const LINK_GC_TTL"),
        "main should define LINK_GC_TTL constant for link series GC"
    );
    assert!(
        src.contains("const TCP_GC_MISSED_TICKS"),
        "main should define TCP_GC_MISSED_TICKS constant for tcp series GC"
    );
    // 不允许 LINK_GC_TTL = Duration::from_secs(0) / from_millis(0) 这类零值。
    assert!(
        !src.contains("LINK_GC_TTL: Duration = Duration::from_secs(0)")
            && !src.contains("LINK_GC_TTL: Duration = Duration::from_millis(0)"),
        "LINK_GC_TTL must be a non-zero duration"
    );
}

// 守卫 poll loop 真的在调 forget_link / forget_tcp。如果有人后来手贱把 retain 删了
// 或者把 forget_* 调用注释掉，这条会立刻报警。
#[test]
fn should_invoke_forget_helpers_during_poll_loop_gc() {
    let src = read_repo_file("caretta/src/main.rs");

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

// 守卫 metrics 模块的 forget_* 同时清理 Prometheus series 和差分基准——只清一边
// 等于没清（review 问题 3 的根因之一）。
#[test]
fn should_clear_prometheus_series_and_baseline_in_forget_helpers() {
    let src = read_repo_file("caretta/src/metrics.rs");

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
    // 防止只删 series 不清基准——这是修复前最容易留下的 subtle bug。
    assert!(
        src.contains("LAST_LINK_TOTALS")
            && src.matches("LAST_LINK_TOTALS").count() >= 2,
        "forget_link must also clear the diff baseline in LAST_LINK_TOTALS"
    );
}

// 守卫 link / tcp 的 label values 由共享 helper 构造——而不是 produce 路径和 forget
// 路径各拼一遍。重复构造是经典漂移源：改了 produce 忘了改 forget，forget 找不到
// series → 漏删 → 泄漏依旧。
#[test]
fn should_share_label_construction_between_produce_and_forget_paths() {
    let src = read_repo_file("caretta/src/metrics.rs");

    assert!(
        src.contains("fn link_label_values("),
        "metrics module should centralize link label construction in link_label_values"
    );
    assert!(
        src.contains("fn tcp_label_values("),
        "metrics module should centralize tcp label construction in tcp_label_values"
    );
}

// 守卫 GC 计时只刷新"本 tick 真正可见的"link，而不是 current_links 合并视图里的所有
// link——后者会让早就死掉、只剩 cumulative 累计值的 link 永远逃过 GC。
#[test]
fn should_refresh_link_last_active_only_for_freshly_observed_links() {
    let src = read_repo_file("caretta/src/main.rs");

    assert!(
        src.contains("link_seen_this_tick"),
        "poll loop should track which links were observed in this tick"
    );
    assert!(
        src.contains("link_seen_this_tick.contains(&link)"),
        "poll loop should gate last_active refresh on link_seen_this_tick"
    );
}
