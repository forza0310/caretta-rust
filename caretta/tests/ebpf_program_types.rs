//! eBPF 程序类型 + BTF 偏移解析的 wiring 守卫。
//!
//! `bpf_get_socket_cookie()` 在 verifier 里按 program type 白名单注册,只有
//! `BPF_PROG_TYPE_TRACING` 系(fentry / fexit / tp_btf)能用。三个程序必须迁到
//! TRACING:tcp_sendmsg / tcp_cleanup_rbuf 走 fentry,inet_sock_set_state 走 tp_btf。
//! 退一步就让 cookie 修复整体失效,但表面看不到任何错(verifier 直接拒载入)。
//!
//! 同时:sock_common 字段偏移由 vmlinux BTF 解出来推到 eBPF 端的 SOCK_OFFSETS,
//! 不再走旧的 tracefs format 解析路径。

use std::fs;
use std::path::PathBuf;

fn read(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn should_not_mutate_byte_counters_when_processing_state_transition() {
    let src = read("caretta-ebpf/src/main.rs");

    assert!(
        !src.contains("throughput.bytes_sent = throughput.bytes_sent.saturating_add(1);"),
        "state transition should not add synthetic bytes_sent"
    );
}

#[test]
fn should_use_fentry_for_byte_accounting_probes() {
    let src = read("caretta-ebpf/src/main.rs");

    assert!(
        src.contains("#[fentry(function = \"tcp_sendmsg\")]"),
        "tcp_sendmsg accounting must run on fentry (BPF_PROG_TYPE_TRACING) for cookie helper"
    );
    assert!(
        src.contains("#[fentry(function = \"tcp_cleanup_rbuf\")]"),
        "tcp_cleanup_rbuf accounting must run on fentry for cookie helper"
    );
    // 守住 legacy kprobe 攻击面 —— 退回 #[kprobe] 会让 cookie helper verifier 拒载入。
    assert!(
        !src.contains("#[kprobe]"),
        "byte accounting must not run on legacy kprobe — cookie helper would fail verifier"
    );
}

#[test]
fn should_use_btf_tracepoint_for_state_transitions() {
    let src = read("caretta-ebpf/src/main.rs");

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
    let src = read("caretta/src/main.rs");

    assert!(
        src.contains("FEntry") && src.contains("BtfTracePoint"),
        "userspace must load FEntry + BtfTracePoint to match the new program types"
    );
    assert!(
        src.contains("Btf::from_sys_fs"),
        "userspace must read kernel BTF from /sys/kernel/btf for fentry/tp_btf attach"
    );
    // legacy 加载 API 不该再出现 —— 出现就意味着新程序类型回退了。
    assert!(
        !src.contains("KProbe") && !src.contains("TracePoint;"),
        "userspace must not still reference KProbe / TracePoint loaders"
    );
    assert!(
        !src.contains("parse_tracepoint_offsets"),
        "tracefs format parsing must be removed; sock_common offsets come from BTF now"
    );
}

#[test]
fn should_resolve_sock_field_offsets_from_vmlinux_btf() {
    let main_src = read("caretta/src/main.rs");
    let btf_src = read("caretta/src/btf/lookup.rs");
    let ebpf_src = read("caretta-ebpf/src/main.rs");

    // sock_common 偏移走 BTF 解析,推到 eBPF 端的 SOCK_OFFSETS map。
    assert!(
        main_src.contains("parse_sock_offsets") && main_src.contains("SOCK_OFFSETS"),
        "main.rs must parse sock_common offsets and push them via SOCK_OFFSETS map"
    );
    assert!(
        btf_src.contains("pub fn parse_sock_offsets"),
        "btf/lookup.rs must expose parse_sock_offsets backed by the BTF parser"
    );
    assert!(
        ebpf_src.contains("static SOCK_OFFSETS"),
        "ebpf side must declare SOCK_OFFSETS map for sock_common offsets"
    );
    assert!(
        !main_src.contains("TRACEPOINT_OFFSETS") && !main_src.contains("TRACEPOINT_FORMAT_PATH"),
        "tracepoint offset path must be fully removed; SOCK_OFFSETS replaces it"
    );
}
