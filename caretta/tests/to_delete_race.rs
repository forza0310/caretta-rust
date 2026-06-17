//! `still_dead_keys` 复检闸门 —— 防同 4-tuple+pid 在 iter() 与 remove 窗口里
//! 被 eBPF 复用,导致新连接被一并删掉。
//!
//! Tick 内序列:
//!   1) `iter()` 收 `is_active==0` 的 key 进 `to_delete`;
//!   2) `still_dead_keys` 复检,产出 `to_purge`;
//!   3) `to_purge` 批量 remove。
//!
//! 1 → 3 之间窗口里 eBPF 可以把同一 key 翻回 `is_active=1`(HTTP keep-alive、
//! NAT 端口复用、SYN_RECV 路径 pid 撞同值)。`still_dead_keys` 必须把这种 key
//! 从候选里剔出去。

use caretta::purge::still_dead_keys;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// 站位 key:bug 形状只依赖 Eq + Hash,无需真 `ConnectionIdentifier`。caretta lib
/// 故意只 re-export `purge`/`per_cpu`(types 链着 resolver/kube),所以走最小
/// 模型。
type ConnId = u64;

/// 0 = closed, 非 0 = active —— 与 eBPF `try_handle_sock_set_state` 写入约定一致。
type IsActive = u64;

type ConnMap = HashMap<ConnId, IsActive>;

/// 闭包工厂:从 fake state 里读 `is_active`,匹配 `Some(&0)` 视为仍 closed。
/// 对应 main.rs 的 `matches!(connection_states.get(conn, 0), Ok(0u64))`。
fn is_still_dead<'a>(states: &'a ConnMap) -> impl Fn(&ConnId) -> bool + 'a {
    move |k| matches!(states.get(k), Some(&0))
}

/// 单 entry race:窗口里 key 被复用,`still_dead_keys` 必须剔除。
#[test]
fn should_filter_out_freshly_reused_key_to_avoid_deleting_active_connection() {
    let mut states = ConnMap::new();
    let key = 0xDEAD_BEEF_u64;

    // T0: 旧连接 close, sock_set_state 写 is_active=0。
    states.insert(key, 0);

    // T1: iter 阶段收候选。
    let to_delete: Vec<ConnId> = states
        .iter()
        .filter(|(_, v)| **v == 0)
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(to_delete, vec![key]);

    // T2: 窗口内 eBPF 复用,is_active 翻 1。
    states.insert(key, 1);

    // T3: 复检必须把它剔出。
    let to_purge = still_dead_keys(to_delete, is_still_dead(&states));

    assert!(
        to_purge.is_empty(),
        "复用的 key 不该被列入 to_purge: {to_purge:?}"
    );
}

/// 防回归:窗口里没复用,closed key 仍要被放行 —— 否则 GC 停摆,map 永久泄漏。
#[test]
fn should_still_purge_closed_connection_when_no_reuse_happens_in_window() {
    let mut states = ConnMap::new();
    let key = 0xCAFE_F00D_u64;

    states.insert(key, 0);
    let to_delete: Vec<ConnId> = states
        .iter()
        .filter(|(_, v)| **v == 0)
        .map(|(k, _)| *k)
        .collect();
    let to_purge = still_dead_keys(to_delete, is_still_dead(&states));

    assert_eq!(to_purge, vec![key]);
}

/// 混合场景:同 tick 里 reused 应剔、truly_dead 应放行,按 entry 粒度决策。
#[test]
fn should_decide_per_entry_when_purge_handles_mixed_reuse_pattern() {
    let mut states = ConnMap::new();
    let reused = 1u64;
    let truly_dead = 2u64;
    let always_active = 3u64;

    states.insert(reused, 0);
    states.insert(truly_dead, 0);
    states.insert(always_active, 1);

    let to_delete: Vec<ConnId> = states
        .iter()
        .filter(|(_, v)| **v == 0)
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(to_delete.len(), 2);

    // 窗口里只有 reused 被复用。
    states.insert(reused, 1);

    let to_purge = still_dead_keys(to_delete, is_still_dead(&states));

    assert!(
        to_purge.contains(&truly_dead),
        "未复用的 closed key 应放行: {to_purge:?}"
    );
    assert!(
        !to_purge.contains(&reused),
        "复用的 key 不该列入: {to_purge:?}"
    );
    assert!(
        !to_purge.contains(&always_active),
        "iter 阶段就活着的 key 与候选无关"
    );
}

/// Wiring 守卫:防 main.rs 把 `still_dead_keys` 调用点删了 / 改回直接遍历 `to_delete`。
/// 上面三条测的是函数本身的语义,函数还在但没人调照样绿;字面 grep 真源码堵这个盲区。
#[test]
fn should_recheck_candidates_via_still_dead_keys_before_batch_remove() {
    let main_rs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let src = fs::read_to_string(&main_rs).expect("read main.rs");

    assert!(
        src.contains("caretta::purge::still_dead_keys(to_delete"),
        "main.rs 必须用 still_dead_keys 把 to_delete 过一遍"
    );
    assert!(
        src.contains("for conn in to_purge"),
        "main.rs 必须迭代复检后的 to_purge,而不是 raw to_delete"
    );
    assert!(
        !src.contains("for conn in to_delete"),
        "禁止 `for conn in to_delete` —— 那是绕过闸门的旧 buggy 路径"
    );
}

/// Wiring 守卫:闸门的输入端 —— `is_active==0` 检测 + 入队 to_delete。
///
/// `still_dead_keys` 守的是 iter→remove 之间的 race;这条守的是 iter 本身。
/// 删除路径还必须同时清 CONNECTIONS 和 CONNECTION_STATES 两张表 —— 拆 RMW race
/// 时把它们分家了,只删一张会让另一张永久泄漏。
#[test]
fn should_mark_and_delete_inactive_entries_in_userspace_poll_loop() {
    let main_rs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let src = fs::read_to_string(&main_rs).expect("read main.rs");

    assert!(
        src.contains("if is_active == 0") && src.contains("to_delete.push(conn)"),
        "poll loop 必须按 is_active==0 入队 to_delete"
    );
    assert!(
        src.contains("connections.remove(&conn)")
            && src.contains("connection_states.remove(&conn)"),
        "poll loop 必须同时清 CONNECTIONS 和 CONNECTION_STATES 两张 BPF map"
    );
}
