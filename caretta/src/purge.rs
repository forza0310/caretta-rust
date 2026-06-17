//! 主循环 `to_delete` 批量 remove 前的复检闸门。
//!
//! `iter()` 收集到的"看上去 closed"候选,在真正 remove 之前对每条再查一次
//! 权威状态:仍然 closed 的放行,已被复用(同 4-tuple+pid)的拦下。把这步
//! 抠成纯 std 函数,integration test 可以直接调,不用过 BPF map 真件。

/// 给候选 key 过一遍 `is_still_dead`,返回仍判定为 dead 的子集。
///
/// `is_still_dead(k)` 返回 `true` 表示 k 仍然 closed、可以删;`false` 表示
/// 已被复用 / 不在 map 里 / 任何应当跳过的状态。典型实现:再读一次
/// `CONNECTION_STATES` 匹配 `Ok(0u64)`。
pub fn still_dead_keys<K: Copy>(candidates: Vec<K>, is_still_dead: impl Fn(&K) -> bool) -> Vec<K> {
    candidates
        .into_iter()
        .filter(|k| is_still_dead(k))
        .collect()
}
