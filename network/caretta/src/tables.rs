//! 用户态 link / tcp 状态表 + 按淘汰键排序的 BTreeMap 二级索引。
//!
//! 主存仍是 `HashMap<key, state>`(O(1) 按 key 查改),旁边挂一个与之同步的
//! `BTreeMap<淘汰键, HashSet<key>>` 二级索引。淘汰 / TTL-GC / 软-GC 都从索引最旧端
//! 弹出,把"每 tick 全表 clone + sort / retain 扫描"降到 O(被删条数)。
//!
//! 同一个 tick 内大量条目共享同一个淘汰键(link 的 `now`、tcp 的 `tick` 序号),
//! 所以桶用 `HashSet` 装多条 key,而不是一对一。

use crate::metrics;
use crate::types::{NetworkLink, TcpConnection, TcpConnectionKey};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

/// links 表里每条 link 的状态。
pub struct LinkState {
    /// 自启动以来这条 link 的累计字节数(活着的 + 已死亡部分)。每次 poll 合并出 current_links。
    pub cumulative_bytes: u64,
    /// 最近一次"还在产生流量"的时间。GC 用 now() - last_active > TTL 判定回收。
    pub last_active: Instant,
}

/// `HashMap<NetworkLink, LinkState>` + 按 `last_active` 排序的二级索引。
pub struct LinkTable {
    map: HashMap<NetworkLink, LinkState>, // 主存:连接 → 状态
    by_active: BTreeMap<Instant, HashSet<NetworkLink>>, // 二级索引:时间 → 该时刻活跃的连接集合
}

impl LinkTable {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            by_active: BTreeMap::new(),
        }
    }

    /// 只读遍历,用于把 past link 的 cumulative_bytes 合并进本 tick 的 current_links。
    pub fn iter(&self) -> impl Iterator<Item = (&NetworkLink, &LinkState)> {
        self.map.iter()
    }

    /// 插入或刷新一条 link:`cumulative_bytes += add_bytes`、`last_active = now`,并同步索引。
    ///
    /// - 本 tick 真见到的 link:`add_bytes = 0`(只刷新时间,保留累计值)。
    /// - dying-link 合并路径:传入这条连接最后一段字节。
    pub fn touch(&mut self, link: NetworkLink, now: Instant, add_bytes: u64) {
        match self.map.get_mut(&link) {
            Some(state) => {
                let old = state.last_active;
                state.cumulative_bytes = state.cumulative_bytes.saturating_add(add_bytes);
                state.last_active = now;
                if old != now {
                    Self::bucket_remove(&mut self.by_active, old, &link);
                    self.by_active.entry(now).or_default().insert(link);
                }
            }
            None => {
                self.map.insert(
                    link.clone(),
                    LinkState {
                        cumulative_bytes: add_bytes,
                        last_active: now,
                    },
                );
                self.by_active.entry(now).or_default().insert(link);
            }
        }
    }

    /// TTL-GC:回收所有 `now - last_active > ttl` 的 link。索引升序,遇到未过期桶即停。
    pub fn gc_older_than(&mut self, now: Instant, ttl: Duration) {
        let mut victims: Vec<NetworkLink> = Vec::new();
        for (ts, links) in self.by_active.iter() {
            if now.duration_since(*ts) > ttl {
                victims.extend(links.iter().cloned());
            } else {
                break;
            }
        }
        for link in victims {
            self.forget_and_remove(&link);
        }
    }

    /// 硬上限:超限时从最旧端取 `len - max` 条淘汰。只 clone 被删的那几条,不再全表。
    pub fn enforce_max(&mut self, max: usize) {
        if self.map.len() <= max {
            return;
        }
        let mut to_remove = self.map.len() - max;
        let mut victims: Vec<NetworkLink> = Vec::with_capacity(to_remove);
        'outer: for links in self.by_active.values() {
            for link in links {
                victims.push(link.clone());
                to_remove -= 1;
                if to_remove == 0 {
                    break 'outer;
                }
            }
        }
        for link in victims {
            self.forget_and_remove(&link);
        }
    }

    /// 删掉一条 link:清 prometheus series + 主存 + 索引桶(空桶一并清理)。
    fn forget_and_remove(&mut self, link: &NetworkLink) {
        if let Some(state) = self.map.remove(link) {
            metrics::forget_link(link);
            Self::bucket_remove(&mut self.by_active, state.last_active, link);
        }
    }

    fn bucket_remove(
        by_active: &mut BTreeMap<Instant, HashSet<NetworkLink>>,
        ts: Instant,
        link: &NetworkLink,
    ) {
        if let Some(bucket) = by_active.get_mut(&ts) {
            bucket.remove(link);
            if bucket.is_empty() {
                by_active.remove(&ts);
            }
        }
    }
}

impl Default for LinkTable {
    fn default() -> Self {
        Self::new()
    }
}

/// tcp_states 表里每条连接的 GC 状态。
pub struct TcpState {
    /// 上次见到这条连接时的 TcpConnection 快照——GC 时拿它去删 series,也用于上报。
    pub last_seen_conn: TcpConnection,
    /// 上次出现的 tick 序号。GC 判据 `current_tick - last_seen_tick > N`,与旧的 missed_ticks 计数等价。
    pub last_seen_tick: u64,
}

/// `HashMap<TcpConnectionKey, TcpState>` + 按 `last_seen_tick` 排序的二级索引。
pub struct TcpTable {
    map: HashMap<TcpConnectionKey, TcpState>,
    by_seen: BTreeMap<u64, HashSet<TcpConnectionKey>>,
}

impl TcpTable {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            by_seen: BTreeMap::new(),
        }
    }

    /// 本 tick 见到一条连接:刷新快照与 `last_seen_tick = tick`,并同步索引。
    pub fn observe(&mut self, conn: TcpConnection, tick: u64) {
        let key = TcpConnectionKey::from(&conn);
        match self.map.get_mut(&key) {
            Some(state) => {
                let old = state.last_seen_tick;
                state.last_seen_conn = conn;
                state.last_seen_tick = tick;
                if old != tick {
                    Self::bucket_remove(&mut self.by_seen, old, &key);
                    self.by_seen.entry(tick).or_default().insert(key);
                }
            }
            None => {
                self.map.insert(
                    key.clone(),
                    TcpState {
                        last_seen_conn: conn,
                        last_seen_tick: tick,
                    },
                );
                self.by_seen.entry(tick).or_default().insert(key);
            }
        }
    }

    /// 软-GC:回收所有 `current_tick - last_seen_tick > max_missed` 的连接。索引升序,遇到新鲜桶即停。
    pub fn gc_stale(&mut self, current_tick: u64, max_missed: u32) {
        let max_missed = u64::from(max_missed);
        let mut victims: Vec<TcpConnectionKey> = Vec::new();
        for (seen_tick, keys) in self.by_seen.iter() {
            if current_tick.saturating_sub(*seen_tick) > max_missed {
                victims.extend(keys.iter().cloned());
            } else {
                break;
            }
        }
        for key in victims {
            self.forget_and_remove(&key);
        }
    }

    /// 硬上限:超限时从最旧端(last_seen_tick 最小 = 最 stale)取 `len - max` 条淘汰。
    pub fn enforce_max(&mut self, max: usize) {
        if self.map.len() <= max {
            return;
        }
        let mut to_remove = self.map.len() - max;
        let mut victims: Vec<TcpConnectionKey> = Vec::with_capacity(to_remove);
        'outer: for keys in self.by_seen.values() {
            for key in keys {
                victims.push(key.clone());
                to_remove -= 1;
                if to_remove == 0 {
                    break 'outer;
                }
            }
        }
        for key in victims {
            self.forget_and_remove(&key);
        }
    }

    fn forget_and_remove(&mut self, key: &TcpConnectionKey) {
        if let Some(state) = self.map.remove(key) {
            metrics::forget_tcp(key);
            Self::bucket_remove(&mut self.by_seen, state.last_seen_tick, key);
        }
    }

    fn bucket_remove(
        by_seen: &mut BTreeMap<u64, HashSet<TcpConnectionKey>>,
        seen_tick: u64,
        key: &TcpConnectionKey,
    ) {
        if let Some(bucket) = by_seen.get_mut(&seen_tick) {
            bucket.remove(key);
            if bucket.is_empty() {
                by_seen.remove(&seen_tick);
            }
        }
    }
}

impl Default for TcpTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl LinkTable {
    fn len(&self) -> usize {
        self.map.len()
    }

    fn contains(&self, link: &NetworkLink) -> bool {
        self.map.contains_key(link)
    }

    /// map 与二级索引的条目数必须始终一致(每条 key 恰好在一个桶里)。
    fn index_entry_count(&self) -> usize {
        self.by_active.values().map(HashSet::len).sum()
    }
}

#[cfg(test)]
impl TcpTable {
    fn len(&self) -> usize {
        self.map.len()
    }

    fn contains(&self, key: &TcpConnectionKey) -> bool {
        self.map.contains_key(key)
    }

    fn index_entry_count(&self) -> usize {
        self.by_seen.values().map(HashSet::len).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Workload;

    fn mk_workload(tag: &str) -> Workload {
        Workload {
            name: tag.to_string(),
            namespace: "ns".to_string(),
            kind: "Pod".to_string(),
            owner: String::new(),
        }
    }

    fn mk_link(n: u32) -> NetworkLink {
        NetworkLink {
            client: mk_workload(&format!("c{n}")),
            server: mk_workload(&format!("s{n}")),
            client_ip: format!("10.0.0.{n}"),
            server_ip: format!("10.0.1.{n}"),
            server_port: 80,
            role: 0,
        }
    }

    fn mk_conn(n: u32) -> TcpConnection {
        TcpConnection {
            client: mk_workload(&format!("c{n}")),
            server: mk_workload(&format!("s{n}")),
            server_port: 80,
            role: 0,
            state: 0,
        }
    }

    // touch 多次累加字节并刷新时间;改键后旧桶不留残留(索引计数 == map 计数)。
    #[test]
    fn link_touch_accumulates_and_moves_bucket() {
        let base = Instant::now();
        let mut t = LinkTable::new();
        let link = mk_link(0);

        t.touch(link.clone(), base, 100);
        t.touch(link.clone(), base + Duration::from_secs(10), 50);

        assert_eq!(t.len(), 1);
        assert_eq!(t.index_entry_count(), 1); // 旧 base 桶已被清空,无残留
        let (_, state) = t.iter().next().expect("one entry");
        assert_eq!(state.cumulative_bytes, 150);
    }

    // 改键后,按旧时间戳判定过期不应误删(条目已迁到新桶)。
    #[test]
    fn link_gc_respects_refreshed_time() {
        let base = Instant::now();
        let mut t = LinkTable::new();
        let link = mk_link(0);
        t.touch(link.clone(), base, 0);
        t.touch(link.clone(), base + Duration::from_secs(10), 0);

        // now - 旧base = 15s > ttl 12s;now - 新t1 = 5s <= 12s → 应保留。
        t.gc_older_than(base + Duration::from_secs(15), Duration::from_secs(12));
        assert!(t.contains(&link));
        assert_eq!(t.index_entry_count(), 1);
    }

    // TTL-GC 只删过期条目,保留新鲜的。
    #[test]
    fn link_gc_removes_only_expired() {
        let base = Instant::now();
        let mut t = LinkTable::new();
        let old = mk_link(0);
        let fresh = mk_link(1);
        t.touch(old.clone(), base, 0);
        t.touch(fresh.clone(), base + Duration::from_secs(20), 0);

        t.gc_older_than(base + Duration::from_secs(25), Duration::from_secs(12));
        assert!(!t.contains(&old)); // 25-0=25 > 12 删
        assert!(t.contains(&fresh)); // 25-20=5 <= 12 留
        assert_eq!(t.len(), 1);
        assert_eq!(t.index_entry_count(), 1);
    }

    // 硬上限保留 last_active 最新的若干条,淘汰最旧的。
    #[test]
    fn link_enforce_max_keeps_freshest() {
        let base = Instant::now();
        let mut t = LinkTable::new();
        let links: Vec<_> = (0..5).map(mk_link).collect();
        for (i, l) in links.iter().enumerate() {
            t.touch(l.clone(), base + Duration::from_secs(i as u64), 0);
        }

        t.enforce_max(2);
        assert_eq!(t.len(), 2);
        assert_eq!(t.index_entry_count(), 2);
        assert!(t.contains(&links[4])); // 最新保留
        assert!(t.contains(&links[3]));
        assert!(!t.contains(&links[0])); // 最旧淘汰
    }

    #[test]
    fn link_enforce_max_noop_under_cap() {
        let base = Instant::now();
        let mut t = LinkTable::new();
        t.touch(mk_link(0), base, 0);
        t.enforce_max(10);
        assert_eq!(t.len(), 1);
    }

    // observe 标记 tick 并迁桶;gc_stale 删 tick 差 > N 者、保留新鲜的。
    #[test]
    fn tcp_gc_stale_removes_only_old() {
        let mut t = TcpTable::new();
        let old = mk_conn(0);
        let fresh = mk_conn(1);
        let old_key = TcpConnectionKey::from(&old);
        let fresh_key = TcpConnectionKey::from(&fresh);
        t.observe(old, 1);
        t.observe(fresh, 5);

        // current=15:15-1=14 > 12 删;15-5=10 <= 12 留。
        t.gc_stale(15, 12);
        assert!(!t.contains(&old_key));
        assert!(t.contains(&fresh_key));
        assert_eq!(t.index_entry_count(), 1);
    }

    // 重新 observe 迁桶后,按旧 tick 判定不应误删。
    #[test]
    fn tcp_observe_moves_bucket() {
        let mut t = TcpTable::new();
        let conn = mk_conn(0);
        let key = TcpConnectionKey::from(&conn);
        t.observe(conn.clone(), 1);
        t.observe(conn, 5);

        t.gc_stale(14, 12); // 14-5=9 <= 12 → 留;若仍挂在 tick1 桶则 14-1=13>12 会误删
        assert!(t.contains(&key));
        assert_eq!(t.index_entry_count(), 1);
    }

    // 硬上限优先淘汰 last_seen_tick 最小(最 stale)者。
    #[test]
    fn tcp_enforce_max_evicts_stalest() {
        let mut t = TcpTable::new();
        let conns: Vec<_> = (0..5).map(mk_conn).collect();
        let keys: Vec<_> = conns.iter().map(TcpConnectionKey::from).collect();
        for (i, c) in conns.into_iter().enumerate() {
            t.observe(c, (i + 1) as u64); // tick 1..5
        }

        t.enforce_max(2);
        assert_eq!(t.len(), 2);
        assert_eq!(t.index_entry_count(), 2);
        assert!(t.contains(&keys[4])); // tick5 最新保留
        assert!(t.contains(&keys[3]));
        assert!(!t.contains(&keys[0])); // tick1 最 stale 淘汰
    }

    #[test]
    fn tcp_enforce_max_noop_under_cap() {
        let mut t = TcpTable::new();
        t.observe(mk_conn(0), 1);
        t.enforce_max(10);
        assert_eq!(t.len(), 1);
    }
}
