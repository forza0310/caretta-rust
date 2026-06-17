# Caretta TODO

来自 2026-06-16 全局 code review 的稳定性 / 安全性 / 鲁棒性问题，按优先级排序。
完成一项请把 `[ ]` 改成 `[x]` 并补一条 commit 引用。

---

## 🔴 P0 — 数据正确性炸点（必须修）

### [x] 1. eBPF map RMW race：sendmsg 字节会被 sock_set_state 静默吞掉

- **位置**：[caretta-ebpf/src/main.rs:252](caretta-ebpf/src/main.rs#L252)
- **症状**：BPF hash map 的 update 是 entry 整体替换，无字段级原子。两个
  program 在不同 CPU 上并发对同一连接做 read-modify-write，后写者盖掉先写者。
- **触发**：CPU0 跑 `try_handle_tcp_sendmsg` 读到 `bytes_sent=1024`、加 size 后写回
  `2048`；CPU1 几乎同时跑 `try_handle_sock_set_state` 读到 `1024` 旧快照、set
  `is_active=1` 后整 struct 写回；CPU1 后于 CPU0 落地 → CPU0 的累加被吞。
  ESTABLISHED → FIN_WAIT 类后续状态切换走同一路径，close 前最后一笔 sendmsg 极
  容易撞上。
- **修法**：state 路径只写 `is_active`，绝不写 bytes 字段；或改 `BPF_MAP_TYPE_PERCPU_HASH`
  让用户态做聚合。
- **修复实施(2026-06-16)**：两条都做了。CONNECTIONS 改 PerCpuHashMap、字节计数从
  `tcp_sendmsg`/`tcp_cleanup_rbuf` 路径只动当前 CPU 副本——跨 CPU 永不冲突;
  `is_active` 拆到独立的 CONNECTION_STATES（普通 HashMap）,只有 sock_set_state 路径写。
  两条写路径的目标 map 物理上不重叠,RMW 跨 CPU 撞车从根上消掉。用户态收割时把
  `PerCpuValues` 求和聚合,以 CONNECTION_STATES 为权威连接清单驱动主循环。
- **caretta-go 对比**：caretta-go 不存在此问题。它通过 `bpf_core_read` 直接读
  内核 `tcp_sock->bytes_sent/bytes_received` 累计计数器,不在 BPF 端做 RMW,
  天然规避了字段级原子问题。

### [ ] 2. to_delete 延迟删除 + 同 key 复用 → 新连接被一并删掉

- **位置**：[caretta/src/main.rs:327](caretta/src/main.rs#L327)
- **症状**：`to_delete` 在 `iter()` 阶段先收集后批量 remove，中间窗口里 ebpf 端
  可能用完全相同的 ConnectionIdentifier 复用同一格，整条新连接被删。
- **触发**：HTTP keep-alive 池关闭后立刻复用同 4-tuple、NAT 端口复用、SYN_RECV
  路径 pid 来自 softirq 当前 task 容易撞同值。Tick 处理时 `connections.remove(&conn)`
  把刚建立的新 entry 一起删了，prometheus 看到 Counter 倒退。
- **修法**：用 `lookup_and_delete` 原子删除；或 remove 前再 get 一次校验
  `is_active` 仍为 0。

---

## 🟠 P1 — 一上量就出问题

### [ ] 3. 1Hz 主循环里串行 await resolver，DNS 抖动直接拖垮

- **位置**：[caretta/src/main.rs:298](caretta/src/main.rs#L298)
- **症状**：`CONNECTIONS` 上限 131072，对每条 entry 串行 `.await` 两次
  `reduce_connection_to_*`。一次 DNS fallback（800ms 超时）就足以让单 tick 跑超 1s。
  `tokio::time::interval` 默认 `MissedTickBehavior::Burst`，堆积的 tick 会背靠背补齐。
- **后果**：主循环背靠背跑、reactor 长时间不归还 → HTTP `/metrics` scrape 超时、
  K8s watch / DNS resolve 任务饿死。
- **修法**：`MissedTickBehavior::Skip`；resolver 调用换成 `join_all` 批量并发。

### [ ] 4. links HashMap 无硬上限，burst 期间 RSS 线性膨胀

- **位置**：[caretta/src/main.rs:230](caretta/src/main.rs#L230)
- **症状**：只有 5 分钟 TTL 兜底，无 size cap。短连接风暴 / 端口扫描 / 滚动更新
  能在 5 分钟内产生几十万到几百万唯一 NetworkLink。
- **估算**：每条 ~300–500 字节，100 万条 ≈ 400MB RSS；同时 LAST_LINK_TOTALS、
  LINKS_METRICS series 各持平。GC retain 全表扫，百万级单次几百毫秒，把主循环挤掉。
- **修法**：加 `max_links` 配置硬上限（达到上限按 last_active 升序丢最老的）；
  或砍 cardinality（src_ip/dst_ip 这种无界 label 折叠到 workload 维度）。

### [ ] 5. LINK_GC_TTL 与 prometheus staleness 完全等长，rate() 出 NaN/spike

- **位置**：[caretta/src/metrics.rs:271](caretta/src/metrics.rs#L271)
- **症状**：`LINK_GC_TTL = 5 min` 与 prometheus 默认 staleness window = 5 min
  完全重叠。`forget_link` 删 series + `LAST_LINK_TOTALS` 清零之后，同一对
  client/server 复活时 Counter 从 0 跳到几十 MB，PromQL `rate()` 在边界产出
  无穷大尖刺或 NaN。注释里自己说"5 分钟是给 staleness 窗口内平滑过渡留的"，
  但没把两个窗口拉开，恰恰构造出最坏边界。
- **修法**：`LINK_GC_TTL` 改成 staleness × 2 = 10 min；或 forget 时不真删 series，
  写 0 让 Counter 走标准 reset 协议。

---

## 🟡 P2 — 设计层面的脆弱点

### [ ] 6. DNS 负缓存无 TTL，一次失败永久钉死

- **位置**：[caretta/src/resolver/dns.rs:98](caretta/src/resolver/dns.rs#L98)
- **症状**：DNS 抖动时某 IP resolve 失败 → fallback 写入 LRU
  `(1.2.3.4 → "1.2.3.4")`。DNS 恢复后只要 LRU 没被淘汰（cache_size 默认大），
  所有后续查询命中负缓存，永远拿到 IP 字面量而不是真实 hostname。
- **修法**：负缓存条目加 60s TTL；或正负缓存分桶，负缓存桶尺寸严格小于正缓存桶。

### [ ] 7. watch 与周期 refresh 并发跑，旧快照覆盖新快照

- **位置**：[caretta/src/resolver/k8s.rs:136](caretta/src/resolver/k8s.rs#L136)
- **症状**：watch 事件触发的 refresh 和 30s 周期 refresh 无互斥。后完成的
  `store()` 用更老的 list 覆盖刚刚被 watch 写入的新状态，最长 30s 内所有受影响
  IP 拿到旧 workload。
- **修法**：`tokio::sync::Mutex` 串行化 refresh；或 store 前比较
  generation/resourceVersion 选最新者。
- **与 491fb04 的关系**：491fb04 把 `ips` 从 `RwLock` 换成 `ArcSwap`，解决的是
  **读 vs 写**（reader 拿不到锁→误归类 external→prometheus series 永久泄漏）。
  这条是**写 vs 写**：`ArcSwap::store()` 是原子指针 swap，但不保证两个 writer
  之间的因果顺序，谁后调 `store` 谁生效，跟 list 时刻早晚无关——旧的 RwLock
  实现也有同样的写覆盖问题，491fb04 既没引入也没解决它。但 491fb04 把"读路径
  fallback 到 external"这条爆发面堵掉之后，本条的后果从"频繁 series 泄漏"
  降级成"最长 30s 的旧数据窗口"，严重性降一档但 race 本身仍在。

### [ ] 8. IPv6 流量整链路被丢弃

- **位置**：[caretta/src/resolver/k8s.rs:549](caretta/src/resolver/k8s.rs#L549)
- **症状**：`IpResolver` 整条链路 key 都是 `u32`，`parse_ipv4_to_u32` 对 v6 IP
  返回 `None`。dual-stack K8s 集群里 IPv6 Pod/Service 索引整体被丢弃。dashboard
  上 dual-stack 工作负载的内部流量被错标成对外流量，触发误告警。
- **修法**：长期把 trait 换成 `IpAddr`，索引改 `HashMap<IpAddr, _>`，ebpf 端读
  `sk_v6_daddr`/`sk_v6_rcv_saddr`。短期至少在文档明示"IPv6 不支持"。

---

## 🟢 P3 — 部署 / 配置面

### [ ] 9. 环境变量解析失败静默 fall back

- **位置**：[caretta/src/config.rs:54](caretta/src/config.rs#L54)
- **症状**：`DEBUG_RESOLVER_ENABLED=ture`（拼错 true）这种情况下 `parse::<bool>`
  返回 Err，整段 `if let Ok(v) = ...` 被跳过，静默用 CLI 默认值，无任何 warn/error。
  运维以为开关生效，实际没生效；安全相关开关（debug 端点）尤其危险。
- **修法**：解析失败 `anyhow!()` 退出（fail loud），或至少 `warn!` 一条
  "env var X='v' could not be parsed, falling back to default"。

### [ ] 10. /metrics + /debug/resolver bind 0.0.0.0、无鉴权

- **位置**：[caretta/src/http_server.rs:22](caretta/src/http_server.rs#L22)、
  [caretta/src/main.rs:159](caretta/src/main.rs#L159)
- **症状**：caretta 通常 `hostNetwork=true` 跑在 node 上，bind `0.0.0.0` 意味着
  同节点任何被攻陷的容器都能 `curl http://127.0.0.1:7117/debug/resolver` 拿到完整
  集群拓扑（pod name、namespace、kind、owner、内部 IP 段）。`debug_resolver_enabled`
  默认 false，但排障时一旦打开经常忘关。`/metrics` 端点本身也是源级别的内部
  IP/服务名 dump，同节点恶意进程同样可读。
- **修法（短期）**：默认 bind `127.0.0.1`，显式配置才允许 `0.0.0.0`；debug 端点
  强制要求 token query string。
- **修法（长期）**：把 `/debug` 拆到独立 unix socket 或加 mTLS。

---

## 上一轮 review 已记录、尚未修的 ebpf 日志相关问题

（来自上一次 commit `6eb9354` 的 review，单列在这里以免遗忘）

### [ ] 11. CONNECTIONS map 满时 hot path 上 `info!/warn!` 日志风暴

- **位置**：[caretta-ebpf/src/main.rs:255](caretta-ebpf/src/main.rs#L255)、
  [caretta-ebpf/src/main.rs:262](caretta-ebpf/src/main.rs#L262)
- **修法**：改成只 `inc` 一个 stat counter map，用户态 1Hz 拉一次再决定打不打日志。

### [ ] 12. CONNECTIONS 写成功 + SOCK_TO_CONNECTION 写失败 → 孤儿条目泄漏

- **位置**：[caretta-ebpf/src/main.rs:258](caretta-ebpf/src/main.rs#L258)
- **症状**：close 路径走 cookie 反查表查不到 key，`is_active` 永远停在 1，
  用户态永远不会推进 `to_delete`。两个 map 一起雪崩。
- **修法**：`SOCK_TO_CONNECTION.insert` 失败时把刚刚写入的 `CONNECTIONS` 条目 remove 掉。

### [ ] 13. EbpfLogger::init 排到 attach 之后，启动期日志窗口丢失

- **位置**：[caretta/src/main.rs:138](caretta/src/main.rs#L138)
- **修法**：调整顺序为 `Ebpf::load → 所有 program.load → EbpfLogger::init → program.attach`。

### [ ] 14. SOCK_OFFSETS 缺失分支是死代码（用户态写入在 attach 之前）

- **位置**：[caretta-ebpf/src/main.rs:222](caretta-ebpf/src/main.rs#L222)
- **修法**：删掉 warn 留 silent skip；或让用户态显式校验 SOCK_OFFSETS 已写入再 attach。

### [ ] 15. map insert 失败 vs SOCK_OFFSETS 缺失，日志级别分级反了

- **位置**：[caretta-ebpf/src/main.rs:255](caretta-ebpf/src/main.rs#L255)、
  [caretta-ebpf/src/main.rs:222](caretta-ebpf/src/main.rs#L222)
- **修法**：map 撑爆 → `warn!`；BTF 解析未完成 → `info!`（或都 `warn!`，自洽即可）。
