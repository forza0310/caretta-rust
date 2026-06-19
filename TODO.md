# Code Review TODO（临时跟进）

> 本文件来自 2026-06 的二次 code-review，已剔除一次 review 已修项与验证后的 false positive。
> 状态：`[ ]` 未处理 / `[x]` 已处理 / `[~]` 部分处理 / `[skip]` 决定不修。

---

## 🔴 Bug 级（应优先修）

- [x] **#1 eBPF 端 sendmsg / cleanup_rbuf 路径 map insert 失败静默**
  - 位置：`caretta-ebpf/src/main.rs::try_handle_tcp_sendmsg` / `try_handle_tcp_cleanup_rbuf`
  - 原状：`CONNECTIONS.insert(...)?` 静默传播 -E2BIG，运维无感
  - 已做：四条 insert 路径统一 `warn!`；`info` 导入移除；编译通过
  - 余项：可选追加 `caretta_failed_inserts` 指标（参照现有 `caretta_failed_deletions`）

- [x] **#2 k8s watch 路径鲁棒性四连**
  - 位置：`caretta/src/resolver/k8s.rs::spawn_watch`
  - 已做：
    - RV 跟踪：Added/Modified/Deleted 抽 `o.meta().resource_version`，Bookmark 抽 `b.metadata.resource_version`；初始 `rv=""` 等价 "0"，首条事件后替换
    - 410 检测：`WatchEvent::Error(e)` 里 `e.code == 410 || e.reason == "Expired"` → 清空 RV 走 re-list 起手；其他错误保留 RV
    - 退避抖动：`backoff` 从 1s 起步，失败 `* 2` 封顶 30s，成功消费事件后重置；`sleep_with_jitter` 加 ±50% 抖动（用 `SystemTime` nanos 做廉价随机源，未引入 rand 依赖）
    - Bookmark 不再 `tx.try_send(())`，避免心跳事件触发空跑 refresh
  - 余项：暂无

- [x] **#3 watch task panic 静默死亡，无 supervisor**
  - 位置：`caretta/src/resolver/k8s.rs::spawn_watch_and_refresh_tasks`
  - 原状：每个 watch / refresh task 都是 detached `tokio::spawn`；闭包内 panic 一旦 unwind 出来,整个 tokio task 永久死亡,主流程不感知
  - 已做：
    - 加通用 `supervise(name, factory)` wrapper：内部 `AssertUnwindSafe(factory()).catch_unwind()` + 1s..30s 指数退避(复用现有 `sleep_with_jitter`)；panic 与提前 return 分别计数
    - 11 个 detached task(9 个 watch + refresh-on-event consumer + periodic ticker)全部走 supervise
    - refresh consumer 的 `mpsc::Receiver` 不可 clone,放进 `Arc<Mutex<_>>`,panic 后 MutexGuard drop,下一轮重 lock 接续消费;9 个 watch 持有的 tx 不受影响
    - watch task label 形如 `k8s:watch:pods` / `k8s:refresh-on-event` / `k8s:refresh-periodic`,便于 prometheus 区分
    - 加指标 `caretta_supervised_task_restarts_total{task, reason ∈ {panic, returned}}`
    - 告警 PromQL:`rate(caretta_supervised_task_restarts_total{reason="panic"}[5m]) > 0`
  - 余项：暂无
  - 注意：metrics HTTP server task(main.rs)和每请求 worker(http_server.rs)不在 supervise 范畴——前者已被 main 持有 handle,后者是一次性短命 task,见 TODO 顶层说明

- [x] **#4 `forget_link` / `forget_tcp` 删除 prometheus series 失败静默**
  - 位置：`caretta/src/metrics.rs::forget_link` / `forget_tcp`
  - 原状：`let _ = LINKS_METRICS.remove_label_values(&refs)` 把所有错误吞掉,cardinality drift 这类开发期 bug 也被静默
  - 已做：
    - 两条 forget 函数从 `let _ = ...` 改成 `if let Err(e) = ...`,Err 一律 `warn!` 带 metric 名 + label values
    - 不区分 not-found 与 cardinality drift:GC 端命中"从未注册"在测试里也少见(forget 都跟 produce 配对走),命中即信号;真正想盯的是 drift,既然全 warn 一并暴露,grep 一次就定位
    - 不引入 `caretta_failed_forgets` 指标:出现一次就进日志,grep 即可
  - 余项：暂无

- [x] **#5 BTF parser `resolve_int_size` 不处理 `KIND_ARRAY`**
  - 位置：`caretta/src/btf/parser.rs::resolve_int_size`
  - 原状：处理 INT/ENUM/STRUCT/UNION/PTR/typedef，但 `KIND_ARRAY` 直接 `bail!`；`sock_common` 没 array 字段所以暂未炸
  - 已做：
    - 函数改名 `resolve_int_size` → `resolve_field_size`（连同顺手关掉 #S）；签名加 `types: &[u8]` 用于读 ARRAY trailing
    - 加 `KIND_ARRAY` 分支：从 trailing 12 字节读 (elem_type, _, nelems)，递归求 elem_size，返回 `elem_size * nelems`，`checked_mul` 防溢出
    - `lookup.rs` 模块文档 / import / 调用点同步更新
    - 单测 `should_resolve_array_field_size`：`struct demo { u8 buf[16]; }`，验证 size=16 通过、size=8 bail；`cargo test --bin caretta btf::lookup` 全绿
  - 余项：暂无

- [x] **#6 `ConnectionIdentifier.id` 字段冗余**
  - 位置：`caretta-ebpf/src/main.rs::ConnectionIdentifier` + `caretta/src/types.rs::ConnectionIdentifier`
  - 原状：`id = fnv_hash(tuple, role)`,但 `(tuple, role, pid)` 已唯一标识；既不做 shard 也不做索引
  - 影响：3 个 map × 131072 entries × 4 字节 ≈ 1.5 MB BPF map 浪费；key cmp 多比一次 u32
  - 已做：
    - 双侧 `ConnectionIdentifier` 删 `id: u32` 字段，C ABI 24→20 字节
    - eBPF 端删 `connection_id()` 函数及其 FNV 常量
    - 4 处用户态单测 fixture 同步去掉 `id: N`
    - `cargo +nightly check -p caretta-ebpf --target bpfel-unknown-none` + `cargo test -p caretta`(56+ tests, 0 failed)
  - 余项：暂无
  - 注意：ABI 长度变了，运行版本升级时需重启 caretta（旧 BPF map 无法被新用户态读懂）

---

## 🟡 设计缺陷（运行 OK 但抗压差或语义不严）

- [x] **A. `refresh_snapshot` 串行 9 个 list**
  - 位置：`caretta/src/resolver/k8s.rs::refresh_snapshot`
  - 原状：Pod / Service / Node / RS / Dep / SS / DS / Job / CronJob 顺序 `.list().await`
  - 已做：
    - 9 个 `Api<T>` handle 先全部建好,然后一次 `tokio::join!` 把 9 个 `.list()` 一并发出,等回包再串行处理 items
    - `ListParams::default()` 提到 join! 外绑成 `lp`,所有 list 共享同一个 `&lp`(否则跨 await 临时值会被释放,E0716)
    - 任一 list 失败整体 `?` 早退,旧快照不动——与改造前每条 `?` 的语义一致
    - 总时延从 sum(9 个 list) 降到 max(9 个 list);`refresh_lock` 持锁时间同步缩短
    - 处理阶段(owners_index → pods → services 的依赖串)仍保留串行,因为是纯内存操作、不在关键路径上
  - 余项：暂无

- [x] **B. DNS 同 IP 并发反查无 single-flight**
  - 位置：`caretta/src/resolver/dns.rs::resolve_name`
  - 原状：每 tick 大量重复 IP（同 ClusterIP / 同 LB / 同 Service 后端），并发 query 都 cache miss 都打 DNS；锁释放期间 check-then-insert 是 racy 的(A 的 Positive 可能被 B 的 Negative 覆盖,造成 60s 不可用)
  - 已做：
    - 加 `inflight: Mutex<HashMap<u32, Shared<BoxFuture<'static, Option<String>>>>>` 单飞表
    - LRU miss 之后先看 inflight:命中 → clone 同一 Shared future 共等结果;未命中 → 自建 Shared future 入表 + await,完成后从 inflight 摘掉再写 LRU
    - `resolver` 字段改 `Option<Arc<TokioAsyncResolver>>`,以便 `clone` 进 'static 的 BoxFuture
    - `reverse_lookup_with_timeout` 改名 `lookup_owned`,签名从 `&TokioAsyncResolver` 改成 `Arc<TokioAsyncResolver>`,future 即 'static
    - 毒化锁直接 `into_inner()` 复用 guard:inflight 语义本是"尽力去重",毒化无害。这一步顺手解了一个 trait 检查问题——`match self.inflight.lock() { Err(_) => ... await ... }` 即使 Err arm 用 `_` 也算隐式持有 PoisonError 内的 MutexGuard 跨 await,把外层 future 拽成 !Send,k8s.rs / static_resolver.rs 的 `resolve_ip` 全部编译失败
  - 余项：暂无

- [ ] **C. `tcp_states` 无硬性容量上限**
  - 位置：`caretta/src/main.rs` 主循环
  - 现状：`links` 有 `LINK_GC_TTL` + `enforce_max_links` 双保护；`tcp_states` 只有 `TCP_GC_MISSED_TICKS`（12 ticks）软 GC，无硬上限
  - 极端场景：50k conn/s × 12 ticks × 5s ≈ 3M 条目 × 2 个 `Workload` 深拷贝 → OOM
  - 建议：加 `MAX_TCP_STATES` 配置；超限按 missed_ticks 降序或优先淘汰已 CLOSED

- [ ] **D. `enforce_max_links` 每 tick 全量克隆 + 排序**
  - 位置：`caretta/src/main.rs::enforce_max_links`
  - 现状：`links.iter().map(|(link, state)| (link.clone(), state.last_active)).collect()` → 100k links × 4 个 String/link → 400k 次 String alloc + O(n log n) sort
  - 建议：`BinaryHeap` 维护最近 N 个最久未活跃；或 `links` 直接换 `BTreeMap<Instant, NetworkLink>` 索引

- [ ] **E. `link_label_values` / `tcp_label_values` 每条 link 14 个 String 分配**
  - 位置：`caretta/src/metrics.rs::link_label_values`
  - 现状：`link.client.name.clone()` 多次出现；`fnv_hash` 先 `to_string` 再 hash；`with_label_values` 还要 `iter().map(...).collect::<Vec<&str>>()`
  - 建议：hash 直接走 byte 序列；label_values 返回 `[Cow<str>; N]`；`with_label_values` 直接接 `[&str; N]`

- [ ] **F. HTTP server 1024 字节固定 buffer + `from_utf8_lossy` + 无 read timeout**
  - 位置：`caretta/src/http_server.rs::run_metrics_server`
  - 风险：长 query / 长 header 静默截断；非 UTF-8 替换为 U+FFFD 后 `starts_with` 行为怪异；慢客户端长占连接
  - 建议：buffer 满 → 414；`from_utf8` 严格 + 400；`tokio::time::timeout(5s, stream.read())`

- [ ] **G. DNS LRU + Negative 互相挤占**
  - 位置：`caretta/src/resolver/dns.rs::DnsCache`
  - 现状：LRU 不区分 Positive / Negative；一波失败 IP 把高价值 Positive entry 挤出
  - 建议：双层缓存（Positive 大池 / Negative 小池），或淘汰策略优先驱逐 Negative

- [ ] **H. `VMLINUX_BTF_PATH` 绕过统一配置系统**
  - 位置：`caretta/src/btf/lookup.rs::parse_sock_offsets`
  - 现状：函数内部 `std::env::var("VMLINUX_BTF_PATH")`，绕过 `Opt` / clap
  - 建议：进 `Opt` 加 `--vmlinux-btf-path` clap 参数 + env 覆盖；`parse_sock_offsets` 改成接 `&Path`

---

## 🟢 可读性 / 规范

- [ ] **K. main 主循环 ticker 分支体过长**
  - 位置：`caretta/src/main.rs`
  - 现状：单分支 200+ 行、8 个阶段（collect / resolve / merge / purge / produce-link / produce-tcp / gc-link / gc-tcp）挤在一起
  - 建议：拆成命名函数

- [ ] **L. `k8s.rs` 单文件 653 行**
  - 现状：watch / snapshot / owner / service / dns / debug 9 个职责挤一起
  - 建议：拆 `watch.rs` / `snapshot.rs` / `owner.rs` / `service.rs`

- [ ] **M. eBPF / 用户态结构体双侧定义无 ABI 校验**
  - 位置：`ConnectionThroughputStats` / `ConnectionIdentifier` / `CONNECTION_ROLE_*`
  - 建议：`static_assertions::assert_eq_size!` 或 build.rs 时校验

- [ ] **N. `fnv_hash` / `connection_id` 双侧实现**
  - 位置：eBPF + 用户态
  - 建议：抽到共享 crate 或加交叉注释

- [ ] **O. `caretta_links_observed` Counter 缺 `_total` 后缀**
  - 现状：违反 prometheus 命名约定
  - 注意：改名要同步所有 dashboard / alert，需权衡

- [ ] **P. role 维度 prometheus label 无白名单校验**
  - 现状：`role.to_string()` 接受任何 u32；非法 role 会污染 cardinality
  - 建议：入口验 `ROLE_CLIENT/SERVER` 白名单

- [ ] **Q. `OWNER_RESOLVE_KIND_ALLOWLIST` 空集合语义未文档化**
  - 现状：空字符串 → 空 HashSet，但"空 = 允许全部" vs "空 = 拒绝全部" 没文档
  - 建议：README 显式说明，代码加注释

- [ ] **R. `trace_owner_hierarchy` 深度 8 是 magic number**
  - 建议：抽成有名常量；用 cycle detection（visited set）替代硬限

- [x] **S. `resolve_int_size` 命名误导**
  - 现状：实际处理 INT/ENUM/STRUCT/UNION/PTR
  - 已做：随 #5 一并改名为 `resolve_field_size`

- [ ] **T. `still_dead_keys<K: Copy>` 不必要的 `Copy` bound**
  - 位置：`caretta/src/purge.rs`
  - 原因：`into_iter` 拿所有权
  - 建议：去掉 bound

---

## ⚪ 验证为 false positive（不再追踪，留底以防 reviewer 复述）

- `handle_link_metric` 的 Mutex ABBA 死锁——当前只有一个锁，不存在
- `last_active` 在 close 字节合并时刷新让 link 永不被 GC——这是 expected behavior，主循环注释已说明
- `connection_states.iter()` 持 RCU 锁阻塞 eBPF 程序——BPF map per-bucket spinlock 不会阻塞 update/delete
- 跨 CPU sendmsg/close race 让字节永久泄漏到 `CONNECTIONS`——`still_dead_keys` 复检 + `connections.get` 在 delete 阶段都能兜住
- hickory 800ms timeout 后后台 task 不被 cancel——hickory 已知设计限制，不是 caretta 自身 bug

---

## 修复优先级建议（仅参考）

| 优先级 | 项 | 估算 |
|---|---|---|
| P0 | #1（已处理）/ #5 / #6 | 各几十行 |
| P0 | #2（watch RV / 410 / 退避） | 一个集中改动 |
| P1 | #3（watch supervisor）/ #4（forget 错误分流） | 中等 |
| P1 | A（并发 list）/ B（single-flight DNS） | 中等，性能收益显著 |
| P2 | C / D / E（容量 / 排序 / String 分配） | 配置或重构 |
| P2 | F / H | 小 |
| P3 | K / L / M-T | 重构，逐步推 |
