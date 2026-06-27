# Caretta Rust

基于 **Rust + aya + tokio** 的 Kubernetes 可观测性探针。两个独立采集器、共享一份 K8s 客户端基础库,各自暴露 Prometheus 端点:

| 采集器 | 形态 | 端口 | 数据源 | 主指标 |
|---|---|---|---|---|
| **network/caretta** | 特权 DaemonSet (`hostNetwork`) | `7117` | eBPF (fentry + tp_btf) | `caretta_links_observed` / `caretta_tcp_states` / `caretta_tcp_retransmits_total` / `caretta_tcp_connection_lifetime_seconds` |
| **k8s-state/caretta-k8s-state** | 非特权单实例 Deployment | `7118` | K8s API (watch Events) | `caretta_k8s_events_total` |

两者共用 [crates/caretta-k8s-core](crates/caretta-k8s-core/) 里的 watch loop / owner 上卷 / 后台任务 supervisor,**部署形态与 RBAC 刻意分离**:eBPF 探针必须每个节点一份且特权,Events 采集器只需要一份且只 watch、不写。

---

## 架构

```
┌─────────────────────────────────────────────────────────────────────┐
│  network/caretta  (DaemonSet, 每节点一份)                            │
│                                                                     │
│   eBPF 内核态                          用户态 (tokio)                  │
│   ┌──────────────────────────┐         ┌─────────────────────────┐   │
│   │ fentry tcp_sendmsg       │ ──────► │ poll loop (默认 5s)       │   │
│   │   → bytes_sent           │  maps   │   ├─ Pass 1 同步收集     │   │
│   │ fentry tcp_cleanup_rbuf  │         │   ├─ Pass 2 resolver fan-out│ │
│   │   → bytes_received       │         │   ├─ to_purge 复检 + 删除   │ │
│   │ tp_btf inet_sock_set_state│        │   └─ link/tcp 表 GC      │   │
│   │   → 连接状态变化            │       │                          │   │
│   └──────────────────────────┘         │  IpResolver               │   │
│                                        │   ├─ K8sResolver (watch)  │   │
│   启动期:从 vmlinux BTF 解 sock        │   └─ StaticResolver (fallback)│ │
│   字段偏移 → SOCK_OFFSETS map         │                          │   │
│                                        │  /metrics  /debug/resolver│   │
│                                        └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  k8s-state/caretta-k8s-state  (Deployment, 单实例)                   │
│                                                                     │
│   watch Events ──► EventObserver ──► owner 上卷 ──► counter delta    │
│        │                              ↑                              │
│        └─ 周期重建 owners_index ──────┘                              │
│                                                                     │
│   /metrics  (CounterVec by namespace/type/reason/workload)           │
└─────────────────────────────────────────────────────────────────────┘
```

### eBPF 侧 (`network/caretta-ebpf`)

四个 program,内核 ≥ 5.5 用 BTF-typed hook,不依赖 kprobe + offset 硬编码:

- **`fentry tcp_sendmsg`** —— 每次发包累加 `bytes_sent` 到 PerCpu map
- **`fentry tcp_cleanup_rbuf`** —— 收包累加 `bytes_received`(同 caretta-go,语义为「已消费」字节)
- **`fentry tcp_retransmit_skb`** —— 按 `segs` 累加 `retransmits` 到同一份 PerCpu 计数器
- **`tp_btf inet_sock_set_state`** —— TCP 状态机迁移,识别 client/server role,写 `CONNECTION_STATES`;同路径写 `CONNECTION_OPEN_TS` 起始戳,close 时算 `now - open_ts` 投递到 `CLOSED_LIFETIMES`

`bpf_probe_read_kernel` 用的 `sock_common` 字段 byte offset 在**用户态启动期**从 `/sys/kernel/btf/vmlinux` 解出来塞到 `SOCK_OFFSETS` map,内核改 ABI 时启动就 fail——不再有 kernel-version-specific 硬编码。

### 用户态主循环 (`network/caretta`)

每 tick (默认 5s) 全量扫一遍 eBPF map:

1. **Pass 1** 同步遍历 `CONNECTION_STATES`,聚合 PerCpu 吞吐、收集 to_delete 候选、过滤 loopback。
2. **Pass 2** 用 `futures_util::join_all` 把 IP → Workload 解析并发 fan-out(每条连接两次 resolver 调用)。
3. **to_purge 复检**——`iter()` 与 `remove()` 之间存在 race(4-tuple+pid 可能被新连接复用),`still_dead_keys` 再读一次 `CONNECTION_STATES` 把已复用的 key 过滤掉。
4. **link / tcp 表 GC**:
   - `LinkTable` —— `HashMap<NetworkLink, LinkState>` + 按 `last_active` 排序的 `BTreeMap` 二级索引;TTL 5min,从最旧端弹出。
   - `TcpTable` —— 同构,按 `last_seen_tick` 排序,12 tick 没见到就 forget。

二级索引让 GC + 硬上限淘汰从 O(n) 全表 scan 降到 O(被删条数)。

### IpResolver

```
K8sResolver (优先) ───► watch Pods/Services/Nodes + 周期 refresh
                      │
                      ├─ ArcSwap 无锁快照(读路径不持锁)
                      ├─ owner 上卷:Pod → ReplicaSet → Deployment → ...
                      │   按 allowlist + priority 挑最终归并目标
                      └─ K8s miss → DnsCache (LRU + hickory async)

StaticResolver (fallback) ───► 一律标 kind=external,name = 反向 DNS 或 IP
```

集群凭据不可用 / K8s API 不通时,自动退化到 `StaticResolver`——程序仍能跑,只是所有目标都标 `external`。

---

## 环境要求

- **内核 ≥ 5.5**(`BPF_PROG_TYPE_TRACING` 才支持 fentry / tp_btf,也是 `bpf_get_socket_cookie()` 的最低门槛——sock 复用 race 修复依赖它)
- **`CONFIG_DEBUG_INFO_BTF=y`**——5.5+ 主流发行版默认开
- **容器化部署**:把宿主机 `/sys/kernel/btf` 挂入容器(用于启动期解析 sock 字段偏移),见 [deploy/caretta.yaml](deploy/caretta.yaml)
- 仅 `network/caretta` 需要特权;`caretta-k8s-state` 普通 Pod 跑

---

## 运行

### 本机调试

```bash
# network 采集器(默认 7117,需要 root 加载 eBPF)
sudo -E cargo run -p caretta
# 或:已在 .cargo/config.toml 配 runner = sudo -E 时
cargo run -p caretta

# events 采集器(默认 7118,普通用户即可,只读 K8s API)
cargo run -p caretta-k8s-state
```

默认端点:

- **网络指标** —— http://127.0.0.1:7117/metrics
- **resolver 调试**(默认关闭) —— http://127.0.0.1:7117/debug/resolver
- **事件指标** —— http://127.0.0.1:7118/metrics

### Kubernetes 部署

完整模板在 [deploy/README.md](deploy/README.md)。最短路径:

```bash
kubectl apply -f deploy/caretta.yaml                              # 两个工作负载 + RBAC
kubectl apply -f deploy/caretta-grafana-dashboard-configmap.yaml  # Grafana sidecar 自动加载的 dashboard
```

DaemonSet 用 `hostNetwork: true`,每节点直接在 `NodeIP:7117` 暴露指标——不需要 Service。Events 采集器走 ClusterIP `:7118`。

---

## 暴露的指标

### `network/caretta` (7117)

| 指标 | 类型 | 含义 |
|---|---|---|
| `caretta_links_observed` | CounterVec | 自启动以来每条 link 的累计字节数 (`bytes_sent + bytes_received`)。labels: link/client/server 全套 + role |
| `caretta_tcp_retransmits_total` | CounterVec | 自启动以来每条 link 的累计重传段数(`tcp_retransmit_skb` 的 `segs` 累加),label 同 `caretta_links_observed` |
| `caretta_tcp_states` | GaugeVec | 当前观察到的 TCP 连接状态;label 同 link |
| `caretta_tcp_connection_lifetime_seconds` | HistogramVec | 连接 close 时一次性 observe 的生命周期(SYN_SENT/SYN_RECV → TCP_CLOSE),label 同 `caretta_tcp_states`;buckets 覆盖 1ms ~ 1000s |
| `caretta_polls_made` | IntCounter | 主循环 tick 数,健康度信号 |
| `caretta_ebpf_connections_map_size` | IntGauge | 本 tick `CONNECTION_STATES` 条目数 |
| `caretta_current_loopback_connections` | Gauge | 本 tick 被过滤的 loopback 连接数 |
| `caretta_failed_deletions` | IntCounter | 用户态删 eBPF map entry 失败计数 |
| `caretta_connection_deletions` | IntCounter | 用户态删 eBPF map entry 成功计数 |

`role` label 取值固定为 `1`(client)或 `2`(server),由 `inet_sock_set_state` 在 `SYN_SENT/SYN_RECV` 时分类。

### `caretta-k8s-state` (7118)

| 指标 | 类型 | 含义 |
|---|---|---|
| `caretta_k8s_events_total` | CounterVec | 自启动以来 K8s Events 总数,按 `(namespace, type, reason, workload_kind, workload_name)` 聚合 |
| `caretta_k8s_state_watch_last_active_unix_seconds` | GaugeVec | 每条 watch 最近一次活动时间戳(任何变更),给存活监控用 |

**注意**:`_events_total` 不含 event message 文本——是 counter 不是日志流。要原文事件流接 Loki / vector。

---

## 端点

### `/metrics`

两个采集器都暴露。标准 Prometheus 文本格式。

### `/debug/resolver` (仅 network/caretta,默认关闭)

返回当前 IP → Workload 解析快照(JSON)。**默认关闭**(K8s 清单里也默认关闭),用于排查:

- 为什么某条连接被标记为 `external`?
- owner 上卷是不是按预期跳到了 Deployment / Installation?

启用:

```bash
DEBUG_RESOLVER_ENABLED=true cargo run
curl -s http://127.0.0.1:7117/debug/resolver | head -n 40
```

HTTP server 自身硬化:读/写各 5s timeout(挡 Slowloris)、严格 UTF-8 请求行(非法 → 400)、buffer 满未匹配 → 414。

---

## 配置

**两个采集器共享同一套约定**:CLI flag 先 parse,环境变量再覆盖。任一无效的 env var 都会打 warn 并退回默认值,不会让程序起不来。

### `network/caretta`

| 环境变量 / CLI flag | 默认值 | 含义 |
|---|---|---|
| `PROMETHEUS_PORT` / `--prometheus-port` | `7117` | Prometheus 端点端口 |
| `PROMETHEUS_ENDPOINT` / `--prometheus-endpoint` | `/metrics` | Prometheus 路径 |
| `POLL_INTERVAL` / `--poll-interval` | `5` | 主循环 tick 间隔(秒) |
| `DEBUG_RESOLVER_ENABLED` / `--debug-resolver-enabled` | `false` | 是否开启 `/debug/resolver` |
| `DEBUG_RESOLVER_ENDPOINT` / `--debug-resolver-endpoint` | `/debug/resolver` | 调试端点路径 |
| `RESOLVE_DNS` / `--resolve-dns` | `true` | 对未命中 K8s 映射的 external IP 做反向 DNS |
| `DNS_CACHE_SIZE` / `--dns-cache-size` | `10000` | DNS LRU 缓存容量 |
| `MAX_LINKS` / `--max-links` | `100000` | link 状态表硬上限,超限按 `last_active` 淘汰最旧 |
| `MAX_TCP_STATES` / `--max-tcp-states` | `100000` | TCP 状态表硬上限,按 `last_seen_tick` 淘汰最 stale |
| `TRAVERSE_UP_HIERARCHY` / `--traverse-up-hierarchy` | `true` | 沿 owner 链上卷到更稳定的工作负载 |
| `OWNER_RESOLVE_KIND_ALLOWLIST` / `--owner-resolve-kind-allowlist` | (空) | CSV;限制可作为最终归并目标的 Kind。空 = 全放行 |
| `OWNER_KIND_PRIORITY` / `--owner-kind-priority` | (空) | CSV;链上有多候选时按此优先级挑;越靠前优先 |
| `VMLINUX_BTF_PATH` / `--vmlinux-btf-path` | `/sys/kernel/btf/vmlinux` | vmlinux BTF blob 路径,容器里挂到别处时用 |
| `KUBECONFIG` | — | 集群外运行时指定 kubeconfig;集群内自动用 ServiceAccount |

### `caretta-k8s-state`

| 环境变量 / CLI flag | 默认值 | 含义 |
|---|---|---|
| `PROMETHEUS_PORT` / `--prometheus-port` | `7118` | (刻意避开 7117,方便共存) |
| `PROMETHEUS_ENDPOINT` / `--prometheus-endpoint` | `/metrics` | |
| `REFRESH_INTERVAL` / `--refresh-interval` | `30` | `owners_index` 周期重建间隔(秒) |
| `TRAVERSE_UP_HIERARCHY` / `--traverse-up-hierarchy` | `true` | 同上 |
| `OWNER_RESOLVE_KIND_ALLOWLIST` / `--owner-resolve-kind-allowlist` | (空) | 同上 |
| `OWNER_KIND_PRIORITY` / `--owner-kind-priority` | (空) | 同上 |

### Owner 上卷示例

链路 `Pod → ReplicaSet → Deployment → Installation`,想最终归并到 Installation:

```bash
TRAVERSE_UP_HIERARCHY=true
OWNER_RESOLVE_KIND_ALLOWLIST=Deployment,StatefulSet,DaemonSet,Installation
OWNER_KIND_PRIORITY=Installation,Deployment,StatefulSet,DaemonSet
```

规则:`allowlist` 非空时只考虑列入的 Kind;在候选里挑 `priority` rank 最小者,同 rank 取链中更深(更靠根)的。空 allowlist = 全放行,取链尾(最远祖先)。

---

## Prometheus + Grafana 接入

### 抓取

DaemonSet 用 `hostNetwork=true`,每节点直接在 `NodeIP:7117` 暴露 `/metrics`,**不需要 ClusterIP Service**。建议:

- 抓取间隔与 `POLL_INTERVAL` 同量级(5~15s)
- 用 Pod/Node SD + relabel `keep` 自己的 app 标签

最小配置:

```yaml
scrape_configs:
  - job_name: caretta-rust
    metrics_path: /metrics
    scrape_interval: 5s
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        regex: caretta-rust
        action: keep
```

### Grafana

仓库自带 dashboard:[deploy/caretta-grafana-dashboard-configmap.yaml](deploy/caretta-grafana-dashboard-configmap.yaml)——含网络面板与 K8s 事件行,`kubectl apply` 后由 Grafana sidecar 自动加载。

快速验证:Explore 里查 `caretta_links_observed` 有数据 → 再看完整面板。

---

## 运行行为说明

- 有 kube 凭据 ⇒ `K8sResolver`,日志会打 `kubernetes resolver enabled`
- 无 kube 凭据或集群不可访问 ⇒ 退化到 `StaticResolver`,所有目标标 `external`
- 即使 `K8sResolver` 启用,external 仍会出现——真实外部流量或被过滤掉的回环

### 排障三步

1. 看日志:有没有 `kubernetes resolver enabled` 与 `eBPF programs attached: fentry tcp_sendmsg + fentry tcp_cleanup_rbuf + tp_btf inet_sock_set_state`?
2. `curl /metrics`:`caretta_links_observed` 是否有 sample?`caretta_polls_made` 是否在涨?
3. `DEBUG_RESOLVER_ENABLED=true` + `curl /debug/resolver`:目标 IP 的解析结果对不对?

---

## 项目结构

```
caretta/
├── network/
│   ├── caretta/          用户态二进制 (DaemonSet)
│   │   └── src/
│   │       ├── main.rs       orchestration:加载 eBPF、起 resolver/server、tick loop
│   │       ├── tables.rs     LinkTable / TcpTable(主存 + BTreeMap 二级索引)
│   │       ├── resolver/     K8sResolver / StaticResolver / DnsCache
│   │       ├── metrics.rs    所有 prometheus 指标 + label 构造 + forget
│   │       ├── http_server.rs Slowloris-hardened /metrics + /debug/resolver
│   │       ├── btf/          vmlinux BTF 解析(sock_common 字段偏移)
│   │       ├── purge.rs      to_delete race 复检闸门
│   │       └── types.rs      ABI 镜像结构体 + 编译期布局断言
│   └── caretta-ebpf/     eBPF 程序 (#![no_std])
├── k8s-state/
│   └── caretta-k8s-state/ Event 采集器二进制 (Deployment)
├── crates/
│   └── caretta-k8s-core/ 共享:watch loop / owner 上卷 / supervisor
└── deploy/               K8s 清单 + Grafana dashboard
```

`network/caretta/src/types.rs` 与 `network/caretta-ebpf/src/main.rs` 都有一组 `const _: () = { assert!(...) }` 编译期断言,把镜像结构体的 size / align / 字段 offset 钉死成同一组字面量——任一侧改字段,build 即 `E0080` 报错提示同步另一侧。
