# 微服务运维系统异常检测设计（基于实际数据字段）

> 数据源：caretta-rust 本项目（eBPF 拓扑+流量+K8s 事件）+ signoz-otel-collector（logs / traces / metrics）
> 原则：不上 LLM，机器学习 + 时序统计；优先小模型、单机可跑、依赖少。

---

## 一、实际可用的数据清单（基于代码核实）

### 1.1 caretta-rust 本项目输出（Prometheus only）

来源：[network/caretta/src/metrics.rs](../network/caretta/src/metrics.rs)、[k8s-state/caretta-k8s-state/src/metrics.rs](../k8s-state/caretta-k8s-state/src/metrics.rs)

#### `caretta_links_observed` — 拓扑边 + 累计字节（Counter）

14 个 label：

```
link_id, client_id, client_ip, client_name, client_namespace, client_kind, client_owner,
server_id, server_ip, server_port, server_name, server_namespace, server_kind,
role
```

**value**：自进程启动以来该链路双向字节数累计（send + recv，eBPF `tcp_sendmsg` + `tcp_cleanup_rbuf`）。

#### `caretta_tcp_states` — 连接状态（Gauge）

12 个 label（同上去掉 IP），value ∈ {1=OPEN, 2=ACCEPT, 3=CLOSED}。

#### `caretta_tcp_connection_lifetime_seconds` — 连接存活时长（Histogram）

label 与 `caretta_tcp_states` 同。一条连接 CLOSE 时 observe 一次 `close_ns - open_ns` 转秒;
bucket 从 1ms 跨到 ~1000s,可挑出超短(SYN 立刻 RST)/超长(连接池长存活)两端。

#### `caretta_tcp_retransmits_total` — 重传计数（Counter）

label 与 `caretta_links_observed` 同。eBPF fentry `tcp_retransmit_skb` 每次触发 +1,
用户态走 delta 上报;高重传率 = 链路丢包或拥塞窗口被打回。

#### `caretta_tcp_srtt_seconds` — 平滑 RTT 直方图(Histogram)

label 与 `caretta_tcp_states` 同。eBPF 在 `tcp_cleanup_rbuf` 路径上采样 `tp->srtt_us` 写入
快照,用户态收割时 observe 一次。bucket 100µs → 1.6s,kernel 端编码 us<<3 已折算为秒。

#### `caretta_tcp_segs_in_total` / `caretta_tcp_segs_out_total` — 收发包数(Counter)

label 与 `caretta_links_observed` 同。来源是 `tcp_sock.segs_in/out` 采样,做 delta 上报。
配合字节数可算包平均大小、配合 retransmits 可算重传率分母。

#### `caretta_k8s_events_total` — K8s 事件（Counter）

5 个 label：

```
namespace, type (Normal/Warning/Unknown),
reason (BackOff / Killing / Pulling / FailedCreate / SuccessfulMountVolume ...),
workload_kind, workload_name
```

#### 内部健康指标

`caretta_polls_made`、`caretta_ebpf_connections_map_size`、`caretta_k8s_watch_last_active_unix_seconds` 等 —— 用来监控采集器自身。

### 1.2 signoz-otel-collector 输出（ClickHouse）

- **traces**：service / operation / span kind / duration / status_code / http.status_code / 调用链关系
- **logs**：service / severity / body / 资源属性
- **metrics**：应用埋点（OTLP histogram/sum/gauge）

### 1.3 关键互补关系（这是设计的核心）

| 维度 | caretta（内核） | SigNoz（应用） |
|---|---|---|
| 拓扑 | ✅ 全量 ground truth（eBPF 看 socket，跑不掉） | ⚠️ 仅有埋点的服务才能看到 |
| L7 协议 | ❌ 无 | ✅ HTTP/gRPC 完整 |
| 字节数 | ✅ 精确 | ❌ 通常没有 |
| 收发包数 | ✅ 精确（tcp_sock 采样） | ❌ |
| 网络延迟 | ✅ smoothed RTT 直方图 | ❌（只有应用 span duration） |
| 应用延迟 | ❌ 无 | ✅ span duration |
| 重传 | ✅ tcp_retransmit_skb fentry 计数 | ❌ |
| 连接寿命 | ✅ open→close 直方图 | ❌ |
| 错误率 | ❌ 无 | ✅ status_code |
| K8s 事件 | ✅ 单独通道 | ❌ |
| TCP 状态变化 | ✅ Gauge OPEN/ACCEPT/CLOSED | ❌ |

**这给出了一个很有价值的组合**：caretta 提供"实际在通信的图"，SigNoz 提供"应用层语义"，K8s 事件提供"基础设施事件"。三者在时间轴上对齐就能做多模态异常检测和根因。

---

## 二、能检测什么 / 不能检测什么

### ✅ 用 caretta 数据能直接检测

1. **链路吞吐异常**：`rate(caretta_links_observed[5m])` 突增突减
2. **新链路出现**：从未观察过的 `(client_id, server_id, server_port)` 组合 → 安全/部署异常
3. **链路消失**：原本活跃的链路突然 rate=0 → 实例下线/网络分区
4. **拓扑结构变化**：服务调用图的边集变化、连通分量变化
5. **TCP 状态异常**：单位时间 CLOSED 比例飙升 → 连接被频繁拒绝/超时
6. **K8s 事件异常**：`Warning` 类事件突增、`BackOff/OOMKilled/FailedScheduling` 等关键 reason
7. **外部流量异常**：`client_kind=external` 或 `server_kind=external` 的字节量异常 → 数据外发/被扫描
8. **端口扫描**：单个 `client_id` 在短时间内连接到大量不同 `server_port`
9. **重传率突增**：`rate(caretta_tcp_retransmits_total) / rate(caretta_tcp_segs_out_total)` 抬升 → 链路拥塞或对端丢包；纯计数告警容易被高吞吐链路淹没,转成无量纲比率更稳
10. **网络层 RTT 劣化**：`histogram_quantile(0.95, caretta_tcp_srtt_seconds_bucket)` 抬升 → 链路 / 对端延迟变大,是"应用 P99 抖动到底是不是网络的锅"的关键判别证据
11. **连接寿命双峰漂移**：`caretta_tcp_connection_lifetime_seconds` 的 p50 骤降(短连接洪泛 / RST 风暴)或 p99 飙升(连接泄漏 / 长连接堆积);桶分布的 JS 散度比单一分位更早出信号
12. **小包风暴 / 心跳抖动**：`rate(segs_in+segs_out) / rate(links_observed)` 异常升高(包数涨字节没涨)→ ACK 风暴 / 频繁 keep-alive / 控制平面打架
13. **半双工写入异常**：`rate(segs_in) / rate(segs_out)` 严重失衡 → 对端 stall 或单向 stream 故障

### ✅ 用 SigNoz 数据能直接检测

- 应用错误率突增（HTTP 5xx / gRPC non-OK）
- P99 延迟劣化
- 日志错误模板突增
- 调用链结构异常

### ✅ 用三者融合能检测（最大价值）

- **L4 正常但 L7 异常**：caretta 显示链路字节正常，但 SigNoz 显示延迟飙升 → 计算/锁/GC 问题
- **L7 看不到的故障**：SigNoz 没埋点的服务/旁路服务通信，caretta 能看到
- **基础设施 vs 应用故障归因**：K8s OOMKilled 事件 + 该 workload 的 SigNoz 错误率上升 → 容量问题；K8s 无事件 + 错误率上升 → 应用 bug
- **依赖识别**：caretta 拓扑是 ground truth，可校验 SigNoz trace 是否完整（漏埋点检测）

### ❌ 用现有数据**做不到**的（不要白费力气）

- L7 协议解析 —— 完全没做（HTTP / gRPC 状态码 / 路径 / payload 必须从 SigNoz 拿）
- 应用层 latency —— srtt 只反映网络段（client→server ACK 时延），不含服务端处理时间
- 单 trace 维度的耗时 / 错误归因 —— caretta 是 socket 级聚合,没有 trace_id
- server 侧 retransmits / segs —— 受 eBPF 服务端 cookie 注册路径缺失影响,`caretta_tcp_retransmits_total` / `caretta_tcp_segs_*` 当前只有 `role=client` 行
- IPv6 链路 —— BTF 字段映射仍是 v4 only（TODO 范畴）

这些只能从 SigNoz 那侧拿,或留待后续扩展。

---

## 三、按数据通道的算法选型

### 3.1 caretta 流量异常（`caretta_links_observed`）

**特征工程**：每个 `(client_id, server_id, server_port)` 链路 → 一条时间序列（`irate` 或 `rate` 1m/5m）。

| 检测目标 | 算法 | 推荐实现 |
|---|---|---|
| 平稳链路的偏离 | 3-Sigma / MAD on rate | numpy / [PyOD](https://github.com/yzhao062/pyod) `MAD` |
| 周期链路的偏离 | STL 残差 → 3-Sigma | `statsmodels.tsa.MSTL` |
| 形态突变（吞吐 pattern 变化） | Matrix Profile | [STUMPY](https://github.com/TDAmeritrade/stumpy) |
| 多链路联合异常（服务级） | 把 server 维度所有链路打包 → Isolation Forest | [PyOD](https://github.com/yzhao062/pyod) `IForest` / `ECOD` |
| 高季节性 KPI | Donut (VAE) | [NetManAIOps/donut](https://github.com/NetManAIOps/donut) |

> **提示**：链路数量可能很大（O(服务²)），按 `client_owner / server_name` 聚合，控制时序条数。

### 3.2 caretta 拓扑结构异常

这是 caretta 数据独有的优势，**强烈推荐**。

| 检测目标 | 算法 | 实现 |
|---|---|---|
| 新边 / 消失边 | 滑动窗口集合差 | 纯 Python，networkx |
| 邻居集合变化 | 每个节点 in/out neighbors 的 Jaccard 距离 | networkx |
| 节点度异常 | 度序列上的 Z-score | numpy |
| 全图结构异常 | 图嵌入 + 距离 / 谱距离 | [PyGOD](https://github.com/pygod-team/pygod)（如需更高级） |
| 端口扫描类异常 | 每个 client 单位时间内独立 `server_port` 数 → 阈值 | promql + alertmanager 即可 |

**最简方案**：每 1 分钟从 Prometheus 拉 `rate(caretta_links_observed[5m]) > 0` 得到当前活跃图 → 用 networkx 算节点度、邻居集合 → 与历史 baseline 差异告警。这套 200 行代码搞定。

### 3.3 caretta TCP 状态异常（`caretta_tcp_states`）

按 `(server_name, server_namespace, server_port)` 聚合，统计 OPEN/ACCEPT/CLOSED 三种状态的计数和比例 → 转成时序：

- `closed_ratio = closed_count / total` —— 平稳时间序列，3-Sigma / EWMA
- `total_connections` —— 连接量本身的时序
- 突变检测可用 [ruptures](https://github.com/deepcharles/ruptures) 的 PELT/BinSeg

### 3.3a caretta 网络健康指标（重传 / RTT / 寿命 / 包数）

四个新指标共享同一聚合维度 `(client_owner, server_name, server_port)`,统一时序检测。核心思路是把"绝对计数"压成"无量纲比率",跨业务可对齐阈值,比纯计数更鲁棒。

**算法/库选型严格遵循开篇原则：不上 LLM、单机可跑、依赖最少**。下面列出来的全部是 §八 已有清单里的项,不引入新框架:

| 指标 | 派生量 | 检测算法 | 实现(库 / 函数) | 推荐窗口 |
|---|---|---|---|---|
| `caretta_tcp_retransmits_total` | `retx_ratio = rate(retransmits) / rate(segs_out)` | EWMA + 3-Sigma;突变用 PageHinkley | `pandas.Series.ewm` / [River](https://github.com/online-ml/river) `drift.PageHinkley` | 5m |
| `caretta_tcp_srtt_seconds` | `histogram_quantile(0.95, ...)` | STL 残差 + 3-Sigma | `statsmodels.tsa.STL` + numpy | 5m |
| `caretta_tcp_connection_lifetime_seconds` | p50 / p99 时序 + 桶分布 | 分位时序 3-Sigma;桶分布 Jensen-Shannon 漂移 | `scipy.spatial.distance.jensenshannon` + 3-Sigma on JS 距离 | 10m |
| `caretta_tcp_segs_*` | `pkt_per_byte = (segs_in+segs_out) / bytes`、`in_out_ratio = segs_in / segs_out` | 比值 3-Sigma;突变用 ruptures | numpy + [ruptures](https://github.com/deepcharles/ruptures) PELT | 5m |

**为什么是 Jensen-Shannon 而不是 KS / Wasserstein / PSI**：

- KS 检验对**已分桶**的直方图退化(精度受桶宽限制);
- Wasserstein 在 log 间距桶上语义更合理,但需要算 EMD,代价高于 JS;
- PSI 在金融 ABM 里常用,本质和 KL 类似但有约定阈值,对**对称、有界**的需求 JS 更合适;
- JS 距离 ∈ [0, √ln2],天然有界,直接喂给 3-Sigma 当流;scipy 一行实现,零新依赖。

**与拓扑联动**：把这四个指标值映射到 networkx 边权(高 retx_ratio / 高 srtt 边着红),与 §3.2 的拓扑变化检测共用同一张图 → §4 多模态融合时可以直接读边权,不需要二次查询。

**与 SigNoz 联动**：retx_ratio 和 srtt_p95 是 §4.3 根因排序里"网络锅 vs 应用锅"的关键判别证据(见下)。

**重量级备选(评估过未采用)**：

- [alibi-detect](https://github.com/SeldonIO/alibi-detect) v0.13.0 (2025-12) —— 算法最全(KS / CvM / Fisher / MMD / LSDD / Chi² / Online MMD ...),但**许可证是 BSL-1.1(Business Source License)非 OSI 开源**,商业用途有限制;且默认不装,TF / PyTorch / KeOps 作为 optional extras。学术或内部论文 demo 没问题,生产部署需 review 许可证。
- [evidently](https://github.com/evidentlyai/evidently) v0.7.21 (2026-03) —— 20+ 统计 / 距离指标(PSI / KS / Wasserstein / JS 等),活跃维护,Apache-2.0;但报告栈较重(pandas + plotly),如果只用单一 drift score 反而不如 scipy 直接。

scipy + River + ruptures(v1.1.10, 2025-09)这套组合在 §八 现有清单内,完全够用,目前没有迁移到 alibi-detect / evidently 的强诉求。

### 3.4 K8s 事件异常（`caretta_k8s_events_total`）

按 `(workload_name, reason)` 聚合 → 时序计数：

| 算法 | 用途 |
|---|---|
| 模板频次 + 3-Sigma | 通用突增检测 |
| 新组合首次出现 | `(workload, reason)` 之前没出现过 → 直接告警 |
| 关键 reason 硬规则 | `OOMKilled / CrashLoopBackOff / FailedScheduling / Evicted` 直接 1 次告警 |
| `type=Warning` 总量异常 | 每个 namespace 的 Warning rate STL 残差 |

这部分基本不需要 ML，PromQL + 规则就足够，但可以把"事件突增"作为其他模态告警的**强证据**（提高融合后告警的置信度）。

### 3.5 SigNoz 三模态

#### Metrics（应用 OTLP 指标）

| 算法 | 库 | 链接 |
|---|---|---|
| Isolation Forest / ECOD / COPOD | PyOD | [github.com/yzhao062/pyod](https://github.com/yzhao062/pyod) |
| AutoARIMA / AutoETS / MSTL | StatsForecast | [github.com/Nixtla/statsforecast](https://github.com/Nixtla/statsforecast) |
| 一站式预测+检测 | Darts | [github.com/unit8co/darts](https://github.com/unit8co/darts) |
| Matrix Profile | STUMPY | [github.com/TDAmeritrade/stumpy](https://github.com/TDAmeritrade/stumpy) |
| 预制 pipeline | Orion (MIT) | [github.com/sintel-dev/Orion](https://github.com/sintel-dev/Orion) |

#### Logs（SigNoz 日志通道）

| 工具 | 用途 | 链接 |
|---|---|---|
| Drain3 | 在线日志模板提取（业界标准） | [github.com/logpai/Drain3](https://github.com/logpai/Drain3) |
| Salesforce LogAI | 端到端日志分析，兼容 OTel 数据模型 | [github.com/salesforce/logai](https://github.com/salesforce/logai) |
| logparser | 30+ 解析算法 benchmark | [github.com/logpai/logparser](https://github.com/logpai/logparser) |
| deep-loglizer | DeepLog/LogAnomaly 等深度方法 | [github.com/logpai/deep-loglizer](https://github.com/logpai/deep-loglizer) |

落地建议：Drain3 抽模板 → 模板计数时序 → 复用 metric 检测器；ERROR 级模板和新模板首次出现做硬规则告警。

#### Traces（SigNoz trace 通道）

聚合成 `(service, operation, time_bucket)` → `p50/p99/error_rate/qps` 四条时序，复用 metric 检测器。这能覆盖 80% 场景。

更高阶（可选）：

- [NetManAIOps/TraceAnomaly](https://github.com/NetManAIOps/TraceAnomaly)（VAE，单 trace 异常）
- [IntelligentDDS/MicroRank](https://github.com/IntelligentDDS/MicroRank)（PageRank + 谱分析根因）

---

## 四、多模态融合：把 caretta 当骨架

caretta 的拓扑图是**地基**，所有融合都围绕它做：

### 4.1 数据模型

定义一个统一的"服务节点状态向量"（每分钟一份）：

```python
ServiceState(time_bucket, workload_name, workload_namespace) = {
    # —— 来自 caretta:拓扑 / 流量
    "inbound_bps":       sum(rate(caretta_links_observed{server_name=$})),
    "outbound_bps":      sum(rate(caretta_links_observed{client_name=$})),
    "in_degree":         count(distinct client_id where server_name=$),
    "out_degree":        count(distinct server_id where client_name=$),

    # —— 来自 caretta:网络健康(本轮新增,仅 role=client 视角)
    "srtt_p95":          histogram_quantile(0.95, caretta_tcp_srtt_seconds_bucket{client_name=$}),
    "retx_ratio":        rate(caretta_tcp_retransmits_total{client_name=$})
                         / rate(caretta_tcp_segs_out_total{client_name=$}),
    "lifetime_p50":      histogram_quantile(0.50, caretta_tcp_connection_lifetime_seconds_bucket{client_name=$}),
    "lifetime_p99":      histogram_quantile(0.99, caretta_tcp_connection_lifetime_seconds_bucket{client_name=$}),
    "pkt_per_byte":      (rate(segs_in)+rate(segs_out)) / rate(links_observed),
    "in_out_ratio":      rate(segs_in) / rate(segs_out),

    # —— 来自 caretta:连接状态 / K8s
    "tcp_closed_ratio":  caretta_tcp_states 聚合,
    "k8s_warning_rate":  rate(caretta_k8s_events_total{type=Warning, workload_name=$}),
    "k8s_critical_reasons": set(reasons命中关键集合),

    # —— 来自 SigNoz
    "p99_latency":       从 traces 聚合,
    "error_rate":        从 traces 聚合,
    "qps":               从 traces 聚合,
    "log_error_rate":    Drain3 模板计数,
}
```

这是一个**服务 × 时间**的多维时序矩阵，每个 cell 现在是 ~16 维向量（原 ~10 维 + 网络健康 6 维），多模态融合的判别力随之提升。

**网络健康字段的视角说明**：`srtt` / `retx` / `segs_*` 当前仅有 `role=client` 行，作为"该 workload 作为发起方时观察到的网络质量"使用。如果某 workload 主要以 server 身份出现（被调用方），用同名 client 视角字段做对偶聚合 fallback。

### 4.2 服务级异常打分

每个服务每分钟一个分数：

1. **单维度异常**：每个维度独立跑检测器（STL/3-Sigma/IForest），输出 0~1 异常分。
2. **联合异常**：所有维度拼向量 → [PyOD](https://github.com/yzhao062/pyod) `IForest/ECOD/COPOD` 给联合分。
3. **融合**：`max(独立分们) 与 联合分 加权` —— 推荐 `final = 0.6 * joint + 0.4 * max(individual)`。

### 4.3 根因排序（轻量版）

告警触发后，往前后各拉 10 分钟，对每个服务算异常分，按以下规则排序：

```
score(service) =
      异常分(service)
    × (1 + 0.3 × k8s_warning_或critical_命中)            # K8s 事件是强证据
    × (1 / (1 + service_出度_异常邻居数))                # 受影响节点越多，越像受害者
    × (1 + 上游异常邻居数 / 总上游)                       # 上游同时异常 → 自己更可能是源
    × (1 + 0.4 × 网络层证据)                              # retx_ratio / srtt_p95 同时异常 → 网络层归因
```

拓扑是从 caretta 实时拿的，不需要任何额外标注。

**网络层证据 = `1 if (retx_ratio 异常 ∨ srtt_p95 异常) else 0`**。引入这一项的目的是把"网络锅"和"应用锅"分开打分,这是 caretta-rust 在论文场景里相对纯 trace/log 链路追踪工具的核心增量:

| 应用层信号 | caretta 网络层信号 | 归因建议 |
|---|---|---|
| P99 延迟劣化 | srtt 平稳 + retx 平稳 | 应用侧:GC / 锁竞争 / DB 慢查询 |
| P99 延迟劣化 | srtt 同步抬高 | 网络侧:链路 / 对端 / 防火墙 |
| 错误率高 | retx_ratio 高 + lifetime_p50 骤降 | 大量 RST/超时,对端不可达或主动拒绝 |
| 错误率高 | 网络层正常 + log_error_rate 高 | 应用 bug / 配置错 |
| QPS 正常 | pkt_per_byte 飙升 | 小包风暴 / 心跳风暴(用 §3.3a 的 segs 派生量) |

这张表也是告警里"嫌疑服务证据卡片"的模板。

### 4.4 进阶（可选，按需上）

- **因果图**：[causal-learn](https://github.com/py-why/causal-learn) PC 算法，输入每个服务的时序，输出有向因果图；和 caretta 拓扑图取交集，置信度更高。
- **事件图根因**：[IntelligentDDS/Nezha](https://github.com/IntelligentDDS/Nezha) 思路，把 metric / log / trace / k8s_event 统一编码为事件，对比无故障期与故障期事件图模式。
- **历史故障复用**：[NetManAIOps/DejaVu](https://github.com/NetManAIOps/DejaVu)，给故障打标签后做相似度检索。

---

## 五、整体架构

```
┌──────────────────────────────────────────────────────────────────────┐
│  采集层                                                              │
│                                                                      │
│  caretta-rust (本项目)            signoz-otel-collector              │
│  ├─ caretta_links_observed         ├─ traces  ─┐                     │
│  ├─ caretta_tcp_states              ├─ logs    ├─► ClickHouse        │
│  ├─ caretta_tcp_retransmits_total   └─ metrics ┘                     │
│  ├─ caretta_tcp_srtt_seconds                                         │
│  ├─ caretta_tcp_segs_in/out_total                                    │
│  ├─ caretta_tcp_connection_lifetime_seconds                          │
│  └─ caretta_k8s_events_total                                         │
│        │                                          │                  │
│        ▼                                          ▼                  │
│  Prometheus (scrape)                       ClickHouse                │
└────────┬─────────────────────────────────────┬───────────────────────┘
         │                                     │
         └────────────────┬────────────────────┘
                          ▼
         ┌─────────────────────────────────┐
         │  检测服务 (Python / FastAPI)    │
         │                                 │
         │  ├─ 流量异常 (STL/IForest)      │
         │  ├─ 拓扑异常 (networkx)         │
         │  ├─ TCP 状态异常 (3-Sigma)      │
         │  ├─ 网络健康异常 (retx/srtt/    │
         │  │   lifetime/segs 派生比率)    │
         │  ├─ K8s 事件异常 (规则+模板)    │
         │  ├─ Trace 异常 (聚合时序)       │
         │  ├─ Log 异常 (Drain3+计数)      │
         │  └─ 多模态融合打分 + 根因排序   │
         │       (含"网络锅 vs 应用锅"判别)│
         └────────────────┬────────────────┘
                          ▼
              告警网关 (飞书/钉钉/Webhook)
```

---

## 六、落地路线图（修订版，对齐实际数据）

### Week 1：caretta 数据接入与基础告警

- [ ] FastAPI + `prometheus-api-client` 从 caretta 的 Prometheus 拉数据
- [ ] 对 `caretta_links_observed` 按 `(client_owner, server_name, server_port)` 聚合
- [ ] STL + 3-Sigma 出第一版链路异常告警
- [ ] 网络健康四指标基线（`retx_ratio` / `srtt_p95` / `lifetime_p50,p99` / `pkt_per_byte`）共用同一套 3-Sigma 框架
- [ ] K8s 关键 reason 硬规则告警（OOMKilled / CrashLoopBackOff / Evicted）

### Week 2：拓扑结构异常（**caretta 独有优势**）

- [ ] networkx 构建当前调用图
- [ ] 新边检测、消失边检测、节点度异常
- [ ] 周期对比（昨天同时段的拓扑 vs 现在）
- [ ] TCP CLOSED 比例异常
- [ ] 把网络健康指标值映射到边权（高 retx / 高 srtt 边着红），与拓扑变化共用一张图

### Week 3：SigNoz 三模态接入

- [ ] ClickHouse SQL 拉 trace 聚合（service/operation × 1min × p99/error_rate/qps）
- [ ] Drain3 解析日志模板
- [ ] 复用 Week 1 的检测器

### Week 4：服务级状态向量 + 联合异常

- [ ] 定义 `ServiceState` 数据结构
- [ ] PyOD `IForest/ECOD` 跑联合异常
- [ ] 各维度独立异常分聚合公式

### Week 5：根因排序

- [ ] 告警去重合并（同窗口）
- [ ] 基于 caretta 拓扑的服务级打分 + 排序
- [ ] 告警里附 Top-3 嫌疑服务和证据

### Week 6+（可选）

- [ ] 在线学习（[River](https://github.com/online-ml/river)）应对概念漂移
- [ ] 因果图增强根因
- [ ] Donut/OmniAnomaly 处理高季节性核心 KPI
- [ ] 故障复盘库（DejaVu 思路）

---

## 七、关键工程细节

### 7.1 时序基数控制

caretta 的 14 个 label 组合基数可能爆炸（每个 Pod IP 一条线）：

- 拉数据时主动按 `client_owner` / `server_name` 聚合，不要保留 `client_ip` 维度做长时存储
- Prometheus 端可以加 recording rules 预聚合

### 7.2 cumulative counter 处理

`caretta_links_observed` 是 Counter，进程重启会清零：

- 一律用 `rate()` / `irate()` 拿瞬时速率
- 不要拿原始 cumulative 值做绝对量比较

### 7.3 caretta 自身健康监控

`caretta_polls_made` 应该是单调递增的，停了说明采集挂了：

- 加 `absent()` / `increase` 监控告警
- 内核 5 系列 + eBPF 兼容性问题在 [TODO.md](../TODO.md) 提到过，要留意

### 7.4 外部流量分离

caretta 里 `client_kind=external` 和 `server_kind=external` 是反向 DNS 兜底结果：

- 这部分时序波动大、稳定性差，单独建检测器或单独阈值
- 关注 `server_kind=external` 突增（数据外发）作为安全监测

### 7.5 告警后处理

原始模型分数 → 告警一定要加：

- 滑动窗口去抖（连续 N 个点异常才告警）
- 最小持续时长
- 同时间窗内同 workload 的告警合并
- 这部分对召回率/准确率的影响经常比换模型还大

---

## 八、推荐库清单（验证过的最新维护状态）

### 时序异常 / 预测

| 库 | 维护状态 | 链接 |
|---|---|---|
| **PyOD** | ✅ 活跃，9.9k★，2026.06 v3.6.1 | [github.com/yzhao062/pyod](https://github.com/yzhao062/pyod) |
| **STUMPY** | ✅ 活跃，NumFOCUS 项目 | [github.com/TDAmeritrade/stumpy](https://github.com/TDAmeritrade/stumpy) |
| **Darts** | ✅ 活跃，v0.45（2026.06） | [github.com/unit8co/darts](https://github.com/unit8co/darts) |
| **StatsForecast** | ✅ 活跃，比 Prophet 快 500× | [github.com/Nixtla/statsforecast](https://github.com/Nixtla/statsforecast) |
| **Orion** | ✅ 活跃，MIT 出品 | [github.com/sintel-dev/Orion](https://github.com/sintel-dev/Orion) |
| **GluonTS** | ✅ 活跃，AWS，含 Chronos | [github.com/awslabs/gluonts](https://github.com/awslabs/gluonts) |
| **TODS** | ⚠️ 学术项目，更新慢 | [github.com/datamllab/tods](https://github.com/datamllab/tods) |
| **Merlion** | ❌ 已归档（2026.03） | [github.com/salesforce/Merlion](https://github.com/salesforce/Merlion) |
| **ADTK** | ❌ 2020 后停更 | [github.com/arundo/adtk](https://github.com/arundo/adtk) |

### 日志

- [Drain3](https://github.com/logpai/Drain3) —— 在线模板提取（业界标准，⚠️ 2022 后慢但稳定）
- [Salesforce LogAI](https://github.com/salesforce/logai) —— 端到端日志分析
- [Loglizer](https://github.com/logpai/loglizer) / [deep-loglizer](https://github.com/logpai/deep-loglizer) —— 经典/深度日志异常
- [logparser](https://github.com/logpai/logparser) —— 30+ 解析算法 benchmark

### Trace / 根因

- [NetManAIOps/TraceAnomaly](https://github.com/NetManAIOps/TraceAnomaly) —— ISSRE'20，VAE
- [NetManAIOps/TraceVAE](https://github.com/NetManAIOps/TraceVAE)
- [IntelligentDDS/MicroRank](https://github.com/IntelligentDDS/MicroRank) —— WWW'21，PageRank+谱分析
- [IntelligentDDS/Nezha](https://github.com/IntelligentDDS/Nezha) —— FSE'23，多模态融合 RCA
- [NetManAIOps/DejaVu](https://github.com/NetManAIOps/DejaVu) —— 历史故障复用
- [NetManAIOps/CIRCA](https://github.com/NetManAIOps/CIRCA) —— 因果图根因
- [NetManAIOps/PSqueeze](https://github.com/NetManAIOps/PSqueeze) —— 多维 KPI 根因定位

### 图 / 流式 / 因果

- [PyGOD](https://github.com/pygod-team/pygod) —— 图异常检测
- [River](https://github.com/online-ml/river) —— 在线学习 / 流式漂移检测(PageHinkley / ADWIN / KSWIN / HalfSpaceTrees)
- [causal-learn](https://github.com/py-why/causal-learn) —— 因果推断
- [ruptures](https://github.com/deepcharles/ruptures) —— 突变点检测
- [Bytewax](https://github.com/bytewax/bytewax) —— Python 流处理

### 数据集（用于训练/调参/benchmark）

- [LogHub](https://github.com/logpai/loghub) —— 多种系统日志
- [NetManAIOps KPI / 多维 / 故障数据集](https://github.com/NetManAIOps)
- [TrainTicket](https://github.com/FudanSELab/train-ticket) —— 微服务故障注入 benchmark
- [Online Boutique](https://github.com/GoogleCloudPlatform/microservices-demo) —— Google 微服务 demo

### 组织索引

- **logpai**（日志方向）：[github.com/logpai](https://github.com/logpai)
- **NetManAIOps**（清华 Netman Lab，AIOps 全栈）：[github.com/NetManAIOps](https://github.com/NetManAIOps)
- **IntelligentDDS**（微服务 RCA）：[github.com/IntelligentDDS](https://github.com/IntelligentDDS)
- **Awesome AIOps**：[github.com/linjinjin123/awesome-AIOps](https://github.com/linjinjin123/awesome-AIOps)

---

## 九、避坑清单

1. **不要追"最新论文模型"**：DeepLog/LogAnomaly/OmniAnomaly 在 benchmark 上漂亮，但实际系统里 STL+3σ + IForest 能解决 80% 问题、维护成本低 10×。
2. **不要重度依赖已停更的项目**：ADTK/Merlion 可读源码学思路，不要作为核心依赖。
3. **不要在 Java 里硬上 ML**：Smile/Tribuo/DJL 能跑，但库选择、调参资料、社区案例远远落后 Python。Java 只做采集+接告警。
4. **不要忽视后处理**：滑动窗口去抖、最小持续时长、告警合并，对最终效果影响巨大。
5. **不要跳过数据集验证**：用 LogHub / NetManAIOps KPI 跑一遍 pipeline，再上自家数据，能少走很多弯路。
6. **不要忽视 caretta 自身的局限**：没 L7、没应用层延迟、当前 `retx` / `segs_*` / `srtt` 仅 `role=client` 视角（server 出方向重传未统计）—— 这些场景靠 SigNoz 补齐。
