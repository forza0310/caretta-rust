# Caretta Rust

本项目是基于 Rust + aya + tokio 的 eBPF 网络探针实现，对齐 caretta-go 的核心能力，并保持 cargo run 可直接启动。

## 当前能力总览

- eBPF 采集
	- fentry tcp_sendmsg: 统计 bytes_sent
	- fentry tcp_cleanup_rbuf: 统计 bytes_received
	- tp_btf sock/inet_sock_set_state: 追踪连接状态变化
- 吞吐语义
	- 用户态链路吞吐采用 bytes_sent + bytes_received
- Kubernetes 解析
	- Pod/Service/Node 解析
	- owner 层级追溯: Service -> Pod -> ReplicaSet -> Deployment 等,可配置 allowlist + priority
	- watch 事件模型: 资源变更触发刷新，并有周期性全量刷新兜底
- 可观测性
	- Prometheus 指标端点
	- Resolver 调试端点

## 环境要求

- 内核版本 ≥ 5.5(fentry / tp_btf 需要 BPF_PROG_TYPE_TRACING)。该程序类型才能使用
  `bpf_get_socket_cookie()`,这是 sock 复用 race 修复的关键 helper。
- 内核启用 `CONFIG_DEBUG_INFO_BTF=y`,5.5+ 主流发行版默认开。
- 容器化部署需要把 host 的 `/sys/kernel/btf` 挂入容器(用于 vmlinux BTF 解析,见
  [deploy/caretta-rust-k8s.yaml](deploy/caretta-rust-k8s.yaml))。

## 运行方式

1. 在项目根目录运行:
	 sudo -E cargo run
2. 如果你在 .cargo/config.toml 中配置了 runner = sudo -E，也可直接运行:
	 cargo run

默认监听:

- 指标端点: http://127.0.0.1:7117/metrics
- 调试端点: 按环境变量控制，默认关闭

## 镜像构建与 GHCR 发布

仓库已提供：

- Dockerfile: [Dockerfile](Dockerfile)
- GitHub Actions: [.github/workflows/docker-publish.yml](.github/workflows/docker-publish.yml)

触发方式：

- push 到 master 分支
- push 版本 tag（例如 v0.1.0）
- 手动触发 workflow_dispatch

发布地址：

- ghcr.io/<owner>/<repo>

例如当前仓库通常会发布到：

- ghcr.io/forza0310/caretta-rust

注意：

- workflow 使用 GitHub 自带的 GITHUB_TOKEN 推送 ghcr，需要仓库允许 packages:write。
- CI 只负责调用 Docker build 并推送镜像到 GHCR；Rust 编译与 eBPF 构建都在 Dockerfile 的 builder 阶段完成。
- Dockerfile 使用 nightly + rust-src 构建，并在构建结束后只保留运行时镜像中的最终二进制。

## 端点说明

### 1) /metrics

- 用途: 导出 Prometheus 指标
- 典型检查:
	- curl -s http://127.0.0.1:7117/metrics | head

### 2) /debug/resolver

- 用途: 返回当前 IP -> Workload 的解析快照(JSON)
- 场景: 排查连接为何被标记为 external，或确认 owner 上卷是否生效
- 默认: 关闭

启用示例:

	DEBUG_RESOLVER_ENABLED=true cargo run
	curl -s http://127.0.0.1:7117/debug/resolver | head -n 40

## Grafana 接入

当前 Rust 版已经暴露了 Prometheus 兼容指标端点，可以直接接入 Grafana。最短路径是先让 Prometheus 抓取 /metrics，再让 Grafana 连接这个 Prometheus 数据源，最后导入 caretta 的 dashboard。

部署模板见 [deploy/README.md](deploy/README.md)。

### 1) 让 Prometheus 抓取本项目指标

- 指标端点默认是 http://127.0.0.1:7117/metrics
- 如果你部署到 Kubernetes 且使用当前 DaemonSet 清单（hostNetwork=true），每个节点会直接在 NodeIP:7117 暴露 /metrics
- Prometheus 建议使用基于 Pod/Node 的发现与 relabel 后按 NodeIP:7117 抓取，不需要 ClusterIP Service
- 抓取间隔建议与 poll interval 保持在同一量级，例如 5s 到 15s

一个最小 Prometheus scrape 配置示例：

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

### 2) 在 Grafana 中添加 Prometheus 数据源

- 数据源类型选择 Prometheus
- URL 指向你的 Prometheus 地址，例如 http://prometheus:9090
- 如果你已经有现成的 Grafana/Prometheus 组件，可以直接复用 caretta-go 的部署方式

### 3) 导入 dashboard

- 这份 Rust 版和 caretta-go 保持了核心指标名一致，主要包括 caretta_links_observed 和 caretta_tcp_states
- 可以直接参考 caretta-go/chart/dashboard.json 的面板定义，迁移时重点核对查询里的标签名是否与当前部署一致
- 如果你是想快速验证，先在 Grafana Explore 里查 caretta_links_observed，再逐步导入 node graph 和 throughput 面板

### 4) 排查建议

- 先确认 /metrics 有数据，再看 Prometheus Targets 是否是 Up
- 如果 Grafana 面板是空的，优先检查 job label、metrics_path 和 scrape_interval 是否匹配
- 如果看不到外部流量名称，确认 RESOLVE_DNS 是否开启，以及 DNS 解析是否成功

## 环境变量

### Kubernetes 凭据

- KUBECONFIG
	- 集群外运行时可指定 kubeconfig 路径
	- 未设置时，kube 客户端会尝试默认位置 ~/.kube/config
- 集群内运行
	- 自动使用 ServiceAccount Token 与集群 CA

### Resolver 行为

- RESOLVE_DNS
	- 可选值: true 或 false
	- 默认: true
	- 作用: 对未命中 K8s 映射的 external IP 做反向 DNS 解析
- DNS_CACHE_SIZE
	- 可选值: 正整数
	- 默认: 10000
	- 作用: LRU 缓存容量(缓存 external IP 到反向解析主机名)
- TRAVERSE_UP_HIERARCHY
	- 可选值: true 或 false
	- 默认: true
	- 作用: 是否沿 owner 链继续上卷到更稳定工作负载
- OWNER_RESOLVE_KIND_ALLOWLIST
	- 格式: 逗号分隔 Kind 列表
	- 默认: 空(表示不限制)
	- 作用: 限制哪些 Kind 可以作为最终归并目标
	- 示例: Deployment,StatefulSet,DaemonSet,Installation
- OWNER_KIND_PRIORITY
	- 格式: 逗号分隔 Kind 列表，越靠前优先级越高
	- 默认: 空(表示按 owner 链最高层目标归并)
	- 作用: 当 owner 链上存在多个候选 Kind 时，按优先级挑选最终归并目标
	- 示例: Installation,Deployment,StatefulSet,DaemonSet,Job,CronJob,ReplicaSet

Installation 场景示例:

	TRAVERSE_UP_HIERARCHY=true
	OWNER_RESOLVE_KIND_ALLOWLIST=Deployment,StatefulSet,DaemonSet,Installation
	OWNER_KIND_PRIORITY=Installation,Deployment,StatefulSet,DaemonSet

当链路为 Pod -> ReplicaSet -> Deployment -> Installation 时，最终会归并到 Installation。

external 回退行为:

- 当 RESOLVE_DNS=true 且解析成功时，external 名称会显示为反向 DNS 结果。
- 当 RESOLVE_DNS=false 或解析失败时，external 名称回退为原始 IP 字符串。

### 调试端点

- DEBUG_RESOLVER_ENABLED
	- 可选值: true 或 false
	- 默认: false
	- 作用: 开启或关闭 resolver 调试端点（K8s 清单默认关闭）
- DEBUG_RESOLVER_ENDPOINT
	- 默认: /debug/resolver
	- 作用: 自定义调试端点路径

## 运行行为说明

- 在有可用 kube 凭据时，启用 K8sResolver。
- 在无 kube 凭据或不可访问集群时，解析会回退为 external。
- 即使 K8sResolver 启用，external 仍可能出现(真实外部流量或回环流量)。

## 快速排障

1. 看程序日志，确认是否打印 kubernetes resolver enabled。
2. 访问 /metrics，确认有 caretta_links_observed 等指标。
3. 开启 DEBUG_RESOLVER_ENABLED 后访问调试端点，核对目标 IP 的解析结果。

## 对比 caretta go 原版的关键改进

下面按稳定性 / 安全性 / 鲁棒性 / 可观测性归类。

### 稳定性

- **sock 复用 race 修复**:caretta-go 的反查表 `sock_infos` 用 `struct sock *` 裸地址做 key,sock 被 free 后内核可能把同一片 slab 内存分给新连接 → 旧 close 与新 sendmsg 互相串扰,表现为同一条 link 出现两次或被错误标记 inactive。Rust 版改用 `bpf_get_socket_cookie()` (kernel ≥ 5.7) 做 key,cookie 一生一码、sock free 后不会复用,从根上消掉这条 race。

  注意:cookie helper 在 verifier 里按 program type 白名单注册,只在 BPF_PROG_TYPE_TRACING 系(fentry / fexit / tp_btf)可用,legacy kprobe / tracepoint 调用会被 verifier 拒绝(`unknown func bpf_get_socket_cookie#46`)。修这条 race 必然要把三个程序一起迁到 TRACING——见下一条。守卫见 [caretta/tests/review_regressions.rs](caretta/tests/review_regressions.rs) 的 `should_key_socket_reverse_map_by_cookie_not_raw_address`。

- **eBPF 程序类型现代化**:caretta-go 用 `BPF_PROG_TYPE_KPROBE` + `BPF_PROG_TYPE_TRACEPOINT`(legacy);Rust 版改成 `BPF_PROG_TYPE_TRACING`——`tcp_sendmsg`/`tcp_cleanup_rbuf` 走 fentry,`inet_sock_set_state` 走 tp_btf。收益:
  - 解锁 `bpf_get_socket_cookie()`,从根上修上面那条 race
  - BTF 类型化 args,不再写 `PT_REGS_PARM*` 寄存器猜参,签名跟内核函数原型一一对应
  - 解析对象从 `/sys/kernel/tracing/events/.../format` 文本换成 `/sys/kernel/btf/vmlinux` 二进制(标准化、不依赖 tracefs 挂载,任何 ≥ 5.5 内核都能跑)

  代价:tp_btf 拿不到 legacy tracepoint 那种"已经平铺好的 IP/端口字段",IP/端口要从 `struct sock *` 走 `bpf_probe_read_kernel` 读 sock_common——这就需要用户态在启动期解析 vmlinux BTF 拿字段偏移。caretta 内置了一个最小 BTF parser(只读 sock_common 一个 path,代码量约 200 行),不依赖 `btf` 第三方 crate。守卫见 [caretta/tests/review_regressions.rs](caretta/tests/review_regressions.rs) 的 `should_use_fentry_for_byte_accounting_probes`、`should_use_btf_tracepoint_for_state_transitions`、`should_resolve_sock_field_offsets_from_vmlinux_btf`。

- **close 路径 key 一致性修复**:caretta-go 的 close handler 在反查 `sock_infos` 失败时,会现场用 `id = get_unique_id(); pid = 0` 拼一个新的 conn_id 把它标记成 closed——这条新 key 跟开链时写入的 key 在 `(pid, id)` 两个维度上根本对不上,等于另起了一条只有 closed 状态的幽灵 entry,而原始 entry 永远停留在 active。Rust 版只走 cookie 反查,反查不到直接 `return` 不写;反查到的 key 严格用 open 路径插入的那一份,close 永远落到原始连接上(见 [caretta-ebpf/src/main.rs](caretta-ebpf/src/main.rs) `mark_connection_closed`,守卫 `should_use_socket_lookup_key_when_closing_connection`)。

- **to_delete 批量删除复用 race 修复**:caretta-go 的 `TracesPollingIteration` 在第一次 iter 时收集 `IsActive==0` 的 entry 到 `connectionsToDelete`(见 [caretta-go/pkg/caretta/links_tracer.go:107-109](caretta-go/pkg/caretta/links_tracer.go#L107-L109)),iter 跑完之后再循环 `deleteAndStoreConnection`(同文件 141-143)逐条 `Lookup → Delete`——这两个阶段之间的 eBPF 这一面会继续跑,同一片 4-tuple+pid 在 close 后被新连接复用、`is_active` 翻回 1 是常见路径(HTTP keep-alive、NAT 端口复用、SYN_RECV 撞同 pid)。`deleteAndStoreConnection` 里的 `Lookup` 只取出新一轮的 throughput,完全不复检 `IsActive`,接着 `Delete` 把活的新连接干掉,新连接的字节还被 `pastLinks[link] += throughput.BytesSent` 灌进**旧连接**的 link 身份里——active 表里少了一条新连接(后续这条流量永远进 unknown / loopback 路径),pastLinks 那条旧 link 字节凭空多出一截。Rust 版用户态把删除路径拆成两步:iter 阶段照常入 `to_delete`,batch remove 之前先过 [caretta::purge::still_dead_keys](caretta/src/purge.rs) 复检每个候选 key 在 `CONNECTION_STATES` 里仍是 0 才放行(见 [caretta/src/main.rs](caretta/src/main.rs) 的 `for conn in to_purge`),复用的 key 在窗口内已经被 eBPF 翻活,复检直接剔出候选——对应 commit `f3693c0` 把 `CONNECTION_STATES` 拆成共享表,正是为了让用户态能拿到逐 entry 的当前活性。守卫见 `should_filter_out_freshly_reused_key_to_avoid_deleting_active_connection`、`should_recheck_candidates_via_still_dead_keys_before_batch_remove`。注意:这只是把窗口从毫秒级压到微秒级,并没有原子化——真正要根除还得走 BPF `lookup_and_delete` 单条原子操作,目前内核 helper 在 hash map 上还没普遍可用。

- **prometheus series cardinality 泄漏修复**:caretta-go 的 `pastLinks` 是 `map[NetworkLink]uint64`,只增不删——每条短连接、每个 rolling update 换出来的 IP、每个外部 IP 都会在 prometheus 注册表里永久占一条 GaugeVec series,长跑必定膨胀,prometheus 自身 OOM。Rust 版用户态新开两张状态表(`links` / `tcp_states`,见 [caretta/src/main.rs:43-51](caretta/src/main.rs#L43-L51) 的 `LINK_GC_TTL` / `TCP_GC_MISSED_TICKS`),每个 tick 跑 `retain` GC,过期的同时调 `metrics::forget_link` / `forget_tcp` 把 prometheus series 和差分基准 `LAST_LINK_TOTALS` 一起清掉。link 与 produce/forget 路径共用 `link_label_values` / `tcp_label_values` 两个 helper(见 [caretta/src/metrics.rs](caretta/src/metrics.rs)),编译期保证 forget 的 label 集跟 produce 一致——否则 forget 找不到 series 等于没 forget。守卫见 `should_invoke_forget_helpers_during_poll_loop_gc`、`should_clear_prometheus_series_and_baseline_in_forget_helpers`、`should_share_label_construction_between_produce_and_forget_paths`。

- **watch 事件突发合并 + 周期性兜底**:caretta-go 的 watch 事件每条都即时改 snapshot,rolling update 时 API server 一秒打几百条修改进来,写者会把 CPU 顶到 100%。Rust 版 resolver 用 `mpsc::channel::<()>(1)` + `tx.try_send(())` 把所有 watch 事件合并成"有变更,得刷"信号(见 [caretta/src/resolver.rs](caretta/src/resolver.rs) `mpsc::channel::<()>(1)` 那段),刷一次相当于全量重建,丢信号无所谓。同时另起 30s 周期性 `refresh_snapshot` 兜底——caretta-go 没有这层兜底,watch 流默默丢一条 modify 就永久漂移。守卫见 `should_coalesce_refresh_signals_when_watch_events_burst`。

- **优雅关闭 + 启动信号**:caretta-go 的 `Stop()` 给通道发信号就 return,metrics server 用 `context.Background()` 关——server 卡住能挂到天荒地老,也不 join 不上报错。启动侧更糙:goroutine 起 metrics server 后直接 `time.Sleep(10s)`,端口已被占用就在 goroutine 里 `log.Fatalf`,主流程毫无察觉继续跑空采集。Rust 版 `signal::ctrl_c() → watch::channel(false)` 触发 shutdown,主 task 等 `metrics_task.await` 真正回收;启动期 `oneshot` 把 bind 成功/失败回报主 task,bind 失败直接 `Err(...)` 退,不存在"server 没起来还在收数据"的窗口(见 [caretta/src/main.rs:178-238](caretta/src/main.rs#L178-L238))。

- **TcpConnectionKey 与 state 解耦**:caretta-go 的 `TcpConnection` 自身把 `State` 嵌成字段,即便后期补 GC,拿来当 key 一条连接生命周期里 OPEN/ACCEPT/CLOSED 会拆出三条独立 entry,GC forget 一条剩两条泄漏。Rust 版 [`TcpConnectionKey`](caretta/src/types.rs) 显式去掉 `state`,同一条连接所有 state 折叠成一条 GC entry。守卫见 `tcp_key_should_be_state_independent`(在 [caretta/src/metrics.rs](caretta/src/metrics.rs) 的 tests 里)。

### 安全性

- **BTF 字段 size 启动期校验**:caretta-go 在 eBPF 端用 `bpf_core_read(&out, sizeof(out), &inet->inet_saddr)` 这种形态——sizeof 走的是用户结构体编译期常量,内核改了 `sock_common` 字段宽度时编译期不会知情,运行起来能读出半个 IPv6 地址塞到 `__be32` 里得到垃圾。Rust 版的 [`parse_sock_offsets`](caretta/src/types.rs) 把每个字段的期望 size 一并传给 [`read_struct_field_offsets`](caretta/src/btf.rs),BTF 解析时发现 `actual_size != expected_size` 直接启动 fail——内核 ABI 变了我们要在启动期看见,而不是把高字节吃进 IP 然后跑出垃圾数据。守卫见 [caretta/src/btf.rs](caretta/src/btf.rs) 的 `should_bail_when_field_size_changed`。

- **整数溢出兜底**:caretta-go 的字节累加 eBPF 端是 C 原生 `+=`、用户态是 Go 的 `currentLinks[link] += throughput.BytesSent`,`u64` 溢出 wrap 到一个小数,Counter 倒退会触发 prometheus reset,PromQL `rate()` 直接失真。Rust 版从 eBPF([caretta-ebpf/src/main.rs](caretta-ebpf/src/main.rs))到用户态([caretta/src/main.rs](caretta/src/main.rs))字节累加全走 `saturating_add`,溢出钳在 `u64::MAX`,Counter 单调性永远成立。

- **RBAC 最小权限**:caretta-go 的 ClusterRole 一口气授了 ~40 种资源,包括 `configmaps` / `endpoints` / `persistentvolumeclaims` / `serviceaccounts` / `pods/log` / `pods/status` / `bindings` / `events` / `replicationcontrollers` / `ingresses` / `networkpolicies` / `poddisruptionbudgets` / `endpointslices` / `metrics.k8s.io`——其中绝大多数 caretta 业务侧根本不用,纯历史遗产/防御性扩权。Rust 版 [deploy/caretta-rust-k8s.yaml](deploy/caretta-rust-k8s.yaml) ClusterRole 只有 9 种资源(pods/services/nodes + apps/batch 工作负载),全是 `get/list/watch`,DaemonSet 跑容器 escape 出来攻击面也只有这一小块。

- **BTF parser 显式守护**:caretta-go 整个 BTF 路径全外包 cilium/ebpf,版本升级语义偏移自己默默吃下去。Rust 版手写 ~200 行最小 parser([caretta/src/btf.rs](caretta/src/btf.rs)),磁盘上 10+ 单测覆盖魔数错误、struct 缺失、字段缺失、size 漂移、typedef 链、匿名 union/struct 嵌套展平,外加一个 `#[ignore]` 真实 vmlinux 烟雾测试。任何 BTF 路径回归都先在 CI 抓住。

### 鲁棒性

- **双向字节记账**:caretta-go 的 link throughput 只算 `BytesSent`(metric help 文本也写 "bytes_sent"),server 视角的入流量在仪表盘上整片消失。Rust 版用户态聚合走 `bytes_sent + bytes_received`(见 [caretta/src/main.rs:288](caretta/src/main.rs#L288)),metric help 文本同步改为 `total bytes transferred (bytes_sent + bytes_received) ...`,client/server 任一侧都能看到完整流量。守卫见 `should_aggregate_sent_and_received_bytes_in_userspace_poll_loop`、`should_describe_bidirectional_bytes_in_links_metric_help_text`。

- **接收记账 hook 改更精确的 `tcp_cleanup_rbuf`**:caretta-go 接收侧挂的是 `tcp_data_queue`,数据一进内核 receive queue 就计数,但应用如果在 read 之前就关连接,这部分根本没被消费——计入了但永远读不到,数值偏高。Rust 版改挂 `tcp_cleanup_rbuf`(数据真正从 queue 被用户态消费时),同时对负 `copied` 参数显式守护 `if copied <= 0 { return Ok(()); }`,异常 cleanup 不污染计数器。

- **DNS 反查改 hickory async + 超时 + 负缓存**:caretta-go 调 `net.LookupAddr(ip)`,走 glibc 同步实现,默认 3 次 × 5s = 最长阻塞 15 秒;失败的 IP 也不进缓存,下一次 metrics 抓取又来一遍。Rust 版用 hickory async resolver + 800ms timeout + 失败也写入 LRU(见 [caretta/src/resolver.rs](caretta/src/resolver.rs) 的 `DNS_LOOKUP_TIMEOUT` 与 `cache.put(ip, host)` 那段),不会把 tokio runtime 拉下水,坏 IP 也不会反复打 DNS。同时 cache 容量从 caretta-go 硬编码 `MAX_RESOLVED_DNS = 10000` 提为环境变量 `DNS_CACHE_SIZE` 可调。

- **Owner 上卷可配置(allowlist + priority)**:caretta-go 的 owner 解析就是沿链一路爬到顶,没法说"只归并到 Deployment、不要再上卷到 Installation"。Rust 版 [resolver.rs](caretta/src/resolver.rs) 的 `trace_owner_hierarchy` + `select_owner_from_chain` 接受两组环境变量:`OWNER_RESOLVE_KIND_ALLOWLIST` 把候选 Kind 收窄,`OWNER_KIND_PRIORITY` 在多候选时按优先级挑——业务侧迁移时不用改代码。

- **link_id 哈希抗碰撞**:caretta-go 的 link_id 算法 `fnvHash(client.Name+client.Namespace+server.Name+server.Namespace) + role` 有两个坑:`("ab","cd")` 和 `("a","bcd")` FNV 输入完全相同 → link_id 相同;`role` 简单加到 FNV 输出末尾只动最低位,同一对 endpoints 不同 role 算出几乎一样的 link_id。Rust 版改成名字段间用 `\x1f` 分隔 + role 乘以黄金比例常数 `0x9E3779B1` 后再 XOR(见 [caretta/src/metrics.rs](caretta/src/metrics.rs) `link_label_values`),拼接歧义和 role 同质碰撞都消掉。守卫见 `link_label_should_disambiguate_concatenated_names`、`link_id_should_diverge_across_roles`。

- **resolver 读路径无锁化**:caretta-go 走 `sync.Map` + 不安全的 `val.(Workload)` 类型断言,全文件多处类型断言失败 path,日志里偶尔会蹦 `type confusion in ipsMap`。Rust 版用 `ArcSwap<HashMap<u32, Workload>>`(见 [caretta/src/resolver.rs](caretta/src/resolver.rs) `ips: ArcSwap`),读路径就是 `self.ips.load()`——原子指针交换,要么拿到当前快照要么拿到上一个快照,永远不返回错误,也没有锁等待。

- **poll 间隔下限保护**:caretta-go 直接 `time.NewTicker(time.Duration(pollingIntervalSeconds) * time.Second)`,配置成 0 / 负数会得到无限频率 ticker,CPU 100%。Rust 版 `Duration::from_secs(opt.poll_interval.max(1))`(见 [caretta/src/main.rs:231](caretta/src/main.rs#L231))兜个最低 1s 的底,误配置不会把节点打爆。

- **eBPF map 迭代/删除错误显式上报**:caretta-go 的 `for entries.Next(&conn, &throughput)` 只返回 bool,迭代失败原因被吃掉。Rust 版每条 entry 单独 `match` 错误并 `warn!` 打日志、`mark_failed_connection_deletion` 累计指标(见 [caretta/src/main.rs:259-333](caretta/src/main.rs#L259-L333)),内核内存压力或 map 损坏在 metric 上立刻可见。

- **Service 上卷消重**:caretta-go 把 ClusterIP 直接打成 `kind: "Service"`,但 DNAT 只改 skb IP 头不回写 sock_common——biz 这一面 sock 永远拿到 ClusterIP,user 那一面 sock 拿到的是 user pod_ip。两端 sock 都被采到后,prometheus 上同一对 (biz Deployment) → (user Deployment) 的连接会变成两条 series:client 视角 `server_kind="Service"`、server 视角 `server_kind="Deployment"`,叠加 Rust 版的 `LINK_GC_TTL` series GC,grafana 拓扑面板上 user 节点 kind 时 Service 时 Deployment、value 来回跳。Rust 版 [resolver.rs](caretta/src/resolver.rs) `refresh_snapshot` 用 `svc.spec.selector` 反查同 namespace 已经过完 owner 上卷的 Pod,把 ClusterIP 直接 map 到 Pod 的 Workload(走完全相同的 `trace_owner_hierarchy` 链路 + 同样的 allowlist/priority 配置)——两端视角落到同一个 workload key,prometheus 单 series。无 selector / ExternalName / selector 暂时选不到 Pod 时退回 `kind=Service` 的原行为,无回归。守卫见 `should_resolve_clusterip_to_pod_workload_when_service_has_selector`。

### 可观测性

- **resolver 调试端点**:caretta-go 没有运行时观测 IP→Workload 解析结果的口子,排"为什么这条流量被打成 external" / "owner 上卷有没有生效"只能 grep 日志或猜。Rust 版默认关闭、可一开关打开 `/debug/resolver`(见 [caretta/src/http_server.rs](caretta/src/http_server.rs) + `DEBUG_RESOLVER_ENABLED` env),返回当前 IP→Workload 快照 + watch 事件计数 + 总条目数 JSON,运维直接 curl 看。

- **K8s 事件指标按事件类型拆分**:caretta-go 的 `watchEventsCounter` 只有 `object_type` 一个 label——风暴时只能看到 "pod 事件多",看不出是 add/modify/delete 哪一类。Rust 版 [`K8S_EVENTS_COUNT`](caretta/src/metrics.rs) 加了 `event_type` 维度(added / modified / deleted / bookmark),控制平面风暴起因可以直接在指标上读出来。