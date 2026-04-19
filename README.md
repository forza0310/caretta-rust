# Caretta Rust

本项目是基于 Rust + aya + tokio 的 eBPF 网络探针实现，对齐 caretta-go 的核心能力，并保持 cargo run 可直接启动。

## 当前能力总览

- eBPF 采集
	- kprobe tcp_sendmsg: 统计 bytes_sent
	- kprobe tcp_cleanup_rbuf: 统计 bytes_received
	- tracepoint sock/inet_sock_set_state: 追踪连接状态变化
- 吞吐语义
	- 用户态链路吞吐采用 bytes_sent + bytes_received
- Kubernetes 解析
	- Pod/Service/Node 解析
	- owner 层级追溯: Pod -> ReplicaSet -> Deployment 等
	- watch 事件模型: 资源变更触发刷新，并有周期性全量刷新兜底
- 可观测性
	- Prometheus 指标端点
	- Resolver 调试端点

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
- CI 会先在 GitHub Actions 里编译 Rust 二进制，再用 Dockerfile 打包运行时镜像并推送到 GHCR。
- Dockerfile 只负责运行时环境配置和复制 `target/release/caretta`，不再执行源码编译。

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
- 如果你部署到 Kubernetes，建议用 Pod 发现或 ServiceMonitor 抓取这个端点
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
	- 作用: 开启或关闭 resolver 调试端点
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