代码里用的是 kube 客户端默认发现逻辑，所以凭据来源是下面两类之一：

- 集群外运行
会按优先级读取：
环境变量 KUBECONFIG 指向的文件
当前用户家目录下 .kube/config
- 集群内运行
会读取 Pod 的 ServiceAccount Token（挂载在 /var/run/secrets/kubernetes.io/serviceaccount）和集群 CA。

在非集群环境会自动回退为 external 解析；在集群内有 kube 凭据时会启用 K8sResolver。

## K8sResolver: owner层级追溯 + watch事件模型

为了更接近 caretta-go 的语义，当前 Rust 版包含两层能力：

- owner 层级追溯：
会先解析 Pod 的直接 owner（如 ReplicaSet），并继续沿 owner 链向上追溯（如 Deployment/StatefulSet/DaemonSet/Job/CronJob），
最终把链路归并到更稳定的工作负载实体上。

- watch 事件模型：
会对 Pod/Service/Node/ReplicaSet/Deployment/StatefulSet/DaemonSet/Job/CronJob 建立 watch。
当收到 Added/Modified/Deleted 事件时触发 resolver 快照刷新，同时保留周期性全量刷新作为兜底。

可通过下面变量控制层级追溯：

- TRAVERSE_UP_HIERARCHY=true|false（默认 true）

## bytes_received 说明

eBPF 侧已补齐 bytes_received：

- 发送方向：kprobe tcp_sendmsg 计入 bytes_sent
- 接收方向：kprobe tcp_cleanup_rbuf 计入 bytes_received

用户态链路吞吐默认使用 bytes_sent + bytes_received 的合计值，语义更接近 caretta-go 的连接吞吐视角。

## 调试端点 /debug/resolver

提供只读调试端点，返回当前 IP -> Workload 的解析快照（JSON），用于排查为什么某条连接是 external。

默认关闭，可通过下列方式启用：

- 环境变量：DEBUG_RESOLVER_ENABLED=true
- 可选自定义路径：DEBUG_RESOLVER_ENDPOINT=/debug/resolver（默认这个值）

示例：

```bash
DEBUG_RESOLVER_ENABLED=true cargo run
curl http://127.0.0.1:7117/debug/resolver
```

禁用方式：

- 不设置 DEBUG_RESOLVER_ENABLED
- 或显式设置 DEBUG_RESOLVER_ENABLED=false