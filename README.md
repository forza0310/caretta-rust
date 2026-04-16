代码里用的是 kube 客户端默认发现逻辑，所以凭据来源是下面两类之一：

- 集群外运行
会按优先级读取：
环境变量 KUBECONFIG 指向的文件
当前用户家目录下 .kube/config
- 集群内运行
会读取 Pod 的 ServiceAccount Token（挂载在 /var/run/secrets/kubernetes.io/serviceaccount）和集群 CA。

在非集群环境会自动回退为 external 解析；在集群内有 kube 凭据时会启用 K8sResolver。