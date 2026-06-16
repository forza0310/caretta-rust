//! caretta lib target —— 故意只暴露 zero-dep 的 `per_cpu` 模块。
//!
//! 主交付物是 `caretta` 二进制。lib 存在的唯一目的是让 integration tests 能直接
//! 调用纯逻辑函数而不是 grep 源码字符串。
//!
//! 关键决定:**只 re-export `per_cpu`**。types/resolver/metrics/btf 链着 kube +
//! k8s-openapi + hickory-resolver 全家桶,如果 lib 把它们也暴露出来,每个
//! integration test binary 都得跟这些重 crate 全量静态链接,link 时间从秒级
//! 飙到分钟级。`per_cpu` 没有任何外部依赖,放进 lib 不会拖累 link。

pub mod per_cpu;
