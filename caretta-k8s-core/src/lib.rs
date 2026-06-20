//! caretta 与单实例 K8s 控制面 collector 共享的 std 基础库。
//!
//! 这里只放"不依赖 caretta 网络探针语义、纯 K8s 客户端层面"的可复用件:
//!   - [`supervisor`]:panic-resilient 后台任务监督 + 退避抖动 sleep。
//!   - [`watch`]:带 RV 跟踪 / 410 re-list / 指数退避的通用 watch loop,
//!     副作用通过 [`watch::WatchObserver`] 注入,不绑定任何 caretta 类型或指标。
//!   - [`owner`]:Pod → ReplicaSet → Deployment owner 上卷的纯函数实现。
//!
//! 刻意不依赖 prometheus / aya:本 crate 要能被一个普通(非特权、无 eBPF)的
//! K8s API collector 直接复用。

pub mod owner;
pub mod supervisor;
pub mod watch;
