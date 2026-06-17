//! IP→Workload 解析器:把 caretta 看到的 4-tuple IP 映射成"是哪个工作负载"。
//!
//! ## 模块拆分
//!
//!   - [`dns`]:DnsCache——LRU + hickory async resolver,做反向 DNS,所有 .await
//!     都不会阻塞 OS 线程,单次最坏时延受内部 timeout 上限。被两种解析器复用。
//!   - [`static_resolver`]:[`StaticResolver`]——非 K8s 环境的退化解析器,所有 IP
//!     一律标 `kind=external`,name 取 DNS 反查结果或 IP 字符串。
//!   - [`k8s`]:[`K8sResolver`]——读 K8s API,通过 watch + 周期 refresh 维护 IP→Workload
//!     映射;读路径走 ArcSwap 无锁快照,fallback 命中时再走 DnsCache。
//!
//! 入口在 main.rs:`K8sResolver::try_new()` 失败 → fallback 到 `StaticResolver::new()`。

use crate::types::Workload;
use async_trait::async_trait;

mod dns;
mod k8s;
mod static_resolver;

pub use k8s::K8sResolver;
pub use static_resolver::StaticResolver;

/// trait 的方法不能直接 async fn(dyn Trait 不支持),用 async_trait 宏把它
/// 重写成返回 Pin<Box<dyn Future>> 的形式。trait object 兼容性保持。
#[async_trait]
pub trait IpResolver: Send + Sync {
    async fn resolve_ip(&self, ip: u32) -> Workload;
    async fn debug_snapshot(&self) -> Option<String> {
        None
    }
}
