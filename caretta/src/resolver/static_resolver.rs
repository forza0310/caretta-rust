//! 用于不在 Kubernetes 环境中运行时退化使用的解析器:仅做 DNS 反查,所有 IP 一律
//! 标记为 `kind=external` 的 workload。

use async_trait::async_trait;

use super::IpResolver;
use super::dns::DnsCache;
use crate::types::Workload;

pub struct StaticResolver {
    dns_cache: DnsCache,
}

impl StaticResolver {
    pub fn new(resolve_dns: bool, dns_cache_size: usize) -> Self {
        Self {
            dns_cache: DnsCache::new(resolve_dns, dns_cache_size),
        }
    }
}

#[async_trait]
impl IpResolver for StaticResolver {
    async fn resolve_ip(&self, ip: u32) -> Workload {
        Workload {
            name: self.dns_cache.resolve_name(ip).await,
            namespace: "external".to_string(),
            kind: "external".to_string(),
            owner: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // Verifies static resolver emits external identity when no cluster mapping exists.
    #[tokio::test]
    async fn should_fallback_to_external_identity_when_dns_is_disabled() {
        let resolver = StaticResolver::new(false, 8);
        let ip = u32::from(Ipv4Addr::new(1, 2, 3, 4));

        let workload = resolver.resolve_ip(ip).await;
        assert_eq!(workload.name, "1.2.3.4");
        assert_eq!(workload.namespace, "external");
        assert_eq!(workload.kind, "external");
    }
}
