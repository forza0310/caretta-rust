//! 反向 DNS 缓存:把 IPv4 → hostname 的解析挪到 LRU + 单次时延上限的异步路径上。

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use log::warn;
use lru::LruCache;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// PTR 反查在最坏情况下要走网络（DNS server 不响应、丢包等），因此在用户配置之外
// 再加一层短超时上限，避免单次解析挂得太久——即使发生在 hickory 内部的网络层。
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_millis(800);
const DNS_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, PartialEq, Eq)]
enum DnsCacheEntry {
    Positive(String),
    Negative {
        fallback: String,
        inserted_at: Instant,
    },
}

fn cached_name(entry: &DnsCacheEntry, now: Instant) -> Option<String> {
    match entry {
        DnsCacheEntry::Positive(host) => Some(host.clone()),
        DnsCacheEntry::Negative {
            fallback,
            inserted_at,
        } if now.duration_since(*inserted_at) < DNS_NEGATIVE_CACHE_TTL => Some(fallback.clone()),
        DnsCacheEntry::Negative { .. } => None,
    }
}

pub struct DnsCache {
    enabled: bool,
    cache: Mutex<LruCache<u32, DnsCacheEntry>>,
    // 用 hickory 的 async DNS 解析器替代 dns_lookup::lookup_addr。
    //
    // 改动动机：lookup_addr 会调 libc::getnameinfo，是同步阻塞调用——在 glibc DNS
    // 不响应的情况下，单次最多卡 ~15s（5s × 3 次重试），这段时间整个调用它的 OS
    // 线程被挂起。
    //
    // 在系统配置（resolv.conf 等）不可用时退化为 None，调用方走 IP 字符串 fallback。
    resolver: Option<TokioAsyncResolver>,
}

impl DnsCache {
    pub fn new(enabled: bool, cache_size: usize) -> Self {
        let cache_size = NonZeroUsize::new(cache_size.max(1)).expect("non-zero dns cache size");
        let resolver = if enabled {
            match Self::build_resolver() {
                Ok(r) => Some(r),
                Err(err) => {
                    warn!("hickory resolver init failed, falling back to IP literals: {err}");
                    None
                }
            }
        } else {
            None
        };
        Self {
            enabled,
            cache: Mutex::new(LruCache::new(cache_size)),
            resolver,
        }
    }

    /// 用系统 resolv.conf 构造 hickory 解析器；若读取失败则退回内置默认。
    fn build_resolver() -> anyhow::Result<TokioAsyncResolver> {
        let apply_overrides = |opts: &mut ResolverOpts| {
            // hickory 自身的 attempt 超时也调小一点，避免极端情况累计。
            opts.timeout = Duration::from_millis(500);
            // 让缓存层归 hickory 自己管（也有上层 LRU 兜底）。
            opts.cache_size = 0;
        };
        match hickory_resolver::system_conf::read_system_conf() {
            Ok((cfg, mut opts)) => {
                apply_overrides(&mut opts);
                Ok(TokioAsyncResolver::tokio(cfg, opts))
            }
            Err(err) => {
                warn!("system DNS config unavailable, using built-in defaults: {err}");
                let mut opts = ResolverOpts::default();
                apply_overrides(&mut opts);
                Ok(TokioAsyncResolver::tokio(ResolverConfig::default(), opts))
            }
        }
    }

    /// Resolve IPv4 to hostname with LRU caching, returning the IP string on miss/failure.
    ///
    /// 关键不变量：本函数永远不会让调用线程 OS 级阻塞。所有耗时操作（PTR 反查）
    /// 都通过 .await 让出 task。最坏时延受 DNS_LOOKUP_TIMEOUT 上限保护。
    pub async fn resolve_name(&self, ip: u32) -> String {
        let fallback = Ipv4Addr::from(ip).to_string();
        if !self.enabled {
            return fallback;
        }

        let now = Instant::now();
        if let Ok(mut cache) = self.cache.lock() {
            if let Some(entry) = cache.get(&ip) {
                if let Some(host) = cached_name(entry, now) {
                    return host;
                }
                cache.pop(&ip);
            }
        }

        let resolved = match &self.resolver {
            Some(resolver) => Self::reverse_lookup_with_timeout(resolver, ip).await,
            None => None,
        };
        let host = resolved.clone().unwrap_or_else(|| fallback.clone());

        // 失败也短暂写入负缓存，避免不可解析 IP 每个 tick 都打 DNS；但负缓存有 TTL，
        // DNS 恢复后最多 DNS_NEGATIVE_CACHE_TTL 后会重新尝试解析。
        if let Ok(mut cache) = self.cache.lock() {
            let entry = match resolved {
                Some(host) => DnsCacheEntry::Positive(host),
                None => DnsCacheEntry::Negative {
                    fallback: fallback.clone(),
                    inserted_at: now,
                },
            };
            cache.put(ip, entry);
        }

        host
    }

    /// 包一层超时，使最坏单次时延有界。返回 None 表示超时或 DNS 失败。
    async fn reverse_lookup_with_timeout(resolver: &TokioAsyncResolver, ip: u32) -> Option<String> {
        let addr = IpAddr::V4(Ipv4Addr::from(ip));
        let lookup = resolver.reverse_lookup(addr);
        match tokio::time::timeout(DNS_LOOKUP_TIMEOUT, lookup).await {
            Ok(Ok(response)) => response.iter().next().map(|name| {
                // PTR 记录通常带尾随点（"example.com."），剥掉以与原 lookup_addr 行为对齐。
                let s = name.to_utf8();
                s.strip_suffix('.').map(str::to_string).unwrap_or(s)
            }),
            Ok(Err(_)) => None,
            Err(_) => None, // timeout
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Confirms DNS layer is a no-op when disabled and keeps literal IP names.
    #[tokio::test]
    async fn should_return_ip_string_when_dns_cache_is_disabled() {
        let cache = DnsCache::new(false, 8);
        let ip = u32::from(Ipv4Addr::new(8, 8, 8, 8));

        let name = cache.resolve_name(ip).await;
        assert_eq!(name, "8.8.8.8");
    }

    #[test]
    fn should_use_fresh_negative_cache_but_expire_stale_one() {
        let now = Instant::now();
        let fresh = DnsCacheEntry::Negative {
            fallback: "1.2.3.4".to_string(),
            inserted_at: now - Duration::from_secs(59),
        };
        let stale = DnsCacheEntry::Negative {
            fallback: "1.2.3.4".to_string(),
            inserted_at: now - Duration::from_secs(60),
        };

        assert_eq!(cached_name(&fresh, now), Some("1.2.3.4".to_string()));
        assert_eq!(cached_name(&stale, now), None);
    }

    #[test]
    fn should_keep_positive_cache_without_negative_ttl() {
        let now = Instant::now();
        let entry = DnsCacheEntry::Positive("example.com".to_string());

        assert_eq!(cached_name(&entry, now), Some("example.com".to_string()));
        assert_eq!(
            cached_name(&entry, now + Duration::from_secs(3600)),
            Some("example.com".to_string())
        );
    }

    // Prevents regressions where invalid cache size could panic at construction time.
    #[tokio::test]
    async fn should_normalize_cache_size_when_configured_as_zero() {
        let cache = DnsCache::new(false, 0);
        let ip = u32::from(Ipv4Addr::new(127, 0, 0, 1));

        // The constructor should normalize invalid zero sizes instead of panicking.
        assert_eq!(cache.resolve_name(ip).await, "127.0.0.1");
    }
}
