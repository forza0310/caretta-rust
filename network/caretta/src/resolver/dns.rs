//! 反向 DNS 缓存:把 IPv4 → hostname 的解析挪到 LRU + 单次时延上限的异步路径上。

use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Shared};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use log::warn;
use lru::LruCache;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// PTR 反查在最坏情况下要走网络（DNS server 不响应、丢包等），因此在用户配置之外
// 再加一层短超时上限，避免单次解析挂得太久——即使发生在 hickory 内部的网络层。
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_millis(800);
const DNS_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);

// 单飞 future 的别名:Shared 让多个 awaiter 共享同一个 PTR 反查的结果。
// `BoxFuture<'static, _>` 是因为 Shared 要求被包裹的 future 是 'static + Clone-output——
// 通过 Arc<TokioAsyncResolver> 移交所有权满足 'static; Output 是 Option<String> 满足 Clone。
type LookupFuture = Shared<BoxFuture<'static, Option<String>>>;

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
    // 单飞表:同一 IP 在飞行期最多挂 1 个 PTR 查询;并发到来的 resolve_name
    // 直接 clone 同一个 Shared future 等同一份结果
    inflight: Mutex<HashMap<u32, LookupFuture>>,

    // 用 hickory 的 async DNS 解析器替代 dns_lookup::lookup_addr,避免线程刮起。
    //
    // 用 Arc 包是为了能被 clone 进 'static 的 Shared future——TokioAsyncResolver
    // 内部已经是 Arc-of-state,这层多一次 Arc::clone 只是 refcount inc,不复制状态。
    //
    // 在系统配置（resolv.conf 等）不可用时退化为 None，调用方走 IP 字符串 fallback。
    resolver: Option<Arc<TokioAsyncResolver>>,
}

impl DnsCache {
    pub fn new(enabled: bool, cache_size: usize) -> Self {
        let cache_size = NonZeroUsize::new(cache_size.max(1)).expect("non-zero dns cache size");
        let resolver = if enabled {
            match Self::build_resolver() {
                Ok(r) => Some(Arc::new(r)),
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
            inflight: Mutex::new(HashMap::new()),
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

        // 单飞:LRU miss 之后,先看 inflight 表——
        //   - 命中 → clone 同一个 Shared future,await 同一份结果
        //   - 未命中 → 自己造一个 Shared future 放进表,自己也拿一份 await
        // 真正打 DNS 的最多只有"首发 task",其余 awaiter 是零成本的等待。
        let resolved = match &self.resolver {
            Some(resolver) => {
                let fut = {
                    // Mutex 毒化时直接复用 PoisonError 里的 guard:inflight 表语义本就
                    // 是"尽力去重",HashMap 状态最多让某个 IP 多打一次 DNS,无害。
                    // 用 unwrap_or_else 是为了避免 `match`/`if let Err` 在 await 前隐式
                    // 持有 PoisonError(里面包着 MutexGuard),把整个外层 future 拽成 !Send。
                    let mut inflight = self
                        .inflight
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    if let Some(existing) = inflight.get(&ip) {
                        existing.clone()
                    } else {
                        let new = Self::lookup_owned(resolver.clone(), ip).boxed().shared();
                        inflight.insert(ip, new.clone());
                        new
                    }
                };
                let result = fut.await;
                // 完成后从 inflight 移除。多个 awaiter 都会执行到这里,remove 是幂等的——
                // 后到的 remove 看不到 entry 直接 None,不会重复释放或 panic。
                // 必须放在 await 之后:future ready 之前移除会让后到的并发 task 重打 DNS。
                self.inflight
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&ip);
                result
            }
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

    /// Owned 版本的反查 + 超时:接 `Arc<TokioAsyncResolver>` 而不是 borrow,
    /// 这样返回的 future 是 'static,可放进 `Shared`。
    async fn lookup_owned(resolver: Arc<TokioAsyncResolver>, ip: u32) -> Option<String> {
        let addr = IpAddr::V4(Ipv4Addr::from(ip));
        match tokio::time::timeout(DNS_LOOKUP_TIMEOUT, resolver.reverse_lookup(addr)).await {
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
