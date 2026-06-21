//! Minimal async HTTP server used for Prometheus and resolver debug endpoints.

use crate::resolver::IpResolver;
use anyhow::Context as _;
use prometheus::Encoder;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tokio::time::timeout;

/// 读完整请求行的上限。慢客户端(Slowloris:连上却迟迟不发完整请求)超时即弃连接,
/// 避免 spawn 出来的 task 永久挂在 read .await 上、攒占 task + fd。
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// 写响应的上限。对称兜住「连上却不读 response body」的慢速读取型 Slowloris,
/// 否则 write_all 会卡死同一个 task。
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// 单次请求读取缓冲区大小。只需容下请求行 + 少量 header(本服务只看请求行前缀),
/// 读满仍无法匹配已知路由即视为超长请求 → 414。
const REQUEST_BUFFER_SIZE: usize = 1024;

/// 请求路由判定结果——把"拿请求字节决定走哪条响应分支"从 I/O 里剥出来,便于单测。
#[derive(Debug, PartialEq, Eq)]
enum Route {
    Metrics,
    DebugSnapshot,
    NotFound,
    /// 请求行非法 UTF-8(RFC 7230 要求 ASCII)→ 400。
    BadRequest,
    /// buffer 读满仍没匹配到完整请求行,疑似超长 URI/header 被截断 → 414。
    UriTooLong,
}

/// 纯函数路由:只看读到的请求字节 + buffer 是否读满,不碰 I/O / resolver。
///
/// 用严格 `from_utf8` 而非 `from_utf8_lossy`:请求行按 RFC 是 ASCII,非法字节应当 400,
/// 而不是替换成 U+FFFD 后继续拿被污染的串做前缀匹配。
fn route_request(
    req: &[u8],
    buffer_full: bool,
    endpoint: &str,
    debug_resolver_enabled: bool,
    debug_resolver_endpoint: &str,
) -> Route {
    let first_line = match std::str::from_utf8(req) {
        Ok(s) => s,
        Err(_) => return Route::BadRequest,
    };

    if first_line.starts_with(&format!("GET {endpoint} ")) {
        Route::Metrics
    } else if debug_resolver_enabled
        && first_line.starts_with(&format!("GET {debug_resolver_endpoint} "))
    {
        Route::DebugSnapshot
    } else if buffer_full {
        Route::UriTooLong
    } else {
        Route::NotFound
    }
}

/// Serve /metrics and optional resolver debug endpoint until shutdown is signaled.
pub async fn run_metrics_server(
    addr: SocketAddr,
    endpoint: String,
    debug_resolver_enabled: bool,
    debug_resolver_endpoint: String,
    resolver: Arc<dyn IpResolver>,
    startup_tx: oneshot::Sender<anyhow::Result<()>>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = match TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind metrics server at {addr}"))
    {
        Ok(listener) => {
            let _ = startup_tx.send(Ok(()));
            listener
        }
        Err(e) => {
            let msg = e.to_string();
            let _ = startup_tx.send(Err(anyhow::anyhow!(msg)));
            return Err(e);
        }
    };

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (mut stream, _) = accepted?;
                let endpoint = endpoint.clone();
                let debug_resolver_endpoint = debug_resolver_endpoint.clone();
                let resolver = Arc::clone(&resolver);
                tokio::spawn(async move {
                    let mut req = [0u8; REQUEST_BUFFER_SIZE];
                    // 读请求行:超时 / 出错 / EOF(n==0)一律放弃连接。单次 read 不保证读到
                    // 完整请求行,但本服务只匹配短前缀,5s 内 Prometheus/curl 必发完。
                    let n = match timeout(REQUEST_READ_TIMEOUT, stream.read(&mut req)).await {
                        Ok(Ok(n)) if n > 0 => n,
                        _ => return,
                    };

                    let route = route_request(
                        &req[..n],
                        n == req.len(),
                        &endpoint,
                        debug_resolver_enabled,
                        &debug_resolver_endpoint,
                    );

                    let (status, body, content_type) = match route {
                        Route::Metrics => {
                            let encoder = prometheus::TextEncoder::new();
                            let mf = prometheus::gather();
                            let mut buffer = Vec::new();
                            if encoder.encode(&mf, &mut buffer).is_err() {
                                (
                                    "500 Internal Server Error",
                                    b"failed to encode metrics".to_vec(),
                                    String::from("text/plain"),
                                )
                            } else {
                                ("200 OK", buffer, encoder.format_type().to_string())
                            }
                        }
                        Route::DebugSnapshot => {
                            if let Some(snapshot) = resolver.debug_snapshot().await {
                                (
                                    "200 OK",
                                    snapshot.into_bytes(),
                                    String::from("application/json"),
                                )
                            } else {
                                (
                                    "503 Service Unavailable",
                                    b"resolver snapshot unavailable".to_vec(),
                                    String::from("text/plain"),
                                )
                            }
                        }
                        Route::NotFound => (
                            "404 Not Found",
                            b"not found".to_vec(),
                            String::from("text/plain"),
                        ),
                        Route::BadRequest => (
                            "400 Bad Request",
                            b"bad request".to_vec(),
                            String::from("text/plain"),
                        ),
                        Route::UriTooLong => (
                            "414 URI Too Long",
                            b"request line or headers too long".to_vec(),
                            String::from("text/plain"),
                        ),
                    };

                    let header = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );

                    // 写也包超时,与 read 对称。任一步超时/出错即弃连接。
                    if !matches!(
                        timeout(RESPONSE_WRITE_TIMEOUT, stream.write_all(header.as_bytes())).await,
                        Ok(Ok(()))
                    ) {
                        return;
                    }
                    let _ = timeout(RESPONSE_WRITE_TIMEOUT, stream.write_all(&body)).await;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EP: &str = "/metrics";
    const DBG: &str = "/debug/resolver";

    fn route(req: &str, buffer_full: bool, debug_enabled: bool) -> Route {
        route_request(req.as_bytes(), buffer_full, EP, debug_enabled, DBG)
    }

    #[test]
    fn matches_metrics_request_line() {
        assert_eq!(route("GET /metrics HTTP/1.1\r\n", false, false), Route::Metrics);
    }

    // 前缀必须带结尾空格:/metricsfoo 不应命中 /metrics。
    #[test]
    fn does_not_match_metrics_prefix_without_trailing_space() {
        assert_eq!(
            route("GET /metricsfoo HTTP/1.1\r\n", false, false),
            Route::NotFound
        );
    }

    #[test]
    fn matches_debug_snapshot_only_when_enabled() {
        assert_eq!(
            route("GET /debug/resolver HTTP/1.1\r\n", false, true),
            Route::DebugSnapshot
        );
        // 未启用时 debug 路径退化为普通未知路由 → 404。
        assert_eq!(
            route("GET /debug/resolver HTTP/1.1\r\n", false, false),
            Route::NotFound
        );
    }

    #[test]
    fn unknown_path_is_not_found() {
        assert_eq!(route("GET /nope HTTP/1.1\r\n", false, true), Route::NotFound);
    }

    // 非法 UTF-8 请求行 → 400,而不是 lossy 替换后继续路由。
    #[test]
    fn invalid_utf8_is_bad_request() {
        let bytes = [b'G', b'E', b'T', b' ', 0xff, 0xfe, b' '];
        assert_eq!(
            route_request(&bytes, false, EP, true, DBG),
            Route::BadRequest
        );
    }

    // buffer 读满且未匹配已知路由 → 414(疑似超长请求被截断)。
    #[test]
    fn full_buffer_without_match_is_uri_too_long() {
        assert_eq!(route("GET /some/long/path", true, false), Route::UriTooLong);
    }

    // 即使 buffer 读满,只要前缀匹配到合法路由,仍正常服务而非 414。
    #[test]
    fn full_buffer_still_routes_known_prefix() {
        assert_eq!(route("GET /metrics HTTP/1.1\r\n", true, false), Route::Metrics);
    }
}
