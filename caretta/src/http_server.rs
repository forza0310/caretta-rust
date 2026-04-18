//! Minimal async HTTP server used for Prometheus and resolver debug endpoints.

use crate::resolver::IpResolver;
use anyhow::Context as _;
use prometheus::Encoder;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

/// Serve /metrics and optional resolver debug endpoint until shutdown is signaled.
pub async fn run_metrics_server(
    addr: SocketAddr,
    endpoint: String,
    debug_resolver_enabled: bool,
    debug_resolver_endpoint: String,
    resolver: Arc<dyn IpResolver>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind metrics server at {addr}"))?;

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
                    let mut req = [0u8; 1024];
                    let n = match stream.read(&mut req).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };

                    let first_line = String::from_utf8_lossy(&req[..n]);
                    let expected = format!("GET {endpoint} ");
                    let debug_expected = format!("GET {debug_resolver_endpoint} ");
                    let (status, body, content_type) = if first_line.starts_with(&expected) {
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
                    } else if debug_resolver_enabled && first_line.starts_with(&debug_expected) {
                        if let Some(snapshot) = resolver.debug_snapshot() {
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
                    } else {
                        (
                            "404 Not Found",
                            b"not found".to_vec(),
                            String::from("text/plain"),
                        )
                    };

                    let header = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );

                    if stream.write_all(header.as_bytes()).await.is_err() {
                        return;
                    }
                    let _ = stream.write_all(&body).await;
                });
            }
        }
    }
}
