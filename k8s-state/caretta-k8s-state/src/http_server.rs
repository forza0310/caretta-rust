//! 最小异步 HTTP server,只暴露 Prometheus /metrics。改自 caretta 的同名模块,
//! 去掉了 resolver debug 端点。

use anyhow::Context as _;
use prometheus::Encoder;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};

/// 服务 /metrics 直到收到 shutdown 信号。
pub async fn run_metrics_server(
    addr: SocketAddr,
    endpoint: String,
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
                tokio::spawn(async move {
                    let mut req = [0u8; 1024];
                    let n = match stream.read(&mut req).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };

                    let first_line = String::from_utf8_lossy(&req[..n]);
                    let expected = format!("GET {endpoint} ");
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
