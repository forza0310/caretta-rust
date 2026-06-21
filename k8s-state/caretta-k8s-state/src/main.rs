//! caretta-k8s-state 入口:单实例 K8s 控制面 collector。
//!
//! 启动顺序:env_logger → 配置 → kube client → 初始刷新 owners 索引 → 起周期刷新 →
//! 起 Event watch → 起 metrics server → 等 ctrl_c 优雅退出。

mod config;
mod events;
mod http_server;
mod metrics;
mod owners;

use config::Opt;
use events::EventObserver;
use k8s_openapi::api::core::v1::Event;
use kube::Client;
use log::{info, warn};
use owners::OwnerIndex;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::signal;
use tokio::sync::{oneshot, watch};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let opt = Opt::from_env_and_args();

    let client = Client::try_default()
        .await
        .map_err(|e| anyhow::anyhow!("failed to build kube client: {e}"))?;
    info!("kube client initialized");

    // owners 索引:先同步刷一次,保证 watch 起来时就能解析(失败不致命,周期刷新会重试)。
    let owners = OwnerIndex::new(
        client.clone(),
        opt.traverse_up_hierarchy,
        opt.owner_kind_allowlist(),
        opt.owner_kind_priority(),
    );
    if let Err(e) = owners.refresh_once().await {
        warn!("initial owners index refresh failed, will retry on schedule: {e}");
    }
    owners
        .clone()
        .spawn_refresh(Duration::from_secs(opt.refresh_interval.max(1)));

    // Event watch:复用 caretta-k8s-core 的通用 watch loop。
    let observer = EventObserver::new(owners);
    caretta_k8s_core::watch::spawn_watch::<Event, _>(client, "events", observer);
    info!("event watch started");

    // metrics server。
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let metrics_addr = SocketAddr::from(([0, 0, 0, 0], opt.prometheus_port));
    let endpoint = opt.normalized_prometheus_endpoint();
    let (metrics_startup_tx, metrics_startup_rx) = oneshot::channel();
    let metrics_task = tokio::spawn(http_server::run_metrics_server(
        metrics_addr,
        endpoint.clone(),
        metrics_startup_tx,
        shutdown_rx,
    ));

    match metrics_startup_rx.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(e) => {
            return Err(anyhow::anyhow!("metrics server startup signal dropped: {e}"));
        }
    }
    info!("metrics server listening on {}{}", metrics_addr, endpoint);

    signal::ctrl_c().await?;
    info!("received shutdown signal");
    let _ = shutdown_tx.send(true);

    match metrics_task.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!("metrics server stopped with error: {e}"),
        Err(e) => warn!("metrics server task join error: {e}"),
    }

    Ok(())
}
