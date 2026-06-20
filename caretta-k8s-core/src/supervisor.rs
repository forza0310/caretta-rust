//! Panic-resilient 后台任务监督与退避抖动 sleep。
//!
//! 从 caretta 的 K8s resolver 抽出:每个 detached `tokio::spawn` 闭包内 panic 一旦
//! unwind 出来,整个 task 会永久死亡且主流程不感知。`supervise` 把工厂闭包包在
//! `catch_unwind` 里,panic 与提前 return 都重启,配指数退避防止热循环。

use futures_util::FutureExt;
use log::{error, warn};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

/// 监督一个永不应返回的后台 future:它每次都由 `factory` 重新构造,panic 或提前
/// 返回都会被捕获并在退避后重启。`name` 仅用于日志区分。
///
/// 退避从 1s 起,每次重启翻倍,封顶 30s;不重置(返回/ panic 都视作异常)。
pub async fn supervise<F, Fut>(name: &'static str, factory: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = ()>,
{
    let mut backoff = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(30);

    loop {
        let fut = AssertUnwindSafe(factory()).catch_unwind();
        match fut.await {
            Ok(()) => {
                warn!("supervised task {name} returned cleanly, restarting");
            }
            Err(panic) => {
                error!("supervised task {name} panicked: {panic:?}, restarting");
            }
        }
        sleep_with_jitter(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// 给 sleep 加 ±50% 抖动:多条 watch × N 个节点同时反弹时,把它们打散到一个时间窗口
/// 里,避免 API server 刚恢复就被同步的 thundering herd 二次打挂。
///
/// 不引入 rand 依赖,用 SystemTime nanos 做廉价伪随机源——这个用途下不需要密码学强度,
/// 只需要"不同任务在同一秒内得到不同尾数"。
pub async fn sleep_with_jitter(base: Duration) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    // 0.5..=1.5, precision 1/1000
    let ratio = 0.5 + (nanos as f64 % 1000.0) / 1000.0;
    tokio::time::sleep(base.mul_f64(ratio)).await;
}
