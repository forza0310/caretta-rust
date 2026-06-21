//! K8s watch loop:RV 跟踪 / 410 re-list / 指数退避抖动 / Bookmark 心跳,
//! 外加 [`supervisor::supervise`] 的 panic 重启。
//!
//! "事件发生后做什么"通过 [`WatchObserver`] 注入。

use crate::supervisor::{sleep_with_jitter, supervise};
use futures_util::StreamExt;
use kube::api::{WatchEvent, WatchParams};
use kube::{Api, Client};
use log::warn;
use std::sync::Arc;
use std::time::Duration;

/// Added / Modified / Deleted 三类实际对象变更(不含 Bookmark 心跳)。
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
}

/// watch loop 的副作用注入点。所有方法都是 sync(无 `.await`):watch loop 自己
/// 负责 RV 跟踪、重连、退避,observer 只决定"看到一条事件后做什么"。
pub trait WatchObserver<K>: Send + Sync + 'static {
    /// 每条 Added / Modified / Deleted 事件回调一次(Bookmark 不触发)。
    fn on_change(&self, kind: ChangeKind, obj: &K);

    /// 任意流量(Added / Modified / Deleted / Bookmark 都算)都回调,证明这条 watch
    /// 还活着——给存活探测 / 心跳指标用。默认 no-op。
    fn on_active(&self, _watch_name: &'static str) {}
}

/// 起一条对 `K` 的 cluster-wide watch,跑在被 supervise 包裹的后台 task 里。
///
/// loop 行为:
///   - RV 跟踪:Added/Modified/Deleted 从 `o.meta().resource_version` 取,Bookmark
///     从 `b.metadata.resource_version` 取;初始空串等价 "0"(让 API server 用 cache
///     最新 RV 起手)。
///   - 410 GONE(`code == 410 || reason == "Expired"`):清空 RV 走 re-list;其余
///     错误保留 RV 让下一轮带着重连。
///   - 退避:1s 起,本轮消费过任何事件则重置,否则翻倍封顶 30s,每轮 sleep 带抖动。
pub fn spawn_watch<K, O>(client: Client, watch_name: &'static str, observer: Arc<O>)
where
    K: Clone
        + core::fmt::Debug
        + serde::de::DeserializeOwned
        + kube::Resource<DynamicType = ()>
        + Send
        + Sync
        + 'static,
    O: WatchObserver<K>,
{
    // 形如 "k8s:watch:pods",方便监督指标按 task label 区分各 watch 的重启率。
    let task_label: &'static str = Box::leak(format!("k8s:watch:{watch_name}").into_boxed_str());
    tokio::spawn(supervise(task_label, move || {
        let client = client.clone();
        let observer = Arc::clone(&observer);
        async move {
            let api: Api<K> = Api::all(client);
            // 当前 watch 锚定的 RV。空串等价于 "0",让 API server 用 cache 最新 RV 起手。
            // 410 GONE 触发时清空回 "0",相当于一次 re-list。
            let mut rv = String::new();
            // 指数退避 1s..30s。成功消费过任何事件就重置,反映 API server 已恢复。
            let mut backoff = Duration::from_secs(1);
            const MAX_BACKOFF: Duration = Duration::from_secs(30);

            loop {
                let watch_rv = if rv.is_empty() { "0" } else { rv.as_str() };
                let mut stream = match api.watch(&WatchParams::default(), watch_rv).await {
                    Ok(stream) => stream.boxed(),
                    Err(err) => {
                        warn!("failed to start watch for {watch_name}: {err}");
                        sleep_with_jitter(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        continue;
                    }
                };

                // 本轮 watch 是否消费过事件,用于决定 backoff 是重置还是继续累加。
                let mut got_event = false;
                while let Some(event) = stream.next().await {
                    match event {
                        Ok(WatchEvent::Added(o)) => {
                            if let Some(v) = o.meta().resource_version.as_ref() {
                                rv.clone_from(v);
                            }
                            observer.on_active(watch_name);
                            observer.on_change(ChangeKind::Added, &o);
                            got_event = true;
                        }
                        Ok(WatchEvent::Modified(o)) => {
                            if let Some(v) = o.meta().resource_version.as_ref() {
                                rv.clone_from(v);
                            }
                            observer.on_active(watch_name);
                            observer.on_change(ChangeKind::Modified, &o);
                            got_event = true;
                        }
                        Ok(WatchEvent::Deleted(o)) => {
                            if let Some(v) = o.meta().resource_version.as_ref() {
                                rv.clone_from(v);
                            }
                            observer.on_active(watch_name);
                            observer.on_change(ChangeKind::Deleted, &o);
                            got_event = true;
                        }
                        Ok(WatchEvent::Bookmark(b)) => {
                            // Bookmark 是 RV 心跳:冷资源也定期推一次,防止 etcd
                            // compaction 把当前 RV 抛弃造成下次重连 410。
                            // 刷新存活心跳——bookmark 在场就证明链路活着。
                            // 不触发 on_change,避免下游空跑。
                            rv.clone_from(&b.metadata.resource_version);
                            observer.on_active(watch_name);
                            got_event = true;
                        }
                        Ok(WatchEvent::Error(e)) => {
                            // 410 GONE: RV 太旧,丢了走 re-list 起手;其余错误保留 RV
                            // 让下一轮带着已有 RV 重连。
                            if e.code == 410 || e.reason == "Expired" {
                                warn!(
                                    "watch {watch_name} got 410 GONE (rv={}), restarting from 0",
                                    rv
                                );
                                rv.clear();
                            } else {
                                warn!("watch error event for {watch_name}: {:?}", e);
                            }
                            break;
                        }
                        Err(err) => {
                            warn!("watch stream error for {watch_name}: {err}");
                            break;
                        }
                    }
                }

                if got_event {
                    backoff = Duration::from_secs(1);
                } else {
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
                sleep_with_jitter(backoff).await;
            }
        }
    }));
}
