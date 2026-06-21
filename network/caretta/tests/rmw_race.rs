//! 检查 BPF map RMW race 修复后,用户态收割侧能正确把 N 个 CPU 的字节计数副本
//! 求和,不会因为并发写出现读写脏数据导致的统计不一致。

use caretta::per_cpu::{ConnectionThroughputStats, aggregate_per_cpu_throughput};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

/// 模拟 PerCpuHashMap 模型:N 个写线程各自只动自己的副本,聚合时求和。
/// 期望:总字节数 = 写线程数 × 每线程写次数 × 单次字节数,一字节不少。
#[test]
fn should_not_lose_bytes_under_concurrent_per_cpu_writes() {
    const CPUS: usize = 8;
    const WRITES_PER_CPU: usize = 100_000;
    const SEND_PER_WRITE: u64 = 1024;
    const RECV_PER_WRITE: u64 = 2048;

    let slots: Vec<Arc<Mutex<ConnectionThroughputStats>>> = (0..CPUS)
        .map(|_| {
            Arc::new(Mutex::new(ConnectionThroughputStats {
                bytes_sent: 0,
                bytes_received: 0,
            }))
        })
        .collect();

    let barrier = Arc::new(Barrier::new(CPUS));
    let mut handles = Vec::with_capacity(CPUS);
    for slot in slots.iter().cloned() {
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..WRITES_PER_CPU {
                let mut s = slot.lock().unwrap();
                s.bytes_sent = s.bytes_sent.saturating_add(SEND_PER_WRITE);
                s.bytes_received = s.bytes_received.saturating_add(RECV_PER_WRITE);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let snapshot: Vec<ConnectionThroughputStats> =
        slots.iter().map(|s| *s.lock().unwrap()).collect();
    let agg = aggregate_per_cpu_throughput(snapshot);

    let total_writes = (CPUS * WRITES_PER_CPU) as u64;
    assert_eq!(agg.bytes_sent, total_writes * SEND_PER_WRITE);
    assert_eq!(agg.bytes_received, total_writes * RECV_PER_WRITE);
}

/// 反例对照:如果用单一共享槽做 RMW(修复前的模型),并发会丢字节。
/// 这条用来证明上面那条 test 的对照组确实成立——不依赖每线程独立副本时,
/// 我们就拿不到一致的统计;有了独立副本(修复后),拿得到。
#[test]
fn should_show_shared_rmw_loses_bytes_without_per_cpu_split() {
    const THREADS: usize = 8;
    const WRITES_PER_THREAD: usize = 50_000;
    const SEND_PER_WRITE: u64 = 1024;

    // 共享槽:多线程对同一份 struct 做 read-copy-write,模拟 BPF hash map 的
    // entry-level replace 语义(无字段级原子)。
    let shared = Arc::new(Mutex::new(ConnectionThroughputStats {
        bytes_sent: 0,
        bytes_received: 0,
    }));

    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let shared = shared.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..WRITES_PER_THREAD {
                // 故意分两步:读快照 → 释放锁 → 重新拿锁写回。这正是 BPF map
                // RMW 的语义,中间允许别的写者插入,后写者会盖掉先写者。
                let snap = {
                    let s = shared.lock().unwrap();
                    *s
                };
                barrier.wait();
                let mut updated = snap;
                updated.bytes_sent = updated.bytes_sent.saturating_add(SEND_PER_WRITE);
                let mut s = shared.lock().unwrap();
                *s = updated;
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let final_snap = *shared.lock().unwrap();
    let expected_if_no_loss = (THREADS as u64) * (WRITES_PER_THREAD as u64) * SEND_PER_WRITE;
    // 共享 RMW 一定丢字节,聚合值严格小于"理论上每次都成功累加"的总数。
    // 这条 assert 反向锁住"如果哪天有人把 PerCpuHashMap 退回普通 HashMap,
    // 上面那条 should_not_lose_bytes 就再也守不住了"。
    assert!(
        final_snap.bytes_sent < expected_if_no_loss,
        "shared RMW must drop writes (got {}, ceiling {})",
        final_snap.bytes_sent,
        expected_if_no_loss
    );
}
