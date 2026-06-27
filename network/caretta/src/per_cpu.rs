//! Per-CPU 吞吐统计的 user-side 数据模型 + 聚合函数。

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct ConnectionThroughputStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    // 重传计数:tcp_retransmit_skb fentry 在内核里按 segs 累加。语义上与字节计数器同
    // 类——纯单调累加,跨 CPU 各自写自己副本,用户态求和。
    pub retransmits: u64,
}

/// 把一条连接在所有 CPU 上的副本聚合成一份累计快照。
///
/// `saturating_add` 保证 prometheus counter 永不倒退——单台机器累计到 16 EB 之前
/// 不会触发,但语义上必须是"饱和不绕回"。
pub fn aggregate_per_cpu_throughput<I>(per_cpu: I) -> ConnectionThroughputStats
where
    I: IntoIterator<Item = ConnectionThroughputStats>,
{
    per_cpu.into_iter().fold(
        ConnectionThroughputStats::default(),
        |mut acc, v| {
            acc.bytes_sent = acc.bytes_sent.saturating_add(v.bytes_sent);
            acc.bytes_received = acc.bytes_received.saturating_add(v.bytes_received);
            acc.retransmits = acc.retransmits.saturating_add(v.retransmits);
            acc
        },
    )
}
