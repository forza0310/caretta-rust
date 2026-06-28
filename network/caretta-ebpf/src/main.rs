#![no_std]
#![no_main]

use aya_ebpf::bindings::{BPF_TCP_CLOSE, BPF_TCP_SYN_RECV, BPF_TCP_SYN_SENT};
use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid, bpf_get_socket_cookie, bpf_ktime_get_ns, bpf_probe_read_kernel,
};
use aya_ebpf::macros::{btf_tracepoint, fentry, map};
use aya_ebpf::maps::{HashMap, LruHashMap, PerCpuHashMap};
use aya_ebpf::programs::{BtfTracePointContext, FEntryContext};
use aya_log_ebpf::{error, warn};

const CONNECTION_ROLE_UNKNOWN: u32 = 0;
const CONNECTION_ROLE_CLIENT: u32 = 1;
const CONNECTION_ROLE_SERVER: u32 = 2;

#[repr(C)]
#[derive(Copy, Clone)]
// `struct sock_common` 关键字段在该内核 vmlinux BTF 里的 byte offset。
// 用户态在启动期解析 /sys/kernel/btf/vmlinux 写入,eBPF 端 bpf_probe_read_kernel
// 时按这些 offset 从 sock 指针读字段——这样不依赖任何 kernel-version-specific
// 硬编码,内核改 ABI 时启动就 fail。
//
// 字段语义:
//   skc_daddr_off      —— __be32,对端 IP(对 sk_common 而言是 "destination")
//   skc_rcv_saddr_off  —— __be32,本端 IP(实际接收/绑定地址)
//   skc_dport_off      —— __be16,对端 port(network byte order)
//   skc_num_off        —— u16,本端 port(host byte order,sk 内核就是原生序)
pub struct SockOffsets {
    pub skc_daddr_off: u32,
    pub skc_rcv_saddr_off: u32,
    pub skc_dport_off: u32,
    pub skc_num_off: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
// Raw 4-tuple extracted from the kernel socket struct.
pub struct ConnectionTuple {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
// Connection identity used as the userspace-visible map key.
// (tuple, role, pid) 已唯一标识一条连接 —— tuple 由 TCP 协议保证同时只有一条活跃,
// role 区分 loopback 同 host 通信时同 4-tuple 上的两个方向,pid 携带"哪个进程"语义。
pub struct ConnectionIdentifier {
    pub pid: u32,
    pub tuple: ConnectionTuple,
    pub role: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
// Per-connection counters tracked in eBPF maps.
//
// 都是单调累加计数器,跨 CPU 各自累加自己副本、用户态再求和——所以可以塞进
// PerCpuHashMap。retransmits 由 tcp_retransmit_skb fentry 在重传发生时 +1。
pub struct ConnectionThroughputStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub retransmits: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
// `struct tcp_sock` 关键采样字段相对 sk 指针的 byte offset。用户态启动期从
// vmlinux BTF 解出来写到 TCP_SOCK_OFFSETS map,eBPF 端按这些 offset 读 tcp_sock 字段。
//
// `struct sock *` 与 `struct tcp_sock *` 在 Linux 里同基址(tcp_sock 头部递归嵌入
// inet_connection_sock → inet_sock → sock),所以 BTF 解出的 tcp_sock 字段 bit_offset
// 直接当作相对 sk 指针的 byte offset。`_reserved` 预留给后续要补的采样字段。
pub struct TcpSockOffsets {
    pub srtt_us_off: u32,
    pub segs_in_off: u32,
    pub segs_out_off: u32,
    pub _reserved: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
// 每条连接最近一次观测到的 sock 采样型快照。cleanup_rbuf 路径 last-writer-wins
// 覆写一次,用户态在收割 CONNECTION_STATES 时 lookup 拿这一份快照投到对应指标。
//
// 不放 PerCpuHashMap 的理由:srtt 是 gauge / segs 是 kernel 内部计数器,跨 CPU 求和
// 没有意义,本就该 last-writer-wins。读写都走 BPF_MAP_LOOKUP/UPDATE_ELEM,内核 hashtab
// 的 bucket lock 保证读者看到完整 entry——不依赖单字段原子性,扩到多字段也成立。
pub struct SockSampleSnapshot {
    pub last_srtt_us: u32,
    pub last_segs_in: u32,
    pub last_segs_out: u32,
    pub _reserved: u32,
}

// ── ABI 契约:与用户态镜像结构体逐字节一致 ──────────────────────────────────
// 这几个结构体在 `network/caretta/src/types.rs`(SockOffsets/ConnectionTuple/
// ConnectionIdentifier)与 `per_cpu.rs`(ConnectionThroughputStats)里有完全相同
// 的定义。eBPF 端在内核里按这份布局写 map,用户态按那份布局读同一块字节——两侧
// 字段类型/顺序/对齐错一处就静默读到错位数据。
//
// 下面把 size / align / 每个字段 offset 钉死成同样的字面量,与用户态 types.rs 里的
// 同名断言一一对应。任一侧改字段都会在本侧编译期炸,提示同步另一侧。改这里的数字
// 前,务必同步 caretta/src/types.rs 的断言。
const _: () = {
    use core::mem::{align_of, offset_of, size_of};

    // ConnectionTuple: src_ip(u32) dst_ip(u32) src_port(u16) dst_port(u16)
    assert!(size_of::<ConnectionTuple>() == 12);
    assert!(align_of::<ConnectionTuple>() == 4);
    assert!(offset_of!(ConnectionTuple, src_ip) == 0);
    assert!(offset_of!(ConnectionTuple, dst_ip) == 4);
    assert!(offset_of!(ConnectionTuple, src_port) == 8);
    assert!(offset_of!(ConnectionTuple, dst_port) == 10);

    // ConnectionIdentifier: pid(u32) tuple(ConnectionTuple) role(u32)
    assert!(size_of::<ConnectionIdentifier>() == 20);
    assert!(align_of::<ConnectionIdentifier>() == 4);
    assert!(offset_of!(ConnectionIdentifier, pid) == 0);
    assert!(offset_of!(ConnectionIdentifier, tuple) == 4);
    assert!(offset_of!(ConnectionIdentifier, role) == 16);

    // ConnectionThroughputStats: bytes_sent(u64) bytes_received(u64) retransmits(u64)
    assert!(size_of::<ConnectionThroughputStats>() == 24);
    assert!(align_of::<ConnectionThroughputStats>() == 8);
    assert!(offset_of!(ConnectionThroughputStats, bytes_sent) == 0);
    assert!(offset_of!(ConnectionThroughputStats, bytes_received) == 8);
    assert!(offset_of!(ConnectionThroughputStats, retransmits) == 16);

    // SockOffsets: 4 × u32
    assert!(size_of::<SockOffsets>() == 16);
    assert!(align_of::<SockOffsets>() == 4);
    assert!(offset_of!(SockOffsets, skc_daddr_off) == 0);
    assert!(offset_of!(SockOffsets, skc_rcv_saddr_off) == 4);
    assert!(offset_of!(SockOffsets, skc_dport_off) == 8);
    assert!(offset_of!(SockOffsets, skc_num_off) == 12);

    // TcpSockOffsets: srtt_us_off + segs_in_off + segs_out_off + _reserved = 4 × u32
    assert!(size_of::<TcpSockOffsets>() == 16);
    assert!(align_of::<TcpSockOffsets>() == 4);
    assert!(offset_of!(TcpSockOffsets, srtt_us_off) == 0);
    assert!(offset_of!(TcpSockOffsets, segs_in_off) == 4);
    assert!(offset_of!(TcpSockOffsets, segs_out_off) == 8);

    // SockSampleSnapshot: last_srtt_us + last_segs_in + last_segs_out + _reserved = 4 × u32
    assert!(size_of::<SockSampleSnapshot>() == 16);
    assert!(align_of::<SockSampleSnapshot>() == 4);
    assert!(offset_of!(SockSampleSnapshot, last_srtt_us) == 0);
    assert!(offset_of!(SockSampleSnapshot, last_segs_in) == 4);
    assert!(offset_of!(SockSampleSnapshot, last_segs_out) == 8);

    // role 常量两侧必须同值(用户态:ROLE_CLIENT / ROLE_SERVER)。
    assert!(CONNECTION_ROLE_CLIENT == 1);
    assert!(CONNECTION_ROLE_SERVER == 2);
};

#[cfg(not(test))]
#[panic_handler] //#[panic_handler] is required to keep the compiler happy, although it is never used since we cannot panic.
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map]
// Primary per-connection store. Userspace iterates this map to read throughput
// for each observed TCP connection.
//
// PerCpuHashMap 给每个 CPU 一份独立的 ConnectionThroughputStats 实例:每条 sendmsg 调用
// 永远只写当前 CPU 的那份副本,写者之间物理上不重叠,无锁、无 race。
static CONNECTIONS: PerCpuHashMap<ConnectionIdentifier, ConnectionThroughputStats> =
    PerCpuHashMap::<ConnectionIdentifier, ConnectionThroughputStats>::with_max_entries(131072, 0);

#[map]
// 用普通 HashMap 而不是 PerCpuHashMap:状态字段是"全局事实"(socket 关了就是关了),
// 没有 per-CPU 维护副本的语义。
static CONNECTION_STATES: HashMap<ConnectionIdentifier, u64> =
    HashMap::<ConnectionIdentifier, u64>::with_max_entries(131072, 0);

#[map]
// sock cookie → 活跃连接 key 的反查表。
// cookie 在 sock 生命周期内分配一次、sock free 后不会复用。
//
// 用 LruHashMap 而不是 HashMap:目前只有 inet_sock_set_state(..., TCP_CLOSE) tp
// 触发 mark_connection_closed 删 cookie。但内核存在多条绕开这条 tp 直接释放 sock
// 的路径——
//   - SYN backlog 里 request_sock 被 inet_csk_reqsk_queue_drop 等直接淘汰
//   - 进程 kill / __sk_free 批量回收(OOM、滚动更新)
//   - 个别内核版本的 tcp_done / RST abort 路径
//   - request_sock 升格全 sock 的失败分支
// 这些路径上 cookie 没人删,如果用普通 HashMap 长期累积必然撑爆 131072。而 cookie
// 是用户态看不见的维度,没法像 CONNECTION_STATES 那样在用户态做 missed-tick GC
static SOCK_TO_CONNECTION: LruHashMap<u64, ConnectionIdentifier> =
    LruHashMap::<u64, ConnectionIdentifier>::with_max_entries(131072, 0);

#[map]
// Open 时间戳:open 路径写 bpf_ktime_get_ns(),close 路径取出来算 lifetime。
// 与 CONNECTION_STATES 同样的 key 体系——便于 mark_connection_closed 一把锁的逻辑里
// 一并清理,不引入新的身份维度。
static CONNECTION_OPEN_TS: HashMap<ConnectionIdentifier, u64> =
    HashMap::<ConnectionIdentifier, u64>::with_max_entries(131072, 0);

#[map]
// Close 时算出的连接 lifetime(纳秒)投递桶:eBPF 写,用户态每 tick 全量读+删。
// 单次投递语义——同一条连接关闭只产生一条记录,用户态收割后就抹掉,容量与
// CONNECTION_STATES 同阶,只在用户态收割比 close 风暴慢时才会撑爆。
static CLOSED_LIFETIMES: HashMap<ConnectionIdentifier, u64> =
    HashMap::<ConnectionIdentifier, u64>::with_max_entries(131072, 0);

#[map]
// Runtime-discovered sock_common field offsets. Userspace populates this once at startup
// after parsing /sys/kernel/btf/vmlinux,eBPF 端按这些 offset 读 sock 字段。
static SOCK_OFFSETS: HashMap<u32, SockOffsets> =
    HashMap::<u32, SockOffsets>::with_max_entries(1, 0);

#[map]
// 同 SOCK_OFFSETS 但解的是 tcp_sock 字段——cleanup_rbuf 路径按 srtt_us_off 取 RTT 采样。
// 单 entry,启动期 populate 一次,此后只读;缺失时 cleanup_rbuf 跳过 srtt 采样但不影响
// throughput 统计——容错降级,免得 BTF 解析 race 把基础指标也拖坏。
static TCP_SOCK_OFFSETS: HashMap<u32, TcpSockOffsets> =
    HashMap::<u32, TcpSockOffsets>::with_max_entries(1, 0);

#[map]
// 每条连接最近一次的 sock 采样快照(srtt_us / segs_in / segs_out)。cleanup_rbuf
// last-writer-wins 写入,用户态每 tick 在收割 CONNECTION_STATES 时 lookup → 分别
// 投到 srtt 直方图 / segs 计数器。max_entries 与 CONNECTION_STATES 同阶,close 路径
// 与用户态 GC 都会同步删,避免泄漏。
static SOCK_SAMPLES: HashMap<ConnectionIdentifier, SockSampleSnapshot> =
    HashMap::<ConnectionIdentifier, SockSampleSnapshot>::with_max_entries(131072, 0);

// fentry on tcp_sendmsg captures TCP write-side payload size.
#[fentry(function = "tcp_sendmsg")]
pub fn handle_tcp_sendmsg(ctx: FEntryContext) -> u32 {
    match try_handle_tcp_sendmsg(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

// fentry on tcp_cleanup_rbuf captures TCP read-side accounting.
#[fentry(function = "tcp_cleanup_rbuf")]
pub fn handle_tcp_cleanup_rbuf(ctx: FEntryContext) -> u32 {
    match try_handle_tcp_cleanup_rbuf(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

// fentry on tcp_retransmit_skb counts retransmissions per connection.
// kernel 原型: void tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
#[fentry(function = "tcp_retransmit_skb")]
pub fn handle_tcp_retransmit_skb(ctx: FEntryContext) -> u32 {
    match try_handle_tcp_retransmit_skb(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

// btf_tracepoint on sock/inet_sock_set_state — 同一个内核 hook,但程序类型从 legacy
// BPF_PROG_TYPE_TRACEPOINT 升级到 BPF_PROG_TYPE_TRACING,因此 cookie helper 可用。
// args: (struct sock *sk, int oldstate, int newstate, int family, u16 protocol, ...)
// 我们只读 sk 与 newstate;IP/端口从 sk 走 sock_common 字段。
#[btf_tracepoint(function = "inet_sock_set_state")]
pub fn handle_sock_set_state(ctx: BtfTracePointContext) -> u32 {
    match try_handle_sock_set_state(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[inline(always)]
fn sock_cookie(skaddr: u64) -> u64 {
    // bpf_get_socket_cookie(struct sock *) — 内核 ≥ 5.7 提供的 helper。
    // 返回 64-bit、单调递增、sock 生命周期内唯一、sock free 后不会复用的标识符
    // (即使下一次 alloc 拿到同一个 `struct sock *` 地址,cookie 也会是新值)。
    //
    // 0 表示 helper 在当前 program type 上不可用,或 sock 指针为空。调用方必须把 0
    // 当 "本次跳过" 处理,而不是当合法 key。
    unsafe { bpf_get_socket_cookie(skaddr as *mut core::ffi::c_void) }
}

#[inline(always)]
fn read_sock_field<T: Copy>(sk: u64, byte_off: u32) -> Option<T> {
    if sk == 0 {
        return None;
    }
    let src = (sk + byte_off as u64) as *const T;
    unsafe { bpf_probe_read_kernel(src) }.ok()
}

#[inline(always)]
fn mark_connection_closed(cookie: u64) {
    // close 路径必须复用 open 路径写下的那把 key——直接从 tuple/role 现拼一把
    // 可能落空,pid 等字段在 close 时未必和 open 时一致。
    if let Some(key) = unsafe { SOCK_TO_CONNECTION.get(&cookie) } {
        let key = *key;
        // 只动 CONNECTION_STATES。CONNECTIONS 是 PerCpuHashMap、专给字节累加用,
        // 状态字段不在那张表里,close 路径对它一字不动——这是 RMW race 修复的关键
        // 不变量,不能回退。
        let _ = CONNECTION_STATES.insert(&key, &0u64, 0);

        // lifetime 投递:open 时写入的时间戳还在就算 now - open,投到 CLOSED_LIFETIMES
        // 让用户态下一轮收割。算完一律抹掉 open_ts,避免 sock 复用时撞键。
        if let Some(open_ts) = unsafe { CONNECTION_OPEN_TS.get(&key) } {
            let lifetime_ns = unsafe { bpf_ktime_get_ns() }.saturating_sub(*open_ts);
            let _ = CLOSED_LIFETIMES.insert(&key, &lifetime_ns, 0);
        }
        let _ = CONNECTION_OPEN_TS.remove(&key);
        // sock 关闭后最后一次 srtt 采样也没意义了——同步抹掉避免 sock 复用时残留旧值。
        // best-effort:删失败影响仅是这条 sample 多活一会儿,不影响正确性。
        let _ = SOCK_SAMPLES.remove(&key);
    }

    let _ = SOCK_TO_CONNECTION.remove(&cookie);
}

fn try_handle_sock_set_state(ctx: &BtfTracePointContext) -> Result<(), i32> {
    // tp_btf 的 args 顺序固定:(sk, oldstate, newstate, family, protocol, ...)。
    let sk: *const core::ffi::c_void = ctx.arg(0);
    let newstate: i32 = ctx.arg(2);
    let sk_addr = sk as u64;

    let role = match newstate {
        state if state == BPF_TCP_SYN_SENT as i32 => CONNECTION_ROLE_CLIENT,
        state if state == BPF_TCP_SYN_RECV as i32 => CONNECTION_ROLE_SERVER,
        state if state == BPF_TCP_CLOSE as i32 => CONNECTION_ROLE_UNKNOWN,
        _ => CONNECTION_ROLE_UNKNOWN,
    };

    if newstate == BPF_TCP_CLOSE as i32 {
        // cookie→连接 key 的反查表保存了这条 sock 的活跃 key,close 时只用 cookie 就能找回,
        // 不必再用 tuple+role 现拼,避免拼错。
        // cookie 不会在 sock free/realloc 之间存活,所以即便 close 事件比 sock 复用慢一拍,
        // 拿到的 cookie 也已经属于新 sock,不会污染上一代的连接条目。
        let cookie = sock_cookie(sk_addr);
        if cookie == 0 {
            return Ok(());
        }
        mark_connection_closed(cookie);
        return Ok(());
    }

    if role == CONNECTION_ROLE_UNKNOWN {
        return Ok(());
    }

    let cookie = sock_cookie(sk_addr);
    if cookie == 0 {
        // 没有稳定身份就没法把后续 sendmsg/recvmsg 安全归到这条连接,直接跳过,
        // 避免不同 sock 一起在 cookie==0 上撞 key。
        return Ok(());
    }

    // 用户态启动期写入,此后只读;cookie==0 之外,SOCK_OFFSETS 缺失视为内核 BTF 解析未完成,
    // 直接跳过本条事件。
    let offsets_key = 0u32;
    let offsets = match unsafe { SOCK_OFFSETS.get(&offsets_key) } {
        Some(v) => *v,
        None => {
            // 边界事件:启动期 BTF 解析尚未完成的极短窗口里会命中,populate 之后永不发。
            // 如果 caretta 已经稳跑还在打这条,说明用户态 SOCK_OFFSETS 写入路径被破坏。
            warn!(ctx, "SOCK_OFFSETS not populated yet, skipping event");
            return Ok(());
        }
    };

    // sock_common 几个字段:
    //   skc_rcv_saddr (__be32) → 本端 IP,作为 src_ip
    //   skc_daddr     (__be32) → 对端 IP,作为 dst_ip
    //   skc_num       (u16,host order)   → 本端 port,作为 src_port
    //   skc_dport     (__be16,network order) → 对端 port,作为 dst_port
    let saddr_be: u32 = read_sock_field(sk_addr, offsets.skc_rcv_saddr_off).ok_or(1)?;
    let daddr_be: u32 = read_sock_field(sk_addr, offsets.skc_daddr_off).ok_or(1)?;
    let dport_be: u16 = read_sock_field(sk_addr, offsets.skc_dport_off).ok_or(1)?;
    let num: u16 = read_sock_field(sk_addr, offsets.skc_num_off).ok_or(1)?;

    let tuple = ConnectionTuple {
        src_ip: u32::from_be(saddr_be),
        dst_ip: u32::from_be(daddr_be),
        src_port: num,
        dst_port: u16::from_be(dport_be),
    };

    let key = ConnectionIdentifier {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        tuple,
        role,
    };

    // sock_set_state 路径只写 CONNECTION_STATES + SOCK_TO_CONNECTION,绝不动 CONNECTIONS。
    if let Err(e) = CONNECTION_STATES.insert(&key, &1u64, 0) {
        // 边界事件:131072 entries 撑爆,通常是 close 路径漏 cleanup 或者短连接风暴。
        // 用户态 GC 兜底,但出现这条说明 cleanup 跟不上、视图会丢新 link。
        warn!(ctx, "CONNECTION_STATES map insert failed: err={}", e);
        return Err(e);
    }
    if let Err(e) = SOCK_TO_CONNECTION.insert(&cookie, &key, 0) {
        error!(ctx, "SOCK_TO_CONNECTION insert failed unexpectedly: err={}", e);
        return Err(e);
    }
    // 起始时间戳:lifetime 用,close 时 now - open_ts 投递到 CLOSED_LIFETIMES。
    // 写失败只 warn 不回滚——失败的后果仅是这条连接没 lifetime 样本,不影响其他指标。
    let open_ts = unsafe { bpf_ktime_get_ns() };
    if let Err(e) = CONNECTION_OPEN_TS.insert(&key, &open_ts, 0) {
        warn!(ctx, "CONNECTION_OPEN_TS map insert failed: err={}", e);
    }
    Ok(())
}

fn try_handle_tcp_sendmsg(ctx: &FEntryContext) -> Result<(), i32> {
    // fentry args 与内核函数原型一一对应:(sk, msg, size)。
    let sk: *const core::ffi::c_void = ctx.arg(0);
    let size: usize = ctx.arg(2);
    let cookie = sock_cookie(sk as u64);
    if cookie == 0 {
        return Ok(());
    }

    let key = match unsafe { SOCK_TO_CONNECTION.get(&cookie) } {
        Some(k) => *k,
        None => return Ok(()),
    };

    // CONNECTIONS 是 PerCpuHashMap:get/insert 在 BPF 端语义都是"当前 CPU 的那份副本",
    // 写者只动自己 CPU 的实例,跨 CPU 永不冲突。这里因此可以放心做 read-modify-write:
    // 它在并发安全意义上等价于 single-threaded RMW。用户态收割时再把所有 CPU 的副本
    // 求和聚合。
    let mut throughput = match unsafe { CONNECTIONS.get(&key) } {
        Some(t) => *t,
        None => ConnectionThroughputStats {
            bytes_sent: 0,
            bytes_received: 0,
            retransmits: 0,
        },
    };

    throughput.bytes_sent = throughput.bytes_sent.saturating_add(size as u64);
    if let Err(e) = CONNECTIONS.insert(&key, &throughput, 0) {
        warn!(ctx, "CONNECTIONS map insert failed in tcp_sendmsg: err={}", e);
        return Err(e);
    }

    Ok(())
}

fn try_handle_tcp_cleanup_rbuf(ctx: &FEntryContext) -> Result<(), i32> {
    // fentry args:(sk, copied)。
    let sk: *const core::ffi::c_void = ctx.arg(0);
    let copied: i32 = ctx.arg(1);
    if copied <= 0 {
        return Ok(());
    }
    let cookie = sock_cookie(sk as u64);
    if cookie == 0 {
        return Ok(());
    }

    let key = match unsafe { SOCK_TO_CONNECTION.get(&cookie) } {
        Some(k) => *k,
        None => return Ok(()),
    };

    // 同 sendmsg:在 PerCpuHashMap 当前 CPU 的副本上做 RMW,跨 CPU 不冲突。
    let mut throughput = match unsafe { CONNECTIONS.get(&key) } {
        Some(t) => *t,
        None => ConnectionThroughputStats {
            bytes_sent: 0,
            bytes_received: 0,
            retransmits: 0,
        },
    };

    throughput.bytes_received = throughput.bytes_received.saturating_add(copied as u64);
    if let Err(e) = CONNECTIONS.insert(&key, &throughput, 0) {
        warn!(ctx, "CONNECTIONS map insert failed in tcp_cleanup_rbuf: err={}", e);
        return Err(e);
    }

    // sock 采样:cleanup_rbuf 每次 ACK 段进来时,顺手把 tp 上最新的 srtt_us / segs_in /
    // segs_out 读一份写到 SOCK_SAMPLES,用户态收割时拿来分别喂 srtt 直方图与 segs 计数器。
    //
    // 容错:TCP_SOCK_OFFSETS 缺失(BTF populate race)时直接跳过——throughput 已经记上了,
    // 不要为采样字段把这条 ACK 整条丢掉。srtt_us==0 是 tp 初始值(kernel 还没拿到任何 RTT
    // 样本前都是 0),写进去会把直方图首桶刷糊——所以即便 segs 已经非零,srtt==0 时整条
    // 采样仍跳过;反正下一次 cleanup_rbuf 会带着真正非零的 srtt 把 segs 一并写进来。
    let off_key = 0u32;
    if let Some(tcp_off) = unsafe { TCP_SOCK_OFFSETS.get(&off_key) } {
        if let Some(srtt_us) = read_sock_field::<u32>(sk as u64, tcp_off.srtt_us_off)
            && srtt_us > 0
        {
            let segs_in = read_sock_field::<u32>(sk as u64, tcp_off.segs_in_off).unwrap_or(0);
            let segs_out = read_sock_field::<u32>(sk as u64, tcp_off.segs_out_off).unwrap_or(0);
            let snap = SockSampleSnapshot {
                last_srtt_us: srtt_us,
                last_segs_in: segs_in,
                last_segs_out: segs_out,
                _reserved: 0,
            };
            // insert 失败只 warn 不返回错误:采样丢一拍不影响其他指标。
            if let Err(e) = SOCK_SAMPLES.insert(&key, &snap, 0) {
                warn!(ctx, "SOCK_SAMPLES insert failed: err={}", e);
            }
        }
    }

    Ok(())
}

fn try_handle_tcp_retransmit_skb(ctx: &FEntryContext) -> Result<(), i32> {
    // fentry args:(sk, skb, segs)。segs 是这次重传包含的 TSO 段数,一次"重传事件"
    // 实际可能跨多个 TCP 段——按 segs 累加比 +1 更接近真实重传字节量。
    let sk: *const core::ffi::c_void = ctx.arg(0);
    let segs: i32 = ctx.arg(2);
    if segs <= 0 {
        return Ok(());
    }
    let cookie = sock_cookie(sk as u64);
    if cookie == 0 {
        return Ok(());
    }

    let key = match unsafe { SOCK_TO_CONNECTION.get(&cookie) } {
        Some(k) => *k,
        None => return Ok(()),
    };

    // 同 sendmsg / cleanup_rbuf 的 RMW 模板:PerCpuHashMap 当前 CPU 副本不冲突。
    let mut throughput = match unsafe { CONNECTIONS.get(&key) } {
        Some(t) => *t,
        None => ConnectionThroughputStats {
            bytes_sent: 0,
            bytes_received: 0,
            retransmits: 0,
        },
    };

    throughput.retransmits = throughput.retransmits.saturating_add(segs as u64);
    if let Err(e) = CONNECTIONS.insert(&key, &throughput, 0) {
        warn!(
            ctx,
            "CONNECTIONS map insert failed in tcp_retransmit_skb: err={}", e
        );
        return Err(e);
    }

    Ok(())
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
