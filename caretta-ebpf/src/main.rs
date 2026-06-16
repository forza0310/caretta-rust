#![no_std]
#![no_main]

use aya_ebpf::bindings::{BPF_TCP_CLOSE, BPF_TCP_SYN_RECV, BPF_TCP_SYN_SENT};
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_get_socket_cookie, bpf_probe_read_kernel};
use aya_ebpf::macros::{btf_tracepoint, fentry, map};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::{BtfTracePointContext, FEntryContext};
use aya_log_ebpf::{info, warn};

const CONNECTION_ROLE_UNKNOWN: u32 = 0;
const CONNECTION_ROLE_CLIENT: u32 = 1;
const CONNECTION_ROLE_SERVER: u32 = 2;

#[repr(C)]
#[derive(Copy, Clone)]
// `struct sock_common` 关键字段在该内核 vmlinux BTF 里的 byte offset。
// 用户态在启动期解析 /sys/kernel/btf/vmlinux 写入,eBPF 端 bpf_probe_read_kernel
// 时按这些 offset 从 sock 指针读字段——这样不依赖任何 kernel-version-specific
// 硬编码,内核改 ABI 时启动就 fail,而不是默默读垃圾。
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
// It combines the raw socket tuple, role, and current process id.
pub struct ConnectionIdentifier {
    pub id: u32,
    pub pid: u32,
    pub tuple: ConnectionTuple,
    pub role: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
// Per-connection counters tracked in eBPF maps.
// bytes_sent comes from tcp_sendmsg, bytes_received comes from tcp_cleanup_rbuf,
// and is_active tracks whether the socket is still open.
pub struct ConnectionThroughputStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub is_active: u64,
}

#[cfg(not(test))]
#[panic_handler] //#[panic_handler] is required to keep the compiler happy, although it is never used since we cannot panic.
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map]
// Primary per-connection store. Userspace iterates this map to read throughput and liveness
// for each observed TCP connection.
static CONNECTIONS: HashMap<ConnectionIdentifier, ConnectionThroughputStats> =
    HashMap::<ConnectionIdentifier, ConnectionThroughputStats>::with_max_entries(131072, 0);

#[map]
// sock cookie → 活跃连接 key 的反查表。
// cookie 在 sock 生命周期内分配一次、sock free 后不会复用,
// 所以即使新分配的 sock 恰好落在刚刚释放的那块内存上,
// 它一定拿到不同的 cookie。这条不变量把 sendmsg/recvmsg 计费路径和 close 路径,
// 从 "sock-slab 复用 race" 中保护出来。
static SOCK_TO_CONNECTION: HashMap<u64, ConnectionIdentifier> =
    HashMap::<u64, ConnectionIdentifier>::with_max_entries(131072, 0);

#[map]
// Runtime-discovered sock_common field offsets. Userspace populates this once at startup
// after parsing /sys/kernel/btf/vmlinux,eBPF 端按这些 offset 读 sock 字段。
static SOCK_OFFSETS: HashMap<u32, SockOffsets> =
    HashMap::<u32, SockOffsets>::with_max_entries(1, 0);

// fentry on tcp_sendmsg captures TCP write-side payload size.
// fentry 类型签名按 vmlinux BTF 决定,内核函数原型 (struct sock *sk, struct msghdr *msg, size_t size)。
// fentry 是 BPF_PROG_TYPE_TRACING,bpf_get_socket_cookie() helper 在这个 program type 下可用。
#[fentry(function = "tcp_sendmsg")]
pub fn handle_tcp_sendmsg(ctx: FEntryContext) -> u32 {
    match try_handle_tcp_sendmsg(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

// fentry on tcp_cleanup_rbuf captures TCP read-side accounting.
// 内核函数原型 (struct sock *sk, int copied)。
#[fentry(function = "tcp_cleanup_rbuf")]
pub fn handle_tcp_cleanup_rbuf(ctx: FEntryContext) -> u32 {
    match try_handle_tcp_cleanup_rbuf(&ctx) {
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

// FNV-1a hash of the 4-tuple and role, used as a key for identifying connections in maps.
#[inline(always)]
fn connection_id(tuple: &ConnectionTuple, role: u32) -> u32 {
    let mut hash = 0x811C9DC5u32;
    hash ^= tuple.src_ip;
    hash = hash.wrapping_mul(0x01000193);
    hash ^= tuple.dst_ip;
    hash = hash.wrapping_mul(0x01000193);
    hash ^= tuple.src_port as u32;
    hash = hash.wrapping_mul(0x01000193);
    hash ^= tuple.dst_port as u32;
    hash = hash.wrapping_mul(0x01000193);
    hash ^= role;
    hash
}

#[inline(always)]
fn sock_cookie(skaddr: u64) -> u64 {
    // bpf_get_socket_cookie(struct sock *) — 内核 ≥ 5.7 提供的 helper。
    // 返回 64-bit、单调递增、sock 生命周期内唯一、sock free 后不会复用的标识符
    // (即使下一次 alloc 拿到同一个 `struct sock *` 地址,cookie 也会是新值)。
    //
    // 0 表示 helper 在当前 program type 上不可用,或 sock 指针为空。调用方必须把 0
    // 当 "本次跳过" 处理,而不是当合法 key,否则多个不相关的 sock 会在 cookie==0 上互撞。
    //
    // 此 helper 只在 BPF_PROG_TYPE_TRACING/BPF_PROG_TYPE_CGROUP_SOCK 等几类 program 上注册;
    // 这就是为什么 sendmsg/recvmsg 必须改成 fentry、inet_sock_set_state 必须改成 tp_btf
    // ——legacy kprobe / tracepoint program 类型走不通这条 helper。
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
        if let Some(existing) = unsafe { CONNECTIONS.get(&key) } {
            let mut updated = *existing;
            updated.is_active = 0;
            let _ = CONNECTIONS.insert(&key, &updated, 0);
        }
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
        id: connection_id(&tuple, role),
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        tuple,
        role,
    };

    let mut throughput = ConnectionThroughputStats {
        bytes_sent: 0,
        bytes_received: 0,
        is_active: 1,
    };

    if let Some(existing) = unsafe { CONNECTIONS.get(&key) } {
        throughput = *existing;
        // State transitions should not mutate byte counters.
        // Bytes are only accounted in tcp_sendmsg/tcp_cleanup_rbuf probes.
        throughput.is_active = 1;
    }

    if let Err(e) = CONNECTIONS.insert(&key, &throughput, 0) {
        // 边界事件:131072 entries 撑爆,通常是 close 路径漏 cleanup 或者短连接风暴。
        // 用户态 GC 兜底,但出现这条说明 cleanup 跟不上、视图会丢新 link。
        info!(ctx, "CONNECTIONS map insert failed: err={}", e);
        return Err(e);
    }
    if let Err(e) = SOCK_TO_CONNECTION.insert(&cookie, &key, 0) {
        // 同上,反查表撑爆——后续 sendmsg/cleanup_rbuf/close 都没法落到这条 sock 上。
        info!(ctx, "SOCK_TO_CONNECTION map insert failed: err={}", e);
        return Err(e);
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

    let mut throughput = match unsafe { CONNECTIONS.get(&key) } {
        Some(t) => *t,
        None => {
            let init = ConnectionThroughputStats {
                bytes_sent: 0,
                bytes_received: 0,
                is_active: 1,
            };
            CONNECTIONS.insert(&key, &init, 0)?;
            init
        }
    };

    throughput.bytes_sent = throughput.bytes_sent.saturating_add(size as u64);
    throughput.is_active = 1;
    CONNECTIONS.insert(&key, &throughput, 0)?;

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

    let mut throughput = match unsafe { CONNECTIONS.get(&key) } {
        Some(t) => *t,
        None => {
            let init = ConnectionThroughputStats {
                bytes_sent: 0,
                bytes_received: 0,
                is_active: 1,
            };
            CONNECTIONS.insert(&key, &init, 0)?;
            init
        }
    };

    throughput.bytes_received = throughput.bytes_received.saturating_add(copied as u64);
    throughput.is_active = 1;
    CONNECTIONS.insert(&key, &throughput, 0)?;

    Ok(())
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
