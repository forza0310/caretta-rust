#![no_std]
#![no_main]

use aya_ebpf::bindings::{BPF_TCP_CLOSE, BPF_TCP_SYN_RECV, BPF_TCP_SYN_SENT};
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::macros::{kprobe, map, tracepoint};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::{ProbeContext, TracePointContext};

const CONNECTION_ROLE_UNKNOWN: u32 = 0;
const CONNECTION_ROLE_CLIENT: u32 = 1;
const CONNECTION_ROLE_SERVER: u32 = 2;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TraceOffsets {
    pub skaddr_off: u32,
    pub newstate_off: u32,
    pub sport_off: u32,
    pub dport_off: u32,
    pub saddr_off: u32,
    pub daddr_off: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnectionTuple {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnectionIdentifier {
    pub id: u32,
    pub pid: u32,
    pub tuple: ConnectionTuple,
    pub role: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
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
static CONNECTIONS: HashMap<ConnectionIdentifier, ConnectionThroughputStats> =
    HashMap::<ConnectionIdentifier, ConnectionThroughputStats>::with_max_entries(131072, 0);

#[map]
static SOCK_TO_CONNECTION: HashMap<u64, ConnectionIdentifier> =
    HashMap::<u64, ConnectionIdentifier>::with_max_entries(131072, 0);

#[map]
static TRACEPOINT_OFFSETS: HashMap<u32, TraceOffsets> =
    HashMap::<u32, TraceOffsets>::with_max_entries(1, 0);

#[kprobe]
pub fn handle_tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_handle_tcp_sendmsg(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[kprobe]
pub fn handle_tcp_cleanup_rbuf(ctx: ProbeContext) -> u32 {
    match try_handle_tcp_cleanup_rbuf(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn handle_sock_set_state(ctx: TracePointContext) -> u32 {
    match try_handle_sock_set_state(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[inline(always)]
fn ctx_u16(ctx: &TracePointContext, offset: usize) -> Result<u16, i32> {
    unsafe { ctx.read_at::<u16>(offset) }
}

#[inline(always)]
fn ctx_u32(ctx: &TracePointContext, offset: usize) -> Result<u32, i32> {
    unsafe { ctx.read_at::<u32>(offset) }
}

#[inline(always)]
fn ctx_u64(ctx: &TracePointContext, offset: usize) -> Result<u64, i32> {
    unsafe { ctx.read_at::<u64>(offset) }
}

#[inline(always)]
fn ctx_i32(ctx: &TracePointContext, offset: usize) -> Result<i32, i32> {
    unsafe { ctx.read_at::<i32>(offset) }
}

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
fn mark_connection_closed(skaddr: u64, tuple: ConnectionTuple, role: u32) {
    if role == CONNECTION_ROLE_UNKNOWN {
        return;
    }

    let key = ConnectionIdentifier {
        id: connection_id(&tuple, role),
        pid: 0,
        tuple,
        role,
    };

    if let Some(existing) = unsafe { CONNECTIONS.get(&key) } {
        let mut updated = *existing;
        updated.is_active = 0;
        let _ = CONNECTIONS.insert(&key, &updated, 0);
    }

    let _ = SOCK_TO_CONNECTION.remove(&skaddr);
}

fn try_handle_sock_set_state(ctx: &TracePointContext) -> Result<(), i32> {
    // Offsets are discovered in userspace from tracefs format and written to TRACEPOINT_OFFSETS map.
    let offsets_key = 0u32;
    let offsets = match unsafe { TRACEPOINT_OFFSETS.get(&offsets_key) } {
        Some(v) => *v,
        None => return Ok(()),
    };

    let skaddr = ctx_u64(ctx, offsets.skaddr_off as usize)?;
    let newstate = ctx_i32(ctx, offsets.newstate_off as usize)?;
    let sport_raw = ctx_u16(ctx, offsets.sport_off as usize)?;
    let dport_raw = ctx_u16(ctx, offsets.dport_off as usize)?;
    let src_ip = u32::from_be(ctx_u32(ctx, offsets.saddr_off as usize)?);
    let dst_ip = u32::from_be(ctx_u32(ctx, offsets.daddr_off as usize)?);

    let tuple = ConnectionTuple {
        src_ip,
        dst_ip,
        src_port: u16::from_be(sport_raw),
        dst_port: u16::from_be(dport_raw),
    };

    let role = match newstate {
        state if state == BPF_TCP_SYN_SENT as i32 => CONNECTION_ROLE_CLIENT,
        state if state == BPF_TCP_SYN_RECV as i32 => CONNECTION_ROLE_SERVER,
        state if state == BPF_TCP_CLOSE as i32 => CONNECTION_ROLE_UNKNOWN,
        _ => CONNECTION_ROLE_UNKNOWN,
    };

    if newstate == BPF_TCP_CLOSE as i32 {
        mark_connection_closed(skaddr, tuple, CONNECTION_ROLE_CLIENT);
        mark_connection_closed(skaddr, tuple, CONNECTION_ROLE_SERVER);
        return Ok(());
    }

    if role == CONNECTION_ROLE_UNKNOWN {
        return Ok(());
    }

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
        throughput.bytes_sent = throughput.bytes_sent.saturating_add(1);
        throughput.is_active = 1;
    }

    CONNECTIONS.insert(&key, &throughput, 0)?;
    SOCK_TO_CONNECTION.insert(&skaddr, &key, 0)?;
    Ok(())
}

fn try_handle_tcp_sendmsg(ctx: &ProbeContext) -> Result<(), i32> {
    let sk: *const core::ffi::c_void = ctx.arg(0).ok_or(1)?;
    let size: usize = ctx.arg(2).ok_or(1)?;
    let skaddr = sk as u64;

    let key = match unsafe { SOCK_TO_CONNECTION.get(&skaddr) } {
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

fn try_handle_tcp_cleanup_rbuf(ctx: &ProbeContext) -> Result<(), i32> {
    let sk: *const core::ffi::c_void = ctx.arg(0).ok_or(1)?;
    let copied: i32 = ctx.arg(1).ok_or(1)?;
    if copied <= 0 {
        return Ok(());
    }
    let skaddr = sk as u64;

    let key = match unsafe { SOCK_TO_CONNECTION.get(&skaddr) } {
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
