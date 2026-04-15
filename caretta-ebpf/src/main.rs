#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use core::mem;
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[cfg(not(test))]
#[panic_handler] //#[panic_handler] is required to keep the compiler happy, although it is never used since we cannot panic.
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map] // (1)
static BLOCK_SRC_ADDR_LIST: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(1024, 0);

#[map]
static IGNORE_DEST_PORT_LIST: HashMap<u16, u32> = // 不输出的端口
    HashMap::<u16, u32>::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 { // xdp程序-函数定义
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn block_ip(address: u32) -> bool {
    unsafe { BLOCK_SRC_ADDR_LIST.get(&address).is_some() }
}

fn ignore_port(port: u16) -> bool {
    unsafe { IGNORE_DEST_PORT_LIST.get(&port).is_some() }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; // 读取以太网报头
    // ? 是 Rust 的错误传播（early return）运算符。
    // 放在一个返回 Result 或 Option 的表达式后面，会做两件事：
    // 成功分支：解包并拿到内部值（相当于 Ok(v) => v / Some(v) => v）
    // 失败分支：立刻从当前函数返回错误（相当于 Err(e) => return Err(e) / None => return None）
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).dst_addr });

    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be_bytes(unsafe { (*tcphdr).source }) // 手动做大端转主机序
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe { (*udphdr).src_port() }
        }
        _ => return Err(()),
    };

    let dest_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be_bytes(unsafe { (*tcphdr).dest })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe { (*udphdr).dst_port() }
        }
        _ => return Err(()),
    };

    // 跳过忽略的目的端口
    if ignore_port(dest_port) {
        return Ok(xdp_action::XDP_PASS);
    }

    let action = if block_ip(source_addr) {
        xdp_action::XDP_ABORTED
    } else {
        xdp_action::XDP_PASS
    };
    // 记录 IP 和端口
    // 把日志事件写入 Aya 日志通道（底层走 eBPF map + perf/ring buffer 机制）供用户态消费
    info!(&ctx, "SRC IP: {:i}, SRC PORT: {}; DST IP: {:i}, DST PORT: {}. ACTION: {}",
        source_addr, source_port, dest_addr, dest_port, action);

    Ok(action)
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
