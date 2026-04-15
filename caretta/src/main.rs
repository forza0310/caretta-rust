use anyhow::Context as _;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use std::net::Ipv4Addr;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")] // 让 clap 从命令行读取参数
    iface: String, // Here we declare our CLI flags. Just --iface for now for passing the interface name
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/caretta"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            // 异步任务：输出ebpf日志到用户态
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface } = opt;
    // 提取 XDP 程序并将其附加到指定的网络接口上
    let program: &mut Xdp = ebpf.program_mut("xdp_firewall").unwrap().try_into()?; // 传入xdp程序-函数名
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // 获取ebpf映射
    let mut block_src_addr_list: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.map_mut("BLOCK_SRC_ADDR_LIST").unwrap())?;
    // 写入封禁ip
    let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).into();
    block_src_addr_list.insert(block_addr, 0, 0)?;

    // 获取ebpf映射
    let mut ignore_dest_port_list: HashMap<_, u16, u32> =
        HashMap::try_from(ebpf.map_mut("IGNORE_DEST_PORT_LIST").unwrap())?;
    // 写入忽略的dest port：ssh-22
    ignore_dest_port_list.insert(22, 0, 0)?;


    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
