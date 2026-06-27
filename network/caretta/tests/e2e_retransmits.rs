//! E2E: caretta_tcp_retransmits_total 必须能在真实丢包下涨数。
//!
//! 守的是 wiring guards / 单元 / 聚合三层都覆盖不到的"运行时事实":
//!   1. tcp_retransmit_skb fentry 在当前 kernel 上能挂上 + 真触发
//!   2. ctx.arg(2) 读到的就是 segs(args 顺序对,不是别的寄存器值)
//!   3. 用户态 throughput.retransmits 真的被读出来 + 喂给 prom counter
//!   4. /metrics 端点上 caretta_tcp_retransmits_total 出非零 sample
//!
//! 运行条件:
//!   - root + CAP_BPF(加载 ebpf) + CAP_NET_ADMIN(配 tc netem)
//!   - iproute2 (`tc`,绝大多数发行版默认装)
//!   - kernel ≥ 5.5 + BTF(与项目主要求一致)
//!
//! 跑法(默认 `#[ignore]`,CI 一般跑不了):
//!     sudo -E cargo test -p caretta --test e2e_retransmits -- --ignored --nocapture
//!
//! 一句话:wiring guards 守"代码长得对",这条测试守"线上数会涨"。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// 测试用端口。tc netem 仅对 dport=NETEM_PORT 的 TCP 流量加丢包,
/// 不影响 SSH / 其它 lo 流量——前提是没人撞到这个端口。
const NETEM_PORT: u16 = 53917;
/// caretta 的 prom 端口(避开默认 7117 防本机已经在跑一份)。
const PROM_PORT: u16 = 17117;
/// server 绑 127.0.0.2 而不是 127.0.0.1——caretta 在 main.rs:304 用
/// `src==dst && is_loopback(dst)` 把 127.0.0.1<->127.0.0.1 的自环过滤掉了,
/// 用不同 IP 才能保留链路。127.0.0.0/8 全部路由到 lo,无需额外 ip addr add。
const SERVER_BIND: &str = "127.0.0.2";

fn sh(cmd: &str) -> std::process::Output {
    Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .expect("spawn /bin/sh failed (PATH 异常)")
}

fn require_root() {
    let out = sh("id -u");
    let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if uid != "0" {
        panic!(
            "must run as root (CAP_BPF + CAP_NET_ADMIN); retry: \
             sudo -E cargo test -p caretta --test e2e_retransmits -- --ignored --nocapture"
        );
    }
}

/// lo 上 dport=NETEM_PORT 的 TCP 加 30% 丢包,触发 tcp_retransmit_skb。
/// prio + netem + u32 filter 把 netem 局限在测试端口,而不是整片 lo——
/// 否则 SSH / 本机其它服务都会被丢包,跑测试把 dev box 自己卡死。
/// Drop 一定要清干净,即使 panic;残留 qdisc 会让下次测试 / 日常使用受影响。
struct LoNetem;
impl LoNetem {
    fn setup() -> Self {
        // 清理上一次跑挂掉留下的残留 qdisc,失败忽略——可能本来就没有。
        let _ = sh("tc qdisc del dev lo root 2>/dev/null");
        let out = sh(&format!(
            "set -e; \
             tc qdisc add dev lo root handle 1: prio; \
             tc qdisc add dev lo parent 1:3 handle 30: netem loss 30%; \
             tc filter add dev lo protocol ip parent 1:0 prio 3 u32 \
                 match ip dport {NETEM_PORT} 0xffff flowid 1:3"
        ));
        assert!(
            out.status.success(),
            "tc netem setup failed (CAP_NET_ADMIN 缺失或 iproute2 未装); stderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        LoNetem
    }
}
impl Drop for LoNetem {
    fn drop(&mut self) {
        let _ = sh("tc qdisc del dev lo root 2>/dev/null");
    }
}

/// 测试退出时(含 panic)杀掉 caretta 子进程,避免遗留持有端口和 eBPF 程序。
struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for_port(addr: &str, deadline: Duration) -> bool {
    let target: SocketAddr = addr.parse().expect("addr parse");
    let start = Instant::now();
    while start.elapsed() < deadline {
        if TcpStream::connect_timeout(&target, Duration::from_millis(200)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(200));
    }
    false
}

/// 跑一段 TCP 流量,在 30% 丢包链路上必产生重传。client 127.0.0.1 → server 127.0.0.2。
/// 64KB chunk × N 块,确保 segment 数远高于"丢包统计学下零重传"的窗口。
fn drive_lossy_flow(payload_bytes: usize) {
    let bind = format!("{SERVER_BIND}:{NETEM_PORT}");
    let listener =
        TcpListener::bind(&bind).unwrap_or_else(|e| panic!("bind {bind} failed: {e}"));
    let acceptor = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        sock.set_read_timeout(Some(Duration::from_secs(60))).ok();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0usize;
        loop {
            match sock.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(_) => break,
            }
        }
        total
    });

    let mut client = TcpStream::connect(&bind).expect("client connect");
    client.set_write_timeout(Some(Duration::from_secs(60))).ok();
    let chunk = vec![0xa5u8; 64 * 1024];
    let mut sent = 0usize;
    while sent < payload_bytes {
        let n = client.write(&chunk).expect("client write");
        sent += n;
    }
    drop(client);
    let received = acceptor.join().expect("acceptor join");
    eprintln!("[flow] sent {sent}B, server received {received}B");
}

fn scrape_metrics() -> String {
    let mut sock = TcpStream::connect(format!("127.0.0.1:{PROM_PORT}"))
        .expect("connect /metrics");
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    sock.write_all(b"GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .expect("send GET");
    let mut body = String::new();
    sock.read_to_string(&mut body).expect("read /metrics");
    body
}

/// 把所有 caretta_tcp_retransmits_total{...} 行的 value 加起来。
/// 跨标签求和:测试只关心"端到端 > 0",不依赖具体 (client, server) 标签。
fn sum_caretta_retransmits_total(metrics: &str) -> f64 {
    metrics
        .lines()
        .filter(|l| l.starts_with("caretta_tcp_retransmits_total{"))
        .filter_map(|l| l.rsplit_once(' ').and_then(|(_, v)| v.parse::<f64>().ok()))
        .sum()
}

#[test]
#[ignore]
fn caretta_tcp_retransmits_total_must_grow_under_netem_loss() {
    require_root();
    let _netem = LoNetem::setup();

    // env!("CARGO_BIN_EXE_caretta") 是 cargo 在 build test 前注入的 bin 路径,
    // 自动随当前 crate 重新编译——拿到的一定是最新代码。
    let caretta = Command::new(env!("CARGO_BIN_EXE_caretta"))
        .env("PROMETHEUS_PORT", PROM_PORT.to_string())
        .env("POLL_INTERVAL", "1")
        .env("DEBUG_RESOLVER_ENABLED", "false")
        // 强制走 StaticResolver,避免本测试机器没 KUBECONFIG 时初始化挂掉。
        .env_remove("KUBECONFIG")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn caretta binary");
    let _killer = KillOnDrop(caretta);

    assert!(
        wait_for_port(&format!("127.0.0.1:{PROM_PORT}"), Duration::from_secs(20)),
        "caretta /metrics port did not open within 20s — \
         通常是 BTF 缺失 / eBPF verifier 拒绝 / cap 不够,看上面 stderr"
    );

    // 两轮 2MB:第一轮触发足够重传,第二轮保证 throughput 跨 tick 被 poll loop 看到。
    // 64KB chunk × 32 = ~32 segment/MB,30% loss 下每 MB 期望 ~10 次重传,远高于零。
    drive_lossy_flow(2 * 1024 * 1024);
    drive_lossy_flow(2 * 1024 * 1024);

    // POLL_INTERVAL=1s,留 ≥3 tick 等 caretta 把 BPF map 里的 retransmits delta 收上来。
    thread::sleep(Duration::from_secs(4));

    let body = scrape_metrics();
    let total = sum_caretta_retransmits_total(&body);

    assert!(
        total > 0.0,
        "caretta_tcp_retransmits_total 跨标签求和必须 > 0(4MB 丢包流量后);实际 = {total}.\n\
         可能原因:\n\
           - tcp_retransmit_skb fentry 没被 kernel 触发(内核版本/符号问题)\n\
           - eBPF 程序 attach 失败但 caretta 没退出\n\
           - 用户态 poll loop 没读到 throughput.retransmits\n\
         相关 metric 行 dump:\n{}",
        body.lines()
            .filter(|l| l.contains("retransmit"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    eprintln!("[PASS] caretta_tcp_retransmits_total sum = {total}");
}
