//! E2E: caretta_tcp_srtt_seconds + caretta_tcp_segs_{in,out}_total 必须在真实 TCP
//! 流量下出合理的值。
//!
//! 守的是 wiring guards / 单元 / BTF 三层都覆盖不到的"运行时事实":
//!   1. tcp_cleanup_rbuf fentry 在当前 kernel 上能挂上 + 真触发
//!   2. TCP_SOCK_OFFSETS 解出的偏移读到的就是 srtt_us / segs_in / segs_out
//!      (不是别的字段错位的垃圾值)
//!   3. 用户态 SOCK_SAMPLES 真的被 lookup + 喂给 prom histogram / counter
//!   4. /metrics 端点上 srtt 直方图 sum/count 与人为加的 50ms RTT 一致,
//!      segs_in/out 计数随流量真实增长
//!
//! 用 50ms netem delay 是关键:在 lo 上无 delay 时 srtt 在 10-30µs 量级,
//! 加了 delay 后跳到 ms 量级——断"avg 落在 [1ms, 10s]"既能挡住"读到的是常数 0 /
//! 错位字段"(几乎必为 0 或巨大值)又不依赖任何精确数值。
//!
//! lo 上 tc netem 通过 `prio + u32 filter dport` 单向施加 delay(server→client 反向
//! 的 ACK 走 client ephemeral 端口,filter 不匹配),实测 srtt 落在 ~10-20ms,
//! 远高于 lo 基线,远低于"读错字段读到 u32 计数器"那种秒级数字。
//!
//! 运行条件:
//!   - root + CAP_BPF(加载 ebpf) + CAP_NET_ADMIN(配 tc netem)
//!   - iproute2 (`tc`)
//!   - kernel ≥ 5.5 + BTF
//!
//! 跑法(默认 `#[ignore]` 没加,但非 root 跑直接 panic 提示——
//! 和 e2e_retransmits 风格一致,统一约定):
//!     sudo -E cargo test -p caretta --test e2e_srtt_segs -- --nocapture

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// 锁定测试端口,netem delay 只施加于 dport=NETEM_PORT,不连累 lo 上其它流量。
/// 与 e2e_retransmits 避开撞号——两条 e2e 一起跑也不会互相干扰。
const NETEM_PORT: u16 = 53919;
/// caretta 的 prom 端口。避开 7117(默认)+ 17117(e2e_retransmits)。
const PROM_PORT: u16 = 17118;
/// server 绑 127.0.0.2 而非 127.0.0.1——caretta 把 src==dst loopback 自环过滤了。
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
             sudo -E cargo test -p caretta --test e2e_srtt_segs -- --nocapture"
        );
    }
}

/// lo 上 dport=NETEM_PORT 的 TCP 加 50ms delay。
///
/// lo 的 tc netem 只对 egress 起作用,且 filter 按 dport 匹配——所以仅 client→server
/// 方向的包(dport=NETEM_PORT)被 delay,server→client 的 ACK(dport=client ephemeral)
/// 不走 filter。两端 tp->srtt_us 的实测值落在 ~10-20ms 区间:lo 基线只有 10-30µs,
/// 升到 ms 量级足以证明 netem 在生效且我们读到的字段就是 srtt_us。
///
/// Drop 一定要清干净,即使 panic;残留 qdisc 会持续 delay lo 上的测试端口流量,
/// 把后续 cargo test 全卡死在 timeout。
struct LoNetemDelay;
impl LoNetemDelay {
    fn setup() -> Self {
        // 上一次跑挂掉留下的残留 qdisc 顺手清,失败忽略——可能本来就没有。
        let _ = sh("tc qdisc del dev lo root 2>/dev/null");
        let out = sh(&format!(
            "set -e; \
             tc qdisc add dev lo root handle 1: prio; \
             tc qdisc add dev lo parent 1:3 handle 30: netem delay 50ms; \
             tc filter add dev lo protocol ip parent 1:0 prio 3 u32 \
                 match ip dport {NETEM_PORT} 0xffff flowid 1:3"
        ));
        assert!(
            out.status.success(),
            "tc netem setup failed (CAP_NET_ADMIN 缺失或 iproute2 未装); stderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        LoNetemDelay
    }
}
impl Drop for LoNetemDelay {
    fn drop(&mut self) {
        let _ = sh("tc qdisc del dev lo root 2>/dev/null");
    }
}

/// 测试退出时(含 panic)杀掉 caretta 子进程。
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

/// 跑一段双向 TCP 流量,写完 payload 后 hold 一段时间不 close。
///
/// **双向是关键**。eBPF 端 SOCK_TO_CONNECTION 只在 inet_sock_set_state 的 SYN_SENT
/// (client)分支写入;server 端 child sock 由 tcp_create_openreq_child 直接以 SYN_RECV
/// 状态创建,**不走 tcp_set_state**,tracepoint 不触发 → server 端 cookie 永远不在
/// SOCK_TO_CONNECTION 里。而 tcp_cleanup_rbuf(srtt / segs 采样口)只在接收侧 fire——
/// 单向 client→server 的话:server 端有 cleanup_rbuf 但拿不到 key,client 端有 key 但
/// 没 cleanup_rbuf,两边都漏。让 server 也回一段、client 也读,**client 侧** cleanup_rbuf
/// 才会命中已写入的 SOCK_TO_CONNECTION,SOCK_SAMPLES 才有 testing flow 的 entry。
///
/// hold 至关重要——SOCK_SAMPLES 在 conn close 时被 eBPF 端立刻抹掉(mark_connection_closed),
/// LinkState 也不留 cumulative_segs,所以 testing 流量必须在 caretta 主循环 iter
/// CONNECTION_STATES 时**还活着**,这条 conn 才能被 lookup 到、贡献 segs / srtt。
fn drive_flow_and_hold(payload_bytes: usize, hold: Duration) {
    let bind = format!("{SERVER_BIND}:{NETEM_PORT}");
    let listener =
        TcpListener::bind(&bind).unwrap_or_else(|e| panic!("bind {bind} failed: {e}"));
    let acceptor = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        sock.set_read_timeout(Some(Duration::from_secs(60))).ok();
        sock.set_write_timeout(Some(Duration::from_secs(60))).ok();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0usize;
        // echo:server 收一段就回一小段(8 字节),让 client 端 tcp_cleanup_rbuf 在每个
        // chunk 上 fire——这是 SOCK_SAMPLES 能采到 client 端 sock 的唯一入口。回写
        // 大小只需 > 0,segs/srtt 看的是 sample 是否被写入,不看具体字节数。
        loop {
            match sock.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    let _ = sock.write_all(&[0u8; 8]);
                }
                Err(_) => break,
            }
        }
        total
    });

    let mut client = TcpStream::connect(&bind).expect("client connect");
    client.set_write_timeout(Some(Duration::from_secs(60))).ok();
    client.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let chunk = vec![0xa5u8; 64 * 1024];
    let mut ack = [0u8; 8];
    let mut sent = 0usize;
    while sent < payload_bytes {
        let n = client.write(&chunk).expect("client write");
        sent += n;
        // 配对 read,把 server 回的 8B 收掉——内核侧触发 client 端 tcp_cleanup_rbuf,
        // SOCK_SAMPLES 才有 testing flow 的快照。
        let _ = client.read(&mut ack);
    }
    // 写完不 close,sleep 让 caretta 主循环至少跑过 hold/poll_interval 次,
    // 这段时间内 testing conn 一直 ESTABLISHED,iter CONNECTION_STATES 必能命中。
    thread::sleep(hold);
    drop(client);
    let received = acceptor.join().expect("acceptor join");
    eprintln!("[flow] sent {sent}B, server received {received}B, hold {hold:?}");
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

/// 找出 metrics 里 testing flow 那条 link 的 counter 值。
///
/// testing flow 的 link label 必然带 `client_ip="127.0.0.1"` 与 `server_ip="127.0.0.2"`,
/// 用这两个 substring 双重定位到唯一一行,直接拿到 testing flow 的端到端 counter 值——
/// 比"全局 sum - baseline"更精准,免疫 K8s 后台流量噪声。
fn testing_flow_counter(metrics: &str, name: &str) -> Option<f64> {
    let prefix = format!("{name}{{");
    metrics
        .lines()
        .filter(|l| l.starts_with(&prefix))
        .filter(|l| l.contains("client_ip=\"127.0.0.1\""))
        .filter(|l| l.contains("server_ip=\"127.0.0.2\""))
        .find_map(|l| l.rsplit_once(' ').and_then(|(_, v)| v.parse::<f64>().ok()))
}

/// 读 lo MTU 推导 segs 下界——内核默认 lo MTU 是 65536,但 CI/container 里可能被
/// 改成 1500。直接 cat /sys/class/net/lo/mtu,实在读不到才 fallback 1500(保守:按
/// 最小可能 MTU 推导,segs 数会偏多,门槛会偏严但不会假阳性放过)。
fn lo_mtu() -> u32 {
    std::fs::read_to_string("/sys/class/net/lo/mtu")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(1500)
}

/// 跨标签把 histogram 的 `_sum` 与 `_count` 各自求和,得到全链路 avg = sum/count。
/// 直方图 sum/count 比 buckets 数值更稳:不依赖具体的 bucket 划分,只依赖 observe 的事实。
fn sum_histogram_sum_count(metrics: &str, base: &str) -> (f64, f64) {
    let sum_prefix = format!("{base}_sum{{");
    let count_prefix = format!("{base}_count{{");
    let mut sum = 0.0;
    let mut count = 0.0;
    for line in metrics.lines() {
        if line.starts_with(&sum_prefix) {
            if let Some((_, v)) = line.rsplit_once(' ')
                && let Ok(f) = v.parse::<f64>()
            {
                sum += f;
            }
        } else if line.starts_with(&count_prefix)
            && let Some((_, v)) = line.rsplit_once(' ')
            && let Ok(f) = v.parse::<f64>()
        {
            count += f;
        }
    }
    (sum, count)
}

/// 用 50ms netem delay 一次性验证 srtt 直方图 + segs 计数:
///   - srtt avg 必须落在 [1ms, 10s] 区间:下界过滤"lo 基线 + 没生效",
///     上界过滤"读错字段读到大数(timestamp / counter)"
///   - segs_in / segs_out 必须在 testing 流量期间真实增长——用 before/after 增量
///     断,剥离 K8s 节点上后台流量的噪声(直接断绝对值会被 K8s 后台 segs 假阳性
///     通过)
///
/// 两件事共用一次 caretta + netem 启动,省一次 eBPF 加载 + verifier 时间。
#[test]
fn caretta_srtt_and_segs_must_reflect_real_traffic_under_netem_delay() {
    require_root();
    let _netem = LoNetemDelay::setup();

    // env!("CARGO_BIN_EXE_caretta") 是 cargo 在 build test 前注入的 bin 路径,
    // 自动随当前 crate 重新编译——拿到的一定是最新代码。
    let caretta = Command::new(env!("CARGO_BIN_EXE_caretta"))
        .env("PROMETHEUS_PORT", PROM_PORT.to_string())
        .env("POLL_INTERVAL", "1")
        .env("DEBUG_RESOLVER_ENABLED", "false")
        // 走 StaticResolver,跳过 K8s 初始化——测试机器没 KUBECONFIG 也不挂。
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

    // 让 caretta 稳定跑几轮 poll,baseline 阶段已不再需要——下面直接用 127.0.0.1 ↔
    // 127.0.0.2 label 双重定位 testing flow 自己的 counter,K8s 后台流量噪声天然过滤。
    thread::sleep(Duration::from_secs(3));

    // 两轮 2MB,每轮写完 hold 3s——保证 testing conn 在 caretta 至少 2-3 个 poll
    // cycle 期间处于 ESTABLISHED,主循环 iter 必能 lookup 到它的 SOCK_SAMPLES。
    drive_flow_and_hold(2 * 1024 * 1024, Duration::from_secs(3));
    drive_flow_and_hold(2 * 1024 * 1024, Duration::from_secs(3));

    // 再留 2 个 poll cycle 给 caretta 收 last sample。
    thread::sleep(Duration::from_secs(2));

    let body = scrape_metrics();

    // ── srtt 直方图:必须 observe 过 + avg 落在 delay 推导的合理区间 ───────────
    let (srtt_sum, srtt_count) = sum_histogram_sum_count(&body, "caretta_tcp_srtt_seconds");
    assert!(
        srtt_count > 0.0,
        "caretta_tcp_srtt_seconds_count = 0,直方图从未被 observe 过.\n\
         可能原因:\n  - tcp_cleanup_rbuf fentry 没挂上 / 没触发\n\
           - TCP_SOCK_OFFSETS 没 populate(BTF 缺 tcp_sock.srtt_us)\n\
           - SOCK_SAMPLES.insert 全部失败\n\
         相关 metric 行:\n{}",
        body.lines()
            .filter(|l| l.contains("srtt"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let srtt_avg = srtt_sum / srtt_count;
    // 下界 1ms:lo 基线 srtt 在 10-30µs 量级,1ms 是基线的 ~30-100×,稳稳能区分
    //   "netem 没生效 / 字段读错读到 0"。
    // 上界 10s:防"读到的是 timestamp / monotonic counter 等大数字段",srtt_us 物理上
    //   不可能到 10s。两端门槛配合 count > 0 一起,就是"读对了 RTT 形状的字段"的强证据。
    assert!(
        (0.001..10.0).contains(&srtt_avg),
        "srtt_avg = {srtt_avg}s 不在 [1ms, 10s] 合理区间——\n\
         < 1ms 通常是 netem 没生效 / 读到常数 0;\n\
         > 10s 通常是 BTF 偏移错位读到 timestamp / counter 类字段.\n\
         sum={srtt_sum}, count={srtt_count}"
    );
    eprintln!(
        "[srtt] count={srtt_count} sum={srtt_sum}s avg={srtt_avg:.6}s (∈[1ms,10s] ✓ delay reflected)"
    );

    // ── segs:直接定位 testing flow 自己那条 link 的 counter ─────────────────
    //
    // label 双重锁定 client_ip=127.0.0.1 + server_ip=127.0.0.2,直接拿 testing flow 的
    // 端到端 counter——比"全局 sum 减 baseline"更精准,免疫 K8s 后台流量噪声。
    //
    // 门槛按 lo MTU 动态推导:GSO/TSO 把 user write 合并成 ≤ MTU 的 superpacket。
    // 4MB / MTU 是 segs_out 上限的悲观估计——实际值会更低(GSO 把多个 64KB write 合并
    // 成更大 superpacket),实测在 lo 默认 MTU=65536 时 ~80-90、MTU=1500 时 ~5000-6000。
    // 取理论上限的 1/4 当下界:既宽到给慢启动 / 重传扣帧 / 早期 sample 留余地,又比
    // K8s 后台流量噪声高一截。segs_in(server 端 echo 8B + 纯 ACK)按 client 收到的
    // ACK 数估,基本不受 MTU 影响,固定 > 20 即可。
    let mtu = lo_mtu();
    let payload_total = 4 * 1024 * 1024u64; // 2 轮 × 2MB
    let segs_out_floor = (payload_total / mtu as u64 / 4).max(20) as f64;
    eprintln!("[segs] lo MTU={mtu} → segs_out 下界 = {segs_out_floor}");

    let testing_segs_in = testing_flow_counter(&body, "caretta_tcp_segs_in_total");
    let testing_segs_out = testing_flow_counter(&body, "caretta_tcp_segs_out_total");
    assert!(
        testing_segs_in.is_some(),
        "caretta_tcp_segs_in_total 里没有 testing flow(127.0.0.1→127.0.0.2)的 link.\n\
         可能原因:\n  - SOCK_SAMPLES 没采到 testing flow(eBPF cleanup_rbuf 没触发 / \
         SOCK_TO_CONNECTION 没 key)\n\
           - resolver 把 link 丢了 / 主循环未把它进 current_links\n\
         segs_in 全量行:\n{}",
        body.lines()
            .filter(|l| l.starts_with("caretta_tcp_segs_in_total"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let in_v = testing_segs_in.unwrap();
    let out_v = testing_segs_out.unwrap_or(0.0);
    assert!(
        in_v > 20.0,
        "testing flow segs_in = {in_v},低于 echo + ACK 推导的下限(>20).\n\
         过低通常意味着 cleanup_rbuf 几乎没触发 / SOCK_SAMPLES 写入失败."
    );
    assert!(
        out_v > segs_out_floor,
        "testing flow segs_out = {out_v},低于 lo MTU={mtu} 推导的下限(>{segs_out_floor}).\n\
         过低通常意味着 tp->segs_out 偏移读错字段 / SOCK_SAMPLES 没更新到 conn 后期."
    );
    eprintln!(
        "[segs] testing flow segs_in={in_v} segs_out={out_v} (✓ 双向流量被精准采到)"
    );

    eprintln!("[PASS] srtt + segs 在真实流量 + 50ms netem delay 下均符合预期");
}
