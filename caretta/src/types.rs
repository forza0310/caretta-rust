//! Shared data model for eBPF map values, resolved workloads, and graph entities.

use crate::resolver::IpResolver;
use anyhow::Context as _;
use std::fmt;
use std::net::Ipv4Addr;

pub const ROLE_CLIENT: u32 = 1;
pub const ROLE_SERVER: u32 = 2;

pub const TCP_CONNECTION_OPEN_STATE: u32 = 1;
pub const TCP_CONNECTION_ACCEPT_STATE: u32 = 2;
pub const TCP_CONNECTION_CLOSED_STATE: u32 = 3;

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Default)]
pub struct ConnectionTuple {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Default)]
pub struct ConnectionIdentifier {
    pub id: u32,
    pub pid: u32,
    pub tuple: ConnectionTuple,
    pub role: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct ConnectionThroughputStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub is_active: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct TraceOffsets {
    pub skaddr_off: u32,
    pub newstate_off: u32,
    pub sport_off: u32,
    pub dport_off: u32,
    pub saddr_off: u32,
    pub daddr_off: u32,
}

unsafe impl aya::Pod for ConnectionTuple {}
unsafe impl aya::Pod for ConnectionIdentifier {}
unsafe impl aya::Pod for ConnectionThroughputStats {}
unsafe impl aya::Pod for TraceOffsets {}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Workload {
    pub name: String,
    pub namespace: String,
    pub kind: String,
    pub owner: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct NetworkLink {
    pub client: Workload,
    pub server: Workload,
    pub client_ip: String,
    pub server_ip: String,
    pub server_port: u16,
    pub role: u32,
}

#[derive(Clone, Debug)]
pub struct TcpConnection {
    pub client: Workload,
    pub server: Workload,
    pub server_port: u16,
    pub role: u32,
    pub state: u32,
}

/// 用于跟踪单条 TCP series 生命周期的稳定 key。
///
/// 为什么要单独再造一个 key 类型而不直接拿 `TcpConnection` 当 HashMap key：
///   - `TcpConnection` 含 `state` 字段，state 在同一条连接上会变（OPEN→CLOSED）；
///     直接做 key 会让"同一条连接的不同 state"被记成两条不同 entry，GC 表里会
///     堆出冗余项，更糟的是 forget 时可能漏删某些 state 的 series。
///   - GC 真正关心的"这条 series 是否还活着"由 client/server/server_port/role
///     这五个维度决定（与 `caretta_tcp_states` 的 label 集对应），其他都是数据。
///
/// 派生 Eq/Hash 让它可以直接当 HashMap key 使。
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TcpConnectionKey {
    pub client: Workload,
    pub server: Workload,
    pub server_port: u16,
    pub role: u32,
}

impl From<&TcpConnection> for TcpConnectionKey {
    fn from(conn: &TcpConnection) -> Self {
        Self {
            client: conn.client.clone(),
            server: conn.server.clone(),
            server_port: conn.server_port,
            role: conn.role,
        }
    }
}

impl fmt::Display for NetworkLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({} {}) -> {}({} {}:{}) role={}",
            self.client.name,
            self.client.namespace,
            self.client_ip,
            self.server.name,
            self.server.namespace,
            self.server_ip,
            self.server_port,
            self.role
        )
    }
}

/// Reduce a directional connection tuple into a normalized client->server link.
///
/// 现在是 async：内部对 src/dst 两个 IP 并发 resolve_ip。两次 K8s 缓存命中在 ~µs 级；
/// 命中 fallback 走 DNS 时 .await 让出 task 而不是阻塞线程，最坏单次时延受
/// DnsCache::DNS_LOOKUP_TIMEOUT 上限保护。
pub async fn reduce_connection_to_link(
    resolver: &dyn IpResolver,
    conn: ConnectionIdentifier,
) -> anyhow::Result<NetworkLink> {
    let (src, dst) = tokio::join!(
        resolver.resolve_ip(conn.tuple.src_ip),
        resolver.resolve_ip(conn.tuple.dst_ip),
    );

    match conn.role {
        ROLE_CLIENT => Ok(NetworkLink {
            client: src,
            server: dst,
            client_ip: Ipv4Addr::from(conn.tuple.src_ip).to_string(),
            server_ip: Ipv4Addr::from(conn.tuple.dst_ip).to_string(),
            server_port: conn.tuple.dst_port,
            role: conn.role,
        }),
        ROLE_SERVER => Ok(NetworkLink {
            client: dst,
            server: src,
            client_ip: Ipv4Addr::from(conn.tuple.dst_ip).to_string(),
            server_ip: Ipv4Addr::from(conn.tuple.src_ip).to_string(),
            server_port: conn.tuple.src_port,
            role: conn.role,
        }),
        _ => anyhow::bail!("unknown connection role"),
    }
}

/// Build a TCP connection state view from eBPF tuple+throughput data.
pub async fn reduce_connection_to_tcp(
    resolver: &dyn IpResolver,
    conn: ConnectionIdentifier,
    throughput: ConnectionThroughputStats,
) -> anyhow::Result<TcpConnection> {
    let (src, dst) = tokio::join!(
        resolver.resolve_ip(conn.tuple.src_ip),
        resolver.resolve_ip(conn.tuple.dst_ip),
    );

    let mut connection = match conn.role {
        ROLE_CLIENT => TcpConnection {
            client: src,
            server: dst,
            server_port: conn.tuple.dst_port,
            role: conn.role,
            state: TCP_CONNECTION_OPEN_STATE,
        },
        ROLE_SERVER => TcpConnection {
            client: dst,
            server: src,
            server_port: conn.tuple.src_port,
            role: conn.role,
            state: TCP_CONNECTION_ACCEPT_STATE,
        },
        _ => anyhow::bail!("unknown connection role"),
    };

    if throughput.is_active == 0 {
        connection.state = TCP_CONNECTION_CLOSED_STATE;
    }

    Ok(connection)
}

pub fn is_loopback(ip: u32) -> bool {
    std::net::Ipv4Addr::from(ip).is_loopback()
}

pub fn fnv_hash(s: &str) -> u32 {
    let mut hash = 0x811C9DC5u32;
    for b in s.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// 解析 `/sys/kernel/tracing/events/.../format` 文件，提取 caretta eBPF 程序需要的
/// 字段偏移。同一份 eBPF 字节码靠运行时读取这些偏移来适配不同内核版本——format
/// 文件就是内核暴露的"自描述"接口。
///
/// 解析做了两层防御（修 review 问题 5）：
///   1. **精确字段名匹配**：原实现用 `line.contains("saddr")`，会同时匹配 `saddr_v6`。
///      只是因为内核源码里 saddr 行恰好排在 saddr_v6 之前，substring + 第一行命中
///      取胜——这是巧合不是 ABI 保证。任何把 IPv6 字段提前的内核版本（出于对齐或
///      cache locality 优化）都会让 caretta 把 saddr_v6 高 4 字节当成 IPv4 saddr 读，
///      eBPF 抓到的 IP 全是垃圾、所有连接被归为 external。这种错误不会 crash，只会
///      让识别准确率悄悄垮掉。
///   2. **size 校验**：调用方传入预期 size，解析时同时核对。如果未来内核把 saddr
///      改成 16 字节联合字段、或者 sport 从 __u16 升级成 __u32 这种 ABI 变更，启动
///      就 bail——清晰失败 > 静默错误。
pub fn parse_tracepoint_offsets(path: &str) -> anyhow::Result<TraceOffsets> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read tracepoint format: {path}"))?;

    Ok(TraceOffsets {
        // skaddr 是指针，64-bit 内核上 8 字节、32-bit 上 4 字节。caretta 几乎只跑
        // 在 64-bit 上，但代码层面用 size_of::<*const u8>() 兜住极少数 32-bit 场景，
        // 让解析器在那种环境下也是"对的"而不是误报。
        skaddr_off: find_offset(&content, "skaddr", std::mem::size_of::<*const u8>() as u32)?,
        // newstate / oldstate 是 int —— Linux 上 sizeof(int) 在所有支持架构都是 4。
        newstate_off: find_offset(&content, "newstate", 4)?,
        // sport / dport 是 __u16，固定 2 字节。
        sport_off: find_offset(&content, "sport", 2)?,
        dport_off: find_offset(&content, "dport", 2)?,
        // saddr / daddr 是 __u8[4]，IPv4 地址固定 4 字节。这条 size 约束正是用来挡住
        // "saddr substring 匹配到 saddr_v6 (size=16)" 的核心防线——即使匹配真的漂到了
        // saddr_v6 行，size 校验也会立刻 bail。
        saddr_off: find_offset(&content, "saddr", 4)?,
        daddr_off: find_offset(&content, "daddr", 4)?,
    })
}

/// 从 format 文件的一行里提取 (字段名, offset, size)，按精确字段名匹配过滤。
///
/// format 文件每行结构（示例）：
/// ```text
///         field:__u8 saddr[4];    offset:32;      size:4; signed:0;
/// ```
/// 拆解：以 `field:` 开头，紧跟 C 类型 + 字段名 + 可选 `[N]`（数组维度），以 `;`
/// 终止；之后按 `key:value;` 排列 offset / size / signed。
fn parse_field_line(line: &str) -> Option<(&str, u32, u32)> {
    // 必须包含 field:/offset:/size: 三段，缺一不可——避免误吃 print fmt 行或空行。
    if !line.contains("field:") || !line.contains("offset:") || !line.contains("size:") {
        return None;
    }

    // 字段名在 "field:" 与第一个 ";" 之间。
    let after_field = line.split("field:").nth(1)?;
    let decl = after_field.split(';').next()?.trim();
    // decl 形如 "__u8 saddr[4]" / "const void * skaddr" / "int common_pid"。
    // 字段名是声明里"最后一个 identifier"——按空白和 `*` 拆完拿最后非空段，再剥
    // 掉数组维度 `[N]` 即可。
    let last_token = decl
        .rsplit(|c: char| c.is_ascii_whitespace() || c == '*')
        .find(|s| !s.is_empty())?;
    let field_name = match last_token.find('[') {
        Some(pos) => &last_token[..pos],
        None => last_token,
    };

    let offset = extract_uint_after(line, "offset:")?;
    let size = extract_uint_after(line, "size:")?;
    Some((field_name, offset, size))
}

/// 从 line 里找第一处 `key`，跳过空白后取连续数字解析为 u32。
fn extract_uint_after(line: &str, key: &str) -> Option<u32> {
    let pos = line.find(key)?;
    let rest = &line[pos + key.len()..];
    let digits: String = rest
        .chars()
        .skip_while(|c| c.is_ascii_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u32>().ok()
}

/// 在 format 文件里精确匹配字段名，校验 size，返回 offset。
fn find_offset(content: &str, field_name: &str, expected_size: u32) -> anyhow::Result<u32> {
    for line in content.lines() {
        let Some((name, offset, size)) = parse_field_line(line) else {
            continue;
        };
        if name != field_name {
            continue;
        }
        // size 不符 = 内核把这个字段的语义改了。继续按旧 offset 读会拿到垃圾值，
        // 不如启动就 bail，让运维一眼看到具体哪里不兼容。
        if size != expected_size {
            anyhow::bail!(
                "tracepoint field {field_name} has unexpected size {size} \
                 (expected {expected_size}); kernel layout may have changed"
            );
        }
        return Ok(offset);
    }
    anyhow::bail!("field offset not found in tracepoint format: {field_name}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::IpResolver;
    use async_trait::async_trait;

    struct MockResolver;

    #[async_trait]
    impl IpResolver for MockResolver {
        async fn resolve_ip(&self, ip: u32) -> Workload {
            Workload {
                name: format!("ip-{ip}"),
                namespace: "ns".to_string(),
                kind: "Mock".to_string(),
                owner: String::new(),
            }
        }
    }

    // Ensures client-role tuples keep direction: src is client, dst is server.
    #[tokio::test]
    async fn should_map_src_to_client_when_role_is_client() {
        let resolver = MockResolver;
        let conn = ConnectionIdentifier {
            id: 1,
            pid: 10,
            tuple: ConnectionTuple {
                src_ip: 1,
                dst_ip: 2,
                src_port: 1000,
                dst_port: 2000,
            },
            role: ROLE_CLIENT,
        };

        let link = reduce_connection_to_link(&resolver, conn)
            .await
            .expect("client role should map");
        assert_eq!(link.client.name, "ip-1");
        assert_eq!(link.server.name, "ip-2");
        assert_eq!(link.client_ip, "0.0.0.1");
        assert_eq!(link.server_ip, "0.0.0.2");
        assert_eq!(link.server_port, 2000);
    }

    // Ensures server-role tuples are normalized into client->server orientation.
    #[tokio::test]
    async fn should_map_dst_to_client_when_role_is_server() {
        let resolver = MockResolver;
        let conn = ConnectionIdentifier {
            id: 2,
            pid: 20,
            tuple: ConnectionTuple {
                src_ip: 1,
                dst_ip: 2,
                src_port: 3000,
                dst_port: 4000,
            },
            role: ROLE_SERVER,
        };

        let link = reduce_connection_to_link(&resolver, conn)
            .await
            .expect("server role should map");
        assert_eq!(link.client.name, "ip-2");
        assert_eq!(link.server.name, "ip-1");
        assert_eq!(link.client_ip, "0.0.0.2");
        assert_eq!(link.server_ip, "0.0.0.1");
        assert_eq!(link.server_port, 3000);
    }

    // Guards against silently accepting unknown role values.
    #[tokio::test]
    async fn should_return_error_when_role_is_unknown() {
        let resolver = MockResolver;
        let conn = ConnectionIdentifier {
            id: 3,
            pid: 30,
            tuple: ConnectionTuple::default(),
            role: 999,
        };

        assert!(reduce_connection_to_link(&resolver, conn).await.is_err());
    }

    // Verifies inactive entries are exposed as CLOSED in TCP state view.
    #[tokio::test]
    async fn should_mark_tcp_state_closed_when_entry_is_inactive() {
        let resolver = MockResolver;
        let conn = ConnectionIdentifier {
            id: 4,
            pid: 40,
            tuple: ConnectionTuple {
                src_ip: 10,
                dst_ip: 20,
                src_port: 1234,
                dst_port: 4321,
            },
            role: ROLE_CLIENT,
        };
        let throughput = ConnectionThroughputStats {
            bytes_sent: 1,
            bytes_received: 2,
            is_active: 0,
        };

        let tcp = reduce_connection_to_tcp(&resolver, conn, throughput)
            .await
            .expect("tcp reduction should succeed");
        assert_eq!(tcp.state, TCP_CONNECTION_CLOSED_STATE);
    }

    // ---- review 问题 5：tracepoint 字段解析的精确性 ----
    //
    // 这一组 fixture 测试覆盖 parse_tracepoint_offsets 的边界。format 文件就是字符
    // 串，写 fixture 零成本——测试性价比最高的地方。

    /// 当前内核（cbw 这台 ecm-1280）实际抓到的 inet_sock_set_state layout。
    /// 把它当 baseline：日常 happy path 必须能解析出已知 offset/size 组合。
    /// 未来某天升级内核如果偏移变了，本测试不会失败（因为它只验当前 layout 是否被
    /// 正确解析），但 reverse_layout 那条会保护反序场景。
    const FIXTURE_CURRENT_KERNEL: &str = "\
name: inet_sock_set_state
ID: 1603
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:const void * skaddr;      offset:8;       size:8; signed:0;
        field:int oldstate;     offset:16;      size:4; signed:1;
        field:int newstate;     offset:20;      size:4; signed:1;
        field:__u16 sport;      offset:24;      size:2; signed:0;
        field:__u16 dport;      offset:26;      size:2; signed:0;
        field:__u16 family;     offset:28;      size:2; signed:0;
        field:__u16 protocol;   offset:30;      size:2; signed:0;
        field:__u8 saddr[4];    offset:32;      size:4; signed:0;
        field:__u8 daddr[4];    offset:36;      size:4; signed:0;
        field:__u8 saddr_v6[16];        offset:40;      size:16;        signed:0;
        field:__u8 daddr_v6[16];        offset:56;      size:16;        signed:0;
";

    // happy path：已知 layout 必须解出已知偏移。这是 regression baseline——升级内核
    // 后如果哪个 caretta 关心的字段被悄悄移走，下面任一断言都会响。
    #[test]
    fn should_parse_offsets_from_current_kernel_layout() {
        let off = find_offset(FIXTURE_CURRENT_KERNEL, "saddr", 4)
            .expect("saddr should resolve");
        assert_eq!(off, 32);
        let off = find_offset(FIXTURE_CURRENT_KERNEL, "daddr", 4)
            .expect("daddr should resolve");
        assert_eq!(off, 36);
        let off = find_offset(FIXTURE_CURRENT_KERNEL, "sport", 2)
            .expect("sport should resolve");
        assert_eq!(off, 24);
        let off = find_offset(FIXTURE_CURRENT_KERNEL, "newstate", 4)
            .expect("newstate should resolve");
        assert_eq!(off, 20);
    }

    // 反序 layout：假设未来某个内核版本（或 distro patch）把 saddr_v6 排到 saddr
    // 之前。原实现 substring 匹配会返回 saddr_v6 的偏移，eBPF 把 IPv6 高 4 字节当
    // IPv4 saddr 读——caretta 表面看就是"识别不出集群内 IP"。修复后必须挑出真正的
    // saddr 那一行。
    //
    // 这是 review 问题 5 的核心场景。如果不修，下面的断言会拿到 47 而不是 51。
    #[test]
    fn should_pick_saddr_when_v6_field_appears_first() {
        const REVERSED: &str = "\
        field:__u8 saddr_v6[16];        offset:31;      size:16; signed:0;
        field:__u8 daddr_v6[16];        offset:47;      size:16; signed:0;
        field:__u8 saddr[4];            offset:63;      size:4;  signed:0;
        field:__u8 daddr[4];            offset:67;      size:4;  signed:0;
";
        let off =
            find_offset(REVERSED, "saddr", 4).expect("saddr should resolve to its own line");
        assert_eq!(off, 63, "must skip saddr_v6 and find the real saddr");
        let off =
            find_offset(REVERSED, "daddr", 4).expect("daddr should resolve to its own line");
        assert_eq!(off, 67, "must skip daddr_v6 and find the real daddr");
    }

    // size 校验：如果某天内核把 saddr 改成 16 字节联合字段（IPv4/IPv6 复用）或者
    // sport 升宽到 __u32，size 不再匹配。这种情况启动就 bail，比静默读垃圾好。
    #[test]
    fn should_bail_when_field_size_changed() {
        const HYPOTHETICAL: &str = "\
        field:__u8 saddr[16];   offset:32;      size:16; signed:0;
";
        let err = find_offset(HYPOTHETICAL, "saddr", 4)
            .expect_err("size mismatch must bail, not silently return offset");
        let msg = format!("{err}");
        assert!(
            msg.contains("unexpected size"),
            "error message should explain the size mismatch, got: {msg}"
        );
    }

    // 字段彻底缺失：format 文件里压根没有期望的字段。比 substring 模式更严格——
    // 原实现可能在某些前缀冲突场景 substring 命中错的字段；新实现命中不了任何字段
    // 就如实 bail。
    #[test]
    fn should_bail_when_field_is_absent() {
        const WITHOUT_SADDR: &str = "\
        field:__u16 sport;      offset:24;      size:2; signed:0;
";
        assert!(find_offset(WITHOUT_SADDR, "saddr", 4).is_err());
    }

    // 防止前缀污染：保证带 saddr 子串的其它字段（real_world 无此例，但属于通用
    // robustness）不会被错认成 saddr。这条直接钉住 parse_field_line 用的是精确名
    // 匹配而不是 substring。
    #[test]
    fn should_not_match_field_with_saddr_substring() {
        const WITH_LOOKALIKE: &str = "\
        field:__u8 not_saddr_really[4];   offset:32;      size:4;  signed:0;
        field:__u8 saddr[4];              offset:48;      size:4;  signed:0;
";
        let off =
            find_offset(WITH_LOOKALIKE, "saddr", 4).expect("real saddr should still resolve");
        assert_eq!(
            off, 48,
            "must skip lookalike field name and find the exact saddr"
        );
    }

    // print fmt 行里也含 saddr 字样（"saddr=%pI4 ..."），但没有 field:/offset:/size:
    // 三件套，必须被 parse_field_line 过滤掉，不能误当成字段行解析。
    #[test]
    fn should_ignore_print_fmt_line_with_field_name_substring() {
        const WITH_PRINT_FMT: &str = "\
        field:__u8 saddr[4];    offset:32;      size:4; signed:0;
print fmt: \"saddr=%pI4 daddr=%pI4\", REC->saddr, REC->daddr
";
        let off = find_offset(WITH_PRINT_FMT, "saddr", 4).expect("saddr should resolve");
        assert_eq!(off, 32);
    }
}
