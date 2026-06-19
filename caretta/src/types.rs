//! Shared data model for eBPF map values, resolved workloads, and graph entities.

pub use crate::per_cpu::{ConnectionThroughputStats, aggregate_per_cpu_throughput};
use crate::resolver::IpResolver;
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
    pub pid: u32,
    pub tuple: ConnectionTuple,
    pub role: u32,
}

/// 与 caretta-ebpf `SockOffsets` 一一对应:eBPF 端按这些 byte offset 从 `struct sock *`
/// 走 `bpf_probe_read_kernel` 读 sock_common 字段。
///
/// 字段语义见 `caretta-ebpf/src/main.rs` 的同名结构体注释:
///   - `skc_daddr_off`     → 对端 IP   (__be32)
///   - `skc_rcv_saddr_off` → 本端 IP   (__be32)
///   - `skc_dport_off`     → 对端 port (__be16)
///   - `skc_num_off`       → 本端 port (host order u16)
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SockOffsets {
    pub skc_daddr_off: u32,
    pub skc_rcv_saddr_off: u32,
    pub skc_dport_off: u32,
    pub skc_num_off: u32,
}

unsafe impl aya::Pod for ConnectionTuple {}
unsafe impl aya::Pod for ConnectionIdentifier {}
unsafe impl aya::Pod for ConnectionThroughputStats {}
unsafe impl aya::Pod for SockOffsets {}

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
    is_active: u64,
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

    if is_active == 0 {
        connection.state = TCP_CONNECTION_CLOSED_STATE;
    }

    // throughput 字段在这里没直接用——它对外只承担"被收割聚合后传上来"的语义。但保留
    // 参数让上层调用点显式把"这条连接的吞吐快照"和"它的活跃状态"一起传下来,
    // 以后需要在 TcpConnection 上加吞吐字段时不用再改签名。
    let _ = throughput;

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
        };

        let tcp = reduce_connection_to_tcp(&resolver, conn, throughput, 0)
            .await
            .expect("tcp reduction should succeed");
        assert_eq!(tcp.state, TCP_CONNECTION_CLOSED_STATE);
    }
}
