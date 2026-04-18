//! Shared data model for eBPF map values, resolved workloads, and graph entities.

use crate::resolver::IpResolver;
use anyhow::Context as _;
use std::fmt;

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

impl fmt::Display for NetworkLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({}) -> {}({}) : {} role={}",
            self.client.name,
            self.client.namespace,
            self.server.name,
            self.server.namespace,
            self.server_port,
            self.role
        )
    }
}

/// Reduce a directional connection tuple into a normalized client->server link.
pub fn reduce_connection_to_link(
    resolver: &dyn IpResolver,
    conn: ConnectionIdentifier,
) -> anyhow::Result<NetworkLink> {
    let src = resolver.resolve_ip(conn.tuple.src_ip);
    let dst = resolver.resolve_ip(conn.tuple.dst_ip);

    match conn.role {
        ROLE_CLIENT => Ok(NetworkLink {
            client: src,
            server: dst,
            server_port: conn.tuple.dst_port,
            role: conn.role,
        }),
        ROLE_SERVER => Ok(NetworkLink {
            client: dst,
            server: src,
            server_port: conn.tuple.src_port,
            role: conn.role,
        }),
        _ => anyhow::bail!("unknown connection role"),
    }
}

/// Build a TCP connection state view from eBPF tuple+throughput data.
pub fn reduce_connection_to_tcp(
    resolver: &dyn IpResolver,
    conn: ConnectionIdentifier,
    throughput: ConnectionThroughputStats,
) -> anyhow::Result<TcpConnection> {
    let src = resolver.resolve_ip(conn.tuple.src_ip);
    let dst = resolver.resolve_ip(conn.tuple.dst_ip);

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

pub fn parse_tracepoint_offsets(path: &str) -> anyhow::Result<TraceOffsets> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read tracepoint format: {path}"))?;

    fn find_offset(content: &str, field_name: &str) -> anyhow::Result<u32> {
        for line in content.lines() {
            if !line.contains("field:") || !line.contains(field_name) || !line.contains("offset:") {
                continue;
            }
            if let Some(pos) = line.find("offset:") {
                let rest = &line[(pos + "offset:".len())..];
                let digits: String = rest
                    .chars()
                    .skip_while(|c| c.is_ascii_whitespace())
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if !digits.is_empty() {
                    return digits
                        .parse::<u32>()
                        .with_context(|| format!("invalid offset for field {field_name}"));
                }
            }
        }
        anyhow::bail!("field offset not found in tracepoint format: {field_name}")
    }

    Ok(TraceOffsets {
        skaddr_off: find_offset(&content, "skaddr")?,
        newstate_off: find_offset(&content, "newstate")?,
        sport_off: find_offset(&content, "sport")?,
        dport_off: find_offset(&content, "dport")?,
        saddr_off: find_offset(&content, "saddr")?,
        daddr_off: find_offset(&content, "daddr")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::IpResolver;

    struct MockResolver;

    impl IpResolver for MockResolver {
        fn resolve_ip(&self, ip: u32) -> Workload {
            Workload {
                name: format!("ip-{ip}"),
                namespace: "ns".to_string(),
                kind: "Mock".to_string(),
                owner: String::new(),
            }
        }
    }

    // Ensures client-role tuples keep direction: src is client, dst is server.
    #[test]
    fn should_map_src_to_client_when_role_is_client() {
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

        let link = reduce_connection_to_link(&resolver, conn).expect("client role should map");
        assert_eq!(link.client.name, "ip-1");
        assert_eq!(link.server.name, "ip-2");
        assert_eq!(link.server_port, 2000);
    }

    // Ensures server-role tuples are normalized into client->server orientation.
    #[test]
    fn should_map_dst_to_client_when_role_is_server() {
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

        let link = reduce_connection_to_link(&resolver, conn).expect("server role should map");
        assert_eq!(link.client.name, "ip-2");
        assert_eq!(link.server.name, "ip-1");
        assert_eq!(link.server_port, 3000);
    }

    // Guards against silently accepting unknown role values.
    #[test]
    fn should_return_error_when_role_is_unknown() {
        let resolver = MockResolver;
        let conn = ConnectionIdentifier {
            id: 3,
            pid: 30,
            tuple: ConnectionTuple::default(),
            role: 999,
        };

        assert!(reduce_connection_to_link(&resolver, conn).is_err());
    }

    // Verifies inactive entries are exposed as CLOSED in TCP state view.
    #[test]
    fn should_mark_tcp_state_closed_when_entry_is_inactive() {
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
            .expect("tcp reduction should succeed");
        assert_eq!(tcp.state, TCP_CONNECTION_CLOSED_STATE);
    }
}
