# Caretta eBPF Data Collection

This document describes the raw data captured by the eBPF side of the Rust userspace project and the kernel hook types used to capture it.

## Raw Data Captured

The eBPF program captures the following raw kernel data:

- TCP socket state transitions from `sock/inet_sock_set_state`
- Socket address identity via the kernel `struct sock *`
- TCP source and destination ports
- TCP source and destination IPv4 addresses
- TCP send-side byte counts from `tcp_sendmsg`
- TCP receive-side byte counts from `tcp_cleanup_rbuf`
- Connection liveness through `is_active`
- Current process id when a connection key is first created

## Kernel Hook Types

The current implementation uses:

1. kprobes
- `tcp_sendmsg`
- `tcp_cleanup_rbuf`

2. tracepoints
- `sock/inet_sock_set_state`

## How the Data Is Used

- `tcp_sendmsg` contributes to `bytes_sent`.
- `tcp_cleanup_rbuf` contributes to `bytes_received`.
- `inet_sock_set_state` provides the tuple and TCP role used to create or update the connection record.
- `sock->connection` mapping is used to close the exact connection entry that was previously opened for a socket.

## Why This Matters

These hooks separate raw socket activity from userspace aggregation:

- The eBPF side collects per-socket, per-connection facts.
- The userspace side resolves IPs into workloads and exports metrics.
- Tests in `caretta/tests/review_regressions.rs` protect the lifecycle and aggregation behavior.
