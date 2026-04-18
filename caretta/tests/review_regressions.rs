use std::fs;
use std::path::PathBuf;

// Integration-level source assertions that lock in fixes for previously reviewed regressions.

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("caretta crate should have workspace parent")
        .to_path_buf()
}

fn read_repo_file(path_from_repo_root: &str) -> String {
    let path = repo_root().join(path_from_repo_root);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

    // Ensures close-path key lookup cannot drift from open-path key construction.
#[test]
    fn should_use_socket_lookup_key_when_closing_connection() {
    let src = read_repo_file("caretta-ebpf/src/main.rs");

    assert!(
        src.contains("fn mark_connection_closed(skaddr: u64)"),
        "close helper should only need skaddr"
    );
    assert!(
        src.contains("SOCK_TO_CONNECTION.get(&skaddr)"),
        "close path should look up original key from SOCK_TO_CONNECTION"
    );
    assert!(
        !src.contains("pid: 0,"),
        "close path should not construct a pid=0 key"
    );
}

// Ensures byte counters only reflect tcp_sendmsg/tcp_cleanup_rbuf accounting paths.
#[test]
fn should_not_mutate_byte_counters_when_processing_state_transition() {
    let src = read_repo_file("caretta-ebpf/src/main.rs");

    assert!(
        !src.contains("throughput.bytes_sent = throughput.bytes_sent.saturating_add(1);"),
        "state transition should not add synthetic bytes_sent"
    );
}

// Ensures resolver refresh signaling remains bounded under watch-event bursts.
#[test]
fn should_coalesce_refresh_signals_when_watch_events_burst() {
    let src = read_repo_file("caretta/src/resolver.rs");

    assert!(
        src.contains("mpsc::channel::<()>(1)"),
        "resolver refresh queue should be bounded to 1"
    );
    assert!(
        src.contains("tx.try_send(())"),
        "watch event handler should coalesce by try_send"
    );
    assert!(
        !src.contains("mpsc::unbounded_channel::<()>()"),
        "unbounded refresh queue should not be used"
    );
}

// Ensures metric help text matches runtime aggregation semantics.
#[test]
fn should_describe_bidirectional_bytes_in_links_metric_help_text() {
    let src = read_repo_file("caretta/src/metrics.rs");

    assert!(
        src.contains("bytes_sent + bytes_received"),
        "metric help text should describe the actual aggregation"
    );
}

// Ensures userspace link aggregation keeps bidirectional throughput behavior.
#[test]
fn should_aggregate_sent_and_received_bytes_in_userspace_poll_loop() {
    let src = read_repo_file("caretta/src/main.rs");

    assert!(
        src.contains("throughput.bytes_sent.saturating_add(throughput.bytes_received)"),
        "poll loop should aggregate sent+received bytes into link throughput"
    );
}

// Ensures closed entries are both detected and removed during userspace polling.
#[test]
fn should_mark_and_delete_inactive_entries_in_userspace_poll_loop() {
    let src = read_repo_file("caretta/src/main.rs");

    assert!(
        src.contains("if throughput.is_active == 0") && src.contains("to_delete.push(conn)"),
        "poll loop should identify inactive entries for deletion"
    );
    assert!(
        src.contains("connections.remove(&conn)"),
        "poll loop should remove inactive entries from the eBPF map"
    );
}
