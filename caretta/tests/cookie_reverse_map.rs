//! sock cookie / SOCK_TO_CONNECTION 反查表的不变量。
//!
//! 背景:`struct sock` 是 slab 分配的,close 后内核会把同一片地址重分配给新连接,
//! 旧 close 与新 sendmsg 串扰。修法是用 `bpf_get_socket_cookie()` 取一生一码的
//! cookie 替代 raw `struct sock *` 地址做反查 key(kernel ≥ 5.7)。
//!
//! 这套守卫钉死:
//!   - cookie helper 真的被引入,反查路径全部走 cookie 而非 skaddr;
//!   - cookie==0(helper 不可用 / sock NULL)时直接 return,不让多个 sock 都映射到 0;
//!   - close 路径用 cookie 反查得到原 key,而不是构造一个 pid=0 的伪 key。

use std::fs;
use std::path::PathBuf;

fn read_ebpf_main() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("caretta-ebpf/src/main.rs");
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn should_use_socket_lookup_key_when_closing_connection() {
    let src = read_ebpf_main();

    assert!(
        src.contains("fn mark_connection_closed(cookie: u64)"),
        "close helper should look up the original key by sock cookie"
    );
    assert!(
        src.contains("SOCK_TO_CONNECTION.get(&cookie)"),
        "close path should look up original key from SOCK_TO_CONNECTION"
    );
    assert!(
        !src.contains("pid: 0,"),
        "close path should not construct a pid=0 key"
    );
}

#[test]
fn should_key_socket_reverse_map_by_cookie_not_raw_address() {
    let src = read_ebpf_main();

    assert!(
        src.contains("bpf_get_socket_cookie"),
        "ebpf prog should call bpf_get_socket_cookie helper"
    );
    assert!(
        src.contains("fn sock_cookie(skaddr: u64) -> u64"),
        "ebpf prog should expose a sock_cookie() wrapper"
    );
    assert!(
        src.contains("SOCK_TO_CONNECTION.insert(&cookie, &key, 0)"),
        "open path should insert into SOCK_TO_CONNECTION keyed by cookie"
    );
    // close + sendmsg + recvmsg 三处都要先取 cookie 再查表。
    let lookups = src.matches("SOCK_TO_CONNECTION.get(&cookie)").count();
    assert!(
        lookups >= 3,
        "close + sendmsg + recvmsg should each look up by cookie (got {lookups})"
    );
    // 残留的 skaddr-as-key 用法必须拔除。
    assert!(
        !src.contains("SOCK_TO_CONNECTION.insert(&skaddr"),
        "no path should still insert into SOCK_TO_CONNECTION keyed by skaddr"
    );
    assert!(
        !src.contains("SOCK_TO_CONNECTION.get(&skaddr)"),
        "no path should still look up SOCK_TO_CONNECTION by skaddr"
    );
}

#[test]
fn should_skip_when_socket_cookie_is_unavailable() {
    let src = read_ebpf_main();

    // cookie==0 表示 helper 不可用或 sock NULL —— 直接 return,而不是把多 sock 都映射到 key=0。
    let zero_guards = src.matches("if cookie == 0 {").count();
    assert!(
        zero_guards >= 4,
        "every cookie consumer should bail out on cookie==0 (got {zero_guards})"
    );
}
