//! 配置解析不变量:环境变量解析失败必须打 warn,不能静默 fallback。

use std::fs;
use std::path::PathBuf;

fn read_config() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("caretta/src/config.rs");
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn should_warn_when_env_var_parse_fails() {
    let src = read_config();

    assert!(
        src.contains("use log::warn"),
        "config parsing should be able to emit warn logs"
    );
    assert!(
        src.contains("fn warn_invalid_env(") && src.contains("could not be parsed"),
        "config parsing should centralize invalid env warnings"
    );
    for name in [
        "PROMETHEUS_PORT",
        "POLL_INTERVAL",
        "DEBUG_RESOLVER_ENABLED",
        "RESOLVE_DNS",
        "DNS_CACHE_SIZE",
        "MAX_LINKS",
        "TRAVERSE_UP_HIERARCHY",
    ] {
        assert!(
            src.contains(&format!("Self::warn_invalid_env(\"{name}\"")),
            "{name} parse failure should warn instead of silently falling back"
        );
    }
}
