//! caretta-k8s-state 的运行配置:CLI flag(优先)+ 环境变量覆盖,与 caretta 同风格。

use clap::Parser;
use log::warn;
use std::collections::{HashMap, HashSet};

const DEFAULT_PROMETHEUS_ENDPOINT: &str = "/metrics";
// 默认 7118,刻意避开 caretta 的 7117,方便同机/同 namespace 共存。
const DEFAULT_PROMETHEUS_PORT: u16 = 7118;
// owners_index 周期重建的间隔(秒)。Event 的 involvedObject → workload 解析依赖它。
const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 30;
const DEFAULT_TRAVERSE_UP_HIERARCHY: bool = true;
const DEFAULT_OWNER_RESOLVE_KIND_ALLOWLIST: &str = "";
const DEFAULT_OWNER_KIND_PRIORITY: &str = "";

#[derive(Debug, Clone, Parser)]
pub struct Opt {
    #[clap(long, default_value_t = DEFAULT_PROMETHEUS_PORT)]
    pub prometheus_port: u16,
    #[clap(long, default_value = DEFAULT_PROMETHEUS_ENDPOINT)]
    pub prometheus_endpoint: String,
    #[clap(long, default_value_t = DEFAULT_REFRESH_INTERVAL_SECS)]
    pub refresh_interval: u64,
    #[clap(long, default_value_t = DEFAULT_TRAVERSE_UP_HIERARCHY)]
    pub traverse_up_hierarchy: bool,
    #[clap(long, default_value = DEFAULT_OWNER_RESOLVE_KIND_ALLOWLIST)]
    pub owner_resolve_kind_allowlist: String,
    #[clap(long, default_value = DEFAULT_OWNER_KIND_PRIORITY)]
    pub owner_kind_priority: String,
}

impl Opt {
    fn warn_invalid_env(name: &str, value: &str, expected: &str) {
        warn!(
            "env var {name}={value:?} could not be parsed as {expected}; falling back to default"
        );
    }

    fn parse_csv_values(raw: &str) -> Vec<String> {
        raw.split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string)
            .collect()
    }

    /// CLI flag 先 parse 成默认/显式值,再用环境变量覆盖,与 caretta 的配置习惯一致。
    pub fn from_env_and_args() -> Self {
        let mut opt = Self::parse();

        if let Ok(v) = std::env::var("PROMETHEUS_PORT") {
            match v.parse::<u16>() {
                Ok(p) => opt.prometheus_port = p,
                Err(_) => Self::warn_invalid_env("PROMETHEUS_PORT", &v, "u16"),
            }
        }
        if let Ok(v) = std::env::var("PROMETHEUS_ENDPOINT")
            && !v.is_empty()
        {
            opt.prometheus_endpoint = v;
        }
        if let Ok(v) = std::env::var("REFRESH_INTERVAL") {
            match v.parse::<u64>() {
                Ok(i) => opt.refresh_interval = i.max(1),
                Err(_) => Self::warn_invalid_env("REFRESH_INTERVAL", &v, "u64"),
            }
        }
        if let Ok(v) = std::env::var("TRAVERSE_UP_HIERARCHY") {
            match v.parse::<bool>() {
                Ok(enabled) => opt.traverse_up_hierarchy = enabled,
                Err(_) => Self::warn_invalid_env("TRAVERSE_UP_HIERARCHY", &v, "bool"),
            }
        }
        if let Ok(v) = std::env::var("OWNER_RESOLVE_KIND_ALLOWLIST") {
            opt.owner_resolve_kind_allowlist = v;
        }
        if let Ok(v) = std::env::var("OWNER_KIND_PRIORITY") {
            opt.owner_kind_priority = v;
        }

        opt
    }

    pub fn owner_kind_allowlist(&self) -> HashSet<String> {
        Self::parse_csv_values(&self.owner_resolve_kind_allowlist)
            .into_iter()
            .collect()
    }

    pub fn owner_kind_priority(&self) -> HashMap<String, usize> {
        Self::parse_csv_values(&self.owner_kind_priority)
            .into_iter()
            .enumerate()
            .map(|(idx, kind)| (kind, idx))
            .collect()
    }

    pub fn normalized_prometheus_endpoint(&self) -> String {
        if self.prometheus_endpoint.starts_with('/') {
            self.prometheus_endpoint.clone()
        } else {
            format!("/{}", self.prometheus_endpoint)
        }
    }
}
