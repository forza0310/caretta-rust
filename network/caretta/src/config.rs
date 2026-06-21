//! Runtime configuration parsing and defaults for the Caretta userspace binary.

use clap::Parser;
use log::warn;
use std::collections::{HashMap, HashSet};

const DEFAULT_PROMETHEUS_ENDPOINT: &str = "/metrics";
const DEFAULT_PROMETHEUS_PORT: u16 = 7117;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
const DEFAULT_DEBUG_RESOLVER_ENDPOINT: &str = "/debug/resolver";
const DEFAULT_DEBUG_RESOLVER_ENABLED: bool = false;
const DEFAULT_RESOLVE_DNS: bool = true;
const DEFAULT_DNS_CACHE_SIZE: usize = 10000;
const DEFAULT_MAX_LINKS: usize = 100000;
const DEFAULT_MAX_TCP_STATES: usize = 100000;
const DEFAULT_TRAVERSE_UP_HIERARCHY: bool = true;
const DEFAULT_OWNER_RESOLVE_KIND_ALLOWLIST: &str = "";
const DEFAULT_OWNER_KIND_PRIORITY: &str = "";

#[derive(Debug, Clone, Parser)]
pub struct Opt {
    #[clap(long, default_value_t = DEFAULT_PROMETHEUS_PORT)]
    pub prometheus_port: u16,
    #[clap(long, default_value = DEFAULT_PROMETHEUS_ENDPOINT)]
    pub prometheus_endpoint: String,
    #[clap(long, default_value_t = DEFAULT_POLL_INTERVAL_SECS)]
    pub poll_interval: u64,
    #[clap(long, default_value_t = DEFAULT_DEBUG_RESOLVER_ENABLED)]
    pub debug_resolver_enabled: bool,
    #[clap(long, default_value = DEFAULT_DEBUG_RESOLVER_ENDPOINT)]
    pub debug_resolver_endpoint: String,
    #[clap(long, default_value_t = DEFAULT_RESOLVE_DNS)]
    pub resolve_dns: bool,
    #[clap(long, default_value_t = DEFAULT_DNS_CACHE_SIZE)]
    pub dns_cache_size: usize,
    #[clap(long, default_value_t = DEFAULT_MAX_LINKS)]
    pub max_links: usize,
    #[clap(long, default_value_t = DEFAULT_MAX_TCP_STATES)]
    pub max_tcp_states: usize,
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

    /// Merge CLI defaults with environment variables to keep compatibility with caretta-go style config.
    pub fn from_env_and_args() -> Self {
        let mut opt = Self::parse();

        if let Ok(v) = std::env::var("PROMETHEUS_PORT") {
            match v.parse::<u16>() {
                Ok(p) => opt.prometheus_port = p,
                Err(_) => Self::warn_invalid_env("PROMETHEUS_PORT", &v, "u16"),
            }
        }
        if let Ok(v) = std::env::var("PROMETHEUS_ENDPOINT") {
            if !v.is_empty() {
                opt.prometheus_endpoint = v;
            }
        }
        if let Ok(v) = std::env::var("POLL_INTERVAL") {
            match v.parse::<u64>() {
                Ok(i) => opt.poll_interval = i.max(1),
                Err(_) => Self::warn_invalid_env("POLL_INTERVAL", &v, "u64"),
            }
        }
        if let Ok(v) = std::env::var("DEBUG_RESOLVER_ENABLED") {
            match v.parse::<bool>() {
                Ok(enabled) => opt.debug_resolver_enabled = enabled,
                Err(_) => Self::warn_invalid_env("DEBUG_RESOLVER_ENABLED", &v, "bool"),
            }
        }
        if let Ok(v) = std::env::var("DEBUG_RESOLVER_ENDPOINT") {
            if !v.is_empty() {
                opt.debug_resolver_endpoint = v;
            }
        }
        if let Ok(v) = std::env::var("RESOLVE_DNS") {
            match v.parse::<bool>() {
                Ok(enabled) => opt.resolve_dns = enabled,
                Err(_) => Self::warn_invalid_env("RESOLVE_DNS", &v, "bool"),
            }
        }
        if let Ok(v) = std::env::var("DNS_CACHE_SIZE") {
            match v.parse::<usize>() {
                Ok(size) => opt.dns_cache_size = size.max(1),
                Err(_) => Self::warn_invalid_env("DNS_CACHE_SIZE", &v, "usize"),
            }
        }
        if let Ok(v) = std::env::var("MAX_LINKS") {
            match v.parse::<usize>() {
                Ok(size) => opt.max_links = size.max(1),
                Err(_) => Self::warn_invalid_env("MAX_LINKS", &v, "usize"),
            }
        }
        if let Ok(v) = std::env::var("MAX_TCP_STATES") {
            match v.parse::<usize>() {
                Ok(size) => opt.max_tcp_states = size.max(1),
                Err(_) => Self::warn_invalid_env("MAX_TCP_STATES", &v, "usize"),
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

    pub fn normalized_debug_resolver_endpoint(&self) -> String {
        if self.debug_resolver_endpoint.starts_with('/') {
            self.debug_resolver_endpoint.clone()
        } else {
            format!("/{}", self.debug_resolver_endpoint)
        }
    }
}
