//! Runtime configuration parsing and defaults for the Caretta userspace binary.

use clap::Parser;
use std::collections::{HashMap, HashSet};

const DEFAULT_PROMETHEUS_ENDPOINT: &str = "/metrics";
const DEFAULT_PROMETHEUS_PORT: u16 = 7117;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
const DEFAULT_DEBUG_RESOLVER_ENDPOINT: &str = "/debug/resolver";
const DEFAULT_DEBUG_RESOLVER_ENABLED: bool = false;
const DEFAULT_RESOLVE_DNS: bool = true;
const DEFAULT_DNS_CACHE_SIZE: usize = 10000;
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
    #[clap(long, default_value_t = DEFAULT_TRAVERSE_UP_HIERARCHY)]
    pub traverse_up_hierarchy: bool,
    #[clap(long, default_value = DEFAULT_OWNER_RESOLVE_KIND_ALLOWLIST)]
    pub owner_resolve_kind_allowlist: String,
    #[clap(long, default_value = DEFAULT_OWNER_KIND_PRIORITY)]
    pub owner_kind_priority: String,
}

impl Opt {
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
            if let Ok(p) = v.parse::<u16>() {
                opt.prometheus_port = p;
            }
        }
        if let Ok(v) = std::env::var("PROMETHEUS_ENDPOINT") {
            if !v.is_empty() {
                opt.prometheus_endpoint = v;
            }
        }
        if let Ok(v) = std::env::var("POLL_INTERVAL") {
            if let Ok(i) = v.parse::<u64>() {
                opt.poll_interval = i.max(1);
            }
        }
        if let Ok(v) = std::env::var("DEBUG_RESOLVER_ENABLED") {
            if let Ok(enabled) = v.parse::<bool>() {
                opt.debug_resolver_enabled = enabled;
            }
        }
        if let Ok(v) = std::env::var("DEBUG_RESOLVER_ENDPOINT") {
            if !v.is_empty() {
                opt.debug_resolver_endpoint = v;
            }
        }
        if let Ok(v) = std::env::var("RESOLVE_DNS") {
            if let Ok(enabled) = v.parse::<bool>() {
                opt.resolve_dns = enabled;
            }
        }
        if let Ok(v) = std::env::var("DNS_CACHE_SIZE") {
            if let Ok(size) = v.parse::<usize>() {
                opt.dns_cache_size = size.max(1);
            }
        }
        if let Ok(v) = std::env::var("TRAVERSE_UP_HIERARCHY") {
            if let Ok(enabled) = v.parse::<bool>() {
                opt.traverse_up_hierarchy = enabled;
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
