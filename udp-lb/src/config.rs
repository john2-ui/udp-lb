/*
    YAML配置文件解析
    网络接口断言检验
*/
use std::fs;

use anyhow::{Context, Result};
use serde::Deserialize;
use udp_lb_common::LbConfig;

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub iface: String,
    pub ring_size: u32,
    pub vip: String,
    pub lip: String,
    pub backends: Vec<BackendConfig>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct BackendConfig {
    pub ip: String,
    pub port: u16,
    pub mac: String,
}

// 解决孤儿原则的包装器
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct PodLbConfig(pub LbConfig);
unsafe impl aya::Pod for PodLbConfig {}

pub fn load_config(path: &std::path::Path) -> Result<AppConfig> {
    let config_file = fs::read_to_string(path).context("Failed to read config.yaml")?;
    let app_config: AppConfig =
        serde_yaml::from_str(&config_file).context("Failed to parse YAML config")?;
    Ok(app_config)
}

pub fn parse_mac(mac_str: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow::anyhow!("Invalid MAC address format"));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| anyhow::anyhow!("Invalid MAC address format"))?;
    }
    Ok(mac)
}
