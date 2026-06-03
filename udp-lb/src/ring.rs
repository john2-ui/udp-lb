/*
    一致性哈希环用户态构建
    平滑分配算法
*/
use std::{net::Ipv4Addr, str::FromStr};

use anyhow::Result;
use aya::maps::{Array, MapData};
use udp_lb_common::BackendInfo;

use crate::config::{BackendConfig, parse_mac};

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct PodBackendInfo(pub BackendInfo);
unsafe impl aya::Pod for PodBackendInfo {}

pub fn populate_ring(
    ring_map: &mut Array<&mut MapData, PodBackendInfo>,
    backends: &[BackendConfig],
    ring_size: u32,
) -> Result<()> {
    log::info!("Populating Consistent Hash Ring ({} slots)...", ring_size);

    // 基础槽位分配：均分给现有后端。生产环境可接入 Ketama 算法。
    for slot in 0..ring_size {
        let backend_idx = (slot % backends.len() as u32) as usize;
        let b = &backends[backend_idx];

        let info = BackendInfo {
            ip: u32::from(Ipv4Addr::from_str(&b.ip)?).to_be(),
            port: b.port.to_be(),
            mac: parse_mac(&b.mac)?,
            _pad: [0; 4],
        };

        ring_map.set(slot, PodBackendInfo(info), 0)?;
    }

    log::info!("Hash Ring fully populated.");
    Ok(())
}
