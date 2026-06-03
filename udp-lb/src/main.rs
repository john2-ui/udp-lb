mod config;
mod conntrack;
mod health;
mod ring;

use std::{net::Ipv4Addr, str::FromStr};

use anyhow::{Context, Result};
use aya::{
    maps::Array,
    programs::{Xdp, XdpMode},
};
use rand::Rng;
use tokio::signal;
use udp_lb_common::LbConfig;

use crate::{
    config::{PodLbConfig, load_config},
    ring::{PodBackendInfo, populate_ring},
};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    log::info!("Initializing UDP Load Balancer Control Plane...");

    // 1. 路径解析与配置加载
    let mut root_dir = std::env::current_exe().context("Failed to get current executable path")?;
    root_dir.pop();
    root_dir.pop();
    root_dir.pop();

    let config_path = root_dir.join("config.yaml");
    let app_config = load_config(&config_path)?;
    log::info!(
        "Config loaded successfully. Using interface: {}",
        app_config.iface
    );

    // 2. 加载 eBPF 字节码
    let ebpf_path = root_dir.join("target/bpfel-unknown-none/release/udp-lb");
    let mut bpf = aya::Ebpf::load_file(&ebpf_path)
        .context(format!("Failed to load eBPF bytecode at {:?}", ebpf_path))?;

    // 3. 将字节码 Load 进内核
    {
        let program: &mut Xdp = bpf
            .program_mut("xdp_fullnat_lb")
            .context("failed to find xdp program")?
            .try_into()?;
        program.load()?;
    }

    // 4. 初始化日志管道
    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        log::warn!("Failed to initialize eBPF logger: {}", e);
    } else {
        log::info!("eBPF Logger initialized. Listening for data-plane events...");
    }

    // 5. 挂载到网卡
    let program: &mut Xdp = bpf
        .program_mut("xdp_fullnat_lb")
        .context("failed to find xdp program")?
        .try_into()?;
    program
        .attach(&app_config.iface, XdpMode::Skb)
        .context("failed to attach the XDP program")?;

    // 6. 下发全局常量配置
    let mut config_map: Array<_, PodLbConfig> =
        Array::try_from(bpf.map_mut("CONFIG_MAP").unwrap())?;
    let dynamic_seed: u32 = rand::thread_rng().r#gen();

    let lb_config = LbConfig {
        vip: u32::from(Ipv4Addr::from_str(&app_config.vip)?).to_be(),
        lip: u32::from(Ipv4Addr::from_str(&app_config.lip)?).to_be(),
        ring_size: app_config.ring_size,
        hash_seed: dynamic_seed,
    };
    config_map.set(0, PodLbConfig(lb_config), 0)?;
    log::info!("Global constants injected into eBPF.");

    // 7. 构建一致性哈希环
    let mut ring_map: Array<_, PodBackendInfo> =
        Array::try_from(bpf.map_mut("RING_LOOKUP_TABLE").unwrap())?;
    populate_ring(&mut ring_map, &app_config.backends, app_config.ring_size)?;

    // 8. 启动异步管控协程
    health::start_health_check_loop(app_config.backends.clone()).await;
    conntrack::start_gc_loop().await;

    // 9. 挂起并等待退出信号
    log::info!("Load Balancer is fully active. Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    log::info!("Exiting gracefully...");

    Ok(())
}
