use std::{fs, net::Ipv4Addr, str::FromStr};

use anyhow::{Context, Result};
use aya::{
    maps::Array,
    programs::{Xdp, XdpMode},
};
use rand::Rng;
use serde::Deserialize;
use tokio::signal;
use udp_lb_common::{BackendInfo, LbConfig};

// YAML 配置结构体
#[derive(Deserialize, Debug)]
struct AppConfig {
    iface: String,
    ring_size: u32,
    vip: String,
    lip: String,
    backends: Vec<BackendConfig>,
}

#[derive(Deserialize, Debug)]
struct BackendConfig {
    ip: String,
    port: u16,
    mac: String,
}

// 解决孤儿原则的包装器
#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodBackendInfo(BackendInfo);
unsafe impl aya::Pod for PodBackendInfo {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodLbConfig(LbConfig);
unsafe impl aya::Pod for PodLbConfig {}
// // 模拟的后端节点
// struct Backend {
//     ip: Ipv4Addr,
//     port: u16,
//     mac: [u8; 6],
// }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    println!("Loading config from configy.yaml... ");

    // 动态获取当前可执行文件路径，并回退到项目根目录
    let mut root_dir = std::env::current_exe().context("Failed to get current executable path")?;
    root_dir.pop(); // 弹出可执行文件名 (udp-lb)
    root_dir.pop(); // 弹出 release/
    root_dir.pop(); // 弹出 target/

    // 拼接配置文件的绝对路径
    let config_path = root_dir.join("config.yaml");
    println!("Using absolute config path: {:?}", config_path);

    let config_file = fs::read_to_string(&config_path).context("Failed to read config.yaml")?;
    let app_config: AppConfig =
        serde_yaml::from_str(&config_file).context("Failed to parse YAML config")?;
    println!(
        "Config loaded successfully. Using interface: {}",
        app_config.iface
    );

    // 复用 root_dir，拼接 eBPF 字节码的绝对路径
    let ebpf_path = root_dir.join("target/bpfel-unknown-none/release/udp-lb");

    println!("Loading eBPF program from file: {:?}", ebpf_path);
    let mut bpf = aya::Ebpf::load_file(&ebpf_path)
        .context(format!("Failed to load eBPF bytecode at {:?}", ebpf_path))?;
    println!("eBPF program loaded successfully.");

    // 在init日志之前，先加载程序
    {
        let program: &mut Xdp = bpf
            .program_mut("xdp_fullnat_lb")
            .context("failed to find xdp program")?
            .try_into()?;
        program.load()?;
    }

    // 初始化 eBPF 日志读取通道（需要在load()和attach()之间）
    // 把内核数据流日志打印到用户态控制台中
    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        eprintln!("Warning: Failed to initialize eBPF logger: {}", e);
    } else {
        println!("eBPF Logger initialized successfully. Listening for data-plane events...");
    }

    // 挂载 XDP 程序到指定网络接口
    let iface = &app_config.iface;
    println!("Attaching XDP program to interface: {}", iface);

    let program: &mut Xdp = bpf
        .program_mut("xdp_fullnat_lb")
        .context("failed to find xdp program")?
        .try_into()?;

    program
        .attach(iface, XdpMode::Skb)
        .context("failed to attach the XDP program with Skb mode")?;

    let mut config_map: Array<_, PodLbConfig> =
        Array::try_from(bpf.map_mut("CONFIG_MAP").unwrap())?;

    // 生成一个随机的u32作为哈希种子
    let mut rng = rand::thread_rng();
    let dynamic_seed: u32 = rng.r#gen();
    let lb_config = LbConfig {
        vip: u32::from(Ipv4Addr::from_str(&app_config.vip)?).to_be(),
        lip: u32::from(Ipv4Addr::from_str(&app_config.lip)?).to_be(),
        ring_size: app_config.ring_size,
        hash_seed: dynamic_seed,
    };
    config_map.set(0, PodLbConfig(lb_config), 0)?;
    println!("Global constants (VIP/LIP) injected into eBPF.");

    let mut ring_map: Array<_, PodBackendInfo> =
        Array::try_from(bpf.map_mut("RING_LOOKUP_TABLE").unwrap())?;

    // 简单的槽位分配逻辑：将 ring_size 个槽位均分给现有的后端
    // 实际生产中这里应使用带虚拟节点的一致性哈希算法 (如 Ketama) 计算槽位映射
    println!(
        "Populating Consistent Hash Ring ({} slots)...",
        app_config.ring_size
    );
    for slot in 0..app_config.ring_size {
        let backend_idx = (slot % app_config.backends.len() as u32) as usize;
        let b = &app_config.backends[backend_idx as usize];

        let info = BackendInfo {
            ip: u32::from(Ipv4Addr::from_str(&b.ip)?).to_be(), // 转为网络字节序给 eBPF 使用
            port: b.port.to_be(),
            mac: parse_mac(&b.mac)?,
            _pad: [0; 4],
        };

        ring_map.set(slot as u32, PodBackendInfo(info), 0)?;
    }
    println!("Hash Ring fully populated. Load Balancer is active.");

    // 等待中断信号退出
    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}

fn parse_mac(mac_str: &str) -> Result<[u8; 6]> {
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
