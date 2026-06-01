use std::net::Ipv4Addr;

use anyhow::Context;
use aya::{
    Ebpf,
    maps::Array,
    programs::{Xdp, XdpMode},
};
use tokio::signal;
use udp_lb_common::BackendInfo;

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodBackendInfo(BackendInfo);

// 现在可以合法地为我们自己定义的类型实现 Pod 了！
unsafe impl aya::Pod for PodBackendInfo {}
// 模拟的后端节点
struct Backend {
    ip: Ipv4Addr,
    port: u16,
    mac: [u8; 6],
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // 加载编译好的eBPF字节码
    let mut bpf = Ebpf::load_file("../target/bpf-unknown-none/release/udp-lb/ebpf")?; //TODO: 需要根据实际路径调整

    // 挂载 XDP 程序到指定网络接口
    let iface = "eth0"; //TODO: 需要根据实际环境调整
    let program: &mut Xdp = bpf
        .program_mut("xpd_fullnat_lb")
        .context("failed to find xdp program")?
        .try_into()?;
    program.load()?;
    program.attach(iface, XdpMode::default()).context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

    // 构建并下发一致性哈希环
    //TODO: 这里可以添加读取配置文件的功能，目前是硬编码的后端节点列表
    let backends = vec![
        Backend {
            ip: Ipv4Addr::new(192, 168, 1, 10),
            port: 8080,
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        },
        Backend {
            ip: Ipv4Addr::new(192, 168, 1, 11),
            port: 8080,
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x66],
        },
        Backend {
            ip: Ipv4Addr::new(192, 168, 1, 12),
            port: 8080,
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x77],
        },
    ];

    let mut ring_map: Array<_, PodBackendInfo> =
        Array::try_from(bpf.map_mut("RING_LOOKUP_TABLE").unwrap())?;

    // 简单的槽位分配逻辑：将 1024 个槽位均分给现有的后端
    // 实际生产中这里应使用带虚拟节点的一致性哈希算法 (如 Ketama) 计算槽位映射
    println!("Populating Consistent Hash Ring (1024 slots)...");
    for slot in 0..1024 {
        let backend_idx = (slot % backends.len()) as usize;
        let b = &backends[backend_idx];

        let info = BackendInfo {
            ip: u32::from(b.ip).to_be(), // 转为网络字节序给 eBPF 使用
            port: b.port.to_be(),
            mac: b.mac,
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
