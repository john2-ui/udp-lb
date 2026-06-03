#![no_std]
#![no_main]

mod fwd;
mod maps;
mod rev;
mod utils;

use core::panic::PanicInfo;
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

use crate::{maps::CONFIG_MAP, utils::ptr_at_mut};

#[xdp]
pub fn xdp_fullnat_lb(ctx: XdpContext) -> u32 {
    match try_xdp_fullnat_lb(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xdp_fullnat_lb(ctx: &XdpContext) -> Result<u32, ()> {
    // 1. 读取全局配置
    let config = match CONFIG_MAP.get(0) {
        Some(c) => c,
        None => return Err(()),
    };

    if config.ring_size == 0 || config.ring_size > maps::MAX_RING_SIZE {
        return Err(());
    }

    // 2. 解析以太网头 (L2)
    let eth = ptr_at_mut::<EthHdr>(ctx, 0)?;
    let ether_type =
        u16::from_be(unsafe { core::ptr::addr_of!(eth.ether_type).read_unaligned() } as u16);

    if ether_type != 0x0800 {
        // 仅处理 IPv4
        return Ok(xdp_action::XDP_PASS);
    }

    // 3. 解析 IP 头 (L3)
    let ipv4 = ptr_at_mut::<Ipv4Hdr>(ctx, EthHdr::LEN)?;

    if ipv4.proto != IpProto::Udp {
        // 仅处理 UDP
        return Ok(xdp_action::XDP_PASS);
    }

    let dst_ip = ipv4.dst_addr;

    // 4. 解析 UDP 头 (L4)
    let udp = ptr_at_mut::<UdpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    // 5. 流量分流中心
    if dst_ip == config.vip {
        // 交由 fwd.rs 处理 FullNAT 正向入站逻辑
        fwd::handle_fwd_traffic(ctx, eth, ipv4, udp, config)
    } else if dst_ip == config.lip {
        // 交由 rev.rs 处理后端 RS 反向回包逻辑
        rev::handle_rev_traffic(ctx, eth, ipv4, udp, config.vip)
    } else {
        info!(ctx, "Pass: DST_IP is neither VIP nor LIP");
        Ok(xdp_action::XDP_PASS)
    }
}
