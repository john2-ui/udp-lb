/*反向会话还原与安全校验逻辑 */
use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};
use udp_lb_common::FlowKey;

use crate::{maps::CONNTRACE_REVERSE, utils::compute_ipv4_checksum};

#[inline(always)]
pub fn handle_rev_traffic(
    ctx: &XdpContext,
    eth: &mut EthHdr,
    ipv4: &mut Ipv4Hdr,
    udp: &mut UdpHdr,
    vip: u32,
) -> Result<u32, ()> {
    info!(ctx, "[REV] Match LIP! Entering Reverse path...");

    let src_ip = ipv4.src_addr;
    let src_port = udp.source;
    let lb_mac = eth.dst_addr;

    let rev_key = FlowKey {
        ip: src_ip,
        port: src_port,
        _pad: [0; 2],
    };

    // 查找反向会话表
    if let Some(orig_flow) = unsafe { CONNTRACE_REVERSE.get(&rev_key) } {
        info!(
            ctx,
            "[REV] Conntrack Hit: Restoring client 0x{:x}",
            u32::from_be(orig_flow.target_ip)
        );

        ipv4.src_addr = vip;
        ipv4.dst_addr = orig_flow.target_ip;
        udp.source = src_port; // 保持服务端口不变
        udp.dest = orig_flow.target_port; // 恢复客户端口

        eth.src_addr = lb_mac;
        eth.dst_addr.copy_from_slice(&orig_flow.target_mac);

        ipv4.check = 0;
        ipv4.check = compute_ipv4_checksum(ipv4);
        udp.check = 0;

        info!(ctx, "[REV] Packet restored! Sending XDP_TX...");
        return Ok(xdp_action::XDP_TX);
    } else {
        info!(ctx, "[REV] Conntrack Miss! Dropping packet.");
    }

    Ok(xdp_action::XDP_PASS)
}
