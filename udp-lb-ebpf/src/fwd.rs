use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};
use udp_lb_common::{FlowKey, FlowValue, LbConfig};

use crate::{
    maps::{CONNTRACE_REVERSE, CONNTRACK_FORWARD, MAX_RING_SIZE, RING_LOOKUP_TABLE},
    utils::{calculate_hash, compute_ipv4_checksum},
};

#[inline(always)]
pub fn handle_fwd_traffic(
    ctx: &XdpContext,
    eth: &mut EthHdr,
    ipv4: &mut Ipv4Hdr,
    udp: &mut UdpHdr,
    config: &LbConfig,
) -> Result<u32, ()> {
    info!(ctx, "🎯 [FWD] Match VIP! Entering Forwarding path...");

    let src_ip = ipv4.src_addr;
    let src_port = udp.source;
    let lb_mac = eth.dst_addr;

    let fwd_key = FlowKey {
        ip: src_ip,
        port: src_port,
        _pad: [0; 2],
    };

    let backend = unsafe {
        if let Some(cached) = CONNTRACK_FORWARD.get(&fwd_key) {
            info!(
                ctx,
                "🔗 [FWD] Conntrack Hit: Routing to RS 0x{:x}",
                u32::from_be(cached.target_ip)
            );
            *cached
        } else {
            let safe_ring_size = if config.ring_size > 0 {
                config.ring_size
            } else {
                1
            };

            let hash = calculate_hash(
                u32::from_be(src_ip),
                u16::from_be(src_port),
                config.hash_seed,
            );
            let slot = hash % safe_ring_size;

            if slot >= MAX_RING_SIZE {
                return Err(());
            }

            let rs = RING_LOOKUP_TABLE.get(slot).ok_or(())?;
            let new_value = FlowValue {
                target_ip: rs.ip,
                target_port: rs.port,
                target_mac: rs.mac,
            };

            info!(
                ctx,
                "🎲 [FWD] New Session. Hash slot {}, Selected RS 0x{:x}",
                slot,
                u32::from_be(rs.ip)
            );
            let _ = CONNTRACK_FORWARD.insert(&fwd_key, &new_value, 0);

            let client_mac = eth.src_addr;

            let rev_key = FlowKey {
                ip: rs.ip,
                port: rs.port,
                _pad: [0; 2],
            };
            let rev_value = FlowValue {
                target_ip: src_ip,
                target_port: src_port,
                target_mac: client_mac,
            };
            let _ = CONNTRACE_REVERSE.insert(&rev_key, &rev_value, 0);

            new_value
        }
    };

    ipv4.src_addr = config.lip;
    ipv4.dst_addr = backend.target_ip;
    udp.source = src_port;
    udp.dest = backend.target_port;

    eth.src_addr = lb_mac;
    eth.dst_addr = backend.target_mac;

    ipv4.check = 0;
    ipv4.check = compute_ipv4_checksum(ipv4);
    udp.check = 0;

    info!(ctx, "🚀 [FWD] Packet rewritten! Sending XDP_TX...");
    Ok(xdp_action::XDP_TX)
}
