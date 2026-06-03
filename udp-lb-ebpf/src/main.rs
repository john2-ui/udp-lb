#![no_std]
#![no_main]

use core::panic::PanicInfo;
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, LruHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use udp_lb_common::{BackendInfo, FlowKey, FlowValue, LbConfig};

const MAX_RING_SIZE: u32 = 4096;

#[map(name = "CONFIG_MAP")]
static CONFIG_MAP: Array<LbConfig> = Array::with_max_entries(1, 0);

#[map(name = "RING_LOOKUP_TABLE")]
static RING_LOOKUP_TABLE: Array<BackendInfo> = Array::with_max_entries(MAX_RING_SIZE, 0);

#[map(name = "CONNTRACK_FORWARD")]
static CONNTRACK_FORWARD: LruHashMap<FlowKey, FlowValue> = LruHashMap::with_max_entries(65536, 0);

#[map(name = "CONNTRACE_REVERSE")]
static CONNTRACE_REVERSE: LruHashMap<FlowKey, FlowValue> = LruHashMap::with_max_entries(65536, 0);

#[xdp]
pub fn xdp_fullnat_lb(ctx: XdpContext) -> u32 {
    match try_xdp_fullnat_lb(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xdp_fullnat_lb(ctx: &XdpContext) -> Result<u32, ()> {
    // ---------------- [1] 加载全局配置 ----------------
    let config = match CONFIG_MAP.get(0) {
        Some(c) => c,
        None => {
            info!(ctx, "Drop: CONFIG_MAP is empty");
            return Err(());
        }
    };

    let vip = config.vip;
    let lip = config.lip;
    let ring_size = config.ring_size;
    let hash_seed = config.hash_seed;

    if ring_size == 0 || ring_size > MAX_RING_SIZE {
        info!(ctx, "Drop: Invalid ring_size ({})", ring_size);
        return Err(());
    }

    // ---------------- [2] 解析 Ethernet 头 ----------------
    let eth = match ptr_at_mut::<EthHdr>(ctx, 0) {
        Ok(e) => e,
        Err(_) => {
            info!(ctx, "Drop: Packet too small for EthHdr");
            return Err(());
        }
    };

    // 🌟 核心修复：强制转为主机序后再判断
    let ether_type =
        u16::from_be(unsafe { core::ptr::addr_of!(eth.ether_type).read_unaligned() } as u16);

    if ether_type != 0x0800 {
        // 0x0800 是 IPv4 的以太网类型
        if ether_type == 0x0806 {
            info!(ctx, "Pass: ARP Request detected (0x0806)");
        } else if ether_type == 0x86DD {
            info!(ctx, "Pass: IPv6 Packet detected (0x86DD)");
        }
        return Ok(xdp_action::XDP_PASS);
    }

    // ---------------- [3] 解析 IPv4 头 ----------------
    let ipv4 = match ptr_at_mut::<Ipv4Hdr>(ctx, EthHdr::LEN) {
        Ok(ip) => ip,
        Err(_) => {
            info!(ctx, "Drop: Packet too small for Ipv4Hdr");
            return Err(());
        }
    };

    let src_ip = ipv4.src_addr;
    let dst_ip = ipv4.dst_addr;

    info!(
        ctx,
        "IPv4: proto={}, SRC=0x{:x}, DST=0x{:x}",
        ipv4.proto as u8,
        u32::from_be(src_ip),
        u32::from_be(dst_ip)
    );

    if ipv4.proto != IpProto::Udp {
        info!(ctx, "Pass: Not UDP (proto={})", ipv4.proto as u8);
        return Ok(xdp_action::XDP_PASS);
    }

    // ---------------- [4] 解析 UDP 头 ----------------
    let udp = match ptr_at_mut::<UdpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN) {
        Ok(u) => u,
        Err(_) => {
            info!(ctx, "Drop: Packet too small for UdpHdr");
            return Err(());
        }
    };

    let src_port = udp.source;
    let dst_port = udp.dest;

    info!(
        ctx,
        "📦 UDP: SRC_PORT={}, DST_PORT={}",
        u16::from_be(src_port),
        u16::from_be(dst_port)
    );

    let lb_mac = eth.dst_addr;
    // ---------------- [5] 核心路由逻辑 ----------------
    if dst_ip == vip {
        info!(ctx, "[FWD] Match VIP! Entering Forwarding path...");

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
                let hash = calculate_hash(u32::from_be(src_ip), u16::from_be(src_port), hash_seed);
                let slot = hash % ring_size;

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

                let mut client_mac = [0u8; 6];
                client_mac[0] = eth.src_addr[0];
                client_mac[1] = eth.src_addr[1];
                client_mac[2] = eth.src_addr[2];
                client_mac[3] = eth.src_addr[3];
                client_mac[4] = eth.src_addr[4];
                client_mac[5] = eth.src_addr[5];

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

        ipv4.src_addr = lip;
        ipv4.dst_addr = backend.target_ip;
        udp.source = src_port;
        udp.dest = backend.target_port;

        eth.src_addr = lb_mac;

        eth.dst_addr[0] = backend.target_mac[0];
        eth.dst_addr[1] = backend.target_mac[1];
        eth.dst_addr[2] = backend.target_mac[2];
        eth.dst_addr[3] = backend.target_mac[3];
        eth.dst_addr[4] = backend.target_mac[4];
        eth.dst_addr[5] = backend.target_mac[5];

        ipv4.check = 0;
        ipv4.check = compute_ipv4_checksum(ipv4);
        udp.check = 0;

        info!(ctx, "[FWD] Packet rewritten! Sending XDP_TX...");
        return Ok(xdp_action::XDP_TX);
    } else if dst_ip == lip {
        info!(ctx, "[REV] Match LIP! Entering Reverse path...");

        let rev_key = FlowKey {
            ip: src_ip,
            port: src_port,
            _pad: [0; 2],
        };

        if let Some(orig_flow) = unsafe { CONNTRACE_REVERSE.get(&rev_key) } {
            info!(
                ctx,
                "[REV] Conntrack Hit: Restoring client 0x{:x}",
                u32::from_be(orig_flow.target_ip)
            );

            ipv4.src_addr = vip;
            ipv4.dst_addr = orig_flow.target_ip;
            udp.source = src_port;
            udp.dest = orig_flow.target_port;

            eth.src_addr = lb_mac;

            eth.dst_addr[0] = orig_flow.target_mac[0];
            eth.dst_addr[1] = orig_flow.target_mac[1];
            eth.dst_addr[2] = orig_flow.target_mac[2];
            eth.dst_addr[3] = orig_flow.target_mac[3];
            eth.dst_addr[4] = orig_flow.target_mac[4];
            eth.dst_addr[5] = orig_flow.target_mac[5];

            ipv4.check = 0;
            ipv4.check = compute_ipv4_checksum(ipv4);
            udp.check = 0;

            info!(ctx, "[REV] Packet restored! Sending XDP_TX...");
            return Ok(xdp_action::XDP_TX);
        } else {
            info!(ctx, "[REV] Conntrack Miss! Dropping packet.");
        }
    } else {
        info!(
            ctx,
            "Pass: DST_IP (0x{:x}) is neither VIP nor LIP",
            u32::from_be(dst_ip)
        );
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn calculate_hash(ip: u32, port: u16, seed: u32) -> u32 {
    let jh_magic = 0xdeadbeefu32;
    let length = 6u32;
    let mut a = ip
        .wrapping_add(jh_magic)
        .wrapping_add(length)
        .wrapping_add(seed);
    let mut b = (port as u32)
        .wrapping_add(jh_magic)
        .wrapping_add(length)
        .wrapping_add(seed);
    let mut c = jh_magic.wrapping_add(length).wrapping_add(seed);
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(14));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(11));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(25));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(16));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(4));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(14));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(24));
    c
}

#[inline(always)]
fn compute_ipv4_checksum(ipv4: &Ipv4Hdr) -> u16 {
    let mut csum: u32 = 0;
    let ptr = ipv4 as *const _ as *const u16;
    for i in 0..(Ipv4Hdr::LEN / 2) {
        csum = csum.wrapping_add(unsafe { ptr.add(i).read_unaligned() } as u32);
    }
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    !(csum as u16)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<&mut T, ()> {
    let start = ctx.data() + offset;
    let end = ctx.data_end();
    if start + core::mem::size_of::<T>() > end {
        return Err(());
    }
    Ok(unsafe { &mut *(start as *mut T) })
}
