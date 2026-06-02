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
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use udp_lb_common::{BackendInfo, FlowKey, FlowValue, LbConfig};

// 定义支持的最大哈希环大小，编译期常量
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
    match try_xdp_fullnat_lb(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xdp_fullnat_lb(ctx: XdpContext) -> Result<u32, ()> {
    // 读取配置
    let config = CONFIG_MAP.get(0).ok_or(())?;
    let vip = config.vip;
    let lip = config.lip;
    let ring_size = config.ring_size;
    let hash_seed = config.hash_seed;

    if ring_size == 0 || ring_size > MAX_RING_SIZE {
        return Err(());
    }

    let eth = ptr_at_mut::<EthHdr>(&ctx, 0)?;
    let ether_type = unsafe { core::ptr::addr_of!(eth.ether_type).read_unaligned() };
    if ether_type != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4 = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    if ipv4.proto != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    let src_ip = ipv4.src_addr;
    let dst_ip = ipv4.dst_addr;
    let src_port = udp.source;
    let dst_port = udp.dest;

    //TODO: 添加DSR功能（通过配置文件选择），这里实现的是Full NAT
    if dst_ip == vip {
        let fwd_key = FlowKey {
            ip: src_ip,
            port: src_port,
            _pad: [0; 2],
        };

        let backend = unsafe {
            if let Some(cached) = CONNTRACK_FORWARD.get(&fwd_key) {
                *cached
            } else {
                let hash = calculate_hash(u32::from_be(src_ip), u16::from_be(src_port), hash_seed);
                let slot = hash % ring_size;

                let rs = RING_LOOKUP_TABLE.get(slot).ok_or(())?;
                let new_value = FlowValue {
                    target_ip: rs.ip,
                    target_port: rs.port,
                    target_mac: rs.mac,
                };

                // 写入正向表
                let _ = CONNTRACK_FORWARD.insert(&fwd_key, &new_value, 0);

                let mut client_mac = [0u8; 6];
                client_mac[0] = eth.src_addr[0];
                client_mac[1] = eth.src_addr[1];
                client_mac[2] = eth.src_addr[2];
                client_mac[3] = eth.src_addr[3];
                client_mac[4] = eth.src_addr[4];
                client_mac[5] = eth.src_addr[5];

                // 写入反向表
                let rev_key = FlowKey {
                    ip: rs.ip,
                    port: rs.port,
                    _pad: [0; 2],
                };
                let rev_value = FlowValue {
                    target_ip: src_ip,
                    target_port: src_port,
                    target_mac: client_mac, // 记录客户端/网关MAC地址，回向包时直接使用
                };
                let _ = CONNTRACE_REVERSE.insert(&rev_key, &rev_value, 0);

                new_value
            }
        };

        // 修改包头
        ipv4.src_addr = lip;
        ipv4.dst_addr = backend.target_ip;
        udp.source = src_port; //TODO: 这里是简易实现：直接复用源端口作为Port，实际可能存在冲突，可以改成一个端口池
        udp.dest = backend.target_port;

        eth.dst_addr[0] = backend.target_mac[0];
        eth.dst_addr[1] = backend.target_mac[1];
        eth.dst_addr[2] = backend.target_mac[2];
        eth.dst_addr[3] = backend.target_mac[3];
        eth.dst_addr[4] = backend.target_mac[4];
        eth.dst_addr[5] = backend.target_mac[5];

        // 重新计算校验和
        ipv4.check = 0;
        ipv4.check = compute_ipv4_checksum(ipv4);
        udp.check = 0;

        return Ok(xdp_action::XDP_TX);
    } else if dst_ip == lip {
        // RS发出的回向包
        let rev_key = FlowKey {
            ip: src_ip,
            port: src_port,
            _pad: [0; 2],
        };

        if let Some(orig_flow) = unsafe { CONNTRACE_REVERSE.get(&rev_key) } {
            // 修改包头
            ipv4.src_addr = vip;
            ipv4.dst_addr = orig_flow.target_ip;
            udp.source = dst_port;
            udp.dest = orig_flow.target_port;

            eth.dst_addr[0] = orig_flow.target_mac[0];
            eth.dst_addr[1] = orig_flow.target_mac[1];
            eth.dst_addr[2] = orig_flow.target_mac[2];
            eth.dst_addr[3] = orig_flow.target_mac[3];
            eth.dst_addr[4] = orig_flow.target_mac[4];
            eth.dst_addr[5] = orig_flow.target_mac[5];

            ipv4.check = 0;
            ipv4.check = compute_ipv4_checksum(ipv4);
            udp.check = 0;

            return Ok(xdp_action::XDP_TX);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

// Jenkins Hash(动态加密)
#[inline(always)]
fn calculate_hash(ip: u32, port: u16, seed: u32) -> u32 {
    let jh_magic = 0xdeadbeefu32;
    let length = 6u32; //IP(4) + Port(2) = 6字节

    // 初始化内部状态
    let mut a = ip
        .wrapping_add(jh_magic)
        .wrapping_add(length)
        .wrapping_add(seed);
    let mut b = (port as u32)
        .wrapping_add(jh_magic)
        .wrapping_add(length)
        .wrapping_add(seed);
    let mut c = jh_magic.wrapping_add(length).wrapping_add(seed);

    // Jenkins 原生的核心混淆宏 (mix)
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
