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
pub fn xpd_fullnat_lb(ctx: XdpContext) -> u32 {
    match try_xpd_fullnat_lb(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xpd_fullnat_lb(ctx: XdpContext) -> Result<u32, ()> {
    // 读取配置
    let config = CONFIG_MAP.get(0).ok_or(())?;
    let vip = config.vip;
    let lip = config.lip;
    let ring_size = config.ring_size;

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
    if dst_ip == u32::to_be(vip) {
        //TODO: 负载均衡算法 + 修改包头
        let fwd_key = FlowKey {
            ip: src_ip,
            port: src_port,
            _pad: [0; 2],
        };

        let backend = unsafe {
            if let Some(cached) = CONNTRACK_FORWARD.get(&fwd_key) {
                *cached
            } else {
                let hash = calculate_hash(u32::from_be(src_ip), u16::from_be(src_port));
                let slot = hash % ring_size;

                let rs = RING_LOOKUP_TABLE.get(slot).ok_or(())?;
                let new_value = FlowValue {
                    target_ip: rs.ip,
                    target_port: rs.port,
                    target_mac: rs.mac,
                };

                // 写入正向表
                let _ = CONNTRACK_FORWARD.insert(&fwd_key, &new_value, 0);

                // 写入反向表
                let rev_key = FlowKey {
                    ip: rs.ip,
                    port: rs.port,
                    _pad: [0; 2],
                };
                let rev_value = FlowValue {
                    target_ip: src_ip,
                    target_port: src_port,
                    target_mac: eth.src_addr, // 记录客户端/网关MAC地址，回向包时直接使用
                };
                let _ = CONNTRACE_REVERSE.insert(&rev_key, &rev_value, 0);

                new_value
            }
        };

        // 修改包头
        ipv4.src_addr = u32::to_be(lip);
        ipv4.dst_addr = backend.target_ip;
        udp.source = src_port; //TODO: 这里是简易实现：直接复用源端口作为Port，实际可能存在冲突，可以改成一个端口池
        udp.dest = backend.target_port;
        eth.dst_addr = backend.target_mac;

        // 重新计算校验和
        ipv4.check = 0;
        ipv4.check = compute_ipv4_checksum(ipv4);
        udp.check = 0;

        return Ok(xdp_action::XDP_TX);
    } else if dst_ip == u32::to_be(lip) {
        // RS发出的回向包
        let rev_key = FlowKey {
            ip: src_ip,
            port: src_port,
            _pad: [0; 2],
        };

        if let Some(orig_flow) = unsafe { CONNTRACE_REVERSE.get(&rev_key) } {
            // 修改包头
            ipv4.src_addr = u32::to_be(vip);
            ipv4.dst_addr = orig_flow.target_ip;
            udp.source = dst_port;
            udp.dest = orig_flow.target_port;
            eth.dst_addr = orig_flow.target_mac;

            ipv4.check = 0;
            ipv4.check = compute_ipv4_checksum(ipv4);
            udp.check = 0;

            return Ok(xdp_action::XDP_TX);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn calculate_hash(ip: u32, port: u16) -> u32 {
    // TODO: 可以替换成更好的一致性哈希算法，目前是简易实现
    // FNV-1a hash
    let mut hash = 2166136261u32;
    hash = (hash ^ ip).wrapping_mul(16777619);
    hash = (hash ^ (port as u32)).wrapping_mul(16777619);
    hash
}

#[inline(always)]
fn compute_ipv4_checksum(ipv4: &Ipv4Hdr) -> u16 {
    let mut csum: u32 = 0;
    let ptr = ipv4 as *const _ as *const u16;
    for i in 0..(Ipv4Hdr::LEN / 2) {
        csum = csum.wrapping_add(unsafe { ptr.add(i).read_unaligned() } as u32);
    }
    !(csum.wrapping_add(csum >> 16) as u16)
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
