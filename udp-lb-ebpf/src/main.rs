#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, LruHashMap},
    programs::{XdpContext, xdp},
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{self, IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use udp_lb_common::{BackendInfo, FlowKey, FlowValue};

//TODO: 添加读取配置文件功能
// 常量定义
const RING_SIZE: u32 = 1024;
const VIP: u32 = 0x0A000001; // 10.0.0.1 (网络字节序: 16777226)
const LIP: u32 = 0x0A0000FE; // 10.0.0.254 (网络字节序: 4261412874)

//TODO: 添加日志功能
#[map(name = "RING_LOOKUP_TABLE")]
static RING_LOOKUP_TABLE: Array<BackendInfo> = Array::with_max_entries(RING_SIZE, 0);

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
    if dst_ip == u32::to_be(VIP) {
        //TODO: 负载均衡算法 + 修改包头
    } else if dst_ip == u32::to_be(LIP) {
        // RS发出的回向包
        let rev_key = FlowKey {
            ip: src_ip,
            port: src_port,
            _pad: [0; 2],
        };

        if let Some(orig_flow) = unsafe { CONNTRACE_REVERSE.get(&rev_key) } {
            // 修改包头
            ipv4.src_addr = u32::to_be(VIP);
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
