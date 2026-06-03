/*存放所有无状态的纯计算函数和内存安全检验 */
use aya_ebpf::programs::XdpContext;
use network_types::ip::Ipv4Hdr;

// 截取报文
#[inline(always)]
pub fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<&mut T, ()> {
    let start = ctx.data() + offset;
    let end = ctx.data_end();
    if start + core::mem::size_of::<T>() > end {
        return Err(());
    }
    Ok(unsafe { &mut *(start as *mut T) })
}

// Jenkins Hash 算法
#[inline(always)]
pub fn calculate_hash(ip: u32, port: u16, seed: u32) -> u32 {
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

// IPv4 校验和计算
#[inline(always)]
pub fn compute_ipv4_checksum(ipv4: &Ipv4Hdr) -> u16 {
    let mut csum: u32 = 0;
    let ptr = ipv4 as *const _ as *const u16;
    for i in 0..(Ipv4Hdr::LEN / 2) {
        csum = csum.wrapping_add(unsafe { ptr.add(i).read_unaligned() } as u32);
    }
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    !(csum as u16)
}
