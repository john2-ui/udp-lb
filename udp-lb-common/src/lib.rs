#![no_std]

// 后端服务器信息
#[repr(C)]                  // 使用 #[repr(C)] 确保结构体的内存布局与 C 语言兼容
#[derive(Clone, Copy)]
pub struct BackendInfo {
    pub ip: u32,            //网络字节序
    pub port: u16,          //网络字节序
    pub mac: [u8; 6],       //MAC地址
    pub _pad: [u8; 2],      //填充到4字节对齐（保证Total Alignment）
}

// 连接追踪的 Key (源Ip + 端口)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowKey {
    pub ip: u32,
    pub port: u16,
    pub _pad: [u8; 2],      //填充到4字节对齐
}

// 连接追踪的 Value
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowValue {
    pub target_ip: u32,
    pub target_port: u16,
    pub target_mac: [u8; 6],
}