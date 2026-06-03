/*显示定义所有的 BPF Maps 存储布局 */
use aya_ebpf::{
    macros::map,
    maps::{Array, LruHashMap},
};
use udp_lb_common::{BackendInfo, FlowKey, FlowValue, LbConfig};

// 定义支持的最大哈希环大小
pub const MAX_RING_SIZE: u32 = 4096;

// 储存读取配置文件结果的数组
#[map(name = "CONFIG_MAP")]
pub static CONFIG_MAP: Array<LbConfig> = Array::with_max_entries(1, 0);

// 哈希环
#[map(name = "RING_LOOKUP_TABLE")]
pub static RING_LOOKUP_TABLE: Array<BackendInfo> = Array::with_max_entries(MAX_RING_SIZE, 0);

// 正向连接跟踪表
// Client -> VIP 到 RS
#[map(name = "CONNTRACK_FORWARD")]
pub static CONNTRACK_FORWARD: LruHashMap<FlowKey, FlowValue> =
    LruHashMap::with_max_entries(65536, 0);

// 反向连接跟踪表
// RS -> LIP 回 Client
#[map(name = "CONNTRACE_REVERSE")]
pub static CONNTRACE_REVERSE: LruHashMap<FlowKey, FlowValue> =
    LruHashMap::with_max_entries(65536, 0);
