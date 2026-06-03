/*
    用户态连接追踪回收
    分析器
*/
use std::time::Duration;

use aya::maps::{HashMap, MapData};
use tokio::time;
use udp_lb_common::{FlowKey, FlowValue};

// 会话超时阈值
const TIMEOUT_NS: u64 = 30 * 1_000_000_000;

// 获取纳秒时间戳
fn get_ktime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

pub async fn start_gc_loop(
    mut fwd_map: HashMap<MapData, FlowKey, FlowValue>,
    mut rev_map: HashMap<MapData, FlowKey, FlowValue>,
) {
    log::info!("Starting Conntrack Garbage Collection task (30s timeout)...");

    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(10)); // 每10秒巡检一次

        loop {
            interval.tick().await;

            let now = get_ktime_ns();
            let mut stale_keys = Vec::new();

            // 收集超时的 Key
            for result in fwd_map.iter() {
                if let Ok((key, value)) = result {
                    if now > value.last_active && (now - value.last_active) > TIMEOUT_NS {
                        stale_keys.push((key, value));
                    }
                }
            }

            let stale_count = stale_keys.len();
            if stale_count > 0 {
                // 集中执行删除
                for (fwd_key, value) in stale_keys {
                    let rev_key = FlowKey {
                        ip: value.target_ip,
                        port: value.target_port,
                        _pad: [0; 2],
                    };

                    // 擦除双向表中的记录
                    let _ = fwd_map.remove(&fwd_key);
                    let _ = rev_map.remove(&rev_key);
                }
                log::info!("Conntrack GC: Reaped {} stale sessions.", stale_count);
            }
        }
    });
}
