/*
    用户态连接追踪回收
    分析器
*/
use std::time::Duration;

use tokio::time;

pub async fn start_gc_loop() {
    log::info!("Starting Conntrack Garbage Collection task...");

    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;

            // TODO: 遍历 aya_ebpf::maps::LruHashMap
            // 读取 FlowValue 中的 last_active 时间戳，超时则主动执行 remove()
            log::debug!("Conntrack GC tick: scanning for stale sessions...");
        }
    });
}
