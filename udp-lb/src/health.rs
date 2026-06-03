/*
    异步后端 RS 定时健康检查
    动态剔除器
*/
use std::time::Duration;

use tokio::time;

use crate::config::BackendConfig;

pub async fn start_health_check_loop(backends: Vec<BackendConfig>) {
    log::info!("Starting asynchronous health check task...");

    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;

            // TODO: 实现针对 backends 的端口连通性探测
            // 如果探测到状态变动 (Up -> Down)，触发 ring.rs 重新计算并下发 eBPF
            log::debug!(
                "Health check tick: validating {} backends...",
                backends.len()
            );
        }
    });
}
