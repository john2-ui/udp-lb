/*
    异步后端 RS 定时健康检查
    动态剔除器
*/
use std::time::Duration;

use tokio::{net::UdpSocket, time};

use crate::config::BackendConfig;

pub async fn start_health_check_loop(backends: Vec<BackendConfig>) {
    log::info!("Starting asynchronous health check task...");

    tokio::spawn(async move {
        // 每 5 秒进行一轮全量探测
        let mut interval = time::interval(Duration::from_secs(5));

        loop {
            interval.tick().await;

            for backend in &backends {
                let addr = format!("{}:{}", backend.ip, backend.port);

                // 绑定本地随机端口
                match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(socket) => {
                        // 发送探针数据 (Payload)
                        if socket.connect(&addr).await.is_ok() {
                            let _ = socket.send(b"PING").await;

                            // 设置 1 秒的接收超时时间
                            let mut buf = [0u8; 1024];
                            let check_result =
                                time::timeout(Duration::from_secs(1), socket.recv(&mut buf)).await;

                            match check_result {
                                Ok(Ok(_)) => log::debug!("Health Check: RS {} is UP", addr),
                                _ => log::warn!(
                                    "Health Check: RS {} is DOWN (Timeout/Unreachable)",
                                    addr
                                ),
                            }
                        }
                    }
                    Err(e) => log::error!("Health check socket bind failed: {}", e),
                }
            }
        }
    });
}
