#!/bin/bash

# 确保以 root 权限运行
if [ "$EUID" -ne 0 ]; then
  echo "请使用 root 权限 (sudo) 运行此脚本！"
  exit 1
fi

LB_BIN="./target/release/udp-lb"
LB_LOG="/tmp/udp-lb-benchmark.log"

echo "========================================================"
echo " 准备基准测试环境与控制面..."
echo "========================================================"

# 0. 检查 socat 是否安装
if ! command -v socat &> /dev/null; then
    echo "未检测到 socat，正在为您自动安装..."
    apt-get update && apt-get install -y socat
fi

# 1. 检查编译程序是否存在
if [ ! -f "$LB_BIN" ]; then
    echo "未找到编译产物，正在尝试自动编译项目..."
    sudo ./build.sh
    if [ $? -ne 0 ]; then
        echo " 编译失败，请检查代码错误后重试！"
        exit 1
    fi
fi

# 2. 检查环境是否已经初始化
if ! ip netns list | grep -q "ns-lb"; then
    echo " 检测到网络环境未配置，正在自动执行 setup_env.sh..."
    if [ -f "./setup_env.sh" ]; then
        chmod +x setup_env.sh
        ./setup_env.sh
    else
        echo " 未找到 setup_env.sh 脚本，请确保它在当前目录下！"
        exit 1
    fi
fi

# 3. 清理旧进程
echo "[-] 清理旧的后台残留进程..."
pkill -f "socat.*UDP-LISTEN:8080" 2>/dev/null
pkill -f "mock_rs.py" 2>/dev/null
pkill -f "./target/release/udp-lb" 2>/dev/null

# 4. 启动后端极速反射服务
echo "[+] 在 RS1 和 RS2 启动 socat UDP Echo 服务..."
ip netns exec ns-rs1 socat UDP-LISTEN:8080,fork PIPE &
ip netns exec ns-rs2 socat UDP-LISTEN:8080,fork PIPE &

# 5. 启动 eBPF 负载均衡器
echo "[+] 正在 ns-lb 命名空间中启动 eBPF 负载均衡器..."
ip netns exec ns-lb env RUST_LOG=info $LB_BIN > $LB_LOG 2>&1 &
LB_PID=$!

# 设置终极退出钩子：脚本退出时（无论成功、失败还是 Ctrl+C），一并带走 LB 和 socat
trap "echo -e '\n--> 正在清理压测环境...'; kill $LB_PID 2>/dev/null; pkill -f 'socat.*UDP-LISTEN:8080' 2>/dev/null; echo ' 测试环境及后台进程已安全复位。'" EXIT

# 等待 eBPF 字节码完全加载并下发配置
sleep 2

if ! kill -0 $LB_PID 2>/dev/null; then
    echo " 负载均衡器启动闪退！请查看日志 $LB_LOG :"
    cat $LB_LOG
    exit 1
fi
echo " 负载均衡器已就绪 (PID: $LB_PID)。"

# 6. 动态生成高精度测速 Python 脚本
cat << 'PYEOF' > /tmp/precise_ping.py
import socket
import time
import sys
import statistics

target_ip = sys.argv[1]
target_port = int(sys.argv[2])
count = int(sys.argv[3])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.5)

latencies = []
consecutive_timeouts = 0

for _ in range(count):
    start = time.perf_counter()
    sock.sendto(b"PING", (target_ip, target_port))
    try:
        sock.recvfrom(1024)
        rtt = (time.perf_counter() - start) * 1000
        latencies.append(rtt)
        consecutive_timeouts = 0
    except:
        consecutive_timeouts += 1
        if consecutive_timeouts >= 10:
            print("FAIL 0 0 0 0 0")
            sys.exit(1)
            
    time.sleep(0.002)

if not latencies:
    print("FAIL 0 0 0 0 0")
    sys.exit(1)

latencies.sort()
p99_idx = int(len(latencies) * 0.99)
if p99_idx >= len(latencies): p99_idx = len(latencies) - 1

avg = sum(latencies) / len(latencies)
min_l = latencies[0]
max_l = latencies[-1]
p99 = latencies[p99_idx]

print(f"{avg:.4f} {min_l:.4f} {max_l:.4f} {p99:.4f} {len(latencies)}/{count}")
PYEOF

echo ""
echo "========================================================"
echo "开始极限延迟测试 (1000 Packets/Route)..."
echo "========================================================"

# 确保 Client 能直接路由到 RS 用于对照组测试
ip netns exec ns-client ip route add 192.168.1.0/24 via 10.0.0.254 dev eth0 2>/dev/null

echo " [对照组] 正在测试: 传统 Linux 内核协议栈转发 (Target: RS1 192.168.1.10)..."
read -r avg1 min1 max1 p991 success1 <<< $(ip netns exec ns-client python3 /tmp/precise_ping.py 192.168.1.10 8080 1000)

if [[ "$avg1" == "FAIL" ]]; then
    echo " 对照组测试失败：网络不通，请检查 setup_env.sh 路由配置。"
    exit 1
fi

echo " [测试组] 正在测试: eBPF XDP 极速无锁转发 (Target: VIP 10.0.0.1)..."
read -r avg2 min2 max2 p992 success2 <<< $(ip netns exec ns-client python3 /tmp/precise_ping.py 10.0.0.1 8080 1000)

if [[ "$avg2" == "FAIL" ]]; then
    echo " 测试组测试失败：VIP 不通，可能 XDP 规则未生效或后端宕机。"
    exit 1
fi

echo ""
echo "========================================================"
echo "  延迟基准测试结果 (Round Trip Time)                  "
echo "========================================================"
printf "%-25s | %-12s | %-12s | %-12s | %-12s | %-12s\n" "转发路径" "平均延迟 (ms)" "最小延迟 (ms)" "最大延迟 (ms)" "P99 延迟 (ms)" "成功率"
echo "-------------------------------------------------------------------------------------------------"
printf "%-21s | %-13s | %-13s | %-13s | %-13s | %-12s\n" "1. Linux Kernel" "$avg1" "$min1" "$max1" "$p991" "$success1"
printf "%-21s | %-13s | %-13s | %-13s | %-13s | %-12s\n" "2. eBPF XDP (VIP)" "$avg2" "$min2" "$max2" "$p992" "$success2"
echo "-------------------------------------------------------------------------------------------------"

# 计算性能提升百分比
improvement=$(awk "BEGIN {print (($avg1 - $avg2) / $avg1) * 100}")
printf " 性能结论: XDP 负载均衡器使平均网络延迟降低了 \033[1;32m%.2f%%\033[0m！\n" "$improvement"

jitter1=$(awk "BEGIN {print $p991 - $avg1}")
jitter2=$(awk "BEGIN {print $p992 - $avg2}")
echo " 抖动分析: Linux 内核的 P99 抖动为 ${jitter1}ms, XDP 抖动为 ${jitter2}ms."
echo "========================================================"
