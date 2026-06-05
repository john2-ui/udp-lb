#!/bin/bash

# 确保以 root 权限运行
if [ "$EUID" -ne 0 ]; then
  echo "请使用 root 权限（sudo）运行此脚本！"
  exit 1
fi

LB_BIN="./target/release/udp-lb"
LB_LOG="/tmp/udp-lb-runtime.log"

echo "========================================================"
echo "开始自动化 XDP FullNAT 负载均衡器功能测试"
echo "========================================================"

# 1. 检查编译程序是否存在
if [ ! -f "$LB_BIN" ]; then
    echo "未找到编译产物，正在尝试自动编译项目..."
    cargo build --release
    if [ $? -ne 0 ]; then
        echo "编译失败，请检查代码错误后重试！"
        exit 1
    fi
fi

# 2. 检查环境是否已经初始化（通过判断 ns-lb 是否存在）
if ! ip netns list | grep -q "ns-lb"; then
    echo "检测到网络环境未配置，正在自动执行 setup_env.sh..."
    if [ -f "./setup_env.sh" ]; then
        chmod +x setup_env.sh
        ./setup_env.sh
    else
        echo "未找到 setup_env.sh 脚本，请确保它在当前目录下！"
        exit 1
    fi
fi

# 3. 确保清理上一次可能残留的后台 LB 进程
sudo pkill -f "./target/release/udp-lb" 2>/dev/null

echo "--> 正在 ns-lb 命名空间中启动 eBPF 负载均衡器..."
# 在 ns-lb 内部后台启动程序，日志输出到临时文件
ip netns exec ns-lb env RUST_LOG=info $LB_BIN > $LB_LOG 2>&1 &
LB_PID=$!

# 设置退出钩子：确保脚本不管由于什么原因崩溃或退出，都能把后台的 LB 进程杀掉，防止内核 XDP 残留
trap "echo -e '\n--> 正在清理测试进程...'; kill $LB_PID 2>/dev/null; echo '✨ 测试环境已安全复位。'" EXIT

# 等待 2 秒让 eBPF 字节码完全加载并下发配置
sleep 2

# 检查进程是否还在运行（防止由于验证器拒绝或找不到文件直接闪退）
if ! kill -0 $LB_PID 2>/dev/null; then
    echo "负载均衡器启动闪退！错误日志如下："
    echo "----------------------------------------"
    cat $LB_LOG
    echo "----------------------------------------"
    exit 1
fi
echo "负载均衡器运行正常 (PID: $LB_PID)。"

echo -e "\n--> 开始从 ns-client 发起 UDP 探测请求 (共 8 次)..."
echo "--------------------------------------------------------"

# 统计两台后端真实服务器的命中次数
RS1_COUNT=0
RS2_COUNT=0

for i in {1..8}
do
    # 每次使用 nc 发送一个 UDP 包。
    # 因为没有固定源端口，每次 nc 启动都会分配不同的临时端口，从而触发哈希环分流
    RESPONSE=$(echo "HELO" | ip netns exec ns-client nc -u -w 1 10.0.0.1 8080 2>/dev/null)
    
    if [[ "$RESPONSE" == *"Real Server 1"* ]]; then
        echo "第 $i 次请求命中 -> [RS1] 192.168.1.10"
        ((RS1_COUNT++))
    elif [[ "$RESPONSE" == *"Real Server 2"* ]]; then
        echo "第 $i 次请求命中 -> [RS2] 192.168.1.11"
        ((RS2_COUNT++))
    else
        echo "第 $i 次请求失败 -> 收到未知响应或超时: '$RESPONSE'"
    fi
    sleep 0.2
done

echo "--------------------------------------------------------"
echo "测试数据统计结论："
echo "后端 Real Server 1 命中次数: $RS1_COUNT"
echo "后端 Real Server 2 命中次数: $RS2_COUNT"

# 4. 自动化断言
if [ $RS1_COUNT -gt 0 ] && [ $RS2_COUNT -gt 0 ]; then
    echo -e "\n测试【通过】: 成功验证了跨 Namespace 的 FullNAT 转发和动态一致性哈希分流！"
else
    echo -e "\n测试【失败】: 流量未能成功分流到两个后端。请排查哈希环配置或网络连接。"
    echo -e "你可以通过查看 $LB_LOG 获取控制台输出。"
fi