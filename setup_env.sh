#!/bin/bash

# 确保以 root 权限运行
if [ "$EUID" -ne 0 ]; then
  echo "请使用 root 权限（sudo）运行此脚本！"
  exit 1
fi

echo "清理旧的 Namespace 和网桥..."
ip netns del ns-client 2>/dev/null
ip netns del ns-lb 2>/dev/null
ip netns del ns-rs1 2>/dev/null
ip netns del ns-rs2 2>/dev/null
ip link del br0 2>/dev/null
rm -rf /tmp/nginx-test 2>/dev/null

echo "1. 创建虚拟网桥 br0..."
ip link add br0 type bridge
ip link set br0 up

echo "2. 创建四个隔离的 Network Namespace..."
ip netns add ns-client
ip netns add ns-lb
ip netns add ns-rs1
ip netns add ns-rs2

# 辅助函数：创建 veth pair 并一端绑定到网桥，一端移入 Namespace 并改名为 eth0
setup_ns_interface() {
    local ns=$1
    local veth_host="veth-${ns}"
    local veth_ns="eth0"
    local mac=$2

    # 创建 veth 对
    ip link add $veth_host type veth peer name $veth_ns netns $ns
    # 将宿主机端挂载到网桥上
    ip link set $veth_host master br0
    ip link set $veth_host up
    
    # 如果指定了 MAC 地址，则强制修改（用于精准匹配你的 config.yaml）
    if [ ! -z "$mac" ]; then
        ip netns exec $ns ip link set dev $veth_ns address $mac
    fi
    
    # 启动 Namespace 内的网卡
    ip netns exec $ns ip link set eth0 up
    ip netns exec $ns ip link set lo up
}

echo "3. 建立连接并配置 RS 的专属 MAC 地址..."
setup_ns_interface ns-client ""
setup_ns_interface ns-lb ""
# 这里的 MAC 地址必须与你的 config.yaml 保持绝对一致
setup_ns_interface ns-rs1 "00:11:22:33:44:55"
setup_ns_interface ns-rs2 "00:11:22:33:44:66"

echo "4. 配置各个网络环境的 IP 地址..."
# Client IP
ip netns exec ns-client ip addr add 10.0.0.5/24 dev eth0

# LB 网卡配置多个 IP (VIP, LIP, 以及与 RS 建立 ARP 邻居的 IP)
ip netns exec ns-lb ip addr add 10.0.0.1/24 dev eth0      # VIP
ip netns exec ns-lb ip addr add 10.0.0.254/24 dev eth0    # LIP
ip netns exec ns-lb ip addr add 192.168.1.254/24 dev eth0 # 充当 RS 的网关

# Real Server IPs
ip netns exec ns-rs1 ip addr add 192.168.1.10/24 dev eth0
ip netns exec ns-rs2 ip addr add 192.168.1.11/24 dev eth0

echo "5. 配置路由表..."
# 客户端的默认网关指向 VIP
ip netns exec ns-client ip route add default via 10.0.0.1 dev eth0

# 后端 RS 回包给 LIP (10.0.0.254) 时，必须通过 LB 的 192.168.1.254 接口进行路由转发
ip netns exec ns-rs1 ip route add default via 192.168.1.254 dev eth0
ip netns exec ns-rs2 ip route add default via 192.168.1.254 dev eth0

echo "6. 启动 Nginx 作为支持 UDP 的后端服务器..."
mkdir -p /tmp/nginx-test

# 生成 RS1 的 Nginx UDP 测试配置
cat << 'EOF' > /tmp/nginx-test/rs1.conf
error_log /tmp/nginx-test/error_rs1.log info;
pid /tmp/nginx-test/rs1.pid;
events { worker_connections 1024; }
stream {
    server {
        listen 8080 udp;
        return "Hello from Nginx Real Server 1 (192.168.1.10)\n";
    }
}
EOF

# 生成 RS2 的 Nginx UDP 测试配置
cat << 'EOF' > /tmp/nginx-test/rs2.conf
error_log /tmp/nginx-test/error_rs2.log info;
pid /tmp/nginx-test/rs2.pid;
events { worker_connections 1024; }
stream {
    server {
        listen 8080 udp;
        return "Hello from Nginx Real Server 2 (192.168.1.11)\n";
    }
}
EOF

# 在各自的 Namespace 中以 root 身份独立启动 Nginx
ip netns exec ns-rs1 nginx -c /tmp/nginx-test/rs1.conf
ip netns exec ns-rs2 nginx -c /tmp/nginx-test/rs2.conf

echo "--------------------------------------------------------"
echo "🎉 测试环境创建成功！"
echo "Client 节点  -> Namespace: ns-client | IP: 10.0.0.5"
echo "LB 负载均衡  -> Namespace: ns-lb     | VIP: 10.0.0.1, LIP: 10.0.0.254 (网卡: eth0)"
echo "RS1 服务器   -> Namespace: ns-rs1    | IP: 192.168.1.10, MAC: 00:11:22:33:44:55"
echo "RS2 服务器   -> Namespace: ns-rs2    | IP: 192.168.1.11, MAC: 00:11:22:33:44:66"
echo "--------------------------------------------------------"