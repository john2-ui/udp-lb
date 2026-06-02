#!/bin/bash

set -e  # 出错立即停止

echo "========================================"
echo "  开始编译 udp-lb-ebpf (eBPF 程序)"
echo "========================================"

# 1. 编译 eBPF 程序
cd udp-lb-ebpf
cargo +nightly build --release
cd ..

echo -e "\n========================================"
echo "  开始编译 udp-lb (用户态程序)"
echo "========================================"

# 2. 编译用户态程序
cd udp-lb
cargo build --release
cd ..

echo -e "\n========================================"
echo "  ✅ 编译全部完成！"
echo "========================================"
echo "eBPF 程序输出：udp-lb-ebpf/target/bpfel-unknown-none/release/udp-lb"
echo "用户态程序输出：udp-lb/target/release/udp-lb"