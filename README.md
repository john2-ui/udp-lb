# UDP 负载均衡器

## 内核态程序编译命令

在udp-lb-ebpf目录下执行以下命令，输出目录为target/bpfel-unknown-none/release/udp-lb

```bash
cargo +nightly build --release
```

## 用户态程序编译命令

在udp-lb目录下执行以下命令，输出目录为udp-lb/target/release/udp-lb

```bash
cargo build --release
```
<!-- TODO: 添加网路沙盒配置脚本-->