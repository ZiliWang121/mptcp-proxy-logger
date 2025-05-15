#!/usr/bin/env python3
"""
proxy_logger_fd.py
脚本说明：
- 被 proxy 的 main.go 每次连接自动调用
- 获取连接的 socket fd（传入），调用 mpsched 记录 MPTCP 各子流指标
- 同时接收 task_id：即当前是第几个调度器-文件-轮次组合（类似 server 上的结构）

依赖：
- 自定义 mpsched Python 模块（必须已编译并安装）
"""

import os
import sys
import csv
import time
import argparse
import mpsched
import socket
import struct

# 🔧 你 testbed 中的接口 → 链路类型映射
LINK_MAP = {
    "10.60.0.1": "5G",
    "10.60.0.2": "Wi-Fi"
}

# 将 u32 ip 转换为 IPv4 字符串
def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def detect_link_type(dst_ip):
    ip_str = int_to_ip(dst_ip)
    return LINK_MAP.get(ip_str, "Unknown")

def log_metrics(fd, task_id, output_file):
    """
    获取每个子流的：
    - tcpi_segs_out
    - tcpi_rtt
    - tcpi_rcv_ooopack
    - dst_addr → link_type

    记录为 CSV，每行为一个子流的数据
    """
    subs = mpsched.get_sub_info(fd)

    rows = []
    for i, sub in enumerate(subs):
        segs_out = sub[0]
        rtt_us = sub[1]
        dst_ip = sub[5]
        ooopack = sub[6]

        ip_str = int_to_ip(dst_ip)
        link_type = detect_link_type(dst_ip)

        rows.append({
            "task_id": task_id,
            "subflow_id": i,
            "link_type": link_type,
            "rtt_us": rtt_us,
            "segs_out": segs_out,
            "recv_ooopack": ooopack
        })

    file_exists = os.path.isfile(output_file)
    with open(output_file, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)

    print(f"[✓] Logged metrics for task_id={task_id} with {len(rows)} subflows")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fd", type=int, required=True, help="Socket file descriptor")
    parser.add_argument("--task", type=int, required=True, help="Task ID (调度器 × 文件 × 第几轮)")
    parser.add_argument("--output", type=str, default="proxy_metrics.csv", help="Output CSV file")
    args = parser.parse_args()

    # 告诉内核保留此 fd 的 MPTCP 子流状态
    mpsched.persist_state(args.fd)

    # ⏱ 等待数据收完后再读取子流信息（避免提前）
    time.sleep(0.2)

    log_metrics(args.fd, args.task, args.output)

if __name__ == "__main__":
    main()
