#!/usr/bin/env python3
"""
proxy_logger_fd.py

说明：
- 被 main.go 调用，每个连接传入 fd 和 task_id。
- 自动从 task_id 推导 scheduler / file / round。
- 记录每个子流的 segs_out / rtt_us / ooopack / link_type 等指标。
- 输出到 proxy_metrics.csv。

依赖：
- Python 模块 mpsched
"""

import os
import sys
import csv
import time
import argparse
import mpsched
import socket
import struct

# ✅ 你需要手动维护的列表 —— 与 UE 端 sender 文件和脚本保持一致
SCHEDULERS = ["default", "roundrobin", "redundant", "blest"]
FILES = ["8MB.file"]
N_ROUNDS = 1

# ✅ 映射 IP 到链路类型
LINK_MAP = {
    "10.60.0.1": "5G",
    "10.60.0.2": "Wi-Fi"
}

# 将 u32 IP 转为 IPv4 字符串
def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def detect_link_type(dst_ip):
    ip_str = int_to_ip(dst_ip)
    return LINK_MAP.get(ip_str, "Unknown")

# ✅ 从 task_id 还原 scheduler, file, round
def decode_task(task_id):
    total_files = len(FILES)
    total_scheds = len(SCHEDULERS)

    sched_idx = task_id // (total_files * N_ROUNDS)
    file_idx = (task_id // N_ROUNDS) % total_files
    round_idx = task_id % N_ROUNDS

    scheduler = SCHEDULERS[sched_idx]
    file_name = FILES[file_idx]
    round_num = round_idx + 1

    return scheduler, file_name, round_num

# ✅ 主函数：记录所有子流指标
def log_metrics(fd, task_id, output_file):
    subs = mpsched.get_sub_info(fd)

    scheduler, file_name, round_num = decode_task(task_id)

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
            "scheduler": scheduler,
            "file": file_name,
            "round": round_num,
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

    print(f"[✓] Logged {len(rows)} subflows for task_id={task_id} ({scheduler}, {file_name}, round {round_num})")

# ✅ 参数解析和调用入口
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["persist","log"], required=True,
        help="persist 只打标记；log 则打标记+记录指标")
    parser.add_argument("--fd", type=int, required=True, help="Socket file descriptor")
    parser.add_argument("--task", type=int, required=True, help="Task ID (调度器 × 文件 × 轮次)")
    parser.add_argument("--output", type=str, default="proxy_metrics.csv", help="Output CSV file")
    args = parser.parse_args()

    # 保留 fd 状态
#    mpsched.persist_state(args.fd)

    # 等待连接完成后再记录
#    time.sleep(0.2)

 #   log_metrics(args.fd, args.task, args.output)

if args.mode == "persist":
    # 只打 persist 标记
    mpsched.persist_state(args.fd)
    sys.exit(0)

# mode == "log"，才打标记、sleep、再记录
#mpsched.persist_state(args.fd)
#time.sleep(0.2)
log_metrics(args.fd, args.task, args.output)

if __name__ == "__main__":
    main()
