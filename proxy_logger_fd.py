#!/usr/bin/env python3
"""
proxy_logger_fd.py

说明：
- 被 main.go 调用，每个连接传入 fd 和 task_id，以及 mode（persist 或 log）。
- persist 只在内核打上快照标记；
- log 则拿当前子流数据写入 CSV。
"""

import os
import sys
import csv
import time
import argparse
import mpsched
import socket
import struct

# 你的配置
SCHEDULERS = ["default", "roundrobin", "redundant", "blest"]
FILES      = ["8MB.file"]
N_ROUNDS   = 1
LINK_MAP   = {
    "10.60.0.1": "5G",
    "10.60.0.2": "Wi-Fi"
}

def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def detect_link_type(dst_ip):
    return LINK_MAP.get(int_to_ip(dst_ip), "Unknown")

def decode_task(task_id):
    total_files  = len(FILES)
    sched_idx    = task_id // (total_files * N_ROUNDS)
    file_idx     = (task_id // N_ROUNDS) % total_files
    round_num    = (task_id % N_ROUNDS) + 1
    return SCHEDULERS[sched_idx], FILES[file_idx], round_num

def log_metrics(fd, task_id, output_file):
    subs = mpsched.get_sub_info(fd)
    scheduler, file_name, round_num = decode_task(task_id)
    rows = []
    for i, sub in enumerate(subs):
        rows.append({
            "task_id":      task_id,
            "scheduler":    scheduler,
            "file":         file_name,
            "round":        round_num,
            "subflow_id":   i,
            "link_type":    detect_link_type(sub[5]),
            "rtt_us":       sub[1],
            "segs_out":     sub[0],
            "recv_ooopack": sub[6],
        })
    # 如果没有任何子流，直接退出
    if not rows:
        print(f"[!] No subflows for task {task_id}")
        return
    exists = os.path.isfile(output_file)
    with open(output_file, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        if not exists:
            writer.writeheader()
        writer.writerows(rows)
    print(f"[✓] Logged {len(rows)} subflows for task_id={task_id}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["persist","log"], required=True,
                        help="persist: 打快照；log: 记录数据")
    parser.add_argument("--fd",   type=int, required=True,
                        help="Socket file descriptor")
    parser.add_argument("--task", type=int, required=True,
                        help="Task ID")
    parser.add_argument("--output", type=str, default="proxy_metrics.csv")
    args = parser.parse_args()

    if args.mode == "persist":
        # 先打快照标记
        mpsched.persist_state(args.fd)
        print(f"[→] persist_state on fd={args.fd}")
        return

    # args.mode == "log"
    # 等一小会儿，确保所有子流都建立完
    time.sleep(0.2)
    log_metrics(args.fd, args.task, args.output)

if __name__ == "__main__":
    main()
