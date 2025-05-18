#!/usr/bin/env python3
"""
Receiver with MPTCP subflow metrics (5G / Wi-Fi OFO stats)
- Retains original receiver_logger_file.py functionality
- Fixes OFO queue stats collection based on live sampling during connection
"""

import socket
import struct
import time
import csv
from collections import defaultdict
import os
import mpsched

# ------------------- Configuration -------------------
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 8888
CHUNK_SIZE = 16 * 1024  # 即 16KB
SCHEDULER_LIST = ["default", "roundrobin", "redundant", "blest"]
FILE_LIST = ["8MB.file", "256MB.file"]
CSV_LOG = "recv_log.csv"
CSV_SUMMARY = "summary.csv"

# IP address mapping to subflows
IP_5G = "10.60.0.1"
IP_WIFI = "10.60.0.2"
# ------------------------------------------------------

def recv_exact(sock, size):
    buf = b''
    while len(buf) < size:
        try:
            chunk = sock.recv(size - len(buf))
            if not chunk:
                return None
            buf += chunk
        except socket.timeout:
            raise TimeoutError("Receive timeout")
    return buf

# Initialize TCP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((LISTEN_IP, LISTEN_PORT))
sock.listen(5)
print(f"[Server] Listening on {LISTEN_IP}:{LISTEN_PORT}")

# First connection: receive number of rounds from client
print("[Server] Waiting for round count...")
conn, addr = sock.accept()
n_rounds_bytes = recv_exact(conn, 4)
N_ROUNDS = struct.unpack("!I", n_rounds_bytes)[0]
conn.close()
print(f"[Server] Received N_ROUNDS = {N_ROUNDS}")

# Load existing CSV_LOG and find round offsets
round_offset = defaultdict(int)
try:
    with open(CSV_LOG, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = (row["Scheduler"], row["File"])
            if row["Round"].isdigit():
                round_offset[key] = max(round_offset[key], int(row["Round"]))
    print(f"[Server] Detected round offset per key: {dict(round_offset)}")
except FileNotFoundError:
    print("[Server] No previous log found, starting fresh.")

# Construct expected test tasks
expected_tasks = []
for sched in SCHEDULER_LIST:
    for fname in FILE_LIST:
        base = round_offset.get((sched, fname), 0)
        for i in range(N_ROUNDS):
            round_id = base + i + 1
            expected_tasks.append((sched, fname, round_id))

file_metrics = defaultdict(list)

# Open log file
file_exists = os.path.exists(CSV_LOG)
csvfile = open(CSV_LOG, "a", newline='')
csvwriter = csv.writer(csvfile)
if not file_exists:
    csvwriter.writerow([
        "Scheduler", "File", "Round", "NumChunks", "AvgDelay(ms)",
        "Goodput(KB/s)", "DownloadTime(s)", "OFO_5G", "OFO_WiFi"
    ])

# Main loop
for task_index, (sched, fname, round_id) in enumerate(expected_tasks, 1):
    print(f"\n[Server] Waiting for: Scheduler={sched}, File={fname}, Round={round_id}")
    conn, addr = sock.accept()
    print(f"[Server] Connection from {addr}")
    conn.settimeout(10)
    fd = conn.fileno()
    mpsched.persist_state(fd)

    recv_bytes = 0
    delay_sum = 0
    chunk_count = 0
    start_time = time.time()

    # 初始化 OFO 变量
    ofo_5g = 0
    ofo_wifi = 0

    try:
        while True:
            try:
                data = recv_exact(conn, CHUNK_SIZE)
                if data is None:
                    print("[Info] Connection closed by client.")
                    break
            except TimeoutError as e:
                print(f"[Warning] Receive timeout: {e}")
                break

            recv_time = time.time()
            try:
                send_ts = struct.unpack("!d", data[:8])[0]
            except Exception as e:
                print(f"[Error] Failed to parse timestamp: {e}")
                continue

            delay_ms = (recv_time - send_ts) * 1000
            delay_sum += delay_ms
            recv_bytes += len(data)
            chunk_count += 1

            # 每轮接收数据后实时获取当前 OFO
            subs = mpsched.get_sub_info(fd)

            for idx, sub in enumerate(subs):
                try:
                    dst_ip_raw = sub[5]  # 原始整数 IP
                    #local_ip = socket.inet_ntoa(struct.pack("!I", dst_ip_raw))
                    local_ip = socket.inet_ntoa(struct.pack("<I", dst_ip_raw))  # 改成 little-endian（host byte order）
                    ofo_count = sub[6]

                    if local_ip == IP_5G:
                        ofo_5g = ofo_count
                    elif local_ip == IP_WIFI:
                        ofo_wifi = ofo_count

                except Exception as e:
                    print(f"[Warning] Failed to parse subflow info: {e}")

    finally:
        conn.close()

    end_time = time.time()
    duration = end_time - start_time
    avg_delay = delay_sum / chunk_count if chunk_count > 0 else 0
    goodput = (recv_bytes / 1024) / duration if duration > 0 else 0

    if chunk_count == 0:
        print(f"[Error] No data received: {sched}-{fname} Round {round_id}")

    # Log per-round result
    csvwriter.writerow([
        sched, fname, round_id, chunk_count,
        avg_delay, goodput, duration, ofo_5g, ofo_wifi
    ])
    file_metrics[(sched, fname)].append({
        "chunks": chunk_count,
        "delay": avg_delay,
        "goodput": goodput,
        "time": duration
    })

    print(f"[Result] {sched} | {fname} (Round {round_id}): Delay = {avg_delay:.2f} ms | "
          f"Goodput = {goodput:.2f} KB/s | Time = {duration:.2f} s | OFO_5G = {ofo_5g} | OFO_WiFi = {ofo_wifi}")

csvfile.close()
sock.close()

# Write summary
with open(CSV_SUMMARY, "w", newline='') as summary:
    writer = csv.writer(summary)
    writer.writerow([
        "Scheduler", "File", "AvgChunks", "AvgDelay(ms)",
        "AvgGoodput(KB/s)", "AvgDownloadTime(s)"
    ])
    for sched in SCHEDULER_LIST:
        for fname in FILE_LIST:
            metrics = file_metrics[(sched, fname)]
            if not metrics:
                continue
            avg_chunks = sum(m["chunks"] for m in metrics) / len(metrics)
            avg_delay = sum(m["delay"] for m in metrics) / len(metrics)
            avg_goodput = sum(m["goodput"] for m in metrics) / len(metrics)
            avg_time = sum(m["time"] for m in metrics) / len(metrics)
            writer.writerow([sched, fname, avg_chunks, avg_delay, avg_goodput, avg_time])

print("\n=== Summary written to summary.csv ===")
