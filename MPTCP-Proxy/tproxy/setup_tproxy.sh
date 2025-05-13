#!/bin/bash
grep -q '^100[[:space:]]' /etc/iproute2/rt_tables || echo "100 tproxy" | sudo tee -a /etc/iproute2/rt_tables
set -e

# Clean up existing rules
iptables -t mangle -F
ip rule del fwmark 1 lookup 100 || true
ip route del local 0.0.0.0/0 dev lo table 100 || true

# Add TPROXY rules
iptables -t mangle -A PREROUTING -p tcp --dport 8888 -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -p tcp --dport 8888 -j TPROXY --on-port 52000 --tproxy-mark 1

# Set up routing rules
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
