#!/bin/bash

# Flush mangle table rules
sudo iptables -t mangle -F
sudo iptables -t mangle -X DIVERT 2>/dev/null

# Remove fwmark and routing table 100
sudo ip rule del fwmark 1 table 100 2>/dev/null
sudo ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null
