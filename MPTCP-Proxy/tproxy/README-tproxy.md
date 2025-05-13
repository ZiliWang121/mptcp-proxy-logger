# Transparent Proxy with TPROXY for MPTCP Redirection

This setup enables transparent proxying of **MPTCP traffic from UE** using **TPROXY**, allowing:

```
UE (MPTCP) ──> Free5GC (with TPROXY) ──> Proxy ──> Echo Server (TCP)
```

## Why TPROXY?

Standard `REDIRECT` rules don't work for:
- Non-local destination IPs
- Traffic from virtual interfaces (like `upfgtp` created by Free5GC)

**TPROXY** supports these scenarios and keeps the original destination address.

## Files Overview

### `setup_tproxy.sh`
Adds TPROXY rules and routing:

```bash
iptables -t mangle -A PREROUTING -p tcp --dport 8888 -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -p tcp --dport 8888 -j TPROXY --on-port 52000 --tproxy-mark 1
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

### `run_proxy_tproxy.sh`
Starts proxy:

```bash
sudo ./mptcp-proxy --transparent --mode server --port 52000
```

### `clean_tproxy.sh`
Cleans all TPROXY rules and routes.


## Proxy Binding (`main.go`)
Proxy must bind to `upfgtp` interface to receive traffic:

```go
syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1)
syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "upfgtp")
```
