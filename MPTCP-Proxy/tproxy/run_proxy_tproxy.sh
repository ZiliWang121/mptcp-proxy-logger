#!/bin/bash

# Ensure the mptcpproxy user exists
id -u mptcpproxy &>/dev/null || sudo useradd mptcpproxy

#cd ~/MPTCP-Proxy
#sudo -u mptcpproxy ./mptcp-proxy -m server -p 52000 -t
#!/bin/bash

# Start proxy as root (not using sudo -u anymore)
cd ~/MPTCP-Proxy
sudo ./mptcp-proxy -m server -p 52000 -t
