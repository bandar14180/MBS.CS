#!/bin/sh
# MBS.SC PHASE 7 LAB -- customer-side WireGuard endpoint.
#
# Stands in for infrastructure the CUSTOMER operates. It is deliberately minimal: bring up
# wg0 from the mounted config, route the tunnel subnet, and stay alive. Nothing here is part
# of the MBS implementation under test -- the code being verified is the WORKER side.
set -eu

apk add --no-cache wireguard-tools-wg iproute2 iptables >/dev/null 2>&1

# `wg setconf` rather than `wg-quick`: same reason the worker avoids wg-quick -- no implicit
# route installation, so the routing table below is explicit.
ip link add dev wg0 type wireguard
wg setconf wg0 /etc/wireguard/wg0.conf
ip address add 10.99.0.1/24 dev wg0
ip link set wg0 up

# Masquerade tunnel traffic onto customer-a-net so the in-network target replies correctly
# without needing a route back to the tunnel subnet. This mirrors a customer gateway NATing
# the VPN range into its LAN, which is the common real deployment.
#
# Matched on the DESTINATION network rather than an interface name: Docker assigns eth0/eth1
# by network ordering, which is not guaranteed, and masquerading onto the wrong interface
# silently breaks the return path. `-d 10.90.0.0/24` names the customer LAN itself.
iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -d 10.90.0.0/24 -j MASQUERADE

echo "[lab-gw] wg0 up; interfaces:"
ip -o addr show | awk '{print "  " $2, $4}'
echo "[lab-gw] wireguard peers:"
wg show wg0 peers

# Stay in the foreground.
while true; do sleep 3600; done
