#!/bin/sh
# Puts this peer behind its router (or on the internet, for NAT none), and tunnels loopback ws to the forwarder.
# WsSignal refuses ws:// to anything but loopback, and the lab has no public certificate.
set -eu
wan=$(ip -o -4 addr | awk '$4 ~ /^203\.0\.113\./ {print $2}')
lan=$(ip -o -4 addr | awk '$4 ~ /^10\./ {print $2}')
if [ "$NAT" = none ]; then
    ip link set "$lan" down
else
    ip link set "$wan" down
    ip route replace default via "$GATEWAY"
fi
if [ "${MULTICAST:-}" = block ]; then
    ip route add blackhole 224.0.0.0/4
fi
socat TCP-LISTEN:8787,bind=127.0.0.1,fork,reuseaddr TCP:203.0.113.2:443 &
exec "$@"
