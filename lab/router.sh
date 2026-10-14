#!/bin/sh
# Routes between the internet network (the WAN) and the LANs behind this router, with the NAT in $NAT.
set -eu
wan=$(ip -o -4 addr | awk '$4 ~ /^203\.0\.113\./ {print $2}')
lans=$(ls /sys/class/net | grep -v -x -e lo -e "$wan" | paste -sd, -)
{
    echo "define wan = $wan"
    echo "define lans = { $lans }"
    echo "define peer = $PEER"
    cat "/lab/nat/$NAT.nft"
} | nft -f -
exec sleep infinity
