#!/bin/sh
# Probes the NAT in front of this peer with RFC 5780 (coturn's natdiscovery), and prints what it found.
set -u
out=$(turnutils_natdiscovery -m -f 203.0.113.10 2>&1)
mapping=$(printf '%s\n' "$out" | sed -n 's/^NAT with \(.*\) Mapping!$/\1/p')
filtering=$(printf '%s\n' "$out" | sed -n 's/^NAT with \(.*\) Filtering!$/\1/p')
tcp443=no
timeout 3 bash -c "exec 3<>/dev/tcp/203.0.113.10/443" 2>/dev/null && tcp443=ok
echo "mapping=${mapping:-none} filtering=${filtering:-none} tcp443=$tcp443"
