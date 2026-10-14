#!/bin/sh
# Stand-in for the bench's roles until crates/bench lands. Logs in to the forwarder through the tunnel and prints
# its ICE servers. A dial also allocates a TURN relay over UDP and over TLS on 443, to the forwarder. A relay that
# never answers (UDP blocked) times out, and counts as failed.
# Usage: standin-bench.sh <accept|dial> <key file>
set -eu
role=$1
login ws://127.0.0.1:8787/ws "$2" >/tmp/login.txt
key=$(awk '/^key /{print $2}' /tmp/login.txt)
user=$(awk '/^username /{print $2}' /tmp/login.txt)
pass=$(awk '/^credential /{print $2}' /tmp/login.txt)
urls=$(awk '/^url /{printf "%s\"%s\"", (n++ ? "," : ""), $2}' /tmp/login.txt)

relay() {
    out=$(timeout 30 turnutils_uclient "$@" -e 203.0.113.2 -u "$user" -w "$pass" 203.0.113.10 2>&1 || true)
    case $out in
        *"error ["[0-9]*) echo failed ;;
        *"Total transmit time"*) echo ok ;;
        *) echo failed ;;
    esac
}

udp=-
tls=-
if [ "$role" = dial ]; then
    udp=$(relay -n 3)
    tls=$(relay -t -S -n 3 -p 443)
fi
echo "{\"role\":\"$role\",\"key\":\"$key\",\"ice_urls\":[$urls],\"relay_udp\":\"$udp\",\"relay_tls443\":\"$tls\"}"
