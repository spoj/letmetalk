#!/bin/sh
# shape.sh <lan|wan|constrained> <dev>: netem on both directions of dev, ingress through ifb0.
# A peer's access link adds 12.5 ms each way under wan, so two peers see 50 ms RTT and 1% loss.
set -eu
case $1 in
    lan) exit 0 ;;
    wan) netem="delay 12.5ms loss 0.5%" ;;
    constrained) netem="rate 10mbit limit 5000" ;;
    *) echo "unknown profile $1" >&2; exit 1 ;;
esac
ip link add ifb0 type ifb
ip link set ifb0 up
tc qdisc add dev "$2" root netem $netem
tc qdisc add dev "$2" handle ffff: ingress
tc filter add dev "$2" parent ffff: matchall action mirred egress redirect dev ifb0
tc qdisc add dev ifb0 root netem $netem
