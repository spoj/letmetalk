#!/bin/sh
# Runs each pair in pairs.txt (or $PAIRS): brings its topology up, probes each NAT with RFC 5780, runs the roles,
# keeps their output in results/<pair>/, and tears down. Then writes trial/2-lab.md. A NAT that probes differently
# from its label fails the run. COMPOSE picks the compose command: "docker compose" in CI, "podman-compose" locally.
set -eu
cd "$(dirname "$0")"
COMPOSE=${COMPOSE:-docker compose}
compose() { $COMPOSE -f compose.yml -p lab "$@" </dev/null; }
trap 'compose down -t 1 >/dev/null 2>&1' EXIT
rm -rf results
mkdir results
compose build >results/build.log 2>&1

# What natdiscovery and the TCP check report behind each NAT label, as a pattern. Filtering is the same for none and
# eif. A public peer may also report no mapping at all, since its mapped address is its own.
expect() {
    case $1 in
        none) echo "mapping=(none|Endpoint Independent) filtering=Endpoint Independent tcp443=ok" ;;
        eif) echo "mapping=Endpoint Independent filtering=Endpoint Independent tcp443=ok" ;;
        pr) echo "mapping=Endpoint Independent filtering=Address and Port Dependent tcp443=ok" ;;
        sym) echo "mapping=Address and Port Dependent filtering=Address and Port Dependent tcp443=ok" ;;
        blk) echo "mapping=none filtering=none tcp443=ok" ;;
    esac
}

run_pair() {
    name=$1 svc_a=$2 nat_a=$3 svc_b=$4 nat_b=$5 profile=$6 flags=$7
    dir=results/$name
    mkdir "$dir"
    NAT_A=none NAT_B=none NAT_H=none
    for slot in "$svc_a $nat_a" "$svc_b $nat_b"; do
        set -- $slot
        case $1 in
            *-a*) NAT_A=$2 ;;
            *-b*) NAT_B=$2 ;;
            *-h*) NAT_H=$2 ;;
        esac
    done
    MULTICAST=
    [ "$flags" = mcast-block ] && MULTICAST=block
    routers=
    [ "$NAT_A" = none ] || routers="$routers router-a"
    [ "$NAT_B" = none ] || routers="$routers router-b"
    [ "$NAT_H" = none ] || routers="$routers router-h"
    peers=$svc_a
    [ "$svc_b" = "$svc_a" ] || peers="$peers $svc_b"
    export NAT_A NAT_B NAT_H MULTICAST

    compose down -t 1 >/dev/null 2>&1
    compose up -d signal coturn-member coturn-stranger iroh-relay $routers $peers >"$dir/up.log" 2>&1

    for svc in $peers; do
        case $svc in
            *-a*) nat=$NAT_A ;;
            *-b*) nat=$NAT_B ;;
            *-h*) nat=$NAT_H ;;
        esac
        compose exec -T "$svc" /lab/nat-check.sh >"$dir/probe-$svc.txt"
        if ! grep -Eqx "$(expect "$nat")" "$dir/probe-$svc.txt"; then
            echo "$name: $svc is labelled $nat but probes as: $(cat "$dir/probe-$svc.txt")" >&2
            exit 1
        fi
    done

    for svc in $peers; do
        compose exec -T "$svc" /lab/shape.sh "$profile"
    done

    accept_key=/lab/keys/${svc_b#*-}.key
    [ "$svc_a" = "$svc_b" ] && accept_key=/lab/keys/a2.key
    compose exec -T "$svc_b" /lab/standin-bench.sh accept "$accept_key" >"$dir/accept.json" &
    accept=$!
    compose exec -T "$svc_a" /lab/standin-bench.sh dial /lab/keys/${svc_a#*-}.key >"$dir/dial.json"
    wait "$accept"
    compose down -t 1 >/dev/null 2>&1
    echo "$name: done"
}

grep -v "^#" "${PAIRS:-pairs.txt}" | while read -r name svc_a nat_a svc_b nat_b profile flags; do
    run_pair "$name" "$svc_a" "$nat_a" "$svc_b" "$nat_b" "$profile" "$flags"
done

{
    echo "# Lab results"
    echo
    echo "Written by \`lab/run.sh\`. The roles are stand-ins until the bench lands: each row checks the NAT and then that"
    echo "both peers log in through it and the dialer relays over UDP and TLS. Not measurements."
    echo
    echo "| pair | profile | NAT a | NAT b | dialer relay (udp, tls 443) | accepter ICE URLs |"
    echo "|---|---|---|---|---|---|"
    grep -v "^#" "${PAIRS:-pairs.txt}" | while read -r name svc_a nat_a svc_b nat_b profile flags; do
        dial=results/$name/dial.json
        accept=results/$name/accept.json
        echo "| $name | $profile | $nat_a | $nat_b | $(jq -r '"\(.relay_udp), \(.relay_tls443)"' "$dial") | $(jq -r '.ice_urls | length' "$accept") |"
    done
} >../trial/2-lab.md
