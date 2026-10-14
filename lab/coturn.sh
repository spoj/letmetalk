#!/bin/sh
# Starts coturn from the repo's configs, plus this instance's addresses, relays and a lab secret. The second
# listening-ip is the alternate address that RFC 5780 probes use.
set -eu
ip addr add "$ALT/24" dev "$(ip -o -4 addr | awk '$4 ~ /^203\.0\.113\./ {print $2}')"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$IP" -addext "subjectAltName=IP:$IP" \
    -keyout /tmp/key.pem -out /tmp/cert.pem 2>/dev/null
conf=/tmp/turnserver.conf
{
    cat "/lab/coturn/$CONF.conf"
    cat <<CONF
listening-ip=$IP
listening-ip=$ALT
listening-port=3478
alt-listening-port=3479
tls-listening-port=443
alt-tls-listening-port=444
relay-ip=$IP
bps-capacity=125000000
min-port=49152
max-port=50151
cert=/tmp/cert.pem
pkey=/tmp/key.pem
static-auth-secret=$TURN_SECRET
denied-peer-ip=$IP
denied-peer-ip=$ALT
CONF
} > "$conf"
exec turnserver -c "$conf" --log-file=stdout
