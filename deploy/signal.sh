#!/bin/sh
# Builds letmetalk-signal in a bookworm container (glibc 2.36, so it runs on Ubuntu 24.04), then deploys it with two
# coturn instances, the forwarder and a timer that copies letmeknow's ACME certificate. Rerun to update.
# Usage: deploy/signal.sh root@129.212.227.207
set -eu
host=$1
cd "$(dirname "$0")/.."
podman run --rm -v "$PWD:/src" -v letmetalk-cargo-registry:/usr/local/cargo/registry -w /src \
    docker.io/library/rust:1-bookworm \
    cargo build --release -p letmetalk-signal --target-dir /src/target/container
tmp=$(ssh "$host" mktemp -d)
scp -q target/container/release/letmetalk-signal crates/letmetalk-signal/coturn/member.conf \
    crates/letmetalk-signal/coturn/stranger.conf deploy/check.pub deploy/vps/* "$host:$tmp/"
ssh "$host" sh -s -- "$tmp" <<'REMOTE'
set -eu
src=$1
public=129.212.227.207
id letmetalk >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin letmetalk
dpkg -s coturn >/dev/null 2>&1 || {
    apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends coturn
    systemctl disable --now coturn
}
install -d -o root -g letmetalk -m 0750 /etc/letmetalk /etc/letmetalk/coturn /etc/letmetalk/tls
for name in member stranger; do
    [ -e /etc/letmetalk/$name.secret ] || (umask 077; openssl rand -hex 32 > /etc/letmetalk/$name.secret)
done
install -m 0755 "$src/letmetalk-signal" /usr/local/bin/letmetalk-signal
# The coturn configs are the repo's, plus this host's ports, relays, certificate and secret. The host's own
# addresses are denied as peers, so a relay cannot reach the forwarder or the other coturn.
turn_conf() {
    name=$1 port=$2 tls=$3 min=$4 max=$5
    {
        cat "$src/$name.conf"
        cat <<CONF
listening-port=$port
tls-listening-port=$tls
alt-listening-port=$((port + 10))
alt-tls-listening-port=$((tls + 10))
bps-capacity=125000000
relay-ip=$public
min-port=$min
max-port=$max
cert=/etc/letmetalk/tls/cert.pem
pkey=/etc/letmetalk/tls/key.pem
static-auth-secret=$(cat /etc/letmetalk/$name.secret)
CONF
        ip -o addr show scope global | awk '{ sub(/\/.*/, "", $4); print "denied-peer-ip=" $4 }'
    } > /etc/letmetalk/coturn/$name.conf
    chown root:letmetalk /etc/letmetalk/coturn/$name.conf
    chmod 0640 /etc/letmetalk/coturn/$name.conf
}
turn_conf member 3478 5349 49152 50151
turn_conf stranger 3479 5350 50152 50351
(umask 027; printf 'MEMBER_SECRET=%s\nSTRANGER_SECRET=%s\n' "$(cat /etc/letmetalk/member.secret)" \
    "$(cat /etc/letmetalk/stranger.secret)" > /etc/letmetalk/forwarder.env)
chown root:letmetalk /etc/letmetalk/forwarder.env
[ -e /etc/letmetalk/allowlist ] || install -m 0640 -o root -g letmetalk "$src/check.pub" /etc/letmetalk/allowlist
install -m 0755 "$src/letmetalk-tls-sync" /usr/local/sbin/letmetalk-tls-sync
install -m 0644 "$src/letmetalk-forwarder.service" "$src/letmetalk-turn@.service" \
    "$src/letmetalk-tls-sync.service" "$src/letmetalk-tls-sync.timer" /etc/systemd/system/
systemctl daemon-reload
/usr/local/sbin/letmetalk-tls-sync
systemctl enable --now letmetalk-turn@member letmetalk-turn@stranger letmetalk-forwarder letmetalk-tls-sync.timer
systemctl restart letmetalk-turn@member letmetalk-turn@stranger letmetalk-forwarder
systemctl --no-pager is-active letmetalk-turn@member letmetalk-turn@stranger letmetalk-forwarder letmetalk-tls-sync.timer
rm -rf "$src"
REMOTE
