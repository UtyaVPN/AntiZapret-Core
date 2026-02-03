#!/bin/bash
set -e

log() {
    echo -e "\033[1;34m[SYSTEM]\033[0m $1"
}

log "Setting up host kernel parameters..."
modprobe nf_conntrack || log "Warning: Failed to load nf_conntrack"

if [ -f "/etc/sysctl.d/99-antizapret.conf" ]; then
    log "Applying sysctl parameters..."
    while read -r line; do
        [[ "$line" =~ ^#.* ]] && continue
        [[ -z "$line" ]] && continue
        sysctl -w "$line" || log "Warning: Failed to set sysctl: $line"
    done < /etc/sysctl.d/99-antizapret.conf
fi

if [ ! -d "/root/antizapret/config/manual" ] || [ ! -d "/root/antizapret/config/sources" ]; then
    log "Initializing config directory structure..."
    mkdir -p /root/antizapret/config/manual /root/antizapret/config/sources
    cp -rn /root/antizapret/config_default/* /root/antizapret/config/
fi

log "Generating AntiZapret setup file..."
{
    echo "SETUP_DATE=$(date --iso-8601=seconds)"
    echo "ANTIZAPRET_DNS=$ANTIZAPRET_DNS"
    echo "ALTERNATIVE_IP=$ALTERNATIVE_IP"
    echo "ALTERNATIVE_FAKE_IP=$ALTERNATIVE_FAKE_IP"
    echo "SSH_PROTECTION=$SSH_PROTECTION"
    echo "ATTACK_PROTECTION=$ATTACK_PROTECTION"
    echo "CLEAR_HOSTS=$CLEAR_HOSTS"
} > /root/antizapret/setup

chmod +x /root/antizapret/*.sh
log "Initial rule generation (doall.sh)..."
/root/antizapret/doall.sh noclear 2>&1 | awk '{printf "\033[1;32m[UPDATE]\033[0m %s\n", $0; fflush()}'

cleanup() {
    log "Stopping services..."
    /root/antizapret/down.sh
    killall cron 2>/dev/null || true
    PIDS=$(pgrep -f "kresd|python3 /root/antizapret/proxy.py")
    [ -n "$PIDS" ] && kill $PIDS 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

/usr/sbin/cron -f 2>&1 | awk '{printf "\033[1;35m[CRON]\033[0m %s\n", $0; fflush()}' &

DEFAULT_ROUTE_INFO=$(ip -o -4 route show to default | head -n 1)
export DEFAULT_INTERFACE=$(echo "$DEFAULT_ROUTE_INFO" | awk '{print $5}')
export DEFAULT_IP=$(ip -o -4 addr show dev "$DEFAULT_INTERFACE" | awk '{print $4}' | cut -d/ -f1)

log "Network: Interface=$DEFAULT_INTERFACE, IP=$DEFAULT_IP"
mkdir -p /run/knot-resolver
chown knot-resolver:knot-resolver /run/knot-resolver

log "Starting knot-resolver (Mode: $ANTIZAPRET_DNS)..."
SYSTEMD_INSTANCE=1 /usr/sbin/kresd -n -c /etc/knot-resolver/kresd.conf /run/knot-resolver 2>&1 | awk '{printf "\033[1;36m[DNS1]\033[0m %s\n", $0; fflush()}' &
KRESD1_PID=$!
SYSTEMD_INSTANCE=2 /usr/sbin/kresd -n -c /etc/knot-resolver/kresd.conf /run/knot-resolver 2>&1 | awk '{printf "\033[1;36m[DNS2]\033[0m %s\n", $0; fflush()}' &
KRESD2_PID=$!
sleep 5

log "Finalizing network setup (up.sh)..."
set +e
/root/antizapret/up.sh
UP_SH_EXIT_CODE=$?
set -e
if [ "$UP_SH_EXIT_CODE" -ne 0 ]; then
    log "\033[1;31mError: up.sh failed with exit code $UP_SH_EXIT_CODE\033[0m"
    exit "$UP_SH_EXIT_CODE"
fi

log "Starting proxy.py..."
/usr/bin/python3 -u /root/antizapret/proxy.py --upstream 127.0.0.1:53 --address 127.0.0.2 2>&1 | awk '{printf "\033[1;33m[PROXY]\033[0m %s\n", $0; fflush()}' &
PROXY_PY_PID=$!

log "\033[1;32mAntiZapret-Core is ready!\033[0m"
wait -n $KRESD1_PID $KRESD2_PID $PROXY_PY_PID
log "\033[1;31mOne of the critical processes has exited. Terminating container...\033[0m"
cleanup
