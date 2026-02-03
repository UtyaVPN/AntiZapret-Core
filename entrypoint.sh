#!/bin/bash
set -e

# Load kernel modules and set sysctl (requires privileged mode)
echo "Setting up host kernel parameters..."
modprobe nf_conntrack || echo "Warning: Failed to load nf_conntrack"

if [ -f "/etc/sysctl.d/99-antizapret.conf" ]; then
    echo "Applying sysctl parameters..."
    while read -r line; do
        [[ "$line" =~ ^#.* ]] && continue
        [[ -z "$line" ]] && continue
        sysctl -w "$line" || echo "Warning: Failed to set sysctl: $line"
    done < /etc/sysctl.d/99-antizapret.conf
fi

# Initialize config directory if empty
if [ -z "$(ls -A /root/antizapret/config)" ]; then
    echo "Initializing config directory with defaults..."
    cp -r /root/antizapret/config_default/* /root/antizapret/config/
fi

echo "Generating /root/antizapret/setup configuration..."
echo "SETUP_DATE=$(date --iso-8601=seconds)" > /root/antizapret/setup
echo "ANTIZAPRET_DNS=$ANTIZAPRET_DNS" >> /root/antizapret/setup
echo "BLOCK_ADS=$BLOCK_ADS" >> /root/antizapret/setup
echo "ALTERNATIVE_IP=$ALTERNATIVE_IP" >> /root/antizapret/setup
echo "ALTERNATIVE_FAKE_IP=$ALTERNATIVE_FAKE_IP" >> /root/antizapret/setup
echo "SSH_PROTECTION=n" >> /root/antizapret/setup
echo "ATTACK_PROTECTION=n" >> /root/antizapret/setup
echo "DISCORD_INCLUDE=$DISCORD_INCLUDE" >> /root/antizapret/setup
echo "CLOUDFLARE_INCLUDE=$CLOUDFLARE_INCLUDE" >> /root/antizapret/setup
echo "TELEGRAM_INCLUDE=$TELEGRAM_INCLUDE" >> /root/antizapret/setup
echo "WHATSAPP_INCLUDE=$WHATSAPP_INCLUDE" >> /root/antizapret/setup
echo "ROBLOX_INCLUDE=$ROBLOX_INCLUDE" >> /root/antizapret/setup
echo "AMAZON_INCLUDE=$AMAZON_INCLUDE" >> /root/antizapret/setup
echo "HETZNER_INCLUDE=$HETZNER_INCLUDE" >> /root/antizapret/setup
echo "DIGITALOCEAN_INCLUDE=$DIGITALOCEAN_INCLUDE" >> /root/antizapret/setup
echo "OVH_INCLUDE=$OVH_INCLUDE" >> /root/antizapret/setup
echo "GOOGLE_INCLUDE=$GOOGLE_INCLUDE" >> /root/antizapret/setup
echo "AKAMAI_INCLUDE=$AKAMAI_INCLUDE" >> /root/antizapret/setup
echo "CLEAR_HOSTS=$CLEAR_HOSTS" >> /root/antizapret/setup

if ! [[ "$ANTIZAPRET_DNS" =~ ^[1-6]$ ]]; then
    echo "Error: Invalid value for ANTIZAPRET_DNS: $ANTIZAPRET_DNS. Must be between 1 and 6."
    exit 1
fi

echo "Applying DNS configuration to kresd.conf..."
KRESD_CONF="/etc/knot-resolver/kresd.conf"
PROXY_PY="/root/antizapret/proxy.py"

# Restore clean versions from backup before applying sed
cp "${KRESD_CONF}.bak" "$KRESD_CONF"
cp "${PROXY_PY}.bak" "$PROXY_PY"

case "$ANTIZAPRET_DNS" in
    2) # SkyDNS
        sed -i "s/{'62\.76\.76\.62', '62\.76\.62\.76', '193\.58\.251\.251'}/'127.0.0.1'/" "$KRESD_CONF"
        sed -i "s/{'1\.1\.1\.1', '1\.0\.0\.1', '9\.9\.9\.10', '149\.112\.112\.10'}/'193.58.251.251'/" "$KRESD_CONF"
        ;;
    3) # Cloudflare+Quad9
        sed -i "s/'62\.76\.76\.62', '62\.76\.62\.76', '193\.58\.251\.251'/'1.1.1.1', '1.0.0.1', '9.9.9.10', '149.112.112.10'/" "$KRESD_CONF"
        ;;
    4) # Comss
        sed -i "s/'62\.76\.76\.62', '62\.76\.62\.76', '193\.58\.251\.251'/'83.220.169.155', '212.109.195.93', '195.133.25.16'/" "$KRESD_CONF"
        sed -i "s/'1\.1\.1\.1', '1\.0\.0\.1', '9\.9\.9\.10', '149\.112\.112\.10'/'83.220.169.155', '212.109.195.93', '195.133.25.16'/" "$KRESD_CONF"
        ;;
    5) # XBox
        sed -i "s/'62\.76\.76\.62', '62\.76\.62\.76', '193\.58\.251\.251'/'176.99.11.77', '80.78.247.254', '31.192.108.180'/" "$KRESD_CONF"
        sed -i "s/'1\.1\.1\.1', '1\.0\.0\.1', '9\.9\.9\.10', '149\.112\.112\.10'/'176.99.11.77', '80.78.247.254', '31.192.108.180'/" "$KRESD_CONF"
        ;;
    6) # Malw
        sed -i "s/'62\.76\.76\.62', '62\.76\.62\.76', '193\.58\.251\.251'/'84.21.189.133', '193.23.209.189'/" "$KRESD_CONF"
        sed -i "s/'1\.1\.1\.1', '1\.0\.0\.1', '9\.9\.9\.10', '149\.112\.112\.10'/'84.21.189.133', '193.23.209.189'/" "$KRESD_CONF"
        ;;
esac

echo "Applying IP range configuration to proxy.py..."
if [[ "$ALTERNATIVE_FAKE_IP" == "y" ]]; then
    sed -i 's/10\.30\./198\.18\./g' "$PROXY_PY"
fi

if [[ "$ALTERNATIVE_IP" == "y" ]]; then
    sed -i 's/10\./172\./g' "$PROXY_PY"
    sed -i 's/10\./172\./g' "$KRESD_CONF"
fi

chmod +x /root/antizapret/*.sh

echo "Running doall.sh to generate rules (this may take a while)..."
/root/antizapret/doall.sh noclear

cleanup() {
    echo "Stopping services and cleaning up..."
    /root/antizapret/down.sh
    killall cron 2>/dev/null || true
    PIDS_TO_KILL=""
    KRESD_PIDS=$(pgrep -f "kresd -n -c ${KRESD_CONF}")
    if [ -n "$KRESD_PIDS" ]; then
        PIDS_TO_KILL="$PIDS_TO_KILL $KRESD_PIDS"
    fi
    PROXY_PID=$(pgrep -f "python3 /root/antizapret/proxy.py")
    if [ -n "$PROXY_PID" ]; then
        PIDS_TO_KILL="$PIDS_TO_KILL $PROXY_PID"
    fi

    if [ -n "$PIDS_TO_KILL" ]; then
        echo "Killing background processes: $PIDS_TO_KILL"
        kill $PIDS_TO_KILL 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGTERM SIGINT

/usr/sbin/cron -f &
DEFAULT_ROUTE_INFO=$(ip -o -4 route show to default | head -n 1)

if [[ -z "$DEFAULT_ROUTE_INFO" ]]; then
    echo "Fatal: Could not determine default route."
    exit 1
fi

export DEFAULT_INTERFACE=$(echo "$DEFAULT_ROUTE_INFO" | awk '{print $5}')
export DEFAULT_IP=$(ip -o -4 addr show dev "$DEFAULT_INTERFACE" | awk '{print $4}' | cut -d/ -f1)

if [[ -z "$DEFAULT_INTERFACE" || -z "$DEFAULT_IP" ]]; then
    echo "Fatal: Failed to determine DEFAULT_INTERFACE or DEFAULT_IP."
    echo "DEFAULT_INTERFACE: $DEFAULT_INTERFACE"
    echo "DEFAULT_IP: $DEFAULT_IP"
    exit 1
fi

echo "Found Default Interface: $DEFAULT_INTERFACE"
echo "Found Default IP: $DEFAULT_IP"

mkdir -p /run/knot-resolver
chown knot-resolver:knot-resolver /run/knot-resolver

echo "Starting knot-resolver instance 1 (main)..."
SYSTEMD_INSTANCE=1 /usr/sbin/kresd -n -c "$KRESD_CONF" /run/knot-resolver > /proc/1/fd/1 2>/proc/1/fd/2 &
KRESD1_PID=$!

echo "Starting knot-resolver instance 2 (proxy)..."
SYSTEMD_INSTANCE=2 /usr/sbin/kresd -n -c "$KRESD_CONF" /run/knot-resolver > /proc/1/fd/1 2>/proc/1/fd/2 &
KRESD2_PID=$!

echo "Knot-resolver instances 1 and 2 started."
sleep 5

echo "Running up.sh for iptables and network configurations..."
set +e
/root/antizapret/up.sh
UP_SH_EXIT_CODE=$?
set -e
echo "up.sh exited with code: $UP_SH_EXIT_CODE"
if [ "$UP_SH_EXIT_CODE" -ne 0 ]; then
    echo "Error: Network setup (up.sh) failed with exit code $UP_SH_EXIT_CODE. Exiting."
    exit "$UP_SH_EXIT_CODE"
fi

echo "Starting proxy.py..."
/usr/bin/python3 -u "$PROXY_PY" --upstream 127.0.0.1:53 --address 127.0.0.2 > /proc/1/fd/1 2>/proc/1/fd/2 &
PROXY_PY_PID=$!
echo "proxy.py started."

echo "Entrypoint script finished, proxy.py is now foreground process."
wait $PROXY_PY_PID
