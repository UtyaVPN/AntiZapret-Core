#!/bin/bash
set -e

cd /root/antizapret

./down.sh

source setup

if [[ -z "$DEFAULT_INTERFACE" ]]; then
	DEFAULT_INTERFACE=$(ip route get 1.2.3.4 | awk '{print $5; exit}')
fi
if [[ -z "$DEFAULT_INTERFACE" ]]; then
	echo 'Default network interface unavailable!'
	exit 1
fi

if [[ -z "$DEFAULT_IP" ]]; then
	DEFAULT_IP=$(ip route get 1.2.3.4 | awk '{print $7; exit}')
fi
if [[ -z "$DEFAULT_IP" ]]; then
	echo 'Default IPv4 address unavailable!'
	exit 1
fi

[[ "$ALTERNATIVE_IP" == "y" ]] && IP="172" || IP="10"

# Add dummy IP for DNS
ip addr add ${IP}.29.0.1/32 dev lo || true
ip -6 addr add fd00:10:29::1/128 dev lo || true
ip -6 addr add ::2/128 dev lo || true

# Clear knot-resolver cache
count=$(echo 'cache.clear()' | socat - /run/knot-resolver/control/1 | grep -oE '[0-9]+' || echo 0)
echo "DNS cache cleared (kresd@1): $count entries"
count=$(echo 'cache.clear()' | socat - /run/knot-resolver/control/2 | grep -oE '[0-9]+' || echo 0)
echo "DNS cache cleared (kresd@2): $count entries"

# filter
# Default policy
iptables -w -P INPUT ACCEPT
iptables -w -P FORWARD ACCEPT
iptables -w -P OUTPUT ACCEPT
ip6tables -w -P INPUT ACCEPT
ip6tables -w -P FORWARD ACCEPT
ip6tables -w -P OUTPUT ACCEPT

# Mapping fake IP to real IP
iptables -w -t nat -S ANTIZAPRET-MAPPING &>/dev/null || iptables -w -t nat -N ANTIZAPRET-MAPPING
ip6tables -w -t nat -S ANTIZAPRET-MAPPING &>/dev/null || ip6tables -w -t nat -N ANTIZAPRET-MAPPING
iptables -w -t nat -A PREROUTING -s ${IP}.29.0.0/16 -d ${IP}.30.0.0/15 -j ANTIZAPRET-MAPPING
ip6tables -w -t nat -A PREROUTING -s fd00:10:29::/112 -d fd00:10:30::/112 -j ANTIZAPRET-MAPPING

exit 0