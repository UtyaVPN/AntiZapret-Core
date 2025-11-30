#!/bin/bash
exec 2>/dev/null

cd /root/antizapret

source setup

[[ "$ALTERNATIVE_IP" == "y" ]] && IP="172" || IP="10"

# Remove dummy IP for DNS
ip addr del 1.9.8.4/32 dev lo
ip -6 addr del fd00:10:29::1/128 dev lo
ip -6 addr del ::2/128 dev lo

# Mapping fake IP to real IP
iptables -w -t nat -D PREROUTING -d 19.84.0.0/15 -j ANTIZAPRET-MAPPING
ip6tables -w -t nat -D PREROUTING -d fd00:19:84::/112 -j ANTIZAPRET-MAPPING

exit 0
