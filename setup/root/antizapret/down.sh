#!/bin/bash
exec 2>/dev/null

cd /root/antizapret

source setup

[[ "$ALTERNATIVE_IP" == "y" ]] && IP="172" || IP="10"

# Remove dummy IP for DNS
ip addr del ${IP}.29.0.1/32 dev lo

# Mapping fake IP to real IP
iptables -w -t nat -D PREROUTING -s ${IP}.29.0.0/16 -d ${IP}.30.0.0/15 -j ANTIZAPRET-MAPPING


exit 0
