#!/bin/bash
exec 2>/dev/null

cd /root/antizapret

source setup

[[ "$ALTERNATIVE_IP" == "y" ]] && IP="172" || IP="10"

# Remove dummy IP for DNS
ip addr del ${IP}.77.77.77/32 dev lo
ip -6 addr del fd00:10:29::1/128 dev lo
ip -6 addr del ::2/128 dev lo

exit 0
