#!/bin/bash
exec 2>/dev/null

cd /root/antizapret

source setup

if [[ -z "$DEFAULT_INTERFACE" ]]; then
	DEFAULT_INTERFACE="$(ip route get 1.2.3.4 2>/dev/null | awk '{print $5; exit}')"
fi
if [[ -z "$DEFAULT_INTERFACE" ]]; then
	echo 'Default network interface not found!'
	exit 1
fi

DEFAULT_IP="$(ip route get 1.2.3.4 2>/dev/null | awk '{print $7; exit}')"
if [[ -z "$DEFAULT_IP" ]]; then
	echo 'Default IPv4 address not found!'
	exit 2
fi

[[ "$ALTERNATIVE_IP" == "y" ]] && IP="${IP:-172}" || IP="10"

ip addr del $IP.77.77.77/32 dev lo

# filter
# INPUT connection tracking
iptables -w -D INPUT -m conntrack --ctstate INVALID -j DROP
ip6tables -w -D INPUT -m conntrack --ctstate INVALID -j DROP
# FORWARD connection tracking
iptables -w -D FORWARD -m conntrack --ctstate INVALID -j DROP
ip6tables -w -D FORWARD -m conntrack --ctstate INVALID -j DROP
# OUTPUT connection tracking
iptables -w -D OUTPUT -m conntrack --ctstate INVALID -j DROP
ip6tables -w -D OUTPUT -m conntrack --ctstate INVALID -j DROP
# Attack and scan protection
iptables -w -D INPUT -i "$DEFAULT_INTERFACE" -p icmp --icmp-type echo-request -j DROP
iptables -w -D INPUT -i "$DEFAULT_INTERFACE" -m set --match-set antizapret-allow src -j ACCEPT
iptables -w -D INPUT -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -m set ! --match-set antizapret-watch src,dst -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name antizapret-scan --hashlimit-htable-expire 600000 -j SET --add-set antizapret-block src --exist
iptables -w -D INPUT -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100000/hour --hashlimit-burst 100000 --hashlimit-mode srcip --hashlimit-name antizapret-ddos --hashlimit-htable-expire 600000 -j SET --add-set antizapret-block src --exist
iptables -w -D INPUT -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -m set --match-set antizapret-block src -j DROP
iptables -w -D INPUT -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -j SET --add-set antizapret-watch src,dst --exist
iptables -w -D OUTPUT -o "$DEFAULT_INTERFACE" -p tcp --tcp-flags RST RST -j DROP
iptables -w -D OUTPUT -o "$DEFAULT_INTERFACE" -p icmp --icmp-type port-unreachable -j DROP
ip6tables -w -D INPUT -i "$DEFAULT_INTERFACE" -p icmpv6 --icmpv6-type echo-request -j DROP
ip6tables -w -D INPUT -i "$DEFAULT_INTERFACE" -m set --match-set antizapret-allow-v6 src -j ACCEPT
ip6tables -w -D INPUT -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -m set ! --match-set antizapret-watch6 src,dst -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name antizapret-scan6 --hashlimit-htable-expire 600000 -j SET --add-set antizapret-block6 src --exist
ip6tables -w -D INPUT -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100000/hour --hashlimit-burst 100000 --hashlimit-mode srcip --hashlimit-name antizapret-ddos6 --hashlimit-htable-expire 600000 -j SET --add-set antizapret-block6 src --exist
ip6tables -w -D INPUT -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -m set --match-set antizapret-block6 src -j DROP
ip6tables -w -D INPUT -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -j SET --add-set antizapret-watch6 src,dst --exist
ip6tables -w -D OUTPUT -o "$DEFAULT_INTERFACE" -p tcp --tcp-flags RST RST -j DROP
ip6tables -w -D OUTPUT -o "$DEFAULT_INTERFACE" -p icmpv6 --icmpv6-type port-unreachable -j DROP
# SSH protection
iptables -w -D INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 3/hour --hashlimit-burst 3 --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name antizapret-ssh --hashlimit-htable-expire 60000 -j DROP
ip6tables -w -D INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 3/hour --hashlimit-burst 3 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name antizapret-ssh6 --hashlimit-htable-expire 60000 -j DROP

# mangle
# Clamp TCP MSS
iptables -w -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ip6tables -w -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# raw
# NOTRACK loopback
iptables -w -t raw -D PREROUTING -i lo -j NOTRACK
iptables -w -t raw -D OUTPUT -o lo -j NOTRACK
ip6tables -w -t raw -D PREROUTING -i lo -j NOTRACK
ip6tables -w -t raw -D OUTPUT -o lo -j NOTRACK

# Flush and delete ANTIZAPRET-MAPPING chains
iptables -w -t nat -F ANTIZAPRET-MAPPING
iptables -w -t nat -X ANTIZAPRET-MAPPING
ip6tables -w -t nat -F ANTIZAPRET-MAPPING
ip6tables -w -t nat -X ANTIZAPRET-MAPPING

exit 0
