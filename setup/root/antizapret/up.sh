#!/bin/bash
set -e

cd /root/antizapret

./down.sh

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
[[ "$ALTERNATIVE_FAKE_IP" == "y" ]] && FAKE_IP="${FAKE_IP:-198.18}" || FAKE_IP="$IP.30"

ip addr add 10.77.77.77/32 dev lo

# filter
# Default policy
iptables -w -P INPUT ACCEPT
iptables -w -P FORWARD ACCEPT
iptables -w -P OUTPUT ACCEPT
ip6tables -w -P INPUT ACCEPT
ip6tables -w -P FORWARD ACCEPT
ip6tables -w -P OUTPUT ACCEPT
# INPUT connection tracking
iptables -w -I INPUT 1 -m conntrack --ctstate INVALID -j DROP
ip6tables -w -I INPUT 1 -m conntrack --ctstate INVALID -j DROP
# FORWARD connection tracking
iptables -w -I FORWARD 1 -m conntrack --ctstate INVALID -j DROP
ip6tables -w -I FORWARD 1 -m conntrack --ctstate INVALID -j DROP
# OUTPUT connection tracking
iptables -w -I OUTPUT 1 -m conntrack --ctstate INVALID -j DROP
ip6tables -w -I OUTPUT 1 -m conntrack --ctstate INVALID -j DROP
# Attack and scan protection
if [[ "$ATTACK_PROTECTION" == "y" ]]; then
	{
		echo "create antizapret-allow hash:net -exist"
		echo "flush antizapret-allow"
		while read -r line; do
			echo "add antizapret-allow $line"
		done < result/allow-ips.txt
	} | ipset restore
	ipset create antizapret-block hash:ip timeout 600 -exist
	ipset create antizapret-watch hash:ip,port timeout 600 -exist
	iptables -w -I INPUT 2 -i "$DEFAULT_INTERFACE" -p icmp --icmp-type echo-request -j DROP
	iptables -w -I INPUT 3 -i "$DEFAULT_INTERFACE" -m set --match-set antizapret-allow src -j ACCEPT
	iptables -w -I INPUT 4 -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -m set ! --match-set antizapret-watch src,dst -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name antizapret-scan --hashlimit-htable-expire 600000 -j SET --add-set antizapret-block src --exist
	iptables -w -I INPUT 5 -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100000/hour --hashlimit-burst 100000 --hashlimit-mode srcip --hashlimit-name antizapret-ddos --hashlimit-htable-expire 600000 -j SET --add-set antizapret-block src --exist
	iptables -w -I INPUT 6 -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -m set --match-set antizapret-block src -j DROP
	iptables -w -I INPUT 7 -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -j SET --add-set antizapret-watch src,dst --exist
	iptables -w -I OUTPUT 2 -o "$DEFAULT_INTERFACE" -p tcp --tcp-flags RST RST -j DROP
	iptables -w -I OUTPUT 3 -o "$DEFAULT_INTERFACE" -p icmp --icmp-type port-unreachable -j DROP
	{
		echo "create antizapret-allow-v6 hash:net family inet6 -exist"
		echo "flush antizapret-allow-v6"
		while read -r line; do
			echo "add antizapret-allow-v6 $line"
		done < result/allow-ips-v6.txt
	} | ipset restore
	ipset create antizapret-block6 hash:ip timeout 600 family inet6 -exist
	ipset create antizapret-watch6 hash:ip,port timeout 600 family inet6 -exist
	ip6tables -w -I INPUT 2 -i "$DEFAULT_INTERFACE" -p icmpv6 --icmpv6-type echo-request -j DROP
	ip6tables -w -I INPUT 3 -i "$DEFAULT_INTERFACE" -m set --match-set antizapret-allow-v6 src -j ACCEPT
	ip6tables -w -I INPUT 4 -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -m set ! --match-set antizapret-watch6 src,dst -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name antizapret-scan6 --hashlimit-htable-expire 600000 -j SET --add-set antizapret-block6 src --exist
	ip6tables -w -I INPUT 5 -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100000/hour --hashlimit-burst 100000 --hashlimit-mode srcip --hashlimit-name antizapret-ddos6 --hashlimit-htable-expire 600000 -j SET --add-set antizapret-block6 src --exist
	ip6tables -w -I INPUT 6 -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -m set --match-set antizapret-block6 src -j DROP
	ip6tables -w -I INPUT 7 -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -j SET --add-set antizapret-watch6 src,dst --exist
	ip6tables -w -I OUTPUT 2 -o "$DEFAULT_INTERFACE" -p tcp --tcp-flags RST RST -j DROP
	ip6tables -w -I OUTPUT 3 -o "$DEFAULT_INTERFACE" -p icmpv6 --icmpv6-type port-unreachable -j DROP
fi
# SSH protection
if [[ "$SSH_PROTECTION" == "y" ]]; then
	iptables -w -I INPUT 2 -p tcp --dport ssh -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 3/hour --hashlimit-burst 3 --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name antizapret-ssh --hashlimit-htable-expire 60000 -j DROP
	ip6tables -w -I INPUT 2 -p tcp --dport ssh -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 3/hour --hashlimit-burst 3 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name antizapret-ssh6 --hashlimit-htable-expire 60000 -j DROP
fi

# mangle
# Clamp TCP MSS
iptables -w -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ip6tables -w -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# raw
# NOTRACK loopback
iptables -w -t raw -A PREROUTING -i lo -j NOTRACK
iptables -w -t raw -A OUTPUT -o lo -j NOTRACK
ip6tables -w -t raw -A PREROUTING -i lo -j NOTRACK
ip6tables -w -t raw -A OUTPUT -o lo -j NOTRACK

# Mapping fake IP to real IP
iptables -w -t nat -S ANTIZAPRET-MAPPING &>/dev/null || iptables -w -t nat -N ANTIZAPRET-MAPPING
ip6tables -w -t nat -S ANTIZAPRET-MAPPING &>/dev/null || ip6tables -w -t nat -N ANTIZAPRET-MAPPING

exit 0
