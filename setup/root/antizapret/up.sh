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

DEFAULT_INTERFACE_6=$(ip -6 route get 2a00:1450:4001:824::200e | awk '{print $7; exit}' 2>/dev/null) || true
DEFAULT_IP_6=$(ip -6 route get 2a00:1450:4001:824::200e | awk '{print $5; exit}' 2>/dev/null) || true

# Assign internal resolver IPs to dummy interface
ip link show dummy0 &>/dev/null || ip link add dummy0 type dummy
ip link set dummy0 up
ip addr show dummy0 | grep -q 10.29.0.1/32 || ip addr add 10.29.0.1/32 dev dummy0
if [[ -n "$DEFAULT_INTERFACE_6" ]]; then
	ip addr show dummy0 | grep -q fd00:10:29::1/128 || ip -6 addr add fd00:10:29::1/128 dev dummy0
fi

[[ "$ALTERNATIVE_IP" == "y" ]] && IP="172" || IP="10"

# Clear knot-resolver cache
# count=$(echo 'cache.clear()' | socat - /run/knot-resolver/control/1 | grep -oE '[0-9]+' || echo 0)
# echo "DNS cache cleared: $count entries"

# filter
# Default policy
# These set default policies, running them multiple times is fine.
iptables -w -P INPUT ACCEPT
iptables -w -P FORWARD ACCEPT
iptables -w -P OUTPUT ACCEPT

# INPUT connection tracking
iptables -w -C INPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null || iptables -w -A INPUT -m conntrack --ctstate INVALID -j DROP
# FORWARD connection tracking
iptables -w -C FORWARD -m conntrack --ctstate INVALID -j DROP 2>/dev/null || iptables -w -A FORWARD -m conntrack --ctstate INVALID -j DROP
# OUTPUT connection tracking
iptables -w -C OUTPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null || iptables -w -A OUTPUT -m conntrack --ctstate INVALID -j DROP

if [[ -n "$DEFAULT_INTERFACE_6" ]]; then
	ip6tables -w -P INPUT ACCEPT
	ip6tables -w -P FORWARD ACCEPT
	ip6tables -w -P OUTPUT ACCEPT
	ip6tables -w -C INPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null || ip6tables -w -A INPUT -m conntrack --ctstate INVALID -j DROP
	ip6tables -w -C FORWARD -m conntrack --ctstate INVALID -j DROP 2>/dev/null || ip6tables -w -A FORWARD -m conntrack --ctstate INVALID -j DROP
	ip6tables -w -C OUTPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null || ip6tables -w -A OUTPUT -m conntrack --ctstate INVALID -j DROP
fi

# Restrict forwarding
if [[ "$RESTRICT_FORWARD" == "y" ]]; then
	touch result/forward-ips.txt result/forward-ips6.txt
	{
		echo "create antizapret-forward hash:net family inet -exist"
		echo "flush antizapret-forward"
		while read -r line; do
			echo "add antizapret-forward $line"
		done < result/forward-ips.txt
	} | ipset restore
	{
		echo "create antizapret-forward6 hash:net family inet6 -exist"
		echo "flush antizapret-forward6"
		while read -r line; do
			echo "add antizapret-forward6 $line"
		done < result/forward-ips6.txt
	} | ipset restore
	iptables -w -C FORWARD -s ${IP}.29.0.0/16 -m connmark --mark 0x1 -m set ! --match-set antizapret-forward dst -j DROP 2>/dev/null || iptables -w -A FORWARD -s ${IP}.29.0.0/16 -m connmark --mark 0x1 -m set ! --match-set antizapret-forward dst -j DROP
	if [[ -n "$DEFAULT_INTERFACE_6" ]]; then
		ip6tables -w -C FORWARD -s fd00:10:29::/48 -m connmark --mark 0x1 -m set ! --match-set antizapret-forward6 dst -j DROP 2>/dev/null || ip6tables -w -A FORWARD -s fd00:10:29::/48 -m connmark --mark 0x1 -m set ! --match-set antizapret-forward6 dst -j DROP
	fi
fi
# Attack and scan protection
if [[ "$ATTACK_PROTECTION" == "y" ]]; then
	touch result/allow-ips.txt result/allow-ips6.txt
	{
		echo "create antizapret-allow hash:net family inet -exist"
		echo "flush antizapret-allow"
		while read -r line; do
			echo "add antizapret-allow $line"
		done < result/allow-ips.txt
	} | ipset restore
	ipset create antizapret-block hash:ip timeout 600 -exist
	ipset create antizapret-watch hash:ip,port timeout 60 -exist
	iptables -w -C INPUT -i "$DEFAULT_INTERFACE" -p icmp --icmp-type echo-request -j DROP 2>/dev/null || iptables -w -A INPUT -i "$DEFAULT_INTERFACE" -p icmp --icmp-type echo-request -j DROP
	iptables -w -C INPUT -i "$DEFAULT_INTERFACE" -m set --match-set antizapret-allow src -j ACCEPT 2>/dev/null || iptables -w -A INPUT -i "$DEFAULT_INTERFACE" -m set --match-set antizapret-allow src -j ACCEPT
	iptables -w -C INPUT -m conntrack --ctstate NEW -m set ! --match-set antizapret-watch src,dst -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name antizapret-scan --hashlimit-htable-expire 60000 -j SET --add-set antizapret-block src --exist 2>/dev/null || iptables -w -A INPUT -m conntrack --ctstate NEW -m set ! --match-set antizapret-watch src,dst -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name antizapret-scan --hashlimit-htable-expire 60000 -j SET --add-set antizapret-block src --exist
	iptables -w -C INPUT -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100000/hour --hashlimit-burst 100000 --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name antizapret-ddos --hashlimit-htable-expire 10000 -j SET --add-set antizapret-block src --exist 2>/dev/null || iptables -w -A INPUT -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100000/hour --hashlimit-burst 100000 --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name antizapret-ddos --hashlimit-htable-expire 10000 -j SET --add-set antizapret-block src --exist
	iptables -w -C INPUT -m conntrack --ctstate NEW -m set --match-set antizapret-block src -j DROP 2>/dev/null || iptables -w -A INPUT -m conntrack --ctstate NEW -m set --match-set antizapret-block src -j DROP
	iptables -w -C INPUT -m conntrack --ctstate NEW -j SET --add-set antizapret-watch src,dst --exist 2>/dev/null || iptables -w -A INPUT -m conntrack --ctstate NEW -j SET --add-set antizapret-watch src,dst --exist
	iptables -w -C OUTPUT -o "$DEFAULT_INTERFACE" -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || iptables -w -A OUTPUT -o "$DEFAULT_INTERFACE" -p tcp --tcp-flags RST RST -j DROP
	iptables -w -C OUTPUT -o "$DEFAULT_INTERFACE" -p icmp --icmp-type destination-unreachable -j DROP 2>/dev/null || iptables -w -A OUTPUT -o "$DEFAULT_INTERFACE" -p icmp --icmp-type destination-unreachable -j DROP
	if [[ -n "$DEFAULT_INTERFACE_6" ]]; then
		{
			echo "create antizapret-allow6 hash:net family inet6 -exist"
			echo "flush antizapret-allow6"
			while read -r line; do
				echo "add antizapret-allow6 $line"
			done < result/allow-ips6.txt
		} | ipset restore
		ipset create antizapret-block6 hash:ip timeout 600 family inet6 -exist
		ipset create antizapret-watch6 hash:ip,port timeout 60 family inet6 -exist
		ip6tables -w -C INPUT -i "$DEFAULT_INTERFACE_6" -p icmpv6 --icmpv6-type echo-request -j DROP 2>/dev/null || ip6tables -w -A INPUT -i "$DEFAULT_INTERFACE_6" -p icmpv6 --icmpv6-type echo-request -j DROP
		ip6tables -w -C INPUT -i "$DEFAULT_INTERFACE_6" -m set --match-set antizapret-allow6 src -j ACCEPT 2>/dev/null || ip6tables -w -A INPUT -i "$DEFAULT_INTERFACE_6" -m set --match-set antizapret-allow6 src -j ACCEPT
		ip6tables -w -C INPUT -m conntrack --ctstate NEW -m set ! --match-set antizapret-watch6 src,dst -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name antizapret-scan6 --hashlimit-htable-expire 60000 -j SET --add-set antizapret-block6 src --exist 2>/dev/null || ip6tables -w -A INPUT -m conntrack --ctstate NEW -m set ! --match-set antizapret-watch6 src,dst -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name antizapret-scan6 --hashlimit-htable-expire 60000 -j SET --add-set antizapret-block6 src --exist
		ip6tables -w -C INPUT -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100000/hour --hashlimit-burst 100000 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name antizapret-ddos6 --hashlimit-htable-expire 10000 -j SET --add-set antizapret-block6 src --exist 2>/dev/null || ip6tables -w -A INPUT -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100000/hour --hashlimit-burst 100000 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name antizapret-ddos6 -j SET --add-set antizapret-block6 src --exist
		ip6tables -w -C INPUT -m conntrack --ctstate NEW -m set --match-set antizapret-block6 src -j DROP 2>/dev/null || ip6tables -w -A INPUT -m conntrack --ctstate NEW -m set --match-set antizapret-block6 src -j DROP
		ip6tables -w -C INPUT -m conntrack --ctstate NEW -j SET --add-set antizapret-watch6 src,dst --exist 2>/dev/null || ip6tables -w -A INPUT -m conntrack --ctstate NEW -j SET --add-set antizapret-watch6 src,dst --exist
		ip6tables -w -C OUTPUT -o "$DEFAULT_INTERFACE_6" -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || ip6tables -w -A OUTPUT -o "$DEFAULT_INTERFACE_6" -p tcp --tcp-flags RST RST -j DROP
		ip6tables -w -C OUTPUT -o "$DEFAULT_INTERFACE_6" -p icmpv6 --icmpv6-type destination-unreachable -j DROP 2>/dev/null || ip6tables -w -A OUTPUT -o "$DEFAULT_INTERFACE_6" -p icmpv6 --icmpv6-type destination-unreachable -j DROP
	fi
fi
# SSH protection
if [[ "$SSH_PROTECTION" == "y" ]]; then
	iptables -w -C INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 3/hour --hashlimit-burst 3 --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name antizapret-ssh --hashlimit-htable-expire 60000 -j DROP 2>/dev/null || iptables -w -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 3/hour --hashlimit-burst 3 --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name antizapret-ssh --hashlimit-htable-expire 60000 -j DROP
	if [[ -n "$DEFAULT_INTERFACE_6" ]]; then
		ip6tables -w -C INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 3/hour --hashlimit-burst 3 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name antizapret-ssh6 --hashlimit-htable-expire 60000 -j DROP 2>/dev/null || ip6tables -w -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 3/hour --hashlimit-burst 3 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name antizapret-ssh6 --hashlimit-htable-expire 60000 -j DROP
	fi
fi

# mangle
# Clamp TCP MSS
nft add rule ip filter FORWARD tcp flags syn,rst & syn == syn tcp option maxseg size set rt mtu 2>/dev/null || true
if [[ -n "$DEFAULT_INTERFACE_6" ]]; then
	nft add rule ip6 filter FORWARD tcp flags syn,rst & syn == syn tcp option maxseg size set rt mtu 2>/dev/null || true
fi

# AntiZapret DNS redirection to Knot Resolver
nft add rule ip nat prerouting ip saddr ${IP}.29.0.0/22 ip daddr != ${IP}.29.0.1/32 udp dport 53 dnat to ${IP}.29.0.1 2>/dev/null || true
nft add rule ip nat prerouting ip saddr ${IP}.29.4.0/22 ip daddr != ${IP}.29.4.1/32 udp dport 53 dnat to ${IP}.29.4.1 2>/dev/null || true
nft add rule ip nat prerouting ip saddr ${IP}.29.8.0/24 ip daddr != ${IP}.29.8.1/32 udp dport 53 dnat to ${IP}.29.8.1 2>/dev/null || true
nft add rule ip nat prerouting ip saddr ${IP}.29.0.0/22 ip daddr != ${IP}.29.0.1/32 tcp dport 53 dnat to ${IP}.29.0.1 2>/dev/null || true
nft add rule ip nat prerouting ip saddr ${IP}.29.4.0/22 ip daddr != ${IP}.29.4.1/32 tcp dport 53 dnat to ${IP}.29.4.1 2>/dev/null || true
nft add rule ip nat prerouting ip saddr ${IP}.29.8.0/24 ip daddr != ${IP}.29.8.1/32 tcp dport 53 dnat to ${IP}.29.8.1 2>/dev/null || true
if [[ -n "$DEFAULT_INTERFACE_6" ]]; then
	nft add rule ip6 nat prerouting ip6 saddr fd00:10:29::/64 ip6 daddr != fd00:10:29::1/128 udp dport 53 dnat to fd00:10:29::1 2>/dev/null || true
	nft add rule ip6 nat prerouting ip6 saddr fd00:10:29:4::/64 ip6 daddr != fd00:10:29:4::1/128 udp dport 53 dnat to fd00:10:29:4::1 2>/dev/null || true
	nft add rule ip6 nat prerouting ip6 saddr fd00:10:29:8::/64 ip6 daddr != fd00:10:29:8::1/128 udp dport 53 dnat to fd00:10:29:8::1 2>/dev/null || true
	nft add rule ip6 nat prerouting ip6 saddr fd00:10:29::/64 ip6 daddr != fd00:10:29::1/128 tcp dport 53 dnat to fd00:10:29::1 2>/dev/null || true
	nft add rule ip6 nat prerouting ip6 saddr fd00:10:29:4::/64 ip6 daddr != fd00:10:29:4::1/128 tcp dport 53 dnat to fd00:10:29:4::1 2>/dev/null || true
	nft add rule ip6 nat prerouting ip6 saddr fd00:10:29:8::/64 ip6 daddr != fd00:10:29:8::1/128 tcp dport 53 dnat to fd00:10:29:8::1 2>/dev/null || true
fi
# Restrict forwarding
if [[ "$RESTRICT_FORWARD" == "y" ]]; then
	iptables -w -C nat -A PREROUTING -s ${IP}.29.0.0/16 ! -d ${IP}.30.0.0/15 -j CONNMARK --set-mark 0x1 2>/dev/null || iptables -w -t nat -A PREROUTING -s ${IP}.29.0.0/16 ! -d ${IP}.30.0.0/15 -j CONNMARK --set-mark 0x1
fi
# Mapping fake IP to real IP
iptables -w -t nat -S ANTIZAPRET-MAPPING &>/dev/null || iptables -w -t nat -N ANTIZAPRET-MAPPING
iptables -w -t nat -C PREROUTING -s ${IP}.29.0.0/16 -d ${IP}.30.0.0/15 -j ANTIZAPRET-MAPPING 2>/dev/null || iptables -w -t nat -A PREROUTING -s ${IP}.29.0.0/16 -d ${IP}.30.0.0/15 -j ANTIZAPRET-MAPPING
if [[ -n "$DEFAULT_INTERFACE_6" ]]; then
	ip6tables -w -t nat -S ANTIZAPRET-MAPPING &>/dev/null || ip6tables -w -t nat -N ANTIZAPRET-MAPPING
	ip6tables -w -t nat -C PREROUTING -s fd00:10:29::/48 -d fd00:10:30::/48 -j ANTIZAPRET-MAPPING 2>/dev/null || ip6tables -w -t nat -A PREROUTING -s fd00:10:29::/48 -d fd00:10:30::/48 -j ANTIZAPRET-MAPPING
fi

./custom-up.sh
exit 0
