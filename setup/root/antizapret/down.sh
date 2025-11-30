#!/bin/bash
exec 2>/dev/null

cd /root/antizapret

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

[[ "$ALTERNATIVE_IP" == "y" ]] && IP="172" || IP="10"

# filter
# INPUT connection tracking
iptables -w -D INPUT -m conntrack --ctstate INVALID -j DROP || true
# FORWARD connection tracking
iptables -w -D FORWARD -m conntrack --ctstate INVALID -j DROP || true
# OUTPUT connection tracking
iptables -w -D OUTPUT -m conntrack --ctstate INVALID -j DROP || true
# Restrict forwarding
iptables -w -D FORWARD -s ${IP}.29.0.0/16 -m connmark --mark 0x1 -m set ! --match-set antizapret-forward dst -j DROP || true
# Attack and scan protection
iptables -w -D INPUT -i "$DEFAULT_INTERFACE" -p icmp --icmp-type echo-request -j DROP || true
iptables -w -D INPUT -i "$DEFAULT_INTERFACE" -m set --match-set antizapret-allow src -j ACCEPT || true
iptables -w -D INPUT -i "$DEFAULT_INTERFACE" -m conntrack --ctstate NEW -m set ! --match-set antizapret-watch src,dst -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name antizapret-scan --hashlimit-htable-expire 60000 -j SET --add-set antizapret-block src --exist || true
iptables -w -D INPUT -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100000/hour --hashlimit-burst 100000 --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name antizapret-ddos --hashlimit-htable-expire 10000 -j SET --add-set antizapret-block src --exist || true
iptables -w -D INPUT -m conntrack --ctstate NEW -m set --match-set antizapret-block src -j DROP || true
iptables -w -D INPUT -m conntrack --ctstate NEW -j SET --add-set antizapret-watch src,dst --exist || true
iptables -w -D OUTPUT -o "$DEFAULT_INTERFACE" -p tcp --tcp-flags RST RST -j DROP || true
iptables -w -D OUTPUT -o "$DEFAULT_INTERFACE" -p icmp --icmp-type destination-unreachable -j DROP || true
# SSH protection
iptables -w -D INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 3/hour --hashlimit-burst 3 --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name antizapret-ssh --hashlimit-htable-expire 60000 -j DROP || true

if [[ -n "$DEFAULT_INTERFACE_6" ]]; then
	iptables -w -D INPUT -m conntrack --ctstate INVALID -j DROP || true
	ip6tables -w -D FORWARD -m conntrack --ctstate INVALID -j DROP || true
	ip6tables -w -D OUTPUT -m conntrack --ctstate INVALID -j DROP || true
	ip6tables -w -D FORWARD -s fd00:10:29::/48 -m connmark --mark 0x1 -m set ! --match-set antizapret-forward6 dst -j DROP || true
	ip6tables -w -D INPUT -i "$DEFAULT_INTERFACE_6" -p icmpv6 --icmpv6-type echo-request -j DROP || true
	ip6tables -w -D INPUT -i "$DEFAULT_INTERFACE_6" -m set --match-set antizapret-allow6 src -j ACCEPT || true
	ip6tables -w -D INPUT -i "$DEFAULT_INTERFACE_6" -m conntrack --ctstate NEW -m set ! --match-set antizapret-watch6 src,dst -m hashlimit --hashlimit-above 10/hour --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name antizapret-scan6 --hashlimit-htable-expire 60000 -j SET --add-set antizapret-block6 src --exist || true
	ip6tables -w -D INPUT -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100000/hour --hashlimit-burst 100000 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name antizapret-ddos6 --hashlimit-htable-expire 10000 -j SET --add-set antizapret-block6 src --exist || true
	ip6tables -w -D INPUT -i "$DEFAULT_INTERFACE_6" -m conntrack --ctstate NEW -m set --match-set antizapret-block6 src -j DROP || true
	ip6tables -w -D INPUT -i "$DEFAULT_INTERFACE_6" -m conntrack --ctstate NEW -j SET --add-set antizapret-watch6 src,dst --exist || true
	ip6tables -w -D OUTPUT -o "$DEFAULT_INTERFACE_6" -p tcp --tcp-flags RST RST -j DROP || true
	ip6tables -w -D OUTPUT -o "$DEFAULT_INTERFACE_6" -p icmpv6 --icmpv6-type destination-unreachable -j DROP || true
	ip6tables -w -D INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 3/hour --hashlimit-burst 3 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name antizapret-ssh6 --hashlimit-htable-expire 60000 -j DROP || true
fi

# mangle
# Clamp TCP MSS
iptables -w -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true
if [[ -n "$DEFAULT_INTERFACE_6" ]]; then
	ip6tables -w -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true
fi

# nat
# AntiZapret DNS redirection to Knot Resolver
iptables -w -t nat -D PREROUTING -s ${IP}.29.0.0/22 ! -d ${IP}.29.0.1/32 -p udp --dport 53 -j DNAT --to-destination ${IP}.29.0.1 || true
iptables -w -t nat -D PREROUTING -s ${IP}.29.4.0/22 ! -d ${IP}.29.4.1/32 -p udp --dport 53 -j DNAT --to-destination ${IP}.29.4.1 || true
iptables -w -t nat -D PREROUTING -s ${IP}.29.8.0/24 ! -d ${IP}.29.8.1/32 -p udp --dport 53 -j DNAT --to-destination ${IP}.29.8.1 || true
iptables -w -t nat -D PREROUTING -s ${IP}.29.0.0/22 ! -d ${IP}.29.0.1/32 -p tcp --dport 53 -j DNAT --to-destination ${IP}.29.0.1 || true
iptables -w -t nat -D PREROUTING -s ${IP}.29.4.0/22 ! -d ${IP}.29.4.1/32 -p tcp --dport 53 -j DNAT --to-destination ${IP}.29.4.1 || true
iptables -w -t nat -D PREROUTING -s ${IP}.29.8.0/24 ! -d ${IP}.29.8.1/32 -p tcp --dport 53 -j DNAT --to-destination ${IP}.29.8.1 || true
# Restrict forwarding
iptables -w -t nat -D PREROUTING -s ${IP}.29.0.0/16 ! -d ${IP}.30.0.0/15 -j CONNMARK --set-mark 0x1 || true
# Mapping fake IP to real IP
iptables -w -t nat -D PREROUTING -s ${IP}.29.0.0/16 -d ${IP}.30.0.0/15 -j ANTIZAPRET-MAPPING || true
iptables -w -t nat -F ANTIZAPRET-MAPPING 2>/dev/null || true
iptables -w -t nat -X ANTIZAPRET-MAPPING 2>/dev/null || true

if [[ -n "$DEFAULT_INTERFACE_6" ]]; then
	ip6tables -w -t nat -D PREROUTING -s fd00:10:29::/64 ! -d fd00:10:29::1/128 -p udp --dport 53 -j DNAT --to-destination fd00:10:29::1 || true
	ip6tables -w -t nat -D PREROUTING -s fd00:10:29:4::/64 ! -d fd00:10:29:4::1/128 -p udp --dport 53 -j DNAT --to-destination fd00:10:29:4::1 || true
	ip6tables -w -t nat -D PREROUTING -s fd00:10:29:8::/64 ! -d fd00:10:29:8::1/128 -p udp --dport 53 -j DNAT --to-destination fd00:10:29:8::1 || true
	ip6tables -w -t nat -D PREROUTING -s fd00:10:29::/64 ! -d fd00:10:29::1/128 -p tcp --dport 53 -j DNAT --to-destination fd00:10:29::1 || true
	ip6tables -w -t nat -D PREROUTING -s fd00:10:29:4::/64 ! -d fd00:10:29:4::1/128 -p tcp --dport 53 -j DNAT --to-destination fd00:10:29:4::1 || true
	ip6tables -w -t nat -D PREROUTING -s fd00:10:29:8::/64 ! -d fd00:10:29:8::1/128 -p tcp --dport 53 -j DNAT --to-destination fd00:10:29:8::1 || true
	ip6tables -w -t nat -D PREROUTING -s fd00:10:29::/48 -d fd00:10:30::/48 -j ANTIZAPRET-MAPPING || true
	ip6tables -w -t nat -F ANTIZAPRET-MAPPING 2>/dev/null || true
	ip6tables -w -t nat -X ANTIZAPRET-MAPPING 2>/dev/null || true
fi

# ip address teardown
ip link del dummy0 type dummy 2>/dev/null || true

# ipset teardown
ipset flush antizapret-forward || true
ipset destroy antizapret-forward || true
ipset flush antizapret-allow || true
ipset destroy antizapret-allow || true
ipset flush antizapret-block || true
ipset destroy antizapret-block || true
ipset flush antizapret-watch || true
ipset destroy antizapret-watch || true

if [[ -n "$DEFAULT_INTERFACE_6" ]]; then
	ipset flush antizapret-forward6 || true
	ipset destroy antizapret-forward6 || true
	ipset flush antizapret-allow6 || true
	ipset destroy antizapret-allow6 || true
	ipset flush antizapret-block6 || true
	ipset destroy antizapret-block6 || true
	ipset flush antizapret-watch6 || true
	ipset destroy antizapret-watch6 || true
fi

./custom-down.sh
exit 0

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

./custom-down.sh
exit 0
