#!/usr/bin/env python3
import sys
import ipaddress

def aggregate_ips(ip_list, max_count=300):
    ipv4_list = []
    ipv6_list = []

    for line in ip_list:
        ip_str = line.strip()
        if not ip_str:
            continue
        try:
            ip = ipaddress.ip_address(ip_str.split('/')[0])
            if ip.version == 4:
                ipv4_list.append(ipaddress.IPv4Network(ip_str, strict=False))
            else:
                ipv6_list.append(ipaddress.IPv6Network(ip_str, strict=False))
        except ValueError:
            continue

    aggregated = []
    if ipv4_list:
        aggregated.extend(ipaddress.collapse_addresses(ipv4_list))
    if ipv6_list:
        aggregated.extend(ipaddress.collapse_addresses(ipv6_list))

    if len(aggregated) > max_count:
        aggregated = aggregated[:max_count]

    return aggregated

if __name__ == "__main__":
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    input_ips = sys.stdin.readlines()
    for net in aggregate_ips(input_ips, limit):
        print(net)

