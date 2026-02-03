#!/usr/bin/env python3
import sys
import socket
import binascii

def ip_to_int(ip):
    try:
        if ":" in ip:
            return int(binascii.hexlify(socket.inet_pton(socket.AF_INET6, ip.split('/')[0])), 16), 6
        else:
            return int(binascii.hexlify(socket.inet_pton(socket.AF_INET, ip.split('/')[0])), 16), 4
    except:
        return None, None

def int_to_ip(n, version):
    if version == 6:
        return socket.inet_ntop(socket.AF_INET6, binascii.unhexlify(format(n, '032x')))
    return socket.inet_ntop(socket.AF_INET, binascii.unhexlify(format(n, '08x')))

def aggregate_fast(ip_list, max_count=300):
    if not ip_list: return []
    
    parsed = []
    v = 4
    for line in ip_list:
        n, version = ip_to_int(line.strip())
        if n is not None:
            parsed.append(n)
            v = version
    
    if not parsed: return []
    parsed = sorted(list(set(parsed)))
    max_bits = 128 if v == 6 else 32
    
    if len(parsed) <= max_count:
        return [f"{int_to_ip(n, v)}/{max_bits}" for n in parsed]

    low, high = 0, max_bits
    best_p = 0
    while low <= high:
        mid = (low + high) // 2
        shifted = set(n >> (max_bits - mid) for n in parsed)
        if len(shifted) <= max_count:
            best_p = mid
            low = mid + 1
        else:
            high = mid - 1
            
    results = sorted(list(set(n >> (max_bits - best_p) for n in parsed)))
    return [f"{int_to_ip(r << (max_bits - best_p), v)}/{best_p}" for r in results]

if __name__ == "__main__":
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    for net in aggregate_fast(sys.stdin.readlines(), limit):
        print(net)