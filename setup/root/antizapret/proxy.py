#!/usr/bin/env -S python3 -u
# -*- coding: utf-8 -*-

import socket, struct, subprocess, sys, time, argparse, threading, os
from collections import deque
from ipaddress import IPv4Network, IPv6Network
from dnslib import DNSRecord, RCODE, QTYPE, A, AAAA
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger

class ProxyResolver(BaseResolver):
    def __init__(self, address, port, timeout, ip_range_v4, ip_range_v6, cleanup_interval, cleanup_expiry, min_ttl, max_ttl):
        print(f"ProxyResolver init: ip_range_v4={ip_range_v4}, ip_range_v6={ip_range_v6}")
        try:
            self.ip_pool_v4 = deque([str(x) for x in IPv4Network(ip_range_v4).hosts()])
            self.ip_map_v4 = {}
            print(f"IPv4 pool size: {len(self.ip_pool_v4)}")
        except Exception as e:
            print(f"Error initializing IPv4 pool with {ip_range_v4}: {e}")
            sys.exit(1)
        try:
            self.ip_pool_v6 = deque([str(x) for x in IPv6Network(ip_range_v6).hosts()])
            self.ip_map_v6 = {}
        except Exception as e:
            print(f"Error initializing IPv6 pool with {ip_range_v6}: {e}")
            sys.exit(1)

        current_time = time.time()
        rule_v4 = "iptables -w -t nat -S ANTIZAPRET-MAPPING | awk '{if (NR<2) {next}; split($4, a, \"/\"); print a[1], $8}'"
        try:
            mappings_v4 = subprocess.run(rule_v4, shell=True, check=True, capture_output=True, text=True).stdout.splitlines()
        except subprocess.CalledProcessError as e:
            print(f"Error loading IPv4 mappings: {e.stderr.strip()}")
            sys.exit(1)
        for mapping in mappings_v4:
            fake_ip, real_ip = mapping.split(" ")
            if not self.mapping_ip(real_ip, fake_ip, current_time, "v4"):
                subprocess.run("iptables -w -t nat -F ANTIZAPRET-MAPPING", shell=True, check=True)
                sys.exit(1)
        print(f"Loaded: {len(mappings_v4)} fake IPv4s")

        rule_v6 = "ip6tables -w -t nat -S ANTIZAPRET-MAPPING | awk '{if (NR<2) {next}; split($4, a, \"/\"); print a[1], $8}'"
        try:
            mappings_v6 = subprocess.run(rule_v6, shell=True, check=True, capture_output=True, text=True).stdout.splitlines()
        except subprocess.CalledProcessError as e:
            print(f"Error loading IPv6 mappings: {e.stderr.strip()}")
            sys.exit(1)
        for mapping in mappings_v6:
            fake_ip, real_ip = mapping.split(" ")
            if not self.mapping_ip(real_ip, fake_ip, current_time, "v6"):
                subprocess.run("ip6tables -w -t nat -F ANTIZAPRET-MAPPING", shell=True, check=True)
                sys.exit(1)
        print(f"Loaded: {len(mappings_v6)} fake IPv6s")

        self.address, self.port, self.timeout = address, port, timeout
        self.cleanup_interval, self.cleanup_expiry = cleanup_interval, cleanup_expiry
        self.min_ttl, self.max_ttl = min_ttl, max_ttl
        self.lock = threading.Lock()
        threading.Thread(target=self.cleanup_fake_ips_worker, daemon=True).start()

    def get_fake_ip(self, real_ip, current_time, ip_version):
        with self.lock:
            if ip_version == "v4":
                ip_map, ip_pool = self.ip_map_v4, self.ip_pool_v4
            elif ip_version == "v6":
                ip_map, ip_pool = self.ip_map_v6, self.ip_pool_v6
            else:
                return None
            entry = ip_map.get(real_ip)
            if entry:
                entry["last_access"] = current_time
                return entry["fake_ip"]
            try:
                fake_ip = ip_pool.popleft()
            except IndexError:
                print(f"Error: No fake {ip_version} IP left")
                return None
            ip_map[real_ip] = {"fake_ip": fake_ip, "last_access": current_time}
            rule = f"{('iptables' if ip_version == 'v4' else 'ip6tables')} -w -t nat -A ANTIZAPRET-MAPPING -d {fake_ip} -j DNAT --to-destination {real_ip}"
            subprocess.run(rule, shell=True, check=True)
            return fake_ip

    def mapping_ip(self, real_ip, fake_ip, current_time, ip_version):
        if ip_version == "v4":
            ip_map, ip_pool = self.ip_map_v4, self.ip_pool_v4
        elif ip_version == "v6":
            ip_map, ip_pool = self.ip_map_v6, self.ip_pool_v6
        else:
            return False
        if ip_map.get(real_ip):
            print(f"Error: Real IP {real_ip} is already mapped")
            return False
        try:
            ip_pool.remove(fake_ip)
            ip_map[real_ip] = {"fake_ip": fake_ip, "last_access": current_time}
        except ValueError:
            print(f"Error: Fake IP {fake_ip} not in fake {ip_version} IP pool")
            return False
        return True

    def cleanup_fake_ips_worker(self):
        while True:
            time.sleep(self.cleanup_interval)
            self.cleanup_fake_ips()

    def cleanup_fake_ips(self):
        with self.lock:
            current_time = time.time()
            for ip_ver, ip_map, ip_pool, cmd in [("v4", self.ip_map_v4, self.ip_pool_v4, "iptables"), ("v6", self.ip_map_v6, self.ip_pool_v6, "ip6tables")]:
                cleanup_ips = [(k, v["fake_ip"]) for k, v in ip_map.items() if current_time - v["last_access"] > self.cleanup_expiry]
                if not cleanup_ips: continue
                rules = ["*nat"]
                for real_ip, fake_ip in cleanup_ips:
                    ip_pool.appendleft(fake_ip)
                    del ip_map[real_ip]
                    rules.append(f"-D ANTIZAPRET-MAPPING -d {fake_ip} -j DNAT --to-destination {real_ip}")
                rules.append("COMMIT")
                subprocess.run([f"{cmd}-restore", "-w", "-n"], input="\n".join(rules).encode(), check=True)
                print(f"Cleaned: {len(cleanup_ips)} expired fake IP{ip_ver}s")

    def resolve(self, request, handler):
        try:
            proxy_r = request.send(self.address, self.port, tcp=(handler.protocol != "udp"), timeout=self.timeout)
            reply = DNSRecord.parse(proxy_r)
            new_rr = []
            current_time = time.time()
            if request.q.qtype == QTYPE.A:
                ip_version, rdata_class = "v4", A
            elif request.q.qtype == QTYPE.AAAA:
                ip_version, rdata_class = "v6", AAAA
            else:
                return reply
            for record in reply.rr:
                if record.rtype == request.q.qtype:
                    real_ip = str(record.rdata)
                    fake_ip = self.get_fake_ip(real_ip, current_time, ip_version)
                    if not fake_ip:
                        reply = request.reply()
                        reply.header.rcode = RCODE.SERVFAIL
                        return reply
                    record.rdata = rdata_class(fake_ip)
                    record.rname = request.q.qname
                    record.ttl = max(self.min_ttl, min(record.ttl, self.max_ttl))
                new_rr.append(record)
            reply.rr = new_rr
        except Exception as e:
            print(f"Error: {e}")
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
        return reply

class PassthroughDNSHandler(DNSHandler):
    def get_reply(self, data):
        host, port = self.server.resolver.address, self.server.resolver.port
        request = DNSRecord.parse(data)
        self.server.logger.log_request(self, request)
        if self.protocol == "tcp":
            data = struct.pack("!H", len(data)) + data
            response = send_tcp(data, host, port)[2:]
        else:
            response = send_udp(data, host, port)
        reply = DNSRecord.parse(response)
        self.server.logger.log_reply(self, reply)
        return response

def send_tcp(data, host, port):
    addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    for res in addrinfo:
        af, socktype, proto, canonname, sa = res
        try:
            with socket.socket(af, socktype, proto) as sock:
                sock.connect(sa)
                sock.sendall(data)
                response = sock.recv(8192)
                length = struct.unpack("!H", bytes(response[:2]))[0]
                while len(response) - 2 < length:
                    response += sock.recv(8192)
                return response
        except socket.error: continue
    raise socket.error(f"Could not open socket to {host}:{port}")

def send_udp(data, host, port):
    addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    for res in addrinfo:
        af, socktype, proto, canonname, sa = res
        try:
            with socket.socket(af, socktype, proto) as sock:
                sock.sendto(data, sa)
                return sock.recvfrom(8192)[0]
        except socket.error: continue
    raise socket.error(f"Could not open socket to {host}:{port}")

if __name__ == "__main__":
    alt_ip = os.getenv("ALTERNATIVE_IP", "n")
    alt_fake = os.getenv("ALTERNATIVE_FAKE_IP", "y")
    
    base = "172" if alt_ip == "y" else "10"
    ip_v4 = "198.18.0.0/15" if alt_fake == "y" else f"{base}.30.0.0/15"
    ip_v6 = "fd00:18::/112"

    p = argparse.ArgumentParser(description="DNS Proxy")
    p.add_argument("--port", type=int, default=53, metavar="<port>")
    p.add_argument("--address", default="127.0.0.2", metavar="<address>")
    p.add_argument("--upstream", default="127.0.0.1:53", metavar="<dns server:port>")
    p.add_argument("--tcp", action="store_true", default=True)
    p.add_argument("--timeout", type=float, default=5, metavar="<timeout>")
    p.add_argument("--passthrough", action="store_true", default=False)
    p.add_argument("--log", default="truncated,error")
    p.add_argument("--log-prefix", action="store_true", default=False)
    p.add_argument("--ip-range-v4", default=ip_v4, metavar="<ip/mask>")
    p.add_argument("--ip-range-v6", default=ip_v6, metavar="<ip/mask>")
    p.add_argument("--cleanup-interval", type=int, default=3600, metavar="<seconds>")
    p.add_argument("--cleanup-expiry", type=int, default=7200, metavar="<seconds>")
    p.add_argument("--min-ttl", type=int, default=300, metavar="<seconds>")
    p.add_argument("--max-ttl", type=int, default=3600, metavar="<seconds>")
    args = p.parse_args()
    args.dns, _, args.dns_port = args.upstream.partition(":")
    args.dns_port = int(args.dns_port or 53)
    
    print(f"Starting Proxy Resolver (Range: {args.ip_range_v4})...")
    resolver = ProxyResolver(args.dns, args.dns_port, args.timeout, args.ip_range_v4, args.ip_range_v6, args.cleanup_interval, args.cleanup_expiry, args.min_ttl, args.max_ttl)
    handler = PassthroughDNSHandler if args.passthrough else DNSHandler
    logger = DNSLogger(args.log, prefix=args.log_prefix)
    udp_server = DNSServer(resolver, port=args.port, address=args.address, logger=logger, handler=handler)
    udp_server.start_thread()
    if args.tcp:
        tcp_server = DNSServer(resolver, port=args.port, address=args.address, tcp=True, logger=logger, handler=handler)
        tcp_server.start_thread()
    while udp_server.isAlive():
        time.sleep(1)
