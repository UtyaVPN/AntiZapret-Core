#!/usr/bin/env -S python3 -u
# -*- coding: utf-8 -*-

from __future__ import print_function
import socket,struct,subprocess,sys,time,argparse,threading,ipaddress
from collections import deque
from ipaddress import IPv4Network,IPv6Network
from dnslib import DNSRecord,RCODE,QTYPE,A,AAAA
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger

class ProxyResolver(BaseResolver):
    def __init__(self,address,port,timeout,ip_range,ip6_range,cleanup_interval,cleanup_expiry,min_ttl,max_ttl):
        self.ip4_pool = deque([str(x) for x in IPv4Network(ip_range).hosts()])
        self.ip6_pool = deque([str(x) for x in IPv6Network(ip6_range).hosts()])
        self.ip_map = {}

        self.load_mappings("iptables -w -t nat -S ANTIZAPRET-MAPPING", 4)
        self.load_mappings("ip6tables -w -t nat -S ANTIZAPRET-MAPPING", 6)

        self.address = address
        self.port = port
        self.timeout = timeout
        self.cleanup_interval = cleanup_interval
        self.cleanup_expiry = cleanup_expiry
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.lock = threading.Lock()
        threading.Thread(target=self.cleanup_fake_ips_worker,daemon=True).start()

    def load_mappings(self, rule, ip_version):
        mappings_cmd = f"{rule} | awk '{{if (NR<2) {{next}}; print substr($4, 1, length($4)-3), $8}}'"
        try:
            mappings = subprocess.run(mappings_cmd, shell=True, check=True, capture_output=True, text=True).stdout.splitlines()
            current_time = time.time()
            for mapping in mappings:
                fake_ip, real_ip = mapping.split(" ")
                if not self.mapping_ip(real_ip, fake_ip, current_time):
                    flush_rule = f"{'ip6' if ip_version == 6 else 'ip'}tables -w -t nat -F ANTIZAPRET-MAPPING"
                    subprocess.run(flush_rule, shell=True, check=True)
                    sys.exit(1)
            print(f"Loaded: {len(mappings)} fake IPv{ip_version} IPs")
        except subprocess.CalledProcessError as e:
            print(f"Error loading IPv{ip_version} mappings: {e}")

    def get_fake_ip(self,real_ip_str):
        with self.lock:
            entry = self.ip_map.get(real_ip_str)
            if entry:
                entry["last_access"] = time.time()
                return entry["fake_ip"]
            else:
                try:
                    ip_obj = ipaddress.ip_address(real_ip_str)
                    if ip_obj.version == 4:
                        fake_ip = self.ip4_pool.popleft()
                        iptables_cmd = "iptables"
                    else:
                        fake_ip = self.ip6_pool.popleft()
                        iptables_cmd = "ip6tables"
                except IndexError:
                    print(f"Error: No fake IPv{ip_obj.version} left")
                    return None

                self.ip_map[real_ip_str] = {"fake_ip": fake_ip, "last_access": time.time()}
                rule = f"{iptables_cmd} -w -t nat -A ANTIZAPRET-MAPPING -d {fake_ip} -j DNAT --to {real_ip_str}"
                subprocess.run(rule,shell=True,check=True)
                return fake_ip

    def mapping_ip(self,real_ip_str,fake_ip_str,last_access):
        if self.ip_map.get(real_ip_str):
            print(f"Error: Real IP {real_ip_str} is already mapped")
            return False
        try:
            ip_obj = ipaddress.ip_address(fake_ip_str)
            if ip_obj.version == 4:
                self.ip4_pool.remove(fake_ip_str)
            else:
                self.ip6_pool.remove(fake_ip_str)
            self.ip_map[real_ip_str] = {"fake_ip": fake_ip_str, "last_access": last_access}
        except ValueError:
            print(f"Error: Fake IP {fake_ip_str} not in fake IP pool")
            return False
        return True

    def cleanup_fake_ips_worker(self):
        while True:
            time.sleep(self.cleanup_interval)
            self.cleanup_fake_ips()

    def cleanup_fake_ips(self):
        with self.lock:
            current_time = time.time()
            cleanup_ips = []
            rules4 = ["*nat"]
            rules6 = ["*nat"]

            for key,entry in self.ip_map.items():
                if current_time - entry["last_access"] > self.cleanup_expiry:
                    cleanup_ips.append((key,entry["fake_ip"]))

            for real_ip_str,fake_ip_str in cleanup_ips:
                ip_obj = ipaddress.ip_address(fake_ip_str)
                if ip_obj.version == 4:
                    self.ip4_pool.appendleft(fake_ip_str)
                    rules = rules4
                else:
                    self.ip6_pool.appendleft(fake_ip_str)
                    rules = rules6
                del self.ip_map[real_ip_str]
                rules.append(f"-D ANTIZAPRET-MAPPING -d {fake_ip_str} -j DNAT --to {real_ip_str}")

            rules4.append("COMMIT")
            rules6.append("COMMIT")
            if len(rules4) > 2:
                subprocess.run(["iptables-restore","-w","-n"],input="\n".join(rules4).encode(),check=True)
            if len(rules6) > 2:
                subprocess.run(["ip6tables-restore","-w","-n"],input="\n".join(rules6).encode(),check=True)
            if cleanup_ips:
                print(f"Cleaned: {len(cleanup_ips)} expired fake IPs")

    def resolve(self,request,handler):
        try:
            if handler.protocol == "udp":
                proxy_r = request.send(self.address,self.port,timeout=self.timeout)
            else:
                proxy_r = request.send(self.address,self.port,tcp=True,timeout=self.timeout)
            reply = DNSRecord.parse(proxy_r)

            if request.q.qtype in (QTYPE.A, QTYPE.AAAA):
                newrr = []
                for record in reply.rr:
                    if record.rtype in (QTYPE.A, QTYPE.AAAA):
                        newrr.append(record)
                reply.rr = newrr
                for record in reply.rr:
                    real_ip = str(record.rdata)
                    fake_ip = self.get_fake_ip(real_ip)
                    if not fake_ip:
                        reply = request.reply()
                        reply.header.rcode = RCODE.SERVFAIL
                        return reply
                    if record.rtype == QTYPE.A:
                        record.rdata = A(fake_ip)
                    else:
                        record.rdata = AAAA(fake_ip)
                    record.rname = request.q.qname
            
            for record in reply.rr:
                if record.rtype == QTYPE.A:
                    record.rdata = A(fake_ip)
                else:
                    record.rdata = AAAA(fake_ip)
                record.rname = request.q.qname

                if record.ttl < self.min_ttl:
                    record.ttl = self.min_ttl
                elif record.ttl > self.max_ttl:
                    record.ttl = self.max_ttl

        except Exception as e:
            print(f"Error: {e}")
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
        return reply

class PassthroughDNSHandler(DNSHandler):
    """
        Modify DNSHandler logic (get_reply method) to send directly to
        upstream DNS server rather then decoding/encoding packet and
        passing to Resolver (The request/response packets are still
        parsed and logged but this is not inline)
    """
    def get_reply(self,data):
        host,port = self.server.resolver.address,self.server.resolver.port
        request = DNSRecord.parse(data)
        self.server.logger.log_request(self,request)
        if self.protocol == "tcp":
            data = struct.pack("!H",len(data)) + data
            response = send_tcp(data,host,port)
            response = response[2:]
        else:
            response = send_udp(data,host,port)
        reply = DNSRecord.parse(response)
        self.server.logger.log_reply(self,reply)
        return response

def send_tcp(data,host,port):
    """
        Helper function to send/receive DNS TCP request
        (in/out packets will have prepended TCP length header)
    """
    sock = None
    try:
        if ipaddress.ip_address(host).version == 4:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
        sock.connect((host,port))
        sock.sendall(data)
        response = sock.recv(8192)
        length = struct.unpack("!H",bytes(response[:2]))[0]
        while len(response) - 2 < length:
            response += sock.recv(8192)
        return response
    finally:
        if (sock is not None):
            sock.close()

def send_udp(data,host,port):
    """
        Helper function to send/receive DNS UDP request
    """
    sock = None
    try:
        if ipaddress.ip_address(host).version == 4:
            sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        else:
            sock = socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
        sock.sendto(data,(host,port))
        response,server = sock.recvfrom(8192)
        return response
    finally:
        if (sock is not None):
            sock.close()

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="DNS Proxy")
    p.add_argument("--port",type=int,default=53,
                    metavar="<port>",
                    help="Local proxy port (default:53)")
    p.add_argument("--address",default="127.0.0.2",
                    metavar="<address>",
                    help="Local proxy listen address (default:127.0.0.2)")
    p.add_argument("--address6",default="::2",
                    metavar="<address>",
                    help="Local proxy listen IPv6 address (default: ::2)")
    p.add_argument("--upstream",default="127.0.0.1:53",
                    metavar="<dns server:port>",
                    help="Upstream DNS server:port (default:127.0.0.1:53)")
    p.add_argument("--tcp",action="store_true",default=True,
                    help="TCP proxy (default: True)")
    p.add_argument("--timeout",type=float,default=5,
                    metavar="<timeout>",
                    help="Upstream timeout (default: 5s)")
    p.add_argument("--passthrough",action="store_true",default=False,
                    help="Dont decode/re-encode request/response (default: False)")
    p.add_argument("--log",default="truncated,error",
                    help="Log hooks to enable (default: +truncated,+error,-request,-reply,-recv,-send,-data)")
    p.add_argument("--log-prefix",action="store_true",default=False,
                    help="Log prefix (timestamp/handler/resolver) (default: False)")
    p.add_argument("--ip-range",default="10.30.0.0/15",
                    metavar="<ip/mask>",
                    help="Fake IP range (default:10.30.0.0/15)")
    p.add_argument("--ip6-range",default="fd00:10:30::/112",
                    metavar="<ip6/mask>",
                    help="Fake IPv6 range (default:fd00:10:30::/112)")
    p.add_argument("--cleanup-interval",type=int,default=3600,
                    metavar="<seconds>",
                    help="Seconds between fake IP cleanup runs (default: 3600)")
    p.add_argument("--cleanup-expiry",type=int,default=7200,
                    metavar="<seconds>",
                    help="Seconds of inactivity before fake IP is removed (default: max-ttl * 2)")
    p.add_argument("--min-ttl",type=int,default=300,
                    metavar="<seconds>",
                    help="Minimum TTL in seconds (default: 300)")
    p.add_argument("--max-ttl",type=int,default=3600,
                    metavar="<seconds>",
                    help="Maximum TTL in seconds (default: 3600)")
    args = p.parse_args()
    args.dns,_,args.dns_port = args.upstream.partition(":")
    args.dns_port = int(args.dns_port or 53)
    
    print("Starting Proxy Resolver (%s:%d -> %s:%d) [%s]" % (
                        args.address or "*",args.port,
                        args.dns,args.dns_port,
                        "UDP/TCP" if args.tcp else "UDP"))

    resolver = ProxyResolver(args.dns,args.dns_port,args.timeout,args.ip_range,args.ip6_range,args.cleanup_interval,args.cleanup_expiry,args.min_ttl,args.max_ttl)
    handler = PassthroughDNSHandler if args.passthrough else DNSHandler
    logger = DNSLogger(args.log,prefix=args.log_prefix)
    
    servers = []
    
    if args.address:
        udp_server = DNSServer(resolver, port=args.port, address=args.address, logger=logger, handler=handler)
        servers.append(udp_server)
        if args.tcp:
            tcp_server = DNSServer(resolver, port=args.port, address=args.address, tcp=True, logger=logger, handler=handler)
            servers.append(tcp_server)

    if args.address6:
        udp_server_v6 = DNSServer(resolver, port=args.port, address=args.address6, logger=logger, handler=handler)
        servers.append(udp_server_v6)
        if args.tcp:
            tcp_server_v6 = DNSServer(resolver, port=args.port, address=args.address6, tcp=True, logger=logger, handler=handler)
            servers.append(tcp_server_v6)

    for server in servers:
        server.start_thread()

    while True:
        try:
            time.sleep(1)
            sys.stdout.flush()
        except KeyboardInterrupt:
            for server in servers:
                server.stop()
            break
