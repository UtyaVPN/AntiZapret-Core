#!/usr/bin/env -S python3 -u
# -*- coding: utf-8 -*-

from __future__ import print_function
import socket,struct,subprocess,sys,time,argparse,threading
from collections import deque
from ipaddress import IPv4Network, IPv6Network, ip_address
from dnslib import DNSRecord,RCODE,QTYPE,A,AAAA
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger

class ProxyResolver(BaseResolver):
    """
        Proxy resolver - passes all requests to upstream DNS server and
        returns response

        Note that the request/response will be each be decoded/re-encoded
        twice:

        a) Request packet received by DNSHandler and parsed into DNSRecord
        b) DNSRecord passed to ProxyResolver, serialised back into packet
           and sent to upstream DNS server
        c) Upstream DNS server returns response packet which is parsed into
           DNSRecord
        d) ProxyResolver returns DNSRecord to DNSHandler which re-serialises
           this into packet and returns to client

        In practice this is actually fairly useful for testing but for a
        'real' transparent proxy option the DNSHandler logic needs to be
        modified (see PassthroughDNSHandler)
    """
    def __init__(self,address,port,timeout,ip_range_v4,ip_range_v6,cleanup_interval,cleanup_expiry,min_ttl,max_ttl):
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
            print(f"IPv6 pool size: {len(self.ip_pool_v6)}")
        except Exception as e:
            print(f"Error initializing IPv6 pool with {ip_range_v6}: {e}")
            sys.exit(1)

        # Loading existing mappings
        current_time = time.time()
        # Load IPv4 mappings
        rule_v4 = "iptables -w -t nat -S ANTIZAPRET-MAPPING | awk '{if (NR<2) {next}; split($4, a, \"/\"); print a[1], $8}'"
        try:
            print(f"Running rule_v4: {rule_v4}")
            mappings_v4 = subprocess.run(rule_v4,shell=True,check=True,capture_output=True,text=True).stdout.splitlines()
        except subprocess.CalledProcessError as e:
            print(f"Error loading IPv4 mappings: {e.stderr.strip()}")
            sys.exit(1)
        for mapping in mappings_v4:
            fake_ip,real_ip = mapping.split(" ")
            if not self.mapping_ip(real_ip,fake_ip,current_time,"v4"):
                rule = "iptables -w -t nat -F ANTIZAPRET-MAPPING"
                subprocess.run(rule,shell=True,check=True)
                sys.exit(1)
        print(f"Loaded: {len(mappings_v4)} fake IPv4s")

        # Load IPv6 mappings
        rule_v6 = "ip6tables -w -t nat -S ANTIZAPRET-MAPPING | awk '{if (NR<2) {next}; split($4, a, \"/\"); print a[1], $8}'"
        try:
            print(f"Running rule_v6: {rule_v6}")
            mappings_v6 = subprocess.run(rule_v6,shell=True,check=True,capture_output=True,text=True).stdout.splitlines()
        except subprocess.CalledProcessError as e:
            print(f"Error loading IPv6 mappings: {e.stderr.strip()}")
            sys.exit(1)
        for mapping in mappings_v6:
            fake_ip,real_ip = mapping.split(" ")
            if not self.mapping_ip(real_ip,fake_ip,current_time,"v6"):
                rule = "ip6tables -w -t nat -F ANTIZAPRET-MAPPING"
                subprocess.run(rule,shell=True,check=True) # This might also fail
                sys.exit(1)
        print(f"Loaded: {len(mappings_v6)} fake IPv6s")

        self.address = address
        self.port = port
        self.timeout = timeout
        self.cleanup_interval = cleanup_interval
        self.cleanup_expiry = cleanup_expiry
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.lock = threading.Lock()
        # Start thread for cleanup fake IPs
        threading.Thread(target=self.cleanup_fake_ips_worker,daemon=True).start()

    def get_fake_ip(self,real_ip,current_time,ip_version):
        with self.lock:
            if ip_version == "v4":
                ip_map = self.ip_map_v4
                ip_pool = self.ip_pool_v4
                iptables_cmd = "iptables"
            elif ip_version == "v6":
                ip_map = self.ip_map_v6
                ip_pool = self.ip_pool_v6
                iptables_cmd = "ip6tables"
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
            ip_map[real_ip] = {"fake_ip": fake_ip,"last_access": current_time}
            if ip_version == "v4":
                rule = f"iptables -w -t nat -A ANTIZAPRET-MAPPING -d {fake_ip} -j DNAT --to-destination {real_ip}"
            else:
                rule = f"ip6tables -w -t nat -A ANTIZAPRET-MAPPING -d {fake_ip} -j DNAT --to-destination {real_ip}"
            subprocess.run(rule,shell=True,check=True)
            #print(f"Mapping: {fake_ip} to {real_ip}")
            return fake_ip

    def mapping_ip(self,real_ip,fake_ip,current_time,ip_version):
        if ip_version == "v4":
            ip_map = self.ip_map_v4
            ip_pool = self.ip_pool_v4
        elif ip_version == "v6":
            ip_map = self.ip_map_v6
            ip_pool = self.ip_pool_v6
        else:
            return False

        if ip_map.get(real_ip):
            print(f"Error: Real IP {real_ip} is already mapped")
            return False
        try:
            ip_pool.remove(fake_ip)
            ip_map[real_ip] = {"fake_ip": fake_ip,"last_access": current_time}
            #print(f"Mapping: {fake_ip} to {real_ip}")
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
            cleanup_ips_v4 = []
            cleanup_ips_v6 = []
            rules_v4 = ["*nat"]
            rules_v6 = ["*nat"]

            for key,entry in self.ip_map_v4.items():
                if current_time - entry["last_access"] > self.cleanup_expiry:
                    cleanup_ips_v4.append((key,entry["fake_ip"]))
            for real_ip,fake_ip in cleanup_ips_v4:
                self.ip_pool_v4.appendleft(fake_ip)
                del self.ip_map_v4[real_ip]
                rules_v4.append(f"-D ANTIZAPRET-MAPPING -d {fake_ip} -j DNAT --to-destination {real_ip}")
            rules_v4.append("COMMIT")
            if len(cleanup_ips_v4) > 0:
                subprocess.run(["iptables-restore","-w","-n"],input="\n".join(rules_v4).encode(),check=True)
                print(f"Cleaned: {len(cleanup_ips_v4)} expired fake IPv4s")

            for key,entry in self.ip_map_v6.items():
                if current_time - entry["last_access"] > self.cleanup_expiry:
                    cleanup_ips_v6.append((key,entry["fake_ip"]))
            for real_ip,fake_ip in cleanup_ips_v6:
                self.ip_pool_v6.appendleft(fake_ip)
                del self.ip_map_v6[real_ip]
                rules_v6.append(f"-D ANTIZAPRET-MAPPING -d {fake_ip} -j DNAT --to-destination {real_ip}")
            rules_v6.append("COMMIT")
            if len(cleanup_ips_v6) > 0:
                subprocess.run(["ip6tables-restore","-w","-n"],input="\n".join(rules_v6).encode(),check=True)
                print(f"Cleaned: {len(cleanup_ips_v6)} expired fake IPv6s")

    def resolve(self,request,handler):
        try:
            if handler.protocol == "udp":
                proxy_r = request.send(self.address,self.port,timeout=self.timeout)
            else:
                proxy_r = request.send(self.address,self.port,tcp=True,timeout=self.timeout)
            reply = DNSRecord.parse(proxy_r)
            new_rr = []
            current_time = time.time()

            if request.q.qtype == QTYPE.A:
                ip_version = "v4"
                rdata_class = A
            elif request.q.qtype == QTYPE.AAAA:
                ip_version = "v6"
                rdata_class = AAAA
            else:
                return reply # Return original reply for unsupported QTYPEs

            for record in reply.rr:
                if record.rtype == request.q.qtype:
                    real_ip = str(record.rdata)
                    fake_ip = self.get_fake_ip(real_ip,current_time,ip_version)
                    if not fake_ip:
                        reply = request.reply()
                        reply.header.rcode = RCODE.SERVFAIL
                        return reply
                    record.rdata = rdata_class(fake_ip)
                    record.rname = request.q.qname
                    if record.ttl < self.min_ttl:
                        record.ttl = self.min_ttl
                    elif record.ttl > self.max_ttl:
                        record.ttl = self.max_ttl
                new_rr.append(record)
            reply.rr = new_rr
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
    addrinfo = socket.getaddrinfo(host,port,socket.AF_UNSPEC,socket.SOCK_STREAM)
    sock = None
    try:
        for res in addrinfo:
            af,socktype,proto,canonname,sa = res
            try:
                sock = socket.socket(af,socktype,proto)
                sock.connect(sa)
                break
            except socket.error as e:
                sock = None
                continue
        if sock is None:
            raise socket.error("Could not open socket to %s:%s" % (host,port))
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
    addrinfo = socket.getaddrinfo(host,port,socket.AF_UNSPEC,socket.SOCK_DGRAM)
    sock = None
    try:
        for res in addrinfo:
            af,socktype,proto,canonname,sa = res
            try:
                sock = socket.socket(af,socktype,proto)
                sock.sendto(data,sa)
                break
            except socket.error as e:
                sock = None
                continue
        if sock is None:
            raise socket.error("Could not open socket to %s:%s" % (host,port))
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
                    help="Local proxy listen address (default:all)")
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
    p.add_argument("--ip-range-v4",default="10.30.0.0/15",
                    metavar="<ip/mask>",
                    help="Fake IPv4 range (default:10.30.0.0/15)")
    p.add_argument("--ip-range-v6",default="fd00:18::/112",
                    metavar="<ip/mask>",
                    help="Fake IPv6 range (default:fd00:18::/112)")
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
    print("Starting Proxy Resolver...")
    resolver = ProxyResolver(args.dns,args.dns_port,args.timeout,args.ip_range_v4,args.ip_range_v6,args.cleanup_interval,args.cleanup_expiry,args.min_ttl,args.max_ttl)
    handler = PassthroughDNSHandler if args.passthrough else DNSHandler
    logger = DNSLogger(args.log,prefix=args.log_prefix)
    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger,
                           handler=handler)
    udp_server.start_thread()
    if args.tcp:
        tcp_server = DNSServer(resolver,
                               port=args.port,
                               address=args.address,
                               tcp=True,
                               logger=logger,
                               handler=handler)
        tcp_server.start_thread()
    print("Started Proxy Resolver: %s:%d -> %s:%d (%s)" % (args.address or "*",args.port,args.dns,args.dns_port,"UDP/TCP" if args.tcp else "UDP"))
    while udp_server.isAlive():
        time.sleep(1)
