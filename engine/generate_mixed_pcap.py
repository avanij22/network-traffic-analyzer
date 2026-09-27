from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, wrpcap
import random
import string
import os
from generate_pcaps import normal_traffic, with_time, OUT_DIR, SERVER

ATTACKER = "192.168.1.66"
TUNNEL_HOST = "192.168.1.30"
START = 1_700_000_000


def port_scan_burst(start_at):
    pkts = [Ether() / IP(src=ATTACKER, dst=SERVER) / TCP(sport=44444, dport=p, flags="S")
            for p in range(1, 1001)]
    return with_time(pkts, start_at, 0.005)  # ~5 seconds


def syn_flood_burst(start_at):
    pkts = [Ether() / IP(src=ATTACKER, dst=SERVER) /
            TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
            for _ in range(3000)]
    return with_time(pkts, start_at, 0.001)  # ~3 seconds


def dns_tunnel_burst(start_at):
    junk = lambda n: "".join(random.choices(string.ascii_lowercase + string.digits, k=n))
    pkts = [Ether() / IP(src=TUNNEL_HOST, dst="192.168.1.1") /
            UDP(sport=random.randint(1024, 65535), dport=53) /
            DNS(rd=1, qd=DNSQR(qname=f"{junk(30)}.{junk(30)}.evil.com"))
            for _ in range(400)]
    return with_time(pkts, start_at, 0.0125)  # ~5 seconds


def generate_mixed():
    """One capture, three different attacks, at different times, on top of ongoing normal traffic."""
    baseline = normal_traffic(2400, START)          # ~48 seconds of normal traffic
    scan = port_scan_burst(START + 8)                # port scan: 8s to 13s
    flood = syn_flood_burst(START + 20)              # SYN flood: 20s to 23s
    tunnel = dns_tunnel_burst(START + 35)            # DNS tunnel: 35s to 40s
    return sorted(baseline + scan + flood + tunnel, key=lambda p: p.time)


if __name__ == "__main__":
    os.makedirs(OUT_DIR, exist_ok=True)
    wrpcap(os.path.join(OUT_DIR, "mixed.pcap"), generate_mixed())
    print("Created mixed.pcap in data/")