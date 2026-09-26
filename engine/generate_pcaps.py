from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Ether, wrpcap
import random
import os

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(OUT_DIR, exist_ok=True)

CLIENTS = [f"192.168.1.{i}" for i in range(10, 20)]
SERVER = "192.168.1.100"
DNS_SERVER = "192.168.1.1"
ATTACKER = "192.168.1.66"


def with_time(pkts, start, step):
    """Give each packet a timestamp so windowing works later."""
    t = start
    for p in pkts:
        p.time = t
        t += step
    return pkts


def normal_traffic(n=1500, start=1_700_000_000):
    pkts = []
    for _ in range(n):
        c = random.choice(CLIENTS)
        r = random.random()
        if r < 0.55:    # web traffic
            port = random.choice([80, 443])
            pkts.append(Ether() / IP(src=c, dst=SERVER) /
                        TCP(sport=random.randint(1024, 65535), dport=port, flags="PA") /
                        ("x" * random.randint(20, 800)))
        elif r < 0.80:  # DNS
            pkts.append(Ether() / IP(src=c, dst=DNS_SERVER) /
                        UDP(sport=random.randint(1024, 65535), dport=53) /
                        DNS(rd=1, qd=DNSQR(qname=f"site{random.randint(1,30)}.com")))
        elif r < 0.90:  # ICMP ping
            pkts.append(Ether() / IP(src=c, dst=SERVER) / ICMP())
        else:           # proper handshake (SYN, SYN-ACK, ACK)
            sp = random.randint(1024, 65535)
            pkts.append(Ether() / IP(src=c, dst=SERVER) / TCP(sport=sp, dport=80, flags="S"))
            pkts.append(Ether() / IP(src=SERVER, dst=c) / TCP(sport=80, dport=sp, flags="SA"))
            pkts.append(Ether() / IP(src=c, dst=SERVER) / TCP(sport=sp, dport=80, flags="A"))
    return with_time(pkts, start, 0.02)


def port_scan(start=1_700_000_000):
    pkts = normal_traffic(800, start)
    scan = []
    for port in range(1, 1001):  # attacker probes 1000 ports
        scan.append(Ether() / IP(src=ATTACKER, dst=SERVER) /
                    TCP(sport=44444, dport=port, flags="S"))
    scan = with_time(scan, start + 8, 0.005)  # scan starts 8s in
    return sorted(pkts + scan, key=lambda p: p.time)


def syn_flood(start=1_700_000_000):
    pkts = normal_traffic(800, start)
    flood = []
    for _ in range(4000):  # many SYNs, no handshake completion
        flood.append(Ether() / IP(src=ATTACKER, dst=SERVER) /
                     TCP(sport=random.randint(1024, 65535), dport=80, flags="S"))
    flood = with_time(flood, start + 8, 0.001)
    return sorted(pkts + flood, key=lambda p: p.time)


if __name__ == "__main__":
    wrpcap(os.path.join(OUT_DIR, "normal.pcap"), normal_traffic())
    wrpcap(os.path.join(OUT_DIR, "port_scan.pcap"), port_scan())
    wrpcap(os.path.join(OUT_DIR, "syn_flood.pcap"), syn_flood())
    print("Created normal.pcap, port_scan.pcap, syn_flood.pcap in data/")