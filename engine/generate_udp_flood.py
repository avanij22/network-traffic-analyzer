from scapy.all import IP, UDP, Ether, wrpcap
import random
import os
from generate_pcaps import normal_traffic, with_time, OUT_DIR, SERVER

ATTACKER = "192.168.1.66"
TARGET_PORT = 9999  # a made-up UDP service being flooded
START = 1_700_000_000


def udp_flood_burst(start_at):
    """Many UDP packets to one target port, from spoofed-looking random source ports.
    Unlike SYN flood, UDP has no handshake to fail to complete — the signature here
    is purely volume to one destination, which is why the detector works differently."""
    pkts = [Ether() / IP(src=ATTACKER, dst=SERVER) /
            UDP(sport=random.randint(1024, 65535), dport=TARGET_PORT) /
            (b"x" * random.randint(20, 200))
            for _ in range(3000)]
    return with_time(pkts, start_at, 0.001)  # ~3 seconds


def generate_udp_flood():
    baseline = normal_traffic(800, START)
    flood = udp_flood_burst(START + 8)
    return sorted(baseline + flood, key=lambda p: p.time)


if __name__ == "__main__":
    os.makedirs(OUT_DIR, exist_ok=True)
    wrpcap(os.path.join(OUT_DIR, "udp_flood.pcap"), generate_udp_flood())
    print("Created udp_flood.pcap in data/")