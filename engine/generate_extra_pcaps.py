from scapy.all import IP, UDP, Ether, ARP, DNS, DNSQR, wrpcap
import random
import string
import os
from generate_pcaps import normal_traffic, with_time, OUT_DIR

GATEWAY_IP = "192.168.1.1"
GATEWAY_MAC = "aa:bb:cc:00:00:01"
ATTACKER_MAC = "de:ad:be:ef:00:66"
TUNNEL_HOST = "192.168.1.30"
START = 1_700_000_000


def arp_reply(ip, mac, victim_ip, victim_mac):
    """An ARP reply saying: 'ip is at mac'."""
    return (Ether(src=mac, dst=victim_mac) /
            ARP(op=2, psrc=ip, hwsrc=mac, pdst=victim_ip, hwdst=victim_mac))


def arp_spoof():
    pkts = normal_traffic(800, START)

    # Legitimate ARP replies: the gateway and 10 clients announce their real MACs
    legit = []
    for i in range(10):
        c_ip = f"192.168.1.{10 + i}"
        c_mac = f"aa:bb:cc:00:01:{10 + i:02x}"
        legit.append(arp_reply(c_ip, c_mac, GATEWAY_IP, GATEWAY_MAC))
        legit.append(arp_reply(GATEWAY_IP, GATEWAY_MAC, c_ip, c_mac))
    legit = with_time(legit, START + 1, 0.3)

    # Attack: from 8 s in, the attacker claims the gateway's IP with its own MAC
    spoof = []
    for i in range(10):
        c_ip = f"192.168.1.{10 + i}"
        c_mac = f"aa:bb:cc:00:01:{10 + i:02x}"
        spoof.append(arp_reply(GATEWAY_IP, ATTACKER_MAC, c_ip, c_mac))
    spoof = with_time(spoof, START + 8, 0.2)

    return sorted(pkts + legit + spoof, key=lambda p: p.time)


def dns_tunnel():
    pkts = normal_traffic(800, START)
    tunnel = []
    for _ in range(400):  # 400 queries in about 5 seconds
        junk = lambda n: "".join(random.choices(string.ascii_lowercase + string.digits, k=n))
        name = f"{junk(30)}.{junk(30)}.evil.com"   # ~75 characters, random-looking
        tunnel.append(Ether() / IP(src=TUNNEL_HOST, dst=GATEWAY_IP) /
                      UDP(sport=random.randint(1024, 65535), dport=53) /
                      DNS(rd=1, qd=DNSQR(qname=name)))
    tunnel = with_time(tunnel, START + 8, 0.0125)
    return sorted(pkts + tunnel, key=lambda p: p.time)


if __name__ == "__main__":
    os.makedirs(OUT_DIR, exist_ok=True)
    wrpcap(os.path.join(OUT_DIR, "arp_spoof.pcap"), arp_spoof())
    wrpcap(os.path.join(OUT_DIR, "dns_tunnel.pcap"), dns_tunnel())
    print("Created arp_spoof.pcap and dns_tunnel.pcap in data/")
    