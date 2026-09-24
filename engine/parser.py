import sys
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNSQR


def parse_packet(pkt):
    """Turn one Scapy packet into a simple dict. Returns None if we don't handle it."""
    ts = float(pkt.time)
    size = len(pkt)

    # ARP has no IP layer, so handle it first
    if ARP in pkt:
        return {
            "ts": ts, "src_ip": pkt[ARP].psrc, "dst_ip": pkt[ARP].pdst,
            "src_port": None, "dst_port": None, "protocol": "ARP",
            "flags": "", "size": size, "src_mac": pkt[ARP].hwsrc,
            "dns_name": None,
        }

    if IP not in pkt:
        return None

    record = {
        "ts": ts, "src_ip": pkt[IP].src, "dst_ip": pkt[IP].dst,
        "src_port": None, "dst_port": None, "protocol": "OTHER",
        "flags": "", "size": size, "src_mac": None, "dns_name": None,
    }

    if TCP in pkt:
        record["protocol"] = "TCP"
        record["src_port"] = pkt[TCP].sport
        record["dst_port"] = pkt[TCP].dport
        record["flags"] = str(pkt[TCP].flags)   # e.g. "S", "SA", "A", "PA"
    elif UDP in pkt:
        record["src_port"] = pkt[UDP].sport
        record["dst_port"] = pkt[UDP].dport
        # Decision: UDP on port 53 is counted as DNS, not UDP
        is_dns = 53 in (pkt[UDP].sport, pkt[UDP].dport)
        record["protocol"] = "DNS" if is_dns else "UDP"
        if is_dns and DNSQR in pkt:
            name = pkt[DNSQR].qname
            record["dns_name"] = (
                name.decode(errors="ignore").rstrip(".")
                if isinstance(name, bytes) else str(name)
            )
    elif ICMP in pkt:
        record["protocol"] = "ICMP"

    return record


def parse_pcap(path):
    """Read a PCAP file and return a list of packet records, in time order."""
    packets = rdpcap(path)
    records = []
    for pkt in packets:
        r = parse_packet(pkt)
        if r is not None:
            records.append(r)
    records.sort(key=lambda r: r["ts"])
    return records


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/normal.pcap"
    records = parse_pcap(path)

    print(f"{len(records)} packets parsed from {path}\n")
    print("First 10 packets:")
    for r in records[:10]:
        print(r)

    counts = {}
    for r in records:
        counts[r["protocol"]] = counts.get(r["protocol"], 0) + 1
    print("\nProtocol counts:", counts)