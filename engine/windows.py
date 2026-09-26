import sys
from collections import Counter
from datetime import datetime, timezone
from parser import parse_pcap

WINDOW = 5      # seconds
TOP_N = 5       # entries in top_talkers / top_ports


def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_windows(records, window=WINDOW):
    """Group packet records into fixed windows. Returns a list of (start_ts, [records])."""
    if not records:
        return []
    start = records[0]["ts"]
    buckets = {}
    for r in records:
        idx = int((r["ts"] - start) // window)
        buckets.setdefault(idx, []).append(r)
    return [(start + idx * window, buckets[idx]) for idx in sorted(buckets)]


def compute_stats(start_ts, recs, window=WINDOW):
    """Turn one window of records into the stats JSON from the README."""
    total_bytes = sum(r["size"] for r in recs)
    protocol_counts = Counter(r["protocol"] for r in recs)

    talker_packets = Counter()
    talker_bytes = Counter()
    for r in recs:
        talker_packets[r["src_ip"]] += 1
        talker_bytes[r["src_ip"]] += r["size"]

    port_packets = Counter(r["dst_port"] for r in recs if r["dst_port"] is not None)

    return {
        "timestamp": iso(start_ts),
        "window_seconds": window,
        "packets_per_sec": round(len(recs) / window, 1),
        "bytes_per_sec": round(total_bytes / window, 1),
        "protocol_counts": dict(protocol_counts),
        "top_talkers": [
            {"ip": ip, "packets": n, "bytes": talker_bytes[ip]}
            for ip, n in talker_packets.most_common(TOP_N)
        ],
        "top_ports": [
            {"port": p, "packets": n} for p, n in port_packets.most_common(TOP_N)
        ],
    }


def pcap_to_stats(path):
    records = parse_pcap(path)
    return [compute_stats(s, recs) for s, recs in build_windows(records)]


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/port_scan.pcap"
    for s in pcap_to_stats(path):
        print(f"{s['timestamp']}  pps={s['packets_per_sec']:>7}  "
              f"bps={s['bytes_per_sec']:>9}  protocols={s['protocol_counts']}")
        print(f"    top talker: {s['top_talkers'][0]}")