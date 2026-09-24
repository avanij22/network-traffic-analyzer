import sys
import statistics
from collections import Counter, defaultdict
from parser import parse_pcap
from windows import build_windows, compute_stats, iso, WINDOW

# Thresholds (tune these in Step 6)
PORT_SCAN_MIN_PORTS = 100      # distinct dst ports from one source to one target, per window
SYN_FLOOD_MIN_SYNS = 300       # SYNs to one ip:port per window
SYN_FLOOD_MAX_COMPLETION = 0.2 # SYN-ACK replies / SYNs at or below this = handshakes not completing
SPIKE_Z = 3                    # z-score above the recent average
SPIKE_MIN_HISTORY = 1          # captures are short; raise this for longer captures
SPIKE_HISTORY = 6              # how many previous normal windows form the baseline


def make_alert(start_ts, type_, severity, source_ip, explanation, details):
    return {
        "timestamp": iso(start_ts), "type": type_, "severity": severity,
        "source_ip": source_ip, "explanation": explanation, "details": details,
    }


def detect_port_scan(recs, start_ts):
    """One source sending SYNs to many distinct ports on the same target."""
    ports = defaultdict(set)
    for r in recs:
        if r["protocol"] == "TCP" and r["flags"] == "S":
            ports[(r["src_ip"], r["dst_ip"])].add(r["dst_port"])

    alerts = []
    for (src, dst), p in ports.items():
        n = len(p)
        if n >= PORT_SCAN_MIN_PORTS:
            sev = "high" if n >= 500 else "medium" if n >= 200 else "low"
            alerts.append(make_alert(
                start_ts, "port_scan", sev, src,
                f"{src} sent SYN packets to {n} distinct ports on {dst} "
                f"in {WINDOW} seconds (possible port scan).",
                {"target_ip": dst, "distinct_ports": n, "window_seconds": WINDOW}))
    return alerts


def detect_syn_flood(recs, start_ts):
    """Many SYNs to one ip:port while few handshakes complete."""
    syns = Counter()
    sources = defaultdict(Counter)
    synacks = Counter()
    for r in recs:
        if r["protocol"] != "TCP":
            continue
        if r["flags"] == "S":
            key = (r["dst_ip"], r["dst_port"])
            syns[key] += 1
            sources[key][r["src_ip"]] += 1
        elif r["flags"] == "SA":
            synacks[(r["src_ip"], r["src_port"])] += 1

    alerts = []
    for key, n in syns.items():
        if n < SYN_FLOOD_MIN_SYNS:
            continue
        completion = synacks[key] / n
        if completion <= SYN_FLOOD_MAX_COMPLETION:
            dst, port = key
            top_src, _ = sources[key].most_common(1)[0]
            sev = "high" if n >= 1000 else "medium" if n >= 500 else "low"
            alerts.append(make_alert(
                start_ts, "syn_flood", sev, top_src,
                f"{n} SYN packets hit {dst}:{port} in {WINDOW} seconds and only "
                f"{completion:.0%} were answered with SYN-ACK (possible SYN flood).",
                {"target_ip": dst, "target_port": port, "syn_count": n,
                 "completion_ratio": round(completion, 3), "window_seconds": WINDOW}))
    return alerts


def detect_spike(stats, baseline, start_ts):
    """Packets/sec far above the recent average (z-score)."""
    if len(baseline) < SPIKE_MIN_HISTORY:
        return None
    mean = statistics.mean(baseline)
    # floor on the std so a perfectly flat baseline doesn't give infinite z
    std = max(statistics.pstdev(baseline), 0.1 * mean)
    pps = stats["packets_per_sec"]
    z = (pps - mean) / std
    if z >= SPIKE_Z:
        sev = "high" if z >= 10 else "medium" if z >= 5 else "low"
        return make_alert(
            start_ts, "traffic_spike", sev, None,
            f"Traffic rose to {pps} packets/sec, against a recent average of "
            f"{mean:.1f} (z-score {z:.1f}).",
            {"packets_per_sec": pps, "baseline_mean": round(mean, 1), "z_score": round(z, 1)})
    return None


def detect_pcap(path):
    """Returns (stats_list, alerts_list) for a PCAP."""
    records = parse_pcap(path)
    all_stats, all_alerts, baseline = [], [], []
    for start, recs in build_windows(records):
        stats = compute_stats(start, recs)
        all_stats.append(stats)
        all_alerts += detect_port_scan(recs, start)
        all_alerts += detect_syn_flood(recs, start)
        spike = detect_spike(stats, baseline, start)
        if spike:
            all_alerts.append(spike)
        else:  # only normal windows feed the baseline
            baseline.append(stats["packets_per_sec"])
            baseline[:] = baseline[-SPIKE_HISTORY:]
    return all_stats, all_alerts


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/port_scan.pcap"
    _, alerts = detect_pcap(path)
    print(f"{len(alerts)} alert(s) in {path}\n")
    for a in alerts:
        print(f"[{a['severity'].upper():6}] {a['timestamp']}  {a['type']}")
        print(f"         {a['explanation']}")