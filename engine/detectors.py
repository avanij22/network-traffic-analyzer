import sys
import statistics
from datetime import datetime, timezone
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
DNS_MIN_QUERIES = 100          # DNS queries from one host per window
DNS_LONG_NAME = 50             # names longer than this many characters count as "long"
DNS_MIN_LONG_QUERIES = 50      # long-name queries from one host per window


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


def detect_arp_spoof(recs, start_ts, arp_table):
    """Same IP seen with a different MAC than before.
    arp_table maps ip -> first MAC seen and persists across windows."""
    alerts = []
    for r in recs:
        if r["protocol"] != "ARP" or not r["src_mac"]:
            continue
        ip, mac = r["src_ip"], r["src_mac"]
        known = arp_table.get(ip)
        if known is None:
            arp_table[ip] = mac
        elif known != mac:
            alerts.append(make_alert(
                start_ts, "arp_spoof", "high", ip,
                f"{ip} was first seen at MAC {known}, now claims MAC {mac} "
                f"(possible ARP spoofing).",
                {"ip": ip, "original_mac": known, "new_mac": mac}))
    # one alert per (ip, new_mac) per window
    seen, unique = set(), []
    for a in alerts:
        k = (a["source_ip"], a["details"]["new_mac"])
        if k not in seen:
            seen.add(k)
            unique.append(a)
    return unique


def detect_dns_anomaly(recs, start_ts):
    """A host sending very many DNS queries, or many very long names."""
    total, long_, length_sum = Counter(), Counter(), Counter()
    for r in recs:
        if r["protocol"] == "DNS" and r["dns_name"] and r["dst_port"] == 53:
            total[r["src_ip"]] += 1
            length_sum[r["src_ip"]] += len(r["dns_name"])
            if len(r["dns_name"]) > DNS_LONG_NAME:
                long_[r["src_ip"]] += 1

    alerts = []
    for ip, n in total.items():
        if n >= DNS_MIN_QUERIES or long_[ip] >= DNS_MIN_LONG_QUERIES:
            avg = length_sum[ip] / n
            sev = "high" if long_[ip] >= DNS_MIN_LONG_QUERIES else "medium"
            alerts.append(make_alert(
                start_ts, "dns_anomaly", sev, ip,
                f"{ip} sent {n} DNS queries in {WINDOW} seconds with an average "
                f"name length of {avg:.0f} characters (possible DNS tunneling).",
                {"queries": n, "long_queries": long_[ip],
                 "avg_name_length": round(avg, 1), "window_seconds": WINDOW}))
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


# ---------- alert merging ----------

def _seconds_between(ts1, ts2):
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    t1 = datetime.strptime(ts1, fmt).replace(tzinfo=timezone.utc)
    t2 = datetime.strptime(ts2, fmt).replace(tzinfo=timezone.utc)
    return abs((t2 - t1).total_seconds())


def _start(a):
    c = dict(a)
    c["_last_ts"] = a["timestamp"]
    c["_first_ts"] = a["timestamp"]
    c["_count"] = 1
    c["_details_list"] = [a["details"]]
    return c


def _combine(current, a):
    current["_last_ts"] = a["timestamp"]
    current["_count"] += 1
    current["_details_list"].append(a["details"])
    order = {"low": 0, "medium": 1, "high": 2}
    if order[a["severity"]] > order[current["severity"]]:
        current["severity"] = a["severity"]
    return current


def _rebuild_explanation(type_, source_ip, details_list, n):
    """Build an accurate explanation using totals summed across all merged windows."""
    if type_ == "port_scan":
        total_ports = sum(d["distinct_ports"] for d in details_list)
        target = details_list[0]["target_ip"]
        total_window = n * details_list[0]["window_seconds"]
        return (f"{source_ip} sent SYN packets to {total_ports} distinct ports on {target} "
                f"over {total_window} seconds (possible port scan).")
    if type_ == "syn_flood":
        total_syns = sum(d["syn_count"] for d in details_list)
        target = details_list[0]["target_ip"]
        port = details_list[0]["target_port"]
        avg_completion = sum(d["completion_ratio"] for d in details_list) / n
        total_window = n * details_list[0]["window_seconds"]
        return (f"{total_syns} SYN packets hit {target}:{port} over {total_window} seconds and only "
                f"{avg_completion:.0%} were answered with SYN-ACK (possible SYN flood).")
    if type_ == "dns_anomaly":
        total_queries = sum(d["queries"] for d in details_list)
        avg_len = sum(d["avg_name_length"] * d["queries"] for d in details_list) / total_queries
        total_window = n * details_list[0]["window_seconds"]
        return (f"{source_ip} sent {total_queries} DNS queries over {total_window} seconds with an "
                f"average name length of {avg_len:.0f} characters (possible DNS tunneling).")
    if type_ == "traffic_spike":
        max_pps = max(d["packets_per_sec"] for d in details_list)
        max_z = max(d["z_score"] for d in details_list)
        mean = details_list[0]["baseline_mean"]
        return (f"Traffic rose to {max_pps} packets/sec at its peak, against a recent average of "
                f"{mean} (peak z-score {max_z}).")
    return None  # unmerged / single-window types (e.g. arp_spoof) keep their original text


def _finalize(current):
    n = current["_count"]
    first, last = current["_first_ts"], current["_last_ts"]
    explanation = current["explanation"]
    if n > 1:
        rebuilt = _rebuild_explanation(current["type"], current["source_ip"], current["_details_list"], n)
        if rebuilt:
            explanation = rebuilt + f" (seen in {n} consecutive windows, {first} to {last}.)"
    return {
        "timestamp": first,
        "type": current["type"],
        "severity": current["severity"],
        "source_ip": current["source_ip"],
        "explanation": explanation,
        "details": {"windows_merged": n, "per_window": current["_details_list"]},
    }


def merge_alerts(alerts, window=WINDOW, gap=1):
    """Combine consecutive alerts of the same type and source into one.
    Two alerts merge if they're the same type, same source_ip, and their
    windows are adjacent (start time within `gap` windows of each other)."""
    if not alerts:
        return []

    def sort_key(a):
        return (a["type"], a["source_ip"] or "", a["timestamp"])
    ordered = sorted(alerts, key=sort_key)

    merged = []
    current = None
    for a in ordered:
        if current and a["type"] == current["type"] and a["source_ip"] == current["source_ip"] \
                and _seconds_between(current["_last_ts"], a["timestamp"]) <= window * (gap + 1):
            current = _combine(current, a)
        else:
            if current:
                merged.append(_finalize(current))
            current = _start(a)
    if current:
        merged.append(_finalize(current))

    merged.sort(key=lambda a: a["timestamp"])
    return merged


# ---------- main pipeline ----------

def detect_pcap(path):
    """Returns (stats_list, alerts_list) for a PCAP."""
    records = parse_pcap(path)
    all_stats, all_alerts, baseline = [], [], []
    arp_table = {}
    for start, recs in build_windows(records):
        stats = compute_stats(start, recs)
        all_stats.append(stats)
        all_alerts += detect_port_scan(recs, start)
        all_alerts += detect_syn_flood(recs, start)
        all_alerts += detect_arp_spoof(recs, start, arp_table)
        all_alerts += detect_dns_anomaly(recs, start)
        spike = detect_spike(stats, baseline, start)
        if spike:
            all_alerts.append(spike)
        else:  # only normal windows feed the baseline
            baseline.append(stats["packets_per_sec"])
            baseline[:] = baseline[-SPIKE_HISTORY:]
    return all_stats, merge_alerts(all_alerts)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/port_scan.pcap"
    _, alerts = detect_pcap(path)
    print(f"{len(alerts)} alert(s) in {path}\n")
    for a in alerts:
        print(f"[{a['severity'].upper():6}] {a['timestamp']}  {a['type']}")
        print(f"         {a['explanation']}")