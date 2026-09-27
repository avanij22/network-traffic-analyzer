"""mock_data.py — despite the name, this streams REAL analysis from the engine.
Provides the generate(scenario) interface that backend/main.py's run_replay()
expects, so no changes are needed in main.py."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parent.parent / "engine"
sys.path.insert(0, str(ENGINE_DIR))
from export import analyze_pcap  # noqa: E402

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
WINDOW_S = 5

SCENARIOS = {
    "normal": "normal.pcap",
    "port_scan": "port_scan.pcap",
    "syn_flood": "syn_flood.pcap",
    "arp_spoof": "arp_spoof.pcap",
    "dns_tunnel": "dns_tunnel.pcap",
    "mixed": "mixed.pcap",
}

TYPE_MAP = {
    "port_scan": "port_scan",
    "syn_flood": "syn_flood",
    "traffic_spike": "traffic_spike",
    "arp_spoof": "arp_spoofing",
    "dns_anomaly": "dns_anomaly",
}


def _parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _adapt_stats(s: dict) -> dict:
    start = _parse_ts(s["timestamp"])
    return {
        "window_start": start,
        "window_end": start + timedelta(seconds=s["window_seconds"]),
        "packets_per_sec": s["packets_per_sec"],
        "bytes_per_sec": s["bytes_per_sec"],
        "protocol_counts": s["protocol_counts"],
        "top_talkers": s["top_talkers"],
        "top_ports": s["top_ports"],
    }


def _adapt_alert(a: dict) -> dict:
    details = a.get("details") or {}
    first_detail = details.get("per_window", [details])[0]
    return {
        "timestamp": _parse_ts(a["timestamp"]),
        "type": TYPE_MAP.get(a["type"], a["type"]),
        "severity": a["severity"],
        "src_ip": a.get("source_ip"),
        "dst_ip": first_detail.get("target_ip"),
        "description": a["explanation"],
        "evidence": details,
    }


def generate(scenario: str):
    filename = SCENARIOS.get(scenario)
    if filename is None:
        raise ValueError(f"unknown scenario: {scenario}")
    result = analyze_pcap(str(DATA_DIR / filename))

    alerts_by_start = {}
    for a in result["alerts"]:
        alerts_by_start.setdefault(a["timestamp"], []).append(_adapt_alert(a))

    for s in result["stats"]:
        yield _adapt_stats(s), alerts_by_start.get(s["timestamp"], [])