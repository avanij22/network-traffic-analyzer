import json
import os
from detectors import detect_pcap

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
OUT_DIR = os.path.join(DATA_DIR, "output")


def analyze_pcap(path):
    """Main entry point for the backend: PCAP path in, stats and alerts out."""
    stats, alerts = detect_pcap(path)
    return {"file": os.path.basename(path), "stats": stats, "alerts": alerts}


if __name__ == "__main__":
    os.makedirs(OUT_DIR, exist_ok=True)
    for name in ["normal", "port_scan", "syn_flood"]:
        result = analyze_pcap(os.path.join(DATA_DIR, f"{name}.pcap"))
        out = os.path.join(OUT_DIR, f"{name}.json")
        with open(out, "w") as f:
            json.dump(result, f, indent=2)
        print(f"{name}: {len(result['stats'])} windows, {len(result['alerts'])} alerts -> {out}")