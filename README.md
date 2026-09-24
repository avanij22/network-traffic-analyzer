# Network Traffic Analyzer

A web-based system that analyzes network packets (protocols, IPs, ports, traffic volume), detects anomalous behavior with explainable rules and statistics, and shows traffic and alerts on a live dashboard.

Course project: Computer Networks and Web Technology.

## Architecture

```
PCAP file -> Parser (Scapy) -> Window stats -> Detectors -> Backend (FastAPI + PostgreSQL) -> Dashboard (Chart.js)
```

## Folders

| Folder | Contents | Owner |
|---|---|---|
| engine/ | Parser, window stats, detectors, PCAP generator | Person A |
| backend/ | FastAPI, WebSocket, database, schema.sql, mock data | Person B |
| frontend/ | Dashboard (HTML/CSS/JS, Chart.js) | Person B |
| data/ | Small sample PCAPs only (large ones go on Google Drive) | Both |
| docs/ | Diagrams, report, slides, evaluation table | Both |

## Data contract (DRAFT, to be agreed by both)

The engine produces these two JSON objects. The backend and dashboard consume them. Neither side changes the format without telling the other.

### Stats (one per 5-second window)

```json
{
  "timestamp": "2026-09-24T10:15:05Z",
  "window_seconds": 5,
  "packets_per_sec": 120.4,
  "bytes_per_sec": 98213.0,
  "protocol_counts": {"TCP": 540, "UDP": 50, "ICMP": 12, "DNS": 30, "ARP": 5},
  "top_talkers": [
    {"ip": "192.168.1.20", "packets": 300, "bytes": 250000},
    {"ip": "192.168.1.5", "packets": 120, "bytes": 90000}
  ],
  "top_ports": [
    {"port": 80, "packets": 210},
    {"port": 443, "packets": 180}
  ]
}
```

### Alert

```json
{
  "timestamp": "2026-09-24T10:15:05Z",
  "type": "port_scan",
  "severity": "high",
  "source_ip": "192.168.1.20",
  "explanation": "192.168.1.20 sent SYN packets to 350 distinct ports in 10 seconds (possible port scan).",
  "details": {"distinct_ports": 350, "window_seconds": 10}
}
```

- `type`: `port_scan`, `syn_flood`, `traffic_spike` (later: `arp_spoof`, `dns_anomaly`)
- `severity`: `low`, `medium`, `high`

## Endpoints (DRAFT)

| Method | Path | Purpose |
|---|---|---|
| GET | /stats | Recent stats windows (optional `?from=&to=`) |
| GET | /alerts | Recent alerts (optional `?type=&ip=`) |
| POST | /replay | Start replaying a PCAP, body: `{"file": "port_scan.pcap"}` |
| WS | /ws | Live push of new stats and alerts |

## Setup

TBD (added once the code exists).

## Team

- Person A: engine (parser, detectors, threshold tuning)
- Person B: web (backend, database, dashboard) and lab# network-traffic-analyzer