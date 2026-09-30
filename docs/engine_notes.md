# Engine notes (Person A)

## Step 1: PCAP generator

**What I built:** a Python script, `engine/generate_pcaps.py`, that creates fake network traffic and saves it as three PCAP files in `data/`:
- `normal.pcap`
- `port_scan.pcap`
- `syn_flood.pcap`

### Why we need it
We can't test the detectors without traffic. Setting up VMs and capturing real attacks would take too long at this stage, so a Scapy script generates the traffic instead. The files are the same every time, so testing and demos are repeatable.

### What a PCAP is
A PCAP is a file that stores captured network packets. Each packet is saved with its timestamp and raw bytes (Ethernet, IP, and TCP/UDP headers, plus payload). It is a binary file, so a text editor like VS Code shows unreadable characters. To read it, open it in Wireshark or load it with Scapy.

### The three files

**normal.pcap**
Ordinary traffic from 10 client machines to one server. It contains web requests (TCP ports 80 and 443), DNS queries (UDP port 53), ICMP pings, and complete TCP handshakes (SYN, SYN-ACK, ACK). It has no attack in it, so it shows what "normal" looks like.

**port_scan.pcap**
Normal traffic plus a simulated port scan. The attacker (`192.168.1.66`) sends 1000 SYN packets to the server (`192.168.1.100`), one for each port from 1 to 1000, 5 ms apart. The scan starts 8 seconds into the capture. The pattern to detect is one source IP hitting many different ports in a very short time.

**syn_flood.pcap**
Normal traffic plus a simulated SYN flood. The attacker sends 4000 SYN packets to port 80, using random source ports, 1 ms apart, starting 8 seconds in. None of the handshakes are completed. The pattern to detect is a sudden burst of SYN packets with no matching ACKs.

### Details worth remembering
- Every packet has an explicit timestamp, so grouping into 5-second windows will work later.
- IP addresses: clients `192.168.1.10` to `.19`, server `.100`, DNS server `.1`, attacker `.66`.
- Attacks start 8 seconds in, so the first few seconds are clean. That lets us see traffic change from normal to attack.
- The files are small (a few MB), so they can be committed to the repo.

### How to run
```
pip install scapy pandas numpy
python engine/generate_pcaps.py
```

### How I checked it worked
- Opened `port_scan.pcap` in Wireshark and filtered with `ip.src == 192.168.1.66`. I saw many SYN packets, each going to a different port.
- Opened `syn_flood.pcap` and filtered with `tcp.flags.syn == 1 && tcp.flags.ack == 0`. I saw thousands of SYN packets from the same source.

### Problems and fixes
- **Problem:** VS Code showed strange characters when I opened the PCAP. **Cause:** it is a binary file. **Fix:** open it in Wireshark.
- **Problem:** pip warned that some scripts were not on PATH. **Fix:** ignored, because we don't use those command-line tools.
- **Problem:** the repo was inside OneDrive, which can interfere with Git's hidden `.git` folder. **Fix:** moved the repo to `C:\projects\`.

### Not done yet
- A separate traffic spike PCAP. For now, the SYN flood file also causes a volume spike, so the spike detector can be built against it.
- ARP spoofing and DNS anomaly traffic. These will be added with those detectors later.

### Decisions so far
- Window size is 5 seconds.
- Synthetic traffic first, real `nmap` and `hping3` captures later.
- Thresholds are not set yet. They will be tuned after the detectors are built.

## Step 2: Parser

**What I built:** `engine/parser.py`. It reads a PCAP with Scapy and returns a list of simple records, one per packet.

**Each record has:** timestamp, source IP, destination IP, source port, destination port, protocol, TCP flags, size, and source MAC (for ARP).

**Decisions:**
- UDP traffic on port 53 is labelled `DNS`, not `UDP`.
- ARP packets are kept, since ARP spoofing detection needs them later.
- Packets that are not IP or ARP are skipped.
- Records are sorted by timestamp.

**How to run:** `python engine/parser.py data/port_scan.pcap`

**How I checked it:** ran it on all three PCAPs and confirmed the protocol counts and that the attack packets show flags `S`.

## Step 3: Window stats
- `engine/windows.py` groups parsed packets into fixed 5-second windows and builds the stats JSON.
- Window timestamp = start of the window. Top 5 talkers by source IP, top 5 destination ports.
- The last window can be partial (capture ends mid-window), so its packets/sec looks low.
- Verified: normal ~50 pps; scan windows show 400 and 600 packets from 192.168.1.66; flood windows show 2000 each.

## Step 4: Detectors
- `engine/detectors.py`: port scan, SYN flood, traffic spike.
- Port scan: >= 100 distinct dst ports from one source to one target in a window.
- SYN flood: >= 300 SYNs to one ip:port in a window and <= 20% answered by SYN-ACK.
- Spike: z-score >= 3 versus the mean of recent non-spike windows (std floored at 10% of the mean).
- Each attack appears in two windows, so it produces two alerts.
- Limitation: very short baseline in the test files.

## Step 4 results
- normal.pcap: 0 alerts
- port_scan.pcap: 2 port_scan alerts (400 and 600 ports) + 2 traffic_spike, no syn_flood
- syn_flood.pcap: 2 syn_flood alerts (~2000 SYNs, 1% answered) + 2 traffic_spike, no port_scan
- Each attack straddles a window boundary, so it shows up as two alerts.

## Step 5: Export for backend
- `engine/export.py`: `analyze_pcap(path)` takes a PCAP path and returns stats and alerts in the README format.
- Sample output for all three PCAPs is saved in `data/output/`, so the web side can build against real data.
- Result: normal = 8 windows, 0 alerts; port_scan = 4 windows, 4 alerts; syn_flood = 4 windows, 4 alerts.

## Step 6: Extra test traffic (ARP spoof, DNS tunnel)
- `engine/generate_extra_pcaps.py` creates `arp_spoof.pcap` and `dns_tunnel.pcap`.
- Kept in a separate script so the existing PCAPs are not regenerated (they use random numbers and the web side is building against them).
- arp_spoof: legitimate ARP replies first, then from 8 s the attacker (de:ad:be:ef:00:66) claims 192.168.1.1, which normally belongs to aa:bb:cc:00:00:01.
- dns_tunnel: 192.168.1.30 sends 400 DNS queries in ~5 s with random ~75-character names. Normal hosts send ~5 per window with short names.

## Step 7: Parser update for DNS
- Parser now records `dns_name` (the query name) for DNS packets, `None` otherwise.
- Needed for the DNS anomaly detector (name length).
- Re-checked: normal.pcap still gives 0 alerts.

## Step 8: ARP spoof and DNS anomaly detectors
- `engine/detectors.py` now has five detectors (port scan, SYN flood, traffic spike, ARP spoof, DNS anomaly).
- ARP spoof: keeps a table of ip -> first MAC seen (across windows). An ARP packet claiming the same IP with a different MAC raises a high-severity alert.
- DNS anomaly: per host per window, alert if >= 100 queries or >= 50 queries with names longer than 50 characters.
- Thresholds: DNS_MIN_QUERIES=100, DNS_LONG_NAME=50, DNS_MIN_LONG_QUERIES=50.

### Results
| File | Result |
|---|---|
| normal.pcap | 0 alerts |
| port_scan.pcap | 2 port_scan + 2 traffic_spike |
| syn_flood.pcap | 2 syn_flood + 2 traffic_spike |
| arp_spoof.pcap | 1 arp_spoof (192.168.1.1: aa:bb:cc:00:00:01 -> de:ad:be:ef:00:66) |
| dns_tunnel.pcap | 2 dns_anomaly (160 + 240 = 400 queries, avg name length 70) + 2 traffic_spike |

### Limitations
- The ARP detector trusts the first MAC it sees. If the attacker's reply came first, it would be trusted instead.
- Normal hosts send ~5 DNS queries per window with short names, so the thresholds are far from normal traffic. Real networks would need tuning.

## Step 9: Alert merging
- `merge_alerts()` in detectors.py combines consecutive alerts of the same type and source_ip (from adjacent windows) into one.
- `_rebuild_explanation()` recomputes the explanation text from the combined totals across all merged windows (e.g. port_scan sums distinct ports, syn_flood sums SYN count, dns_anomaly sums queries, traffic_spike shows the peak pps/z-score), so the text always matches the real scale of the attack.
- Full per-window detail is kept in details.per_window for anyone who wants the breakdown.
- Result after merging: port_scan 4->2 alerts, syn_flood 4->2, dns_tunnel 4->2, arp_spoof unchanged (1).

### Results (final)
| File | Alerts |
|---|---|
| normal.pcap | 0 |
| port_scan.pcap | 1 port_scan (1000 ports, 10s) + 1 traffic_spike |
| syn_flood.pcap | 1 syn_flood (4039 SYNs, 10s) + 1 traffic_spike |
| arp_spoof.pcap | 1 arp_spoof |
| dns_tunnel.pcap | 1 dns_anomaly (400 queries, 10s) + 1 traffic_spike |

## Step 10: UDP flood detector
- New file: engine/generate_udp_flood.py creates udp_flood.pcap (3000 UDP packets to port 9999 from 192.168.1.66).
- detect_udp_flood() in detectors.py: >=300 UDP packets (excluding DNS, port 53) to one ip:port in a window.
- Unlike SYN flood, there's no handshake-completion check, since UDP has no handshake. Detection is purely volume-based.
- Result: udp_flood.pcap -> 1 udp_flood alert (2001 packets) + 1 traffic_spike. normal.pcap unaffected (0 alerts). syn_flood.pcap unaffected (no cross-triggering).