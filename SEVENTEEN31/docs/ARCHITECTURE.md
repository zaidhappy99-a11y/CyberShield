# NetSentinel Architecture & Design Specification

NetSentinel is a hybrid, production-grade **Network Intrusion Detection System (NIDS)** and **Security Operations Center (SOC) Analytics Dashboard** built utilizing **Python**, **Java**, and modern **CSS**.

---

## 1. System Architecture Overview

```
                      +------------------------------------------+
                      |           ATTACK SIMULATOR               |
                      |   (Port Scan, DoS, SQLi, XSS, Brute)     |
                      +---------------------+--------------------+
                                            |
                                            v (Raw Packets / TCP / HTTP)
                      +------------------------------------------+
                      |         PYTHON DETECTION ENGINE          |
                      | - Sliding-Window Connection Tracking     |
                      | - Signature Engine (Regex / CWE / CVE)   |
                      | - Behavioral Anomaly Detectors           |
                      | - Alert Dispatcher (JSON)                |
                      +---------------------+--------------------+
                                            |
                                            | HTTP POST /api/alerts (JSON)
                                            v
                      +------------------------------------------+
                      |            JAVA BACKEND SERVER           |
                      | - Multi-Threaded HTTP API Server         |
                      | - ThreatCorrelator (Incident Escalation) |
                      | - QuarantineManager (Active Defense)     |
                      | - NetworkStats (Aggregator & Metrics)    |
                      | - StaticFileHandler (Asset Delivery)     |
                      +---------------------+--------------------+
                                            |
                                            | REST API & Static Files
                                            v
                      +------------------------------------------+
                      |          CSS / JS SOC DASHBOARD          |
                      | - 360-Degree Animated Radar Scanner      |
                      | - Real-Time Alert Stream & Inspection    |
                      | - Threat Gauge & Protocol Distribution   |
                      | - One-Click IP Quarantine & Simulation   |
                      +------------------------------------------+
```

---

## 2. Technology Stack & Role Breakdown

| Component | Technology | Primary Responsibilities |
|---|---|---|
| **Detection Engine** | **Python 3** | Packet capture/sniffing, sliding-window traffic analysis, signature pattern matching (SQLi, XSS, LFI, RCE), DoS/Port-scan heuristics, alert generation. |
| **Analytics Backend** | **Java (JDK 11+)** | High-concurrency event ingestion, alert correlation, threat score calculation ($0-100$), automated IP quarantine / containment, CSV forensic report generation, REST API. |
| **Frontend UI/UX** | **CSS3 & HTML5** | Cyber/SOC visual theme, CSS Grid & Flexbox layout, 360-degree radar animation (`@keyframes`), glassmorphism, glowing severity badges, responsive telemetry bars. |
| **Client Logic** | **Vanilla JS** | Real-time telemetry polling, interactive attack triggers, dynamic DOM table updates, deep packet inspection modal, forensic export download. |

---

## 3. Python Detection Engine Architecture

### A. Behavioral Sliding-Window Analyzers
- **Port Scan Detector (`PORT_SCAN_WINDOW_SECONDS = 3.0s`)**:
  Tracks timestamps and destination ports targeted by each source IP. If distinct ports $\ge 4$, an intrusion alert is fired (`Network Reconnaissance (Port Scan)`).
- **Denial of Service (DoS) Detector (`DOS_WINDOW_SECONDS = 2.0s`)**:
  Maintains a deque of packet timestamps per source IP. If rate exceeds 25 packets/sec, a `TCP/UDP Flood (DoS)` alert is triggered; bursts $\ge 60$ escalate to `CRITICAL`.
- **Brute Force Detector (`BRUTE_FORCE_WINDOW = 10.0s`)**:
  Monitors connection frequency to sensitive authentication ports (21 FTP, 22 SSH, 23 Telnet, 3389 RDP). Alerts when rapid successive login attempts occur.

### B. Deep Payload Signature Matching
Regular expressions in `signatures.py` inspect packet contents for exploits:
- **SQL Injection**: Tautologies (`' OR '1'='1'`), `UNION SELECT`, time delays (`SLEEP(5)`).
- **Cross-Site Scripting (XSS)**: `<script>`, `onerror=alert()`, `document.cookie`.
- **Path Traversal / LFI**: `../../../../windows/win.ini`, `/etc/passwd`.
- **Remote Code Execution**: `cmd.exe /c`, `powershell -enc`, `; cat /etc/shadow`.
- **Automated Scanner Fingerprints**: `sqlmap`, `nikto`, `nmap`, `gobuster`.

---

## 4. Java Backend Architecture

The Java backend (`com.netsentinel`) is built with zero third-party dependencies, leveraging Java SE's high-performance standard library (`com.sun.net.httpserver`):

1. **`NetSentinelServer.java`**:
   Initializes an asynchronous thread pool of 16 worker threads, registers REST handlers, and dispatches HTTP traffic.
2. **`ThreatCorrelator.java`**:
   Maintains a thread-safe circular buffer of alerts. When alerts with severity `CRITICAL` arrive, it signals the `QuarantineManager` to execute automated host isolation (`AUTO_QUARANTINED`).
3. **`QuarantineManager.java`**:
   Active defense registry. Stores quarantined IPs, timestamp, and incident reason. Allows security operators to inspect and unblock quarantined hosts.
4. **`NetworkStats.java`**:
   Aggregates live metrics (packet counters, protocol breakdown, top 5 attacker IPs, top 5 target ports) using `AtomicLong` counters.
5. **`StaticFileHandler.java`**:
   Streams dashboard assets (`index.html`, `style.css`, `components.css`, `app.js`) with MIME type inference and protection against path traversal.

---

## 5. CSS & Dashboard Design System

The SOC interface is built around a modern cyber-defense aesthetic:
- **Palette**: Obsidian background (`#070a12`, `#0d1322`), Glassmorphism cards (`backdrop-filter: blur(12px)`), Electric Cyan (`#00f0ff`), Danger Crimson (`#ff3366`), Amber (`#ffb703`), Emerald (`#00f59b`).
- **Animated Radar Component**:
  Built with concentric SVG rings, crosshairs, and a sweeping radial gradient driven by CSS keyframe animation:
  ```css
  @keyframes radar-sweep-rotate {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }
  ```
- **Pulsing Blips & Threat Badges**: Blinking red and amber blips visualize active hostile probes across the network space.
- **Responsive Layout**: CSS Grid adapts smoothly from wide monitors (multi-column SOC layout) to single-column laptops.

---

## 6. REST API Endpoint Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the interactive SOC Web Dashboard |
| `GET` | `/api/alerts?limit=50&severity=ALL` | Retrieves recent security alerts with query filters |
| `POST` | `/api/alerts` | Ingests a new intrusion alert from Python sniffer |
| `DELETE` | `/api/alerts` | Clears alert feed history |
| `GET` | `/api/stats` | Retrieves real-time telemetry (threat score, top IPs, protocols) |
| `GET` | `/api/quarantine` | Lists currently blocked/quarantined IP addresses |
| `POST` | `/api/quarantine` | Manually quarantines an IP `{"ip":"x.x.x.x","reason":"..."}` |
| `DELETE` | `/api/quarantine` | Unblocks an IP address |
| `POST` | `/api/simulate` | Triggers a simulated attack vector `{"type":"portscan\|dos\|sqli\|xss"}` |
| `GET` | `/api/export` | Downloads forensic incident log as CSV |
