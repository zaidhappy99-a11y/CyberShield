# NetSentinel: Hybrid Network Intrusion Detection System & SOC Dashboard

> A high-performance, full-stack Cybersecurity Network Intrusion Detection System (NIDS) and Security Operations Center (SOC) monitoring platform engineered with **CSS**, **Java**, and **Python**.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)
[![Java: 11+](https://img.shields.io/badge/Java-11%2B-orange?logo=java)](https://adoptium.net)
[![UI: Modern CSS3](https://img.shields.io/badge/Frontend-CSS3%20SOC%20Theme-cyan?logo=css3)](web/css/style.css)

---

## 🛡️ Project Overview

**NetSentinel** demonstrates how modern cybersecurity defense systems combine low-level network packet analysis, high-concurrency event correlation, and intuitive visual telemetry:

1. **Python Detection Engine**: Captures and inspects network packets in real time. Features sliding-window algorithms for behavioral detection (SYN Port Scans, DoS/DDoS Floods, Authentication Brute Force) and signature regex engines for web exploits (SQL Injection, XSS, Path Traversal, Command Injection, Automated Scanner fingerprinting).
2. **Java Correlation & Analytics Backend**: A multi-threaded, zero-dependency Java server (`com.sun.net.httpserver`) that aggregates alert streams, scores global threat levels ($0-100$), coordinates automated host quarantine / active containment, generates forensic reports, and exposes REST APIs.
3. **CSS Security Operations Center (SOC) Dashboard**: A sleek, tactical dark-mode web interface styled with custom CSS animations, an interactive 360-degree radar scanner, telemetry graphs, live alert feeds, payload inspection modals, and attack simulation controls.

---

## 🏛️ System Architecture

```
+-----------------------------------------------------------------------------------+
|                           CYBERSECURITY SOC DASHBOARD                             |
|  - CSS Animated 360 Radar Scanner          - Real-Time Intrusion Alert Log        |
|  - Threat Level Meter (0-100 Index)        - Protocol Distribution Breakdown      |
|  - Top Attacker IP Leaderboard             - Active Defense / Host Quarantine     |
+-----------------------------------------+-----------------------------------------+
                                          ^
                                          | (REST API & Static Assets)
+-----------------------------------------v-----------------------------------------+
|                              JAVA BACKEND SERVER                                  |
|  - Multi-Threaded HTTP API (Port 8080)     - Incident Escalation Correlator       |
|  - Active Defense Quarantine Manager       - Forensic CSV Log Exporter            |
|  - Real-Time Network Telemetry Counters    - Zero External Dependencies           |
+-----------------------------------------+-----------------------------------------+
                                          ^
                                          | (JSON Alert Feed /api/alerts)
+-----------------------------------------v-----------------------------------------+
|                            PYTHON DETECTION ENGINE                                |
|  - Sliding-Window Port Scan Detector       - Denial of Service (DoS) Flood Tracker |
|  - SSH/FTP Brute Force Frequency Engine    - Deep Payload Signature Matching      |
|  - CWE/CVE Exploit Pattern Database        - Multi-Vector Cyber Attack Simulator   |
+-----------------------------------------------------------------------------------+
```

---

## ⚡ Key Features

- **Multi-Vector Detection Capabilities**:
  - **Reconnaissance Port Scans**: Detects vertical and horizontal port scans within sliding time windows.
  - **Denial of Service (DoS / DDoS)**: Flags anomalous surges in packet rates (SYN, UDP, ICMP floods).
  - **Credential Brute Force**: Identifies rapid successive login attempts against SSH, FTP, Telnet, or RDP.
  - **Web Application Exploits**: Regex and heuristic signatures for SQL Injection (CWE-89), Cross-Site Scripting (CWE-79), Directory Traversal (CWE-22), and Command Injection (CWE-78).
  - **Automated Security Scanners**: Flags reconnaissance tools such as `sqlmap`, `nikto`, `nmap`, and `gobuster`.
- **Active Defense & Quarantine Management**:
  - Auto-quarantines hosts executing critical exploits.
  - Security operators can block or unblock IPs with one click directly from the SOC interface.
- **On-Demand Cyber Attack Simulator**:
  - Built-in simulation console to fire simulated Port Scans, DoS Floods, SQL Injection, and XSS payloads to test detection and mitigation rules live.
- **Deep Packet Inspection Modal**:
  - Click "Inspect" on any alert to view the raw payload snippet, matched rule ID, CWE reference, and mitigation recommendation.
- **Dual-Stack Run Modes**:
  - Run the full Java backend (`NetSentinelServer.java`) with any standard JDK.
  - Or run the turnkey Python Bridge (`bridge_server.py`) immediately with zero setup required.

---

## 📂 Project Structure

```
CyberSecurity-Project/
├── backend/                              # Java Analytics, Correlation & API Server
│   ├── src/com/netsentinel/
│   │   ├── NetSentinelServer.java        # Main HTTP server & API routes
│   │   ├── ThreatCorrelator.java          # Incident correlation & auto-mitigation
│   │   ├── QuarantineManager.java         # IP blocklist & active defense
│   │   ├── SecurityAlert.java             # Alert data model & JSON serialization
│   │   ├── NetworkStats.java              # Telemetry & threat score aggregator
│   │   └── StaticFileHandler.java         # Static asset delivery & MIME resolver
│   ├── build.bat                          # Compile Java backend
│   └── run.bat                            # Launch Java server
│
├── detector/                             # Python Detection Engine & Sniffer
│   ├── engine.py                          # Core packet analyzer & sliding-window trackers
│   ├── signatures.py                      # Exploit signatures & payload regex database
│   ├── attack_simulator.py                # Multi-vector attack generator
│   ├── config.py                          # Thresholds, timeouts, sensitive ports
│   └── bridge_server.py                   # Standalone Python server & API bridge
│
├── web/                                  # SOC Frontend Dashboard
│   ├── index.html                         # Dashboard layout & structure
│   ├── css/
│   │   ├── style.css                      # Cyber theme, layout & typography
│   │   └── components.css                 # Radar scanner, KPI cards, tables & badges
│   └── js/
│       └── app.js                         # Telemetry polling, UI updates & actions
│
├── tests/
│   └── test_system.py                     # Full automated integration test suite
│
├── docs/
│   ├── ARCHITECTURE.md                    # Technical architecture & protocol spec
│   └── SETUP_GUIDE.md                     # Step-by-step installation & run guide
│
├── start_all.bat                          # One-click complete system launcher
├── start_soc_dashboard.bat                # Start SOC Dashboard server
├── start_detector.bat                     # Run detection engine & attack tests
└── README.md                              # Project documentation
```

---

## 🚀 Quick Start Guide

### 1-Click Launch (Recommended)
Double-click **`start_all.bat`** (or run `.\start_all.bat` in terminal).
This will launch the SOC server on `http://localhost:8080/` and open your default browser.

### Interactive Demonstration:
1. In the **Cyber Attack Simulation Console**, click **⚡ SYN Port Scan** or **💉 SQL Injection**.
2. Watch the live **Intrusion Detection Log** update instantly.
3. Observe the **Threat Level Score** and **Protocol Breakdown** adapt in real time.
4. Click **Inspect** to review exploit payload bytes and remediation guidelines.
5. Click **Block** to place attacker IPs into the **Active Quarantine List**.
6. Click **Export Forensic Report** to download the incident report in CSV format.

---

## 🧪 Running Automated Tests

Run the built-in test suite to verify all detection rules, frontend files, and Java components:

```cmd
run_python.bat tests\test_system.py
```

---

## Security note

The standalone bridge binds to `127.0.0.1` by default because its dashboard/API has no user authentication. Do not expose it to the public internet or an untrusted network. To bind elsewhere, set `NETSENTINEL_HOST` only inside a trusted, isolated lab and add authentication and network controls first. Firewall blocking is a Windows-only, privileged action; queued rules are not active until explicitly applied as Administrator.

## 📜 License
This project is open-source and available under the [MIT License](LICENSE).


## Automatic quarantine policy

The Python bridge automatically adds an alert source to the SOC quarantine list when its severity is **HIGH** or **CRITICAL**. LOW and MEDIUM alerts remain visible in the alert log but are not quarantined. The dashboard refreshes the quarantine list after simulations and during normal polling.

For safety, private, loopback, link-local, and reserved/documentation IP addresses are recorded as `SIMULATION_ONLY` and do not create Windows Firewall rules. Globally routable source IPs are passed to the Windows Firewall manager; immediate enforcement requires the server to run with Administrator privileges. Otherwise the rule is marked as queued for elevated synchronization. Review the source IP before applying any exported firewall script.
