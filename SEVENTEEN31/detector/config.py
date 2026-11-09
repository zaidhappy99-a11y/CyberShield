"""
NetSentinel - Network Intrusion Detection System
Configuration Settings & Thresholds
"""

import os

# Server Configuration
JAVA_BACKEND_URL = os.environ.get("NETSENTINEL_JAVA_URL", "http://localhost:8080/api/alerts")
DETECTOR_HOST = "127.0.0.1"
DETECTOR_PORT = 5050
SNIFFER_INTERFACE = "0.0.0.0"

# Time Windows & Thresholds for Anomaly / Behavioral Detection
PORT_SCAN_WINDOW_SECONDS = 3.0       # Time window to track port scan attempts
PORT_SCAN_THRESHOLD = 4              # Distinct ports targeted by same IP within window -> Port Scan Alert
PORT_SCAN_BURST_THRESHOLD = 8        # Fast scan threshold -> High severity

DOS_WINDOW_SECONDS = 2.0             # Time window for flood tracking
DOS_PACKET_THRESHOLD = 25            # Packets per second from single IP -> SYN/UDP/ICMP Flood Alert
DOS_BURST_THRESHOLD = 60             # Severe DDoS alert

BRUTE_FORCE_WINDOW = 10.0            # Time window for auth attempts
BRUTE_FORCE_THRESHOLD = 5            # Repeated attempts to same auth port -> Brute Force Alert

# Monitored Sensitive Ports
SENSITIVE_PORTS = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted CLI)",
    25: "SMTP (Mail)",
    53: "DNS (Domain Name Service)",
    80: "HTTP (Web Server)",
    110: "POP3 (Mail)",
    135: "MSRPC (RPC Endpoint)",
    139: "NetBIOS (Windows File Sharing)",
    443: "HTTPS (Encrypted Web)",
    445: "SMB (Server Message Block)",
    1433: "MSSQL (Microsoft SQL)",
    3306: "MySQL (Database)",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL (Database)",
    8080: "HTTP-Alt (Web Proxy/App)",
    8443: "HTTPS-Alt (Web App)"
}

# Alert Severities
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"
