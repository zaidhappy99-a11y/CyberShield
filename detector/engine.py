"""
NetSentinel - Core Network Detection Engine
Multi-threaded packet inspection, port scan tracking, flood detection, and alert dispatcher.
"""

import os
import sys

detector_dir = os.path.dirname(os.path.abspath(__file__))
if detector_dir not in sys.path:
    sys.path.insert(0, detector_dir)

import socket
import struct
import time
import json
import threading
import urllib.request
import urllib.error
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, Any, Optional, List

from config import (
    JAVA_BACKEND_URL,
    PORT_SCAN_WINDOW_SECONDS,
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_BURST_THRESHOLD,
    DOS_WINDOW_SECONDS,
    DOS_PACKET_THRESHOLD,
    DOS_BURST_THRESHOLD,
    BRUTE_FORCE_WINDOW,
    BRUTE_FORCE_THRESHOLD,
    SENSITIVE_PORTS,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL
)
from signatures import match_payload_signatures
from firewall_manager import global_firewall


class PacketRecord:
    def __init__(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                 protocol: str, length: int, payload: bytes, flags: str = ""):
        self.timestamp = time.time()
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.length = length
        self.payload = payload
        self.flags = flags


class IntrusionDetectionEngine:
    def __init__(self, java_backend_url: str = JAVA_BACKEND_URL):
        self.java_backend_url = java_backend_url
        self.running = False
        self.alert_counter = 0
        self.packet_counter = 0

        # State tracking sliding windows (ip -> deque of timestamps/records)
        self.ip_packet_history: Dict[str, deque] = defaultdict(deque)
        self.ip_port_history: Dict[str, deque] = defaultdict(deque)
        self.ip_auth_history: Dict[str, deque] = defaultdict(deque)

        # Alert suppression / cool-down to prevent flooding the backend with duplicate alerts (ip + type -> last_alert_time)
        self.alert_cooldown: Dict[str, float] = {}
        self.cooldown_period = 3.0  # seconds

        # Local storage buffer
        self.recent_alerts: List[Dict[str, Any]] = []
        self.lock = threading.Lock()

        # Listeners / callbacks for bridge server
        self.on_alert_callbacks = []

    def register_alert_callback(self, cb):
        self.on_alert_callbacks.append(cb)

    def _should_suppress_alert(self, key: str) -> bool:
        now = time.time()
        last_time = self.alert_cooldown.get(key, 0)
        if now - last_time < self.cooldown_period:
            return True
        self.alert_cooldown[key] = now
        return False

    def process_packet(self, pkt: PacketRecord) -> Optional[Dict[str, Any]]:
        """Core detection pipeline for every inspected packet."""
        with self.lock:
            self.packet_counter += 1
            now = pkt.timestamp
            src_ip = pkt.src_ip
            dst_port = pkt.dst_port

            # 1. Update sliding window for DoS/Flood
            pkts_queue = self.ip_packet_history[src_ip]
            pkts_queue.append(now)
            while pkts_queue and now - pkts_queue[0] > DOS_WINDOW_SECONDS:
                pkts_queue.popleft()

            # 2. Update sliding window for Port Scanning
            ports_queue = self.ip_port_history[src_ip]
            ports_queue.append((now, dst_port))
            while ports_queue and now - ports_queue[0][0] > PORT_SCAN_WINDOW_SECONDS:
                ports_queue.popleft()

            # 3. Update sliding window for Brute Force on Auth Ports
            auth_ports = {21, 22, 23, 3389}
            if dst_port in auth_ports:
                auth_queue = self.ip_auth_history[src_ip]
                auth_queue.append(now)
                while auth_queue and now - auth_queue[0] > BRUTE_FORCE_WINDOW:
                    auth_queue.popleft()

            # --- Detection Check A: DoS / DDoS Flood ---
            packet_rate = len(pkts_queue)
            if packet_rate >= DOS_PACKET_THRESHOLD:
                severity = SEVERITY_CRITICAL if packet_rate >= DOS_BURST_THRESHOLD else SEVERITY_HIGH
                key = f"{src_ip}:DOS"
                if not self._should_suppress_alert(key):
                    alert = self._create_alert(
                        src_ip=src_ip,
                        src_port=pkt.src_port,
                        dst_ip=pkt.dst_ip,
                        dst_port=dst_port,
                        protocol=pkt.protocol,
                        attack_type=f"{pkt.protocol} Flood (DoS)",
                        severity=severity,
                        description=f"High packet volume detected: {packet_rate} packets in {DOS_WINDOW_SECONDS}s window",
                        payload_preview=f"Packet size: {pkt.length} bytes, Flags: {pkt.flags}",
                        recommendation="Activate rate-limiting and quarantine attacker IP at firewall"
                    )
                    return alert

            # --- Detection Check B: Port Scan Activity ---
            distinct_ports = {p for _, p in ports_queue}
            if len(distinct_ports) >= PORT_SCAN_THRESHOLD:
                severity = SEVERITY_HIGH if len(distinct_ports) >= PORT_SCAN_BURST_THRESHOLD else SEVERITY_MEDIUM
                key = f"{src_ip}:PORTSCAN"
                if not self._should_suppress_alert(key):
                    port_list_str = ", ".join(str(p) for p in sorted(list(distinct_ports))[:10])
                    alert = self._create_alert(
                        src_ip=src_ip,
                        src_port=pkt.src_port,
                        dst_ip=pkt.dst_ip,
                        dst_port=dst_port,
                        protocol=pkt.protocol,
                        attack_type="Network Reconnaissance (Port Scan)",
                        severity=severity,
                        description=f"Host probed {len(distinct_ports)} ports within {PORT_SCAN_WINDOW_SECONDS}s: [{port_list_str}]",
                        payload_preview=f"Probed ports: {port_list_str}",
                        recommendation="Block probing IP and filter unneeded exposed network ports"
                    )
                    return alert

            # --- Detection Check C: Authentication Brute Force ---
            if dst_port in auth_ports:
                auth_queue = self.ip_auth_history[src_ip]
                if len(auth_queue) >= BRUTE_FORCE_THRESHOLD:
                    key = f"{src_ip}:BRUTEFORCE:{dst_port}"
                    if not self._should_suppress_alert(key):
                        service_name = SENSITIVE_PORTS.get(dst_port, str(dst_port))
                        alert = self._create_alert(
                            src_ip=src_ip,
                            src_port=pkt.src_port,
                            dst_ip=pkt.dst_ip,
                            dst_port=dst_port,
                            protocol=pkt.protocol,
                            attack_type=f"Brute Force Attempt ({service_name})",
                            severity=SEVERITY_HIGH,
                            description=f"Rapid connection attempts ({len(auth_queue)}) to authentication service on port {dst_port}",
                            payload_preview=f"Service: {service_name}",
                            recommendation="Enforce multi-factor authentication and fail2ban IP lockout"
                        )
                        return alert

            # --- Detection Check D: Deep Payload Signature Inspection ---
            try:
                payload_str = pkt.payload.decode('utf-8', errors='ignore')
            except Exception:
                payload_str = ""

            if payload_str:
                sig_match = match_payload_signatures(payload_str)
                if sig_match:
                    key = f"{src_ip}:SIG:{sig_match['rule_id']}"
                    if not self._should_suppress_alert(key):
                        alert = self._create_alert(
                            src_ip=src_ip,
                            src_port=pkt.src_port,
                            dst_ip=pkt.dst_ip,
                            dst_port=dst_port,
                            protocol=pkt.protocol,
                            attack_type=sig_match["attack_type"],
                            severity=sig_match["severity"],
                            description=f"Exploit pattern matched [{sig_match['rule_id']} - {sig_match['cve']}]: {sig_match['matched_text']}",
                            payload_preview=sig_match["snippet"],
                            recommendation=sig_match["recommendation"]
                        )
                        return alert

        return None

    def _create_alert(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                      protocol: str, attack_type: str, severity: str,
                      description: str, payload_preview: str, recommendation: str) -> Dict[str, Any]:
        """Construct alert record and trigger dispatch."""
        self.alert_counter += 1
        now_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_id = f"ALT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{self.alert_counter:04d}"

        action_taken = "FLAGGED"
        if severity == SEVERITY_CRITICAL:
            try:
                global_firewall.block_ip(src_ip, f"Critical Exploit Block: {attack_type}")
                action_taken = "AUTO_FIREWALL_BLOCKED"
            except Exception:
                action_taken = "AUTO_QUARANTINED"

        alert = {
            "id": alert_id,
            "timestamp": now_dt,
            "source_ip": src_ip,
            "source_port": src_port,
            "dest_ip": dst_ip,
            "dest_port": dst_port,
            "protocol": protocol,
            "attack_type": attack_type,
            "severity": severity,
            "description": description,
            "payload_preview": payload_preview[:120],
            "action_taken": action_taken,
            "recommendation": recommendation
        }

        self.recent_alerts.append(alert)
        if len(self.recent_alerts) > 500:
            self.recent_alerts.pop(0)

        # Notify registered callbacks (e.g. bridge server)
        for cb in self.on_alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

        # Dispatch alert to Java backend asynchronously
        threading.Thread(target=self._dispatch_to_java_backend, args=(alert,), daemon=True).start()

        # Print formatted security alert to console
        print(f"\n[!] ALERT [{alert['severity']}] {alert['attack_type']} from {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        print(f"    Details: {alert['description']}")

        return alert

    def _dispatch_to_java_backend(self, alert: Dict[str, Any]):
        """Send JSON alert to Java backend via HTTP POST."""
        try:
            req_data = json.dumps(alert).encode("utf-8")
            req = urllib.request.Request(
                self.java_backend_url,
                data=req_data,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status == 200 or resp.status == 201:
                    pass
        except Exception:
            # Java backend might not be running yet; alert is safely retained in memory/bridge
            pass

    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            severity_counts = {SEVERITY_LOW: 0, SEVERITY_MEDIUM: 0, SEVERITY_HIGH: 0, SEVERITY_CRITICAL: 0}
            for a in self.recent_alerts:
                s = a.get("severity", SEVERITY_LOW)
                severity_counts[s] = severity_counts.get(s, 0) + 1

            return {
                "packets_processed": self.packet_counter,
                "total_alerts": len(self.recent_alerts),
                "severity_counts": severity_counts,
                "active_tracking_ips": len(self.ip_packet_history)
            }


# Singleton engine instance
global_engine = IntrusionDetectionEngine()
