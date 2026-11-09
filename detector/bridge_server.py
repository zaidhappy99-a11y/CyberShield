"""
NetSentinel - Python Bridge & Standalone SOC Server
Provides REST API & Web Dashboard hosting, allowing the complete system
to operate standalone or as a bridge to the Java correlation backend.
"""

import os
import sys

# Add detector directory to python path
detector_dir = os.path.dirname(os.path.abspath(__file__))
if detector_dir not in sys.path:
    sys.path.insert(0, detector_dir)

import json
import ipaddress
import time
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Dict, Any
import threading

from config import SENSITIVE_PORTS
from engine import global_engine, PacketRecord
from attack_simulator import global_simulator
from firewall_manager import global_firewall


WEB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "web"))

# In-memory quarantine list for standalone mode
QUARANTINE_LOCK = threading.RLock()

QUARANTINE_LIST: Dict[str, Dict[str, str]] = {
    "198.51.100.14": {
        "ip": "198.51.100.14",
        "reason": "Preemptive Blacklist: Known Mirai Botnet Node",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "severity": "HIGH"
    }
}


def _auto_quarantine_high_severity(alert: Dict[str, Any]):
    """Quarantine HIGH/CRITICAL sources; never firewall-block private or reserved demo IPs."""
    severity = str(alert.get("severity", "")).upper()
    if severity not in {"HIGH", "CRITICAL"}:
        return

    raw_ip = alert.get("source_ip")
    try:
        source_ip = str(ipaddress.ip_address(str(raw_ip).strip()))
    except ValueError:
        return

    reason = f"Automatic {severity} quarantine: {alert.get('attack_type', 'Security alert')}"[:200]
    firewall_record = None
    # Simulation/private/reserved addresses are tracked in the SOC UI only.
    # Actual Windows firewall enforcement is reserved for globally routable source IPs.
    if ipaddress.ip_address(source_ip).is_global:
        firewall_record = global_firewall.block_ip(source_ip, reason)

    with QUARANTINE_LOCK:
        existing = QUARANTINE_LIST.get(source_ip, {})
        QUARANTINE_LIST[source_ip] = {
            "ip": source_ip,
            "reason": reason,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "severity": severity,
            "firewall_rule": (firewall_record or {}).get("rule_name", existing.get("firewall_rule", "")),
            "firewall_status": (firewall_record or {}).get("status", "SIMULATION_ONLY"),
            "automatic": "true"
        }

    alert["action_taken"] = "AUTO_QUARANTINED"
    if firewall_record and firewall_record.get("enforced"):
        alert["action_taken"] = "AUTO_FIREWALL_BLOCKED"


# Register once so both live detector alerts and attack simulations share the same policy.
global_engine.register_alert_callback(_auto_quarantine_high_severity)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class NetSentinelHTTPHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code: int, data: Any):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, rel_path: str, mime_type: str):
        clean_path = rel_path.lstrip("/").replace("/", os.sep)
        full_path = os.path.abspath(os.path.join(WEB_DIR, clean_path))

        # Path traversal guard (commonpath avoids sibling-prefix bypasses)
        if os.path.commonpath([WEB_DIR, full_path]) != WEB_DIR or not os.path.isfile(full_path):
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"404 Not Found")
            return

        try:
            with open(full_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"500 Internal Error: {e}".encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Static Dashboard Files
        if path in ("", "/", "/index.html"):
            self._serve_file("index.html", "text/html; charset=utf-8")
            return
        elif path.startswith("/css/"):
            self._serve_file(path, "text/css; charset=utf-8")
            return
        elif path.startswith("/js/"):
            self._serve_file(path, "application/javascript; charset=utf-8")
            return

        # REST API: Alerts
        if path == "/api/alerts":
            try:
                limit = max(1, min(500, int(query.get("limit", [50])[0])))
            except (TypeError, ValueError):
                self._send_json(400, {"error": "Invalid limit"})
                return
            sev_filter = query.get("severity", ["ALL"])[0].upper()

            alerts = list(reversed(global_engine.recent_alerts))
            if sev_filter != "ALL":
                alerts = [a for a in alerts if a.get("severity", "").upper() == sev_filter]

            self._send_json(200, alerts[:limit])
            return

        # REST API: Stats
        elif path == "/api/stats":
            stats = global_engine.get_stats()
            attacker_counts = {}
            port_counts = {}
            proto_counts = {"TCP": 0, "UDP": 0, "HTTP": 0, "DNS": 0, "SSH": 0, "ICMP": 0}

            for a in global_engine.recent_alerts:
                src = a.get("source_ip", "")
                if src:
                    attacker_counts[src] = attacker_counts.get(src, 0) + 1
                dst_port = a.get("dest_port", 0)
                if dst_port:
                    port_counts[str(dst_port)] = port_counts.get(str(dst_port), 0) + 1
                proto = a.get("protocol", "TCP").upper()
                proto_counts[proto] = proto_counts.get(proto, 0) + 1

            top_attackers = dict(sorted(attacker_counts.items(), key=lambda x: x[1], reverse=True)[:5])
            top_ports = dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5])

            sev_counts = stats["severity_counts"]
            weighted = (sev_counts.get("CRITICAL", 0) * 30 +
                        sev_counts.get("HIGH", 0) * 15 +
                        sev_counts.get("MEDIUM", 0) * 5 +
                        sev_counts.get("LOW", 0) * 1)
            threat_score = min(100, max(5, weighted))
            threat_level = "CRITICAL" if threat_score >= 75 else "HIGH" if threat_score >= 50 else "ELEVATED" if threat_score >= 25 else "NORMAL"

            response_data = {
                "total_alerts": stats["total_alerts"],
                "packets_inspected": stats["packets_processed"],
                "threat_score": threat_score,
                "threat_level": threat_level,
                "quarantined_ips": len(QUARANTINE_LIST),
                "severities": sev_counts,
                "top_attackers": top_attackers,
                "top_ports": top_ports,
                "protocols": proto_counts
            }
            self._send_json(200, response_data)
            return

        # REST API: Quarantine
        elif path == "/api/quarantine":
            with QUARANTINE_LOCK:
                items = list(QUARANTINE_LIST.values())
            self._send_json(200, items)
            return

        # REST API: Windows Firewall Status & Script Download
        elif path == "/api/firewall/status":
            self._send_json(200, global_firewall.get_status())
            return

        elif path == "/api/firewall/download":
            bat_path = global_firewall.get_status()["script_bat_path"]
            if os.path.exists(bat_path):
                with open(bat_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", 'attachment; filename="apply_firewall_rules.bat"')
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            else:
                self._send_json(404, {"error": "Firewall script not generated yet"})
                return

        # REST API: Export
        elif path == "/api/export":
            csv_lines = ["Alert_ID,Timestamp,Source_IP,Source_Port,Dest_IP,Dest_Port,Protocol,Attack_Type,Severity,Action_Taken,Recommendation"]
            for a in reversed(global_engine.recent_alerts):
                rec = a.get("recommendation", "").replace('"', '""')
                csv_lines.append(f'"{a.get("id")}","{a.get("timestamp")}","{a.get("source_ip")}",{a.get("source_port")},"{a.get("dest_ip")}",{a.get("dest_port")},"{a.get("protocol")}","{a.get("attack_type")}","{a.get("severity")}","{a.get("action_taken")}","{rec}"')
            csv_content = "\n".join(csv_lines).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=UTF-8")
            self.send_header("Content-Disposition", 'attachment; filename="netsentinel_report.csv"')
            self.send_header("Content-Length", str(len(csv_content)))
            self.end_headers()
            self.wfile.write(csv_content)
            return

        self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            content_len = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            self._send_json(400, {"error": "Invalid Content-Length"})
            return
        if content_len < 0 or content_len > 1024 * 1024:
            self._send_json(413, {"error": "Request body too large"})
            return
        body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else ""

        if path == "/api/alerts":
            try:
                alert_data = json.loads(body)
                if not isinstance(alert_data, dict):
                    self._send_json(400, {"error": "Alert must be a JSON object"})
                    return
                global_engine.recent_alerts.append(alert_data)
                del global_engine.recent_alerts[:-1000]
                self._send_json(201, {"status": "success", "id": alert_data.get("id")})
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        elif path == "/api/quarantine":
            try:
                data = json.loads(body)
                ip = data.get("ip")
                if ip:
                    try:
                        ip = str(ipaddress.ip_address(str(ip).strip()))
                    except ValueError:
                        self._send_json(400, {"error": "Invalid IP address"})
                        return
                    reason = str(data.get("reason", "Manual SOC Block"))[:200]
                    severity = str(data.get("severity", "HIGH")).upper()
                    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                        severity = "HIGH"
                    # Only send globally routable addresses to the OS firewall.
                    # Private, loopback, link-local and documentation IPs are kept
                    # in the SOC quarantine list as simulation/lab entries.
                    address = ipaddress.ip_address(ip)
                    fw_record = None
                    if address.is_global:
                        fw_record = global_firewall.block_ip(ip, reason)

                    with QUARANTINE_LOCK:
                        QUARANTINE_LIST[ip] = {
                            "ip": ip,
                            "reason": reason,
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "severity": severity,
                            "firewall_rule": (fw_record or {}).get("rule_name", ""),
                            "firewall_status": (fw_record or {}).get("status", "SIMULATION_ONLY")
                        }
                    self._send_json(200, {
                        "status": "blocked",
                        "ip": ip,
                        "firewall": fw_record or {
                            "rule_name": "",
                            "status": "SIMULATION_ONLY",
                            "enforced": False
                        }
                    })
                else:
                    self._send_json(400, {"error": "Missing IP"})
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        elif path == "/api/simulate":
            try:
                data = json.loads(body) if body else {}
                sim_type = data.get("type", "portscan").lower()

                if sim_type == "portscan":
                    global_simulator.simulate_port_scan()
                elif sim_type == "dos":
                    global_simulator.simulate_dos_flood()
                elif sim_type == "sqli":
                    global_simulator.simulate_sqli_attack()
                elif sim_type == "xss":
                    global_simulator.simulate_xss_attack()
                elif sim_type == "traversal":
                    global_simulator.simulate_path_traversal()
                elif sim_type == "scanner":
                    global_simulator.simulate_scanner_recon()
                elif sim_type == "bruteforce":
                    global_simulator.simulate_brute_force()
                else:
                    global_simulator.simulate_port_scan()

                self._send_json(200, {"status": "simulation_triggered", "type": sim_type})
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        self._send_json(404, {"error": "Not Found"})

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/alerts":
            global_engine.recent_alerts.clear()
            self._send_json(200, {"status": "cleared"})
            return

        elif path == "/api/quarantine":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else ""
            ip = None
            if body:
                try:
                    data = json.loads(body)
                    ip = data.get("ip")
                except Exception:
                    pass
            if not ip:
                query = urllib.parse.parse_qs(parsed.query)
                ip = query.get("ip", [None])[0]

            with QUARANTINE_LOCK:
                existed = bool(ip and ip in QUARANTINE_LIST)
                if existed:
                    del QUARANTINE_LIST[ip]
            if existed:
                if ipaddress.ip_address(ip).is_global:
                    global_firewall.unblock_ip(ip)
                self._send_json(200, {"status": "unblocked", "ip": ip, "firewall_rule_removed": True})
            else:
                self._send_json(404, {"error": "IP not found in quarantine"})
            return

        self._send_json(404, {"error": "Not Found"})

    def log_message(self, format, *args):
        # Quiet down standard HTTP logs to avoid cluttering console
        pass


def run_bridge_server(port: int = 8080):
    # Disable Java forwarding when running as standalone bridge to avoid self-connection loops
    global_engine.java_backend_url = ""

    # Local-only by default: this dashboard has no authentication layer.
    # Set NETSENTINEL_HOST explicitly only in a trusted, isolated lab.
    host = os.environ.get("NETSENTINEL_HOST", "127.0.0.1")
    server_address = (host, port)
    httpd = ThreadedHTTPServer(server_address, NetSentinelHTTPHandler)

    print("=" * 70)
    print(f"  [NetSentinel SOC Server & Detector Bridge] ACTIVE at {host}:{port}")
    print(f"  -> Open in your browser: http://localhost:{port}/")
    print(f"  -> Serving Web Directory: {WEB_DIR}")
    print("=" * 70)

    # Pre-populate initial attack telemetry so dashboard is immediately rich
    try:
        global_simulator.simulate_port_scan(attacker_ip="198.51.100.14")
        global_simulator.simulate_sqli_attack(attacker_ip="198.51.100.156")
        global_simulator.simulate_xss_attack(attacker_ip="203.0.113.88")
    except Exception:
        pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping NetSentinel Bridge Server...")
        httpd.server_close()


if __name__ == "__main__":
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_bridge_server(port)
