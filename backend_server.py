import hashlib
import hmac
import json
import os
import secrets
import time
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from flask import Flask, jsonify, redirect, request, send_from_directory, session

try:
    from flask_cors import CORS
except ImportError:  # pragma: no cover
    def CORS(app, **kwargs):
        return None

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
WEB_DIR = os.path.join(BASE_DIR, "web")
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
# Java detector backend. Empty string = disabled (demo data). On Render the
# demo data is used unless NETSENTINEL_JAVA_URL points at a real Java server.
# IMPORTANT: never point this at the same port this Flask app serves on —
# that creates a recursive proxy loop (every /api/* call re-enters itself).
JAVA_BACKEND_URL = os.environ.get("NETSENTINEL_JAVA_URL", "").rstrip("/")
if JAVA_BACKEND_URL:
    try:
        _java_port = urllib_parse.urlparse(JAVA_BACKEND_URL).port
        _self_port = int(os.environ.get("PORT", "8080"))
        if _java_port == _self_port and urllib_parse.urlparse(JAVA_BACKEND_URL).hostname in ("localhost", "127.0.0.1", "0.0.0.0"):
            print("[backend_server] NETSENTINEL_JAVA_URL points at this server — disabling Java proxy")
            JAVA_BACKEND_URL = ""
    except ValueError:
        pass

# NOTE: static_folder is None on purpose. Flask's automatic static route
# would otherwise swallow the /app/ + /web/ NetSentinel mounts (404/redirects).
# Every static file is served explicitly by serve_frontend /
# serve_netsentinel_app via send_from_directory below.
app = Flask(__name__, static_folder=None)
# Set SECRET_KEY on Render (Environment → SECRET_KEY) for stable logins.
app.secret_key = os.environ.get("SECRET_KEY", "cybershield-dev-secret-key-change-me")
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    # Secure is set per-request based on the actual scheme (see before_request).
    # Setting it globally breaks http://localhost and drops sessions there.
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=12 * 60 * 60,
)

@app.before_request
def _set_cookie_secure_per_request():
    # Render (and any reverse proxy) terminates HTTPS upstream; honor the forwarded proto.
    proto = request.headers.get("X-Forwarded-Proto", "").lower()
    app.config["SESSION_COOKIE_SECURE"] = request.is_secure or proto == "https"
CORS(app, resources={r"/api/*": {"origins": "*"}})

DEMO_ALERTS = [
    {
        "id": "ALT-001",
        "timestamp": "2024-01-15 10:23:45",
        "source_ip": "192.168.1.105",
        "source_port": 54321,
        "dest_ip": "10.0.0.1",
        "dest_port": 3389,
        "protocol": "TCP",
        "attack_type": "Brute Force",
        "severity": "CRITICAL",
        "description": "Repeated SSH login attempts from unknown source",
        "payload_preview": "",
        "action_taken": "AUTO_QUARANTINED",
        "recommendation": "Block source IP and review SSH config",
    },
    {
        "id": "ALT-002",
        "timestamp": "2024-01-15 10:18:12",
        "source_ip": "10.0.0.55",
        "source_port": 49152,
        "dest_ip": "192.168.1.50",
        "dest_port": 80,
        "protocol": "HTTP",
        "attack_type": "SQL Injection",
        "severity": "HIGH",
        "description": "SQL injection attempt on login form",
        "payload_preview": "' OR 1=1 --",
        "action_taken": "FLAGGED",
        "recommendation": "Implement parameterized queries",
    },
    {
        "id": "ALT-003",
        "timestamp": "2024-01-15 10:12:33",
        "source_ip": "172.16.0.22",
        "source_port": 55211,
        "dest_ip": "192.168.1.10",
        "dest_port": 22,
        "protocol": "TCP",
        "attack_type": "Port Scan",
        "severity": "MEDIUM",
        "description": "Port scan detected across 50+ ports",
        "payload_preview": "",
        "action_taken": "FLAGGED",
        "recommendation": "Enable firewall rate limiting",
    },
    {
        "id": "ALT-004",
        "timestamp": "2024-01-15 09:45:10",
        "source_ip": "45.234.12.8",
        "source_port": 44388,
        "dest_ip": "192.168.1.100",
        "dest_port": 443,
        "protocol": "HTTPS",
        "attack_type": "XSS",
        "severity": "HIGH",
        "description": "Cross-site scripting in comment field",
        "payload_preview": "<script>alert('xss')</script>",
        "action_taken": "FLAGGED",
        "recommendation": "Sanitize all user inputs",
    },
]

DEMO_STATS = {
    "total_alerts": 4,
    "packets_inspected": 45230,
    "threat_score": 78,
    "threat_level": "HIGH",
    "quarantined_ips": 5,
    "severities": {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 1},
    "top_attackers": {"192.168.1.105": 12, "10.0.0.55": 8, "172.16.0.22": 5},
    "top_ports": {"22": 15, "80": 12, "443": 8, "3389": 6, "8080": 4},
    "protocols": {"TCP": 89, "UDP": 23, "HTTP": 12, "DNS": 6, "SSH": 4, "ICMP": 2},
}

DEMO_QUARANTINE = [
    {
        "ip": "198.51.100.14",
        "reason": "Preemptive Blacklist: Known Mirai Botnet Node",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "severity": "HIGH",
    }
]


def _request_json_from_java(path, method="GET", payload=None):
    if not JAVA_BACKEND_URL:  # Java detector disabled — serve demo data instantly
        return None
    url = f"{JAVA_BACKEND_URL}{path}"
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib_request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib_request.urlopen(req, timeout=5) as response:
            response_body = response.read().decode("utf-8")
            if not response_body:
                return None
            try:
                return json.loads(response_body)
            except json.JSONDecodeError:
                return {"raw": response_body}
    except (urllib_error.URLError, TimeoutError, ValueError):
        return None


def _demo_alerts(limit=50, severity="ALL"):
    alerts = list(DEMO_ALERTS)
    if severity and severity.upper() != "ALL":
        alerts = [alert for alert in alerts if alert.get("severity", "").upper() == severity.upper()]
    return alerts[:limit]


def _build_error(message, status_code=400):
    return jsonify({"error": message}), status_code


# ===== Auth: salted-hashed password store (stdlib only) =====
def _load_users():
    try:
        with open(USERS_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_users(users):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(USERS_FILE, "w", encoding="utf-8") as fh:
        json.dump(users, fh, indent=2)


def _hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000).hex()
    return f"{salt}${digest}"


def _verify_password(password, stored):
    try:
        salt, digest = stored.split("$", 1)
    except (AttributeError, ValueError):
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000).hex()
    return hmac.compare_digest(candidate, digest)


def _current_user():
    email = session.get("user")
    if not email:
        return None
    return _load_users().get(email)


def _require_login():
    """Server-side gate: anonymous visitors go to /login.html."""
    if _current_user() is None:
        return redirect("/login.html")
    return None


@app.after_request
def _add_cache_headers(response):
    # HTML should stay fresh; assets can be cached briefly (1h, no far-future surprises).
    path = request.path or ""
    if path.endswith((".css", ".js", ".svg", ".png", ".jpg", ".jpeg", ".webp", ".ttf", ".woff", ".woff2")):
        # Always revalidate: a stale cached app.js once broke the dashboard
        # for a whole deploy cycle. no-cache means "check with server" (fresh or 304).
        response.headers.setdefault("Cache-Control", "no-cache, must-revalidate")
    elif path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.route("/api/stats", methods=["GET", "OPTIONS"])
def api_stats():
    if request.method == "OPTIONS":
        return "", 204
    java_payload = _request_json_from_java("/api/stats")
    if java_payload is not None:
        return jsonify(java_payload)
    return jsonify(DEMO_STATS)


@app.route("/api/alerts", methods=["GET", "POST", "DELETE", "OPTIONS"])
def api_alerts():
    if request.method == "OPTIONS":
        return "", 204

    if request.method == "GET":
        limit = request.args.get("limit", default=50, type=int)
        severity = request.args.get("severity", default="ALL", type=str)
        java_payload = _request_json_from_java(f"/api/alerts?limit={limit}&severity={urllib_parse.quote(severity)}")
        if java_payload is not None:
            return jsonify(java_payload)
        return jsonify(_demo_alerts(limit=limit, severity=severity))

    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        if not payload:
            return _build_error("Empty alert payload", 400)
        java_payload = _request_json_from_java("/api/alerts", method="POST", payload=payload)
        if java_payload is not None:
            return jsonify(java_payload), 201
        return jsonify({"status": "success", "id": payload.get("id", "ALT-LOCAL")}), 201

    if request.method == "DELETE":
        java_payload = _request_json_from_java("/api/alerts", method="DELETE")
        if java_payload is not None:
            return jsonify(java_payload)
        return jsonify({"status": "cleared"})

    return _build_error("Method not allowed", 405)


@app.route("/api/quarantine", methods=["GET", "POST", "DELETE", "OPTIONS"])
def api_quarantine():
    if request.method == "OPTIONS":
        return "", 204

    if request.method == "GET":
        java_payload = _request_json_from_java("/api/quarantine")
        if java_payload is not None:
            return jsonify(java_payload)
        return jsonify(DEMO_QUARANTINE)

    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        ip = payload.get("ip")
        if not ip:
            return _build_error("Missing IP", 400)
        java_payload = _request_json_from_java("/api/quarantine", method="POST", payload=payload)
        if java_payload is not None:
            return jsonify(java_payload)
        return jsonify({"status": "blocked", "ip": ip, "reason": payload.get("reason", "Manual SOC Block")})

    if request.method == "DELETE":
        payload = request.get_json(silent=True) or {}
        ip = payload.get("ip") or request.args.get("ip")
        java_payload = _request_json_from_java("/api/quarantine", method="DELETE", payload={"ip": ip or ""})
        if java_payload is not None:
            return jsonify(java_payload)
        return jsonify({"status": "unblocked", "ip": ip or ""})

    return _build_error("Method not allowed", 405)


@app.route("/api/simulate", methods=["POST", "OPTIONS"])
def api_simulate():
    if request.method == "OPTIONS":
        return "", 204
    payload = request.get_json(silent=True) or {}
    sim_type = (payload.get("type") or "portscan").lower()
    java_payload = _request_json_from_java("/api/simulate", method="POST", payload=payload)
    if java_payload is not None:
        return jsonify(java_payload)
    return jsonify({"status": "simulation_triggered", "type": sim_type})


@app.route("/api/website_scan", methods=["POST", "OPTIONS"])
def api_website_scan():
    """Passive safety check for ANY public URL (no active attacking).

    Fetches the page once, like visiting it, and reports: HTTP status,
    final URL after redirects, HTTPS, security response headers, and
    cookie flags. Blocks private/internal targets (SSRF guard).
    """
    if request.method == "OPTIONS":
        return "", 204
    payload = request.get_json(silent=True) or {}
    raw_url = (payload.get("url") or "").strip()
    if not raw_url:
        return _build_error("Please enter a URL", 400)
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    try:
        parsed = urllib_parse.urlparse(raw_url)
    except ValueError:
        return _build_error("That URL is not valid", 400)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or "." not in host and host not in ("localhost",):
        pass  # single-label hosts are still fine to validate per rules below
    # SSRF guard: block loopback/private/reserved hosts
    _private_patterns = [
        "localhost", "127.", "10.", "192.168.", "169.254.", "0.0.0.0", "::1", "[::1]",
        "100.64.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.",
        "metadata.google", "169.254.169.254",
    ]
    if any(host == p or host.startswith(p) or host.endswith(".local") or host.endswith(".internal") or host.endswith(".lan") for p in _private_patterns):
        return _build_error("That looks like a private/internal address — the safety check only scans public sites", 400)

    missing_headers = []
    # Critical security headers
    header_checks = [
        ("strict-transport-security", "Strict-Transport-Security (forces HTTPS)"),
        ("content-security-policy", "Content-Security-Policy (blocks injected scripts)"),
        ("x-frame-options", "X-Frame-Options (stops clickjacking)"),
        ("x-content-type-options", "X-Content-Type-Options (stops mime sniffing)"),
        ("referrer-policy", "Referrer-Policy (controls referrer data)"),
        ("permissions-policy", "Permissions-Policy (controls camera/mic/geolocation)"),
    ]

    req = urllib_request.Request(raw_url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; CyberShieldSafetyCheck/1.0; +https://cybershield.io)",
        "Accept": "text/html,application/xhtml+xml",
    })
    redirects = []
    status = None
    final_url = raw_url
    try:
        with urllib_request.urlopen(req, timeout=8) as r:
            status = r.status
            final_url = r.geturl()
            redirects = list(getattr(r, "redirects", []) or [])
            # urllib folds redirect history into the response object differently
            headers = {k.lower(): v for k, v in r.headers.items()}
            cookies = r.headers.get_all("Set-Cookie") or []
            content_type = r.headers.get("Content-Type", "")
            cl = r.headers.get("Content-Length")
            try:
                content_len = int(cl) if cl else len(r.read(256 * 1024))
            except Exception:
                content_len = None
    except urllib_error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        cookies = e.headers.get_all("Set-Cookie") if e.headers else []
        status = e.code
        final_url = e.geturl() or raw_url
        content_type = e.headers.get("Content-Type", "") if e.headers else ""
        content_len = None
    except Exception:
        return _build_error("Couldn't reach that site — check the URL and that the site is online", 502)

    cookie_flags = []
    for cookie in cookies or []:
        flag_str = "; ".join(p.strip() for p in cookie.split(";")[1:]) or "(no flags)"
        name = cookie.split("=", 1)[0].strip()
        cookie_flags.append({"name": name[:60], "flags": flag_str[:200]})

    for header, label in header_checks:
        if header not in headers:
            missing_headers.append(label)

    warnings = []
    if parsed.scheme == "http":
        warnings.append("Site is served over plain HTTP — traffic can be intercepted")
    for c in cookie_flags:
        flags = c["flags"].lower()
        if "secure" not in flags:
            warnings.append(f"Cookie '{c['name']}' missing Secure flag")
        if "httponly" not in flags:
            warnings.append(f"Cookie '{c['name']}' missing HttpOnly flag (readable by scripts)")
        if "samesite" not in flags:
            warnings.append(f"Cookie '{c['name']}' missing SameSite flag (CSRF protection)")

    score = max(0, 100 - len(missing_headers) * 15 - len(warnings) * 8)
    if raw_url.startswith("https:"):
        https_ok = True
    else:
        https_ok = False
    if score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    return jsonify({
        "status": "ok",
        "url": raw_url,
        "final_url": final_url,
        "http_status": status,
        "https": https_ok,
        "content_type": content_type,
        "content_length": content_len,
        "missing_security_headers": missing_headers,
        "cookies": cookie_flags,
        "warnings": warnings,
        "score": score,
        "grade": grade,
        "redirect_count": len(redirects),
    })


@app.route("/api/firewall/status", methods=["GET", "OPTIONS"])
def api_firewall_status():
    if request.method == "OPTIONS":
        return "", 204
    java_payload = _request_json_from_java("/api/firewall/status")
    if java_payload is not None:
        return jsonify(java_payload)
    return jsonify({"status": "AVAILABLE", "simulated": True})


@app.route("/api/firewall/download")
def api_firewall_download():
    java_payload = _request_json_from_java("/api/firewall/status")
    if java_payload is not None:
        return jsonify(java_payload)
    return jsonify({"status": "simulated", "download": "not_required"})


@app.route("/api/export")
def api_export():
    java_payload = _request_json_from_java("/api/export")
    if java_payload is not None and isinstance(java_payload, dict):
        return jsonify(java_payload)
    csv = "Alert_ID,Timestamp,Source_IP,Source_Port,Dest_IP,Dest_Port,Protocol,Attack_Type,Severity,Action_Taken,Recommendation\n"
    for alert in _demo_alerts(limit=50):
        csv += f'"{alert.get("id", "")}","{alert.get("timestamp", "")}","{alert.get("source_ip", "")}",{alert.get("source_port", 0)},"{alert.get("dest_ip", "")}",{alert.get("dest_port", 0)},"{alert.get("protocol", "")}","{alert.get("attack_type", "")}","{alert.get("severity", "")}","{alert.get("action_taken", "")}","{alert.get("recommendation", "")}"\n'
    return csv, 200, {"Content-Type": "text/csv; charset=utf-8", "Content-Disposition": 'attachment; filename="netsentinel_report.csv"'}


@app.route("/robots.txt")
def robots_txt():
    from flask import Response
    return Response("User-agent: *\nAllow: /\n", mimetype="text/plain")


@app.route("/favicon.ico")
def favicon_route():
    path = os.path.join(FRONTEND_DIR, "assets", "images", "favicon.svg")
    if os.path.isfile(path):
        return send_from_directory(os.path.dirname(path), "favicon.svg")
    return _build_error("Not found", 404)


@app.route("/api/auth/login", methods=["POST", "OPTIONS"])
def api_login():
    if request.method == "OPTIONS":
        return "", 204
    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip().lower()
    password = (payload.get("password") or "").strip()
    if not email or not password:
        return _build_error("Email and password are required", 400)
    users = _load_users()
    record = users.get(email)
    if not record or not _verify_password(password, record.get("pw_hash", "")):
        return _build_error("Invalid email or password", 401)
    session.clear()
    session.permanent = True
    session["user"] = email
    return jsonify({"status": "success", "user": email, "role": "admin"})


@app.route("/api/auth/register", methods=["POST", "OPTIONS"])
def api_register():
    if request.method == "OPTIONS":
        return "", 204
    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip().lower()
    password = (payload.get("password") or "").strip()
    full_name = (payload.get("fullName") or "").strip()
    if not email or not password:
        return _build_error("Valid email and password are required", 400)
    if "@" not in email or "." not in email:
        return _build_error("Email looks invalid, please check it and try again", 400)
    if len(password) < 8:
        return _build_error("Password must be at least 8 characters", 400)
    users = _load_users()
    if email in users:
        return _build_error("An account with this email already exists — try signing in", 409)
    users[email] = {
        "fullName": full_name,
        "organization": (payload.get("organization") or "").strip(),
        "pw_hash": _hash_password(password),
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        _save_users(users)
    except OSError:
        return _build_error("Could not save account, please try again", 500)
    session.clear()
    session.permanent = True
    session["user"] = email
    return jsonify({"status": "success", "user": email})


@app.route("/api/auth/logout", methods=["POST", "OPTIONS"])
def api_logout():
    if request.method == "OPTIONS":
        return "", 204
    session.clear()
    return jsonify({"status": "logged_out"})


@app.route("/api/auth/me")
def api_me():
    user = _current_user()
    if user is None:
        return _build_error("Not signed in", 401)
    return jsonify({"status": "success", "user": session.get("user")})


@app.route("/app/")
@app.route("/app/<path:web_path>")
@app.route("/web/")
@app.route("/web/<path:web_path>")
def serve_netsentinel_app(web_path="index.html"):
    """Serve the NetSentinel SOC app (web/ folder) inside the same unified server.

    The marketing site lives at / (frontend/), the NetSentinel app is
    mounted at /app/ (and at the legacy /web/ alias). Both share the
    same origin, so the landing-page login/register can redirect
    straight to the real app and /api/* calls keep working without
    CORS or cross-port wiring.

    Requires a signed-in session (server-side gate) — anonymous
    visitors are sent to /login.html.
    """
    gate = _require_login()
    if gate is not None:
        return gate
    safe_path = os.path.normpath(web_path or "index.html")
    if safe_path in {"", "."}:
        safe_path = "index.html"
    candidate = os.path.normpath(os.path.join(WEB_DIR, safe_path))
    if os.path.commonpath([WEB_DIR, candidate]) != WEB_DIR:
        return _build_error("Forbidden", 403)
    if os.path.isfile(candidate):
        # Serve with the original forward-slash URL path: send_from_directory
        # 404s on Windows when handed a normpath() (backslash) path.
        return send_from_directory(WEB_DIR, web_path or "index.html")
    return send_from_directory(WEB_DIR, "index.html")


@app.route("/v1/<path:path>")
def ignore_v1(path):
    # Browser extensions/AI tools poll this — don't return the landing page for it
    return _build_error("Not found", 404)


def getHomeForUser():
    """Signed-in users land on the scanner; anonymous users get the landing page."""
    if _current_user() is not None:
        return redirect("/scanner.html")
    return None


@app.route("/")
@app.route("/<path:path>")
def serve_frontend(path="index.html"):
    # The scanner is the signed-in home page — visiting / while logged in
    # takes you straight there.
    if path == "" or path == "index.html":
        home = getHomeForUser()
        if home is not None:
            return home
    # The scanner needs a signed-in account too (mirrors the /app/ gate).
    if (path or "") == "scanner.html":
        gate = _require_login()
        if gate is not None:
            return gate
    safe_path = os.path.normpath(path)
    if safe_path in {"", "."}:
        safe_path = "index.html"

    candidate = os.path.normpath(os.path.join(FRONTEND_DIR, safe_path))
    if os.path.commonpath([FRONTEND_DIR, candidate]) != FRONTEND_DIR:
        return _build_error("Forbidden", 403)

    if os.path.isfile(candidate):
        # Serve with the original forward-slash URL path (see note above).
        return send_from_directory(FRONTEND_DIR, path or "index.html")

    if path and path.endswith(".html"):
        return _build_error("Not found", 404)

    return send_from_directory(FRONTEND_DIR, "index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)