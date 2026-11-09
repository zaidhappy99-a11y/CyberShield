# NetSentinel Project Review

## Work completed
- Reviewed the project layout, README/setup guide, Python detector and bridge, Java backend, frontend JavaScript, Windows launch scripts, firewall manager, and verification suite.
- Fixed the Windows `start.bat` launcher so it uses the project's Python resolver and serves the dashboard at `http://localhost:8080/` instead of opening a disconnected `file://` page. Removed the hard-coded MySQL Workbench Python executable path.
- Changed the Python bridge default bind address from all network interfaces to `127.0.0.1`. The dashboard/API has no authentication, so it should remain local by default.
- Removed permissive wildcard CORS response headers; the dashboard uses same-origin requests.
- Hardened static-file path containment using `os.path.commonpath`.
- Added request-body size checks, IP address validation for quarantine requests, severity validation, alert object validation, and an alert-history cap.
- Made invalid alert limit values return HTTP 400.
- Added a unittest-discoverable wrapper for the existing assertion-based verification script.
- Added a security note to the README.

## Verification performed
- Python source compilation: passed (`python -m compileall`).
- JavaScript syntax checks: passed (`node --check` for all project `.js` files).
- Java compilation: passed (`javac` for all six backend classes).
- Project verification script: all six reported suites passed.
- Standard unittest discovery: one discoverable test passed; it imports and executes the existing assertion-based verification suite.
- Local HTTP smoke test: dashboard returned HTTP 200, `/api/stats` returned HTTP 200, and an invalid quarantine IP was rejected with HTTP 400.

## Remaining limitations / cautions
- The built-in tests primarily use synthetic attack simulations and structural checks; they do not prove detection quality on real production traffic.
- Live packet capture depends on platform permissions and available packet-capture support; it was not validated against a real network interface in this review.
- Windows Firewall enforcement is platform- and privilege-dependent. `QUEUED_ELEVATED_SYNC` means a rule is queued for elevated application, not that it is already blocking traffic.
- The dashboard/API does not implement user authentication. Keep it bound to localhost; do not expose it to the internet or an untrusted LAN without adding authentication, authorization, TLS, and network restrictions.
- The separate `backend_server.py` Flask app is an alternate/legacy entry point and is not the recommended launch path. The documented primary path is `server.py` / `detector/bridge_server.py`.
