const API_BASE_URL = (() => {
  const override = (window.__NETSENTINEL_API_BASE__ || '').replace(/\/+$/, '');
  if (override) return override;
  if (window.location.protocol === 'file:') return 'http://localhost:8080/api';
  return `${window.location.origin.replace(/\/+$/, '')}/api`;
})();

let BACKEND_ONLINE = null;

const MOCK_STATS = { total_alerts: 124, packets_inspected: 45230, threat_score: 78, threat_level: 'HIGH', quarantined_ips: 5, severities: { LOW: 45, MEDIUM: 38, HIGH: 28, CRITICAL: 13 }, top_attackers: { '192.168.1.105': 12, '10.0.0.55': 8, '172.16.0.22': 5 }, top_ports: { 22: 15, 80: 12, 443: 8, 3389: 6, 8080: 4 }, protocols: { TCP: 89, UDP: 23, HTTP: 12, DNS: 6, SSH: 4, ICMP: 2 } };

const MOCK_ALERTS = [
  { id: 'ALT-001', timestamp: '2024-01-15 10:23:45', source_ip: '192.168.1.105', source_port: 54321, dest_ip: '10.0.0.1', dest_port: 3389, protocol: 'TCP', attack_type: 'Brute Force', severity: 'CRITICAL', description: 'Repeated SSH login attempts', payload_preview: '', action_taken: 'AUTO_QUARANTINED', recommendation: 'Block source IP' },
  { id: 'ALT-002', timestamp: '2024-01-15 10:18:12', source_ip: '10.0.0.55', source_port: 49152, dest_ip: '192.168.1.50', dest_port: 80, protocol: 'HTTP', attack_type: 'SQL Injection', severity: 'HIGH', description: 'SQL injection attempt on login form', payload_preview: "' OR 1=1 --", action_taken: 'FLAGGED', recommendation: 'Use parameterized queries' },
  { id: 'ALT-003', timestamp: '2024-01-15 10:12:33', source_ip: '172.16.0.22', source_port: 55211, dest_ip: '192.168.1.10', dest_port: 22, protocol: 'TCP', attack_type: 'Port Scan', severity: 'MEDIUM', description: 'Port scan detected across 50+ ports', payload_preview: '', action_taken: 'FLAGGED', recommendation: 'Enable firewall rate limiting' },
  { id: 'ALT-004', timestamp: '2024-01-15 09:45:10', source_ip: '45.234.12.8', source_port: 44388, dest_ip: '192.168.1.100', dest_port: 443, protocol: 'HTTPS', attack_type: 'XSS', severity: 'HIGH', description: 'Cross-site scripting in comment field', payload_preview: "<script>alert('xss')</script>", action_taken: 'FLAGGED', recommendation: 'Sanitize user inputs' },
  { id: 'ALT-005', timestamp: '2024-01-15 09:30:05', source_ip: '203.0.113.45', source_port: 12345, dest_ip: '192.168.1.5', dest_port: 8080, protocol: 'HTTP', attack_type: 'Directory Traversal', severity: 'HIGH', description: 'Path traversal attempt on web server', payload_preview: '../../../etc/passwd', action_taken: 'FLAGGED', recommendation: 'Update web server and WAF' },
  { id: 'ALT-006', timestamp: '2024-01-14 22:40:11', source_ip: '192.168.1.105', source_port: 44122, dest_ip: '10.0.0.99', dest_port: 445, protocol: 'TCP', attack_type: 'SMB Exploit', severity: 'CRITICAL', description: 'EternalBlue SMB exploit attempt', payload_preview: '', action_taken: 'AUTO_QUARANTINED', recommendation: 'Patch SMBv1' },
  { id: 'ALT-007', timestamp: '2024-01-14 21:55:30', source_ip: '10.0.0.77', source_port: 49201, dest_ip: '192.168.1.75', dest_port: 3306, protocol: 'TCP', attack_type: 'Database Attack', severity: 'CRITICAL', description: 'Unauthorized database connection attempt', payload_preview: '', action_taken: 'AUTO_QUARANTINED', recommendation: 'Enable DB authentication' },
];

async function checkBackend() {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 3000);
    await fetch(`${API_BASE_URL}/stats`, { signal: ctrl.signal });
    clearTimeout(t);
    BACKEND_ONLINE = true;
  } catch (e) {
    BACKEND_ONLINE = false;
  }
  return BACKEND_ONLINE;
}

const API = {
  async request(endpoint, options = {}) {
    const cfg = { headers: { 'Content-Type': 'application/json', ...options.headers }, ...options };

    if (cfg.body && typeof cfg.body === 'object' && !(cfg.body instanceof FormData)) {
      cfg.body = JSON.stringify(cfg.body);
    }

    if (BACKEND_ONLINE === null) await checkBackend();

    if (BACKEND_ONLINE) {
      const res = await fetch(`${API_BASE_URL}${endpoint}`, { ...cfg, credentials: 'same-origin' });
      if (!res.ok) {
        let msg = 'HTTP ' + res.status;
        try {
          const data = await res.clone().json();
          if (data && data.error) msg = data.error;
        } catch (e) { /* not JSON — keep status */ }
        throw new Error(msg);
      }
      const contentType = res.headers.get('content-type') || '';
      return contentType.includes('application/json') ? await res.json() : await res.text();
    }

    return this.mockResponse(endpoint, options.method || 'GET', options.body);
  },
  mockResponse(endpoint, method, body) {
    if (endpoint === '/stats') return { ...MOCK_STATS };
    if (endpoint === '/alerts') {
      const payload = body && typeof body === 'object' ? body : (body ? JSON.parse(body) : null);
      if (payload && payload.type) {
        MOCK_ALERTS.unshift({
          id: 'ALT-' + Date.now(),
          timestamp: new Date().toLocaleString(),
          source_ip: '10.10.10.10',
          source_port: 12345,
          dest_ip: '192.168.1.50',
          dest_port: 80,
          protocol: 'HTTP',
          attack_type: payload.type.charAt(0).toUpperCase() + payload.type.slice(1),
          severity: 'HIGH',
          description: 'Simulated ' + payload.type + ' attack',
          payload_preview: '',
          action_taken: 'FLAGGED',
          recommendation: 'Review firewall rules',
        });
        if (MOCK_ALERTS.length > 50) MOCK_ALERTS.pop();
      }
      return MOCK_ALERTS;
    }
    if (endpoint === '/quarantine' && method === 'POST') {
      const payload = body && typeof body === 'object' ? body : (body ? JSON.parse(body) : {});
      return { status: 'blocked', ip: payload.ip || 'unknown', reason: payload.reason || 'Manual block' };
    }
    if (endpoint === '/quarantine' && method === 'DELETE') return { status: 'unblocked' };
    if (endpoint === '/simulate') return { status: 'simulation_started', type: body && typeof body === 'object' ? body.type : (body ? JSON.parse(body).type : 'unknown') };
    if (endpoint === '/alerts' && method === 'DELETE') { MOCK_ALERTS.length = 0; return { status: 'cleared' }; }
    if (endpoint === '/auth/login') return { status: 'success', user: 'demo@netsentinel.local' };
    if (endpoint === '/auth/register') return { status: 'success', user: 'demo@netsentinel.local' };
    return { status: 'ok' };
  },
  async getAlerts(limit = 50, severity = 'ALL') {
    const params = new URLSearchParams({ limit: String(limit), severity });
    return this.request(`/alerts?${params.toString()}`);
  },
  async createAlert(data) { return this.request('/alerts', { method: 'POST', body: data }); },
  async clearAlerts() { return this.request('/alerts', { method: 'DELETE' }); },
  async getStats() { return this.request('/stats'); },
  async getQuarantine() { return this.request('/quarantine'); },
  async blockIp(ip, reason, severity) { return this.request('/quarantine', { method: 'POST', body: { ip, reason, severity } }); },
  async unblockIp(ip) { return this.request(`/quarantine?ip=${encodeURIComponent(ip)}`, { method: 'DELETE' }); },
  async runSimulation(type = 'port_scan') { return this.request('/simulate', { method: 'POST', body: { type } }); },
  async login(payload) { return this.request('/auth/login', { method: 'POST', body: payload }); },
  async register(payload) { return this.request('/auth/register', { method: 'POST', body: payload }); },
};