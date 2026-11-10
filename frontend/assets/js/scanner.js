// ========================================
// CyberShield - Scanner JavaScript
// Connected to NetSentinel Java Backend
// ========================================

// ===== Website Safety Check (passive — any public URL) =====
document.getElementById('safetyCheckBtn')?.addEventListener('click', async function () {
    const urlInput = document.getElementById('targetUrl');
    let url = urlInput?.value.trim();
    if (!url) {
        showToast('Enter a URL first', 'error');
        return;
    }
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
    const report = document.getElementById('safetyReport');
    const btn = this;
    const original = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-circle-notch spin"></i> Checking…';
    try {
        const res = await fetch((window.location.protocol === 'file:' ? 'http://localhost:8080' : '') + '/api/website_scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ url })
        });
        const data = await res.json();
        if (!res.ok) {
            showToast(data.error || 'Safety check failed', 'error');
            return;
        }
        renderSafetyReport(data, url);
        report.style.display = 'block';
        report.scrollIntoView({ behavior: 'smooth' });
        showToast('Safety check complete', 'success');
    } catch (e) {
        console.error('Safety check failed:', e);
        showToast('Could not reach that site — is it online?', 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = original;
    }
});

function renderSafetyReport(data, url) {
    document.getElementById('safetyUrl').textContent = data.url;
    document.getElementById('safetyFinal').textContent = data.final_url;
    document.getElementById('safetyStatus').textContent = data.http_status;
    document.getElementById('safetyHttps').textContent = data.https ? 'Yes' : 'No';
    document.getElementById('safetyType').textContent = (data.content_type || 'unknown').split(';')[0];
    document.getElementById('safetyScore').textContent = data.score;
    document.getElementById('safetyMissing').textContent = (data.missing_security_headers || []).length;
    document.getElementById('safetyWarnings').textContent = (data.warnings || []).length;
    const gradeEl = document.getElementById('safetyGrade');
    gradeEl.textContent = 'Grade ' + data.grade;
    gradeEl.className = 'status-badge ' + (['A', 'B'].includes(data.grade) ? 'status-success' : data.grade === 'C' ? 'status-safe' : 'status-danger');

    const findings = document.getElementById('safetyFindings');
    findings.innerHTML = '';
    const item = (title, severity, desc) => {
        const el = document.createElement('div');
        el.className = 'issue-item';
        el.innerHTML = `<div class="issue-info"><h4>${title}</h4><span class="issue-severity ${severity}">${severity.toUpperCase()}</span></div><p class="issue-description">${desc}</p>`;
        findings.appendChild(el);
    };
    (data.missing_security_headers || []).forEach(h => item('Missing: ' + h, 'medium', 'This header helps protect visitors. Your developer can add it — it is usually a one-line config change.'));
    (data.warnings || []).forEach(w => item(w, 'high', 'Detected on this site. Worth fixing if you own it.'));
    (data.cookies || []).forEach(c => item(`Cookie: ${c.name}`, 'low', 'Flags: ' + c.flags));
    if (!findings.children.length) {
        findings.innerHTML = '<div class="issue-item"><div class="issue-info"><h4>Clean report</h4><span class="issue-severity low">PASS</span></div><p class="issue-description">No missing headers or cookie problems detected.</p></div>';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initScanForm();
});

function initScanForm() {
    const startBtn = document.getElementById('startScanBtn');
    const resultsSection = document.getElementById('scanResults');

    if (!startBtn) return;

    startBtn.addEventListener('click', async () => {
        const urlInput = document.getElementById('targetUrl');
        const url = urlInput.value.trim();

        if (!url) {
            showToast('Please enter a valid URL', 'error');
            return;
        }

        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            urlInput.value = 'https://' + url;
        }

        const scanType = document.querySelector('input[name="scanType"]:checked').value;

        const originalText = startBtn.innerHTML;
        startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running Simulation...';
        startBtn.disabled = true;

        try {
            // Run simulation on backend
            await API.runSimulation(scanType);

            // Wait briefly for backend to process
            await new Promise(resolve => setTimeout(resolve, 1500));

            // Fetch alerts as scan results
            const alerts = await API.getAlerts(20, 'ALL');

            // Show results
            resultsSection.style.display = 'block';
            resultsSection.scrollIntoView({ behavior: 'smooth' });

            // Populate results from real alerts
            populateScanResults(alerts, urlInput.value);

            showToast('Scan simulation completed!', 'success');
        } catch (error) {
            showToast(error.message || 'Scan failed. Please try again.', 'error');
        } finally {
            startBtn.innerHTML = originalText;
            startBtn.disabled = false;
        }
    });
}

function populateScanResults(alerts, targetUrl) {
    const critical = alerts.filter(a => a.severity === 'CRITICAL').length;
    const high = alerts.filter(a => a.severity === 'HIGH').length;
    const medium = alerts.filter(a => a.severity === 'MEDIUM').length;
    const total = alerts.length;

    document.getElementById('totalIssues').textContent = total;
    document.getElementById('criticalIssues').textContent = critical;
    document.getElementById('highIssues').textContent = high;
    document.getElementById('mediumIssues').textContent = medium;

    const issuesList = document.getElementById('issuesList');
    issuesList.innerHTML = '';

    if (total === 0) {
        issuesList.innerHTML = `
            <div class="issue-item">
                <div class="issue-info">
                    <h4>No threats detected</h4>
                    <span class="issue-severity low">Low</span>
                </div>
                <div class="issue-target">${targetUrl}</div>
                <p class="issue-description">Target appears clean based on latest scan data.</p>
            </div>
        `;
        return;
    }

    alerts.slice(0, 10).forEach(alert => {
        const issueEl = document.createElement('div');
        issueEl.className = 'issue-item';
        issueEl.innerHTML = `
            <div class="issue-info">
                <h4>${alert.attack_type || 'Security Alert'}</h4>
                <span class="issue-severity ${alert.severity.toLowerCase()}">${alert.severity}</span>
            </div>
            <div class="issue-target">${alert.source_ip} → ${alert.dest_ip}</div>
            <p class="issue-description">${alert.description || 'No description available'}</p>
        `;
        issuesList.appendChild(issueEl);
    });
}