// ========================================
// CyberShield - Scanner JavaScript
// Connected to NetSentinel Java Backend
// ========================================

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