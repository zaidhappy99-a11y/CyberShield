// ========================================
// CyberShield - Main JavaScript
// Connected to NetSentinel Java Backend
// ========================================

// ===== NetSentinel App URL =====
// Landing site (frontend/) -> NetSentinel SOC app (web/ folder).
// Over HTTP the unified server mounts the app at /netsentinel.html. Opened
// directly as files, it lives in ../web/index.html.
function getNetSentinelUrl() {
    // NetSentinel lives inside CyberShield now — one site, one app.
    if (window.location.protocol === 'file:') {
        return 'netsentinel.html';
    }
    return '/netsentinel.html';
}

function getScannerUrl() {
    if (window.location.protocol === 'file:') {
        return 'scanner.html';
    }
    return '/scanner.html';
}

function storeAuthUser(user, email, role) {
    const name = (user && (user.fullName || user.name || user.username || user.email || user)) || email || 'demo@netsentinel.local';
    try {
        localStorage.setItem('netsentinel_user', String(email || name));
        sessionStorage.setItem('netsentinel_user', String(email || name));
        if (role) localStorage.setItem('netsentinel_role', String(role));
        if (name && name !== email) localStorage.setItem('netsentinel_name', String(name));
    } catch (e) { /* storage unavailable */ }
}

document.addEventListener('DOMContentLoaded', () => {
    initNavbar();
    initMobileMenu();
    initSidebar();
    initAuthUI();
    initAuthForms();
    initTheme();
    initDashboard();
    initLandingNav();
    initContactForm();
});

// ===== Navigation =====
function initNavbar() {
    const navbar = document.getElementById('navbar');
    const navLinks = document.querySelectorAll('.nav-link');

    // Scroll effect
    window.addEventListener('scroll', () => {
        if (!navbar) return; // auth pages have no navbar
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });

    // Active link based on current page
    const currentPage = window.location.pathname.split('/').pop();
    navLinks.forEach(link => {
        const linkPage = link.getAttribute('href');
        if (currentPage === linkPage || (currentPage === '' && linkPage === '#home')) {
            link.classList.add('active');
        }
    });
}

function initMobileMenu() {
    const toggle = document.getElementById('nav-toggle');
    const links = document.getElementById('nav-links');

    if (!toggle || !links) return;

    toggle.addEventListener('click', () => {
        links.classList.toggle('active');
        toggle.classList.toggle('active');
    });

    // Close menu when clicking a link
    links.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', () => {
            links.classList.remove('active');
            toggle.classList.remove('active');
        });
    });
}

// ===== Sidebar =====
function initSidebar() {
    const toggle = document.getElementById('sidebar-toggle');
    const sidebar = document.getElementById('sidebar');

    if (!toggle || !sidebar) return;

    toggle.addEventListener('click', () => {
        sidebar.classList.toggle('open');
    });

    // Close sidebar on outside click
    document.addEventListener('click', (e) => {
        if (!sidebar.contains(e.target) && !toggle.contains(e.target) && sidebar.classList.contains('open')) {
            sidebar.classList.remove('open');
        }
    });
}

// ===== Auth UI (password toggle only - no auth API on this backend) =====
function initAuthUI() {
    document.querySelectorAll('.toggle-password').forEach(btn => {
        btn.addEventListener('click', function() {
            const input = this.parentElement.querySelector('input');
            const icon = this.querySelector('i');
            
            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });
    });
}

// ===== Friendly form helpers =====
function setFormMessage(formId, message, type = 'error') {
    const box = document.getElementById('formMessage');
    if (!box) return;
    box.hidden = !message;
    box.className = 'form-message ' + type;
    box.textContent = message || '';
}

function setLoading(formId, loading, label) {
    const btn = document.querySelector(`#${formId} .auth-btn`);
    if (!btn) return;
    if (loading) {
        btn.dataset.label = btn.querySelector('.btn-label')?.textContent || '';
        const lbl = btn.querySelector('.btn-label');
        if (lbl) lbl.textContent = label || 'Please wait…';
        const arrow = btn.querySelector('.btn-arrow');
        if (arrow) { arrow.className = 'fas fa-circle-notch spin btn-arrow'; }
        btn.disabled = true;
    } else {
        const lbl = btn.querySelector('.btn-label');
        if (lbl) lbl.textContent = btn.dataset.label || '';
        const arrow = btn.querySelector('.btn-arrow');
        if (arrow) { arrow.className = 'fas fa-arrow-right btn-arrow'; }
        btn.disabled = false;
    }
}

// Plain-English password strength (register page)
function initPasswordStrength() {
    const input = document.getElementById('password');
    const fill = document.getElementById('strengthFill');
    const text = document.getElementById('strengthText');
    if (!input || !fill || !text) return;
    const scorePassword = (v) => {
        let s = 0;
        if (v.length >= 8) s++;
        if (v.length >= 12) s++;
        if (/[0-9]/.test(v)) s++;
        if (/[^A-Za-z0-9]/.test(v)) s++;
        if (/[a-z]/.test(v) && /[A-Z]/.test(v)) s++;
        return Math.min(s, 4);
    };
    const update = () => {
        const v = input.value;
        const score = scorePassword(v);
        fill.style.width = (score / 4 * 100) + '%';
        fill.className = 'strength-fill ' + (score <= 1 ? 'weak' : score === 2 ? 'fair' : score === 3 ? 'good' : 'strong');
        text.textContent = v ? `Password strength: ${['Too weak', 'Weak', 'Fair', 'Good', 'Strong'][score]}` : 'Password strength: —';
        const confirm = document.getElementById('confirmPassword');
        const hint = document.getElementById('confirmHint');
        if (confirm && hint) {
            hint.textContent = confirm.value
                ? (confirm.value === v ? 'Passwords match ✓' : 'Passwords do not match yet — check them')
                : "One more time, so typos don't lock you out.";
        }
    };
    input.addEventListener('input', update);
    document.getElementById('confirmPassword')?.addEventListener('input', update);
}

function initContactForm() {
    const form = document.getElementById('contactForm');
    if (!form) return;
    form.addEventListener('submit', (event) => {
        event.preventDefault();
        const name = form.name.value.trim();
        const email = form.email.value.trim();
        const subject = form.subject.value.trim();
        const message = form.message.value.trim();
        if (!name || !email || !subject || !message) {
            showToast('Please fill in every field first', 'error');
            return;
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            showToast('That email doesn\'t look right', 'error');
            return;
        }
        const btn = form.querySelector('#contactSubmit');
        const original = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-circle-notch spin"></i> Sending…';
        // Open the visitor's email client with everything pre-filled — no backend mail server needed.
        const body = `Name: ${name}\nEmail: ${email}\n\n${message}`;
        window.location.href = `mailto:support@cybershield.io?subject=${encodeURIComponent('[CyberShield] ' + subject)}&body=${encodeURIComponent(body)}`;
        setTimeout(() => {
            btn.disabled = false;
            btn.innerHTML = original;
            showToast('Your message is ready to send — check your email app!', 'success');
        }, 800);
    });
}

function initFaq() {
    // FAQ uses <details> for zero-JS friendliness; nothing to wire up here.
}

function initAuthForms() {
    initPasswordStrength();
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');

    if (loginForm) {
        loginForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value.trim();

            if (!email || !password) {
                setFormMessage('loginForm', 'Please enter both your email and password.', 'error');
                showToast('Please enter both email and password', 'error');
                return;
            }
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                setFormMessage('loginForm', 'That email doesn\'t look right — check for a typo.', 'error');
                return;
            }

            setFormMessage('loginForm', '', 'error');
            setLoading('loginForm', true, 'Signing you in…');
            try {
                const result = await API.login({ email, password });
                storeAuthUser(result && result.user, email, result && result.role);
                setFormMessage('loginForm', 'Signed in! Opening your NetSentinel dashboard…', 'success');
                showToast('Login successful — opening NetSentinel…', 'success');
                window.location.href = getScannerUrl();
            } catch (error) {
                console.error('Login failed:', error);
                const msg = (error && error.message && !error.message.startsWith('HTTP'))
                    ? error.message
                    : 'We couldn\'t sign you in. Check your details and try again in a moment.';
                setFormMessage('loginForm', msg, 'error');
                showToast(msg, 'error');
                setLoading('loginForm', false);
            }
        });
    }

    if (registerForm) {
        registerForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const payload = {
                fullName: document.getElementById('fullName')?.value.trim() || '',
                email: document.getElementById('email')?.value.trim() || '',
                organization: document.getElementById('organization')?.value.trim() || '',
                password: document.getElementById('password')?.value.trim() || '',
                confirmPassword: document.getElementById('confirmPassword')?.value.trim() || ''
            };

            if (!payload.fullName || !payload.email || !payload.password) {
                setFormMessage('registerForm', 'Please fill in your name, email, and password.', 'error');
                return;
            }
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payload.email)) {
                setFormMessage('registerForm', 'That email doesn\'t look right — check for a typo.', 'error');
                return;
            }
            if (payload.password.length < 8) {
                setFormMessage('registerForm', 'Your password needs at least 8 characters.', 'error');
                return;
            }
            if (payload.password !== payload.confirmPassword) {
                setFormMessage('registerForm', 'Passwords don\'t match yet — please re-type them.', 'error');
                return;
            }
            if (!document.getElementById('terms')?.checked) {
                setFormMessage('registerForm', 'Please tick the box to agree to the Terms first.', 'error');
                return;
            }

            setFormMessage('registerForm', '', 'error');
            setLoading('registerForm', true, 'Creating your account…');
            try {
                const result = await API.register(payload);
                storeAuthUser(result && result.user, payload.email, result && result.role);
                setFormMessage('registerForm', 'Account created! Opening your NetSentinel dashboard…', 'success');
                showToast('Account created — opening NetSentinel…', 'success');
                window.location.href = getScannerUrl();
            } catch (error) {
                console.error('Registration failed:', error);
                const msg = (error && error.message && !error.message.startsWith('HTTP'))
                    ? error.message
                    : 'We couldn\'t create your account. Try again in a moment.';
                setFormMessage('registerForm', msg, 'error');
                showToast(msg, 'error');
                setLoading('registerForm', false);
            }
        });
    }
}

// ===== Landing page: already logged in -> offer the NetSentinel app =====
function initLandingNav() {
    // Keep scanner/sidebar app links working when opened as files.
    document.querySelectorAll('a[href="/netsentinel.html"]').forEach((a) => {
        if (window.location.protocol === 'file:') a.href = '../web/index.html';
    });
    const currentPage = window.location.pathname.split('/').pop();
    if (currentPage === 'login.html' || currentPage === 'register.html') return;
    let user = null;
    try { user = localStorage.getItem('netsentinel_user'); } catch (e) { /* ignore */ }
    if (!user) return;
    const navActions = document.querySelector('.nav-actions');
    if (!navActions) return;
    navActions.innerHTML = '';
    const scannerLink = document.createElement('a');
    scannerLink.href = getScannerUrl();
    scannerLink.className = 'btn btn-primary';
    scannerLink.textContent = 'Open Scanner';
    const appLink = document.createElement('a');
    appLink.href = getNetSentinelUrl();
    appLink.className = 'btn btn-outline';
    appLink.textContent = 'NetSentinel';
    const logout = document.createElement('a');
    logout.href = '#';
    logout.className = 'btn btn-outline';
    logout.textContent = 'Logout';
    logout.addEventListener('click', (e) => {
        e.preventDefault();
        try {
            localStorage.removeItem('netsentinel_user');
            sessionStorage.removeItem('netsentinel_user');
        } catch (err) { /* ignore */ }
        window.location.href = 'login.html';
    });
    navActions.appendChild(scannerLink);
    navActions.appendChild(appLink);
    navActions.appendChild(logout);
}

// ===== Dashboard Data Loading (deprecated) =====
// The old landing-site dashboard page was removed (it errored). The
// NetSentinel SOC app at /netsentinel.html loads its own telemetry via web/js/app.js,
// so there is nothing to load here. Kept as a no-op for compatibility.
async function initDashboard() {
    return;
}

function updateStatsCards(stats) {
    const totalScans = document.querySelector('.stat-card.primary .stat-info h3');
    if (totalScans) totalScans.textContent = stats.total_alerts || 0;

    const criticalThreats = document.querySelector('.stat-card.danger .stat-info h3');
    if (criticalThreats) criticalThreats.textContent = stats.severities?.CRITICAL || 0;

    const warnings = document.querySelector('.stat-card.warning .stat-info h3');
    if (warnings) {
        const high = stats.severities?.HIGH || 0;
        const medium = stats.severities?.MEDIUM || 0;
        warnings.textContent = high + medium;
    }

    const securityScore = document.querySelector('.stat-card.success .stat-info h3');
    if (securityScore) securityScore.textContent = (stats.threat_score || 0) + '%';
}

function updateActivityList(alerts) {
    const activityList = document.querySelector('.activity-list');
    if (!activityList || !alerts) return;
    activityList.innerHTML = '';
    (alerts || []).slice(0, 10).forEach(alert => {
        const severityClass = getSeverityClass(alert.severity);
        const item = document.createElement('div');
        item.className = 'activity-item';
        item.innerHTML = `
            <div class="activity-icon ${severityClass}">
                <i class="fas ${getAlertIcon(alert.attack_type)}"></i>
            </div>
            <div class="activity-content">
                <h4>${alert.attack_type || 'Security Alert'}</h4>
                <p>${alert.source_ip} → ${alert.dest_ip}</p>
                <span class="activity-time">${alert.timestamp}</span>
            </div>
        `;
        activityList.appendChild(item);
    });
}

function updateThreatList(alerts) {
    const threatList = document.querySelector('.threat-list');
    if (!threatList || !alerts) return;
    threatList.innerHTML = '';
    const threats = alerts.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH');
    threats.slice(0, 10).forEach(alert => {
        const severityClass = alert.severity.toLowerCase();
        const item = document.createElement('div');
        item.className = 'threat-item';
        const progressWidth = alert.severity === 'CRITICAL' ? 85 : alert.severity === 'HIGH' ? 65 : 35;
        item.innerHTML = `
            <div class="threat-info">
                <h4>${alert.attack_type || 'Threat'}</h4>
                <span class="threat-severity ${severityClass}">${alert.severity}</span>
            </div>
            <div class="threat-target">${alert.source_ip}</div>
            <div class="threat-progress">
                <div class="progress-bar" style="width: ${progressWidth}%;"></div>
            </div>
        `;
        threatList.appendChild(item);
    });
}

function getSeverityClass(severity) {
    switch ((severity || '').toLowerCase()) {
        case 'critical': return 'danger';
        case 'high': return 'warning';
        case 'medium': return 'warning';
        case 'low': return 'info';
        default: return 'info';
    }
}

function getAlertIcon(attackType) {
    switch ((attackType || '').toLowerCase()) {
        case 'sql injection': return 'fa-database';
        case 'xss': return 'fa-code';
        case 'brute force': return 'fa-user-lock';
        case 'port scan': return 'fa-search';
        case 'ddos': return 'fa-exclamation-triangle';
        default: return 'fa-exclamation-circle';
    }
}

// ===== Theme =====
function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
}

// ===== Utility: Show Toast Notification =====
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle'}"></i>
        <span>${message}</span>
    `;
    document.body.appendChild(toast);
    
    setTimeout(() => toast.classList.add('show'), 100);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}