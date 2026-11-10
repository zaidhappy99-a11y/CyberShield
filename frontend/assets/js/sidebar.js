// ===== CyberShield sidebar pages: shared top bar + logout handling =====
(function () {
  'use strict';

  function getUserEmail() {
    try {
      return localStorage.getItem('netsentinel_user')
        || sessionStorage.getItem('netsentinel_user')
        || '';
    } catch (e) {
      return '';
    }
  }

  function getDisplayName(email) {
    try {
      var saved = localStorage.getItem('netsentinel_name');
      if (saved) return saved;
    } catch (e) { /* ignore */ }
    return displayName(email);
  }

  function applyRoleVisibility() {
    // The role lives server-side (in ADMIN_EMAILS). Read it from /api/auth/me so
    // sessions created before this feature still see/hides the Clients link correctly.
    var fallbackRole = 'member';
    try { fallbackRole = localStorage.getItem('netsentinel_role') || fallbackRole; } catch (e) { /* ignore */ }
    var apply = function (role) {
      var isAdmin = role === 'admin';
      document.querySelectorAll('a[href="clients.html"]').forEach(function (a) {
        a.style.display = isAdmin ? '' : 'none';
      });
    };
    fetch('/api/auth/me', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        var role = data && data.role ? data.role : fallbackRole;
        try { localStorage.setItem('netsentinel_role', role); } catch (e) { /* ignore */ }
        apply(role);
      })
      .catch(function () { apply(fallbackRole); });
  }

  function displayName(email) {
    if (!email) return 'CyberShield User';
    var local = email.split('@')[0].replace(/[._-]+/g, ' ').trim();
    if (!local) return email;
    return local.replace(/\b\w/g, function (c) { return c.toUpperCase(); });
  }

  function populateUserBar() {
    var email = getUserEmail();
    var name = getDisplayName(email);
    document.querySelectorAll('.user-name, .sidebar-user-name').forEach(function (el) {
      el.textContent = name;
    });
    document.querySelectorAll('.user-email, .sidebar-user-email').forEach(function (el) {
      el.textContent = email || 'not signed in';
    });
  }

  function wireLogout() {
    document.querySelectorAll('.logout-link, .logout-btn').forEach(function (el) {
      el.addEventListener('click', async function (e) {
        e.preventDefault();
        // Clear the server-side session too (fire and forget)
        try {
          var controller = new AbortController();
          setTimeout(function () { controller.abort(); }, 2000);
          await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin', signal: controller.signal });
        } catch (err) { /* ignore */ }
        try {
          localStorage.removeItem('netsentinel_user');
          sessionStorage.removeItem('netsentinel_user');
        } catch (err) { /* ignore */ }
        window.location.href = 'login.html';
      });
    });
  }

  function wireSearch() {
    var search = document.getElementById('topBarSearch');
    if (!search) return;
    search.addEventListener('keyup', function () {
      var q = search.value.trim().toLowerCase();
      document.querySelectorAll('.sidebar-nav .nav-item span').forEach(function (item) {
        var link = item.closest('a');
        link.style.display = (!q || item.textContent.toLowerCase().includes(q)) ? '' : 'none';
      });
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    populateUserBar();
    wireLogout();
    wireSearch();
    applyRoleVisibility();
  });
})();
