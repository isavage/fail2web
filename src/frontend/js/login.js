// ============================================================
// Fail2Web — login.js
// Behavior preserved: POST /api/login, token in localStorage,
// redirect to /index.html, error in #error-message,
// 2-minute inactivity timer.
// ============================================================

const SESSION_TIMEOUT = 120000; // 2 minutes

function handleLogin(event) {
    event.preventDefault();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const errorBox = document.getElementById('error-message');
    const button = document.getElementById('login-button');
    const label = button.querySelector('.lb-label');
    const spinner = button.querySelector('.lb-spinner');

    errorBox.classList.remove('show');
    errorBox.textContent = '';

    if (!username || !password) {
        showError('Please enter both username and password.');
        return false;
    }

    // Loading state
    button.disabled = true;
    label.textContent = 'Signing in…';
    button.classList.add('loading');

    fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, password: password })
    })
        .then(response => response.json().then(data => ({ ok: response.ok, status: response.status, data })))
        .then(({ ok, status, data }) => {
            if (ok && data.token) {
                localStorage.setItem('token', data.token);
                window.location.replace('/index.html');
                return;
            }
            restoreButton();
            showError(data.error || `Login failed (HTTP ${status}).`);
        })
        .catch(error => {
            restoreButton();
            showError('Could not reach the server. Check that Fail2Web is running.');
            console.error('Login error:', error);
        });

    return false;
}

function showError(msg) {
    const errorBox = document.getElementById('error-message');
    errorBox.textContent = msg;
    errorBox.classList.add('show');
}

function restoreButton() {
    const button = document.getElementById('login-button');
    button.disabled = false;
    button.querySelector('.lb-label').textContent = 'Sign in';
    button.classList.remove('loading');
}

// Enter key in password field also submits (form handles it, but keep explicit)
document.addEventListener('DOMContentLoaded', () => {
    // Password visibility toggle
    const toggle = document.getElementById('pass-toggle');
    const pass = document.getElementById('password');
    const eyeOpen = document.getElementById('eye-open');
    const eyeOff = document.getElementById('eye-off');
    if (toggle && pass) {
        toggle.addEventListener('click', () => {
            const showing = pass.type === 'text';
            pass.type = showing ? 'password' : 'text';
            eyeOpen.style.display = showing ? '' : 'none';
            eyeOff.style.display = showing ? 'none' : '';
            toggle.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
            pass.focus();
        });
    }

    // Clear field errors on typing
    ['username', 'password'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('input', () => {
            document.getElementById('error-message').classList.remove('show');
        });
    });

    // If a token already exists, go straight to the console
    const existing = localStorage.getItem('token');
    if (existing) {
        fetch('/api/verify-token', { headers: { 'Authorization': 'Bearer ' + existing } })
            .then(r => { if (r.ok) window.location.replace('/index.html'); })
            .catch(() => { /* stay on login */ });
    }

    // Engine status hint (unauthenticated /api/health)
    const dot = document.getElementById('login-hc-dot');
    const text = document.getElementById('login-hc-text');
    fetch('/api/health')
        .then(r => r.json().then(d => ({ ok: r.ok, d })))
        .then(({ ok, d }) => {
            const healthy = ok && d.status === 'healthy';
            dot.className = 'hc-dot ' + (healthy ? 'ok' : 'bad');
            text.textContent = healthy ? 'fail2ban engine connected' : 'fail2ban engine unreachable';
        })
        .catch(() => {
            dot.className = 'hc-dot bad';
            text.textContent = 'backend unreachable';
        });
});

// Inactivity timer (same policy as dashboard)
let inactivityTimer;
function resetInactivityTimer() {
    clearTimeout(inactivityTimer);
    inactivityTimer = setTimeout(() => {
        localStorage.removeItem('token');
        window.location.href = '/login.html';
    }, SESSION_TIMEOUT);
}

document.addEventListener('mousemove', resetInactivityTimer);
document.addEventListener('keypress', resetInactivityTimer);
resetInactivityTimer();
