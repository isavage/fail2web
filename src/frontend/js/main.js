// ============================================================
// Fail2Web — main.js (modern console UI)
// All backend endpoints and behaviors preserved.
// ============================================================

const SESSION_TIMEOUT = 120000; // 2 minutes inactivity logout
const REFRESH_MS = 30000;       // data refresh every 30s

let ignoreIPList = [];
let currentJails = [];          // active jail names
let selectedJail = null;        // currently inspected jail
let jailBannedCounts = {};      // jail -> { ips: [...], subnets: n }
let selectedFilter = '';        // filter chosen in config form

// ---------- Icons (shared) ----------
const ICONS = {
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
    x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
    warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
    trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
    edit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>',
    play: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>',
    stop: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="5" width="14" height="14" rx="2"/></svg>',
    ban: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M4.93 4.93l14.14 14.14"/></svg>',
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
};

const AVATAR_COLORS = ['#4f46e5', '#0891b2', '#059669', '#d97706', '#dc2626', '#7c3aed', '#db2777', '#2563eb'];

// ============================================================
// UI helpers: toasts / confirm modal / busy overlay
// ============================================================
function toast(type, message, ms = 4200) {
    const wrap = document.getElementById('toasts');
    if (!wrap) return;
    const el = document.createElement('div');
    el.className = 'toast ' + type;
    const icon = type === 'success' ? ICONS.check : type === 'error' ? ICONS.x : type === 'warning' ? ICONS.warn : ICONS.info;
    el.innerHTML = icon + '<div>' + escapeHtml(message) + '</div>';
    wrap.appendChild(el);
    setTimeout(() => {
        el.classList.add('leaving');
        setTimeout(() => el.remove(), 260);
    }, ms);
}

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

let confirmResolve = null;
function showConfirm(title, message) {
    return new Promise(resolve => {
        confirmResolve = resolve;
        const modal = document.getElementById('confirm-modal');
        document.getElementById('confirm-title').textContent = title;
        document.getElementById('confirm-message').textContent = message;
        modal.style.display = 'grid';
    });
}

function closeConfirm(result) {
    document.getElementById('confirm-modal').style.display = 'none';
    if (confirmResolve) { confirmResolve(result); confirmResolve = null; }
}

function showBusy(title, sub) {
    document.getElementById('busy-title').textContent = title;
    document.getElementById('busy-sub').textContent = sub || 'Please wait…';
    document.getElementById('busy-overlay').classList.add('show');
}

function hideBusy() {
    document.getElementById('busy-overlay').classList.remove('show');
}

// ============================================================
// Auth utilities (unchanged contract with backend)
// ============================================================
function getToken() {
    return localStorage.getItem('token') || document.cookie.replace(/(?:(?:^|.*;\s*)token\s*\=\s*([^;]*).*$)|^.*$/, "$1");
}

function logout() {
    localStorage.removeItem('token');
    document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    window.location.replace('/login.html');
}

function authenticatedFetch(url, options = {}) {
    const token = getToken();
    if (!token) {
        window.location.href = '/login.html';
        return Promise.reject(new Error('No token'));
    }

    const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...options.headers
    };

    return fetch(url, { ...options, headers })
        .then(response => {
            if (response.status === 401) {
                localStorage.removeItem('token');
                window.location.href = '/login.html';
                return Promise.reject(new Error('Authentication failed'));
            }
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || `HTTP error! status: ${response.status}`);
                }).catch(() => {
                    throw new Error(`HTTP error! status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            if (data && data.error) {
                throw new Error(data.error);
            }
            return data;
        });
}

// ============================================================
// View switching (sidebar navigation)
// ============================================================
const VIEW_META = {
    jails: { title: 'Active Jails', sub: 'Live status of all fail2ban jails' },
    banned: { title: 'Banned IPs', sub: 'Inspect, search and manage banned addresses' },
    config: { title: 'Configuration', sub: 'Jails, filters and ignore lists' },
};

function switchView(name) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === name));
    const view = document.getElementById('view-' + name);
    if (view) view.classList.add('active');
    const meta = VIEW_META[name] || VIEW_META.jails;
    document.getElementById('page-title').textContent = meta.title;
    document.getElementById('page-subtitle').textContent = meta.sub;
    closeSidebar();
}

function openSidebar() {
    document.getElementById('sidebar').classList.add('open');
    document.getElementById('sidebar-scrim').classList.add('show');
}

function closeSidebar() {
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebar-scrim').classList.remove('show');
}

// showJailConfig / hideJailConfig keep their old names — they now just switch views
function showJailConfig() {
    switchView('config');
    loadJailConfigs();
    loadIgnoreIP();
    populateFilterOptions();
}

function hideJailConfig() {
    switchView('jails');
    fetchJails();
}

// ============================================================
// Health status (unauthenticated /api/health)
// ============================================================
function checkHealth() {
    const dot = document.getElementById('hc-dot');
    const text = document.getElementById('hc-text');
    const pill = document.getElementById('health-pill');
    const pillText = document.getElementById('health-pill-text');
    const time = document.getElementById('hc-time');
    if (!dot) return;

    fetch('/api/health')
        .then(r => r.json().then(d => ({ ok: r.ok, d })))
        .then(({ ok, d }) => {
            const healthy = ok && d.status === 'healthy';
            dot.className = 'hc-dot ' + (healthy ? 'ok' : 'bad');
            text.textContent = healthy ? 'fail2ban connected' : 'fail2ban unreachable';
            pill.className = 'pill ' + (healthy ? 'ok' : 'bad');
            pillText.textContent = healthy ? 'Operational' : 'Engine down';
            if (d.timestamp && time) {
                time.textContent = new Date(d.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            }
        })
        .catch(() => {
            dot.className = 'hc-dot bad';
            text.textContent = 'Backend unreachable';
            pill.className = 'pill bad';
            pillText.textContent = 'Backend down';
        });
}

// ============================================================
// Jails view — cards with live banned counts
// ============================================================
function fetchJails() {
    const token = getToken();
    if (!token) {
        window.location.href = '/login.html';
        return;
    }

    fetch('/api/jails', { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } })
        .then(response => {
            if (response.status === 401) {
                localStorage.removeItem('token');
                window.location.href = '/login.html';
                return Promise.reject(new Error('Authentication failed'));
            }
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || `HTTP error! status: ${response.status}`);
                }).catch(() => {
                    throw new Error(`HTTP error! status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            if (!data) return;
            if (data.error) throw new Error(data.error);

            currentJails = Array.isArray(data.jails) ? data.jails : [];
            renderJailGrid();
            refreshBannedCounts();
        })
        .catch(error => {
            console.error('Error fetching jails:', error);
            if (error.message !== 'Authentication failed') {
                const list = document.getElementById('jails-list');
                if (list) list.innerHTML = `<div class="empty"><div class="e-icon" style="background:var(--danger-soft);color:var(--danger)">${ICONS.warn}</div><h4>Unable to load jails</h4><p>${escapeHtml(error.message)}<br>Check that fail2ban is running and the socket is shared.</p></div>`;
            }
        });
}

function jailAvatarColor(name) {
    let h = 0;
    for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
    return AVATAR_COLORS[h % AVATAR_COLORS.length];
}

function renderJailGrid() {
    const container = document.getElementById('jails-list');
    if (!container) return;

    if (currentJails.length === 0) {
        container.innerHTML = `<div class="empty" style="grid-column:1/-1"><div class="e-icon">${ICONS.shield}</div><h4>No active jails</h4><p>No jails are currently running. Create one from the Configuration page.</p><div style="margin-top:14px"><button class="btn btn-primary btn-sm" onclick="showJailConfig()">Open Configuration</button></div></div>`;
        updateStats(0, 0);
        return;
    }

    container.innerHTML = '';
    currentJails.forEach(jail => {
        const info = jailBannedCounts[jail];
        const count = info ? info.ips.length : null;
        const card = document.createElement('div');
        card.className = 'jail-card' + (jail === selectedJail ? ' selected' : '');
        card.id = `jail-card-${jail}`;
        card.onclick = () => selectJail(jail);
        card.innerHTML = `
            <div class="jc-top">
                <div class="jc-avatar" style="background:${jailAvatarColor(jail)}">${escapeHtml(jail.slice(0, 2).toUpperCase())}</div>
                <div style="min-width:0">
                    <div class="jc-name">${escapeHtml(jail)}</div>
                    <div class="jc-meta">fail2ban jail</div>
                </div>
                <div class="jc-count">
                    <b data-count>${count === null ? '…' : count}</b>
                    <span>banned</span>
                </div>
            </div>
            <div class="jc-bottom">
                <span class="badge green"><span class="dot"></span>Active</span>
                <div class="spacer"></div>
                <button class="btn btn-outline btn-sm" onclick="event.stopPropagation();viewBannedIPs('${jail}')">Banned IPs</button>
                <button class="btn btn-icon btn-ghost" title="Stop jail" onclick="event.stopPropagation();toggleJail('${jail}', true)">${ICONS.stop}</button>
            </div>`;
        container.appendChild(card);
    });
}

function updateStats(totalBanned, totalSubnets) {
    const sj = document.getElementById('stat-jails');
    if (!sj) return;
    sj.textContent = currentJails.length;
    document.getElementById('stat-banned').textContent = totalBanned;
    document.getElementById('stat-subnets').textContent = totalSubnets;
    const nb = document.getElementById('nav-badge-jails');
    if (nb) nb.textContent = currentJails.length;
    const nbb = document.getElementById('nav-badge-banned');
    if (nbb) nbb.textContent = totalBanned;
}

// Fetch banned lists for every jail in parallel → counts for cards & stats
function refreshBannedCounts() {
    if (currentJails.length === 0) { updateStats(0, 0); return; }
    const token = getToken();
    const headers = { 'Authorization': `Bearer ${token}` };
    Promise.all(currentJails.map(jail =>
        fetch(`/api/banned/${jail}`, { headers })
            .then(r => r.ok ? r.json() : { status: '' })
            .then(d => ({ jail, d }))
            .catch(() => ({ jail, d: { status: '' } }))
    )).then(results => {
        let total = 0, subnets = 0;
        results.forEach(({ jail, d }) => {
            const { bannedIPs } = parseJailStatus(d.status || '');
            jailBannedCounts[jail] = { ips: bannedIPs };
            total += bannedIPs.length;
            subnets += bannedIPs.filter(isSubnet).length;
        });
        updateStats(total, subnets);
        // update counts on cards without a full re-render
        currentJails.forEach(jail => {
            const card = document.getElementById(`jail-card-${jail}`);
            if (card) {
                const b = card.querySelector('[data-count]');
                if (b) b.textContent = (jailBannedCounts[jail] || { ips: [] }).ips.length;
            }
        });
    });
}

function selectJail(jail) {
    selectedJail = jail;
    document.querySelectorAll('.jail-card').forEach(c => c.classList.toggle('selected', c.id === `jail-card-${jail}`));
    switchView('banned');
    fetchJailDetails(jail);
}

// ============================================================
// Banned IPs view
// ============================================================
function renderJailSwitcher() {
    const wrap = document.getElementById('jail-switcher');
    if (!wrap) return;
    wrap.innerHTML = '';
    if (currentJails.length === 0) return;
    const label = document.createElement('span');
    label.className = 'badge gray';
    label.textContent = 'Jail:';
    wrap.appendChild(label);
    currentJails.forEach(jail => {
        const b = document.createElement('button');
        b.className = 'btn btn-sm ' + (jail === selectedJail ? 'btn-primary' : 'btn-outline');
        b.textContent = jail;
        b.onclick = () => { selectedJail = jail; renderJailSwitcher(); fetchJailDetails(jail); };
        wrap.appendChild(b);
    });
}

function renderBanJailSelect() {
    const sel = document.getElementById('ban-jail-select');
    if (!sel) return;
    const prev = sel.value;
    sel.innerHTML = '';
    currentJails.forEach(jail => {
        const o = document.createElement('option');
        o.value = jail;
        o.textContent = jail;
        sel.appendChild(o);
    });
    // default: selected jail if present, else previous choice, else first jail
    if (selectedJail && currentJails.includes(selectedJail)) sel.value = selectedJail;
    else if (prev && currentJails.includes(prev)) sel.value = prev;
}

function viewBannedIPs(jailName) {
    selectedJail = jailName;
    switchView('banned');
    fetchJailDetails(jailName);
}

function fetchJailDetails(jail) {
    const token = getToken();
    const headers = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };

    renderJailSwitcher();
    renderBanJailSelect();
    const sub = document.getElementById('banned-sub');
    if (sub) sub.textContent = `Banned addresses in jail “${jail}”`;

    fetch(`/api/banned/${jail}`, { headers })
        .then(response => {
            if (response.status === 401) {
                localStorage.removeItem('token');
                window.location.href = '/login.html';
                return Promise.reject(new Error('Authentication failed'));
            }
            return response.json();
        })
        .then(data => {
            const bannedIPsContainer = document.getElementById('banned-ips');
            const { bannedIPs } = parseJailStatus(data.status || '');
            jailBannedCounts[jail] = { ips: bannedIPs };

            if (bannedIPs.length > 0) {
                bannedIPsContainer.innerHTML = `
                    <div class="table-wrap">
                        <table class="data" id="ip-table">
                            <thead><tr><th>Address</th><th>Type</th><th style="text-align:right">Actions</th></tr></thead>
                            <tbody></tbody>
                        </table>
                    </div>`;
                renderIPTable(document.getElementById('ip-table'), bannedIPs, jail);
            } else {
                bannedIPsContainer.innerHTML = `
                    <div class="empty">
                        <div class="e-icon" style="background:var(--success-soft);color:var(--success)">${ICONS.shield}</div>
                        <h4>No Banned IPs</h4>
                        <p>The jail <strong>${escapeHtml(jail)}</strong> has no banned IP addresses. All connections are currently allowed for this service.</p>
                    </div>`;
            }
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('banned-ips').innerHTML =
                `<div class="empty"><div class="e-icon" style="background:var(--danger-soft);color:var(--danger)">${ICONS.warn}</div><h4>Error</h4><p>Failed to fetch jail details: ${escapeHtml(error.message)}</p></div>`;
        });
}

window.fetchJailDetails = fetchJailDetails;

function isSubnet(ip) {
    return ip.includes('/');
}

function ipTypeLabel(ip) {
    if (isSubnet(ip)) return 'Subnet';
    return ip.includes(':') ? 'IPv6' : 'IPv4';
}

function renderIPTable(table, ips, jail) {
    const tbody = table.querySelector('tbody') || document.createElement('tbody');
    tbody.innerHTML = '';
    ips.forEach(ip => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="ip-mono ip-cell">${escapeHtml(ip)}</span></td>
            <td><span class="badge ${isSubnet(ip) ? 'violet' : 'indigo'}">${ipTypeLabel(ip)}</span></td>
            <td>
                <div class="row-actions">
                    <button class="btn btn-icon btn-ghost" title="Unban ${escapeHtml(ip)}" onclick="unbanIP('${jail}', '${ip}')">${ICONS.ban}</button>
                </div>
            </td>`;
        tbody.appendChild(tr);
    });
    if (!table.querySelector('tbody')) table.appendChild(tbody);
    // keep an active search applied across re-renders (jail switch / auto-refresh)
    window.filterIPs();
}

window.filterIPs = function () {
    const searchInput = document.getElementById('ip-search');
    const filter = searchInput.value.toLowerCase();
    const cells = document.querySelectorAll('#banned-ips .ip-cell');
    cells.forEach(cell => {
        const ip = cell.textContent;
        const tr = cell.closest('tr');
        if (tr) tr.style.display = ip.toLowerCase().includes(filter) ? '' : 'none';
    });
};

// ---------- Ban / unban ----------
window.banIP = function () {
    const ip = document.getElementById('ip-to-ban').value.trim();
    if (!ip) {
        toast('warning', 'Please enter an IP address or CIDR to ban');
        return;
    }
    const jail = document.getElementById('ban-jail-select').value || currentJails[0];
    if (!jail) {
        toast('error', 'No active jail available to ban into');
        return;
    }

    showBusy('Banning address', `${ip} → ${jail}`);
    authenticatedFetch('/api/ban', {
        method: 'POST',
        body: JSON.stringify({ jail: jail, ip: ip })
    })
        .then(data => {
            hideBusy();
            toast(data.status === 'warning' ? 'warning' : 'success', data.message);
            document.getElementById('ip-to-ban').value = '';
            fetchJailDetails(jail);
            refreshBannedCounts();
        })
        .catch(error => {
            hideBusy();
            if (error.message !== 'Authentication failed' && error.message !== 'No token') {
                toast('error', 'Ban failed: ' + error.message);
            }
        });
};

window.unbanIP = function (jail, ip) {
    showConfirm('Unban address?', `Are you sure you want to unban ${ip} from jail ${jail}?`)
        .then(ok => {
            if (!ok) return;
            showBusy('Unbanning address', `${ip} from ${jail}`);
            return authenticatedFetch('/api/unban', {
                method: 'POST',
                body: JSON.stringify({ jail: jail, ip: ip })
            })
                .then(() => {
                    hideBusy();
                    toast('success', `IP ${ip} unbanned from ${jail}`);
                    fetchJailDetails(jail);
                    refreshBannedCounts();
                })
                .catch(error => {
                    hideBusy();
                    if (error.message !== 'Authentication failed' && error.message !== 'No token') {
                        toast('error', `Failed to unban IP: ${error.message}`);
                    }
                });
        });
};

// ============================================================
// Status parsing (unchanged)
// ============================================================
function parseJailStatus(statusText) {
    const bannedIPsMatch = statusText.match(/Banned IP list:\t(.+)$/);
    if (!bannedIPsMatch) return { bannedIPs: [] };
    const bannedIPs = bannedIPsMatch[1].split(' ').filter(ip => ip.trim());
    return { bannedIPs };
}

// ============================================================
// Configuration — filter picker
// ============================================================
const FILTERS = [
    { value: 'sshd', text: 'SSH (sshd)' },
    { value: 'sshd2', text: 'SSH Enhanced (sshd2)' },
    { value: 'nginx', text: 'Nginx (nginx)' },
    { value: 'auth', text: 'Nginx Auth (auth)' },
    { value: 'apache-auth', text: 'Apache Auth (apache-auth)' },
    { value: 'apache-badbots', text: 'Apache Bad Bots (apache-badbots)' },
    { value: 'apache-botsearch', text: 'Apache Bot Search (apache-botsearch)' },
    { value: 'apache-common', text: 'Apache Common (apache-common)' },
    { value: 'apache-fakegooglebot', text: 'Apache Fake Googlebot (apache-fakegooglebot)' },
    { value: 'apache-modsecurity', text: 'Apache ModSecurity (apache-modsecurity)' },
    { value: 'apache-nohome', text: 'Apache No Home (apache-nohome)' },
    { value: 'apache-noscript', text: 'Apache No Script (apache-noscript)' },
    { value: 'apache-overflows', text: 'Apache Overflows (apache-overflows)' },
    { value: 'apache-pass', text: 'Apache Pass (apache-pass)' },
    { value: 'apache-shellshock', text: 'Apache Shellshock (apache-shellshock)' },
    { value: 'vsftpd', text: 'VSFTPD (vsftpd)' },
    { value: 'proftpd', text: 'ProFTPD (proftpd)' },
    { value: 'pure-ftpd', text: 'Pure-FTPd (pure-ftpd)' },
    { value: 'wuftpd', text: 'WU-FTPd (wuftpd)' },
    { value: 'postfix', text: 'Postfix (postfix)' },
    { value: 'sendmail-auth', text: 'Sendmail Auth (sendmail-auth)' },
    { value: 'sendmail-reject', text: 'Sendmail Reject (sendmail-reject)' },
    { value: 'exim', text: 'Exim (exim)' },
    { value: 'dovecot', text: 'Dovecot (dovecot)' },
    { value: 'sieve', text: 'Sieve (sieve)' },
    { value: 'solid-pop3d', text: 'Solid POP3d (solid-pop3d)' },
    { value: 'courier-auth', text: 'Courier Auth (courier-auth)' },
    { value: 'courier-smtp', text: 'Courier SMTP (courier-smtp)' },
    { value: 'named', text: 'BIND9 (named)' },
    { value: 'recidive', text: 'Recidive (recidive)' },
    { value: 'murmur', text: 'Mumble (murmur)' },
    { value: 'asterisk', text: 'Asterisk (asterisk)' },
    { value: 'freeswitch', text: 'FreeSWITCH (freeswitch)' },
    { value: 'mysqld', text: 'MySQL (mysqld)' },
    { value: 'mysqld-auth', text: 'MySQL Auth (mysqld-auth)' },
    { value: 'oracle', text: 'Oracle (oracle)' },
    { value: 'php-url-fopen', text: 'PHP URL Fopen (php-url-fopen)' },
    { value: 'roundcube-auth', text: 'Roundcube Auth (roundcube-auth)' },
    { value: 'openwebmail', text: 'OpenWebMail (openwebmail)' },
    { value: 'horde', text: 'Horde (horde)' },
    { value: 'groupoffice', text: 'GroupOffice (groupoffice)' },
    { value: 'sogo', text: 'SOGo (sogo)' },
    { value: 'tomcat', text: 'Tomcat (tomcat)' },
    { value: 'monit', text: 'Monit (monit)' },
    { value: 'webmin', text: 'Webmin (webmin)' },
    { value: 'drupal-auth', text: 'Drupal Auth (drupal-auth)' },
    { value: 'magento', text: 'Magento (magento)' },
    { value: 'wordpress', text: 'WordPress (wordpress)' },
    { value: 'phpmyadmin', text: 'phpMyAdmin (phpmyadmin)' },
    { value: 'guacamole', text: 'Guacamole (guacamole)' },
    { value: 'slapd', text: 'OpenLDAP (slapd)' },
    { value: 'directadmin', text: 'DirectAdmin (directadmin)' },
    { value: 'iptables', text: 'iptables (iptables)' },
    { value: 'nginx-http-auth', text: 'Nginx HTTP Auth (nginx-http-auth)' },
    { value: 'nginx-limit-req', text: 'Nginx Limit Requests (nginx-limit-req)' },
    { value: 'nginx-botsearch', text: 'Nginx Bot Search (nginx-botsearch)' },
];

function populateFilterOptions() {
    const list = document.getElementById('filter-list');
    if (!list || list.dataset.built === '1') { filterFilterList(); return; }
    list.dataset.built = '1';
    list.innerHTML = '';
    FILTERS.forEach(f => {
        const row = document.createElement('div');
        row.className = 'filter-row';
        row.dataset.value = f.value;
        row.dataset.text = f.text.toLowerCase();
        row.innerHTML = `<span class="fname">${f.value}</span><span class="fdesc">${escapeHtml(f.text.replace(/\s*\(.*\)$/, ''))}</span>`;
        row.onclick = () => onFilterChange(f.value);
        list.appendChild(row);
    });
    filterFilterList();
}

function filterFilterList() {
    const q = (document.getElementById('filter-search').value || '').toLowerCase();
    document.querySelectorAll('#filter-list .filter-row').forEach(row => {
        row.style.display = (row.dataset.text.includes(q) || row.dataset.value.includes(q)) ? '' : 'none';
    });
}

function setFilterSelectedUI(value) {
    selectedFilter = value || '';
    document.querySelectorAll('#filter-list .filter-row').forEach(row => {
        const on = row.dataset.value === selectedFilter;
        row.style.borderColor = on ? 'var(--primary)' : '';
        row.style.background = on ? 'var(--primary-soft)' : '';
    });
}

function onFilterChange(filterValue) {
    const customFilterInput = document.getElementById('jail-filter-custom');
    const filterContent = document.getElementById('filter-content');
    const jailName = document.getElementById('jail-name');
    const logpathInput = document.getElementById('jail-logpath');

    if (!filterValue) {
        customFilterInput.value = '';
        filterContent.style.display = 'none';
        jailName.value = '';
        logpathInput.value = '';
        resetToDefaults();
        setFilterSelectedUI('');
        document.getElementById('jail-filter').value = '';
        return;
    }

    // Clear custom text when a known filter is chosen
    customFilterInput.value = '';
    setFilterSelectedUI(filterValue);
    document.getElementById('jail-filter').value = filterValue;
    setFilterDefaults(filterValue);
    loadFilterContent(filterValue);
}

function setFilterDefaults(filterValue) {
    const jailName = document.getElementById('jail-name');
    const logpathInput = document.getElementById('jail-logpath');

    const filterDefaults = {
        'sshd': { name: 'sshd', logpath: '%(syslog_authpriv)s', maxretry: 3, findtime: 3600, bantime: 60000 },
        'sshd2': { name: 'sshd2', logpath: '%(syslog_authpriv)s', maxretry: 3, findtime: 1800, bantime: 60000 },
        'nginx': { name: 'nginx', logpath: '/var/log/nginx/access.log', maxretry: 5, findtime: 600, bantime: 60000 },
        'auth': { name: 'auth', logpath: '/var/log/nginx/access.log', maxretry: 5, findtime: 600, bantime: 60000 },
        'apache-auth': { name: 'apache-auth', logpath: '/var/log/apache2/error.log', maxretry: 3, findtime: 600, bantime: 60000 },
        'postfix': { name: 'postfix', logpath: '/var/log/mail.log', maxretry: 5, findtime: 600, bantime: 180000 },
        'dovecot': { name: 'dovecot', logpath: '/var/log/dovecot.log', maxretry: 5, findtime: 300, bantime: 90000 },
        'vsftpd': { name: 'vsftpd', logpath: '/var/log/vsftpd.log', maxretry: 3, findtime: 600, bantime: 180000 },
        'mysqld': { name: 'mysqld', logpath: '/var/log/mysql/error.log', maxretry: 3, findtime: 600, bantime: 120000 }
    };

    const defaults = filterDefaults[filterValue] || {
        name: filterValue,
        logpath: '/var/log/' + filterValue + '.log',
        maxretry: 3,
        findtime: 3600,
        bantime: 60000
    };

    jailName.value = defaults.name;
    logpathInput.value = defaults.logpath;
    document.getElementById('jail-maxretry').value = defaults.maxretry;
    document.getElementById('jail-findtime').value = defaults.findtime;
    document.getElementById('jail-bantime').value = defaults.bantime;
}

function resetToDefaults() {
    document.getElementById('jail-maxretry').value = 3;
    document.getElementById('jail-findtime').value = 3600;
    document.getElementById('jail-bantime').value = 60000;
    document.getElementById('jail-action').value = '';
    document.getElementById('jail-enabled').checked = true;
}

function loadFilterContent(filterName) {
    authenticatedFetch(`/api/filters/${filterName}`)
        .then(data => {
            const filterContent = document.getElementById('filter-content');
            const filterRegex = document.getElementById('filter-regex');
            if (data.status === 'success') {
                filterRegex.textContent = data.content;
                filterContent.style.display = 'block';
            } else {
                filterContent.style.display = 'none';
            }
        })
        .catch(() => {
            document.getElementById('filter-content').style.display = 'none';
        });
}

// ============================================================
// Configuration — jail create/edit form
// ============================================================
function clearJailForm() {
    document.getElementById('jail-form').reset();
    document.getElementById('jail-enabled').checked = true;
    document.getElementById('filter-content').style.display = 'none';
    document.getElementById('jail-filter-custom').value = '';
    document.getElementById('jail-filter').value = '';
    setFilterSelectedUI('');
    document.getElementById('jail-form-title').textContent = 'Create Jail';
}

function handleJailFormSubmit(event) {
    event.preventDefault();

    const customFilter = document.getElementById('jail-filter-custom').value.trim();
    const filterValue = customFilter || document.getElementById('jail-filter').value;
    if (!filterValue) {
        toast('warning', 'Please select a filter (or type a custom filter name)');
        return;
    }

    const formData = {
        name: document.getElementById('jail-name').value.trim(),
        filter: filterValue,
        logpath: document.getElementById('jail-logpath').value,
        maxretry: parseInt(document.getElementById('jail-maxretry').value),
        findtime: parseInt(document.getElementById('jail-findtime').value),
        bantime: parseInt(document.getElementById('jail-bantime').value),
        action: document.getElementById('jail-action').value,
        enabled: document.getElementById('jail-enabled').checked
    };

    // === AUTOMATIC FIX: Force systemd backend for SSH jails ===
    if (formData.filter === 'sshd' || formData.filter === 'sshd2') {
        formData.backend = 'systemd';
    }

    if (!formData.name || !formData.filter || !formData.logpath) {
        toast('warning', 'Please fill in all required fields: Name, Filter, and Log Path');
        return;
    }

    showBusy('Creating jail configuration', `Writing and activating ${formData.name}…`);

    authenticatedFetch('/api/jails/config', {
        method: 'POST',
        body: JSON.stringify(formData)
    })
        .then(data => {
            hideBusy();
            if (data.status === 'success') {
                toast(data.jail_active ? 'success' : 'warning',
                    data.jail_active
                        ? `Jail ${formData.name} created and active`
                        : 'Config saved. Jail will activate on next reload — check logpath/filter.');
                clearJailForm();
                loadJailConfigs();
                fetchJails();
            } else {
                toast('error', 'Error saving jail: ' + (data.error || 'Unknown error'));
            }
        })
        .catch(error => {
            hideBusy();
            if (error.message !== 'Authentication failed' && error.message !== 'No token') {
                toast('error', 'Network error while saving jail: ' + error.message);
            }
        });
}

// ============================================================
// Configuration — existing jails list
// ============================================================
function loadJailConfigs() {
    const token = getToken();
    if (!token) {
        window.location.href = '/login.html';
        return;
    }

    fetch('/api/jails/config', { headers: { 'Authorization': 'Bearer ' + token } })
        .then(response => {
            if (response.status === 401) {
                localStorage.removeItem('token');
                window.location.href = '/login.html';
                return Promise.reject(new Error('Authentication failed'));
            }
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || `HTTP error! status: ${response.status}`);
                }).catch(() => {
                    throw new Error(`HTTP error! status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            if (!data) return;
            if (data.error) throw new Error(data.error);
            if (data.jails) {
                renderJailConfigs(data.jails);
            }
        })
        .catch(error => {
            console.error('Error loading jail configs:', error);
            if (error.message !== 'Authentication failed') {
                toast('error', 'Error loading jail configurations: ' + error.message);
            }
        });
}

function fmtDur(v) {
    if (v === '' || v === undefined || v === null) return '—';
    return `${v}s`;
}

function renderJailConfigs(jails) {
    const container = document.getElementById('jail-config-list');
    if (!container) return;

    const enabledCount = jails.filter(j => j.enabled === 'true' || j.enabled === true).length;
    const se = document.getElementById('stat-enabled');
    if (se) se.textContent = enabledCount;

    if (jails.length === 0) {
        container.innerHTML = `<div class="empty"><div class="e-icon">${ICONS.edit}</div><h4>No jail configurations</h4><p>Create your first jail with the form on the left.</p></div>`;
        return;
    }

    container.innerHTML = '';
    jails.forEach(jail => {
        const enabled = jail.enabled === 'true' || jail.enabled === true;
        const isActive = currentJails.includes(jail.name);
        const item = document.createElement('div');
        item.className = 'cfg-item' + (enabled ? '' : ' disabled');
        item.innerHTML = `
            <div class="cfg-head">
                <span class="name">${escapeHtml(jail.name)}</span>
                <span class="badge ${enabled ? 'green' : 'red'}"><span class="dot"></span>${enabled ? 'Enabled' : 'Disabled'}</span>
                ${isActive ? '<span class="badge indigo">Running</span>' : ''}
                <span class="spacer"></span>
            </div>
            <div class="cfg-kv">
                <div><span class="k">Filter</span><span class="v">${escapeHtml(jail.filter || '—')}</span></div>
                <div><span class="k">Log Path</span><span class="v">${escapeHtml(jail.logpath || '—')}</span></div>
                <div><span class="k">Max Retry</span><span class="v">${escapeHtml(jail.maxretry || '—')}</span></div>
                <div><span class="k">Find Time</span><span class="v">${fmtDur(jail.findtime)}</span></div>
                <div><span class="k">Ban Time</span><span class="v">${fmtDur(jail.bantime)}</span></div>
                ${jail.action ? `<div><span class="k">Action</span><span class="v">${escapeHtml(jail.action)}</span></div>` : ''}
            </div>
            <div class="cfg-actions">
                <button class="btn btn-outline btn-sm" onclick="editJail('${jail.name}')">${ICONS.edit} Edit</button>
                <button class="btn ${enabled ? 'btn-ghost' : 'btn-success'} btn-sm" onclick="toggleJail('${jail.name}', ${enabled})">${enabled ? ICONS.stop + ' Stop' : ICONS.play + ' Start'}</button>
                <button class="btn btn-danger btn-sm" onclick="deleteJail('${jail.name}')">${ICONS.trash} Delete</button>
            </div>`;
        container.appendChild(item);
    });
}

function editJail(jailName) {
    authenticatedFetch('/api/jails/config')
        .then(data => {
            const jail = data.jails.find(j => j.name === jailName);
            if (!jail) return;
            switchView('config');
            populateFilterOptions();

            document.getElementById('jail-name').value = jail.name;
            document.getElementById('jail-logpath').value = jail.logpath;
            document.getElementById('jail-maxretry').value = jail.maxretry;
            document.getElementById('jail-findtime').value = jail.findtime;
            document.getElementById('jail-bantime').value = jail.bantime;
            document.getElementById('jail-action').value = jail.action || '';
            document.getElementById('jail-enabled').checked = jail.enabled === 'true' || jail.enabled === true;
            document.getElementById('jail-form-title').textContent = `Edit Jail — ${jail.name}`;

            const known = FILTERS.some(f => f.value === jail.filter);
            if (known) {
                document.getElementById('jail-filter-custom').value = '';
                onFilterChange(jail.filter);
                // don't let the filter defaults overwrite the stored values
                document.getElementById('jail-name').value = jail.name;
                document.getElementById('jail-logpath').value = jail.logpath;
                document.getElementById('jail-maxretry').value = jail.maxretry;
                document.getElementById('jail-findtime').value = jail.findtime;
                document.getElementById('jail-bantime').value = jail.bantime;
                document.getElementById('jail-action').value = jail.action || '';
                document.getElementById('jail-enabled').checked = jail.enabled === 'true' || jail.enabled === true;
            } else {
                document.getElementById('jail-filter').value = jail.filter || '';
                document.getElementById('jail-filter-custom').value = jail.filter || '';
                setFilterSelectedUI('');
                if (jail.filter) loadFilterContent(jail.filter);
            }
            window.scrollTo({ top: 0, behavior: 'smooth' });
        })
        .catch(error => {
            console.error('Error loading jail for edit:', error);
        });
}

function toggleJail(jailName, currentlyEnabled) {
    const action = currentlyEnabled ? 'stop' : 'start';
    authenticatedFetch(`/api/jails/${jailName}/${action}`, { method: 'POST' })
        .then(data => {
            if (data.status === 'success') {
                toast('success', `Jail ${jailName} ${action === 'stop' ? 'stopped' : 'started'}`);
                loadJailConfigs();
                fetchJails();
            } else {
                toast('error', 'Error: ' + (data.error || 'unknown'));
            }
        })
        .catch(error => {
            if (error.message !== 'Authentication failed' && error.message !== 'No token') {
                toast('error', `Error ${action}ing jail: ${error.message}`);
            }
        });
}

function deleteJail(jailName) {
    showConfirm('Delete jail?', `Are you sure you want to delete jail ${jailName}? This will stop the jail and remove its configuration.`)
        .then(ok => {
            if (!ok) return;
            showBusy('Deleting jail', `Stopping and removing ${jailName}…`);
            return authenticatedFetch(`/api/jails/config/${jailName}`, { method: 'DELETE' })
                .then(data => {
                    hideBusy();
                    if (data.status === 'success') {
                        toast('success', `Jail ${jailName} deleted successfully`);
                        loadJailConfigs();
                        fetchJails();
                    } else {
                        toast('error', 'Error deleting jail: ' + (data.error || 'Unknown error'));
                    }
                })
                .catch(error => {
                    hideBusy();
                    if (error.message !== 'Authentication failed' && error.message !== 'No token') {
                        toast('error', 'Network error while deleting jail: ' + error.message);
                    }
                });
        });
}

// Alias kept for parity with old code paths
function deleteJailConfig(jailName) { deleteJail(jailName); }

// ============================================================
// Ignore IP management
// ============================================================
function loadIgnoreIP() {
    authenticatedFetch('/api/ignoreip')
        .then(data => {
            if (data.ignoreip) {
                ignoreIPList = data.ignoreip;
                renderIgnoreIPList();
            }
        })
        .catch(error => {
            console.error('Error loading ignoreIP:', error);
            if (error.message !== 'Authentication failed' && error.message !== 'No token') {
                toast('error', 'Error loading ignoreIP: ' + error.message);
            }
        });
}

function renderIgnoreIPList() {
    const container = document.getElementById('ignoreip-list');
    container.innerHTML = '';

    if (ignoreIPList.length === 0) {
        container.innerHTML = '<p style="color:var(--muted);font-size:0.82rem;margin:0;">No ignoreIP entries found.</p>';
        return;
    }

    ignoreIPList.forEach(ip => {
        const chip = document.createElement('span');
        chip.className = 'chip';
        chip.innerHTML = `<span>${escapeHtml(ip)}</span><button class="chip-x" title="Remove ${escapeHtml(ip)}" onclick="removeIgnoreIP('${ip}')">${ICONS.x}</button>`;
        container.appendChild(chip);
    });
}

function addIgnoreIP() {
    const input = document.getElementById('new-ignoreip');
    const ip = input.value.trim();

    if (!ip) {
        toast('warning', 'Please enter an IP address or CIDR range');
        return;
    }

    const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const cidrRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-2]?[0-9]|3[0-2])$/;

    if (!ipRegex.test(ip) && !cidrRegex.test(ip)) {
        toast('warning', 'Invalid IP or CIDR format. Use e.g. 192.168.1.1 or 10.0.0.0/24');
        return;
    }

    if (ignoreIPList.includes(ip)) {
        toast('warning', 'This IP is already in the ignore list');
        return;
    }

    ignoreIPList.push(ip);
    renderIgnoreIPList();
    input.value = '';
    saveIgnoreIPToBackend();
}

function removeIgnoreIP(ip) {
    ignoreIPList = ignoreIPList.filter(item => item !== ip);
    renderIgnoreIPList();
    saveIgnoreIPToBackend();
}

function saveIgnoreIPToBackend() {
    authenticatedFetch('/api/ignoreip', {
        method: 'POST',
        body: JSON.stringify({ ignoreip: ignoreIPList })
    })
        .then(data => {
            if (data.status === 'success') {
                toast('success', 'Ignore list saved and fail2ban reloaded');
                // The backend merges default private ranges — resync the view
                loadIgnoreIP();
            }
        })
        .catch(error => {
            console.error('Error auto-saving ignoreIP:', error);
            if (error.message !== 'Authentication failed' && error.message !== 'No token') {
                toast('error', 'Error saving ignoreIP: ' + error.message);
            }
        });
}

// Expose functions used by inline handlers
window.showJailConfig = showJailConfig;
window.hideJailConfig = hideJailConfig;
window.onFilterChange = onFilterChange;
window.filterFilterList = filterFilterList;
window.clearJailForm = clearJailForm;
window.loadIgnoreIP = loadIgnoreIP;
window.addIgnoreIP = addIgnoreIP;
window.removeIgnoreIP = removeIgnoreIP;
window.editJail = editJail;
window.toggleJail = toggleJail;
window.deleteJail = deleteJail;
window.viewBannedIPs = viewBannedIPs;
window.loadJailConfigs = loadJailConfigs;
window.banIP = banIP;

// ============================================================
// Boot
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    // Navigation
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.addEventListener('click', () => switchView(btn.dataset.view));
    });
    document.getElementById('hamburger').addEventListener('click', openSidebar);
    document.getElementById('sidebar-scrim').addEventListener('click', closeSidebar);

    // Refresh + confirm modal wiring
    document.getElementById('refresh-btn').addEventListener('click', () => {
        fetchJails();
        loadJailConfigs();
        loadIgnoreIP();
        checkHealth();
        toast('info', 'Data refreshed');
    });
    document.getElementById('confirm-ok').addEventListener('click', () => closeConfirm(true));
    document.getElementById('confirm-cancel').addEventListener('click', () => closeConfirm(false));
    document.getElementById('confirm-modal').addEventListener('click', e => {
        if (e.target.id === 'confirm-modal') closeConfirm(false);
    });

    // Jail form + logout
    const jailForm = document.getElementById('jail-form');
    if (jailForm) jailForm.addEventListener('submit', handleJailFormSubmit);
    document.getElementById('logout-btn').addEventListener('click', logout);

    // Custom filter input clears the known-filter selection
    document.getElementById('jail-filter-custom').addEventListener('input', function () {
        if (this.value.trim()) {
            setFilterSelectedUI('');
            document.getElementById('jail-filter').value = '';
        }
    });

    // Auth verification (pairs with auth-pending gate in index.html)
    const token = getToken();
    const reveal = () => { document.documentElement.classList.remove('auth-pending'); document.body.classList.add('auth-ready'); };
    const goLogin = () => window.location.replace('/login.html');
    if (!token) { goLogin(); return; }

    fetch('/api/verify-token', { headers: { 'Authorization': 'Bearer ' + token } })
        .then(response => {
            if (response.status === 401) {
                localStorage.removeItem('token');
                goLogin();
                return Promise.reject(new Error('Token verification failed'));
            }
            if (!response.ok) {
                return Promise.reject(new Error(`Token verification failed: ${response.status}`));
            }
            return response.json();
        })
        .then(() => { reveal(); })
        .catch(error => {
            if (error.message === 'Token verification failed') return;
            reveal(); // network/server error: let API calls decide, don't strand on blank screen
        });

    // Initial data load
    populateFilterOptions();
    fetchJails();
    loadJailConfigs();
    loadIgnoreIP();
    checkHealth();

    // Periodic refresh
    setInterval(fetchJails, REFRESH_MS);
    setInterval(checkHealth, REFRESH_MS);
});

// Inactivity timer
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
