// main.js

// Initialize the frontend application
document.addEventListener("DOMContentLoaded", () => {
    // Set up event listeners and render components
    setupEventListeners();
    renderComponents();
});

// Function to set up event listeners
function setupEventListeners() {
    // Set up jail form submission
    const jailForm = document.getElementById("jail-form");
    if (jailForm) {
        jailForm.addEventListener("submit", handleJailFormSubmit);
    }
    
    // Set up logout button
    const logoutBtn = document.getElementById("logout-btn");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", logout);
    }
}

// Function to render components
function renderComponents() {
    renderJailList();
    renderBannedIPs();
    loadJailConfigs();
}

// Jail Management Functions
let jailTemplates = {};
let ignoreIPList = [];

function showJailConfig() {
    document.getElementById('jails-section').style.display = 'none';
    document.getElementById('banned-ips-section').style.display = 'none';
    document.getElementById('jail-config-section').style.display = 'block';
    loadJailConfigs();
    loadIgnoreIP();
    
    // Initialize filter options
    populateFilterOptions();
}

function onFilterChange(filterValue) {
    const customFilterInput = document.getElementById('jail-filter-custom');
    const filterContent = document.getElementById('filter-content');
    const filterRegex = document.getElementById('filter-regex');
    const jailName = document.getElementById('jail-name');
    const logpathInput = document.getElementById('jail-logpath');
    
    if (filterValue === 'custom') {
        customFilterInput.style.display = 'block';
        customFilterInput.required = true;
        filterContent.style.display = 'none';
        // Clear defaults for custom
        jailName.value = '';
        logpathInput.value = '';
        resetToDefaults();
    } else if (filterValue === '') {
        customFilterInput.style.display = 'none';
        customFilterInput.required = false;
        filterContent.style.display = 'none';
        // Clear all fields
        jailName.value = '';
        logpathInput.value = '';
        resetToDefaults();
    } else {
        customFilterInput.style.display = 'none';
        customFilterInput.required = false;
        // Set smart defaults based on filter
        setFilterDefaults(filterValue);
        // Load filter content
        loadFilterContent(filterValue);
    }
}

function setFilterDefaults(filterValue) {
    const jailName = document.getElementById('jail-name');
    const logpathInput = document.getElementById('jail-logpath');
    
    const filterDefaults = {
        'sshd': {
            name: 'sshd',
            logpath: '%(syslog_authpriv)s',
            maxretry: 3,
            findtime: 3600,
            bantime: 600
        },
        'sshd2': {
            name: 'sshd2',
            logpath: '%(syslog_authpriv)s',
            maxretry: 3,
            findtime: 1800,
            bantime: 3600
        },
        'nginx': {
            name: 'nginx',
            logpath: '/var/log/nginx/access.log',
            maxretry: 5,
            findtime: 600,
            bantime: 3600
        },
        'apache-auth': {
            name: 'apache-auth',
            logpath: '/var/log/apache2/error.log',
            maxretry: 3,
            findtime: 600,
            bantime: 1200
        },
        'postfix': {
            name: 'postfix',
            logpath: '/var/log/mail.log',
            maxretry: 5,
            findtime: 600,
            bantime: 1800
        },
        'dovecot': {
            name: 'dovecot',
            logpath: '/var/log/dovecot.log',
            maxretry: 5,
            findtime: 300,
            bantime: 900
        },
        'vsftpd': {
            name: 'vsftpd',
            logpath: '/var/log/vsftpd.log',
            maxretry: 3,
            findtime: 600,
            bantime: 1800
        },
        'mysqld': {
            name: 'mysqld',
            logpath: '/var/log/mysql/error.log',
            maxretry: 3,
            findtime: 600,
            bantime: 1200
        }
    };
    
    const defaults = filterDefaults[filterValue] || {
        name: filterValue,
        logpath: '/var/log/' + filterValue + '.log',
        maxretry: 3,
        findtime: 3600,
        bantime: 600
    };
    
    jailName.value = defaults.name;
    logpathInput.value = defaults.logpath;
    document.getElementById('jail-maxretry').value = defaults.maxretry;
    document.getElementById('jail-findtime').value = defaults.findtime;
    document.getElementById('jail-bantime').value = defaults.bantime;

    // Hint for sshd users
    if (filterValue === 'sshd' || filterValue === 'sshd2') {
        console.log('%cNote: This jail will automatically use backend=systemd for better reliability in containers', 'color: green; font-weight: bold;');
    }
}

function resetToDefaults() {
    document.getElementById('jail-maxretry').value = 3;
    document.getElementById('jail-findtime').value = 3600;
    document.getElementById('jail-bantime').value = 600;
    document.getElementById('jail-action').value = '';
    document.getElementById('jail-enabled').checked = true;
}

function loadFilterContent(filterName) {
    fetch(`/api/filters/${filterName}`, {
        headers: {
            'Authorization': 'Bearer ' + getToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            const filterContent = document.getElementById('filter-content');
            const filterRegex = document.getElementById('filter-regex');
            
            filterRegex.value = data.content;
            filterContent.style.display = 'block';
        }
    })
    .catch(error => {
        console.error('Error loading filter content:', error);
    });
}

function populateFilterOptions() {
    const filterSelect = document.getElementById('jail-filter');
    
    // Common filter options
    const filters = [
        { value: 'sshd', text: 'SSH (sshd)' },
        { value: 'nginx', text: 'Nginx (nginx)' },
        { value: 'sshd2', text: 'SSH Enhanced (sshd2)' },
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
        { value: 'custom', text: 'Custom (specify below)' }
    ];
    
    filterSelect.innerHTML = '<option value="">Select a filter...</option>';
    filters.forEach(filter => {
        const option = document.createElement('option');
        option.value = filter.value;
        option.textContent = filter.text;
        filterSelect.appendChild(option);
    });
}

function hideJailConfig() {
    document.getElementById('jail-config-section').style.display = 'none';
    document.getElementById('jails-section').style.display = 'block';
    document.getElementById('banned-ips-section').style.display = 'block';
}

function clearJailForm() {
    document.getElementById('jail-form').reset();
    document.getElementById('filter-content').style.display = 'none';
    document.getElementById('jail-filter-custom').style.display = 'none';
}
function loadIgnoreIP() {
    fetch('/api/ignoreip', {
        headers: {
            'Authorization': 'Bearer ' + getToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.ignoreip) {
            ignoreIPList = data.ignoreip;
            renderIgnoreIPList();
        }
    })
    .catch(error => {
        console.error('Error loading ignoreIP:', error);
    });
}

function renderIgnoreIPList() {
    const container = document.getElementById('ignoreip-list');
    container.innerHTML = '';
    
    if (ignoreIPList.length === 0) {
        container.innerHTML = '<p>No ignoreIP entries found.</p>';
        return;
    }
    
    // Allow more IPs per row - let CSS flexbox handle the layout
    // Just create one row with all IPs and let flexbox wrap them
    const rowItem = document.createElement('div');
    rowItem.className = 'ignoreip-row';
    
    const ipContainer = document.createElement('div');
    ipContainer.className = 'ip-container';
    
    ignoreIPList.forEach((ip, index) => {
        const ipItem = document.createElement('div');
        ipItem.className = 'ignoreip-item-inline';
        ipItem.innerHTML = `
            <span class="ip-text">${ip}</span>
            <button class="remove-ip-button-small" onclick="removeIgnoreIP('${ip}')">×</button>
        `;
        ipContainer.appendChild(ipItem);
    });
    
    rowItem.appendChild(ipContainer);
    container.appendChild(rowItem);
}

function addIgnoreIP() {
    const input = document.getElementById('new-ignoreip');
    const ip = input.value.trim();
    
    if (!ip) {
        alert('Please enter an IP address or CIDR range');
        return;
    }
    
    // Basic validation
    const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const cidrRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-2]?[0-9]|3[0-2])$/;
    
    if (!ipRegex.test(ip) && !cidrRegex.test(ip)) {
        alert('Invalid IP or CIDR format. Please use format like 192.168.1.1 or 10.0.0.0/24');
        return;
    }
    
    // Check for duplicates
    if (ignoreIPList.includes(ip)) {
        alert('This IP is already in the ignore list');
        return;
    }
    
    ignoreIPList.push(ip);
    renderIgnoreIPList();
    input.value = '';
}

function removeIgnoreIP(ip) {
    ignoreIPList = ignoreIPList.filter(item => item !== ip);
    renderIgnoreIPList();
}

function saveIgnoreIP() {
    fetch('/api/ignoreip', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + getToken()
        },
        body: JSON.stringify({
            ignoreip: ignoreIPList
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert('ignoreIP configuration saved successfully!');
        } else {
            alert('Error: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Error saving ignoreIP:', error);
        alert('Error saving ignoreIP configuration');
    });
}

function loadTemplates() {
    fetch('/api/jails/templates', {
        headers: {
            'Authorization': 'Bearer ' + getToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.templates) {
            jailTemplates = data.templates;
            populateTemplateSelect();
        }
    })
    .catch(error => {
        console.error('Error loading templates:', error);
    });
}

function populateTemplateSelect() {
    const select = document.getElementById('jail-template');
    // Keep the existing options and add templates
    select.innerHTML = '<option value="">-- Select Template --</option><option value="custom">Custom (configure manually)</option>';
    
    Object.keys(jailTemplates).forEach(templateName => {
        const option = document.createElement('option');
        option.value = templateName;
        option.textContent = templateName.replace('-template', '').charAt(0).toUpperCase() + 
                           templateName.replace('-template', '').slice(1);
        select.appendChild(option);
    });
}

function loadTemplate(templateName) {
    const templateSelect = document.getElementById('jail-template');
    const logpathInput = document.getElementById('jail-logpath');
    const filterSelect = document.getElementById('jail-filter');
    const customFilterInput = document.getElementById('jail-filter-custom');
    
    if (templateName && jailTemplates[templateName]) {
        const template = jailTemplates[templateName];
        
        // Fill form fields
        document.getElementById('jail-maxretry').value = template.maxretry || 3;
        document.getElementById('jail-findtime').value = template.findtime || 3600;
        document.getElementById('jail-bantime').value = template.bantime || 600;
        document.getElementById('jail-action').value = template.action || '';
        logpathInput.value = template.logpath || '';
        
        // Set filter selection
        if (template.filter) {
            filterSelect.value = template.filter;
            customFilterInput.style.display = 'none';
        } else {
            filterSelect.value = 'custom';
            customFilterInput.style.display = 'block';
            customFilterInput.value = template.filter || '';
        }
        
        document.getElementById('jail-enabled').checked = template.enabled !== false;
    }
}

function handleJailFormSubmit(event) {
    event.preventDefault();
    
    const filterSelect = document.getElementById('jail-filter');
    const customFilterInput = document.getElementById('jail-filter-custom');
    
    let filterValue = filterSelect.value;
    if (filterValue === 'custom') {
        filterValue = customFilterInput.value.trim();
        if (!filterValue) {
            alert('Please specify a custom filter name');
            return;
        }
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
    // This prevents the "Have not found any log file for sshd jail" error during reload
    if (formData.filter === 'sshd' || formData.filter === 'sshd2') {
        // Inject backend = systemd directly into the config
        // Our backend supports this via custom parameters in jail.local
        formData.backend = 'systemd';
    }

    // Basic validation
    if (!formData.name || !formData.filter || !formData.logpath) {
        alert('Please fill in all required fields: Name, Filter, and Log Path');
        return;
    }

    const headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + getToken()
    };

    fetch('/api/jails/config', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(formData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            // Instant success feedback
            alert('Jail configuration saved successfully!\n\n' +
                  (data.jail_active 
                             ? '✅ Jail started and is now active!' 
                             : '⚠️ Config saved. Jail will activate on next reload.'));
            clearJailForm();
            loadJailConfigs();
            renderJailList(); // Refresh active jails
            fetchJails();     // Refresh main jails view
        } else {
            alert('Error saving jail: ' + (data.error || 'Unknown error'));
        }
    })
    .catch(error => {
        console.error('Error saving jail config:', error);
        alert('Network error while saving jail configuration');
    });

}

function clearJailForm() {
    document.getElementById('jail-form').reset();
    document.getElementById('jail-enabled').checked = true;
}

function loadJailConfigs() {
    fetch('/api/jails/config', {
        headers: {
            'Authorization': 'Bearer ' + getToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.jails) {
            renderJailConfigs(data.jails);
        }
    })
    .catch(error => {
        console.error('Error loading jail configs:', error);
    });
}

function renderJailConfigs(jails) {
    const container = document.getElementById('jail-config-list');
    container.innerHTML = '';
    
    if (jails.length === 0) {
        container.innerHTML = '<p>No jail configurations found.</p>';
        return;
    }
    
    jails.forEach(jail => {
        const jailItem = document.createElement('div');
        jailItem.className = 'jail-config-item' + (jail.enabled ? '' : ' disabled');
        
        jailItem.innerHTML = `
            <div class="jail-config-header">
                <span class="jail-config-name">${jail.name}</span>
                <span class="jail-config-status ${jail.enabled ? 'enabled' : 'disabled'}">
                    ${jail.enabled ? 'Enabled' : 'Disabled'}
                </span>
            </div>
            <div class="jail-config-details">
                <div><strong>Filter:</strong> ${jail.filter}</div>
                <div><strong>Log Path:</strong> ${jail.logpath}</div>
                <div><strong>Max Retry:</strong> ${jail.maxretry}</div>
                <div><strong>Find Time:</strong> ${jail.findtime}s</div>
                <div><strong>Ban Time:</strong> ${jail.bantime}s</div>
                ${jail.action ? `<div><strong>Action:</strong> ${jail.action}</div>` : ''}
            </div>
            <div class="jail-config-actions">
                <button class="jail-action-btn edit" onclick="editJail('${jail.name}')">Edit</button>
                <button class="jail-action-btn ${jail.enabled ? 'stop' : 'start'}" 
                        onclick="toggleJail('${jail.name}', ${jail.enabled})">
                    ${jail.enabled ? 'Stop' : 'Start'}
                </button>
                <button class="jail-action-btn delete" onclick="deleteJail('${jail.name}')">Delete</button>
            </div>
        `;
        
        container.appendChild(jailItem);
    });
}

function editJail(jailName) {
    fetch('/api/jails/config', {
        headers: {
            'Authorization': 'Bearer ' + getToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        const jail = data.jails.find(j => j.name === jailName);
        if (jail) {
            document.getElementById('jail-name').value = jail.name;
            document.getElementById('jail-filter').value = jail.filter;
            document.getElementById('jail-logpath').value = jail.logpath;
            document.getElementById('jail-maxretry').value = jail.maxretry;
            document.getElementById('jail-findtime').value = jail.findtime;
            document.getElementById('jail-bantime').value = jail.bantime;
            document.getElementById('jail-action').value = jail.action || '';
            document.getElementById('jail-enabled').checked = jail.enabled;
        }
    })
    .catch(error => {
        console.error('Error loading jail for edit:', error);
    });
}

function toggleJail(jailName, currentlyEnabled) {
    const action = currentlyEnabled ? 'stop' : 'start';
    
    fetch(`/api/jails/${jailName}/${action}`, {
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + getToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            loadJailConfigs();
            renderJailList(); // Refresh active jails
        } else {
            alert('Error: ' + data.error);
        }
    })
    .catch(error => {
        console.error(`Error ${action}ing jail:`, error);
        alert(`Error ${action}ing jail`);
    });
}

function deleteJailConfig(jailName) {
    if (!confirm(`Are you sure you want to delete jail ${jailName}? This will stop the jail and remove its configuration.`)) return;
    
    // Show instant loading indicator
    const loadingDiv = document.createElement('div');
    loadingDiv.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: rgba(0, 0, 0, 0.8);
        color: white;
        padding: 20px;
        border-radius: 8px;
        font-family: Arial, sans-serif;
        font-size: 16px;
        z-index: 1000;
        text-align: center;
    `;
    loadingDiv.innerHTML = '<div>Deleting jail and stopping service...</div>';
    document.body.appendChild(loadingDiv);
    
    const headers = {
        'Authorization': 'Bearer ' + getToken()
    };

    fetch(`/api/jails/config/${jailName}`, {
        method: 'DELETE',
        headers: headers
    })
    .then(response => response.json())
    .then(data => {
        document.body.removeChild(loadingDiv);
        if (data.status === 'success') {
            alert(`✅ Jail ${jailName} deleted successfully!`);
            loadJailConfigs();
            renderJailList(); // Refresh active jails
            fetchJails();     // Refresh main jails view
        } else {
            alert('Error deleting jail: ' + (data.error || 'Unknown error'));
        }
    })
    .catch(error => {
        document.body.removeChild(loadingDiv);
        alert('Network error while deleting jail');
    });
}

function deleteJail(jailName) {
    if (confirm(`Are you sure you want to delete the jail "${jailName}"?`)) {
        fetch(`/api/jails/config/${jailName}`, {
            method: 'DELETE',
            headers: {
                'Authorization': 'Bearer ' + getToken()
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                alert('Jail deleted successfully');
                loadJailConfigs();
                renderJailList(); // Refresh active jails
            } else {
                alert('Error: ' + data.error);
            }
        })
        .catch(error => {
            console.error('Error deleting jail:', error);
            alert('Error deleting jail');
        });
    }
}

// ... (rest of the code remains the same)
// Existing functions (modified to work with new structure)
function renderJailList() {
    fetch('/api/jails', {
        headers: {
            'Authorization': 'Bearer ' + getToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        const container = document.getElementById('jails-list');
        container.innerHTML = '';
        
        if (data.jails && data.jails.length > 0) {
            data.jails.forEach(jail => {
                const jailElement = document.createElement('div');
                jailElement.className = 'jail-item';
                jailElement.innerHTML = `
                    <h3>${jail}</h3>
                    <button onclick="viewBannedIPs('${jail}')">View Banned IPs</button>
                `;
                container.appendChild(jailElement);
            });
        } else {
            container.innerHTML = '<p>No active jails found.</p>';
        }
    })
    .catch(error => {
        console.error('Error loading jails:', error);
        document.getElementById('jails-list').innerHTML = '<p>Error loading jails.</p>';
    });
}

function renderBannedIPs() {
    fetch('/api/jails', {
        headers: {
            'Authorization': 'Bearer ' + getToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.jails && data.jails.length > 0) {
            // Load banned IPs for the first jail
            viewBannedIPs(data.jails[0]);
        } else {
            document.getElementById('banned-ips').innerHTML = '<p>No jails to display.</p>';
        }
    })
    .catch(error => {
        console.error('Error loading banned IPs:', error);
        document.getElementById('banned-ips').innerHTML = '<p>Error loading banned IPs.</p>';
    });
}

function viewBannedIPs(jailName) {
    fetch(`/api/banned/${jailName}`, {
        headers: {
            'Authorization': 'Bearer ' + getToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        const container = document.getElementById('banned-ips');
        container.innerHTML = '';
        
        if (data.status) {
            const lines = data.status.split('\n');
            const bannedIPs = [];
            
            lines.forEach(line => {
                if (line.includes('Banned IP list:')) {
                    const ips = line.split('Banned IP list:')[1].trim();
                    if (ips) {
                        bannedIPs.push(...ips.split(' '));
                    }
                }
            });
            
            if (bannedIPs.length > 0) {
                const listElement = document.createElement('div');
                listElement.innerHTML = `<h3>Banned IPs in ${jailName}</h3>`;
                
                const ipList = document.createElement('div');
                ipList.className = 'ip-list';
                
                bannedIPs.forEach(ip => {
                    const ipElement = document.createElement('div');
                    ipElement.className = 'ip-item';
                    ipElement.innerHTML = `
                        <span>${ip}</span>
                        <button onclick="unbanIP('${jailName}', '${ip}')">Unban</button>
                    `;
                    ipList.appendChild(ipElement);
                });
                
                listElement.appendChild(ipList);
                container.appendChild(listElement);
            } else {
                container.innerHTML = `<p>No banned IPs in ${jailName}.</p>`;
            }
        } else {
            container.innerHTML = '<p>Error loading banned IPs.</p>';
        }
    })
    .catch(error => {
        console.error('Error loading banned IPs:', error);
        document.getElementById('banned-ips').innerHTML = '<p>Error loading banned IPs.</p>';
    });
}

function banIP() {
    const jailSelect = document.createElement('select');
    // Populate with current jails
    fetch('/api/jails', {
        headers: {
            'Authorization': 'Bearer ' + getToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.jails && data.jails.length > 0) {
            data.jails.forEach(jail => {
                const option = document.createElement('option');
                option.value = jail;
                option.textContent = jail;
                jailSelect.appendChild(option);
            });
        }
    });
    
    const ip = document.getElementById('ip-to-ban').value;
    if (!ip) {
        alert('Please enter an IP address to ban');
        return;
    }
    
    // For simplicity, use the first available jail
    fetch('/api/jails', {
        headers: {
            'Authorization': 'Bearer ' + getToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.jails && data.jails.length > 0) {
            const jail = data.jails[0];
            
            fetch('/api/ban', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + getToken()
                },
                body: JSON.stringify({
                    jail: jail,
                    ip: ip
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success' || data.status === 'warning') {
                    alert(data.message);
                    document.getElementById('ip-to-ban').value = '';
                    renderBannedIPs();
                } else {
                    alert('Error: ' + data.error);
                }
            })
            .catch(error => {
                console.error('Error banning IP:', error);
                alert('Error banning IP');
            });
        }
    });
}

function unbanIP(jailName, ipAddress) {
    fetch('/api/unban', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + getToken()
        },
        body: JSON.stringify({
            jail: jailName,
            ip: ipAddress
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert('IP unbanned successfully');
            renderBannedIPs();
        } else {
            alert('Error: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Error unbanning IP:', error);
        alert('Error unbanning IP');
    });
}

function filterIPs() {
    const searchTerm = document.getElementById('ip-search').value.toLowerCase();
    const ipItems = document.querySelectorAll('.ip-item');
    
    ipItems.forEach(item => {
        const ipText = item.textContent.toLowerCase();
        if (ipText.includes(searchTerm)) {
            item.style.display = 'block';
        } else {
            item.style.display = 'none';
        }
    });
}

// Utility functions
function getToken() {
    return localStorage.getItem('token') || document.cookie.replace(/(?:(?:^|.*;\s*)token\s*\=\s*([^;]*).*$)|^.*$/, "$1");
}

function logout() {
    localStorage.removeItem('token');
    document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    window.location.replace('/login.html');
}

// Check authentication on page load
document.addEventListener('DOMContentLoaded', function() {
    const token = getToken();
    if (!token) {
        window.location.replace('/login.html');
        return;
    }
    
    // Verify token is valid
    fetch('/api/verify-token', {
        headers: {
            'Authorization': 'Bearer ' + token
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Token invalid');
        }
        return response.json();
    })
    .then(data => {
        // Token is valid, continue
    })
    .catch(error => {
        console.error('Token verification failed:', error);
        logout();
    });
});

function fetchJails() {
    const token = getToken();
    const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    };
    
    fetch('/api/jails', { headers })
        .then(response => {
            if (response.status === 401) {
                // Token expired or invalid
                localStorage.removeItem('token');
                window.location.href = '/login.html';
                return;
            }
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            
            const jailsList = document.getElementById('jails-list');
            if (!Array.isArray(data.jails) || data.jails.length === 0) {
                jailsList.innerHTML = '<p>No active jails found</p>';
                return;
            }

            const table = document.createElement('table');
            table.className = 'jails-table';
            const tbody = document.createElement('tbody');
            
            // Calculate number of columns based on window width
            const windowWidth = window.innerWidth;
            const columns = windowWidth > 1200 ? 4 : windowWidth > 768 ? 3 : windowWidth > 480 ? 2 : 1;
            
            // Create rows
            for (let i = 0; i < data.jails.length; i += columns) {
                const row = document.createElement('tr');
                for (let j = 0; j < columns; j++) {
                    if (i + j < data.jails.length) {
                        const jail = data.jails[i + j];
                        const cell = document.createElement('td');
                        cell.innerHTML = `
                            <div class="jail-cell">
                                <input type="radio" 
                                       id="jail-${jail}" 
                                       name="jail-selection" 
                                       value="${jail}"
                                       onchange="handleJailSelection('${jail}')">
                                <label for="jail-${jail}">${jail}</label>
                            </div>
                        `;
                        row.appendChild(cell);
                    }
                }
                tbody.appendChild(row);
            }
            
            table.appendChild(tbody);
            jailsList.innerHTML = '';
            jailsList.appendChild(table);
        })
        .catch(error => {
            console.error('Error fetching jails:', error);
            document.getElementById('jails-list').innerHTML = 
                `<div class="error-message">Error: ${error.message}</div>`;
        });
}

// Make handleJailSelection available globally
window.handleJailSelection = function(jail) {
    // Remove active class from all cells
    document.querySelectorAll('.jail-cell').forEach(cell => {
        cell.classList.remove('active');
    });
    
    // Add active class to selected cell
    const selectedInput = document.getElementById(`jail-${jail}`);
    if (selectedInput) {
        selectedInput.closest('.jail-cell').classList.add('active');
    }
    
    // Fetch jail details
    fetchJailDetails(jail);
};

window.fetchJailDetails = function(jail) {
    const token = getToken();
    const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    };
    
    fetch(`/api/banned/${jail}`, { headers })
        .then(response => response.json())
        .then(data => {
            const bannedIPsContainer = document.getElementById('banned-ips');
            const { bannedIPs } = parseJailStatus(data.status);
            
            bannedIPsContainer.innerHTML = `
                <table class="ip-table" id="ip-table"></table>
            `;
            
            renderIPTable(document.getElementById('ip-table'), bannedIPs, jail);
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('banned-ips').innerHTML = 
                `<div class="error-message">Error fetching jail details</div>`;
        });
};

// Update unbanIP to use headers
window.unbanIP = function(jail, ip) {
    if (!confirm(`Are you sure you want to unban ${ip} from ${jail}?`)) return;

    const token = getToken();
    const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    };

    fetch('/api/unban', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({ jail, ip })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) throw new Error(data.error);
        // Refresh the jail details after successful unban
        fetchJailDetails(jail);
    })
    .catch(error => {
        console.error('Error:', error);
        alert(`Failed to unban IP: ${error.message}`);
    });
};

// Initialize inactivity timer
let inactivityTimer;
function resetInactivityTimer() {
    clearTimeout(inactivityTimer);
    inactivityTimer = setTimeout(() => {
        localStorage.removeItem('token');
        window.location.href = '/login.html';
    }, 60000); // 1 minute timeout
}

// Reset timer on activity
document.addEventListener('mousemove', resetInactivityTimer);
document.addEventListener('keypress', resetInactivityTimer);
resetInactivityTimer();

// Add logout handler
document.getElementById('logout-btn').addEventListener('click', function() {
    localStorage.removeItem('token');
    // Clear the cookie by setting it to expire
    document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    window.location.replace('/login.html');
});

// Initial load
fetchJails();
    
// Refresh every 30 seconds
setInterval(fetchJails, 30000);

function parseJailStatus(statusText) {
    const bannedIPsMatch = statusText.match(/Banned IP list:\t(.+)$/);
    if (!bannedIPsMatch) return { bannedIPs: [] };

    const bannedIPs = bannedIPsMatch[1].split(' ').filter(ip => ip.trim());
    return { bannedIPs };
}

function isSubnet(ip) {
    return ip.includes('/');
}

// Add function to render IP table
function renderIPTable(table, ips, jail) {
    const tbody = document.createElement('tbody');
    const windowWidth = window.innerWidth;
    const columns = windowWidth > 1200 ? 4 : windowWidth > 768 ? 3 : windowWidth > 480 ? 2 : 1;
    
    for (let i = 0; i < ips.length; i += columns) {
        const row = document.createElement('tr');
        for (let j = 0; j < columns; j++) {
            if (i + j < ips.length) {
                const ip = ips[i + j];
                const cell = document.createElement('td');
                cell.innerHTML = `
                    <div class="ip-cell ${isSubnet(ip) ? 'subnet' : ''}">
                        <span>${ip}</span>
                        <button onclick="unbanIP('${jail}', '${ip}')" class="unban-button">
                            <svg viewBox="0 0 24 24" width="16" height="16">
                                <path fill="currentColor" d="M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z"/>
                            </svg>
                        </button>
                    </div>
                `;
                row.appendChild(cell);
            }
        }
        tbody.appendChild(row);
    }
    
    table.appendChild(tbody);
}

// Add global filter function
window.filterIPs = function() {
    const searchInput = document.getElementById('ip-search');
    const filter = searchInput.value.toLowerCase();
    const table = document.getElementById('ip-table');
    const cells = table.getElementsByClassName('ip-cell');

    for (let cell of cells) {
        const ip = cell.querySelector('span').textContent;
        if (ip.toLowerCase().includes(filter)) {
            cell.closest('td').style.display = "";
        } else {
            cell.closest('td').style.display = "none";
        }
    }
}
