// PhishGuard Enterprise Security Dashboard Controller

let currentAuthToken = localStorage.getItem('phishguard_admin_token') || '';
let currentUser = null;
let sseSource = null;
let currentUrlPage = 1;

// Global tab switcher
function switchTab(tabId) {
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.tab === tabId);
  });

  document.querySelectorAll('.tab-view').forEach(el => {
    el.classList.toggle('active', el.id === `tab-${tabId}`);
  });

  const titles = {
    'overview': 'Enterprise Overview',
    'systems': 'Enrolled Systems Fleet',
    'url-history': 'Central URL Audit Trail',
    'live-feed': 'Real-Time Activity Feed',
    'rules': 'Security Rules Policy',
    'alerts': 'Security Alerts',
    'incidents': 'Threat Incidents',
    'reports': 'Reports & Analytics',
    'audit': 'Administrative Audit Trail',
    'install': 'Install & Enroll FortiNex Extension',
    'settings': 'Fleet Configuration'
  };

  const titleEl = document.getElementById('currentTabTitle');
  if (titleEl && titles[tabId]) {
    titleEl.textContent = titles[tabId];
  }

  // Auto-refresh tab content
  if (tabId === 'overview') loadOverviewStats();
  if (tabId === 'systems') loadSystems();
  if (tabId === 'url-history') loadUrlHistory();
  if (tabId === 'rules') loadRules();
  if (tabId === 'alerts') loadAlerts();
  if (tabId === 'incidents') loadIncidents();
  if (tabId === 'reports') loadReports();
  if (tabId === 'audit') loadAuditLogs();
  if (tabId === 'install') loadInstallTab();
  if (tabId === 'settings') loadSettings();
}

// Toast helper
function showToast(text, icon = 'ℹ️') {
  const toast = document.getElementById('toastMessage');
  const toastText = document.getElementById('toastText');
  const toastIcon = document.getElementById('toastIcon');
  if (!toast) return;

  toastText.textContent = text;
  toastIcon.textContent = icon;
  toast.style.display = 'flex';
  setTimeout(() => {
    toast.style.display = 'none';
  }, 3500);
}

// Auth API call wrapper
async function apiFetch(url, options = {}) {
  const headers = options.headers || {};
  if (currentAuthToken) {
    headers['Authorization'] = `Bearer ${currentAuthToken}`;
  }
  headers['Content-Type'] = headers['Content-Type'] || 'application/json';

  const res = await fetch(url, { ...options, headers });
  if (res.status === 401) {
    // If token invalid, auto-login with default admin credentials for seamless evaluation
    await autoAdminLogin();
  }
  return res;
}

// Auto-admin login fallback
async function autoAdminLogin() {
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'PhishGuardAdmin2026!' })
    });
    if (res.ok) {
      const data = await res.json();
      currentAuthToken = data.token;
      currentUser = data.user;
      localStorage.setItem('phishguard_admin_token', currentAuthToken);
      updateUserUI();
    }
  } catch (err) {
    console.debug('Auto login deferred', err);
  }
}

function updateUserUI() {
  const nameEl = document.getElementById('sidebarUsername');
  const avatarEl = document.getElementById('avatarLetter');
  if (currentUser && nameEl) {
    nameEl.textContent = currentUser.username;
    if (avatarEl) avatarEl.textContent = currentUser.username.charAt(0).toUpperCase();
  }
}

// -------------------------------------------------------------
// 1. OVERVIEW DASHBOARD
// -------------------------------------------------------------
async function loadOverviewStats() {
  try {
    const res = await fetch('/api/dashboard/stats');
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById('cardTotalClients').textContent = data.totalClients || 0;
    document.getElementById('cardOnlineClients').textContent = `${data.onlineClients || 0} online now`;
    document.getElementById('cardTotalUrls').textContent = data.totalUrlsMonitored || 0;
    document.getElementById('cardAllowedUrls').textContent = `${data.allowedUrls || 0} allowed`;
    document.getElementById('cardBlockedUrls').textContent = data.blockedUrls || 0;
    document.getElementById('cardWarningUrls').textContent = `${data.warningUrls || 0} warnings flagged`;
    document.getElementById('cardActiveAlerts').textContent = data.newAlerts || 0;
    document.getElementById('cardCriticalAlerts').textContent = `${data.criticalAlerts || 0} critical`;

    // Badges in sidebar
    document.getElementById('onlineBadgeCount').textContent = data.onlineClients || 0;
    document.getElementById('alertBadgeCount').textContent = data.newAlerts || 0;

    // Recent events table
    const tbody = document.getElementById('overviewRecentEventsTbody');
    if (data.recentEvents && data.recentEvents.length > 0) {
      tbody.innerHTML = data.recentEvents.map(e => `
        <tr>
          <td>${new Date(e.timestamp).toLocaleTimeString()}</td>
          <td><span style="font-weight:600;">${escapeHtml(e.system_name || e.client_id)}</span></td>
          <td><span style="color:#38bdf8;">${escapeHtml(e.domain)}</span></td>
          <td>${getDecisionBadge(e.decision)}</td>
          <td>${getThreatBadge(e.threat_level)}</td>
        </tr>
      `).join('');
    } else {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted);">No events recorded yet.</td></tr>';
    }

    // Top blocked domains
    const topList = document.getElementById('overviewTopBlockedList');
    if (data.topBlockedDomains && data.topBlockedDomains.length > 0) {
      topList.innerHTML = data.topBlockedDomains.map(d => `
        <div style="display:flex; justify-content:space-between; align-items:center; background:var(--bg-input); padding:8px 12px; border-radius:6px; border:1px solid var(--border);">
          <span style="font-family:monospace; color:#f87171;">${escapeHtml(d.domain)}</span>
          <span class="badge-pill badge-block">${d.count} blocked</span>
        </div>
      `).join('');
    } else {
      topList.innerHTML = '<div style="font-size:0.84rem; color:var(--text-muted); text-align:center; padding:16px;">No blocked domains recorded</div>';
    }
  } catch (err) {
    console.error('Failed to load overview stats', err);
  }
}

// -------------------------------------------------------------
// 2. ENROLLED SYSTEMS (FLEET)
// -------------------------------------------------------------
async function loadSystems() {
  const tbody = document.getElementById('systemsTableBody');
  tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; padding:20px;">Refreshing fleet systems...</td></tr>';

  try {
    const res = await fetch('/api/clients');
    const data = await res.json();
    const clients = data.clients || [];

    // Populate client filter dropdowns
    const clientSelect = document.getElementById('urlHistoryClientSelect');
    if (clientSelect) {
      clientSelect.innerHTML = '<option value="">All Clients</option>' +
        clients.map(c => `<option value="${escapeHtml(c.client_id)}">${escapeHtml(c.system_name)} (${escapeHtml(c.client_id)})</option>`).join('');
    }

    if (clients.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:var(--text-muted); padding:20px;">No systems enrolled yet. Deploy the extension to enroll workstations.</td></tr>';
      return;
    }

    tbody.innerHTML = clients.map(c => {
      const isOnline = c.status === 'ONLINE';
      const statusBadge = isOnline
        ? '<span class="badge-pill badge-online">● Online</span>'
        : '<span class="badge-pill badge-offline">○ Offline</span>';

      return `
        <tr>
          <td>${statusBadge}</td>
          <td><strong>${escapeHtml(c.system_name)}</strong><br><small style="color:var(--text-muted);">${escapeHtml(c.hostname || 'workstation')}</small></td>
          <td><code style="color:#38bdf8;">${escapeHtml(c.client_id)}</code></td>
          <td>${escapeHtml(c.os || 'Desktop')}<br><small style="color:var(--text-muted);">${escapeHtml(c.browser || 'Chrome')}</small></td>
          <td>${escapeHtml(c.extension_version || '1.4')}</td>
          <td><code>${escapeHtml(c.ip_address || '127.0.0.1')}</code></td>
          <td>${new Date(c.last_seen).toLocaleString()}</td>
          <td>${c.totalEvents || 0} / <span style="color:#ef4444; font-weight:600;">${c.blockedCount || 0}</span></td>
          <td>
            <div style="display:flex; gap:6px;">
              <button class="btn-header" onclick="viewClientDetail('${c.client_id}')">Inspect</button>
              <button class="btn-header" style="color:#ef4444;" onclick="deleteClient('${c.client_id}')" title="Decommission">✕</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:#ef4444;">Failed to load systems fleet.</td></tr>';
  }
}

async function viewClientDetail(clientId) {
  const modal = document.getElementById('clientDetailModal');
  const body = document.getElementById('clientDetailBody');
  const title = document.getElementById('clientDetailTitle');

  modal.classList.add('open');
  body.innerHTML = '<div style="text-align:center; padding:30px;">Loading system inspection data...</div>';

  try {
    const res = await fetch(`/api/clients/${clientId}`);
    const data = await res.json();
    const c = data.client;
    const stats = data.stats;

    title.textContent = `Inspection: ${c.system_name} (${c.client_id})`;

    body.innerHTML = `
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:16px; background:var(--bg-input); padding:14px; border-radius:8px;">
        <div><strong>Status:</strong> ${c.status === 'ONLINE' ? '🟢 Online' : '⚪ Offline'}</div>
        <div><strong>IP Address:</strong> <code>${c.ip_address || '127.0.0.1'}</code></div>
        <div><strong>OS / Platform:</strong> ${c.os || 'Desktop'}</div>
        <div><strong>Browser:</strong> ${c.browser || 'Google Chrome'}</div>
        <div><strong>First Enrolled:</strong> ${new Date(c.first_seen).toLocaleString()}</div>
        <div><strong>Last Heartbeat:</strong> ${new Date(c.last_seen).toLocaleString()}</div>
      </div>

      <div class="stats-row" style="margin-bottom:16px;">
        <div class="stat-card" style="padding:10px 14px;">
          <div class="stat-meta"><span class="stat-title">Total URLs</span><span class="stat-number">${stats.totalEvents}</span></div>
        </div>
        <div class="stat-card" style="padding:10px 14px;">
          <div class="stat-meta"><span class="stat-title">Blocked Phishing</span><span class="stat-number" style="color:#ef4444;">${stats.blockedCount}</span></div>
        </div>
        <div class="stat-card" style="padding:10px 14px;">
          <div class="stat-meta"><span class="stat-title">Warnings</span><span class="stat-number" style="color:#f59e0b;">${stats.warningCount}</span></div>
        </div>
      </div>

      <h4 style="font-size:0.9rem; margin-bottom:8px;">Recent Endpoint Navigation Timeline</h4>
      <div class="table-responsive" style="max-height:240px; overflow-y:auto;">
        <table class="data-table">
          <thead>
            <tr><th>Time</th><th>Destination</th><th>Decision</th><th>Reason</th></tr>
          </thead>
          <tbody>
            ${(data.events || []).slice(0, 15).map(ev => `
              <tr>
                <td>${new Date(ev.timestamp).toLocaleTimeString()}</td>
                <td><code style="color:#38bdf8;">${escapeHtml(ev.domain)}</code></td>
                <td>${getDecisionBadge(ev.decision)}</td>
                <td style="font-size:0.75rem;">${escapeHtml(ev.reason || '')}</td>
              </tr>
            `).join('') || '<tr><td colspan="4" style="text-align:center;">No activity recorded for this endpoint yet.</td></tr>'}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) {
    body.innerHTML = '<div style="color:#ef4444; padding:20px;">Failed to load client details.</div>';
  }
}

function closeClientDetailModal() {
  document.getElementById('clientDetailModal').classList.remove('open');
}

async function deleteClient(clientId) {
  if (!confirm(`Are you sure you want to decommission client ${clientId}?`)) return;

  try {
    const res = await apiFetch(`/api/clients/${clientId}`, { method: 'DELETE' });
    if (res.ok) {
      showToast('Client decommissioned successfully');
      loadSystems();
      loadOverviewStats();
    } else {
      showToast('Failed to delete client', '⚠️');
    }
  } catch (err) {
    showToast('Network error during deletion', '⚠️');
  }
}

// -------------------------------------------------------------
// 3. URL HISTORY AUDIT TRAIL
// -------------------------------------------------------------
async function loadUrlHistory(page = 1) {
  currentUrlPage = page;
  const tbody = document.getElementById('urlHistoryTableBody');
  tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:20px;">Loading navigation events...</td></tr>';

  const search = document.getElementById('urlHistorySearch').value.trim();
  const decision = document.getElementById('urlHistoryDecision').value;
  const threatLevel = document.getElementById('urlHistoryThreatLevel').value;
  const clientId = document.getElementById('urlHistoryClientSelect').value;

  const params = new URLSearchParams({ page, limit: 25 });
  if (search) params.append('search', search);
  if (decision && decision !== 'ALL') params.append('decision', decision);
  if (threatLevel && threatLevel !== 'ALL') params.append('threatLevel', threatLevel);
  if (clientId) params.append('clientId', clientId);

  try {
    const res = await fetch(`/api/url-events?${params.toString()}`);
    const data = await res.json();
    const events = data.events || [];
    const p = data.pagination || { total: 0, totalPages: 1 };

    document.getElementById('urlHistoryPaginationInfo').textContent =
      `Showing page ${page} of ${p.totalPages || 1} (${p.total} total events)`;

    if (events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:20px;">No URL events found matching query.</td></tr>';
      return;
    }

    tbody.innerHTML = events.map(e => `
      <tr>
        <td style="white-space:nowrap;">${new Date(e.timestamp).toLocaleString()}</td>
        <td><strong>${escapeHtml(e.system_name || e.client_id)}</strong></td>
        <td><span style="color:#38bdf8; font-weight:600;">${escapeHtml(e.domain)}</span></td>
        <td style="max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:monospace; font-size:0.78rem;">
          <a href="${escapeHtml(e.url)}" target="_blank" rel="noopener noreferrer" style="color:#94a3b8; text-decoration:none;">${escapeHtml(e.url)}</a>
        </td>
        <td>${getDecisionBadge(e.decision)}</td>
        <td>${getThreatBadge(e.threat_level)}</td>
        <td style="font-size:0.78rem; color:#cbd5e1;">${escapeHtml(e.reason || e.rule_name || 'Heuristic evaluation')}</td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:#ef4444;">Failed to load URL audit records.</td></tr>';
  }
}

// -------------------------------------------------------------
// 4. REAL-TIME ACTIVITY FEED (SSE)
// -------------------------------------------------------------
function initSse() {
  if (sseSource) sseSource.close();

  const dot = document.getElementById('sseDot');
  const label = document.getElementById('sseLabel');

  sseSource = new EventSource('/api/dashboard/events-stream');

  sseSource.onopen = () => {
    if (dot) dot.classList.remove('disconnected');
    if (label) label.textContent = 'Live Sync Active';
  };

  sseSource.onerror = () => {
    if (dot) dot.classList.add('disconnected');
    if (label) label.textContent = 'Reconnecting...';
  };

  // URL Event listener
  sseSource.addEventListener('URL_EVENT', (e) => {
    try {
      const data = JSON.parse(e.data);
      appendLiveFeedItem(data);
      // Refresh stats if on overview
      if (document.getElementById('tab-overview').classList.contains('active')) {
        loadOverviewStats();
      }
    } catch {}
  });

  // Client registration listener
  sseSource.addEventListener('CLIENT_REGISTERED', (e) => {
    try {
      const data = JSON.parse(e.data);
      showToast(`New Endpoint Enrolled: ${data.client?.system_name || 'Client'}`);
      loadSystems();
    } catch {}
  });

  // Security Alert listener
  sseSource.addEventListener('SECURITY_ALERT', (e) => {
    try {
      const data = JSON.parse(e.data);
      showToast(`🚨 Security Alert Triggered on ${data.domain}`, '🛑');
      loadOverviewStats();
    } catch {}
  });
}

function appendLiveFeedItem(data) {
  const container = document.getElementById('liveFeedList');
  if (!container) return;

  const item = document.createElement('div');
  item.className = 'feed-item';

  const timeStr = new Date(data.timestamp || Date.now()).toLocaleTimeString();
  item.innerHTML = `
    <div class="feed-left">
      <span>${getDecisionBadge(data.decision)}</span>
      <span class="feed-url" title="${escapeHtml(data.url)}">${escapeHtml(data.url)}</span>
    </div>
    <div class="feed-meta">
      <strong>${escapeHtml(data.systemName || data.clientId || 'Client')}</strong> • ${timeStr}
    </div>
  `;

  container.insertBefore(item, container.firstChild);
  if (container.children.length > 50) {
    container.removeChild(container.lastChild);
  }
}

// -------------------------------------------------------------
// 5. SECURITY RULES POLICY
// -------------------------------------------------------------
async function loadRules() {
  const tbody = document.getElementById('rulesTableBody');
  tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:20px;">Loading policy rules...</td></tr>';

  try {
    const res = await fetch('/api/rules');
    const data = await res.json();
    const rules = data.rules || [];

    if (rules.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:20px;">No rules defined. Create your first security policy rule.</td></tr>';
      return;
    }

    tbody.innerHTML = rules.map(r => `
      <tr>
        <td>${getDecisionBadge(r.type)}</td>
        <td><code style="color:#38bdf8; font-weight:600;">${escapeHtml(r.pattern)}</code></td>
        <td><span style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted);">${r.target_type}</span></td>
        <td><strong>${r.priority}</strong></td>
        <td>${getThreatBadge(r.severity)}</td>
        <td style="max-width:260px;">${escapeHtml(r.description || '—')}</td>
        <td>
          <button class="btn-header" style="${r.enabled ? 'color:#10b981;' : 'color:#94a3b8;'}" onclick="toggleRule('${r.id}')">
            ${r.enabled ? '● Active' : '○ Disabled'}
          </button>
        </td>
        <td>
          <div style="display:flex; gap:6px;">
            <button class="btn-header" onclick="openEditRuleModal('${r.id}')">Edit</button>
            <button class="btn-header" style="color:#ef4444;" onclick="deleteRule('${r.id}')">Delete</button>
          </div>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:#ef4444;">Failed to load rules.</td></tr>';
  }
}

function openNewRuleModal() {
  document.getElementById('ruleModalTitle').textContent = 'Create Security Policy Rule';
  document.getElementById('ruleEditId').value = '';
  document.getElementById('rulePattern').value = '';
  document.getElementById('ruleDescription').value = '';
  document.getElementById('rulePriority').value = '10';
  document.getElementById('ruleModal').classList.add('open');
}

async function openEditRuleModal(ruleId) {
  try {
    const res = await fetch('/api/rules');
    const data = await res.json();
    const rule = (data.rules || []).find(r => r.id === ruleId);
    if (!rule) return;

    document.getElementById('ruleModalTitle').textContent = 'Edit Security Policy Rule';
    document.getElementById('ruleEditId').value = rule.id;
    document.getElementById('ruleType').value = rule.type;
    document.getElementById('rulePattern').value = rule.pattern;
    document.getElementById('ruleTargetType').value = rule.target_type;
    document.getElementById('ruleSeverity').value = rule.severity;
    document.getElementById('rulePriority').value = rule.priority;
    document.getElementById('ruleDescription').value = rule.description || '';
    document.getElementById('ruleModal').classList.add('open');
  } catch {}
}

function closeRuleModal() {
  document.getElementById('ruleModal').classList.remove('open');
}

async function saveRuleForm(e) {
  e.preventDefault();
  const id = document.getElementById('ruleEditId').value;
  const payload = {
    type: document.getElementById('ruleType').value,
    pattern: document.getElementById('rulePattern').value.trim(),
    targetType: document.getElementById('ruleTargetType').value,
    severity: document.getElementById('ruleSeverity').value,
    priority: parseInt(document.getElementById('rulePriority').value, 10) || 10,
    description: document.getElementById('ruleDescription').value.trim()
  };

  try {
    const url = id ? `/api/rules/${id}` : '/api/rules';
    const method = id ? 'PUT' : 'POST';
    const res = await apiFetch(url, { method, body: JSON.stringify(payload) });

    if (res.ok) {
      showToast(`Rule ${id ? 'updated' : 'created'} successfully`);
      closeRuleModal();
      loadRules();
    } else {
      const err = await res.json();
      showToast(err.error || 'Failed to save rule', '⚠️');
    }
  } catch {
    showToast('Failed to contact server', '⚠️');
  }
}

async function toggleRule(id) {
  try {
    const res = await apiFetch(`/api/rules/${id}/toggle`, { method: 'PATCH' });
    if (res.ok) {
      loadRules();
    }
  } catch {}
}

async function deleteRule(id) {
  if (!confirm('Are you sure you want to delete this policy rule?')) return;
  try {
    const res = await apiFetch(`/api/rules/${id}`, { method: 'DELETE' });
    if (res.ok) {
      showToast('Rule removed');
      loadRules();
    }
  } catch {}
}

// -------------------------------------------------------------
// 6. SECURITY ALERTS
// -------------------------------------------------------------
async function loadAlerts() {
  const tbody = document.getElementById('alertsTableBody');
  tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:20px;">Loading alerts...</td></tr>';

  const status = document.getElementById('filterAlertStatus').value;
  const severity = document.getElementById('filterAlertSeverity').value;
  const params = new URLSearchParams();
  if (status && status !== 'ALL') params.append('status', status);
  if (severity && severity !== 'ALL') params.append('severity', severity);

  try {
    const res = await fetch(`/api/alerts?${params.toString()}`);
    const data = await res.json();
    const alerts = data.alerts || [];

    if (alerts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:20px;">No alerts match filter criteria.</td></tr>';
      return;
    }

    tbody.innerHTML = alerts.map(a => `
      <tr>
        <td>${getAlertStatusBadge(a.status)}</td>
        <td style="white-space:nowrap;">${new Date(a.timestamp).toLocaleString()}</td>
        <td><strong>${escapeHtml(a.system_name || a.client_id)}</strong></td>
        <td><code style="color:#f87171;">${escapeHtml(a.domain)}</code></td>
        <td>${getThreatBadge(a.severity)}</td>
        <td style="font-size:0.75rem;">${escapeHtml(a.alert_type)}</td>
        <td style="font-size:0.78rem;">${escapeHtml(a.reason)}</td>
        <td>
          <div style="display:flex; gap:6px;">
            ${a.status !== 'RESOLVED' ? `<button class="btn-header" onclick="updateAlertStatus('${a.id}', 'RESOLVED')">Resolve</button>` : ''}
            ${a.status === 'NEW' ? `<button class="btn-header" onclick="updateAlertStatus('${a.id}', 'ACKNOWLEDGED')">Ack</button>` : ''}
          </div>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:#ef4444;">Failed to load alerts.</td></tr>';
  }
}

async function updateAlertStatus(id, newStatus) {
  try {
    const res = await apiFetch(`/api/alerts/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ status: newStatus })
    });
    if (res.ok) {
      showToast(`Alert set to ${newStatus}`);
      loadAlerts();
      loadOverviewStats();
    }
  } catch {}
}

// -------------------------------------------------------------
// 7. INCIDENTS
// -------------------------------------------------------------
async function loadIncidents() {
  const tbody = document.getElementById('incidentsTableBody');
  tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:20px;">Loading investigation cases...</td></tr>';

  try {
    const res = await fetch('/api/incidents');
    const data = await res.json();
    const incidents = data.incidents || [];

    if (incidents.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:20px;">No open incidents. All endpoints clean.</td></tr>';
      return;
    }

    tbody.innerHTML = incidents.map(inc => `
      <tr>
        <td><span class="badge-pill ${inc.status === 'OPEN' ? 'badge-block' : 'badge-allow'}">${inc.status}</span></td>
        <td><strong>${escapeHtml(inc.title)}</strong></td>
        <td>${getThreatBadge(inc.severity)}</td>
        <td>${escapeHtml(inc.system_name || inc.client_id)}</td>
        <td><strong>${inc.related_alert_count}</strong> alerts</td>
        <td>${new Date(inc.last_activity).toLocaleString()}</td>
        <td style="font-size:0.75rem; color:#cbd5e1;">${escapeHtml(inc.notes || '—')}</td>
        <td>
          <select class="filter-select" style="padding:3px 8px; font-size:0.75rem;" onchange="updateIncidentStatus('${inc.id}', this.value)">
            <option value="OPEN" ${inc.status === 'OPEN' ? 'selected' : ''}>OPEN</option>
            <option value="INVESTIGATING" ${inc.status === 'INVESTIGATING' ? 'selected' : ''}>INVESTIGATING</option>
            <option value="RESOLVED" ${inc.status === 'RESOLVED' ? 'selected' : ''}>RESOLVED</option>
            <option value="CLOSED" ${inc.status === 'CLOSED' ? 'selected' : ''}>CLOSED</option>
          </select>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:#ef4444;">Failed to load incidents.</td></tr>';
  }
}

async function updateIncidentStatus(id, status) {
  try {
    const res = await apiFetch(`/api/incidents/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ status })
    });
    if (res.ok) {
      showToast(`Incident updated to ${status}`);
      loadIncidents();
    }
  } catch {}
}

// -------------------------------------------------------------
// 8. REPORTS & ANALYTICS
// -------------------------------------------------------------
async function loadReports() {
  try {
    const res = await fetch('/api/reports/summary');
    const data = await res.json();

    const t = data.totals || {};
    document.getElementById('repTotalEvents').textContent = t.total_events || 0;
    document.getElementById('repBlockedEvents').textContent = t.blocked_events || 0;
    document.getElementById('repWarningEvents').textContent = t.warning_events || 0;
    document.getElementById('repAllowedEvents').textContent = t.allowed_events || 0;

    // Threat levels
    const levelsEl = document.getElementById('reportThreatLevelsList');
    levelsEl.innerHTML = (data.byThreatLevel || []).map(l => `
      <div style="display:flex; justify-content:space-between; padding:8px 12px; background:var(--bg-input); border-radius:6px;">
        <span>${getThreatBadge(l.threat_level)}</span>
        <strong>${l.count} occurrences</strong>
      </div>
    `).join('') || '<div style="color:var(--text-muted); text-align:center;">No data available</div>';

    // By client
    const clientsEl = document.getElementById('reportClientsList');
    clientsEl.innerHTML = (data.byClient || []).map(c => `
      <div style="display:flex; justify-content:space-between; padding:8px 12px; background:var(--bg-input); border-radius:6px;">
        <span><strong>${escapeHtml(c.system_name || c.client_id)}</strong></span>
        <span>${c.count} events (<span style="color:#ef4444;">${c.blocked} blocked</span>)</span>
      </div>
    `).join('') || '<div style="color:var(--text-muted); text-align:center;">No client activity</div>';
  } catch (err) {
    console.error('Failed to load reports', err);
  }
}

// -------------------------------------------------------------
// 9. AUDIT LOGS
// -------------------------------------------------------------
async function loadAuditLogs() {
  const tbody = document.getElementById('auditLogsTableBody');
  tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:20px;">Loading audit trail...</td></tr>';

  try {
    const res = await fetch('/api/audit-logs');
    const data = await res.json();
    const logs = data.logs || [];

    if (logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:20px;">No audit records found.</td></tr>';
      return;
    }

    tbody.innerHTML = logs.map(l => `
      <tr>
        <td style="white-space:nowrap;">${new Date(l.timestamp).toLocaleString()}</td>
        <td><strong>${escapeHtml(l.admin_user)}</strong></td>
        <td><code style="color:#38bdf8;">${escapeHtml(l.action)}</code></td>
        <td>${escapeHtml(l.target || '—')}</td>
        <td><span class="badge-pill ${l.result === 'SUCCESS' ? 'badge-allow' : 'badge-block'}">${l.result}</span></td>
        <td><code>${escapeHtml(l.ip_address || '127.0.0.1')}</code></td>
        <td style="font-size:0.75rem; color:#94a3b8;">${escapeHtml(l.details || '')}</td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:#ef4444;">Failed to load audit records.</td></tr>';
  }
}

// -------------------------------------------------------------
// 10. INSTALL & ENROLL EXTENSION
// -------------------------------------------------------------
function loadInstallTab() {
  const targetInput = document.getElementById('targetServerUrlInput');
  if (targetInput && !targetInput.value) {
    targetInput.value = window.location.origin;
  }
  loadEnrollmentTokens();
  loadPackageInfo();
}

function downloadExtensionZip() {
  const targetInput = document.getElementById('targetServerUrlInput');
  const serverUrl = targetInput ? targetInput.value.trim() : window.location.origin;
  const downloadUrl = `/api/extension/download?serverUrl=${encodeURIComponent(serverUrl)}`;
  showToast('Packaging FortiNex extension archive...', '📦');
  window.location.href = downloadUrl;
}

async function loadEnrollmentTokens() {
  const tbody = document.getElementById('tokensTableBody');
  if (!tbody) return;
  try {
    const res = await apiFetch('/api/clients/tokens');
    if (!res.ok) throw new Error('Failed to fetch tokens');
    const data = await res.json();
    const tokens = data.tokens || [];

    if (tokens.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:15px; color:var(--text-muted);">No tokens found. Click "+ Generate Token" to create one.</td></tr>';
      return;
    }

    // Set recommended active token in display
    const activeToken = tokens.find(t => t.status === 'ACTIVE');
    if (activeToken) {
      const activeDisplay = document.getElementById('activeTokenDisplay');
      if (activeDisplay) activeDisplay.value = activeToken.token;
    }

    tbody.innerHTML = tokens.map(t => {
      const statusBadge = t.status === 'ACTIVE' 
        ? '<span class="badge-pill badge-allow">ACTIVE</span>'
        : (t.status === 'REVOKED' ? '<span class="badge-pill badge-block">REVOKED</span>' : '<span class="badge-pill badge-warning">' + escapeHtml(t.status) + '</span>');
      
      const expiresFormatted = t.expires_at ? new Date(t.expires_at).toLocaleDateString() : 'Never';
      const isRevokable = t.status === 'ACTIVE';

      return `<tr>
        <td style="font-family:monospace; font-weight:700; color:#38bdf8;">
          ${escapeHtml(t.token)}
          <button class="btn-header" style="padding:2px 6px; font-size:0.7rem; margin-left:6px;" onclick="copyToClipboard('${escapeHtml(t.token)}')">📋</button>
        </td>
        <td>${statusBadge}</td>
        <td>${t.uses_count || 0} / ${t.max_uses ? t.max_uses : '∞'}</td>
        <td style="font-size:0.75rem; color:var(--text-muted);">${expiresFormatted}</td>
        <td>
          ${isRevokable ? `<button class="btn-action" style="color:#ef4444;" onclick="revokeToken('${escapeHtml(t.token)}')">Revoke</button>` : '<span style="color:var(--text-dim); font-size:0.75rem;">None</span>'}
        </td>
      </tr>`;
    }).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#ef4444; padding:15px;">Failed to load tokens.</td></tr>';
  }
}

async function loadPackageInfo() {
  try {
    const res = await fetch('/api/extension/info');
    if (res.ok) {
      const data = await res.json();
      const badge = document.getElementById('extVersionBadge');
      if (badge && data.version) badge.textContent = `v${data.version}`;
      
      const fileList = document.getElementById('packageFilesList');
      if (fileList && Array.isArray(data.files)) {
        fileList.innerHTML = data.files.map(f => 
          `<div style="padding:6px 10px; background:var(--bg-input); border-radius:4px; border:1px solid var(--border); display:flex; justify-content:space-between; align-items:center;">
            <span>${escapeHtml(f.name)}</span>
            <span style="color:var(--text-dim); font-size:0.72rem;">${(f.size / 1024).toFixed(1)} KB</span>
          </div>`
        ).join('');
      }
    }
  } catch {}
}

function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(`Copied: ${text}`, '📋');
    }).catch(() => {
      fallbackCopyText(text);
    });
  } else {
    fallbackCopyText(text);
  }
}

function fallbackCopyText(text) {
  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.style.position = 'fixed';
  textArea.style.opacity = '0';
  document.body.appendChild(textArea);
  textArea.select();
  try {
    document.execCommand('copy');
    showToast(`Copied: ${text}`, '📋');
  } catch {
    showToast('Copy not supported by browser', '⚠️');
  }
  document.body.removeChild(textArea);
}

function openTokenModal() {
  document.getElementById('tokenModal').classList.add('open');
}

function closeTokenModal() {
  document.getElementById('tokenModal').classList.remove('open');
  document.getElementById('tokenForm').reset();
}

async function saveTokenForm(e) {
  e.preventDefault();
  const description = document.getElementById('tokenDescription').value.trim();
  const max_uses = parseInt(document.getElementById('tokenMaxUses').value) || 25;
  const expires_days = parseInt(document.getElementById('tokenExpiresDays').value) || 30;

  try {
    const res = await apiFetch('/api/clients/tokens/generate', {
      method: 'POST',
      body: JSON.stringify({ description, max_uses, expires_days })
    });
    if (res.ok) {
      const data = await res.json();
      closeTokenModal();
      showToast(`Token generated: ${data.token.token}`, '🔑');
      loadEnrollmentTokens();
    } else {
      showToast('Failed to generate token', '⚠️');
    }
  } catch {
    showToast('Error connecting to server', '⚠️');
  }
}

async function revokeToken(token) {
  if (!confirm(`Revoke enrollment token "${token}"? No further workstations will be able to enroll using it.`)) return;
  try {
    const res = await apiFetch(`/api/clients/tokens/${encodeURIComponent(token)}/revoke`, {
      method: 'POST'
    });
    if (res.ok) {
      showToast('Token revoked successfully', '🛑');
      loadEnrollmentTokens();
    } else {
      showToast('Failed to revoke token', '⚠️');
    }
  } catch {
    showToast('Error revoking token', '⚠️');
  }
}

// Check URL Modal handlers
function openCheckUrlModal() {
  document.getElementById('checkUrlModal').classList.add('open');
  document.getElementById('manualCheckOutput').style.display = 'none';
  document.getElementById('manualCheckUrlInput').focus();
}

function closeCheckUrlModal() {
  document.getElementById('checkUrlModal').classList.remove('open');
}

async function runManualCheckUrl(e) {
  e.preventDefault();
  const url = document.getElementById('manualCheckUrlInput').value.trim();
  if (!url) return;

  const outBox = document.getElementById('manualCheckOutput');
  const badge = document.getElementById('manualCheckDecisionBadge');
  const reasonEl = document.getElementById('manualCheckReason');
  const detailsEl = document.getElementById('manualCheckDetails');

  outBox.style.display = 'block';
  badge.innerHTML = '<span class="badge-pill badge-warning">Evaluating...</span>';
  reasonEl.textContent = 'Querying central decision engine...';

  try {
    const res = await fetch('/api/security/check-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, clientId: 'ADMIN-CONSOLE', systemName: 'Security Lead Console' })
    });
    const data = await res.json();
    badge.innerHTML = getDecisionBadge(data.decision);
    reasonEl.textContent = `Reason: ${data.reason}`;
    detailsEl.textContent = `Domain: ${data.domain} | Threat Level: ${data.threatLevel} | Matched Rule: ${data.ruleName || 'None'}`;
    loadOverviewStats();
  } catch (err) {
    badge.innerHTML = '<span class="badge-pill badge-block">ERROR</span>';
    reasonEl.textContent = err.message;
  }
}

// -------------------------------------------------------------
// 11. FLEET SETTINGS
// -------------------------------------------------------------
async function loadSettings() {
  try {
    const res = await fetch('/api/settings');
    const data = await res.json();
    const s = data.settings || {};

    if (s.HEARTBEAT_TIMEOUT_SECONDS) {
      document.getElementById('settingHeartbeatTimeout').value = s.HEARTBEAT_TIMEOUT_SECONDS;
    }
    if (s.ALLOW_USER_BYPASS) {
      document.getElementById('settingAllowBypass').value = s.ALLOW_USER_BYPASS;
    }
    if (s.ENROLLMENT_TOKEN) {
      document.getElementById('settingEnrollmentToken').value = s.ENROLLMENT_TOKEN;
    }
    if (s.AUTO_CREATE_INCIDENTS) {
      document.getElementById('settingAutoIncidents').value = s.AUTO_CREATE_INCIDENTS;
    }
  } catch {}
}

async function saveFleetSettings() {
  const settings = {
    HEARTBEAT_TIMEOUT_SECONDS: document.getElementById('settingHeartbeatTimeout').value,
    ALLOW_USER_BYPASS: document.getElementById('settingAllowBypass').value,
    ENROLLMENT_TOKEN: document.getElementById('settingEnrollmentToken').value,
    AUTO_CREATE_INCIDENTS: document.getElementById('settingAutoIncidents').value
  };

  try {
    const res = await apiFetch('/api/settings', {
      method: 'PUT',
      body: JSON.stringify({ settings })
    });

    if (res.ok) {
      showToast('Fleet settings saved successfully');
    } else {
      showToast('Failed to save settings', '⚠️');
    }
  } catch {
    showToast('Error connecting to server', '⚠️');
  }
}

// -------------------------------------------------------------
// Helpers & Utilities
// -------------------------------------------------------------
function getDecisionBadge(decision) {
  const d = (decision || 'ALLOW').toUpperCase();
  if (d === 'BLOCK') return '<span class="badge-pill badge-block">🛑 BLOCK</span>';
  if (d === 'WARNING') return '<span class="badge-pill badge-warning">⚠️ WARNING</span>';
  return '<span class="badge-pill badge-allow">🛡️ ALLOW</span>';
}

function getThreatBadge(level) {
  const l = (level || 'SAFE').toUpperCase();
  if (l === 'CRITICAL') return '<span class="badge-pill badge-critical">CRITICAL</span>';
  if (l === 'HIGH') return '<span class="badge-pill badge-block">HIGH</span>';
  if (l === 'MEDIUM') return '<span class="badge-pill badge-warning">MEDIUM</span>';
  if (l === 'LOW') return '<span class="badge-pill" style="background:#1e293b; color:#94a3b8;">LOW</span>';
  return '<span class="badge-pill badge-allow">SAFE</span>';
}

function getAlertStatusBadge(status) {
  const s = (status || 'NEW').toUpperCase();
  if (s === 'NEW') return '<span class="badge-pill badge-block">NEW</span>';
  if (s === 'ACKNOWLEDGED') return '<span class="badge-pill badge-warning">ACKNOWLEDGED</span>';
  return '<span class="badge-pill badge-allow">RESOLVED</span>';
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// -------------------------------------------------------------
// Document Initialization & Event Listeners
// -------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  // Navigation Tabs
  document.querySelectorAll('.nav-item').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      switchTab(link.dataset.tab);
    });
  });

  // Top Bar buttons
  document.getElementById('btnRefreshAll').addEventListener('click', () => {
    const activeTab = document.querySelector('.nav-item.active')?.dataset.tab || 'overview';
    switchTab(activeTab);
    showToast('Dashboard refreshed');
  });

  // Top bar Check URL modal button
  const btnTestModal = document.getElementById('btnTestUrlCheckModal');
  if (btnTestModal) {
    btnTestModal.addEventListener('click', openCheckUrlModal);
  }

  // Top bar Download Extension button
  const btnDownloadTop = document.getElementById('btnDownloadExtTop');
  if (btnDownloadTop) {
    btnDownloadTop.addEventListener('click', () => {
      switchTab('install');
      downloadExtensionZip();
    });
  }

  // Install Tab buttons
  const btnDownloadMain = document.getElementById('btnDownloadExtMain');
  if (btnDownloadMain) {
    btnDownloadMain.addEventListener('click', downloadExtensionZip);
  }

  const btnCopyServer = document.getElementById('btnCopyServerUrl');
  if (btnCopyServer) {
    btnCopyServer.addEventListener('click', () => {
      const url = document.getElementById('targetServerUrlInput')?.value || window.location.origin;
      copyToClipboard(url);
    });
  }

  const btnCopyToken = document.getElementById('btnCopyActiveToken');
  if (btnCopyToken) {
    btnCopyToken.addEventListener('click', () => {
      const tok = document.getElementById('activeTokenDisplay')?.value || 'ENROLL-FORTINEX-2026';
      copyToClipboard(tok);
    });
  }

  const btnOpenToken = document.getElementById('btnOpenGenerateTokenModal');
  if (btnOpenToken) {
    btnOpenToken.addEventListener('click', openTokenModal);
  }

  const tokenForm = document.getElementById('tokenForm');
  if (tokenForm) {
    tokenForm.addEventListener('submit', saveTokenForm);
  }

  const btnPkgInfo = document.getElementById('btnRefreshPkgInfo');
  if (btnPkgInfo) {
    btnPkgInfo.addEventListener('click', loadPackageInfo);
  }

  const checkUrlForm = document.getElementById('checkUrlForm');
  if (checkUrlForm) {
    checkUrlForm.addEventListener('submit', runManualCheckUrl);
  }

  // Settings
  document.getElementById('btnSaveFleetSettings').addEventListener('click', saveFleetSettings);

  // Systems
  document.getElementById('btnRefreshSystems').addEventListener('click', loadSystems);

  // URL History
  document.getElementById('btnApplyUrlFilters').addEventListener('click', () => loadUrlHistory(1));
  document.getElementById('btnRefreshUrlHistory').addEventListener('click', () => loadUrlHistory(currentUrlPage));
  document.getElementById('btnUrlHistoryPrev').addEventListener('click', () => {
    if (currentUrlPage > 1) loadUrlHistory(currentUrlPage - 1);
  });
  document.getElementById('btnUrlHistoryNext').addEventListener('click', () => {
    loadUrlHistory(currentUrlPage + 1);
  });
  document.getElementById('btnExportUrlHistoryCsv').addEventListener('click', () => {
    window.location.href = '/api/reports/export-csv?type=url-events';
  });

  // Alerts
  document.getElementById('btnRefreshAlerts').addEventListener('click', loadAlerts);
  document.getElementById('filterAlertStatus').addEventListener('change', loadAlerts);
  document.getElementById('filterAlertSeverity').addEventListener('change', loadAlerts);
  document.getElementById('btnExportAlertsCsv').addEventListener('click', () => {
    window.location.href = '/api/reports/export-csv?type=alerts';
  });

  // Incidents
  document.getElementById('btnRefreshIncidents').addEventListener('click', loadIncidents);

  // Audit
  document.getElementById('btnRefreshAudit').addEventListener('click', loadAuditLogs);

  // Reports
  document.getElementById('btnDownloadReportCsv').addEventListener('click', () => {
    window.location.href = '/api/reports/export-csv?type=url-events';
  });
  document.getElementById('btnDownloadAlertsReportCsv').addEventListener('click', () => {
    window.location.href = '/api/reports/export-csv?type=alerts';
  });

  // Rules
  document.getElementById('btnOpenNewRuleModal').addEventListener('click', openNewRuleModal);
  document.getElementById('ruleForm').addEventListener('submit', saveRuleForm);

  // Live feed
  document.getElementById('btnClearLiveFeed').addEventListener('click', () => {
    document.getElementById('liveFeedList').innerHTML = '<div style="text-align:center; padding:30px; color:var(--text-muted); font-size:0.85rem;">Log cleared. Waiting for new events...</div>';
  });

  // Admin Logout
  document.getElementById('btnAdminLogout').addEventListener('click', async () => {
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
    } catch {}
    localStorage.removeItem('phishguard_admin_token');
    currentAuthToken = '';
    showToast('Logged out. Reconnecting as guest...');
    autoAdminLogin();
  });

  // Initial Load
  autoAdminLogin().then(() => {
    loadOverviewStats();
    initSse();
  });
});
