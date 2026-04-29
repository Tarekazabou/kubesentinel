/**
 * KubeSentinel Dashboard – app.js
 * Static SPA that polls the Flask /api/incidents endpoint
 * through a Cloudflare Tunnel (or any public URL).
 */

// ─── State ───────────────────────────────────────────────────────────────────

const STORAGE_KEY = 'kubesentinel_settings';

const state = {
  endpoint: '',
  interval: 15,
  incidents: [],
  filteredIncidents: [],
  currentFilter: 'all',
  connected: false,
  refreshTimer: null,
  loading: true,
};

// ─── Init ────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  startClock();
  fetchIncidents();
  startAutoRefresh();
});

// ─── Settings ────────────────────────────────────────────────────────────────

function loadSettings() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
    state.endpoint = saved.endpoint || '';
    state.interval = saved.interval || 15;
  } catch { /* ignore */ }

  const elEndpoint = document.getElementById('setting-endpoint');
  const elInterval = document.getElementById('setting-interval');
  if (elEndpoint) elEndpoint.value = state.endpoint;
  if (elInterval) elInterval.value = state.interval;
  updateEndpointDisplay();
}

function saveSettings() {
  const elEndpoint = document.getElementById('setting-endpoint');
  const elInterval = document.getElementById('setting-interval');

  state.endpoint = (elEndpoint.value || '').replace(/\/+$/, '');
  state.interval = Math.max(5, Math.min(300, parseInt(elInterval.value) || 15));

  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    endpoint: state.endpoint,
    interval: state.interval,
  }));

  updateEndpointDisplay();
  startAutoRefresh();
  fetchIncidents();
}

function updateEndpointDisplay() {
  const el = document.getElementById('ov-endpoint');
  if (el) el.textContent = state.endpoint || '(not configured)';
}

async function testConnection() {
  if (!state.endpoint) {
    alert('Set an API endpoint first.');
    return;
  }
  setConnectionStatus('connecting', 'Testing…');
  try {
    const resp = await fetch(`${state.endpoint}/health`, { signal: AbortSignal.timeout(5000) });
    if (resp.ok) {
      const data = await resp.json();
      setConnectionStatus('connected', 'Connected');
      alert(`✅ Connected!\nModel loaded: ${data.model_loaded}`);
    } else {
      throw new Error(`HTTP ${resp.status}`);
    }
  } catch (e) {
    setConnectionStatus('disconnected', 'Failed');
    alert(`❌ Connection failed: ${e.message}`);
  }
}

function retryConnection() {
  fetchIncidents();
}

// ─── Clock ───────────────────────────────────────────────────────────────────

function startClock() {
  const el = document.getElementById('topbar-time');
  function tick() {
    const now = new Date();
    el.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
  tick();
  setInterval(tick, 1000);
}

// ─── Data Fetching ───────────────────────────────────────────────────────────

async function fetchIncidents() {
  if (!state.endpoint) {
    showNeedsConfig();
    return;
  }

  showRefreshSpinner(true);
  setConnectionStatus('connecting', 'Fetching…');

  try {
    const resp = await fetch(`${state.endpoint}/api/incidents`, {
      signal: AbortSignal.timeout(10000),
    });

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    const data = await resp.json();
    state.incidents = data.incidents || [];
    state.connected = true;
    state.loading = false;

    setConnectionStatus('connected', 'Live');
    hideBanner();
    updateStats(data);
    applyFilters();
    updateOverview(data);

  } catch (e) {
    state.connected = false;
    setConnectionStatus('disconnected', 'Disconnected');
    showBanner(`Cannot reach API: ${e.message}`);
    if (state.loading) {
      renderEmpty('Connection Error', `Could not reach ${state.endpoint}. Check your Cloudflare Tunnel or endpoint settings.`);
      state.loading = false;
    }
  } finally {
    showRefreshSpinner(false);
  }
}

async function fetchWarmup() {
  if (!state.endpoint) return null;
  try {
    const resp = await fetch(`${state.endpoint}/warmup/status`, { signal: AbortSignal.timeout(5000) });
    if (resp.ok) return await resp.json();
  } catch { /* ignore */ }
  return null;
}

function startAutoRefresh() {
  if (state.refreshTimer) clearInterval(state.refreshTimer);
  state.refreshTimer = setInterval(() => fetchIncidents(), state.interval * 1000);
  const el = document.getElementById('refresh-text');
  if (el) el.textContent = `${state.interval}s`;
}

// ─── Rendering ───────────────────────────────────────────────────────────────

function updateStats(data) {
  const incidents = state.incidents;
  const critical = incidents.filter(i => i.severity === 'critical').length;
  const high = incidents.filter(i => i.severity === 'high').length;
  const medlow = incidents.filter(i => i.severity === 'medium' || i.severity === 'low').length;

  setText('stat-total', data.total || incidents.length);
  setText('stat-critical', critical);
  setText('stat-high', high);
  setText('stat-medlow', medlow);

  const badge = document.getElementById('sidebar-badge');
  if (badge) {
    badge.textContent = critical + high;
    badge.style.display = (critical + high) > 0 ? '' : 'none';
  }

  if (data.last_analysis) {
    const d = new Date(data.last_analysis);
    setText('stat-last-update', `Updated ${d.toLocaleTimeString()}`);
  }
}

function applyFilters() {
  const search = (document.getElementById('search-input')?.value || '').toLowerCase();
  const filter = state.currentFilter;

  state.filteredIncidents = state.incidents.filter(inc => {
    if (filter !== 'all' && inc.severity !== filter) return false;
    if (search) {
      const haystack = `${inc.incident_type} ${inc.description} ${inc.pod_name} ${inc.container_name} ${inc.ai_analysis}`.toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });

  renderIncidents();
}

function setFilter(filter, el) {
  state.currentFilter = filter;
  document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
  if (el) el.classList.add('active');
  applyFilters();
}

function renderIncidents() {
  const list = document.getElementById('incident-list');
  if (!list) return;

  if (state.filteredIncidents.length === 0) {
    if (state.incidents.length === 0 && state.connected) {
      list.innerHTML = emptyStateHTML('No Incidents Yet', 'Your cluster is clean — no anomalies have been detected. Incidents will appear here as the runtime monitor captures them.', '🛡️');
    } else if (state.incidents.length > 0) {
      list.innerHTML = emptyStateHTML('No Matches', 'No incidents match the current filter.', '🔍');
    }
    return;
  }

  list.innerHTML = state.filteredIncidents.map((inc, idx) => incidentCardHTML(inc, idx)).join('');
}

function incidentCardHTML(inc, idx) {
  const riskClass = inc.risk_score >= 70 ? 'risk-high' : inc.risk_score >= 40 ? 'risk-medium' : 'risk-low';
  const timeStr = inc.timestamp ? formatTimestamp(inc.timestamp) : '—';
  const sevClass = inc.severity || 'medium';

  return `
    <div class="incident-card" id="incident-${idx}" onclick="toggleIncident(${idx})">
      <div>
        <span class="severity-badge ${sevClass}">
          <span class="severity-dot"></span>
          ${escapeHtml(inc.severity || 'unknown')}
        </span>
      </div>
      <div class="incident-main">
        <div class="incident-type">${escapeHtml(inc.incident_type || 'Unknown Event')}</div>
        <div class="incident-desc">${escapeHtml(inc.description || '')}</div>
        <div class="incident-meta">
          <span class="incident-meta-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 002 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0022 16z"/></svg>
            ${escapeHtml(inc.pod_name || 'N/A')}
          </span>
          <span class="incident-meta-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="15" rx="2" ry="2"/><polyline points="17 2 12 7 7 2"/></svg>
            ${escapeHtml(inc.container_name || 'N/A')}
          </span>
          <span class="incident-meta-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            ${inc.related_events || 0} event(s)
          </span>
        </div>
      </div>
      <div class="incident-right">
        <span class="incident-time">${timeStr}</span>
        <span class="risk-score ${riskClass}">Risk ${inc.risk_score || 0}%</span>
      </div>

      <!-- Expanded detail -->
      <div class="incident-detail">
        <div class="detail-grid">
          <div class="detail-grid-item">
            <div class="detail-label">Incident ID</div>
            <div class="detail-val" style="font-size:0.75rem;word-break:break-all">${escapeHtml(inc.id || '—')}</div>
          </div>
          <div class="detail-grid-item">
            <div class="detail-label">Risk Score</div>
            <div class="detail-val">${inc.risk_score || 0}%</div>
          </div>
          <div class="detail-grid-item">
            <div class="detail-label">Related Events</div>
            <div class="detail-val">${inc.related_events || 0}</div>
          </div>
          <div class="detail-grid-item">
            <div class="detail-label">Source File</div>
            <div class="detail-val" style="font-size:0.75rem">${escapeHtml(inc.raw_file || '—')}</div>
          </div>
        </div>
        <div class="detail-section" style="margin-top:14px">
          <div class="detail-label">AI Analysis</div>
          <div class="detail-value">${escapeHtml(inc.ai_analysis || 'No analysis available.')}</div>
        </div>
      </div>
    </div>`;
}

function toggleIncident(idx) {
  const el = document.getElementById(`incident-${idx}`);
  if (el) el.classList.toggle('expanded');
}

function emptyStateHTML(title, desc, icon) {
  return `
    <div class="empty-state">
      <div class="empty-icon">${icon || '📭'}</div>
      <div class="empty-title">${escapeHtml(title)}</div>
      <div class="empty-desc">${escapeHtml(desc)}</div>
    </div>`;
}

function renderEmpty(title, desc) {
  const list = document.getElementById('incident-list');
  if (list) list.innerHTML = emptyStateHTML(title, desc, '⚠️');
}

function showNeedsConfig() {
  state.loading = false;
  const list = document.getElementById('incident-list');
  if (list) {
    list.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🔗</div>
        <div class="empty-title">Configure API Endpoint</div>
        <div class="empty-desc">Go to <strong>Settings</strong> and enter your KubeSentinel API URL (your Cloudflare Tunnel URL) to start seeing incidents.</div>
      </div>`;
  }
  setConnectionStatus('disconnected', 'Not configured');
}

// ─── Overview ────────────────────────────────────────────────────────────────

async function updateOverview(data) {
  setText('ov-model-status', state.connected ? '✅ Connected' : '❌ Disconnected');
  setText('ov-gemini', data.using_gemini_enrichment ? '✅ Active' : '⬚ Disabled');

  const warmup = await fetchWarmup();
  if (warmup) {
    if (warmup.warmup_complete) {
      setText('ov-warmup', '✅ Complete');
      setText('ov-warmup-sub', '');
    } else {
      setText('ov-warmup', `${warmup.samples_collected}/${warmup.threshold}`);
      setText('ov-warmup-sub', 'Collecting baseline…');
    }
  }
}

// ─── View Switching ──────────────────────────────────────────────────────────

function switchView(viewName, el) {
  // Hide all views
  document.querySelectorAll('[id^="view-"]').forEach(v => v.style.display = 'none');
  // Show target
  const target = document.getElementById(`view-${viewName}`);
  if (target) target.style.display = '';

  // Update nav
  document.querySelectorAll('.sidebar-link').forEach(l => l.classList.remove('active'));
  if (el) el.classList.add('active');

  // Refresh data when switching to overview
  if (viewName === 'overview' && state.connected) {
    fetchIncidents();
  }
  if (viewName === 'settings') {
    loadSettings();
  }
}

// ─── UI Helpers ──────────────────────────────────────────────────────────────

function setConnectionStatus(status, text) {
  const dot = document.getElementById('status-dot');
  const txt = document.getElementById('status-text');
  if (dot) {
    dot.className = 'status-dot';
    if (status === 'disconnected') dot.classList.add('disconnected');
    if (status === 'connecting') dot.classList.add('connecting');
  }
  if (txt) txt.textContent = text;
}

function showBanner(msg) {
  const el = document.getElementById('connection-banner');
  const txt = document.getElementById('banner-text');
  if (el) el.classList.remove('hidden');
  if (txt) txt.textContent = msg;
}

function hideBanner() {
  const el = document.getElementById('connection-banner');
  if (el) el.classList.add('hidden');
}

function showRefreshSpinner(show) {
  const el = document.getElementById('refresh-spinner');
  if (el) el.classList.toggle('hidden', !show);
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function formatTimestamp(ts) {
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    const now = new Date();
    const diff = (now - d) / 1000;
    if (diff < 60) return `${Math.floor(diff)}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return d.toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch {
    return ts;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
