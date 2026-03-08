const API_BASE = `${window.location.origin}/api`;

let policies = [];
let promotions = [];
let environments = {};   // keyed by env name → { policies: [...], max_risk_score: N }
let currentTab = 'dashboard';
let auditRefreshTimer = null;

// --- SVG icon library ---
const ICONS = {
    moon: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
    sun: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`,
    shieldCheck: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`,
    shieldAlert: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><circle cx="12" cy="16" r="0.5" fill="currentColor"/></svg>`,
    alertTriangle: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><circle cx="12" cy="17" r="0.5" fill="currentColor"/></svg>`,
    undo: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>`,
};

// --- Event type metadata ---
const EVENT_META = {
    promotion_approved:   { dot: '#10b981', label: 'Approved',    rowClass: 'audit-row-approved' },
    promotion_rejected:   { dot: '#ef4444', label: 'Rejected',    rowClass: 'audit-row-rejected' },
    icap_threat_detected: { dot: '#f59e0b', label: 'ICAP Threat', rowClass: 'audit-row-threat'   },
    policy_rollback:      { dot: '#667eea', label: 'Rollback',    rowClass: 'audit-row-rollback'  },
    promotion_created:    { dot: '#9ca3af', label: 'Created',     rowClass: ''                    },
};

// --- Core data loading ---
async function loadData() {
    try {
        const [policiesRes, promotionsRes, analyticsRes, envsRes] = await Promise.all([
            fetch(`${API_BASE}/policies`),
            fetch(`${API_BASE}/promotions`),
            fetch(`${API_BASE}/analytics`),
            fetch(`${API_BASE}/environments`),
        ]);

        policies = await policiesRes.json();
        promotions = await promotionsRes.json();
        const analytics = await analyticsRes.json();
        const envsData = await envsRes.json();

        // Index environments by name for fast lookup
        environments = {};
        (Array.isArray(envsData) ? envsData : Object.values(envsData)).forEach(env => {
            environments[env.name] = env;
        });

        renderPolicies();
        renderPromotions();
        updateStats(analytics);
        loadApprovals();

        // Refresh remove-policies list if a target is already selected
        const targetEnv = document.getElementById('target-env').value;
        if (targetEnv) renderRemovePolicies(targetEnv);
    } catch (error) {
        console.error('Failed to load data:', error);
    }
}

// --- Remove-policies panel ---
function renderRemovePolicies(targetEnv) {
    const container = document.getElementById('remove-policy-selector');
    if (!targetEnv) {
        container.innerHTML = '<p class="empty-state" style="font-size:0.85rem;padding:8px 0">Select a target environment above to see removable policies.</p>';
        return;
    }

    const env = environments[targetEnv];
    const activePolicies = env ? (env.policies || []) : [];

    if (activePolicies.length === 0) {
        container.innerHTML = '<p class="empty-state" style="font-size:0.85rem;padding:8px 0">No active policies in this environment.</p>';
        return;
    }

    container.innerHTML = activePolicies.map(name => `
        <div class="policy-item">
            <label>
                <input type="checkbox" name="remove-policy" value="${name}">
                <span><strong>${name}</strong></span>
            </label>
        </div>
    `).join('');
}

function renderPolicies() {
    const selector = document.getElementById('policy-selector');
    selector.innerHTML = policies.map(p => `
        <div class="policy-item">
            <label>
                <input type="checkbox" name="policy" value="${p.name}">
                <span><strong>${p.name}</strong>: ${p.description} <span class="severity-tag severity-${p.severity}">${p.severity}</span></span>
            </label>
        </div>
    `).join('');
}

function renderPromotions() {
    const list = document.getElementById('promotions-list');
    if (promotions.length === 0) {
        list.innerHTML = '<p class="empty-state">No promotions yet. Create one above or restart the server to load demo data.</p>';
        return;
    }

    // Show most-recent first
    const sorted = [...promotions].reverse();
    list.innerHTML = `
        <table class="data-table">
            <thead><tr>
                <th>Promotion</th>
                <th>Application</th>
                <th>Pipeline</th>
                <th>Version</th>
                <th style="text-align:center">Risk</th>
                <th style="text-align:center">Decision</th>
            </tr></thead>
            <tbody>
                ${sorted.map(p => {
                    const score = p.risk_score ?? null;
                    const scoreColor = score === null ? '#9ca3af'
                        : score >= 70 ? '#ef4444' : score >= 40 ? '#f59e0b' : '#10b981';
                    return `
                    <tr>
                        <td>
                            <strong>${p.name}</strong>
                            <br><code class="mono" style="font-size:0.75rem">${p.id}</code>
                        </td>
                        <td class="text-muted">${p.application || p.app || '—'}</td>
                        <td>
                            <span class="env-chip env-${p.source}">${p.source}</span>
                            <span style="opacity:0.4;margin:0 4px">→</span>
                            <span class="env-chip env-${p.target}">${p.target}</span>
                        </td>
                        <td><code class="mono">${p.version}</code></td>
                        <td style="text-align:center">
                            ${score !== null
                                ? `<span style="font-weight:700;color:${scoreColor}">${score}</span>`
                                : '<span style="opacity:0.4">—</span>'}
                        </td>
                        <td style="text-align:center">
                            <span class="badge badge-${p.decision === 'APPROVED' ? 'approved' : 'rejected'}"
                                  title="${p.nlp_reasoning || ''}"
                                  style="cursor:${p.nlp_reasoning ? 'help' : 'default'}">${p.decision}</span>
                        </td>
                    </tr>`;
                }).join('')}
            </tbody>
        </table>`;
}

// --- Pending Approvals ---
async function loadApprovals() {
    try {
        const res = await fetch(`${API_BASE}/approvals`);
        const pending = await res.json();
        const card = document.getElementById('approvals-card');
        card.style.display = pending.length > 0 ? 'block' : 'none';
        document.getElementById('approvals-count').textContent = pending.length;
        document.getElementById('approvals-list').innerHTML = pending.length === 0 ? '' : `
            <table class="data-table">
                <thead><tr>
                    <th>Name</th><th>App</th><th>Route</th><th>Version</th>
                    <th style="text-align:center">Risk</th><th>Reason</th>
                    <th style="text-align:center">Actions</th>
                </tr></thead>
                <tbody>
                ${pending.map(p => `
                    <tr>
                        <td><code class="mono">${p.name}</code></td>
                        <td>${p.application}</td>
                        <td style="opacity:0.7">${p.source} &rarr; ${p.target}</td>
                        <td><code class="mono">${p.version}</code></td>
                        <td style="text-align:center;font-weight:700;color:#f59e0b">${p.risk_score}</td>
                        <td style="font-size:0.8rem;opacity:0.7;max-width:220px">${p.message || ''}</td>
                        <td style="text-align:center;white-space:nowrap">
                            <button class="btn btn-primary" style="padding:4px 12px;font-size:0.8rem;margin-right:6px"
                                onclick="approvePromotion('${p.id}')">Approve</button>
                            <button class="btn btn-secondary" style="padding:4px 12px;font-size:0.8rem;color:#ef4444;border-color:#ef4444"
                                onclick="rejectPromotion('${p.id}')">Reject</button>
                        </td>
                    </tr>`).join('')}
                </tbody>
            </table>`;
    } catch (e) {
        console.error('Failed to load approvals', e);
    }
}

async function approvePromotion(id) {
    const name = prompt('Your name (for the audit log):') || 'operator';
    if (name === null) return;
    await fetch(`${API_BASE}/approvals/${id}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approved_by: name }),
    });
    await loadData();
}

async function rejectPromotion(id) {
    const reason = prompt('Rejection reason:') || 'Rejected by operator';
    if (reason === null) return;
    await fetch(`${API_BASE}/approvals/${id}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason }),
    });
    await loadData();
}

function updateStats(analytics) {
    document.getElementById('total-promotions').textContent = analytics.total_promotions;
    document.getElementById('approved').textContent = analytics.approved;
    document.getElementById('rejected').textContent = analytics.rejected;
    document.getElementById('avg-risk').textContent = analytics.average_risk_score;
}

// Update remove-policies list when target environment changes
document.getElementById('target-env').addEventListener('change', (e) => {
    renderRemovePolicies(e.target.value);
});

// --- Promotion form submit ---
document.getElementById('promotion-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const selectedPolicies = Array.from(document.querySelectorAll('input[name="policy"]:checked'))
        .map(cb => cb.value);

    const removePolicies = Array.from(document.querySelectorAll('input[name="remove-policy"]:checked'))
        .map(cb => cb.value);

    const namespace = document.getElementById('app-namespace').value.trim() || 'default';

    const data = {
        name: document.getElementById('name').value,
        application_name: document.getElementById('app-name').value,
        source_environment: document.getElementById('source-env').value,
        target_environment: document.getElementById('target-env').value,
        version: document.getElementById('version').value,
        application_namespace: namespace,
        add_policies: selectedPolicies,
        remove_policies: removePolicies,
    };

    try {
        const response = await fetch(`${API_BASE}/promotions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });

        const result = await response.json();
        showResult(result);
        document.getElementById('promotion-form').reset();
        await loadData();
    } catch (error) {
        alert('Failed to create promotion: ' + error.message);
    }
});

// --- Result modal ---
function showResult(result) {
    const modal = document.getElementById('result-modal');
    const details = document.getElementById('result-details');
    const decisionClass = result.decision === 'APPROVED' ? 'success' : 'danger';
    const icap = result.icap_scan;

    // Build ICAP card
    let icapClass, icapIcon, icapStatusText, icapStatusColor;
    if (icap.threat_found) {
        icapClass = 'threat';
        icapIcon = ICONS.shieldAlert;
        icapStatusText = `Threat detected: ${icap.threat_type}`;
        icapStatusColor = '#ef4444';
    } else if (icap.low_coverage_warning) {
        icapClass = 'warning';
        icapIcon = ICONS.alertTriangle;
        icapStatusText = 'Clean (low coverage warning)';
        icapStatusColor = '#f59e0b';
    } else {
        icapClass = 'clean';
        icapIcon = ICONS.shieldCheck;
        icapStatusText = 'Clean';
        icapStatusColor = '#10b981';
    }

    const coverageFillClass = icap.coverage_score >= 75 ? 'coverage-good' : 'coverage-warn';

    const icapCard = `
        <div class="icap-card ${icapClass}">
            <div class="icap-header">
                <span style="color:${icapStatusColor}">${icapIcon}</span>
                <span class="icap-title">ICAP Content Scan</span>
            </div>
            <div class="icap-status" style="color:${icapStatusColor}">${icapStatusText}</div>
            <div class="icap-coverage-row">
                <span class="icap-coverage-label">Coverage: ${icap.coverage_score}/100</span>
                <div class="coverage-bar">
                    <div class="coverage-fill ${coverageFillClass}" style="width:${icap.coverage_score}%"></div>
                </div>
            </div>
        </div>
    `;

    // Build risk section (null when ICAP rejected)
    let riskSection = '';
    if (result.risk_assessment) {
        riskSection = `
            <h3 class="section-title">Risk Assessment</h3>
            <p class="result-message">${result.message}</p>
            ${result.risk_assessment.factors.map(f => `
                <div class="risk-factor">
                    <div class="risk-factor-name">${f.name.replace(/_/g, ' ')}</div>
                    <div class="risk-factor-score">${Math.round(f.weighted_score)} pts</div>
                    <div class="risk-factor-reason">${f.reason}</div>
                </div>
            `).join('')}
        `;
    } else {
        riskSection = `<p class="result-message">${result.message}</p>`;
    }

    const scoreLabel = icap.threat_found
        ? 'ICAP rejection: risk score not computed'
        : `Risk score: ${result.risk_score} / ${result.max_allowed}`;

    const reasoningBlock = result.nlp_reasoning
        ? `<div style="background:var(--bg-secondary,#1e1e2e);border-left:3px solid var(--accent,#7c3aed);border-radius:6px;padding:14px 16px;margin-bottom:20px;font-size:0.92rem;line-height:1.6;color:var(--text-primary);">
               <span style="font-size:0.75rem;font-weight:600;letter-spacing:0.05em;opacity:0.5;display:block;margin-bottom:6px;text-transform:uppercase;">CAPSLOCK Reasoning</span>
               ${result.nlp_reasoning}
           </div>`
        : '';

    details.innerHTML = `
        <h2>Promotion Result</h2>
        <div class="stat-card ${decisionClass}" style="margin-bottom:20px;">
            <div class="stat-value">${result.decision}</div>
            <div class="stat-label">${scoreLabel}</div>
        </div>
        ${reasoningBlock}
        ${icapCard}
        ${riskSection}
    `;

    modal.style.display = 'block';
}

document.querySelector('.close').addEventListener('click', () => {
    document.getElementById('result-modal').style.display = 'none';
});

window.addEventListener('click', (e) => {
    const modal = document.getElementById('result-modal');
    if (e.target === modal) modal.style.display = 'none';
});

// --- Tab navigation ---
function switchTab(name) {
    currentTab = name;
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(`tab-${name}`).classList.remove('hidden');
    document.querySelector(`[data-tab="${name}"]`).classList.add('active');

    clearInterval(auditRefreshTimer);
    clearInterval(icapRefreshTimer);
    auditRefreshTimer = null;
    icapRefreshTimer  = null;

    if (name === 'icap') {
        loadICAPStatus();
        icapRefreshTimer = setInterval(loadICAPStatus, 60000);
    } else if (name === 'audit') {
        loadAuditLog();
        auditRefreshTimer = setInterval(loadAuditLog, 10000);
    } else if (name === 'versions') {
        const env = document.getElementById('versions-env-select').value;
        loadVersions(env);
    } else if (name === 'validation') {
        loadHealthScenarios();
        loadTrafficScenarios();
    } else if (name === 'policy-engine') {
        loadPENamespaces();
        loadPEPolicies();
        loadPEFrameworks();
    } else if (name === 'load-balancer') {
        loadLBState();
        loadLBTrend();
    } else if (name === 'assistant') {
        document.getElementById('chat-input').focus();
    }
}

// --- Audit log ---
async function loadAuditLog() {
    const eventType = document.getElementById('audit-filter').value;
    const url = eventType
        ? `${API_BASE}/audit?limit=100&event_type=${eventType}`
        : `${API_BASE}/audit?limit=100`;

    try {
        const res = await fetch(url);
        const events = await res.json();
        renderAuditLog(events.reverse()); // most recent first
    } catch (err) {
        console.error('Failed to load audit log:', err);
    }
}

function renderAuditLog(events) {
    const container = document.getElementById('audit-table');
    if (events.length === 0) {
        container.innerHTML = '<p class="empty-state">No audit events yet.</p>';
        return;
    }

    const rows = events.map(e => {
        const meta = EVENT_META[e.event_type] || { dot: '#9ca3af', label: e.event_type, rowClass: '' };
        const time = formatTime(e.timestamp);
        const details = formatEventDetails(e);
        const env = e.environment || 'N/A';
        const pid = e.promotion_id ? `<code class="mono">${e.promotion_id}</code>` : 'N/A';

        return `
            <tr class="${meta.rowClass}">
                <td class="audit-time">${time}</td>
                <td>
                    <span class="status-dot" style="background:${meta.dot}"></span>
                    ${meta.label}
                </td>
                <td>${env}</td>
                <td>${pid}</td>
                <td class="text-muted">${details}</td>
            </tr>
        `;
    }).join('');

    container.innerHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Event</th>
                    <th>Environment</th>
                    <th>Promotion</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
    `;
}

function formatEventDetails(event) {
    const d = event.details || {};
    switch (event.event_type) {
        case 'promotion_approved':
            return `risk ${d.risk_score ?? '?'}/${d.max_allowed ?? '?'}`;
        case 'promotion_rejected':
            return d.reason === 'icap_threat'
                ? `ICAP: ${d.threat_type || 'unknown'}`
                : `risk ${d.risk_score ?? '?'}/${d.max_allowed ?? '?'}`;
        case 'icap_threat_detected':
            return `${d.threat_type || ''} coverage ${d.coverage_score ?? '?'}`;
        case 'policy_rollback':
            return `to version ${d.version_id || ''}`;
        case 'promotion_created':
            return d.decision || '';
        default:
            return '';
    }
}

// --- Policy versions ---
async function loadVersions(env) {
    try {
        const res = await fetch(`${API_BASE}/environments/${env}/versions`);
        const versions = await res.json();
        renderVersions(versions, env);
    } catch (err) {
        console.error('Failed to load versions:', err);
    }
}

function renderVersions(versions, env) {
    const container = document.getElementById('versions-table');
    if (versions.length === 0) {
        container.innerHTML = '<p class="empty-state">No versions recorded yet. Approve a promotion to create the first policy snapshot.</p>';
        return;
    }

    const rows = versions.map((v, i) => {
        const isCurrent = i === 0;
        const time = formatDateTime(v.timestamp);
        const policyCount = v.policies.length;
        const note = v.note.length > 50 ? v.note.slice(0, 50) + '…' : v.note;
        const actionCell = isCurrent
            ? `<span class="badge badge-current">Current</span>`
            : `<button class="btn-rollback" onclick="confirmRollback('${env}', '${v.version_id}')">
                   ${ICONS.undo} Rollback
               </button>`;

        return `
            <tr>
                <td><code class="mono">${v.version_id}</code></td>
                <td>${time}</td>
                <td class="text-muted">${note || 'N/A'}</td>
                <td>${policyCount} ${policyCount === 1 ? 'policy' : 'policies'}</td>
                <td>${actionCell}</td>
            </tr>
        `;
    }).join('');

    container.innerHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>Version ID</th>
                    <th>Timestamp</th>
                    <th>Note</th>
                    <th>Policies</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
    `;
}

async function confirmRollback(env, versionId) {
    const ok = window.confirm(`Restore ${env} to policy version ${versionId}?\n\nThis will replace the current active policies for this environment.`);
    if (!ok) return;

    try {
        const res = await fetch(`${API_BASE}/environments/${env}/rollback`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ version_id: versionId }),
        });

        if (!res.ok) {
            const err = await res.json();
            showToast(err.detail || 'Rollback failed', 'error');
            return;
        }

        showToast(`Rolled back ${env} to version ${versionId}`, 'success');
        loadVersions(env);
    } catch (err) {
        showToast('Rollback failed: ' + err.message, 'error');
    }
}

// --- Toast notification ---
function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3500);
}

// --- Helpers ---
function formatTime(isoStr) {
    return new Date(isoStr).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDateTime(isoStr) {
    return new Date(isoStr).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// --- ICAP Operator tab ---
let icapRefreshTimer = null;

async function loadICAPStatus() {
    try {
        const [statusRes, healthRes] = await Promise.all([
            fetch(`${API_BASE}/icap/status`),
            fetch(`${API_BASE}/icap/health`),
        ]);
        const status = await statusRes.json();
        const health = await healthRes.json();
        renderICAPStatus(status, health);
        renderICAPInstances(health);

        // Pre-fill configure form with current live values
        const modeEl = document.getElementById('icap-scanning-mode');
        if (modeEl && status.scanning_mode) modeEl.value = status.scanning_mode;
        const repEl = document.getElementById('icap-replicas');
        if (repEl && status.desired_replicas) repEl.value = status.desired_replicas;
    } catch (err) {
        document.getElementById('icap-status-panel').innerHTML =
            `<p class="empty-state" style="color:var(--danger)">Failed to load ICAP status: ${err.message}</p>`;
    }
}

function renderICAPStatus(status, health) {
    const score     = health.aggregate_health_score ?? status.health_score ?? 0;
    const scoreClass = score >= 80 ? 'success' : score >= 60 ? 'warning' : 'danger';
    const ready     = status.ready_replicas   ?? health.ready_replicas   ?? 0;
    const desired   = status.desired_replicas ?? health.desired_replicas ?? 0;
    const mode      = status.scanning_mode    ?? health.scanning_mode    ?? 'N/A';
    const source    = status.source           ?? health.source           ?? 'N/A';
    const modeClass = mode === 'block' ? 'danger' : mode === 'warn' ? 'warning' : 'success';

    document.getElementById('icap-status-panel').innerHTML = `
        <div class="stats-grid" style="margin:0 0 16px">
            <div class="stat-card ${scoreClass}">
                <div class="stat-value">${score}</div>
                <div class="stat-label">Health Score</div>
            </div>
            <div class="stat-card ${ready === desired ? 'success' : 'warning'}">
                <div class="stat-value">${ready}/${desired}</div>
                <div class="stat-label">Ready Replicas</div>
            </div>
            <div class="stat-card ${modeClass}">
                <div class="stat-value" style="font-size:1.1rem;text-transform:uppercase">${mode}</div>
                <div class="stat-label">Scanning Mode</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="font-size:1rem">${source}</div>
                <div class="stat-label">Data Source</div>
            </div>
        </div>
        <div class="icap-coverage-row" style="max-width:420px">
            <span class="icap-coverage-label">Aggregate health: ${score}/100</span>
            <div class="coverage-bar">
                <div class="coverage-fill ${score >= 75 ? 'coverage-good' : 'coverage-warn'}" style="width:${score}%"></div>
            </div>
        </div>
        ${status.clamav_image ? `<p class="text-muted" style="margin-top:10px;font-size:0.85rem">ClamAV image: <code class="mono">${status.clamav_image}</code></p>` : ''}
    `;
}

function renderICAPInstances(health) {
    const instances = health.instances ?? {};
    const keys = Object.keys(instances);
    if (keys.length === 0) {
        document.getElementById('icap-instances-panel').innerHTML =
            '<p class="empty-state">No per-instance data available.</p>';
        return;
    }

    const scoreBar = (score, width = 100) => {
        const c = score >= 80 ? '#10b981' : score >= 60 ? '#f59e0b' : '#ef4444';
        return `<div style="display:flex;align-items:center;gap:8px">
            <div style="flex:1;max-width:${width}px;height:7px;background:var(--border-color,#e5e7eb);border-radius:4px;overflow:hidden">
                <div style="height:100%;width:${score}%;background:${c};transition:width .4s"></div>
            </div>
            <span style="font-weight:600;color:${c};min-width:32px;text-align:right">${score}</span>
        </div>`;
    };

    const rows = keys.map(ver => {
        const inst  = instances[ver];
        const score = inst.health_score ?? 0;
        const ready = inst.ready;
        const sub   = inst.sub_scores ?? {};
        const subKeys = ['readiness','latency','signatures','errors','resources','queue'];
        const subCols = subKeys.map(k =>
            `<td style="text-align:center;font-size:0.82rem;color:${
                (sub[k]??100)>=80?'#10b981':(sub[k]??100)>=60?'#f59e0b':'#ef4444'}">${sub[k]??'—'}</td>`
        ).join('');

        return `
            <tr>
                <td>
                    <div style="display:flex;align-items:center;gap:8px">
                        <div style="width:10px;height:10px;border-radius:50%;background:${ready?'#10b981':'#ef4444'};flex-shrink:0"></div>
                        <strong>Instance ${ver.toUpperCase()}</strong>
                    </div>
                </td>
                <td style="min-width:160px">${scoreBar(score, 120)}</td>
                ${subCols}
            </tr>`;
    }).join('');

    document.getElementById('icap-instances-panel').innerHTML = `
        <table class="data-table" style="font-size:0.88rem">
            <thead><tr>
                <th>Instance</th>
                <th>Overall Score</th>
                <th style="text-align:center" title="weight 25%">Readiness</th>
                <th style="text-align:center" title="weight 25%">Latency</th>
                <th style="text-align:center" title="weight 20%">Signatures</th>
                <th style="text-align:center" title="weight 15%">Errors</th>
                <th style="text-align:center" title="weight 10%">Resources</th>
                <th style="text-align:center" title="weight 5%">Queue</th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table>
        <p style="font-size:0.76rem;color:var(--text-secondary,#666);margin-top:8px">
            Sub-scores shown only when reported by the ICAP Operator (requires K8s cluster).
        </p>`;
}

document.getElementById('icap-configure-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const resultEl = document.getElementById('icap-configure-result');
    resultEl.innerHTML = '<span class="text-muted">Applying…</span>';

    const mode     = document.getElementById('icap-scanning-mode').value;
    const replicas = parseInt(document.getElementById('icap-replicas').value, 10);

    const body = {};
    if (mode)              body.scanning_mode = mode;
    if (!isNaN(replicas))  body.replicas      = replicas;

    try {
        const res = await fetch(`${API_BASE}/icap/configure`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(body),
        });
        const result = await res.json();

        if (result.status === 'patched') {
            showToast('Configuration applied to K8s cluster', 'success');
            resultEl.innerHTML = `<span style="color:var(--success)">Applied to K8s: ${JSON.stringify(result.patch)}</span>`;
        } else if (result.status === 'applied_local') {
            showToast('Configuration saved, active immediately', 'success');
            const patch = result.patch ?? {};
            resultEl.innerHTML = `<span style="color:var(--success)">Saved: ${JSON.stringify(patch)}</span><br><small class="text-muted">${result.message}</small>`;
        } else {
            resultEl.innerHTML = `<span style="color:var(--danger)">${JSON.stringify(result)}</span>`;
        }
        setTimeout(loadICAPStatus, 800);
    } catch (err) {
        resultEl.innerHTML = `<span style="color:var(--danger)">Error: ${err.message}</span>`;
    }
});

// --- Theme ---
function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeButton(newTheme);
}

function updateThemeButton(theme) {
    const btn = document.querySelector('.theme-toggle');
    if (!btn) return;
    if (theme === 'dark') {
        btn.innerHTML = `${ICONS.sun} <span>Light Mode</span>`;
    } else {
        btn.innerHTML = `${ICONS.moon} <span>Dark Mode</span>`;
    }
}

(function () {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeButton(savedTheme);
})();

// =============================================================================
// Validation Tab
// =============================================================================

// --- Risk Score Calculator ---
document.getElementById('risk-score-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const resultEl = document.getElementById('risk-score-result');
    resultEl.innerHTML = '<p class="empty-state">Calculating…</p>';

    const body = {
        version:          document.getElementById('rs-version').value,
        source_env:       document.getElementById('rs-source-env').value,
        target_env:       document.getElementById('rs-target-env').value,
        add_policies:     parseInt(document.getElementById('rs-add-policies').value) || 0,
        remove_policies:  parseInt(document.getElementById('rs-remove-policies').value) || 0,
        max_allowed_score: parseInt(document.getElementById('rs-max-score').value) || 60,
    };

    try {
        const res = await fetch(`${API_BASE}/demo/risk-score`, {
            method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
        });
        const data = await res.json();
        renderRiskScoreResult(data);
    } catch (err) {
        resultEl.innerHTML = `<p style="color:var(--danger)">Error: ${err.message}</p>`;
    }
});

function renderRiskScoreResult(data) {
    const el = document.getElementById('risk-score-result');
    const score = data.total_score;
    const max   = data.max_allowed;
    const pct   = Math.min(100, Math.round(score / max * 100));
    const rec   = data.recommendation || '';
    const isRej = rec.startsWith('REJECTED');
    const colour = isRej ? 'var(--danger)' : score > max * 0.8 ? 'var(--warning)' : 'var(--success)';

    const factors = (data.factors || []).map(f => `
        <tr>
            <td>${f.name.replace(/_/g,' ')}</td>
            <td style="text-align:center">${f.score}</td>
            <td style="text-align:center">${(f.weight * 100).toFixed(0)}%</td>
            <td style="text-align:center">${f.weighted_score.toFixed(1)}</td>
            <td style="font-size:0.8rem;color:var(--text-muted)">${f.reason}</td>
        </tr>`).join('');

    el.innerHTML = `
        <div style="display:flex;align-items:center;gap:24px;margin-bottom:16px;flex-wrap:wrap">
            <div style="text-align:center">
                <div style="font-size:2.5rem;font-weight:700;color:${colour}">${score}</div>
                <div style="font-size:0.8rem;color:var(--text-muted)">/ ${max} max</div>
            </div>
            <div style="flex:1;min-width:160px">
                <div style="height:12px;background:var(--border);border-radius:6px;overflow:hidden">
                    <div style="height:100%;width:${pct}%;background:${colour};transition:width .4s"></div>
                </div>
                <div style="margin-top:8px;font-weight:600;color:${colour}">${rec}</div>
            </div>
        </div>
        <table class="audit-table" style="width:100%">
            <thead><tr>
                <th>Factor</th><th style="text-align:center">Score</th>
                <th style="text-align:center">Weight</th><th style="text-align:center">Weighted</th>
                <th>Reason</th>
            </tr></thead>
            <tbody>${factors}</tbody>
        </table>`;
}

// --- Policy Conflict Detector ---
document.getElementById('conflict-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const resultEl = document.getElementById('conflict-result');
    resultEl.innerHTML = '<p class="empty-state">Detecting…</p>';

    const stds = [];
    if (document.getElementById('cf-pci').checked)  stds.push('pci-dss');
    if (document.getElementById('cf-cis').checked)  stds.push('cis');

    const body = {
        name: 'policy-under-test',
        enforcement_mode:         document.getElementById('cf-enforcement').value,
        risk_level:               document.getElementById('cf-risk').value,
        pod_security_standard:    document.getElementById('cf-pss').value,
        target_environment:       document.getElementById('cf-env').value,
        compliance_standards:     stds,
        require_network_policies: document.getElementById('cf-network').checked,
        require_resource_limits:  document.getElementById('cf-limits').checked,
    };

    try {
        const res = await fetch(`${API_BASE}/demo/conflicts`, {
            method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
        });
        const data = await res.json();
        renderConflictResult(data);
    } catch (err) {
        resultEl.innerHTML = `<p style="color:var(--danger)">Error: ${err.message}</p>`;
    }
});

function renderConflictResult(data) {
    const el = document.getElementById('conflict-result');
    if (data.count === 0) {
        el.innerHTML = `<div style="color:var(--success);font-weight:600;padding:12px 0">
            No conflicts detected. Policy configuration is valid.</div>`;
        return;
    }

    const sevColour = { HIGH: 'var(--danger)', MEDIUM: 'var(--warning)', LOW: 'var(--success)', CRITICAL: '#7c3aed' };
    const rows = data.conflicts.map(c => `
        <div style="border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin-bottom:10px">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
                <span style="background:${sevColour[c.severity]||'var(--text-muted)'};color:#fff;
                    font-size:0.72rem;font-weight:700;padding:2px 8px;border-radius:4px">${c.severity}</span>
                <span style="font-size:0.75rem;color:var(--text-muted);text-transform:uppercase">${c.type}</span>
            </div>
            <div style="font-weight:500;margin-bottom:4px">${c.description}</div>
            <div style="font-size:0.85rem;color:var(--text-muted)">Fix: ${c.remediation}</div>
        </div>`).join('');

    el.innerHTML = `
        <div style="font-weight:600;margin-bottom:12px;color:var(--danger)">
            ${data.count} conflict${data.count > 1 ? 's' : ''} detected
        </div>
        ${rows}`;
}

// --- Health Score Scenarios ---
async function loadHealthScenarios() {
    const el = document.getElementById('health-scenarios-panel');
    el.innerHTML = '<p class="empty-state">Loading…</p>';
    try {
        const res = await fetch(`${API_BASE}/demo/health-scenarios`);
        const data = await res.json();
        renderHealthScenarios(data);
    } catch (err) {
        el.innerHTML = `<p style="color:var(--danger)">Error: ${err.message}</p>`;
    }
}

function renderHealthScenarios(scenarios) {
    const el = document.getElementById('health-scenarios-panel');
    const scoreBar = (score) => {
        const colour = score >= 80 ? 'var(--success)' : score >= 50 ? 'var(--warning)' : 'var(--danger)';
        return `<div style="display:flex;align-items:center;gap:8px">
            <div style="flex:1;height:8px;background:var(--border);border-radius:4px;overflow:hidden">
                <div style="height:100%;width:${score}%;background:${colour}"></div>
            </div>
            <span style="min-width:36px;text-align:right;font-weight:600;color:${colour}">${score}</span>
        </div>`;
    };

    const rows = scenarios.map(s => `
        <tr>
            <td><strong>${s.name}</strong><br><span style="font-size:0.8rem;color:var(--text-muted)">${s.description}</span></td>
            <td style="min-width:120px">${scoreBar(s.overall)}</td>
            <td style="text-align:center;font-size:0.85rem">${s.scores.readiness}</td>
            <td style="text-align:center;font-size:0.85rem">${s.scores.latency}</td>
            <td style="text-align:center;font-size:0.85rem">${s.scores.signatures}</td>
            <td style="text-align:center;font-size:0.85rem">${s.scores.errors}</td>
            <td style="text-align:center;font-size:0.85rem">${s.scores.resources}</td>
            <td style="text-align:center;font-size:0.85rem">${s.scores.queue}</td>
        </tr>`).join('');

    el.innerHTML = `
        <table class="audit-table" style="width:100%">
            <thead><tr>
                <th>Scenario</th><th>Overall Score</th>
                <th style="text-align:center" title="weight 25%">Readiness</th>
                <th style="text-align:center" title="weight 25%">Latency</th>
                <th style="text-align:center" title="weight 20%">Signatures</th>
                <th style="text-align:center" title="weight 15%">Errors</th>
                <th style="text-align:center" title="weight 10%">Resources</th>
                <th style="text-align:center" title="weight 5%">Queue</th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table>
        <p style="font-size:0.78rem;color:var(--text-muted);margin-top:8px">
            Weights: Readiness 25%, Latency 25%, Signatures 20%, Errors 15%, Resources 10%, Queue 5%
        </p>`;
}

// --- Traffic Switching Scenarios ---
async function loadTrafficScenarios() {
    const el = document.getElementById('traffic-scenarios-panel');
    el.innerHTML = '<p class="empty-state">Loading…</p>';
    try {
        const res = await fetch(`${API_BASE}/demo/traffic-scenarios`);
        const data = await res.json();
        renderTrafficScenarios(data);
    } catch (err) {
        el.innerHTML = `<p style="color:var(--danger)">Error: ${err.message}</p>`;
    }
}

function renderTrafficScenarios(scenarios) {
    const el = document.getElementById('traffic-scenarios-panel');

    const decisionStyle = (d) => {
        if (['route', 'collapse_to_single', 'enter_spread'].includes(d))
            return 'color:var(--success);font-weight:600';
        if (d === 'force_spread')
            return 'color:var(--danger);font-weight:600';
        return 'color:var(--warning)';
    };

    const icapBar = (score) => {
        const c = score >= 80 ? 'var(--success)' : score >= 70 ? 'var(--warning)' : 'var(--danger)';
        return `<span style="font-weight:600;color:${c}">${score}</span>`;
    };

    const rows = scenarios.map(s => `
        <tr>
            <td><strong>${s.name}</strong><br>
                <span style="font-size:0.8rem;color:var(--text-muted)">${s.description}</span></td>
            <td style="text-align:center">${icapBar(s.inputs.icap_aggregate)}</td>
            <td style="text-align:center;font-size:0.85rem">${s.inputs.traffic_growth}</td>
            <td style="text-align:center;font-size:0.85rem">${s.inputs.current_mode}</td>
            <td style="text-align:center">
                <span style="${decisionStyle(s.result.decision)}">${s.result.decision.replace(/_/g,' ')}</span>
            </td>
            <td style="text-align:center;font-weight:600">${s.result.selected}</td>
            <td style="font-size:0.8rem;color:var(--text-muted)">${s.result.reason}</td>
        </tr>`).join('');

    el.innerHTML = `
        <table class="audit-table" style="width:100%">
            <thead><tr>
                <th>Scenario</th>
                <th style="text-align:center">ICAP Health</th>
                <th style="text-align:center">Traffic Growth</th>
                <th style="text-align:center">Current Mode</th>
                <th style="text-align:center">Decision</th>
                <th style="text-align:center">Route To</th>
                <th>Reason</th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table>
        <p style="font-size:0.78rem;color:var(--text-muted);margin-top:8px">
            Thresholds: spread entry 8% growth | spread exit 3% growth |
            ICAP force-spread below 70 | min routing improvement 20% | cooldown 60s
        </p>`;
}

// ---------------------------------------------------------------------------
// Assistant (NLP chat)
// ---------------------------------------------------------------------------

let chatHistory = [];

function handleChatKey(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendChatMessage();
    }
}

async function sendChatMessage() {
    const input = document.getElementById('chat-input');
    const msg   = input.value.trim();
    if (!msg) return;

    input.value = '';
    appendChatMsg('user', msg);
    chatHistory.push({ role: 'user', content: msg });

    const sendBtn = document.getElementById('chat-send-btn');
    sendBtn.disabled = true;
    input.disabled   = true;

    const thinkingId = appendChatMsg('assistant', '<span class="chat-thinking">Thinking...</span>');

    try {
        const res = await fetch(`${API_BASE}/nlp/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: msg, history: chatHistory.slice(-20) }),
        });
        const data = await res.json();

        updateChatMsg(thinkingId, data.reply || '(no response)');
        chatHistory.push({ role: 'assistant', content: data.reply || '' });

        if (data.action) {
            handleChatAction(data.action);
        }
    } catch (err) {
        updateChatMsg(thinkingId, `Error: ${err.message}`);
    } finally {
        sendBtn.disabled = false;
        input.disabled   = false;
        input.focus();
    }
}

function handleChatAction(action) {
    if (action.type === 'switch_tab') {
        switchTab(action.tab);
        return;
    }
    if (action.type === 'fill_promotion_form') {
        switchTab('dashboard');
        const set = (id, val) => { if (val !== undefined && val !== '') { const el = document.getElementById(id); if (el) el.value = val; } };
        set('name',          action.name);
        set('app-name',      action.app_name);
        set('source-env',    action.source_env);
        set('target-env',    action.target_env);
        set('version',       action.version);
        set('app-namespace', action.namespace || '');
    }
}

let _chatMsgCounter = 0;
function appendChatMsg(role, html) {
    const id  = `chat-msg-${++_chatMsgCounter}`;
    const box = document.getElementById('chat-messages');
    const div = document.createElement('div');
    div.className = `chat-msg chat-msg-${role}`;
    div.id        = id;
    div.innerHTML = `<div class="chat-bubble">${formatChatContent(html)}</div>`;
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
    return id;
}

function updateChatMsg(id, html) {
    const el = document.getElementById(id);
    if (el) el.querySelector('.chat-bubble').innerHTML = formatChatContent(html);
    const box = document.getElementById('chat-messages');
    if (box) box.scrollTop = box.scrollHeight;
}

function formatChatContent(text) {
    // Basic markdown: code blocks, inline code, bold, newlines
    return text
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/```([\s\S]*?)```/g, '<pre style="background:var(--bg-secondary);padding:8px 10px;border-radius:6px;font-size:0.82rem;margin:6px 0;white-space:pre-wrap">$1</pre>')
        .replace(/`([^`]+)`/g, '<code style="background:var(--bg-secondary);padding:1px 5px;border-radius:3px;font-size:0.87em">$1</code>')
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/\n/g, '<br>');
}

// =============================================================================
// Policy Engine Tab
// =============================================================================

async function loadPENamespaces() {
    const el = document.getElementById('pe-namespaces-panel');
    try {
        const res = await fetch(`${API_BASE}/policy-engine/namespaces`);
        const data = await res.json();
        if (!Array.isArray(data) || data.length === 0) {
            el.innerHTML = '<p style="opacity:0.5;text-align:center;padding:24px 0">No namespaces detected. Policy Engine may be offline.</p>';
            return;
        }
        el.innerHTML = `
            <table style="width:100%;border-collapse:collapse;font-size:0.88rem">
                <thead>
                    <tr style="border-bottom:1px solid var(--border);text-align:left">
                        <th style="padding:6px 10px;opacity:0.6;font-weight:500">Namespace</th>
                        <th style="padding:6px 10px;opacity:0.6;font-weight:500">Environment</th>
                        <th style="padding:6px 10px;opacity:0.6;font-weight:500">Policy</th>
                        <th style="padding:6px 10px;opacity:0.6;font-weight:500">Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.map(ns => `
                        <tr style="border-bottom:1px solid var(--border)">
                            <td style="padding:8px 10px;font-family:monospace">${ns.namespace || ns.name || '-'}</td>
                            <td style="padding:8px 10px"><span class="badge badge-${envBadgeClass(ns.environment)}">${ns.environment || 'unknown'}</span></td>
                            <td style="padding:8px 10px;opacity:0.75">${ns.policy || ns.applied_policy || '-'}</td>
                            <td style="padding:8px 10px">
                                <button class="btn btn-secondary" style="padding:2px 10px;font-size:0.8rem"
                                    onclick="quickApplyPolicy('${ns.namespace || ns.name || ''}')">Apply</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>`;
    } catch (e) {
        el.innerHTML = `<p style="color:var(--danger);padding:12px">Error: ${e.message}</p>`;
    }
}

function envBadgeClass(env) {
    if (!env) return 'secondary';
    const e = env.toLowerCase();
    if (e.includes('prod')) return 'danger';
    if (e.includes('stag')) return 'warning';
    return 'success';
}

async function loadPEPolicies() {
    const el = document.getElementById('pe-policies-panel');
    try {
        const res = await fetch(`${API_BASE}/policy-engine/policies`);
        const data = await res.json();
        if (!Array.isArray(data) || data.length === 0) {
            el.innerHTML = '<p style="opacity:0.5;text-align:center;padding:24px 0">No policies found.</p>';
            return;
        }
        el.innerHTML = data.map(p => `
            <div style="padding:10px 12px;border:1px solid var(--border);border-radius:8px;margin-bottom:8px">
                <div style="font-weight:600;margin-bottom:2px">${p.name || p.id || '-'}</div>
                <div style="font-size:0.82rem;opacity:0.65">${p.description || p.type || ''}</div>
                ${p.compliance_frameworks ? `<div style="margin-top:6px;display:flex;gap:4px;flex-wrap:wrap">
                    ${p.compliance_frameworks.map(f => `<span style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:12px;padding:2px 8px;font-size:0.75rem">${f}</span>`).join('')}
                </div>` : ''}
            </div>`).join('');
    } catch (e) {
        el.innerHTML = `<p style="color:var(--danger);padding:12px">Error: ${e.message}</p>`;
    }
}

async function loadPEFrameworks() {
    const el = document.getElementById('pe-frameworks-panel');
    try {
        const res = await fetch(`${API_BASE}/policy-engine/compliance/frameworks`);
        const data = await res.json();
        if (!Array.isArray(data) || data.length === 0) {
            el.innerHTML = '<p style="opacity:0.5;padding:12px">No frameworks found.</p>';
            return;
        }
        el.innerHTML = `<div style="display:flex;gap:10px;flex-wrap:wrap;padding:4px 0">
            ${data.map(f => {
                const name = typeof f === 'string' ? f : (f.name || f.id || JSON.stringify(f));
                const desc = typeof f === 'object' ? (f.description || '') : '';
                return `<div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:10px;padding:10px 16px;min-width:140px">
                    <div style="font-weight:600;font-size:0.9rem">${name}</div>
                    ${desc ? `<div style="font-size:0.78rem;opacity:0.6;margin-top:4px">${desc}</div>` : ''}
                </div>`;
            }).join('')}
        </div>`;
    } catch (e) {
        el.innerHTML = `<p style="color:var(--danger);padding:12px">Error: ${e.message}</p>`;
    }
}

async function applyPEPolicy() {
    const ns = document.getElementById('pe-apply-ns').value.trim();
    const strategy = document.getElementById('pe-apply-strategy').value;
    const el = document.getElementById('pe-apply-result');
    if (!ns) { el.innerHTML = '<p style="color:var(--danger)">Please enter a namespace.</p>'; return; }
    el.innerHTML = '<p style="opacity:0.5">Applying...</p>';
    try {
        const res = await fetch(`${API_BASE}/policy-engine/namespaces/${encodeURIComponent(ns)}/apply`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ strategy }),
        });
        const data = await res.json();
        const ok = res.ok && !data.error;
        el.innerHTML = `<div style="padding:12px;border-radius:8px;background:${ok ? 'var(--bg-secondary)' : '#f8d7da'};color:${ok ? 'inherit' : '#721c24'};font-size:0.88rem">
            ${ok ? 'Policy applied successfully.' : (data.error || data.detail || JSON.stringify(data))}
            ${data.policy ? `<br><strong>Policy:</strong> ${data.policy}` : ''}
            ${data.environment ? `<br><strong>Environment:</strong> ${data.environment}` : ''}
        </div>`;
        if (ok) loadPENamespaces();
    } catch (e) {
        el.innerHTML = `<p style="color:var(--danger)">Error: ${e.message}</p>`;
    }
}

function quickApplyPolicy(ns) {
    document.getElementById('pe-apply-ns').value = ns;
    document.getElementById('pe-apply-ns').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// =============================================================================
// Load Balancer Tab
// =============================================================================

async function loadLBState() {
    const el = document.getElementById('lb-state-panel');
    try {
        const [stateRes, healthRes] = await Promise.all([
            fetch(`${API_BASE}/ssdlb/state`),
            fetch(`${API_BASE}/icap/health`),
        ]);
        const d = await stateRes.json();
        if (d.error) {
            el.innerHTML = `<p style="color:var(--danger);padding:12px">SLDB offline: ${d.error}</p>`;
            return;
        }
        const health = healthRes.ok ? await healthRes.json() : {};
        const instances = health.instances ?? {};

        const modeColor = d.mode === 'spread' ? '#667eea' : '#10b981';
        const secs = d.last_switch_ts ? Math.floor(Date.now() / 1000 - d.last_switch_ts) : null;
        const cooldown = secs !== null && secs < 60;

        const instRows = ['a','b','c'].map(v => {
            const inst  = instances[v] ?? {};
            const score = inst.health_score ?? '—';
            const ready = inst.ready;
            const isActive = d.mode === 'spread' || d.last_selected === v;
            const scoreNum = typeof score === 'number' ? score : 0;
            const barColor = scoreNum >= 80 ? '#10b981' : scoreNum >= 60 ? '#f59e0b' : '#ef4444';
            return `
                <div style="padding:10px 14px;border-radius:8px;background:var(--bg-secondary);border:2px solid ${isActive ? modeColor : 'transparent'}">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                        <span style="font-weight:700">Instance ${v.toUpperCase()}</span>
                        ${isActive ? `<span style="background:${modeColor};color:#fff;font-size:0.72rem;padding:1px 8px;border-radius:10px">ACTIVE</span>` : ''}
                    </div>
                    <div style="display:flex;align-items:center;gap:8px">
                        <div style="flex:1;height:6px;background:var(--border-color,#e5e7eb);border-radius:3px;overflow:hidden">
                            <div style="height:100%;width:${scoreNum}%;background:${barColor}"></div>
                        </div>
                        <span style="font-weight:600;color:${barColor};font-size:0.88rem">${score}</span>
                    </div>
                    ${ready !== undefined ? `<div style="font-size:0.72rem;margin-top:4px;color:${ready?'#10b981':'#ef4444'}">${ready?'● ready':'● not ready'}</div>` : ''}
                </div>`;
        }).join('');

        el.innerHTML = `
            <div style="display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap">
                <div style="flex:1;text-align:center;padding:14px;background:var(--bg-secondary);border-radius:8px">
                    <div style="font-size:0.72rem;opacity:0.6;margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em">Mode</div>
                    <div style="font-size:1.5rem;font-weight:800;color:${modeColor};text-transform:uppercase">${d.mode || '—'}</div>
                </div>
                <div style="flex:1;text-align:center;padding:14px;background:var(--bg-secondary);border-radius:8px">
                    <div style="font-size:0.72rem;opacity:0.6;margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em">Last switch</div>
                    <div style="font-size:1rem;font-weight:600">${secs !== null ? `${secs}s ago` : '—'}</div>
                </div>
                <div style="flex:1;text-align:center;padding:14px;background:var(--bg-secondary);border-radius:8px">
                    <div style="font-size:0.72rem;opacity:0.6;margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em">Cooldown</div>
                    <div style="font-size:1rem;font-weight:600;color:${cooldown?'#f59e0b':'#10b981'}">
                        ${cooldown ? `${60 - secs}s left` : 'Clear'}
                    </div>
                </div>
            </div>
            <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px">${instRows}</div>`;
    } catch (e) {
        el.innerHTML = `<p style="color:var(--danger);padding:12px">Error: ${e.message}</p>`;
    }
}

async function loadLBTrend() {
    const el = document.getElementById('lb-trend-panel');
    try {
        const res = await fetch(`${API_BASE}/ssdlb/trend`);
        const d   = await res.json();
        if (d.error && !d.mode) {
            el.innerHTML = `<p style="color:var(--danger);padding:12px">SLDB offline: ${d.error}</p>`;
            return;
        }

        // Note shown when Prometheus is unavailable
        const note = d._note ? `<p style="font-size:0.78rem;color:var(--text-secondary,#9ca3af);margin-bottom:12px;font-style:italic">ℹ ${d._note}</p>` : '';

        // If we have Prometheus trend data, show growth metrics prominently
        const hasGrowth = d.short_window_rate !== undefined || d.growth_ratio !== undefined;
        if (hasGrowth) {
            const short  = (d.short_window_rate  ?? 0).toFixed(2);
            const medium = (d.medium_window_rate ?? 0).toFixed(2);
            const growth = d.growth_ratio !== undefined ? (d.growth_ratio * 100).toFixed(1) : '—';
            const growthColor = Math.abs(parseFloat(growth)) >= 8 ? '#ef4444'
                : Math.abs(parseFloat(growth)) >= 3 ? '#f59e0b' : '#10b981';
            el.innerHTML = `${note}
                <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px">
                    <div style="text-align:center;padding:12px;background:var(--bg-secondary);border-radius:8px">
                        <div style="font-size:0.72rem;opacity:0.6;margin-bottom:4px">SHORT (1m) req/s</div>
                        <div style="font-size:1.2rem;font-weight:700">${short}</div>
                    </div>
                    <div style="text-align:center;padding:12px;background:var(--bg-secondary);border-radius:8px">
                        <div style="font-size:0.72rem;opacity:0.6;margin-bottom:4px">MEDIUM (5m) req/s</div>
                        <div style="font-size:1.2rem;font-weight:700">${medium}</div>
                    </div>
                    <div style="text-align:center;padding:12px;background:var(--bg-secondary);border-radius:8px">
                        <div style="font-size:0.72rem;opacity:0.6;margin-bottom:4px">GROWTH</div>
                        <div style="font-size:1.2rem;font-weight:700;color:${growthColor}">${growth}%</div>
                    </div>
                </div>`;
        } else {
            // Fallback: show routing state key/values
            const entries = Object.entries(d).filter(([k]) => !k.startsWith('_') && !k.includes('error'));
            if (entries.length === 0) {
                el.innerHTML = `${note}<p style="opacity:0.5;text-align:center;padding:24px 0">No traffic data yet — Prometheus integration not available.</p>`;
                return;
            }
            const rows = entries.map(([k, v]) => {
                const label = k.replace(/_/g, ' ');
                const val = typeof v === 'number' ? (Math.abs(v) < 10 ? v.toFixed(3) : v.toFixed(1)) : String(v);
                return `<tr style="border-bottom:1px solid var(--border-color,#e5e7eb)">
                    <td style="padding:7px 10px;opacity:0.65;font-size:0.83rem;text-transform:capitalize">${label}</td>
                    <td style="padding:7px 10px;font-family:monospace;font-size:0.88rem">${val}</td>
                </tr>`;
            }).join('');
            el.innerHTML = `${note}<table style="width:100%;border-collapse:collapse"><tbody>${rows}</tbody></table>`;
        }
    } catch (e) {
        el.innerHTML = `<p style="color:var(--danger);padding:12px">Error: ${e.message}</p>`;
    }
}

async function lbSetVersion(version) {
    const el = document.getElementById('lb-override-result');
    el.innerHTML = '<p style="opacity:0.5">Sending...</p>';
    try {
        const res = await fetch(`${API_BASE}/ssdlb/set-version/${version}`, { method: 'POST' });
        const d = await res.json();
        const ok = !d.error;
        el.innerHTML = `<div style="padding:10px 14px;border-radius:8px;background:var(--bg-secondary);font-size:0.88rem">
            ${ok
                ? `Routed to <strong>${version.toUpperCase()}</strong>. ${d.message || ''}`
                : `<span style="color:var(--danger)">Error: ${d.error}</span>`}
        </div>`;
        if (ok) { loadLBState(); }
    } catch (e) {
        el.innerHTML = `<p style="color:var(--danger)">Error: ${e.message}</p>`;
    }
}

async function lbAutoRoute() {
    const el = document.getElementById('lb-override-result');
    const dec = document.getElementById('lb-decision-panel');
    el.innerHTML = '<p style="opacity:0.5">Running auto-route decision...</p>';
    try {
        const res = await fetch(`${API_BASE}/ssdlb/auto-route`, { method: 'POST' });
        const d = await res.json();
        el.innerHTML = '';
        if (d.error) {
            dec.innerHTML = `<p style="color:var(--danger);padding:12px">Error: ${d.error}</p>`;
            return;
        }
        const decisionColor = d.decision === 'no_change' ? 'var(--text-primary)' :
                              (d.decision === 'force_spread' || d.decision === 'enter_spread') ? 'var(--accent)' : 'var(--success,#28a745)';
        dec.innerHTML = `
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
                <div style="font-size:1.4rem;font-weight:700;color:${decisionColor};text-transform:uppercase">${d.decision || '-'}</div>
                ${d.selected_version ? `<span style="background:var(--accent);color:#fff;border-radius:6px;padding:2px 10px;font-size:0.88rem">Instance ${d.selected_version.toUpperCase()}</span>` : ''}
            </div>
            <table style="width:100%;border-collapse:collapse;font-size:0.87rem">
                <tbody>
                    ${Object.entries(d).filter(([k]) => !['decision','selected_version'].includes(k)).map(([k,v]) =>
                        `<tr style="border-bottom:1px solid var(--border)">
                            <td style="padding:6px 10px;opacity:0.65">${k}</td>
                            <td style="padding:6px 10px;font-family:monospace">${typeof v === 'object' ? JSON.stringify(v) : String(v)}</td>
                        </tr>`).join('')}
                </tbody>
            </table>`;
        loadLBState();
        loadLBTrend();
    } catch (e) {
        el.innerHTML = `<p style="color:var(--danger)">Error: ${e.message}</p>`;
    }
}

loadData();
loadSystemStatus();
loadICAPHealthStat();

// ── System status (header component badges) ────────────────────────────────
async function loadSystemStatus() {
    const el = document.getElementById('system-status');
    if (!el) return;
    try {
        const res  = await fetch(`${API_BASE}/system/status`);
        const data = await res.json();

        const order = [
            { key: 'meds',          label: 'MEDS' },
            { key: 'policy_engine', label: 'Policy Engine' },
            { key: 'icap_operator', label: 'ICAP Operator' },
            { key: 'ssdlb',         label: 'SLDB' },
        ];

        el.innerHTML = order.map(c => {
            const comp   = data[c.key] || {};
            const online = comp.status === 'ok';
            const cls    = online ? 'online' : comp.status === 'offline' ? 'offline' : '';
            return `
                <div class="component-badge ${cls}" title="${comp.description || ''}">
                    <span class="component-dot ${cls}"></span>
                    <span>${c.label}</span>
                </div>`;
        }).join('');
    } catch (e) {
        console.warn('system status unavailable:', e);
    }
}

// ── ICAP health stat in KPI strip ─────────────────────────────────────────
async function loadICAPHealthStat() {
    try {
        const res   = await fetch(`${API_BASE}/icap/health`);
        const data  = await res.json();
        const score = data.aggregate_health_score ?? 0;
        const el    = document.getElementById('icap-health-stat');
        const card  = document.getElementById('icap-health-card');
        if (el) el.textContent = score;
        if (card) {
            card.classList.remove('success', 'warning', 'danger');
            card.classList.add(score >= 80 ? 'success' : score >= 60 ? 'warning' : 'danger');
        }
    } catch (_) {}
}
