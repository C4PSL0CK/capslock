const API_BASE = 'http://localhost:8000/api';

let policies = [];
let promotions = [];

async function loadData() {
    try {
        const [policiesRes, promotionsRes, analyticsRes] = await Promise.all([
            fetch(`${API_BASE}/policies`),
            fetch(`${API_BASE}/promotions`),
            fetch(`${API_BASE}/analytics`)
        ]);
        
        policies = await policiesRes.json();
        promotions = await promotionsRes.json();
        const analytics = await analyticsRes.json();
        
        renderPolicies();
        renderPromotions();
        updateStats(analytics);
    } catch (error) {
        console.error('Failed to load data:', error);
    }
}

function renderPolicies() {
    const selector = document.getElementById('policy-selector');
    selector.innerHTML = policies.map(p => `
        <div class="policy-item">
            <label>
                <input type="checkbox" name="policy" value="${p.name}">
                <span><strong>${p.name}</strong> - ${p.description} (${p.severity})</span>
            </label>
        </div>
    `).join('');
}

function renderPromotions() {
    const list = document.getElementById('promotions-list');
    if (promotions.length === 0) {
        list.innerHTML = '<p style="text-align:center;color:#999;">No promotions yet</p>';
        return;
    }
    
    list.innerHTML = promotions.map(p => `
        <div class="promotion-item">
            <div>
                <strong>${p.name}</strong><br>
                <small>${p.source} → ${p.target} | v${p.version} | Risk: ${p.risk_score}</small>
            </div>
            <span class="badge badge-${p.decision === 'APPROVED' ? 'approved' : 'rejected'}">
                ${p.decision}
            </span>
        </div>
    `).join('');
}

function updateStats(analytics) {
    document.getElementById('total-promotions').textContent = analytics.total_promotions;
    document.getElementById('approved').textContent = analytics.approved;
    document.getElementById('rejected').textContent = analytics.rejected;
    document.getElementById('avg-risk').textContent = analytics.average_risk_score;
}

document.getElementById('promotion-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const selectedPolicies = Array.from(document.querySelectorAll('input[name="policy"]:checked'))
        .map(cb => cb.value);
    
    const data = {
        name: document.getElementById('name').value,
        application_name: document.getElementById('app-name').value,
        source_environment: document.getElementById('source-env').value,
        target_environment: document.getElementById('target-env').value,
        version: document.getElementById('version').value,
        add_policies: selectedPolicies
    };
    
    try {
        const response = await fetch(`${API_BASE}/promotions`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        showResult(result);
        
        document.getElementById('promotion-form').reset();
        await loadData();
    } catch (error) {
        alert('Failed to create promotion: ' + error.message);
    }
});

function showResult(result) {
    const modal = document.getElementById('result-modal');
    const details = document.getElementById('result-details');
    
    const decisionClass = result.decision === 'APPROVED' ? 'success' : 'danger';
    
    details.innerHTML = `
        <h2>Promotion Result</h2>
        <div class="stat-card ${decisionClass}">
            <div class="stat-value">${result.decision}</div>
            <div class="stat-label">Risk Score: ${result.risk_score} / ${result.max_allowed}</div>
        </div>
        
        <h3 style="margin-top:20px;">Risk Assessment</h3>
        <p><strong>${result.message}</strong></p>
        
        ${result.risk_assessment.factors.map(f => `
            <div class="risk-factor">
                <div class="risk-factor-name">${f.name.replace(/_/g, ' ').toUpperCase()}</div>
                <div class="risk-factor-score">${Math.round(f.weighted_score)} points</div>
                <div style="font-size:0.9rem;color:#666;">${f.reason}</div>
            </div>
        `).join('')}
    `;
    
    modal.style.display = 'block';
}

document.querySelector('.close').addEventListener('click', () => {
    document.getElementById('result-modal').style.display = 'none';
});

window.addEventListener('click', (e) => {
    const modal = document.getElementById('result-modal');
    if (e.target === modal) {
        modal.style.display = 'none';
    }
});

loadData();
