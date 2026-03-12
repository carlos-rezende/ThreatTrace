/**
 * ThreatTrace Dashboard - Main application
 */
let currentData = null;
let currentInvestigation = null;
let currentQueryType = '';
let currentQueryValue = '';
let cyInstance = null;

// Initialize history sidebar
function initHistory() {
    renderHistorySidebar('history-list', (target) => {
        document.getElementById('input-domain').value = target;
        document.querySelector('.type-tab[data-type="domain"]').click();
        document.querySelector('.mode-tab[data-mode="lookup"]').click();
        runSearch('domain', target);
    });
}

// Mode tabs
document.querySelectorAll('.mode-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.mode-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('btn-submit').textContent =
            tab.dataset.mode === 'investigate' ? t('fullInvestigation') : t('investigate');
    });
});

// Type tabs
document.querySelectorAll('.type-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.type-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        document.querySelectorAll('.input-wrap').forEach(w => w.classList.add('hidden'));
        const wrap = document.querySelector(`.input-${tab.dataset.type}`);
        if (wrap) wrap.classList.remove('hidden');
        document.getElementById('input-domain').required = tab.dataset.type === 'domain';
        document.getElementById('input-url').required = tab.dataset.type === 'url';
        document.getElementById('input-hash').required = tab.dataset.type === 'hash';
        document.getElementById('input-tag').required = tab.dataset.type === 'tag';
        document.getElementById('input-signature').required = tab.dataset.type === 'signature';
    });
});

function validateInput(type, value) {
    if (!value) return { valid: false, msg: t('fieldRequired') };
    if (type === 'domain') {
        const re = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/;
        if (!re.test(value)) return { valid: false, msg: t('invalidDomain') };
    } else if (type === 'url') {
        if (!value.startsWith('http://') && !value.startsWith('https://')) {
            return { valid: false, msg: t('urlMustStart') };
        }
        try { new URL(value); } catch {
            return { valid: false, msg: t('invalidUrl') };
        }
    } else if (type === 'hash') {
        if (value.length !== 32 && value.length !== 64) {
            return { valid: false, msg: t('invalidHash') };
        }
        if (!/^[a-f0-9]+$/.test(value)) return { valid: false, msg: t('hashHexOnly') };
    } else if (type === 'tag' || type === 'signature') {
        if (value.length < 2) return { valid: false, msg: t('minChars') };
    }
    return { valid: true };
}

// Form submit
document.getElementById('search-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const mode = document.querySelector('.mode-tab.active').dataset.mode;
    const type = document.querySelector('.type-tab.active').dataset.type;
    let value = '';
    if (type === 'domain') value = document.getElementById('input-domain').value.trim();
    else if (type === 'url') value = document.getElementById('input-url').value.trim();
    else if (type === 'hash') value = document.getElementById('input-hash').value.trim().toLowerCase();
    else if (type === 'tag') value = document.getElementById('input-tag').value.trim();
    else if (type === 'signature') value = document.getElementById('input-signature').value.trim();

    const validation = validateInput(type, value);
    if (!validation.valid) {
        showToast(validation.msg, 'error');
        showError(validation.msg);
        return;
    }
    hideError();

    if (mode === 'investigate' && type === 'domain') {
        await runInvestigation(value);
    } else if (type === 'tag' || type === 'signature') {
        await runTagOrSignature(type, value);
    } else {
        await runSearch(type, value);
    }
});

async function runSearch(type, value) {
    hideError();
    hideDashboard();
    showLoading(t('analyzing'));

    try {
        let data;
        if (type === 'domain') data = await apiDomain(value);
        else if (type === 'url') data = await apiUrl(value);
        else data = await apiHash(value);

        currentData = data;
        currentInvestigation = null;
        currentQueryType = type;
        currentQueryValue = value;

        const domainForAnalysis = type === 'url' ? extractDomainFromUrl(value) : (type === 'domain' ? value : null);
        if (domainForAnalysis) {
            addToHistory(domainForAnalysis);
            const [risk, timeline] = await Promise.all([apiRisk(domainForAnalysis), apiTimeline(domainForAnalysis)]);
            renderDashboard(data, risk, timeline);
            const graphData = await apiGraph(domainForAnalysis);
            renderGraph(graphData);
        } else {
            addToHistory(value);
            renderDashboard(data, null, null);
            renderGraph(null);
        }

        showDashboard();
    } catch (err) {
        showError(err.message);
        showToast(err.message, 'error');
    } finally {
        hideLoading();
    }
}

async function runInvestigation(target) {
    hideError();
    hideDashboard();
    showLoading(t('runningInvestigation'));

    try {
        const data = await apiInvestigate(target);
        currentInvestigation = data;
        currentData = data.threat_lookup || {};
        currentQueryType = 'domain';
        currentQueryValue = target;

        addToHistory(target);
        renderDashboard(currentData, data.risk, data.timeline);
        const graphData = await apiGraph(target);
        renderGraph(graphData);
        showDashboard();
    } catch (err) {
        showError(err.message);
        showToast(err.message, 'error');
    } finally {
        hideLoading();
    }
}

async function runTagOrSignature(type, value) {
    hideError();
    hideDashboard();
    showLoading(type === 'tag' ? t('queryingTag') : t('queryingSignature'));

    try {
        const data = type === 'tag' ? await apiTag(value) : await apiSignature(value);
        currentData = _normalizeTagSignatureResponse(data, type, value);
        currentInvestigation = null;
        currentQueryType = type;
        currentQueryValue = value;

        renderDashboard(currentData, null, null);
        renderGraph(null);
        showDashboard();
    } catch (err) {
        showError(err.message);
        showToast(err.message, 'error');
    } finally {
        hideLoading();
    }
}

function _normalizeTagSignatureResponse(data, type, value) {
    const urls = (data.urls || []).map(u => ({
        url: u.url,
        malware_family: u.signature || (type === 'signature' ? value : null),
        first_seen: u.firstseen || u.dateadded,
        last_seen: u.lastseen || null,
        status: (u.url_status || '').toLowerCase() === 'online' ? 'active' : 'inactive',
        urlhaus_reference: u.urlhaus_reference,
        payload_hash: u.sha256_hash || null,
    }));
    const campaigns = [];
    const infra = { domains: [], ips: [] };
    urls.forEach(u => {
        try {
            const host = new URL(u.url).hostname;
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) infra.ips.push(host);
            else infra.domains.push(host);
        } catch (_) {}
    });
    infra.domains = [...new Set(infra.domains)];
    infra.ips = [...new Set(infra.ips)];
    return {
        query: value,
        query_type: type,
        malicious_urls: urls,
        campaigns,
        infrastructure: infra,
    };
}

function renderDashboard(data, risk, timeline) {
    const rawTarget = data?.query || currentQueryValue;
    const urls = data?.malicious_urls || [];
    const campaigns = data?.campaigns || [];
    const infra = data?.infrastructure || {};

    // Target: para URL, exibir domínio; para hash, formato abreviado; para outros longos, truncar
    let targetDisplay = rawTarget;
    let targetTitle = '';
    if (rawTarget && (rawTarget.startsWith('http://') || rawTarget.startsWith('https://'))) {
        try {
            const host = new URL(rawTarget).hostname.replace(/^www\./, '');
            targetDisplay = host;
            targetTitle = rawTarget;
        } catch (_) {}
    } else if (rawTarget && rawTarget.length === 64 && /^[a-f0-9]+$/.test(rawTarget)) {
        targetDisplay = rawTarget.slice(0, 12) + '…' + rawTarget.slice(-8);
        targetTitle = rawTarget;
    } else if (rawTarget && rawTarget.length === 32 && /^[a-f0-9]+$/.test(rawTarget)) {
        targetDisplay = rawTarget.slice(0, 8) + '…' + rawTarget.slice(-6);
        targetTitle = rawTarget;
    } else if (rawTarget && rawTarget.length > 50) {
        targetDisplay = rawTarget.slice(0, 24) + '…' + rawTarget.slice(-16);
        targetTitle = rawTarget;
    }

    // Threat Overview
    const firstSeen = campaigns[0]?.first_seen || urls[0]?.first_seen || '-';
    const lastSeen = campaigns.reduce((a, c) => (c.last_seen > a ? c.last_seen : a) || a, '') || urls[0]?.last_seen || '-';

    document.getElementById('threat-overview').innerHTML = `
        <div class="overview-stats">
            <div class="stat-item">
                <div class="stat-label">${t('target')}</div>
                <div class="stat-value" ${targetTitle ? `title="${escapeHtml(targetTitle)}"` : ''}>${escapeHtml(targetDisplay)}</div>
            </div>
            <div class="stat-item">
                <div class="stat-label">${t('maliciousUrls')}</div>
                <div class="stat-value">${urls.length}</div>
            </div>
            <div class="stat-item">
                <div class="stat-label">${t('firstSeen')}</div>
                <div class="stat-value">${firstSeen}</div>
            </div>
            <div class="stat-item">
                <div class="stat-label">${t('lastSeen')}</div>
                <div class="stat-value">${lastSeen}</div>
            </div>
        </div>
    `;

    // Risk Gauge
    renderRiskGauge(risk);

    // Timeline
    if (timeline) renderTimelineChart('timeline-chart', timeline);

    // Campaign Table with sortable rows
    const campaignRows = campaigns.map(c => {
        const first = c.first_seen || '-';
        const last = c.last_seen || '-';
        let days = 0;
        if (c.first_seen && c.last_seen) {
            const d1 = new Date(c.first_seen.split(' ')[0]);
            const d2 = new Date(c.last_seen.split(' ')[0]);
            days = Math.max(0, Math.floor((d2 - d1) / 86400000)) + 1;
        }
        return { family: c.family, first, last, days };
    });

    document.getElementById('campaign-table-wrap').innerHTML = campaignRows.length ? `
        <table class="campaign-table" id="campaign-table">
            <thead>
                <tr>
                    <th class="sortable" data-sort="family">${t('malwareFamily')}</th>
                    <th class="sortable" data-sort="first">${t('firstSeen')}</th>
                    <th class="sortable" data-sort="last">${t('lastSeen')}</th>
                    <th class="sortable" data-sort="days">${t('activityDays')}</th>
                </tr>
            </thead>
            <tbody>
                ${campaignRows.map(r => `<tr>
                    <td>${escapeHtml(r.family)}</td>
                    <td>${r.first}</td>
                    <td>${r.last}</td>
                    <td>${r.days}</td>
                </tr>`).join('')}
            </tbody>
        </table>
    ` : `<div class="empty-state">${t('noCampaigns')}</div>`;

    // Table sorting
    let sortOrder = {};
    document.querySelectorAll('#campaign-table .sortable').forEach(th => {
        th.onclick = () => {
            const sort = th.dataset.sort;
            sortOrder[sort] = sortOrder[sort] === 'asc' ? 'desc' : 'asc';
            const dir = sortOrder[sort] === 'asc' ? 1 : -1;
            const sorted = [...campaignRows].sort((a, b) => {
                const va = a[sort], vb = b[sort];
                if (typeof va === 'number') return dir * (va - vb);
                return dir * String(va).localeCompare(vb);
            });
            document.querySelector('#campaign-table tbody').innerHTML = sorted.map(r =>
                `<tr><td>${escapeHtml(r.family)}</td><td>${r.first}</td><td>${r.last}</td><td>${r.days}</td></tr>`
            ).join('');
        };
    });

    // Infrastructure with copy buttons
    const items = [];
    (infra.domains || []).forEach(d => {
        const row = document.createElement('div');
        row.className = 'indicator-row';
        row.innerHTML = `<span class="indicator-value">${escapeHtml(d)}</span>`;
        row.appendChild(createCopyButton(d));
        items.push(row.outerHTML);
    });
    (infra.ips || []).forEach(ip => {
        const row = document.createElement('div');
        row.className = 'indicator-row';
        row.innerHTML = `<span class="indicator-value">${escapeHtml(ip)}</span>`;
        row.appendChild(createCopyButton(ip));
        items.push(row.outerHTML);
    });
    const hashes = (data?.campaigns || []).flatMap(c => c.payload_hashes || []).slice(0, 10);
    const hashSet = new Set(hashes);
    urls.forEach(u => { if (u.payload_hash) hashSet.add(u.payload_hash); });
    [...hashSet].slice(0, 15).forEach(h => {
        const row = document.createElement('div');
        row.className = 'indicator-row';
        row.innerHTML = `<span class="indicator-value" title="${escapeHtml(h)}">${escapeHtml(h.length > 40 ? h.slice(0, 40) + '...' : h)}</span>`;
        row.appendChild(createCopyButton(h));
        if (h.length === 64 && /^[a-f0-9]+$/.test(h)) {
            const dlBtn = document.createElement('a');
            dlBtn.href = getPayloadDownloadUrl(h);
            dlBtn.target = '_blank';
            dlBtn.rel = 'noopener';
            dlBtn.className = 'copy-btn download-btn';
            dlBtn.title = t('downloadPayload');
            dlBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
            row.appendChild(dlBtn);
        }
        items.push(row.outerHTML);
    });
    document.getElementById('infrastructure-panel').innerHTML =
        items.length ? items.join('') : `<div class="empty-state">${t('noInfrastructure')}</div>`;

    // URLs with copy
    document.getElementById('urls-panel').innerHTML = urls.length ? urls.slice(0, 15).map(u => {
        const row = document.createElement('div');
        row.className = 'indicator-row';
        row.innerHTML = `<span class="indicator-value" title="${escapeHtml(u.url)}">${escapeHtml(u.url.length > 60 ? u.url.slice(0, 60) + '...' : u.url)}</span>`;
        row.appendChild(createCopyButton(u.url));
        return row.outerHTML;
    }).join('') : `<div class="empty-state">${t('noMaliciousUrls')}</div>`;

    initHistory();
}

function renderRiskGauge(risk) {
    const container = document.getElementById('risk-gauge');
    if (!risk) {
        container.innerHTML = `<div class="empty-state">${t('riskNotAvailable')}</div>`;
        return;
    }

    const score = risk.risk_score || 0;
    const level = risk.risk_level || 'low';
    const circumference = 2 * Math.PI * 52;
    const offset = circumference - (score / 100) * circumference;

    container.innerHTML = `
        <div class="risk-gauge">
            <div class="risk-gauge-circle">
                <svg class="risk-gauge-svg" width="120" height="120" viewBox="0 0 120 120">
                    <circle class="risk-gauge-bg" cx="60" cy="60" r="52"/>
                    <circle class="risk-gauge-fill ${level}" cx="60" cy="60" r="52"
                        stroke-dasharray="${circumference}"
                        stroke-dashoffset="${offset}"/>
                </svg>
                <span class="risk-gauge-value">${score}</span>
            </div>
            <div class="risk-gauge-details">
                <div class="risk-level-badge ${level}">${level.toUpperCase()}</div>
                <div class="risk-factors">
                    ${(risk.factors || []).map(f => `<span class="risk-factor">${escapeHtml(f.name)}: ${escapeHtml(f.detail)}</span>`).join('')}
                </div>
            </div>
        </div>
    `;
}

function renderGraph(graphData) {
    const container = document.getElementById('cy-graph');
    if (!container) return;
    if (cyInstance) {
        cyInstance.destroy();
        cyInstance = null;
    }
    const hasNodes = graphData?.elements?.nodes?.length || graphData?.nodes?.length;
    if (hasNodes) {
        container.innerHTML = '';
        cyInstance = initGraph('cy-graph', graphData);
    } else {
        container.innerHTML = `<div class="empty-state graph-empty">${t('graphEmpty')}</div>`;
    }
}

// Export buttons
document.getElementById('btn-export-json').addEventListener('click', () => {
    const data = currentInvestigation || currentData;
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'threattrace_report.json';
    a.click();
    URL.revokeObjectURL(a.href);
    showToast(t('reportDownloaded'), 'success');
});

document.getElementById('btn-export-pdf').addEventListener('click', () => {
    if (['tag', 'signature'].includes(currentQueryType)) {
        showToast(t('exportPdfNotAvailable'), 'error');
        return;
    }
    const params = new URLSearchParams({
        query_type: currentQueryType,
        query_value: currentQueryValue
    });
    window.open(`/api/export/pdf?${params}`, '_blank');
});

document.getElementById('btn-export-md').addEventListener('click', async () => {
    if (!currentQueryValue) {
        showToast(t('noInvestigationExport'), 'error');
        return;
    }
    if (['tag', 'signature'].includes(currentQueryType)) {
        showToast(t('exportMdNotAvailable'), 'error');
        return;
    }
    try {
        const blob = await apiExportMarkdown(currentQueryType, currentQueryValue);
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `threattrace_${currentQueryValue.replace(/[^a-zA-Z0-9.-]/g, '_')}.md`;
        a.click();
        URL.revokeObjectURL(a.href);
        showToast(t('markdownDownloaded'), 'success');
    } catch (err) {
        showToast(err.message || t('exportError'), 'error');
    }
});

function showLoading(text) {
    document.getElementById('loading-text').textContent = text;
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('btn-submit').disabled = true;
}

function hideLoading() {
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('btn-submit').disabled = false;
}

function showError(msg) {
    const el = document.getElementById('error');
    el.textContent = msg;
    el.classList.remove('hidden');
}

function hideError() {
    document.getElementById('error').classList.add('hidden');
}

function showDashboard() {
    document.getElementById('dashboard').classList.remove('hidden');
}

function hideDashboard() {
    document.getElementById('dashboard').classList.add('hidden');
}

// Samples - carregar exemplos de teste
let samplesCache = { urls: [], hashes: [] };
document.getElementById('btn-load-samples').addEventListener('click', async () => {
    const btn = document.getElementById('btn-load-samples');
    const list = document.getElementById('samples-list');
    if (list.classList.contains('loading')) return;
    btn.disabled = true;
    list.classList.remove('hidden');
    list.classList.add('loading');
    list.innerHTML = `<span class="samples-loading">${t('loading')}</span>`;

    try {
        const [urlsData, payloadsData] = await Promise.all([
            apiRecentUrls(5),
            apiRecentPayloads(5)
        ]);
        const urls = urlsData?.urls || [];
        const payloads = payloadsData?.payloads || [];
        samplesCache = { urls: urls.map(u => u.url), hashes: payloads.map(p => p.sha256_hash || p.md5_hash || '') };
        let html = '';
        if (urls.length) {
            html += `<div class="samples-group"><strong>${t('recentUrls')}</strong> `;
            urls.forEach((u, i) => {
                const label = u.url.length > 50 ? u.url.slice(0, 50) + '...' : u.url;
                html += `<button type="button" class="sample-chip" data-type="url" data-idx="${i}">${escapeHtml(label)}</button> `;
            });
            html += '</div>';
        }
        if (payloads.length) {
            html += `<div class="samples-group"><strong>${t('recentHashes')}</strong> `;
            payloads.forEach((p, i) => {
                const h = p.sha256_hash || p.md5_hash || '';
                html += `<button type="button" class="sample-chip" data-type="hash" data-idx="${i}">${h.slice(0, 16)}...</button> `;
            });
            html += '</div>';
        }
        if (!html) html = `<span class="samples-empty">${t('noSamples')}</span>`;
        list.innerHTML = html;

        list.querySelectorAll('.sample-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                const type = chip.dataset.type;
                const idx = parseInt(chip.dataset.idx, 10);
                const value = type === 'url' ? samplesCache.urls[idx] : samplesCache.hashes[idx];
                if (!value) return;
                document.querySelector(`.type-tab[data-type="${type}"]`).click();
                document.getElementById(`input-${type}`).value = value;
                document.getElementById('search-form').requestSubmit();
            });
        });
    } catch (err) {
        list.innerHTML = `<span class="samples-error">${escapeHtml(err.message)}</span>`;
        showToast(err.message, 'error');
    } finally {
        btn.disabled = false;
        list.classList.remove('loading');
    }
});

function onLangChange() {
    initHistory();
    if (document.getElementById('dashboard')?.classList.contains('hidden') === false && currentData) {
        const risk = currentInvestigation?.risk ?? null;
        const timeline = currentInvestigation?.timeline ?? null;
        renderDashboard(currentData, risk, timeline);
    }
}

// Clear history button
document.getElementById('btn-clear-history')?.addEventListener('click', () => {
    clearHistory();
    initHistory();
    showToast(t('historyCleared'), 'success');
});

// Event delegation para botões de copiar (preserva função após innerHTML)
document.getElementById('dashboard')?.addEventListener('click', (e) => {
    const btn = e.target.closest('.copy-btn');
    if (btn && btn.dataset.copy) {
        e.stopPropagation();
        copyToClipboard(btn.dataset.copy, btn);
    }
});

// Init
initHistory();
