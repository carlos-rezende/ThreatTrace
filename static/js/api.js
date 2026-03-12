/**
 * ThreatTrace API client
 */
const API_BASE = '';

function handleApiError(res, body) {
    if (res.status === 429) throw new Error(typeof t === 'function' ? t('rateLimit') : 'Rate limit reached. Please wait a few minutes.');
    throw new Error(body?.detail || `Erro ${res.status}`);
}

async function apiDomain(domain) {
    const res = await fetch(`${API_BASE}/api/domain/${encodeURIComponent(domain)}`);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) handleApiError(res, body);
    return body;
}

async function apiUrl(url) {
    const res = await fetch(`${API_BASE}/api/url/${encodeURIComponent(url)}`);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) handleApiError(res, body);
    return body;
}

async function apiHash(hash) {
    const res = await fetch(`${API_BASE}/api/hash/${encodeURIComponent(hash)}`);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) handleApiError(res, body);
    return body;
}

async function apiInvestigate(target) {
    const res = await fetch(`${API_BASE}/api/investigate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) handleApiError(res, body);
    return body;
}

async function apiRisk(domain) {
    const res = await fetch(`${API_BASE}/api/risk/${encodeURIComponent(domain)}`);
    if (!res.ok) return null;
    return res.json();
}

async function apiTimeline(domain) {
    const res = await fetch(`${API_BASE}/api/timeline/${encodeURIComponent(domain)}`);
    if (!res.ok) return null;
    return res.json();
}

async function apiGraph(domain, format = 'cytoscape') {
    const res = await fetch(`${API_BASE}/api/graph/${encodeURIComponent(domain)}?format=${format}`);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) handleApiError(res, body);
    return body;
}

async function apiExportMarkdown(queryType, queryValue) {
    const params = new URLSearchParams({
        query_type: queryType,
        query_value: queryValue
    });
    const res = await fetch(`${API_BASE}/api/export/markdown?${params}`);
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        handleApiError(res, err);
    }
    return res.blob();
}

/** Extrai domínio de uma URL (ex: https://evil.com/path -> evil.com) */
function extractDomainFromUrl(url) {
    try {
        const u = new URL(url);
        return u.hostname.replace(/^www\./, '');
    } catch {
        return null;
    }
}

async function apiRecentUrls(limit = 10) {
    const res = await fetch(`${API_BASE}/api/urls/recent?limit=${limit}`);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) handleApiError(res, body);
    return body;
}

async function apiRecentPayloads(limit = 10) {
    const res = await fetch(`${API_BASE}/api/payloads/recent?limit=${limit}`);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) handleApiError(res, body);
    return body;
}

async function apiUrlById(urlId) {
    const res = await fetch(`${API_BASE}/api/urlid/${urlId}`, { method: 'POST' });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) handleApiError(res, body);
    return body;
}

async function apiTag(tag) {
    const res = await fetch(`${API_BASE}/api/tag/${encodeURIComponent(tag)}`, { method: 'POST' });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) handleApiError(res, body);
    return body;
}

async function apiSignature(signature) {
    const res = await fetch(`${API_BASE}/api/signature/${encodeURIComponent(signature)}`, { method: 'POST' });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) handleApiError(res, body);
    return body;
}

/** URL para download de payload (abre em nova aba com Auth via backend) */
function getPayloadDownloadUrl(sha256) {
    return `${API_BASE}/api/download/${sha256}`;
}
