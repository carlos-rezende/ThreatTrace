/**
 * UI utilities: copy, history, escapeHtml
 */
const HISTORY_KEY = 'threattrace_history';
const MAX_HISTORY = 10;

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function copyToClipboard(text, buttonEl) {
    navigator.clipboard.writeText(text).then(() => {
        const btn = buttonEl || event?.target?.closest('.copy-btn');
        if (btn) {
            const orig = btn.innerHTML;
            btn.classList.add('copied');
            btn.title = typeof t === 'function' ? t('copied') : 'Copied!';
            btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 13l4 4L19 7"/></svg>';
            setTimeout(() => {
                btn.classList.remove('copied');
                btn.title = typeof t === 'function' ? t('copy') : 'Copy';
                btn.innerHTML = orig;
            }, 1500);
        }
    });
}

function createCopyButton(text) {
    const btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.title = typeof t === 'function' ? t('copy') : 'Copy';
    btn.dataset.copy = text;
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>';
    btn.onclick = (e) => {
        e.stopPropagation();
        copyToClipboard(text, btn);
    };
    return btn;
}


function addToHistory(target) {
    let history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
    history = history.filter(t => t !== target);
    history.unshift(target);
    history = history.slice(0, MAX_HISTORY);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    return history;
}

function getHistory() {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
}

function clearHistory() {
    localStorage.setItem(HISTORY_KEY, JSON.stringify([]));
}

function renderHistorySidebar(containerId, onSelect) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const history = getHistory();
    const btnClear = document.getElementById('btn-clear-history');
    if (btnClear) btnClear.style.display = history.length === 0 ? 'none' : 'flex';

    if (history.length === 0) {
        const msg = typeof t === 'function' ? t('noInvestigations') : 'No investigations yet';
        container.innerHTML = `<button class="history-item empty">${msg}</button>`;
        return;
    }

    const formatHistoryLabel = (val) => {
        if (val && val.length === 64 && /^[a-f0-9]+$/.test(val)) {
            return val.slice(0, 12) + '…' + val.slice(-8);
        }
        if (val && val.length === 32 && /^[a-f0-9]+$/.test(val)) {
            return val.slice(0, 8) + '…' + val.slice(-6);
        }
        return val;
    };

    container.innerHTML = history.map(target => {
        const btn = document.createElement('button');
        btn.className = 'history-item';
        btn.textContent = formatHistoryLabel(target);
        btn.title = target;
        btn.onclick = () => onSelect(target);
        return btn;
    }).map(el => el.outerHTML).join('');
}

function showToast(message, type = 'error') {
    let toast = document.getElementById('toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast';
        toast.style.cssText = 'position:fixed;bottom:20px;right:20px;padding:1rem 1.5rem;border-radius:8px;z-index:9999;transition:opacity 0.3s;';
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.style.background = type === 'error' ? 'rgba(248,81,73,0.9)' : 'rgba(63,185,80,0.9)';
    toast.style.color = 'white';
    toast.style.opacity = '1';
    setTimeout(() => { toast.style.opacity = '0'; }, 3000);
}
