/**
 * ThreatTrace i18n - Português, English, Español
 */
const I18N = {
    pt: {
        // App
        appTitle: 'ThreatTrace',
        appSubtitle: 'Plataforma de Investigação de Threat Intelligence',
        dashboard: 'Dashboard',
        modules: 'Módulos',
        apiDocs: 'Documentação API',

        // Investigation
        newInvestigation: 'Nova Investigação',
        quickLookup: 'Consulta Rápida',
        fullInvestigation: 'Investigação Completa',
        investigate: 'Investigar',

        // Types
        domain: 'Domínio',
        url: 'URL',
        hash: 'Hash',
        tag: 'Tag',
        signature: 'Assinatura',

        // Placeholders
        placeholderDomain: 'example.com',
        placeholderUrl: 'https://example.com/path/file.exe',
        placeholderHash: 'MD5 (32 chars) ou SHA256 (64 chars)',
        placeholderTag: 'ex: emotet, Retefe',
        placeholderSignature: 'ex: Gozi, Heodo',

        // Samples
        loadSamples: 'Carregar exemplos de teste',
        loading: 'Carregando...',
        recentUrls: 'URLs recentes:',
        recentHashes: 'Hashes recentes:',
        noSamples: 'Nenhum exemplo disponível',

        // History
        recentInvestigations: 'Investigações Recentes',
        noInvestigations: 'Nenhuma investigação ainda',
        clearHistory: 'Limpar histórico',
        historyCleared: 'Histórico limpo',

        // Loading
        analyzing: 'Analisando...',
        runningInvestigation: 'Executando investigação OSINT completa...',
        queryingTag: 'Consultando tag...',
        queryingSignature: 'Consultando assinatura...',

        // Validation
        fieldRequired: 'Campo obrigatório',
        invalidDomain: 'Domínio inválido (ex: example.com)',
        urlMustStart: 'URL deve começar com http:// ou https://',
        invalidUrl: 'URL inválida',
        invalidHash: 'Hash deve ser MD5 (32 caracteres) ou SHA256 (64 caracteres)',
        hashHexOnly: 'Hash deve conter apenas hexadecimais',
        minChars: 'Mínimo 2 caracteres',

        // Dashboard
        threatOverview: 'Visão Geral da Ameaça',
        target: 'Alvo',
        maliciousUrls: 'URLs Maliciosas',
        firstSeen: 'Primeira Vez Visto',
        lastSeen: 'Última Vez Visto',
        riskScore: 'Pontuação de Risco',
        campaignTimeline: 'Linha do Tempo de Campanhas',
        campaigns: 'Campanhas',
        infrastructure: 'Infraestrutura',
        threatGraph: 'Grafo de Infraestrutura de Ameaças',
        export: 'Exportar',

        // Table
        malwareFamily: 'Família de Malware',
        activityDays: 'Dias de Atividade',
        noCampaigns: 'Nenhuma campanha detectada',
        noInfrastructure: 'Nenhuma infraestrutura descoberta',
        noMaliciousUrls: 'Nenhuma URL maliciosa',
        riskNotAvailable: 'Dados de risco não disponíveis',
        graphEmpty: 'Nenhum nó de infraestrutura encontrado para visualizar',

        // Buttons
        copy: 'Copiar',
        copied: 'Copiado!',
        downloadPayload: 'Download do payload (ZIP)',

        // Export
        reportDownloaded: 'Relatório baixado',
        markdownDownloaded: 'Relatório Markdown baixado',
        noInvestigationExport: 'Nenhuma investigação para exportar',
        exportPdfNotAvailable: 'Export PDF não disponível para Tag/Assinatura',
        exportMdNotAvailable: 'Export Markdown não disponível para Tag/Assinatura',
        exportError: 'Erro ao exportar',

        // API
        rateLimit: 'Limite de requisições atingido. Aguarde alguns minutos antes de tentar novamente.',
    },
    en: {
        appTitle: 'ThreatTrace',
        appSubtitle: 'Threat Intelligence Investigation Platform',
        dashboard: 'Dashboard',
        modules: 'Modules',
        apiDocs: 'API Docs',

        newInvestigation: 'New Investigation',
        quickLookup: 'Quick Lookup',
        fullInvestigation: 'Full Investigation',
        investigate: 'Investigate',

        domain: 'Domain',
        url: 'URL',
        hash: 'Hash',
        tag: 'Tag',
        signature: 'Signature',

        placeholderDomain: 'example.com',
        placeholderUrl: 'https://example.com/path/file.exe',
        placeholderHash: 'MD5 (32 chars) or SHA256 (64 chars)',
        placeholderTag: 'e.g. emotet, Retefe',
        placeholderSignature: 'e.g. Gozi, Heodo',

        loadSamples: 'Load test samples',
        loading: 'Loading...',
        recentUrls: 'Recent URLs:',
        recentHashes: 'Recent hashes:',
        noSamples: 'No samples available',

        recentInvestigations: 'Recent Investigations',
        noInvestigations: 'No investigations yet',

        analyzing: 'Analyzing...',
        runningInvestigation: 'Running full OSINT investigation...',
        queryingTag: 'Querying tag...',
        queryingSignature: 'Querying signature...',

        fieldRequired: 'Field required',
        invalidDomain: 'Invalid domain (e.g. example.com)',
        urlMustStart: 'URL must start with http:// or https://',
        invalidUrl: 'Invalid URL',
        invalidHash: 'Hash must be MD5 (32 characters) or SHA256 (64 characters)',
        hashHexOnly: 'Hash must contain only hexadecimal characters',
        minChars: 'Minimum 2 characters',

        threatOverview: 'Threat Overview',
        target: 'Target',
        maliciousUrls: 'Malicious URLs',
        firstSeen: 'First Seen',
        lastSeen: 'Last Seen',
        riskScore: 'Risk Score',
        campaignTimeline: 'Campaign Timeline',
        campaigns: 'Campaigns',
        infrastructure: 'Infrastructure',
        threatGraph: 'Threat Infrastructure Graph',
        export: 'Export',

        malwareFamily: 'Malware Family',
        activityDays: 'Activity Days',
        noCampaigns: 'No campaigns detected',
        noInfrastructure: 'No infrastructure discovered',
        noMaliciousUrls: 'No malicious URLs',
        riskNotAvailable: 'Risk data not available',
        graphEmpty: 'No infrastructure nodes found to display',

        copy: 'Copy',
        copied: 'Copied!',
        downloadPayload: 'Download payload (ZIP)',

        reportDownloaded: 'Report downloaded',
        markdownDownloaded: 'Markdown report downloaded',
        noInvestigationExport: 'No investigation to export',
        exportPdfNotAvailable: 'PDF export not available for Tag/Signature',
        exportMdNotAvailable: 'Markdown export not available for Tag/Signature',
        exportError: 'Export error',

        rateLimit: 'Rate limit reached. Please wait a few minutes before trying again.',
    },
    es: {
        appTitle: 'ThreatTrace',
        appSubtitle: 'Plataforma de Investigación de Threat Intelligence',
        dashboard: 'Panel',
        modules: 'Módulos',
        apiDocs: 'Documentación API',

        newInvestigation: 'Nueva Investigación',
        quickLookup: 'Consulta Rápida',
        fullInvestigation: 'Investigación Completa',
        investigate: 'Investigar',

        domain: 'Dominio',
        url: 'URL',
        hash: 'Hash',
        tag: 'Etiqueta',
        signature: 'Firma',

        placeholderDomain: 'example.com',
        placeholderUrl: 'https://example.com/path/file.exe',
        placeholderHash: 'MD5 (32 chars) o SHA256 (64 chars)',
        placeholderTag: 'ej: emotet, Retefe',
        placeholderSignature: 'ej: Gozi, Heodo',

        loadSamples: 'Cargar ejemplos de prueba',
        loading: 'Cargando...',
        recentUrls: 'URLs recientes:',
        recentHashes: 'Hashes recientes:',
        noSamples: 'No hay ejemplos disponibles',

        recentInvestigations: 'Investigaciones Recientes',
        noInvestigations: 'Aún no hay investigaciones',
        clearHistory: 'Borrar historial',
        historyCleared: 'Historial borrado',

        analyzing: 'Analizando...',
        runningInvestigation: 'Ejecutando investigación OSINT completa...',
        queryingTag: 'Consultando etiqueta...',
        queryingSignature: 'Consultando firma...',

        fieldRequired: 'Campo obligatorio',
        invalidDomain: 'Dominio inválido (ej: example.com)',
        urlMustStart: 'La URL debe comenzar con http:// o https://',
        invalidUrl: 'URL inválida',
        invalidHash: 'El hash debe ser MD5 (32 caracteres) o SHA256 (64 caracteres)',
        hashHexOnly: 'El hash debe contener solo caracteres hexadecimales',
        minChars: 'Mínimo 2 caracteres',

        threatOverview: 'Resumen de Amenazas',
        target: 'Objetivo',
        maliciousUrls: 'URLs Maliciosas',
        firstSeen: 'Primera Vez Visto',
        lastSeen: 'Última Vez Visto',
        riskScore: 'Puntuación de Riesgo',
        campaignTimeline: 'Línea de Tiempo de Campañas',
        campaigns: 'Campañas',
        infrastructure: 'Infraestructura',
        threatGraph: 'Grafo de Infraestructura de Amenazas',
        export: 'Exportar',

        malwareFamily: 'Familia de Malware',
        activityDays: 'Días de Actividad',
        noCampaigns: 'No se detectaron campañas',
        noInfrastructure: 'No se descubrió infraestructura',
        noMaliciousUrls: 'No hay URLs maliciosas',
        riskNotAvailable: 'Datos de riesgo no disponibles',
        graphEmpty: 'No se encontraron nodos de infraestructura para visualizar',

        copy: 'Copiar',
        copied: '¡Copiado!',
        downloadPayload: 'Descargar payload (ZIP)',

        reportDownloaded: 'Informe descargado',
        markdownDownloaded: 'Informe Markdown descargado',
        noInvestigationExport: 'No hay investigación para exportar',
        exportPdfNotAvailable: 'Exportar PDF no disponible para Etiqueta/Firma',
        exportMdNotAvailable: 'Exportar Markdown no disponible para Etiqueta/Firma',
        exportError: 'Error al exportar',

        rateLimit: 'Límite de solicitudes alcanzado. Espere unos minutos antes de intentar de nuevo.',
    },
};

const LANG_KEY = 'threattrace_lang';
let currentLang = localStorage.getItem(LANG_KEY) || 'pt';

function t(key) {
    return I18N[currentLang]?.[key] ?? I18N.en?.[key] ?? key;
}

function setLang(lang) {
    if (I18N[lang]) {
        currentLang = lang;
        localStorage.setItem(LANG_KEY, lang);
        document.documentElement.lang = lang === 'pt' ? 'pt-BR' : lang;
        applyTranslations();
    }
}

function getLang() {
    return currentLang;
}

function applyTranslations() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        const val = t(key);
        if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
            if (el.placeholder !== undefined) el.placeholder = val;
        } else {
            el.textContent = val;
        }
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        el.placeholder = t(el.getAttribute('data-i18n-placeholder'));
    });
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
        el.title = t(el.getAttribute('data-i18n-title'));
    });
    const btnSubmit = document.getElementById('btn-submit');
    if (btnSubmit) {
        const mode = document.querySelector('.mode-tab.active')?.dataset.mode;
        btnSubmit.textContent = mode === 'investigate' ? t('fullInvestigation') : t('investigate');
    }
    if (typeof onLangChange === 'function') onLangChange();
}
