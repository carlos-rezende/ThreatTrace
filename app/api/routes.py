"""
Rotas da API ThreatTrace
"""
import logging
from urllib.parse import unquote
from fastapi import APIRouter, HTTPException, Query, Request

logger = logging.getLogger("threattrace")
from fastapi.responses import JSONResponse, Response

from app.core.config import get_settings
from app.core.limiter import limiter
from app.clients.urlhaus_client import URLHausClient, URLHausAPIError
from app.services.campaign_analyzer import CampaignAnalyzer
from app.utils.report_generator import ReportGenerator
from app.schemas.threat_schema import ThreatLookupResponse
from app.graph.graph_service import GraphService
from app.services.timeline_analyzer import TimelineAnalyzer
from app.services.risk_scoring import RiskScoringService
from app.services.pattern_detector import PatternDetector
from app.services.intel_correlator import IntelCorrelator
from app.engine.scan_engine import ScanEngine
from app.monitoring.monitor_service import MonitorService
from app.reports.investigation_report import InvestigationReport
from app.schemas.threat_schema import InvestigateRequest, MonitorRequest

# Cache
from cachetools import TTLCache
import hashlib

router = APIRouter(prefix="/api", tags=["Threat Intelligence"])
settings = get_settings()
cache = TTLCache(maxsize=settings.CACHE_MAX_SIZE, ttl=settings.CACHE_TTL_SECONDS)


def _cache_key(prefix: str, value: str) -> str:
    return hashlib.sha256(f"{prefix}:{value}".encode()).hexdigest()


def _get_cached(key: str) -> ThreatLookupResponse | None:
    data = cache.get(key)
    if data is None:
        return None
    return ThreatLookupResponse.model_validate(data)


def _set_cached(key: str, response: ThreatLookupResponse):
    cache[key] = response.model_dump()


async def _analyze(analyzer: CampaignAnalyzer, query_type: str, query_value: str) -> ThreatLookupResponse:
    """Executa análise com cache"""
    ck = _cache_key(query_type, query_value)
    cached = _get_cached(ck)
    if cached:
        return cached
    
    if query_type == "domain":
        result = await analyzer.analyze_domain(query_value)
    elif query_type == "url":
        result = await analyzer.analyze_url(query_value)
    else:
        result = await analyzer.analyze_hash(query_value)
    
    _set_cached(ck, result)
    return result


def _get_analyzer() -> CampaignAnalyzer:
    """Factory para CampaignAnalyzer"""
    client = URLHausClient(settings.URLHAUS_AUTH_KEY)
    return CampaignAnalyzer(client)


def _check_auth():
    if not settings.URLHAUS_AUTH_KEY:
        raise HTTPException(
            status_code=503,
            detail="URLHAUS_AUTH_KEY não configurada. Obtenha em https://auth.abuse.ch/"
        )


# --- Endpoints ---

@router.get("/domain/{domain:path}", response_model=ThreatLookupResponse)
@limiter.limit("60/minute")
async def domain_lookup(request: Request, domain: str):
    """
    Consulta informações de threat associadas a um domínio.
    
    - **domain**: Domínio a ser investigado (ex: example.com)
    """
    _check_auth()
    domain = unquote(domain).strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domínio não pode ser vazio")
    
    try:
        return await _analyze(_get_analyzer(), "domain", domain)
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/url/{url:path}", response_model=ThreatLookupResponse)
@limiter.limit("60/minute")
async def url_lookup(request: Request, url: str):
    """
    Consulta informações sobre uma URL específica.
    
    - **url**: URL completa a ser investigada
    """
    _check_auth()
    url = unquote(url).strip()
    if not url or not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL inválida. Deve começar com http:// ou https://")
    
    try:
        return await _analyze(_get_analyzer(), "url", url)
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/hash/{file_hash}", response_model=ThreatLookupResponse)
@limiter.limit("60/minute")
async def hash_lookup(request: Request, file_hash: str):
    """
    Consulta informações sobre um hash (MD5 ou SHA256).
    
    - **file_hash**: Hash MD5 (32 caracteres) ou SHA256 (64 caracteres)
    """
    _check_auth()
    file_hash = file_hash.strip().lower()
    if len(file_hash) not in (32, 64):
        raise HTTPException(status_code=400, detail="Hash deve ser MD5 (32 chars) ou SHA256 (64 chars)")
    
    try:
        return await _analyze(_get_analyzer(), "hash", file_hash)
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/campaigns/{domain:path}", response_model=ThreatLookupResponse)
@limiter.limit("60/minute")
async def campaigns_by_domain(request: Request, domain: str):
    """
    Retorna campanhas de malware associadas a um domínio.
    
    - **domain**: Domínio a ser analisado
    """
    return await domain_lookup(request, domain)


@router.get("/graph/{domain:path}")
@limiter.limit("60/minute")
async def graph_by_domain(request: Request, domain: str, format: str = Query("d3", description="d3 ou cytoscape")):
    """
    Retorna grafo de infraestrutura - D3.js ou Cytoscape.js compatible.
    """
    _check_auth()
    domain = unquote(domain).strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domínio não pode ser vazio")
    
    try:
        result = await _analyze(_get_analyzer(), "domain", domain)
        graph = GraphService.build_from_lookup(result)
        return graph.to_cytoscape() if format == "cytoscape" else graph.to_d3()
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/timeline/{domain:path}")
@limiter.limit("60/minute")
async def timeline_by_domain(request: Request, domain: str):
    """Campaign timeline analysis for domain"""
    _check_auth()
    domain = unquote(domain).strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domínio não pode ser vazio")
    
    try:
        result = await _analyze(_get_analyzer(), "domain", domain)
        return TimelineAnalyzer.analyze(result)
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/risk/{domain:path}")
@limiter.limit("60/minute")
async def risk_by_domain(request: Request, domain: str):
    """Threat risk score for domain (0-100, low/medium/high)"""
    _check_auth()
    domain = unquote(domain).strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domínio não pode ser vazio")
    
    try:
        result = await _analyze(_get_analyzer(), "domain", domain)
        return RiskScoringService.calculate(result)
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/patterns/{domain:path}")
@limiter.limit("60/minute")
async def patterns_by_domain(request: Request, domain: str):
    """Threat actor pattern detection (DGA, fast flux, infrastructure reuse)"""
    _check_auth()
    domain = unquote(domain).strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domínio não pode ser vazio")
    
    try:
        result = await _analyze(_get_analyzer(), "domain", domain)
        return PatternDetector.detect(result)
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.post("/investigate")
@limiter.limit("10/minute")
async def investigate(request: Request, body: InvestigateRequest):
    """
    Full OSINT investigation - runs modules, builds graph, timeline, risk, correlation.
    """
    _check_auth()
    target = body.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target não pode ser vazio")
    
    engine = ScanEngine(settings.URLHAUS_AUTH_KEY, getattr(settings, "GITHUB_TOKEN", None))
    try:
        return await engine.investigate(target, body.modules or None)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/monitor")
@limiter.limit("30/minute")
async def monitor(request: Request, body: MonitorRequest):
    """Add target to monitoring (webhook/email alerts)"""
    target = body.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target não pode ser vazio")
    
    result = MonitorService.add(target, body.webhook_url, body.email)
    return result


@router.get("/modules")
async def list_modules():
    """List available OSINT modules"""
    from app.modules.module_loader import get_available_modules
    return {"modules": get_available_modules()}


@router.get("/urls/recent")
@limiter.limit("10/minute")
async def recent_urls(request: Request, limit: int = Query(10, ge=1, le=1000)):
    """
    URLs recentes da URLHaus (últimos 3 dias). Útil para obter exemplos para testar.
    Requer HTTP GET conforme documentação URLHaus.
    """
    _check_auth()
    try:
        client = URLHausClient(settings.URLHAUS_AUTH_KEY)
        data = await client.get_recent_urls(limit=limit)
        return data
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/payloads/recent")
@limiter.limit("10/minute")
async def recent_payloads(request: Request, limit: int = Query(10, ge=1, le=1000)):
    """
    Payloads recentes da URLHaus (últimos 3 dias, máx 1000).
    Requer HTTP GET conforme documentação URLHaus.
    """
    _check_auth()
    try:
        client = URLHausClient(settings.URLHAUS_AUTH_KEY)
        data = await client.get_recent_payloads(limit=limit)
        return data
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.post("/urlid/{url_id}")
@limiter.limit("30/minute")
async def url_by_id(request: Request, url_id: str):
    """
    Consulta informações de URL pelo ID do URLhaus.
    POST /v1/urlid/ conforme documentação.
    """
    _check_auth()
    if not url_id or not url_id.isdigit():
        raise HTTPException(status_code=400, detail="ID da URL deve ser numérico")
    try:
        client = URLHausClient(settings.URLHAUS_AUTH_KEY)
        return await client.lookup_url_by_id(url_id)
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.post("/tag/{tag:path}")
@limiter.limit("30/minute")
async def tag_lookup(request: Request, tag: str):
    """
    Consulta informações sobre uma tag (ex: emotet, Retefe).
    POST /v1/tag/ conforme documentação.
    """
    _check_auth()
    tag = unquote(tag).strip()
    if not tag:
        raise HTTPException(status_code=400, detail="Tag não pode ser vazia")
    try:
        client = URLHausClient(settings.URLHAUS_AUTH_KEY)
        return await client.lookup_tag(tag)
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.post("/signature/{signature:path}")
@limiter.limit("30/minute")
async def signature_lookup(request: Request, signature: str):
    """
    Consulta informações sobre assinatura/família de malware (ex: Gozi, Heodo).
    POST /v1/signature/ conforme documentação.
    """
    _check_auth()
    signature = unquote(signature).strip()
    if not signature:
        raise HTTPException(status_code=400, detail="Signature não pode ser vazia")
    try:
        client = URLHausClient(settings.URLHAUS_AUTH_KEY)
        return await client.lookup_signature(signature)
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/download/{sha256_hash}")
@limiter.limit("5/minute")
async def download_payload(request: Request, sha256_hash: str):
    """
    Baixa amostra de malware (ZIP) pelo hash SHA256.
    GET /v1/download/<sha256>/ conforme documentação URLHaus.
    """
    _check_auth()
    sha256 = sha256_hash.strip().lower()
    if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
        raise HTTPException(status_code=400, detail="Hash SHA256 inválido (64 caracteres hex)")
    try:
        client = URLHausClient(settings.URLHAUS_AUTH_KEY)
        content, content_type = await client.download_payload(sha256)
        return Response(
            content=content,
            media_type=content_type,
            headers={"Content-Disposition": f"attachment; filename=payload_{sha256[:16]}.zip"}
        )
    except URLHausAPIError as e:
        err_msg = str(e).lower()
        if "não encontrado" in err_msg or "not_found" in err_msg or "not found" in err_msg:
            raise HTTPException(status_code=404, detail=str(e))
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/export/json")
@limiter.limit("30/minute")
async def export_json(
    request: Request,
    query_type: str = Query(..., description="domain, url ou hash"),
    query_value: str = Query(..., description="Valor da consulta"),
):
    """Exporta resultado da análise em JSON"""
    _check_auth()
    try:
        result = await _analyze(_get_analyzer(), query_type, query_value)
        return JSONResponse(
            content=result.model_dump(),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=threattrace_report.json"}
        )
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/export/pdf")
@limiter.limit("30/minute")
async def export_pdf(
    request: Request,
    query_type: str = Query(..., description="domain, url ou hash"),
    query_value: str = Query(..., description="Valor da consulta"),
):
    """Exporta resultado da análise em PDF"""
    _check_auth()
    try:
        result = await _analyze(_get_analyzer(), query_type, query_value)
        pdf_bytes = ReportGenerator.to_pdf(result)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=threattrace_report.pdf"}
        )
    except ImportError:
        raise HTTPException(status_code=500, detail="Exportação PDF requer: pip install reportlab")
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/export/markdown")
@limiter.limit("30/minute")
async def export_markdown(
    request: Request,
    query_type: str = Query(..., description="domain, url ou hash"),
    query_value: str = Query(..., description="Valor da consulta"),
):
    """Exporta resultado em Markdown"""
    _check_auth()
    try:
        result = await _analyze(_get_analyzer(), query_type, query_value)
        data = result.model_dump()
        data["query"] = result.query
        if query_type == "domain":
            risk = RiskScoringService.calculate(result)
            timeline = TimelineAnalyzer.analyze(result)
            corr = IntelCorrelator.correlate(result)
            data["risk"] = risk
            data["timeline"] = timeline
            data["correlation"] = corr
        md = InvestigationReport.to_markdown(data)
        return Response(
            content=md,
            media_type="text/markdown",
            headers={"Content-Disposition": "attachment; filename=threattrace_report.md"}
        )
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/export/domain/{domain:path}")
@limiter.limit("30/minute")
async def export_domain(request: Request, domain: str, format: str = Query("json", description="json, pdf ou md")):
    """
    Exporta resultado da análise de um domínio.
    
    - **domain**: Domínio a exportar
    - **format**: json ou pdf
    """
    _check_auth()
    domain = unquote(domain).strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domínio não pode ser vazio")
    
    try:
        result = await _analyze(_get_analyzer(), "domain", domain)
        if format == "pdf":
            pdf_bytes = ReportGenerator.to_pdf(result)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=threattrace_{domain}.pdf"}
            )
        if format == "md":
            data = result.model_dump()
            data["risk"] = RiskScoringService.calculate(result)
            data["timeline"] = TimelineAnalyzer.analyze(result)
            data["correlation"] = IntelCorrelator.correlate(result)
            md = InvestigationReport.to_markdown(data)
            return Response(
                content=md,
                media_type="text/markdown",
                headers={"Content-Disposition": f"attachment; filename=threattrace_{domain}.md"}
            )
        return JSONResponse(
            content=result.model_dump(),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=threattrace_{domain}.json"}
        )
    except URLHausAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/health")
async def health_check():
    """Health check da API"""
    return {"status": "ok", "service": "ThreatTrace"}
