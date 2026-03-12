"""
Schemas de request/response para ThreatTrace API
"""
from typing import Optional
from pydantic import BaseModel, Field


# --- Payload ---
class PayloadInfo(BaseModel):
    """Informações de um payload"""
    firstseen: Optional[str] = None
    filename: Optional[str] = None
    file_type: Optional[str] = None
    response_size: Optional[str] = None
    response_md5: Optional[str] = None
    response_sha256: Optional[str] = None
    urlhaus_download: Optional[str] = None
    signature: Optional[str] = None
    virustotal: Optional[dict] = None


# --- URL ---
class MaliciousURL(BaseModel):
    """URL maliciosa identificada"""
    url: str
    malware_family: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    status: str = "unknown"  # active, inactive, unknown
    payload_hash: Optional[str] = None
    urlhaus_reference: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    threat: Optional[str] = None


# --- Campaign ---
class CampaignInfo(BaseModel):
    """Informações de campanha"""
    family: str
    related_domains: list[str] = Field(default_factory=list)
    payload_hashes: list[str] = Field(default_factory=list)
    url_count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


# --- Infrastructure ---
class InfrastructureDiscovery(BaseModel):
    """Descoberta de infraestrutura relacionada"""
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    shared_hosts: list[str] = Field(default_factory=list)


# --- Timeline ---
class TimelineEvent(BaseModel):
    """Evento na linha do tempo"""
    date: str
    event_type: str
    description: str
    url_count: int = 0


# --- API Response ---
class ThreatLookupResponse(BaseModel):
    """Resposta do lookup de threat intelligence"""
    malicious_urls: list[MaliciousURL] = Field(default_factory=list)
    campaigns: list[CampaignInfo] = Field(default_factory=list)
    infrastructure: Optional[InfrastructureDiscovery] = None
    timeline: list[TimelineEvent] = Field(default_factory=list)
    query: str
    query_type: str  # domain, url, hash


# --- Investigation ---
class InvestigateRequest(BaseModel):
    """Request for investigation"""
    target: str
    modules: list[str] = Field(default_factory=list, description="Optional: specific modules to run")


class MonitorRequest(BaseModel):
    """Request for monitoring"""
    target: str
    webhook_url: Optional[str] = None
    email: Optional[str] = None
