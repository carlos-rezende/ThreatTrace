"""
Serviço de análise de campanhas de malware
"""
import re
from collections import defaultdict
from urllib.parse import urlparse

from app.schemas.threat_schema import (
    MaliciousURL,
    CampaignInfo,
    InfrastructureDiscovery,
    TimelineEvent,
    ThreatLookupResponse,
)
from app.clients.urlhaus_client import URLHausClient, URLHausAPIError


class CampaignAnalyzer:
    """Analisa dados da URLHaus e agrupa em campanhas"""
    
    def __init__(self, client: URLHausClient):
        self.client = client
    
    def _extract_host(self, url: str) -> str:
        """Extrai host (domínio ou IP) de uma URL"""
        try:
            parsed = urlparse(url)
            host = parsed.netloc or parsed.path.split("/")[0]
            if ":" in host:
                host = host.split(":")[0]
            return host.strip().lower()
        except Exception:
            return ""
    
    def _is_ip(self, host: str) -> bool:
        """Verifica se host é um endereço IP"""
        ipv4 = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host)
        return bool(ipv4)
    
    def _analyze_campaigns(self, urls: list[MaliciousURL]) -> list[CampaignInfo]:
        """Agrupa URLs por família de malware e infraestrutura"""
        by_family: dict[str, list[MaliciousURL]] = defaultdict(list)
        
        for u in urls:
            if u.malware_family:
                by_family[u.malware_family].append(u)
        
        campaigns: list[CampaignInfo] = []
        seen_families = set()
        
        for family, family_urls in by_family.items():
            if family in seen_families:
                continue
            seen_families.add(family)
            
            domains = set()
            hashes = set()
            dates = []
            for u in family_urls:
                host = self._extract_host(u.url)
                if host and not self._is_ip(host):
                    domains.add(host)
                if u.payload_hash:
                    hashes.add(u.payload_hash)
                if u.first_seen:
                    dates.append(u.first_seen)
                if u.last_seen:
                    dates.append(u.last_seen)
            
            campaigns.append(CampaignInfo(
                family=family,
                related_domains=sorted(domains),
                payload_hashes=sorted(hashes),
                url_count=len(family_urls),
                first_seen=min(dates) if dates else None,
                last_seen=max(dates) if dates else None
            ))
        
        return campaigns
    
    def _discover_infrastructure(self, urls: list[MaliciousURL]) -> InfrastructureDiscovery:
        """Descobre domínios, IPs e infraestrutura compartilhada"""
        domains = set()
        ips = set()
        hosts = []
        
        for u in urls:
            host = self._extract_host(u.url)
            if not host:
                continue
            if self._is_ip(host):
                ips.add(host)
            else:
                domains.add(host)
            hosts.append(host)
        
        from collections import Counter
        host_counts = Counter(hosts)
        shared = [h for h, c in host_counts.items() if c > 1]
        
        return InfrastructureDiscovery(
            domains=sorted(domains),
            ips=sorted(ips),
            shared_hosts=sorted(shared)
        )
    
    def _build_timeline(self, urls: list[MaliciousURL]) -> list[TimelineEvent]:
        """Constrói linha do tempo da campanha"""
        events: list[tuple[str, str, str, int]] = []
        
        for u in urls:
            if u.first_seen:
                date_str = u.first_seen.split()[0] if " " in u.first_seen else u.first_seen
                events.append((date_str, "first_seen", f"URL adicionada: {u.url[:60]}...", 1))
            if u.last_seen:
                date_str = u.last_seen.split()[0] if " " in u.last_seen else u.last_seen
                events.append((date_str, "last_seen", f"Última atividade: {u.url[:60]}...", 1))
        
        by_date: dict[str, list] = defaultdict(list)
        for date, etype, desc, count in events:
            by_date[date].append((etype, desc, count))
        
        timeline = []
        for date in sorted(by_date.keys()):
            items = by_date[date]
            total = sum(i[2] for i in items)
            types = set(i[0] for i in items)
            desc = "Primeira descoberta" if "first_seen" in types else "Atividade registrada"
            if "last_seen" in types and "first_seen" in types:
                desc = "Atividade mista (first/last seen)"
            timeline.append(TimelineEvent(
                date=date,
                event_type=",".join(types),
                description=desc,
                url_count=total
            ))
        
        return sorted(timeline, key=lambda x: x.date)
    
    async def analyze_domain(self, domain: str) -> ThreatLookupResponse:
        """Analisa domínio e retorna resposta completa"""
        data = await self.client.lookup_host(domain)
        # URLHaus doc pode retornar query_status ou query_staus (typo histórico)
        status = data.get("query_status") or data.get("query_staus")
        if status not in ("ok",):
            return ThreatLookupResponse(query=domain, query_type="domain", malicious_urls=[], campaigns=[])
        
        urls = self.client._extract_malicious_urls_from_host(data)
        campaigns = self._analyze_campaigns(urls)
        infrastructure = self._discover_infrastructure(urls)
        timeline = self._build_timeline(urls)
        
        return ThreatLookupResponse(
            malicious_urls=urls,
            campaigns=campaigns,
            infrastructure=infrastructure,
            timeline=timeline,
            query=domain,
            query_type="domain",
        )
    
    async def analyze_url(self, url: str) -> ThreatLookupResponse:
        """Analisa URL específica"""
        data = await self.client.lookup_url(url)
        urls = self.client._extract_malicious_urls_from_url(data)
        
        if not urls:
            return ThreatLookupResponse(query=url, query_type="url", malicious_urls=[], campaigns=[])
        
        campaigns = self._analyze_campaigns(urls)
        infrastructure = self._discover_infrastructure(urls)
        timeline = self._build_timeline(urls)
        
        return ThreatLookupResponse(
            malicious_urls=urls,
            campaigns=campaigns,
            infrastructure=infrastructure,
            timeline=timeline,
            query=url,
            query_type="url",
        )
    
    async def analyze_hash(self, file_hash: str) -> ThreatLookupResponse:
        """Analisa hash de malware"""
        data = await self.client.lookup_payload(file_hash)
        if data.get("query_status") != "ok":
            return ThreatLookupResponse(query=file_hash, query_type="hash", malicious_urls=[], campaigns=[])
        
        urls = self.client._extract_malicious_urls_from_payload(data)
        campaigns = self._analyze_campaigns(urls)
        infrastructure = self._discover_infrastructure(urls)
        timeline = self._build_timeline(urls)
        
        return ThreatLookupResponse(
            malicious_urls=urls,
            campaigns=campaigns,
            infrastructure=infrastructure,
            timeline=timeline,
            query=file_hash,
            query_type="hash",
        )
