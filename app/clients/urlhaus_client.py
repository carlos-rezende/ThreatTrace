"""
Client para URLHaus API - https://urlhaus-api.abuse.ch/

Documentação: https://urlhaus-api.abuse.ch/
Autenticação: cabeçalho HTTP "Auth-Key" obrigatório em todas as requisições.
Exemplo: curl -H "Auth-Key: YOUR-AUTH-KEY-HERE" -X GET https://urlhaus-api.abuse.ch/v1/urls/recent/
"""
import re
from typing import Optional
import httpx
from app.schemas.threat_schema import MaliciousURL


class URLHausAPIError(Exception):
    """Erro na comunicação com URLHaus API"""
    pass


class URLHausClient:
    """
    Client para URLHaus API.
    Todas as requisições incluem o cabeçalho Auth-Key conforme documentação.
    """
    
    BASE_URL = "https://urlhaus-api.abuse.ch/v1"
    
    def __init__(self, auth_key: str, timeout: float = 30.0):
        self.auth_key = auth_key
        self.timeout = timeout
        self._headers = {"Auth-Key": auth_key}
    
    def _extract_domain(self, url_or_host: str) -> str:
        """Extrai domínio de URL ou retorna host se já for domínio/IP"""
        url_or_host = url_or_host.strip().lower()
        if "://" in url_or_host:
            url_or_host = url_or_host.split("://", 1)[1]
        if "/" in url_or_host:
            url_or_host = url_or_host.split("/")[0]
        if ":" in url_or_host:
            url_or_host = url_or_host.split(":")[0]
        return url_or_host
    
    def _is_valid_hash(self, value: str) -> tuple[bool, Optional[str]]:
        """Valida se é MD5 ou SHA256. Retorna (valido, tipo)"""
        value = value.strip().lower()
        if re.match(r"^[a-f0-9]{32}$", value):
            return True, "md5"
        if re.match(r"^[a-f0-9]{64}$", value):
            return True, "sha256"
        return False, None
    
    async def lookup_url(self, url: str) -> dict:
        """Consulta informações sobre uma URL específica"""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    f"{self.BASE_URL}/url/",
                    headers=self._headers,
                    data={"url": url}
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                raise URLHausAPIError(f"URLHaus API error: {e.response.status_code} - {e.response.text}")
            except httpx.RequestError as e:
                raise URLHausAPIError(f"Request failed: {str(e)}")
    
    async def lookup_host(self, host: str) -> dict:
        """Consulta informações sobre um host (domínio ou IP)"""
        host = self._extract_domain(host)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    f"{self.BASE_URL}/host/",
                    headers=self._headers,
                    data={"host": host}
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                raise URLHausAPIError(f"URLHaus API error: {e.response.status_code} - {e.response.text}")
            except httpx.RequestError as e:
                raise URLHausAPIError(f"Request failed: {str(e)}")
    
    async def lookup_payload(self, file_hash: str) -> dict:
        """Consulta informações sobre um hash de payload (MD5 ou SHA256)"""
        valid, hash_type = self._is_valid_hash(file_hash)
        if not valid:
            raise URLHausAPIError(f"Invalid hash format. Use MD5 (32 chars) or SHA256 (64 chars)")
        
        param = "md5_hash" if hash_type == "md5" else "sha256_hash"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    f"{self.BASE_URL}/payload/",
                    headers=self._headers,
                    data={param: file_hash}
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                raise URLHausAPIError(f"URLHaus API error: {e.response.status_code} - {e.response.text}")
            except httpx.RequestError as e:
                raise URLHausAPIError(f"Request failed: {str(e)}")

    async def get_recent_urls(self, limit: Optional[int] = None) -> dict:
        """
        Consulta URLs recentes (adições dos últimos 3 dias, máx 1000).
        Requer HTTP GET conforme documentação.
        limit: opcional, máx 1000 (ex: limit=3 retorna os 3 mais recentes).
        """
        url = f"{self.BASE_URL}/urls/recent/"
        if limit is not None:
            url = f"{self.BASE_URL}/urls/recent/limit/{min(limit, 1000)}/"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.get(url, headers=self._headers)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                raise URLHausAPIError(f"URLHaus API error: {e.response.status_code} - {e.response.text}")
            except httpx.RequestError as e:
                raise URLHausAPIError(f"Request failed: {str(e)}")

    async def get_recent_payloads(self, limit: Optional[int] = None) -> dict:
        """
        Consulta payloads recentes (últimos 3 dias, máx 1000).
        Requer HTTP GET conforme documentação.
        limit: opcional, máx 1000.
        """
        url = f"{self.BASE_URL}/payloads/recent/"
        if limit is not None:
            url = f"{self.BASE_URL}/payloads/recent/limit/{min(limit, 1000)}/"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.get(url, headers=self._headers)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                raise URLHausAPIError(f"URLHaus API error: {e.response.status_code} - {e.response.text}")
            except httpx.RequestError as e:
                raise URLHausAPIError(f"Request failed: {str(e)}")

    async def lookup_url_by_id(self, url_id: str) -> dict:
        """
        Consulta informações de URL pelo ID do URLhaus.
        POST /v1/urlid/ com parâmetro id.
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    f"{self.BASE_URL}/urlid/",
                    headers=self._headers,
                    data={"id": url_id}
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                raise URLHausAPIError(f"URLHaus API error: {e.response.status_code} - {e.response.text}")
            except httpx.RequestError as e:
                raise URLHausAPIError(f"Request failed: {str(e)}")

    async def lookup_tag(self, tag: str) -> dict:
        """
        Consulta informações sobre uma tag (ex: Retefe, emotet).
        POST /v1/tag/ com parâmetro tag.
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    f"{self.BASE_URL}/tag/",
                    headers=self._headers,
                    data={"tag": tag.strip()}
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                raise URLHausAPIError(f"URLHaus API error: {e.response.status_code} - {e.response.text}")
            except httpx.RequestError as e:
                raise URLHausAPIError(f"Request failed: {str(e)}")

    async def lookup_signature(self, signature: str) -> dict:
        """
        Consulta informações sobre uma assinatura/família de malware (ex: Gozi, Heodo).
        POST /v1/signature/ com parâmetro signature.
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    f"{self.BASE_URL}/signature/",
                    headers=self._headers,
                    data={"signature": signature.strip()}
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                raise URLHausAPIError(f"URLHaus API error: {e.response.status_code} - {e.response.text}")
            except httpx.RequestError as e:
                raise URLHausAPIError(f"Request failed: {str(e)}")

    async def download_payload(self, sha256_hash: str) -> tuple[bytes, str]:
        """
        Baixa amostra de malware (ZIP) pelo hash SHA256.
        GET /v1/download/<sha256>/ com Auth-Key.
        Retorna (bytes, content_type). Resposta pode ser not_found ou copy_error.
        """
        sha256 = sha256_hash.strip().lower()
        if not re.match(r"^[a-f0-9]{64}$", sha256):
            raise URLHausAPIError("Hash SHA256 inválido (64 caracteres hexadecimais)")
        url = f"{self.BASE_URL}/download/{sha256}/"
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                response = await client.get(url, headers=self._headers)
                if response.status_code != 200:
                    text = response.text
                    if "not_found" in text.lower():
                        raise URLHausAPIError("Payload não encontrado no URLhaus")
                    if "copy_error" in text.lower():
                        raise URLHausAPIError("Erro ao obter cópia do payload")
                    raise URLHausAPIError(f"URLHaus API error: {response.status_code} - {text}")
                content_type = response.headers.get("content-type", "application/zip")
                return response.content, content_type
            except httpx.RequestError as e:
                raise URLHausAPIError(f"Request failed: {str(e)}")
    
    def _parse_url_status(self, status: str) -> str:
        """Mapeia status URLHaus para status da aplicação"""
        mapping = {"online": "active", "offline": "inactive", "unknown": "unknown"}
        return mapping.get(status.lower(), "unknown")
    
    def _extract_malicious_urls_from_host(self, data: dict) -> list[MaliciousURL]:
        """Extrai lista de MaliciousURL do response de host lookup"""
        urls = []
        for item in data.get("urls") or []:
            tags = item.get("tags") or []
            family = tags[0] if tags and tags[0] not in ("exe", "doc", "elf") else None
            if not family and len(tags) > 1:
                family = next((t for t in tags if t not in ("exe", "doc", "elf", "hta")), None)
            
            urls.append(MaliciousURL(
                url=item.get("url", ""),
                malware_family=family,
                first_seen=item.get("date_added"),
                status=self._parse_url_status(item.get("url_status", "unknown")),
                urlhaus_reference=item.get("urlhaus_reference"),
                tags=tags,
                threat=item.get("threat")
            ))
        return urls
    
    def _extract_malicious_urls_from_url(self, data: dict) -> list[MaliciousURL]:
        """Extrai MaliciousURL do response de URL lookup"""
        if data.get("query_status") != "ok":
            return []
        
        tags = data.get("tags") or []
        family = tags[0] if tags and tags[0] not in ("exe", "doc", "elf") else None
        payload_hash = data["payloads"][0].get("response_sha256") if data.get("payloads") else None
        
        return [MaliciousURL(
            url=data.get("url", ""),
            malware_family=family or (data.get("payloads", [{}])[0].get("signature") if data.get("payloads") else None),
            first_seen=data.get("date_added"),
            last_seen=data.get("last_online"),
            status=self._parse_url_status(data.get("url_status", "unknown")),
            payload_hash=payload_hash,
            urlhaus_reference=data.get("urlhaus_reference"),
            tags=tags,
            threat=data.get("threat")
        )]
    
    def _extract_malicious_urls_from_payload(self, data: dict) -> list[MaliciousURL]:
        """Extrai MaliciousURL do response de payload lookup"""
        urls = []
        for item in data.get("urls") or []:
            urls.append(MaliciousURL(
                url=item.get("url", ""),
                malware_family=data.get("signature"),
                first_seen=item.get("firstseen"),
                last_seen=item.get("lastseen"),
                status=self._parse_url_status(item.get("url_status", "unknown")),
                urlhaus_reference=item.get("urlhaus_reference"),
                payload_hash=data.get("sha256_hash"),
                tags=[],
                threat="malware_download"
            ))
        return urls
