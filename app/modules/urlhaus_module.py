"""
URLHaus OSINT Module - Malware URL intelligence
"""
from app.modules.base import ThreatModule, ModuleResult
from app.clients.urlhaus_client import URLHausClient, URLHausAPIError


class URLHausModule(ThreatModule):
    """Collects malware URL intelligence from URLHaus"""
    name = "urlhaus"
    description = "URLHaus malware distribution intelligence"

    def __init__(self, auth_key: str):
        self.client = URLHausClient(auth_key)

    async def run(self, target: str) -> ModuleResult:
        """Query URLHaus for host/domain intelligence"""
        try:
            data = await self.client.lookup_host(target)
            urls = self.client._extract_malicious_urls_from_host(data)

            return ModuleResult(
                source="urlhaus.abuse.ch",
                module_name=self.name,
                target=target,
                data={
                    "query_status": data.get("query_status"),
                    "url_count": len(urls),
                    "urls": [
                        {
                            "url": u.url,
                            "family": u.malware_family,
                            "status": u.status,
                            "first_seen": u.first_seen,
                            "payload_hash": u.payload_hash,
                        }
                        for u in urls
                    ],
                    "raw": data,
                },
                meta={"success": data.get("query_status") == "ok"},
            )
        except URLHausAPIError as e:
            return ModuleResult(
                source="urlhaus.abuse.ch",
                module_name=self.name,
                target=target,
                data={"error": str(e)},
                meta={"success": False},
            )
