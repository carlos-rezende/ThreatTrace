"""
crt.sh OSINT Module - Certificate transparency logs
"""
import httpx
from app.modules.base import ThreatModule, ModuleResult


class CrtshModule(ThreatModule):
    """Collects subdomains from certificate transparency logs via crt.sh"""
    name = "crtsh"
    description = "Certificate transparency subdomain discovery"

    async def run(self, target: str) -> ModuleResult:
        """Query crt.sh for subdomains"""
        domain = target.strip().lower()
        if "://" in domain:
            domain = domain.split("://")[1].split("/")[0]
        if ":" in domain:
            domain = domain.split(":")[0]

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"User-Agent": "ThreatTrace/1.0"},
                )
                r.raise_for_status()
                entries = r.json() or []
        except Exception as e:
            return ModuleResult(
                source="crt.sh",
                module_name=self.name,
                target=target,
                data={"error": str(e), "subdomains": []},
                meta={"success": False},
            )

        subdomains = set()
        for entry in entries:
            name = entry.get("name_value", "")
            for part in name.replace("\n", " ").split():
                part = part.strip().lower()
                if part and (part == domain or part.endswith(f".{domain}")):
                    subdomains.add(part)

        return ModuleResult(
            source="crt.sh",
            module_name=self.name,
            target=target,
            data={
                "subdomains": sorted(subdomains),
                "count": len(subdomains),
                "raw_count": len(entries),
            },
            meta={"success": True},
        )
